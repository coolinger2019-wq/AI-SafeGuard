use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use aisafeguard_ai::AiClient;
use aisafeguard_core::config::{AiConfig, AppConfig, DetectConfig};
use aisafeguard_core::error::{Error, Result};
use aisafeguard_core::event::{EventBus, SecurityEvent};
use aisafeguard_core::{now_ts, secrets};
use aisafeguard_firewall::{BlockSpec, Direction, Firewall, Protocol, RULE_PREFIX};
use aisafeguard_store::{
    AiRunRow, CredentialStore, EventRow, ProposalRow, RuleRow, StatsSummary, Store,
};
use serde::{Deserialize, Serialize};

use crate::console::Console;
use crate::explain::RuleExplain;

/// 采样捕获运行状态（检测平台 MVP）：捕获任务启动/失败/退出都写在这里，
/// StatusReport 与 GUI/API 只读展示。
#[derive(Default)]
pub struct CaptureState {
    active: AtomicBool,
    mode: Mutex<String>,
    note: Mutex<String>,
    /// 流统计快照（AI 深度介入）：捕获线程 sweep 时刷新，分析时随提示词送评。
    /// 只含元数据与计数，无载荷。
    flows: Mutex<FlowSnapshot>,
}

/// 流统计快照（提示词输入）。
#[derive(Debug, Clone, Serialize, Default)]
pub struct FlowSnapshot {
    pub flow_count: usize,
    pub top_syn: Vec<SynSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SynSource {
    pub ip: String,
    pub syn_count: u32,
}

impl CaptureState {
    pub fn set_active(&self, mode: &str) {
        *self.mode.lock().expect("捕获状态锁中毒") = mode.to_string();
        *self.note.lock().expect("捕获状态锁中毒") = String::new();
        self.active.store(true, Ordering::Relaxed);
    }

    pub fn set_error(&self, note: &str) {
        *self.note.lock().expect("捕获状态锁中毒") = note.to_string();
        self.active.store(false, Ordering::Relaxed);
    }

    pub fn set_flows(&self, snap: FlowSnapshot) {
        *self.flows.lock().expect("流统计锁中毒") = snap;
    }

    pub fn flows(&self) -> FlowSnapshot {
        self.flows.lock().expect("流统计锁中毒").clone()
    }

    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn mode(&self) -> String {
        self.mode.lock().expect("捕获状态锁中毒").clone()
    }

    pub fn note(&self) -> String {
        self.note.lock().expect("捕获状态锁中毒").clone()
    }
}

/// 规则子集引擎运行态（0.5.0 Batch F）：当前生效规则集（原子替换）+ threshold
/// 与流级去重状态 + 加载留痕（status/GUI 只读展示）。加载失败保持旧包生效并留痕。
#[derive(Default)]
pub struct RulesState {
    current: Mutex<Option<Arc<aisafeguard_rules::loader::LoadedRuleset>>>,
    /// 已加载规则包路径与 SHA-256（留痕，空 = 未加载）
    loaded_path: Mutex<String>,
    loaded_sha256: Mutex<String>,
    /// 最近一次加载结果说明（成功条数或失败原因）
    note: Mutex<String>,
    /// threshold 判定器（整包热更时重建——规则语义随包整体切换）
    threshold: Mutex<aisafeguard_rules::matcher::ThresholdTracker>,
    /// 采样路径流级去重：同 (sid, 流) 10 分钟内只报一次（流前缀持续可匹配防刷屏）
    fired_flows: Mutex<HashMap<String, i64>>,
    /// 命中计数（自启动累计，H6 可观测）
    hits: Mutex<u64>,
}

impl RulesState {
    pub fn current(&self) -> Option<Arc<aisafeguard_rules::loader::LoadedRuleset>> {
        self.current.lock().expect("规则集锁中毒").clone()
    }

    pub fn set_current(
        &self,
        rs: Option<Arc<aisafeguard_rules::loader::LoadedRuleset>>,
        path: &str,
        note: &str,
    ) {
        let sha256 = rs.as_ref().map(|r| r.sha256.clone()).unwrap_or_default();
        *self.current.lock().expect("规则集锁中毒") = rs;
        *self.loaded_path.lock().expect("规则路径锁中毒") = if sha256.is_empty() {
            String::new()
        } else {
            path.to_string()
        };
        *self.loaded_sha256.lock().expect("规则哈希锁中毒") = sha256;
        *self.note.lock().expect("规则备注锁中毒") = note.to_string();
    }

    pub fn loaded_path(&self) -> String {
        self.loaded_path.lock().expect("规则路径锁中毒").clone()
    }

    pub fn loaded_sha256(&self) -> String {
        self.loaded_sha256.lock().expect("规则哈希锁中毒").clone()
    }

    pub fn note(&self) -> String {
        self.note.lock().expect("规则备注锁中毒").clone()
    }

    pub fn add_hit(&self) {
        *self.hits.lock().expect("规则命中锁中毒") += 1;
    }

    pub fn hits(&self) -> u64 {
        *self.hits.lock().expect("规则命中锁中毒")
    }
}

/// 引擎对外契约：GUI 与 REST API 都只调用这里的方法，
/// 保证两条控制通道行为一致（0.2 远程控制台直接复用）。
pub struct EngineHandle {
    pub cfg: RwLock<AppConfig>,
    pub cfg_path: PathBuf,
    pub store: Arc<Store>,
    pub bus: EventBus,
    pub firewall: Arc<dyn Firewall>,
    pub detect: Arc<aisafeguard_detect::FreqEngine>,
    pub capture: Arc<CaptureState>,
    pub rules: Arc<RulesState>,
    /// XDP 组合执行器（0.5.1：仅 Linux 且 [xdp].enabled 时 Some；fast 层未附加为 None）
    pub xdp: Option<Arc<aisafeguard_xdp::composite::CompositeFirewall>>,
    pub rt: tokio::runtime::Handle,
    pub started: Instant,
    pub ai_running: Arc<AtomicBool>,
    pub honeypot: aisafeguard_honeypot::HoneypotHandle,
    /// 本机账号名快照（0.5.10 H200）：小写用户名集合，快照任务写、凭证任务读；
    /// 只存用户名，绝不触碰真实口令数据
    pub local_accounts: Arc<RwLock<std::collections::HashSet<String>>>,
    /// 凭证库（0.5.10 H200）：AI 慢路径上下文也要读（H310 只取掩码形态）
    pub credentials: Arc<CredentialStore>,
    /// 多机印证引擎（0.6 F200）：协调者侧内存滑动窗；agent 侧闲置（不参与计算）。
    /// min_peers quorum 门控的数据源（0.4 的 fed_reporter_count 已随
    /// 「协调者不持久化节点事件」切换至此）
    pub corroboration: Arc<std::sync::Mutex<crate::corroboration::CorroborationEngine>>,
    /// F500：fed 协议计数（与协调者 FedState 共享同一 Arc；agent/off 角色为 None）
    pub fed_stats: Option<Arc<crate::fed::FedStats>>,
    pub token: String,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub name: String,
    pub port: u16,
    pub kind: String,
    /// 交互模式：「低交互」banner 级 /「中交互」假 Shell（0.5.10 H150 能力可见）
    pub mode: String,
    /// 实际运行状态（0.5.12）：bind 成功 = true——配置里有 ≠ 真的在跑
    pub running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiStatus {
    pub enabled: bool,
    pub model: String,
    pub key_source: String,
    pub running: bool,
    pub auto_apply: bool,
    pub auto_apply_min_severity: String,
    pub analyze_interval_secs: u64,
    /// 灰度执行：AI 建议应用的默认封禁时长（秒）
    pub trial_ttl_secs: u64,
    /// 转正时长（秒）：人工确认后的封禁时长
    pub promote_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureSnapshot {
    pub ts: i64,
    pub entries: Vec<aisafeguard_detect::exposure::Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStatus {
    pub enabled: bool,
    pub active: bool,
    pub backend: String,
    pub mode: String,
    /// 失败/退出原因（active=false 时有值）
    pub note: String,
}

/// XDP 快速执行层状态（0.5.1 G1/G3 可观测；全部元数据与计数）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XdpStatus {
    /// 快速层已附加
    pub active: bool,
    pub iface: String,
    pub mode: String,
    /// 已镜像封禁源数
    pub mirrored: usize,
    /// XDP 累计丢弃包数（内核计数器，重启清零）
    pub drops_total: u64,
    /// 内核流表条目数（LRU 有界 65536）
    pub flows: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub version: String,
    pub uptime_secs: u64,
    pub backend: String,
    pub elevated: bool,
    pub listeners: Vec<ListenerInfo>,
    pub honeypot_enabled: bool,
    pub rule_count: i64,
    pub pending_proposals: i64,
    pub hits_24h: i64,
    pub attackers_24h: i64,
    /// 全量口径（部署至今，F795 补全）：事件总数（任意 kind）与独立来源数
    pub total_events: i64,
    pub unique_sources: i64,
    pub detect_enabled: bool,
    pub capture: CaptureStatus,
    /// 价值指标（0.4.0 B5）：口径见 store::ValueMetrics，比率由展示层算
    pub metrics_24h: aisafeguard_store::ValueMetrics,
    pub metrics_7d: aisafeguard_store::ValueMetrics,
    pub ai: AiStatus,
    /// 规则子集引擎状态（0.5.0 H6 可观测）
    pub rules: RulesStatus,
    /// XDP 快速执行层状态（0.5.1 G1/G3 可观测；Windows / 未启用时 active=false）
    pub xdp: XdpStatus,
    /// JA3 指纹覆盖（0.5.0 H6：24h 内 Detection 事件携带指纹的占比，比率展示层算）
    pub fingerprint_24h: FingerprintStats,
    /// F300 组织协同价值指标（组织建议采纳率与印证命中率，比率展示层算）
    pub org_metrics: aisafeguard_store::OrgMetrics,
    /// 情报订阅状态（订阅反馈：在库条数 + 上次拉取结果）
    pub intel: IntelStatus,
}

/// 情报订阅状态（GUI 设置页反馈；last_fetch None = 启动后从未拉取）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntelStatus {
    pub entries: i64,
    pub last_fetch_ts: Option<i64>,
    pub last_fetch_ok: bool,
    pub last_fetch_added: i64,
    pub last_fetch_active: i64,
    pub last_fetch_blocked: i64,
    /// 网段丢弃 + 超上限截断（F770 决策依据）
    #[serde(default)]
    pub last_fetch_dropped: i64,
}

/// F500 组织面板数据（只读 + 现有隔离通路；不新增跨节点命令通道）。
/// members/stats 仅协调者角色有数据；org_events 两类角色都有（本节点账本）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FedPanel {
    pub role: String,
    pub node: String,
    /// agent = 协调者地址；coordinator = mTLS 监听地址；off = 空
    pub endpoint: String,
    pub enabled: bool,
    pub members: Vec<FedPanelMember>,
    pub org_events: Vec<aisafeguard_store::OrgEventRow>,
    /// 协调者协议计数（malformed/sig_fail/seq_reject/duplicates/quarantined/rate_limited）
    pub stats: serde_json::Value,
    /// 数据截至（面板对离线成员展示「数据截至」语义的时间基准）
    pub data_as_of: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedPanelMember {
    pub node: String,
    pub status: String,
    pub last_seen: i64,
    pub cert_fp: String,
    /// F740：该成员证书是否已吊销（吊销表对照；吊销后一切连接被拒）
    #[serde(default)]
    pub revoked: bool,
}

/// 规则子集引擎运行状态（加载留痕 + 命中计数，GUI/API 只读展示）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesStatus {
    pub enabled: bool,
    /// 当前是否有生效规则集
    pub loaded: bool,
    /// 生效规则条数
    pub rule_count: usize,
    /// 已加载规则包路径
    pub path: String,
    /// 规则文件 SHA-256 前 16 位（留痕/钉扎比对）
    pub sha256: String,
    /// 最近一次加载结果（成功条数或整包拒绝原因）
    pub note: String,
    /// 自启动累计命中次数
    pub hits: u64,
}

/// JA3 指纹覆盖统计（24h 窗口）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FingerprintStats {
    pub detections: i64,
    pub with_fingerprint: i64,
}

/// Key 来源优先级：环境变量（CI/无头覆盖）> 凭据管理器 > 未配置。
fn key_source() -> &'static str {
    if std::env::var_os("AISAFEGUARD_AI_KEY").is_some_and(|v| !v.is_empty()) {
        "环境变量"
    } else if secrets::ai_key_present() {
        "凭据管理器"
    } else {
        "未配置"
    }
}

impl EngineHandle {
    pub fn config(&self) -> AppConfig {
        self.cfg.read().expect("配置锁中毒").clone()
    }

    pub fn status(&self) -> StatusReport {
        let cfg = self.config();
        let since = now_ts() - 86400;
        let hits_24h = self
            .store
            .count_events_kind_since("honeypot_hit", since)
            .unwrap_or(0);
        let stats = self.store.stats_since(since).unwrap_or_default();
        let (total_events, unique_sources) = self.store.totals_all().unwrap_or((0, 0));
        StatusReport {
            version: self.version.to_string(),
            uptime_secs: self.started.elapsed().as_secs(),
            backend: self.firewall.backend().to_string(),
            elevated: self.firewall.is_elevated(),
            honeypot_enabled: cfg.honeypot.enabled,
            listeners: self
                .honeypot
                .listeners()
                .iter()
                .map(|l| ListenerInfo {
                    name: l.name.clone(),
                    port: l.port,
                    kind: l.kind.clone(),
                    mode: l.mode.clone(),
                    running: l.running.load(std::sync::atomic::Ordering::Relaxed),
                })
                .collect(),
            rule_count: self.store.count_rules().unwrap_or(0),
            pending_proposals: self.store.count_proposals("pending").unwrap_or(0),
            hits_24h,
            attackers_24h: stats.unique_ips,
            total_events,
            unique_sources,
            detect_enabled: cfg.detect.enabled,
            capture: CaptureStatus {
                enabled: cfg.detect.capture.enabled,
                active: self.capture.active(),
                backend: aisafeguard_detect::capture::backend_name().to_string(),
                mode: self.capture.mode(),
                note: self.capture.note(),
            },
            metrics_24h: self
                .store
                .metrics_since(now_ts() - 86_400)
                .unwrap_or_default(),
            metrics_7d: self
                .store
                .metrics_since(now_ts() - 7 * 86_400)
                .unwrap_or_default(),
            ai: AiStatus {
                enabled: cfg.ai.enabled,
                model: cfg.ai.model.clone(),
                key_source: key_source().to_string(),
                running: self.ai_running.load(Ordering::Relaxed),
                auto_apply: cfg.ai.auto_apply,
                auto_apply_min_severity: cfg.ai.auto_apply_min_severity.clone(),
                analyze_interval_secs: cfg.ai.analyze_interval_secs,
                trial_ttl_secs: cfg.ai.trial_ttl_secs,
                promote_ttl_secs: cfg.ai.promote_ttl_secs,
            },
            rules: {
                let loaded = self.rules.current();
                RulesStatus {
                    enabled: cfg.detect.rules.enabled,
                    loaded: loaded.is_some(),
                    rule_count: loaded.as_ref().map(|r| r.rule_count).unwrap_or(0),
                    path: self.rules.loaded_path(),
                    sha256: self.rules.loaded_sha256()[..16.min(self.rules.loaded_sha256().len())]
                        .to_string(),
                    note: self.rules.note(),
                    hits: self.rules.hits(),
                }
            },
            xdp: self.xdp_status(),
            fingerprint_24h: {
                let (detections, with_fingerprint) = self
                    .store
                    .detection_fingerprint_stats_since(since)
                    .unwrap_or((0, 0));
                FingerprintStats {
                    detections,
                    with_fingerprint,
                }
            },
            org_metrics: self.store.org_metrics_since(since).unwrap_or_default(),
            intel: {
                let meta = self
                    .store
                    .get_meta("intel_last_fetch")
                    .ok()
                    .flatten()
                    .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok());
                IntelStatus {
                    entries: self.store.intel_count(now_ts()).unwrap_or(0),
                    last_fetch_ts: meta.as_ref().and_then(|m| m["ts"].as_i64()),
                    last_fetch_ok: meta
                        .as_ref()
                        .and_then(|m| m["ok"].as_bool())
                        .unwrap_or(false),
                    last_fetch_added: meta.as_ref().and_then(|m| m["added"].as_i64()).unwrap_or(0),
                    last_fetch_active: meta
                        .as_ref()
                        .and_then(|m| m["active"].as_i64())
                        .unwrap_or(0),
                    last_fetch_blocked: meta
                        .as_ref()
                        .and_then(|m| m["blocked"].as_i64())
                        .unwrap_or(0),
                    last_fetch_dropped: meta
                        .as_ref()
                        .and_then(|m| m["dropped"].as_i64())
                        .unwrap_or(0),
                }
            },
        }
    }

    /// XDP 快速层运行状态（G1/G3）：未附加 / 非 Linux / 未启用 → active=false。
    pub fn xdp_status(&self) -> XdpStatus {
        let cfg = self.config();
        match &self.xdp {
            Some(c) if c.fast_active() => {
                let stats = c.fast_stats().unwrap_or_default();
                XdpStatus {
                    active: true,
                    iface: cfg.xdp.iface.clone(),
                    mode: cfg.xdp.mode.clone(),
                    mirrored: stats.mirrored,
                    drops_total: stats.drops_total,
                    flows: stats.flows,
                }
            }
            _ => XdpStatus::default(),
        }
    }

    /// 一键清空 XDP map（G3）：封禁镜像与流表全清，nftables 兜底不受影响。
    pub fn xdp_clear_map(&self) -> Result<()> {
        match &self.xdp {
            Some(c) => c.fast_clear().map_err(Error::Firewall),
            None => Ok(()),
        }
    }

    pub fn list_events(&self, limit: u32, ip_filter: Option<&str>) -> Result<Vec<EventRow>> {
        self.store.recent_events(limit, ip_filter)
    }

    /// 规则展示模型（0.5.4 F1）：GUI 与 /api/rules 共用，可解释封禁。
    /// F300：规则行附带组织误报提示（「组织内 N 节点标记误报」，建议性质，
    /// 是否跟进由用户决定——绝不自动改本地抑制）。
    pub fn list_rules_explain(&self) -> Result<Vec<RuleExplain>> {
        let mut out = RuleExplain::of_list(self.store.list_rules()?);
        for e in out.iter_mut() {
            let n = self.store.org_flag_count(&e.remote_ip);
            if n > 0 {
                e.reason_summary = format!("{}（组织内 {} 节点标记误报）", e.reason_summary, n);
            }
        }
        Ok(out)
    }

    pub fn list_proposals(&self, status: Option<&str>, limit: u32) -> Result<Vec<ProposalRow>> {
        self.store.list_proposals(status, limit)
    }

    pub fn list_ai_runs(&self, limit: u32) -> Result<Vec<AiRunRow>> {
        self.store.list_ai_runs(limit)
    }

    /// F500 组织面板数据（只读）。
    pub fn fed_panel(&self) -> FedPanel {
        let cfg = self.config();
        let now = now_ts();
        let members = if cfg.fed.role == "coordinator" {
            let revoked: std::collections::HashSet<String> =
                crate::fed::load_revocations(&cfg.data_dir())
                    .into_iter()
                    .collect();
            self.store
                .list_fed_members()
                .unwrap_or_default()
                .into_iter()
                .map(|(node, cert_fp, last_seen, status)| FedPanelMember {
                    revoked: revoked.contains(&cert_fp),
                    node,
                    status,
                    last_seen,
                    cert_fp,
                })
                .collect()
        } else {
            Vec::new()
        };
        FedPanel {
            role: cfg.fed.role.clone(),
            node: cfg.fed.node.clone(),
            endpoint: if cfg.fed.role == "agent" {
                cfg.fed.coordinator.clone()
            } else {
                cfg.fed.listen_addr.clone()
            },
            enabled: cfg.fed.enabled,
            members,
            org_events: self.store.recent_org_events(50).unwrap_or_default(),
            stats: if cfg.fed.role == "coordinator" {
                self.fed_stats
                    .as_ref()
                    .map(|s| s.to_json())
                    .unwrap_or_else(|| serde_json::json!({}))
            } else {
                serde_json::json!({})
            },
            data_as_of: now,
        }
    }

    /// F500 隔离操作入口（面板与 CLI 同一通路：同一 DB 状态 + 同一留痕）。
    /// 返回人读结果文案（GUI toast 显示）。
    pub fn quarantine_member(
        &self,
        node: &str,
        lift: bool,
        lift_fp: &str,
        reason: &str,
    ) -> Result<String> {
        crate::fed::do_quarantine(&self.store, node, lift, lift_fp, reason)
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// F740：吊销驱离（GUI 面板与 CLI 同一通路）。立即断该证书的一切连接
    /// （含心跳）——与软隔离的区别：隔离留观察，吊销是驱离；重新加入需重新发证。
    pub fn revoke_member(&self, node: &str, reason: &str) -> anyhow::Result<String> {
        let fp = crate::fed::do_revoke(&self.config().data_dir(), node, reason)?;
        self.bus.publish(SecurityEvent::engine(
            "warn",
            format!("节点 {node} 已吊销驱离（{reason}）：一切连接立即拒绝；重新加入需重新签发证书"),
        ));
        Ok(format!(
            "已吊销 {node}（指纹 {fp}）：一切连接立即拒绝。重新加入需重新签发证书并删除吊销记录"
        ))
    }

    // ---------- F740 入伙向导（EngineHandle 粘合） ----------

    pub fn join_request_create(&self, node: &str) -> anyhow::Result<(String, String)> {
        crate::fed::join_request_create(&self.config().data_dir(), node)
    }

    pub fn join_approval_process(
        &self,
        request_json: &str,
        coord_addr: &str,
    ) -> anyhow::Result<(String, String)> {
        crate::fed::join_approval_process(&self.config().data_dir(), request_json, coord_addr)
    }

    /// 成员导入批准包：证书落位 + config.toml [fed] 段自动写入 + 热生效
    /// （agent 任务每轮读配置，无需重启即自动连接协调者）。
    pub fn join_import(&self, approval_json: &str, coord_addr: &str) -> anyhow::Result<String> {
        {
            let cfg = self.config();
            if cfg.fed.enabled && cfg.fed.role != "off" {
                anyhow::bail!(
                    "本节点已加入组织（[fed].enabled，角色 {}）——退出组织后再导入新批准包",
                    cfg.fed.role
                );
            }
        }
        let imported =
            crate::fed::join_import_prep(&self.config().data_dir(), approval_json, coord_addr)?;
        let mut cfg = self.config();
        cfg.fed.enabled = true;
        cfg.fed.role = "agent".into();
        cfg.fed.node = imported.node.clone();
        cfg.fed.coordinator = coord_addr.trim().to_string();
        cfg.save(&self.cfg_path)?;
        *self.cfg.write().expect("配置锁中毒") = cfg;
        self.bus.publish(SecurityEvent::engine(
            "info",
            format!(
                "已加入组织：{} → {}（自动连接中；GUI「组织」页可查看成员状态）",
                imported.node, coord_addr
            ),
        ));
        Ok(imported.message)
    }

    pub fn stats_24h(&self) -> Result<StatsSummary> {
        self.store.stats_since(now_ts() - 86400)
    }

    /// 主机暴露面盘点：枚举监听端口与归属进程，存快照并广播事件。
    pub fn scan_exposure(&self) -> Result<Vec<aisafeguard_detect::exposure::Entry>> {
        let entries = aisafeguard_detect::exposure::collect()?;
        let ts = now_ts();
        let json = serde_json::to_string(&entries)
            .map_err(|e| Error::Store(format!("序列化暴露面失败: {e}")))?;
        self.store.insert_exposure(ts, &json)?;
        self.bus.publish(SecurityEvent::engine(
            "info",
            format!("暴露面扫描完成：{} 个监听端点", entries.len()),
        ));
        Ok(entries)
    }

    /// 最近一次暴露面快照（None = 从未扫描）
    pub fn latest_exposure(&self) -> Result<Option<ExposureSnapshot>> {
        let Some((ts, json)) = self.store.latest_exposure()? else {
            return Ok(None);
        };
        let entries = serde_json::from_str(&json)
            .map_err(|e| Error::Store(format!("解析暴露面快照失败: {e}")))?;
        Ok(Some(ExposureSnapshot { ts, entries }))
    }

    /// 添加并应用一条封禁规则（防火墙 + 记账 + 事件广播），永久有效。
    pub fn add_block(&self, spec: &BlockSpec, origin: &str) -> Result<RuleRow> {
        self.add_block_ex(spec, origin, None)
    }

    /// 带 TTL 的自动封禁：到期由解封任务移除。
    pub fn add_block_ex(
        &self,
        spec: &BlockSpec,
        origin: &str,
        expires_ts: Option<i64>,
    ) -> Result<RuleRow> {
        apply_block(
            &*self.firewall,
            &self.store,
            &self.bus,
            spec,
            origin,
            expires_ts,
        )
    }

    pub fn remove_rule(&self, id: i64) -> Result<()> {
        let row = self
            .store
            .get_rule(id)?
            .ok_or_else(|| Error::Store(format!("规则 #{id} 不存在")))?;
        if !row.name.starts_with(RULE_PREFIX) {
            return Err(Error::Firewall(format!(
                "拒绝删除非 AI-SafeGuard 规则: {}",
                row.name
            )));
        }
        let direction = if row.direction == "in" {
            Direction::In
        } else {
            Direction::Out
        };
        let spec = BlockSpec {
            direction,
            protocol: row.protocol.parse().unwrap_or(Protocol::Any),
            remote_ip: row.remote_ip.parse::<IpAddr>().ok(),
            local_port: row.local_port,
            note: row.note.clone(),
            tag: row.tag.clone(),
        };
        self.firewall.remove(&row.name, &spec)?;
        self.store.delete_rule(id)?;
        self.bus.publish(SecurityEvent::FirewallRuleRemoved {
            ts: now_ts(),
            name: row.name,
        });
        Ok(())
    }

    pub fn apply_proposal(&self, id: i64) -> Result<RuleRow> {
        // 原子认领（F795 C2）：pending→applying 抢占成功才继续，防并发双应用
        // 双封禁（Web 手点 / API / 自动应用回扫三通道并发）
        if !self
            .store
            .set_proposal_status_if(id, "pending", "applying", None)?
        {
            return Err(Error::Store(format!("建议 #{id} 不存在或已被处理")));
        }
        let p = self
            .store
            .get_proposal(id)?
            .ok_or_else(|| Error::Store(format!("建议 #{id} 不存在")))?;
        // F793 补全：观察类（credential_spray）的人工应用 = 「确认封禁」——人工点击
        // 即构成 H310 所等的人工确认，走正常 block 路径按建议自带 TTL 灰度封禁。
        // 红线不变：AI 自动应用仍只作用于 block（auto_apply_policy_ok 门控）；
        // 仅登记不封的「确认战役」语义保留在 confirm 端点（egui）。
        let direction = match p.direction.as_str() {
            "in" => Direction::In,
            _ => Direction::Out,
        };
        let protocol = match p.protocol.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => Protocol::Any,
        };
        let remote_ip = if p.remote_ip.is_empty() {
            None
        } else {
            Some(
                p.remote_ip
                    .parse::<IpAddr>()
                    .map_err(|e| Error::Store(format!("建议中的 IP 非法: {e}")))?,
            )
        };
        // F300「组织」来源位：组织建议（model fed:*）落 org 来源，可解释文案
        // 与 TTL 语义在 explain.rs 单独成路；本地 AI 建议维持 ai 来源
        let org = p.model.starts_with("fed:");
        let spec = BlockSpec {
            direction,
            protocol,
            remote_ip,
            local_port: p.local_port,
            note: if org {
                format!("组织建议 #{}: {}", p.id, p.reason)
            } else {
                format!("AI 建议 #{}: {}", p.id, p.reason)
            },
            tag: if org { "ORG".into() } else { "AI".into() },
        };
        // 灰度执行（AI 深度介入 v1）：建议应用即短 TTL 试运行，到期自动解封；
        // AI 明确给了 ttl_secs 用它的，否则用配置的默认灰度时长。人工"转正"才延长。
        let trial_ttl = p.ttl_secs.unwrap_or(self.config().ai.trial_ttl_secs as i64);
        let row = match self.add_block_ex(
            &spec,
            if org { "org" } else { "ai" },
            Some(now_ts() + trial_ttl),
        ) {
            Ok(r) => r,
            Err(e) => {
                // 封禁失败：认领回滚为 pending（人工可重试），不留死状态
                let _ = self
                    .store
                    .set_proposal_status_if(id, "applying", "pending", None);
                return Err(e);
            }
        };
        self.store
            .set_proposal_status_if(id, "applying", "applied", Some(row.id))?;
        self.bus.publish(SecurityEvent::ProposalApplied {
            ts: now_ts(),
            proposal_id: id,
            rule_name: row.name.clone(),
        });
        Ok(row)
    }

    pub fn dismiss_proposal(&self, id: i64) -> Result<()> {
        // 原子迁移即完整语义：pending 才可驳回，无需先读（不存在/已处理均 no-op）
        self.store
            .set_proposal_status_if(id, "pending", "dismissed", None)?;
        Ok(())
    }

    /// 灰度规则转正：TTL 延长到 promote_ttl_secs。只改记账（规则本体不动，
    /// 解封由既有 TTL 清扫任务负责），全程留痕。
    pub fn promote_rule(&self, id: i64) -> Result<RuleRow> {
        let row = self
            .store
            .get_rule(id)?
            .ok_or_else(|| Error::Store(format!("规则 #{id} 不存在")))?;
        if !row.name.starts_with(RULE_PREFIX) {
            return Err(Error::Firewall(format!(
                "拒绝转正非 AI-SafeGuard 规则: {}",
                row.name
            )));
        }
        if !row.enabled {
            return Err(Error::Store(format!("规则 #{id} 已禁用，无法转正")));
        }
        // 永久规则没有可延长的灰度窗，转正反而会把它变成 30 天 TTL——明确拒绝
        if row.expires_ts.is_none() {
            return Err(Error::Store(format!(
                "规则 {} 已是永久封禁，无需转正",
                row.name
            )));
        }
        let expires = now_ts() + self.config().ai.promote_ttl_secs as i64;
        self.store.mark_promoted(id, expires)?;
        let until = chrono::DateTime::from_timestamp(expires, 0)
            .map(|d| {
                d.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_default();
        self.bus.publish(SecurityEvent::engine(
            "info",
            format!("规则 {} 已转正（封禁延长至 {until}）", row.name),
        ));
        let mut updated = row;
        updated.expires_ts = Some(expires);
        updated.promoted = true;
        Ok(updated)
    }

    /// 误报反馈：记录（30 天抑制期）+ 解除该来源的全部自动封禁（engine/ai 来源，
    /// 人工手动添加的规则不动）+ 收弃该来源的 pending 建议。全程留痕。
    pub fn mark_false_positive(
        &self,
        ip_str: &str,
        note: &str,
        local_port: Option<u16>,
    ) -> Result<(i64, usize)> {
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|e| Error::Store(format!("IP 非法: {e}")))?;
        if aisafeguard_core::is_protected_ip(ip) {
            return Err(Error::Store(
                "内网/回环地址本就受自动封禁保护，无需误报标记".into(),
            ));
        }
        let src = ip.to_string();
        // 进提示词与库的都按不可信输入清洗
        let note: String = note.chars().filter(|c| !c.is_control()).take(200).collect();
        self.store
            .insert_fp_feedback(&src, now_ts(), &note, local_port)?;
        let dismissed = self.store.dismiss_pending_proposals_for_ip(&src)?;
        let mut removed = 0usize;
        for r in self.store.list_rules()? {
            let auto = matches!(r.origin.as_str(), "engine" | "ai");
            if auto && r.enabled && r.remote_ip == src && self.remove_rule(r.id).is_ok() {
                removed += 1;
            }
        }
        self.bus.publish(SecurityEvent::engine(
            "info",
            format!(
                "误报反馈：{src} 已标记（自动封禁抑制 {}；解封 {removed} 条规则，收弃 {dismissed} 条建议）",
                crate::explain::humanize_secs(self.config().ai.fp_suppress_secs as i64)
            ),
        ));
        Ok((dismissed, removed))
    }

    /// 蜜罐监听器热启停（0.5.12）：即时生效；配置内监听器同时把 enabled 写回
    /// config.toml（重启后保持一致）。模板监听器只在运行时切换——其来源是
    /// 模板目录，重启后按模板状态拉起。
    pub fn toggle_listener(&self, name: &str, run: bool) -> Result<()> {
        let cfg = self.config();
        if !cfg.honeypot.enabled {
            return Err(Error::Config(
                "蜜罐总开关未开启——先启用蜜罐并重启程序，再使用热启停".into(),
            ));
        }
        let in_config = cfg.honeypot.listeners.iter().any(|l| l.name == name);
        if run {
            self.honeypot.start_listener(name).map_err(Error::Config)?;
        } else {
            self.honeypot.stop_listener(name).map_err(Error::Config)?;
        }
        if in_config {
            let mut new_cfg = cfg.clone();
            if let Some(row) = new_cfg
                .honeypot
                .listeners
                .iter_mut()
                .find(|l| l.name == name)
            {
                row.enabled = run;
            }
            new_cfg.save(&self.cfg_path)?;
            *self.cfg.write().expect("配置锁中毒") = new_cfg;
        }
        self.bus.publish(SecurityEvent::engine(
            "info",
            format!(
                "蜜罐 [{name}] 已热{}（即时生效{}）",
                if run { "启动" } else { "停止" },
                if in_config {
                    "，已写入配置"
                } else {
                    "（模板监听器，配置源自模板目录）"
                }
            ),
        ));
        Ok(())
    }

    /// 确认凭证喷洒战役（0.5.11 H310）：credential_spray 类建议的人工确认入口。
    /// 不是封禁——登记为「已确认进入观察」（灰度 TTL 到期后自然淡出 AI 上下文），
    /// 并广播 ProposalApplied 留痕。
    pub fn confirm_campaign(&self, id: i64) -> Result<()> {
        let p = self
            .store
            .get_proposal(id)?
            .ok_or_else(|| Error::Store(format!("建议 #{id} 不存在")))?;
        if p.action != "credential_spray" {
            return Err(Error::Store(
                "只有 credential_spray 类建议使用「确认战役」".into(),
            ));
        }
        if p.status != "pending" {
            return Err(Error::Store(format!(
                "建议 #{id} 状态为 {}，无法确认",
                p.status
            )));
        }
        if !self
            .store
            .set_proposal_status_if(id, "pending", "applied", None)?
        {
            return Err(Error::Store(format!("建议 #{id} 已被处理")));
        }
        self.bus.publish(SecurityEvent::ProposalApplied {
            ts: now_ts(),
            proposal_id: id,
            rule_name: format!("凭证喷洒战役观察: {}", p.remote_ip),
        });
        Ok(())
    }

    /// 清除某来源的误报抑制（0.4.0 B3）：删除后该来源恢复自动封禁资格并留痕。
    pub fn clear_false_positive(&self, value: &str) -> Result<usize> {
        value
            .parse::<IpAddr>()
            .map_err(|e| Error::Config(format!("IP 非法: {e}")))?;
        let removed = self.store.clear_fp_feedback(value)?;
        if removed > 0 {
            self.bus.publish(SecurityEvent::engine(
                "info",
                format!("误报抑制已清除：{value}（恢复自动封禁资格）"),
            ));
        }
        Ok(removed)
    }

    /// 触发一次 AI 分析（异步执行，状态通过事件与 ai_running 标志反馈）。
    /// 返回 false 表示已有分析在运行。
    pub fn trigger_analysis(self: &Arc<Self>) -> bool {
        if self.ai_running.swap(true, Ordering::Relaxed) {
            return false;
        }
        let eng = Arc::clone(self);
        // drop guard 复位：run_analysis 内任一 panic 都不能让 ai_running 永久卡死
        //（否则一次 panic 断绝后续所有手动+定时分析）
        let guard = AiRunningGuard(Arc::clone(self));
        self.rt.spawn(async move {
            let _guard = guard;
            run_analysis(&eng).await;
        });
        true
    }

    /// AI 定时分析（0.4.0 A4 接线）：`[ai].analyze_interval_secs` 此前只有配置没有
    /// 消费者，分析全靠手动触发。本任务每轮读最新配置——enabled / interval /
    /// auto_apply 全部热更；ai_running 标志防重入（手动与定时共用同一闸门）。
    /// 首跑延迟 30s（与情报/暴露面任务的启动先例一致，避开启动窗口）。
    pub fn spawn_ai_task(self: &Arc<Self>) {
        let eng = Arc::clone(self);
        let rt = eng.rt.clone();
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            loop {
                let cfg = eng.config().ai;
                if cfg.enabled {
                    eng.trigger_analysis();
                }
                let interval = cfg.analyze_interval_secs.clamp(30, 86_400);
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });
    }

    pub fn save_config(&self, new_cfg: AppConfig) -> Result<()> {
        let old = self.config();
        // 热更/重启分界（A4/A5 契约，定义见 AppConfig::restart_required）
        let req = AppConfig::restart_required(&old, &new_cfg);
        new_cfg.save(&self.cfg_path)?;
        *self.cfg.write().expect("配置锁中毒") = new_cfg;
        let msg = if req.is_empty() {
            "配置已保存（改动全部热更生效，无需重启）".to_string()
        } else {
            format!("配置已保存；以下需重启生效：{}", req.join("、"))
        };
        self.bus.publish(SecurityEvent::engine("info", msg));
        Ok(())
    }

    /// config.toml 原文（Web 控制台配置编辑器，F760）。
    pub fn config_raw(&self) -> Result<String> {
        std::fs::read_to_string(&self.cfg_path)
            .map_err(|e| Error::Config(format!("读取 {} 失败: {e}", self.cfg_path.display())))
    }

    /// 原文应用配置：先解析校验（非法 TOML 不落盘、不动运行态），再落盘 + 热更。
    /// 写盘走 toml_edit 保留原文注释与排版（F790：配置文件自带字段说明，编辑不丢），
    /// 运行态推进与 save_config 相同。返回需重启生效的项名列表（空 = 全部热更）。
    pub fn apply_config_raw(&self, raw: &str) -> Result<Vec<String>> {
        let cfg: AppConfig =
            toml::from_str(raw).map_err(|e| Error::Config(format!("TOML 解析失败: {e}")))?;
        let doc: toml_edit::DocumentMut = raw
            .parse()
            .map_err(|e| Error::Config(format!("TOML 解析失败: {e}")))?;
        let req = AppConfig::restart_required(&self.config(), &cfg);
        std::fs::write(&self.cfg_path, doc.to_string())
            .map_err(|e| Error::Config(format!("写入配置失败: {e}")))?;
        *self.cfg.write().expect("配置锁中毒") = cfg;
        let msg = if req.is_empty() {
            "配置已保存（改动全部热更生效，无需重启）".to_string()
        } else {
            format!("配置已保存；以下需重启生效：{}", req.join("、"))
        };
        self.bus.publish(SecurityEvent::engine("info", msg));
        Ok(req.into_iter().map(String::from).collect())
    }
}

/// 封禁落地：防火墙 + 记账 + 事件广播。依赖收窄成 trait/引用，便于集成测试
/// （检测→封禁链路在单机上无法从真实流量触发，见 engine 单测）。
pub(crate) fn apply_block(
    fw: &dyn Firewall,
    store: &Store,
    bus: &EventBus,
    spec: &BlockSpec,
    origin: &str,
    expires_ts: Option<i64>,
) -> Result<RuleRow> {
    if spec.remote_ip.is_none() && spec.local_port.is_none() {
        return Err(Error::Firewall("必须指定来源 IP 或目标端口之一".into()));
    }
    let name = new_rule_name();
    fw.add_block(&name, spec)?;
    let row = store.insert_rule(
        &name,
        spec.direction.as_str(),
        spec.protocol.as_str(),
        &spec.remote_ip.map(|i| i.to_string()).unwrap_or_default(),
        spec.local_port,
        origin,
        &spec.note,
        &spec.tag,
        expires_ts,
    )?;
    bus.publish(SecurityEvent::FirewallRuleAdded {
        ts: now_ts(),
        name,
        detail: spec.describe(),
        origin: origin.into(),
    });
    Ok(row)
}

/// 快路径判定的落地依赖（防火墙/记账/事件总线，测试可注入假后端）。
pub(crate) struct DetectionSink<'a> {
    pub fw: &'a dyn Firewall,
    pub store: &'a Store,
    pub bus: &'a EventBus,
    /// 误报抑制期（秒，0.4.0 B3 可配置）——快路径自动封禁跳过抑制期来源
    pub fp_suppress_secs: i64,
}

/// 本产品自身 API 攻击面清单（<self_endpoints> 段静态部分）。
/// 与 api.rs 的路由保持同步——加端点时这里也要加（AI 自检的输入完整性依赖它）。
const SELF_API_ENDPOINTS: &[&str] = &[
    "GET /api/status — 状态总览",
    "GET /api/events — 事件查询",
    "GET/POST /api/rules；DELETE /api/rules/{id} — 防火墙规则管理",
    "POST /api/rules/{id}/promote — 灰度规则转正",
    "GET /api/proposals；POST /api/proposals/{id}/apply|dismiss — AI 建议",
    "POST /api/feedback — 误报反馈",
    "DELETE /api/feedback/{ip} — 清除误报抑制",
    "GET /api/stats、GET/POST /api/exposure[*/scan] — 统计与暴露面",
    "GET /api/intel、POST /api/intel/refresh — 威胁情报",
    "GET/POST /api/config — 配置读写",
    "GET/POST/DELETE /api/ai/key — AI Key 管理",
    "GET /api/ai/runs、POST /api/ai/analyze — AI 分析",
    "POST /api/honeypot/listeners/{name}/start|stop — 蜜罐监听器热启停（0.5.12）",
    "GET /api/fed/panel — 组织面板数据（0.6 F500，只读）",
    "POST /api/fed/members/{node}/quarantine|lift — 软隔离与解除（0.6 F500，与 CLI 同通路）",
    "POST /api/fed/members/{node}/revoke — 吊销驱离成员（0.7，两步确认）",
    "POST /api/fed/join/request|approve|import — 入伙向导三件套（0.7 F740）",
    "GET/PUT /api/config/raw — 配置原文读写（F790 Web 控制台，服务端校验落盘）",
    "POST /api/service/restart — 服务自重启（F790 v1.1，Linux systemd）",
    "POST /api/xdp/clear — XDP 快速层清空（0.5.1 G3）",
    "POST /api/proposals/{id}/confirm — 观察类建议确认战役（0.5.11 H310）",
];

/// 本产品自身攻击面快照（<self_endpoints> 段动态部分：协同开关等运行事实）。
fn self_surface_json(eng: &EngineHandle) -> String {
    let cfg = eng.config();
    serde_json::json!({
        "api": {
            "bind": "127.0.0.1（仅本机回环）",
            "auth": "Bearer token（凭据管理器/数据目录文件，不落 config）",
            "endpoints": SELF_API_ENDPOINTS,
        },
        "fed": {
            "enabled": cfg.fed.enabled,
            "role": cfg.fed.role,
            "auth": "mTLS：独立监听面，客户端证书须链到组织 CA（fed init-ca / issue-cert 签发），node↔证书指纹绑定",
        },
        "honeypot": "TCP 蜜罐端口有意对攻击者暴露（诱捕面，非攻击面）",
    })
    .to_string()
}

/// Detection 事件的可选 L7 字段（0.5.0 E6/E5）：full 捕获流前缀可解析时出现，
/// 由 [detect.l7] 开关门控。空字段不进事件。
#[derive(Default)]
struct L7Evidence {
    hint: Option<aisafeguard_l7::HttpHint>,
    ja3: Option<String>,
    ja4: Option<String>,
}

/// 快路径判定统一出口：广播 Detection；auto 时自动封禁（TTL + 内网保护 + 审计）。
/// 频次引擎（蜜罐源）与采样捕获（真实流量源）都走这里，行为一致。
/// F6 解耦：是否自动封禁由调用方决定——内置检测器看 [detect].auto_block，
/// 规则命中看 [detect.rules].auto_block（默认 false 只告警）。
// 参数并列了判定/处置/L7 三组语义字段，逐位传参比拆结构体更直白
#[allow(clippy::too_many_arguments)]
fn handle_detection(
    sink: &DetectionSink<'_>,
    kind: &str,
    ip: IpAddr,
    evidence: &str,
    rule_id: Option<&str>,
    dcfg: &DetectConfig,
    auto_block: bool,
    severity: &str,
    l7: L7Evidence,
) {
    let src = ip.to_string();
    sink.bus.publish(SecurityEvent::Detection {
        ts: now_ts(),
        kind: kind.to_string(),
        src_ip: src.clone(),
        confidence: "high".into(),
        severity: severity.to_string(),
        evidence: evidence.to_string(),
        rule_id: rule_id.map(str::to_string),
        http_hint: l7.hint,
        tls_fingerprint: l7.ja3,
        tls_ja4: l7.ja4,
    });
    if !auto_block {
        return;
    }
    // 内网保护对自动封禁全局生效
    if aisafeguard_core::is_protected_ip(ip) {
        sink.bus.publish(SecurityEvent::engine(
            "info",
            format!("内网保护：跳过对 {src} 的自动封禁（{kind}）"),
        ));
        return;
    }
    // 误报反馈：用户已判定该来源为正常业务，自动封禁跳过（人工封禁不受影响）
    if sink
        .store
        .active_fp(&src, now_ts(), sink.fp_suppress_secs, None)
        .unwrap_or(false)
    {
        sink.bus.publish(SecurityEvent::engine(
            "info",
            format!("误报反馈抑制：跳过对 {src} 的自动封禁（{kind}）"),
        ));
        return;
    }
    let spec = BlockSpec {
        direction: Direction::In,
        protocol: Protocol::Any,
        remote_ip: Some(ip),
        local_port: None,
        note: format!("检测器自动封禁（TTL {}s）: {evidence}", dcfg.ttl_secs),
        tag: "检测器".into(),
    };
    match apply_block(
        sink.fw,
        sink.store,
        sink.bus,
        &spec,
        "engine",
        Some(now_ts() + dcfg.ttl_secs),
    ) {
        Ok(row) => {
            let until = row
                .expires_ts
                .and_then(|t| {
                    chrono::DateTime::from_timestamp(t, 0).map(|d| {
                        d.with_timezone(&chrono::Local)
                            .format("%H:%M:%S")
                            .to_string()
                    })
                })
                .unwrap_or_default();
            // via=xdp（0.5.1 G3）：命中规则的封禁已镜像内核快速丢弃路径时留痕，
            // 避免与 nftables 双执行的可观测性混淆
            let via_xdp = sink.fw.backend() == "nftables+xdp"
                && aisafeguard_xdp::composite::mirrorable(&spec).is_some();
            let via = if via_xdp { "；via=xdp" } else { "" };
            sink.bus.publish(SecurityEvent::engine(
                "info",
                format!("已自动封禁 {src} 至 {until}（规则 {}）{via}", row.name),
            ));
        }
        Err(e) => {
            sink.bus.publish(SecurityEvent::engine(
                "error",
                format!("自动封禁 {src} 失败: {e}"),
            ));
        }
    }
}

/// F310 ioc-hit 标签：stix 导入的 IOC 命中本地事件流时打标（只告警，不改任何
/// 检测/处置行为——自动封禁门控另有 confidence/kind 双保险排除 stix 源）。
/// 缓存 60 秒：CLI 导入的清单最迟一个缓存周期对运行中引擎生效。
pub fn tag_ioc_hit(
    store: &Store,
    cache: &mut (i64, std::collections::HashSet<String>),
    ev: &mut SecurityEvent,
) {
    let (ip, text) = match ev {
        SecurityEvent::HoneypotHit {
            remote_ip, summary, ..
        } => (remote_ip.clone(), summary),
        SecurityEvent::Detection {
            src_ip, evidence, ..
        } => (src_ip.clone(), evidence),
        _ => return,
    };
    if ip.is_empty() {
        return;
    }
    let now = now_ts();
    if now - cache.0 > 60 {
        cache.0 = now;
        cache.1.clear();
        cache.1.extend(
            store
                .active_intel(now)
                .unwrap_or_default()
                .into_iter()
                .filter(|r| r.source.starts_with("stix:"))
                .map(|r| r.value),
        );
    }
    if cache.1.contains(&ip) && !text.contains("ioc-hit") {
        text.push_str(" [ioc-hit]");
    }
}

/// 快路径：消费蜜罐命中事件，产出 Detection 判定；
/// auto_block 开启时自动封禁（TTL + 内网保护），全程留痕。
/// 0.5.0 F4：规则子集引擎在蜜罐 payload 全窗上匹配（enabled 时）。
pub fn spawn_detect_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut rx = eng.bus.subscribe();
        loop {
            match rx.recv().await {
                Ok(SecurityEvent::HoneypotHit {
                    remote_ip,
                    listener,
                    port,
                    remote_port,
                    payload,
                    ..
                }) => {
                    let Ok(ip) = remote_ip.parse::<IpAddr>() else {
                        continue;
                    };
                    let cfg = eng.config().detect;
                    for d in eng.detect.observe(now_ts(), ip, &listener, port, &cfg) {
                        handle_detection(
                            &DetectionSink {
                                fw: &*eng.firewall,
                                store: &eng.store,
                                bus: &eng.bus,
                                fp_suppress_secs: eng.config().ai.fp_suppress_secs as i64,
                            },
                            d.kind,
                            ip,
                            &d.evidence,
                            None,
                            &cfg,
                            cfg.auto_block,
                            "medium",
                            L7Evidence::default(),
                        );
                    }
                    // 规则子集匹配：payload 即窗口（蜜罐会话完整载荷），方向恒 client→server
                    let rcfg = &cfg.rules;
                    if rcfg.enabled && !payload.is_empty() {
                        let is_home = |ip: IpAddr| aisafeguard_core::is_protected_ip(ip);
                        let session = aisafeguard_rules::matcher::Session {
                            client_ip: ip,
                            client_port: remote_port,
                            // 蜜罐事件未带本机 IP；any/$HOME_NET 头即命中（本机侧恒 home）
                            server_ip: IpAddr::from([0, 0, 0, 0]),
                            server_port: port,
                            to_server: true,
                            proto: aisafeguard_rules::ir::Proto::Tcp,
                            is_home: &is_home,
                        };
                        for hit in
                            scan_rules(&eng.rules, rcfg, payload.as_bytes(), &session, ip, None)
                        {
                            let evidence = format!(
                                "{msg}（规则 {rid}；{c}:{cp} → 蜜罐[{l}]:{p}）",
                                msg = hit.msg,
                                rid = hit.rule_id,
                                c = remote_ip,
                                cp = remote_port,
                                l = listener,
                                p = port,
                            );
                            eng.rules.add_hit();
                            handle_detection(
                                &DetectionSink {
                                    fw: &*eng.firewall,
                                    store: &eng.store,
                                    bus: &eng.bus,
                                    fp_suppress_secs: eng.config().ai.fp_suppress_secs as i64,
                                },
                                "signature",
                                ip,
                                &evidence,
                                Some(&hit.rule_id),
                                &cfg,
                                rcfg.auto_block,
                                hit.severity,
                                L7Evidence::default(),
                            );
                        }
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("频次检测通道落后 {n} 条");
                }
                Err(_) => break,
            }
        }
    });
}

/// 规则子集扫描（0.5.0 F4）：在窗口上执行当前生效规则集，应用 threshold 与
/// 采样路径的流级去重，返回放行的命中。只读规则集 + 判定——不碰防火墙（F6：
/// 是否自动封禁由调用方按 [detect.rules].auto_block 决定）。
fn scan_rules(
    rules: &RulesState,
    rcfg: &aisafeguard_core::config::RulesConfig,
    window: &[u8],
    session: &aisafeguard_rules::matcher::Session<'_>,
    threshold_src: IpAddr,
    flow_dedup_key: Option<&str>,
) -> Vec<aisafeguard_rules::matcher::RuleHit> {
    if !rcfg.enabled {
        return Vec::new();
    }
    let Some(ruleset) = rules.current() else {
        return Vec::new();
    };
    let now = now_ts();
    let mut out = Vec::new();
    for rule in &ruleset.rules {
        if !aisafeguard_rules::matcher::rule_matches(rule, window, session) {
            continue;
        }
        if let Some(t) = &rule.threshold {
            let key = if t.by_src {
                format!("{}:{threshold_src}", rule.sid)
            } else {
                rule.sid.to_string()
            };
            let mut tt = rules.threshold.lock().expect("threshold 锁中毒");
            if !tt.allow(t, &key, now) {
                continue;
            }
        }
        if let Some(dk) = flow_dedup_key {
            // 同 (sid, 流) 10 分钟内只报一次：流前缀持续在窗口里，不有意重复刷事件
            let key = format!("{}:{dk}", rule.sid);
            let fired = now
                - rules
                    .fired_flows
                    .lock()
                    .expect("流去重锁中毒")
                    .get(&key)
                    .copied()
                    .unwrap_or(0);
            if fired < 600 {
                continue;
            }
            let mut map = rules.fired_flows.lock().expect("流去重锁中毒");
            if map.len() > 65536 {
                map.clear();
            }
            map.insert(key, now);
        }
        out.push(aisafeguard_rules::matcher::to_hit(rule));
    }
    out
}

/// 凭证采集与本地喷洒检测（0.5.10 H200）：订阅 CredentialObserved 事件 →
/// 落独立凭证库（<data_dir>/honeypot/credentials.db，文件 0600，只有哈希）→
/// 两路判定都走 handle_detection 统一入口（内网保护 / 误报抑制 / auto_block
/// 约束全部继承，AI 不可用不受影响）：
/// 1. credential_spray：蜜罐收到的用户名与本机账号同名（快照比对，高严重度）；
/// 2. credential_reuse：同一来源跨协议提交同一口令（按哈希聚合，中严重度告警）。
///
/// 节流：同 (来源, 判定键) 24h 只发一次，防撞库脚本高频刷屏。
pub fn spawn_credential_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let cred_store = Arc::clone(&eng.credentials);
        // 本地账号快照：启动立即枚举一次，之后按 [honeypot.credentials].
        // snapshot_interval_secs 周期刷新（0 = 仅启动一次）；只取用户名集合
        {
            let eng = Arc::clone(&eng);
            let accounts = Arc::clone(&eng.local_accounts);
            let rt = eng.rt.clone();
            rt.spawn(async move {
                loop {
                    match aisafeguard_core::accounts::local_usernames() {
                        Ok(names) => {
                            *accounts.write().expect("账号快照锁") = names.into_iter().collect();
                        }
                        Err(e) => eng.bus.publish(SecurityEvent::engine(
                            "warn",
                            format!("本地账号快照枚举失败（喷洒比对暂停）: {e}"),
                        )),
                    }
                    let interval = eng.config().honeypot.credentials.snapshot_interval_secs;
                    if interval == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(interval.max(60))).await;
                }
            });
        }
        let mut rx = eng.bus.subscribe();
        let mut spray_fired: HashMap<(String, String), i64> = HashMap::new();
        let mut reuse_fired: HashMap<(String, String), i64> = HashMap::new();
        loop {
            match rx.recv().await {
                Ok(SecurityEvent::CredentialObserved {
                    ts,
                    listener,
                    kind,
                    port,
                    remote_ip,
                    remote_port,
                    username,
                    pass_hash,
                }) => {
                    if !eng.config().honeypot.credentials.enabled {
                        continue;
                    }
                    // 此处只有哈希后的形态；明文在蜜罐会话内已被丢弃
                    let hash = pass_hash.unwrap_or_default();
                    let record = aisafeguard_store::CredentialRecord {
                        ts,
                        remote_ip: &remote_ip,
                        remote_port,
                        listener: &listener,
                        protocol: &kind,
                        username: &username,
                        pass_hash: &hash,
                    };
                    if let Err(e) = cred_store.insert(record) {
                        eng.bus
                            .publish(SecurityEvent::engine("error", format!("凭证入库失败: {e}")));
                        continue;
                    }
                    let Ok(ip) = remote_ip.parse::<IpAddr>() else {
                        continue;
                    };
                    let now = now_ts();
                    let dcfg = eng.config().detect;
                    let is_local = eng
                        .local_accounts
                        .read()
                        .expect("账号快照锁")
                        .contains(&username.to_lowercase());
                    // 1) 用户名命中本机账号 → credential_spray（直推快路径）
                    if is_local && fire_once(&mut spray_fired, (&remote_ip, &username), now) {
                        handle_detection(
                            &DetectionSink {
                                fw: &*eng.firewall,
                                store: &eng.store,
                                bus: &eng.bus,
                                fp_suppress_secs: eng.config().ai.fp_suppress_secs as i64,
                            },
                            "credential_spray",
                            ip,
                            &format!(
                                "蜜罐收到与本地账号同名的登录尝试: 用户 {username} ({kind} :{port})"
                            ),
                            None,
                            &dcfg,
                            dcfg.auto_block,
                            "high",
                            L7Evidence::default(),
                        );
                    }
                    // 2) 跨协议同口令 → credential_reuse（聚合告警，不直接处置）
                    if !hash.is_empty() && fire_once(&mut reuse_fired, (&remote_ip, &hash), now) {
                        let protocols = cred_store
                            .hash_protocol_count(&remote_ip, &hash, now - 86_400)
                            .unwrap_or(0);
                        if protocols >= 2 {
                            handle_detection(
                                &DetectionSink {
                                    fw: &*eng.firewall,
                                    store: &eng.store,
                                    bus: &eng.bus,
                                    fp_suppress_secs: eng.config().ai.fp_suppress_secs as i64,
                                },
                                "credential_reuse",
                                ip,
                                &format!(
                                    "同一来源跨 {protocols} 种协议提交相同口令（撞库/喷洒特征）"
                                ),
                                None,
                                &dcfg,
                                false,
                                "medium",
                                L7Evidence::default(),
                            );
                        }
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("凭证采集通道落后 {n} 条");
                }
                Err(_) => break,
            }
        }
    });
}

/// 同一判定键 24h 只触发一次；键集合超限先清过期项再放行新键。
fn fire_once(fired: &mut HashMap<(String, String), i64>, key: (&str, &str), now: i64) -> bool {
    let k = (key.0.to_string(), key.1.to_string());
    if fired.get(&k).is_some_and(|t| now - *t < 86_400) {
        return false;
    }
    if fired.len() > 10_000 {
        fired.retain(|_, t| now - *t < 86_400);
    }
    fired.insert(k, now);
    true
}

/// 规则包装载任务（0.5.0 F5）：启动即加载；之后每 5 秒检查规则包文件签名
/// （mtime + 长度），变化即整包重载、原子替换；加载失败保持旧包生效并留事件。
/// 关闭（enabled=false 或 path 清空）即卸载当前规则集——无残留强制路径。
pub fn spawn_rules_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut last_sig: Option<(std::time::SystemTime, u64)> = None;
        loop {
            let cfg = eng.config().detect.rules;
            if cfg.enabled && !cfg.path.is_empty() {
                let sig = std::fs::metadata(&cfg.path)
                    .ok()
                    .and_then(|m| m.modified().ok().zip(Some(m.len())));
                if sig != last_sig {
                    match aisafeguard_rules::loader::load_package_file(
                        std::path::Path::new(&cfg.path),
                        cfg.max_rules,
                    ) {
                        Ok(rs) => {
                            let note = format!(
                                "已加载 {} 条规则（sha256 前 8 位 {}）",
                                rs.rule_count,
                                &rs.sha256[..8.min(rs.sha256.len())]
                            );
                            eng.rules.set_current(Some(Arc::new(rs)), &cfg.path, &note);
                            eng.bus.publish(SecurityEvent::engine(
                                "info",
                                format!("规则包加载成功：{note}"),
                            ));
                        }
                        Err(e) => {
                            // 整包拒绝：新包不生效，旧包（若有）保持——不动 current，
                            // 避免一次坏文件让检测引擎当场全盲（与注释承诺一致）
                            eng.bus.publish(SecurityEvent::engine(
                                "error",
                                format!("规则包加载失败（整包拒绝，不半生效，保留旧包）: {e}"),
                            ));
                        }
                    }
                    last_sig = sig;
                }
            } else if last_sig.is_some() || eng.rules.current().is_some() {
                eng.rules
                    .set_current(None, "", "规则引擎未启用或未配置规则包路径");
                eng.bus.publish(SecurityEvent::engine(
                    "info",
                    "规则引擎已停用，卸载当前规则集",
                ));
                last_sig = None;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// 采样捕获任务（检测平台 MVP）：专用线程跑「平台捕获（Windows=WinDivert /
/// Linux=AF_PACKET）分发 → 解析 → 流表/检测器」，判定走 handle_detection
/// 与蜜罐快路径同一出口。
/// 捕获不可用（缺驱动/无提权/被杀软拦截）只降级不退出：状态写进 CaptureState + 事件留痕。
pub fn spawn_capture_task(eng: &Arc<EngineHandle>) {
    let cfg = eng.config().detect.capture;
    if !cfg.enabled {
        eng.bus.publish(SecurityEvent::engine(
            "info",
            "流量采样未启用（[detect.capture].enabled）",
        ));
        return;
    }
    if !cfg.valid_mode() {
        eng.bus.publish(SecurityEvent::engine(
            "error",
            format!("流量采样模式非法：{}（可用 control | full）", cfg.mode),
        ));
        return;
    }
    // 驱动完整性校验（0.4.0 A3，仅 Windows）：配置了期望哈希且驱动文件存在时启用——
    // 供应链防护，只认官方渠道获取的驱动；哈希不符降级并留事件，绝不静默继续。
    #[cfg(windows)]
    if !cfg.driver_sha256.is_empty()
        && let Some(sys_path) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("WinDivert64.sys")))
        && sys_path.exists()
    {
        use sha2::Digest as _;
        let checked = std::fs::read(&sys_path).map(|bytes| {
            let digest = sha2::Sha256::digest(&bytes);
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        });
        match checked {
            Ok(hex) if hex.eq_ignore_ascii_case(cfg.driver_sha256.trim()) => {}
            Ok(hex) => {
                let msg = "WinDivert64.sys SHA-256 与配置不符（driver_sha256），捕获已降级；请从官方渠道重新获取驱动";
                tracing::error!("驱动校验失败: 期望 {} 实际 {hex}", cfg.driver_sha256.trim());
                eng.capture.set_error(msg);
                eng.bus.publish(SecurityEvent::engine(
                    "error",
                    format!("流量采样不可用：{msg}"),
                ));
                return;
            }
            Err(e) => {
                eng.capture
                    .set_error("WinDivert64.sys 读取失败，捕获已降级");
                eng.bus.publish(SecurityEvent::engine(
                    "error",
                    format!("流量采样不可用：驱动读取失败: {e}"),
                ));
                return;
            }
        }
    }
    let eng = Arc::clone(eng);
    let eng_thread = Arc::clone(&eng);
    let spawn = std::thread::Builder::new()
        .name("capture-pipeline".into())
        .spawn(move || {
            let eng = eng_thread;
            let rx = match aisafeguard_detect::capture::spawn(&cfg.mode) {
                Ok(rx) => rx,
                Err(e) => {
                    eng.capture.set_error(&e);
                    eng.bus.publish(SecurityEvent::engine(
                        "error",
                        format!("流量采样不可用：{e}"),
                    ));
                    return;
                }
            };
            eng.capture.set_active(&cfg.mode);
            eng.bus.publish(SecurityEvent::engine(
                "info",
                format!(
                    "流量采样已启动（{} / {} 模式）",
                    aisafeguard_detect::capture::backend_name(),
                    cfg.mode
                ),
            ));

            let mut pipeline = aisafeguard_detect::inspect::CapturePipeline::new(&cfg);
            let mut last_sweep = now_ts();
            loop {
                use std::sync::mpsc::RecvTimeoutError;
                match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(frame) => {
                        let cap_cfg = eng.config().detect.capture;
                        for d in pipeline.on_frame(frame.ts, &frame.data, &cap_cfg) {
                            let mut evidence = d.evidence.clone();
                            if cap_cfg.mode == "full" {
                                let snippet = pipeline.payload_snippet(&d.key);
                                // 轻量 L7 标签（0.4.0 B2）：full 模式流前缀可识别时进证据
                                let l7 = aisafeguard_l7::tags_suffix(&aisafeguard_l7::http_tags(
                                    &snippet,
                                ));
                                evidence.push_str(&l7);
                                if !snippet.is_empty() {
                                    evidence.push_str(&format!("；载荷摘要: {snippet}"));
                                }
                            }
                            let dcfg = eng.config().detect;
                            // E6/E5 + H5：full 模式且 [detect.l7].enabled 时才解析
                            // HTTP 提示与 JA3/JA4（默认关——深检默认 off，热更即时生效）
                            let l7ev = if cap_cfg.mode == "full" && dcfg.l7.enabled {
                                match pipeline.stream_bytes(&d.key) {
                                    Some(stream) => {
                                        let hint = std::str::from_utf8(&stream)
                                            .ok()
                                            .and_then(aisafeguard_l7::parse_http_hint);
                                        let ja3 = if dcfg.l7.ja3 {
                                            aisafeguard_l7::parse_ja3(&stream).map(|j| j.md5)
                                        } else {
                                            None
                                        };
                                        let ja4 = if dcfg.l7.ja4 {
                                            aisafeguard_l7::parse_ja4(&stream)
                                        } else {
                                            None
                                        };
                                        L7Evidence { hint, ja3, ja4 }
                                    }
                                    None => L7Evidence::default(),
                                }
                            } else {
                                L7Evidence::default()
                            };
                            handle_detection(
                                &DetectionSink {
                                    fw: &*eng.firewall,
                                    store: &eng.store,
                                    bus: &eng.bus,
                                    fp_suppress_secs: eng.config().ai.fp_suppress_secs as i64,
                                },
                                d.kind,
                                d.src,
                                &evidence,
                                Some(d.rule_id),
                                &dcfg,
                                dcfg.auto_block,
                                "medium",
                                l7ev,
                            );
                        }
                        // 规则子集匹配（0.5.0 F4）：full 模式下有新载荷产出的流 →
                        // 重组流前缀整窗扫描；方向按纯 SYN 观测判定，未知时按
                        // client→server（攻击载荷的常态方向）
                        let rcfg = eng.config().detect.rules;
                        if rcfg.enabled && cap_cfg.mode == "full" {
                            for fkey in pipeline.take_dirty() {
                                let Some(stream) = pipeline.stream_bytes(&fkey) else {
                                    continue;
                                };
                                if stream.is_empty() {
                                    continue;
                                }
                                let to_server = pipeline.observed_syn(&fkey);
                                let (c_ip, c_port, s_ip, s_port) = if to_server {
                                    (fkey.src, fkey.src_port, fkey.dst, fkey.dst_port)
                                } else {
                                    (fkey.dst, fkey.dst_port, fkey.src, fkey.src_port)
                                };
                                let is_home = |ip: IpAddr| aisafeguard_core::is_protected_ip(ip);
                                let session = aisafeguard_rules::matcher::Session {
                                    client_ip: c_ip,
                                    client_port: c_port,
                                    server_ip: s_ip,
                                    server_port: s_port,
                                    to_server,
                                    proto: aisafeguard_rules::ir::Proto::Tcp,
                                    is_home: &is_home,
                                };
                                let dk = format!(
                                    "{}:{}->{}:{}",
                                    fkey.src, fkey.src_port, fkey.dst, fkey.dst_port
                                );
                                for hit in scan_rules(
                                    &eng.rules,
                                    &rcfg,
                                    &stream,
                                    &session,
                                    c_ip,
                                    Some(&dk),
                                ) {
                                    let evidence = format!(
                                        "{msg}（规则 {rid}；{c}:{cp} → {s}:{sp}）",
                                        msg = hit.msg,
                                        rid = hit.rule_id,
                                        c = c_ip,
                                        cp = c_port,
                                        s = s_ip,
                                        sp = s_port,
                                    );
                                    eng.rules.add_hit();
                                    handle_detection(
                                        &DetectionSink {
                                            fw: &*eng.firewall,
                                            store: &eng.store,
                                            bus: &eng.bus,
                                            fp_suppress_secs: eng.config().ai.fp_suppress_secs
                                                as i64,
                                        },
                                        "signature",
                                        c_ip,
                                        &evidence,
                                        Some(&hit.rule_id),
                                        &eng.config().detect,
                                        rcfg.auto_block,
                                        hit.severity,
                                        L7Evidence::default(),
                                    );
                                }
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let now = now_ts();
                        if now - last_sweep >= 10 {
                            pipeline.sweep(now, &eng.config().detect.capture);
                            last_sweep = now;
                            // 流统计快照随 sweep 刷新（AI 提示词输入，元数据与计数）
                            let (flow_count, top) = pipeline.flow_snapshot(5);
                            eng.capture.set_flows(FlowSnapshot {
                                flow_count,
                                top_syn: top
                                    .into_iter()
                                    .map(|(ip, syn_count)| SynSource {
                                        ip: ip.to_string(),
                                        syn_count,
                                    })
                                    .collect(),
                            });
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        eng.capture
                            .set_error("捕获线程已退出（驱动停止或句柄关闭）");
                        eng.bus.publish(SecurityEvent::engine(
                            "error",
                            "流量采样已停止：捕获线程退出",
                        ));
                        break;
                    }
                }
            }
        });
    if let Err(e) = spawn {
        eng.capture.set_error(&format!("启动捕获线程失败: {e}"));
        eng.bus.publish(SecurityEvent::engine(
            "error",
            format!("流量采样不可用：启动捕获线程失败: {e}"),
        ));
    }
}

/// 两条规则是否落在同一防火墙元素上（F793）：同来源 IP + 同方向 + 粒度交叠。
/// nftables/XDP 的封禁元素按（方向, IP, 粒度）键控：IP 级（无端口）与端口级是
/// 不同集合；端口级需同端口且协议有交集（any 与 tcp/udp 同端口共享拼接集合）。
/// 元素共享的后端上，先到期规则的删除会连带拆掉后到期规则的封禁——解封任务
/// 据此跳过防火墙删除、只清记账，封禁实际生效期 = 同元素规则的叠加最大值。
fn same_element(a: &aisafeguard_store::RuleRow, b: &aisafeguard_store::RuleRow) -> bool {
    if a.remote_ip.is_empty() || a.remote_ip != b.remote_ip || a.direction != b.direction {
        return false;
    }
    match (a.local_port, b.local_port) {
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
        (Some(pa), Some(pb)) => {
            pa == pb
                && match (a.protocol.as_str(), b.protocol.as_str()) {
                    ("any", _) | (_, "any") => true,
                    (x, y) => x == y,
                }
        }
    }
}

/// TTL 到期自动解封：每 60 秒扫一次到期规则，移除防火墙规则并留痕。
pub fn spawn_expiry_janitor(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // 连续失败轮次计数：同样的基础设施错误每 60s 一条 error 事件 = 1440 条/天
        // 刷爆事件页（10-15~10-18 实测 1948 条「element does not exist」毒环）——
        // 只在首轮与每 10 轮发事件，tracing 始终在
        let mut expiry_fail_streak: u32 = 0;
        // F798 m1：入站 IP 选项异常观察（Linux nft 资产；观察型不封禁，损坏不波及防火墙）
        #[cfg(target_os = "linux")]
        let mut ipopts = aisafeguard_firewall::ipopts::IpOptsMonitor::new();
        #[cfg(target_os = "linux")]
        let mut ipopts_fail_streak: u32 = 0;
        loop {
            ticker.tick().await;
            #[cfg(target_os = "linux")]
            {
                match ipopts.poll() {
                    Ok(snap) => {
                        ipopts_fail_streak = 0;
                        for ip in snap.new_sources.clone() {
                            eng.bus.publish(SecurityEvent::Detection {
                                ts: now_ts(),
                                kind: "ipopts".into(),
                                src_ip: ip.to_string(),
                                confidence: "deterministic".into(),
                                severity: "low".into(),
                                evidence: format!(
                                    "入站 IPv4 选项（IHL>5）：{}
累计 {} 包 / {} 源（观察型，不封禁）",
                                    ip,
                                    snap.total_packets,
                                    snap.sources.len()
                                ),
                                rule_id: None,
                                http_hint: None,
                                tls_fingerprint: None,
                                tls_ja4: None,
                            });
                        }
                    }
                    Err(e) => {
                        ipopts_fail_streak += 1;
                        // 首次 + 之后每 30 轮提醒一次（无提权环境长驻失败防日志风暴）
                        if ipopts_fail_streak == 1 || ipopts_fail_streak % 30 == 0 {
                            tracing::warn!(
                                "IP 选项观察轮询失败（连续 {} 次）: {e}",
                                ipopts_fail_streak
                            );
                        }
                    }
                }
            }
            let Ok(expired) = eng.store.expired_rules(now_ts()) else {
                continue;
            };
            if expired.is_empty() {
                continue;
            }
            // F793 元素共享语义：同元素还有别的活跃规则时，跳过防火墙删除
            //（只清记账）——封禁实际生效期 = 同元素规则的叠加最大值，而不是
            // 最早到期时间。本批到期的行不能作为「仍有覆盖」的依据。
            let shared = eng.firewall.removes_shared_element();
            let expired_ids: std::collections::HashSet<i64> =
                expired.iter().map(|r| r.id).collect();
            let active = if shared {
                eng.store.list_rules().unwrap_or_default()
            } else {
                Vec::new()
            };
            for row in expired {
                let name = row.name.clone();
                let spec = BlockSpec {
                    direction: if row.direction == "in" {
                        Direction::In
                    } else {
                        Direction::Out
                    },
                    protocol: row.protocol.parse().unwrap_or(Protocol::Any),
                    remote_ip: row.remote_ip.parse::<IpAddr>().ok(),
                    local_port: row.local_port,
                    note: row.note.clone(),
                    tag: row.tag.clone(),
                };
                let covered = shared
                    && active
                        .iter()
                        .any(|r| r.enabled && !expired_ids.contains(&r.id) && same_element(r, &row));
                if covered {
                    // 同元素仍有覆盖：防火墙元素保留（后到期规则的封禁语义），
                    // 只清本条记账
                    let _ = eng.store.delete_rule(row.id);
                    eng.bus.publish(SecurityEvent::engine(
                        "info",
                        format!(
                            "TTL 到期，{name}（{}）解除记账——同元素封禁仍由其他活跃规则覆盖，防火墙元素保留",
                            row.remote_ip
                        ),
                    ));
                    continue;
                }
                // 先防火墙后记账：remove 失败保留记账行，下轮重试——先删记账会让
                // remove 失败的规则变成无账孤儿（无重试、resync 也读不到）
                match eng.firewall.remove(&name, &spec) {
                    Ok(()) => {
                        expiry_fail_streak = 0;
                        let _ = eng.store.delete_rule(row.id);
                        eng.bus.publish(SecurityEvent::FirewallRuleRemoved {
                            ts: now_ts(),
                            name: name.clone(),
                        });
                        eng.bus.publish(SecurityEvent::engine(
                            "info",
                            format!("TTL 到期，自动解封 {name}（{}）", row.remote_ip),
                        ));
                    }
                    Err(e) => {
                        expiry_fail_streak += 1;
                        tracing::warn!("解封规则 {name} 失败（保留记账下轮重试）: {e}");
                        if expiry_fail_streak == 1 || expiry_fail_streak % 10 == 0 {
                            eng.bus.publish(SecurityEvent::engine(
                                "error",
                                format!(
                                    "解封规则 {name}（{}）失败，保留记账下轮重试（连续 {} 轮）: {e}",
                                    row.remote_ip, expiry_fail_streak
                                ),
                            ));
                        }
                    }
                }
            }
        }
    });
}

fn new_rule_name() -> String {
    format!("{}blk-{}", RULE_PREFIX, uuid::Uuid::new_v4().simple())
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

async fn run_analysis(eng: &Arc<EngineHandle>) {
    let cfg = eng.config();
    let key = cfg.ai.effective_key();
    if !cfg.ai.enabled {
        let msg = "AI 分析未启用（设置中开启）".to_string();
        let _ = eng.store.insert_ai_run(&cfg.ai.model, false, &msg);
        eng.bus.publish(SecurityEvent::AiRun {
            ts: now_ts(),
            ok: false,
            summary: msg,
        });
        return;
    }
    if key.is_empty() {
        let msg = "未配置 API Key".to_string();
        let _ = eng.store.insert_ai_run(&cfg.ai.model, false, &msg);
        eng.bus.publish(SecurityEvent::AiRun {
            ts: now_ts(),
            ok: false,
            summary: msg,
        });
        return;
    }

    let stats = eng.store.stats_since(now_ts() - 86400).unwrap_or_default();
    let hits = match eng.store.recent_honeypot_hits(20) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("读取事件失败: {e}");
            let _ = eng.store.insert_ai_run(&cfg.ai.model, false, &msg);
            eng.bus.publish(SecurityEvent::AiRun {
                ts: now_ts(),
                ok: false,
                summary: msg,
            });
            return;
        }
    };
    let max_chars = cfg.ai.max_snippet_chars;
    let events_json = serde_json::json!(
        hits.iter()
            .map(|h| serde_json::json!({
                "ts": h.ts,
                "listener": h.listener,
                "remote_ip": h.remote_ip,
                "summary": h.summary,
                "payload": truncate(&h.payload, max_chars),
            }))
            .collect::<Vec<_>>()
    )
    .to_string();
    // 蜜罐上下文增强（0.5.11 H310）：有则附带，无则不阻塞——
    // ① 中交互会话逐命令序列
    let interactions_json = serde_json::json!(
        hits.iter()
            .filter(|h| !h.interaction.is_empty())
            .take(3)
            .map(|h| {
                let commands: Vec<String> =
                    serde_json::from_str::<Vec<aisafeguard_core::event::ShellStep>>(&h.interaction)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| truncate(&s.command, 200))
                        .collect();
                serde_json::json!({
                    "ts": h.ts,
                    "remote_ip": h.remote_ip,
                    "listener": h.listener,
                    "commands": commands,
                })
            })
            .collect::<Vec<_>>()
    )
    .to_string();
    let interactions_json = if interactions_json == "[]" {
        None
    } else {
        Some(interactions_json)
    };
    // ② 凭证尝试（口令只以掩码出现；spray 标记 = 用户名与本机账号同名）
    let accounts = eng.local_accounts.read().expect("账号快照锁").clone();
    let credentials_json = match eng.credentials.recent(now_ts() - 86_400, 20) {
        Ok(rows) if !rows.is_empty() => {
            let json = serde_json::json!(
                rows.iter()
                    .map(|c| serde_json::json!({
                        "remote_ip": c.remote_ip,
                        "username": c.username,
                        "password": if c.has_password { "***" } else { "(no password)" },
                        "spray_hit": accounts.contains(&c.username.to_lowercase()),
                    }))
                    .collect::<Vec<_>>()
            )
            .to_string();
            Some(json)
        }
        _ => None,
    };
    // ③ 蜜饵水印命中
    let canary_json = {
        let rows: Vec<serde_json::Value> = hits
            .iter()
            .filter(|h| h.listener == "canary-fs" || h.summary.contains("canary"))
            .take(10)
            .map(|h| {
                serde_json::json!({
                    "ts": h.ts,
                    "remote_ip": h.remote_ip,
                    "summary": truncate(&h.summary, 200),
                })
            })
            .collect();
        if rows.is_empty() {
            None
        } else {
            Some(serde_json::json!(rows).to_string())
        }
    };
    // ④ JA3/JA4 指纹（l7 开启且有指纹事件才出现）
    let fingerprints_json = match eng.store.recent_events(50, None) {
        Ok(rows) => {
            let fps: Vec<serde_json::Value> = rows
                .iter()
                .filter(|r| r.kind == "detection" && !r.tls_fp.is_empty())
                .take(10)
                .map(|r| {
                    serde_json::json!({
                        "remote_ip": r.remote_ip,
                        "ja3": r.tls_fp,
                        "ja4": r.tls_ja4,
                    })
                })
                .collect();
            if fps.is_empty() {
                None
            } else {
                Some(serde_json::json!(fps).to_string())
            }
        }
        Err(_) => None,
    };
    let stats_json = serde_json::to_string(&stats).unwrap_or_default();
    // 30 分钟内扫过暴露面 → 一并送评
    let exposure_json = eng
        .latest_exposure()
        .ok()
        .flatten()
        .filter(|snap| now_ts() - snap.ts < 1800 && !snap.entries.is_empty())
        .map(|snap| serde_json::to_string(&snap.entries).unwrap_or_default());
    // 观察到的来源 IP 与活跃情报的交集 → <intel> 段
    let intel_json = match eng.store.active_intel(now_ts()) {
        Ok(rows) => {
            let observed: std::collections::HashSet<&str> = stats
                .top_ips
                .iter()
                .map(|t| t.ip.as_str())
                .chain(hits.iter().map(|h| h.remote_ip.as_str()))
                .collect();
            let matched: Vec<&aisafeguard_store::IntelRow> = rows
                .iter()
                .filter(|r| observed.contains(r.value.as_str()))
                .take(20)
                .collect();
            if matched.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&matched).unwrap_or_default())
            }
        }
        Err(_) => None,
    };
    // 采样捕获流统计快照（元数据与计数，无载荷）——捕获活跃时送评
    let flows_json = if eng.capture.active() {
        Some(serde_json::to_string(&eng.capture.flows()).unwrap_or_default())
    } else {
        None
    };
    // 误报反馈：抑制期内的来源一并送评（用户已判定正常的不再建议封禁）
    let feedback_json = eng
        .store
        .list_active_feedback(now_ts(), cfg.ai.fp_suppress_secs as i64, 20)
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| serde_json::to_string(&v).unwrap_or_default());
    // 本产品自身 API/服务攻击面
    let self_endpoints_json = self_surface_json(eng);
    // F300 组织上下文：近期组织印证（含复验结果）/组织推荐——有记录才出现。
    // 只含组织聚合结论与键值，无任何载荷细节与凭证材料
    let org_json: Option<String> = {
        let arr: Vec<serde_json::Value> = eng
            .store
            .recent_org_events(20)
            .unwrap_or_default()
            .iter()
            .filter(|r| matches!(r.kind.as_str(), "corroboration" | "quorum" | "suggestion"))
            .map(|r| {
                serde_json::json!({
                    "ts": r.ts, "kind": r.kind, "dim": r.dim,
                    "key": r.key, "nodes": r.nodes_count, "detail": r.detail,
                })
            })
            .collect();
        (!arr.is_empty()).then(|| serde_json::to_string(&arr).unwrap_or_default())
    };

    let client = AiClient::with_protocol(
        &cfg.ai.api_protocol,
        &cfg.ai.base_url,
        &cfg.ai.model,
        &key,
        cfg.ai.extra_headers.clone(),
    );
    let result = client
        .chat(
            aisafeguard_ai::SYSTEM_PROMPT,
            &aisafeguard_ai::build_user_prompt(&aisafeguard_ai::PromptInputs {
                stats: &stats_json,
                events: &events_json,
                exposure: exposure_json.as_deref(),
                intel: intel_json.as_deref(),
                flows: flows_json.as_deref(),
                feedback: feedback_json.as_deref(),
                self_endpoints: Some(&self_endpoints_json),
                interactions: interactions_json.as_deref(),
                credentials: credentials_json.as_deref(),
                canary: canary_json.as_deref(),
                fingerprints: fingerprints_json.as_deref(),
                org: org_json.as_deref(),
                output_language: if cfg.ai.output_language == "en" {
                    "en"
                } else {
                    "zh"
                },
            }),
        )
        .await;

    match result {
        Ok(content) => match aisafeguard_ai::parse_proposals(&content) {
            Ok((analysis, proposals)) => {
                let mut created = 0i64;
                let mut auto_applied = 0i64;
                // 失败记账（F795 C9）：入库/应用失败不再静默消失
                let mut dropped = 0i64;
                let mut apply_failed = 0i64;
                // 去重跳过计数（F795 数据分析驱动）：同一攻击者已有 pending 建议或
                // 已生效封禁时不再重复建档——实测单 IP 曾被重复应用 38 次
                let mut dedup_skipped = 0i64;
                let mut first_error: Option<String> = None;
                for p in proposals {
                    if eng
                        .store
                        .pending_proposal_exists(&p.remote_ip, p.local_port)
                        .unwrap_or(true)
                        || eng
                            .store
                            .active_rule_exists(&p.remote_ip, p.local_port)
                            .unwrap_or(true)
                    {
                        dedup_skipped += 1;
                        continue;
                    }
                    let Ok(pid) = eng.store.insert_proposal(
                        &cfg.ai.model,
                        &p.action,
                        &p.severity,
                        &p.direction,
                        &p.protocol,
                        &p.remote_ip,
                        p.local_port,
                        p.ttl_secs,
                        &p.reason,
                        &analysis,
                    ) else {
                        dropped += 1;
                        if first_error.is_none() {
                            first_error = Some("建议入库失败".into());
                        }
                        continue;
                    };
                    eng.bus.publish(SecurityEvent::ProposalCreated {
                        ts: now_ts(),
                        proposal_id: pid,
                        severity: p.severity.clone(),
                        reason: p.reason.clone(),
                    });
                    created += 1;
                    if auto_apply_policy_ok(
                        eng,
                        &cfg,
                        &p.action,
                        &p.severity,
                        &p.remote_ip,
                        p.local_port,
                    ) {
                        if eng.apply_proposal(pid).is_ok() {
                            auto_applied += 1;
                        } else {
                            apply_failed += 1;
                            if first_error.is_none() {
                                first_error = Some("自动应用失败".into());
                            }
                        }
                    }
                }
                // 存量建议回扫（F793 补全）：策略开启/阈值调整后，pending 的 block 类
                // 建议按当前门控补处理——证据（24h 窗）已老化的自然留在 pending，
                // 攻击者仍在活动的被补上。观察类只等人工「确认封禁」，fed:* 组织
                // 建议走自身四关管线，均不在此列。
                let mut rescan_applied = 0i64;
                if cfg.ai.auto_apply
                    && let Ok(pending) = eng.store.list_proposals(Some("pending"), 200)
                {
                    for row in pending {
                        if row.action != "block" || row.model.starts_with("fed:") {
                            continue;
                        }
                        if auto_apply_policy_ok(
                            eng,
                            &cfg,
                            &row.action,
                            &row.severity,
                            &row.remote_ip,
                            row.local_port,
                        ) && eng.apply_proposal(row.id).is_ok()
                        {
                            rescan_applied += 1;
                        }
                    }
                }
                let mut summary = format!("分析完成：生成 {created} 条建议");
                if auto_applied > 0 {
                    summary.push_str(&format!("，自动应用 {auto_applied} 条"));
                }
                if rescan_applied > 0 {
                    summary.push_str(&format!("，回扫补应用 {rescan_applied} 条"));
                }
                if dedup_skipped > 0 {
                    summary.push_str(&format!("，去重跳过 {dedup_skipped} 条"));
                }
                if dropped + apply_failed > 0 {
                    summary.push_str(&format!(
                        "，失败 {failed} 条（{detail}）",
                        failed = dropped + apply_failed,
                        detail = first_error.as_deref().unwrap_or("未知")
                    ));
                    eng.bus.publish(SecurityEvent::engine(
                        "error",
                        format!(
                            "AI 分析产出处置失败 {failed} 条: {detail}",
                            failed = dropped + apply_failed,
                            detail = first_error.as_deref().unwrap_or("未知")
                        ),
                    ));
                }
                let _ = eng
                    .store
                    .insert_ai_run(&cfg.ai.model, true, &truncate(&summary, 500));
                eng.bus.publish(SecurityEvent::AiRun {
                    ts: now_ts(),
                    ok: true,
                    summary,
                });
            }
            Err(e) => analysis_failed(eng, &cfg.ai.model, &e.to_string()),
        },
        Err(e) => analysis_failed(eng, &cfg.ai.model, &e.to_string()),
    }
}

/// auto_apply 全套政策判定（新鲜建议与存量回扫共用，F793 补全）：只作用于
/// block 类（观察类 credential_spray 走人工「确认封禁」或「确认战役」，永不
/// 自动应用）+ 总开关 + 严重度门槛 + quorum + 误报抑制 + 证据门控 + 已生效去重。
fn auto_apply_policy_ok(
    eng: &EngineHandle,
    cfg: &AppConfig,
    action: &str,
    severity: &str,
    remote_ip: &str,
    local_port: Option<u16>,
) -> bool {
    // AI 不自动处置红线：观察类建议只等人确认，自动应用只作用于 block
    if action != "block" || !cfg.ai.auto_apply {
        return false;
    }
    // 已知测绘/扫描服务（F760 首片）：无害背景声不该被自动封——建议照常
    // 产出等人工，自动应用直接拒绝。口径④ 实证：3/40 抽样错误全属此类
    if remote_ip
        .parse::<IpAddr>()
        .map(|ip| aisafeguard_core::scanner_nets::is_known_scanner(ip))
        .unwrap_or(false)
    {
        return false;
    }
    // 已生效去重（F795 数据驱动）：同目标已有封禁规则时无需重复应用——
    // 覆盖回扫路径（存量 pending 在目标已被封后不再重复建规则）
    if eng
        .store
        .active_rule_exists(remote_ip, local_port)
        .unwrap_or(true)
    {
        return false;
    }
    if aisafeguard_ai::severity_rank(severity)
        < aisafeguard_ai::severity_rank(&cfg.ai.auto_apply_min_severity)
    {
        return false;
    }
    // 误报抑制（0.4.0 B3）：人工标记过误报的来源跳过；
    // fp_ignore_min_severity 配置后，达到该档及以上的建议忽略抑制
    let ignore_fp = !cfg.ai.fp_ignore_min_severity.is_empty()
        && aisafeguard_ai::severity_rank(severity)
            >= aisafeguard_ai::severity_rank(&cfg.ai.fp_ignore_min_severity);
    let fp_suppressed = remote_ip
        .parse::<IpAddr>()
        .ok()
        .map(|ip| {
            eng.store
                .active_fp(
                    &ip.to_string(),
                    now_ts(),
                    cfg.ai.fp_suppress_secs as i64,
                    local_port,
                )
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if !ignore_fp && fp_suppressed {
        return false;
    }
    // quorum（0.4.0 C3）：来源有协同上报但独立节点数不足时不自动应用；
    // 无任何上报（本地判断）不阻塞——单节点部署不假死
    if cfg.fed.min_peers > 0
        && let Ok(ip) = remote_ip.parse::<IpAddr>()
    {
        let reporters = eng
            .corroboration
            .lock()
            .map(|c| c.reporter_count(&ip.to_string(), now_ts() - 86_400))
            .unwrap_or(0) as i64;
        if reporters > 0 && reporters < cfg.fed.min_peers as i64 {
            return false;
        }
    }
    auto_apply_guard_ok(&eng.store, &cfg.ai, remote_ip, now_ts())
}

/// auto_apply 证据门控（F791 补全，2026-10-03 用户拍板）：AI 只提名，本机证据
/// 决定是否自动应用。三道检查全部通过才放行，任一不过留灰度人工审批：
/// ①运营者豁免——清单内 IP 永不自动应用；目标无法解析为 IP 按不可信处理。
/// ②日限额——滚动 24h 内 origin=ai 规则数达上限即暂停（0 = 不限）。
/// ③证据广度（三条定罪通道，阈值均可按攻击强度调）：
///   a) 快路径已定罪——24h 内 detection ≥ auto_apply_min_detections（确定性产出）；
///   b) 带载荷蜜罐命中——24h 内 payload 非空的 honeypot_hit ≥
///      auto_apply_min_honey_payload（攻击者真发了数据，如 telnet 登录名塞
///      二进制；纯端口探测空载荷不计入）；
///   c) 情报命中——可自动封禁条目在库且 24h 内蜜罐观测 ≥
///      auto_apply_intel_min_hits。
///   三通道全不满足 = 单信号，留灰度人工。
fn auto_apply_guard_ok(store: &Store, ai: &AiConfig, remote_ip: &str, now: i64) -> bool {
    // ① 豁免：解析失败的豁免条目忽略；目标解析失败 = 不放行
    let Ok(ip) = remote_ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    let exempt = ai
        .auto_apply_exempt_ips
        .iter()
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .any(|e| e == ip);
    if exempt {
        return false;
    }
    // ② 日限额
    let cap = ai.auto_apply_max_per_day as i64;
    if cap > 0 && store.ai_rules_since(now - 86_400).unwrap_or(cap) >= cap {
        return false;
    }
    // ③ 证据广度（三条定罪通道，满足任一即放行；阈值 0 值防呆视为 1）
    let det_min = ai.auto_apply_min_detections.max(1) as i64;
    let honey_min = ai.auto_apply_min_honey_payload.max(1) as i64;
    let intel_min = ai.auto_apply_intel_min_hits.max(1) as i64;
    let Ok((honey, honey_payload, det)) = store.evidence_breadth(remote_ip, now - 86_400) else {
        return false;
    };
    // 通道一：快路径已定罪（频次检测器确定性产出）
    if det >= det_min {
        return true;
    }
    // 通道二：带载荷蜜罐命中（攻击者真发了数据——telnet 登录名塞二进制/
    // HTTP 利用串；纯端口探测 payload 为空不计入）
    if honey_payload >= honey_min {
        return true;
    }
    // 通道三：情报命中（可自动封禁的库内条目 + 被观测到主动行为）
    honey >= intel_min && store.intel_auto_block_hit(remote_ip, now).unwrap_or(false)
}

fn analysis_failed(eng: &EngineHandle, model: &str, msg: &str) {
    let msg = truncate(msg, 500);
    let _ = eng.store.insert_ai_run(model, false, &msg);
    eng.bus.publish(SecurityEvent::AiRun {
        ts: now_ts(),
        ok: false,
        summary: msg,
    });
}

/// 内嵌控制台：引擎与 GUI 同进程（管理员运行或无服务回退）。
pub struct EmbeddedConsole(pub Arc<EngineHandle>);

impl Console for EmbeddedConsole {
    fn version(&self) -> String {
        self.0.version.to_string()
    }

    fn refresh_intel(&self) -> anyhow::Result<()> {
        let eng = Arc::clone(&self.0);
        self.0.rt.spawn(async move {
            let cfg = eng.config().intel;
            run_intel_refresh(&eng, &cfg).await;
        });
        Ok(())
    }

    fn fed_panel(&self) -> anyhow::Result<crate::engine::FedPanel> {
        Ok(self.0.fed_panel())
    }

    fn join_request_create(&self, node: &str) -> anyhow::Result<(String, String)> {
        self.0.join_request_create(node)
    }

    fn join_approval_process(
        &self,
        request_json: &str,
        coord_addr: &str,
    ) -> anyhow::Result<(String, String)> {
        self.0.join_approval_process(request_json, coord_addr)
    }

    fn join_import(&self, approval_json: &str, coord_addr: &str) -> anyhow::Result<String> {
        self.0.join_import(approval_json, coord_addr)
    }

    fn revoke_member(&self, node: &str, reason: &str) -> anyhow::Result<String> {
        self.0.revoke_member(node, reason)
    }

    fn quarantine_member(
        &self,
        node: &str,
        lift: bool,
        lift_fp: &str,
        reason: &str,
    ) -> anyhow::Result<String> {
        self.0
            .quarantine_member(node, lift, lift_fp, reason)
            .map_err(anyhow::Error::msg)
    }

    fn config_paths(&self) -> (String, String) {
        (
            self.0.cfg_path.display().to_string(),
            self.0.config().data_dir().display().to_string(),
        )
    }

    fn config(&self) -> anyhow::Result<AppConfig> {
        Ok(self.0.config())
    }

    fn status(&self) -> anyhow::Result<StatusReport> {
        Ok(self.0.status())
    }

    fn list_events(&self, limit: u32, ip_filter: Option<&str>) -> anyhow::Result<Vec<EventRow>> {
        self.0
            .list_events(limit, ip_filter)
            .map_err(anyhow::Error::msg)
    }

    fn list_rules(&self) -> anyhow::Result<Vec<crate::explain::RuleExplain>> {
        self.0.list_rules_explain().map_err(anyhow::Error::msg)
    }

    fn list_proposals(&self, status: Option<&str>, limit: u32) -> anyhow::Result<Vec<ProposalRow>> {
        self.0
            .list_proposals(status, limit)
            .map_err(anyhow::Error::msg)
    }

    fn list_ai_runs(&self, limit: u32) -> anyhow::Result<Vec<AiRunRow>> {
        self.0.list_ai_runs(limit).map_err(anyhow::Error::msg)
    }

    fn stats_24h(&self) -> anyhow::Result<StatsSummary> {
        self.0.stats_24h().map_err(anyhow::Error::msg)
    }

    fn clear_xdp_map(&self) -> anyhow::Result<()> {
        self.0.xdp_clear_map().map_err(anyhow::Error::msg)
    }

    fn scan_exposure(&self) -> anyhow::Result<Vec<aisafeguard_detect::exposure::Entry>> {
        self.0.scan_exposure().map_err(anyhow::Error::msg)
    }

    fn latest_exposure(&self) -> anyhow::Result<Option<ExposureSnapshot>> {
        self.0.latest_exposure().map_err(anyhow::Error::msg)
    }

    fn add_block(&self, spec: &BlockSpec, origin: &str) -> anyhow::Result<RuleRow> {
        self.0.add_block(spec, origin).map_err(anyhow::Error::msg)
    }

    fn remove_rule(&self, id: i64) -> anyhow::Result<()> {
        self.0.remove_rule(id).map_err(anyhow::Error::msg)
    }

    fn confirm_campaign(&self, id: i64) -> anyhow::Result<()> {
        self.0.confirm_campaign(id).map_err(anyhow::Error::msg)
    }

    fn toggle_listener(&self, name: &str, run: bool) -> anyhow::Result<()> {
        self.0
            .toggle_listener(name, run)
            .map_err(anyhow::Error::msg)
    }

    fn apply_proposal(&self, id: i64) -> anyhow::Result<RuleRow> {
        self.0.apply_proposal(id).map_err(anyhow::Error::msg)
    }

    fn dismiss_proposal(&self, id: i64) -> anyhow::Result<()> {
        self.0.dismiss_proposal(id).map_err(anyhow::Error::msg)
    }

    fn promote_rule(&self, id: i64) -> anyhow::Result<RuleRow> {
        self.0.promote_rule(id).map_err(anyhow::Error::msg)
    }

    fn clear_false_positive(&self, ip: &str) -> anyhow::Result<usize> {
        self.0.clear_false_positive(ip).map_err(anyhow::Error::msg)
    }

    fn list_feedback(&self) -> anyhow::Result<Vec<aisafeguard_store::FpRow>> {
        self.0
            .store
            .list_active_feedback(
                aisafeguard_core::now_ts(),
                self.0.config().ai.fp_suppress_secs as i64,
                100,
            )
            .map_err(anyhow::Error::msg)
    }

    fn mark_false_positive(
        &self,
        ip: &str,
        note: &str,
        local_port: Option<u16>,
    ) -> anyhow::Result<(i64, usize)> {
        self.0
            .mark_false_positive(ip, note, local_port)
            .map_err(anyhow::Error::msg)
    }

    fn trigger_analysis(&self) -> bool {
        self.0.trigger_analysis()
    }

    fn save_config(&self, cfg: AppConfig) -> anyhow::Result<()> {
        self.0.save_config(cfg).map_err(anyhow::Error::msg)
    }

    fn ai_key_present(&self) -> anyhow::Result<bool> {
        Ok(aisafeguard_core::secrets::ai_key_present())
    }

    fn set_ai_key(&self, value: &str) -> anyhow::Result<()> {
        aisafeguard_core::secrets::set_ai_key(value).map_err(anyhow::Error::msg)
    }

    fn delete_ai_key(&self) -> anyhow::Result<()> {
        aisafeguard_core::secrets::delete_ai_key().map_err(anyhow::Error::msg)
    }

    fn live_events(&self) -> std::sync::mpsc::Receiver<crate::console::LiveEvent> {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        let bus = self.0.bus.clone();
        self.0.rt.spawn(async move {
            let mut sub = bus.subscribe();
            loop {
                match sub.recv().await {
                    Ok(ev) => {
                        if tx
                            .send(crate::console::LiveEvent {
                                kind: ev.kind().to_string(),
                                ts: ev.ts(),
                                summary: ev.summary(),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
        rx
    }
}

/// 威胁情报定时任务（0.3 v1）：拉取 Feodo C2 + 合并本地蜜罐源，
/// 高置信度 C2 自动封禁（TTL 3 天 + 内网保护），全程审计。
pub fn spawn_intel_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        // 启动后延迟 20s 先跑一轮（避免抢占启动窗口）
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            let cfg = eng.config().intel;
            if cfg.enabled {
                run_intel_refresh(&eng, &cfg).await;
            }
            let interval = cfg.interval_secs.clamp(600, 86400);
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    });
}

pub async fn run_intel_refresh(
    eng: &Arc<EngineHandle>,
    cfg: &aisafeguard_core::config::IntelConfig,
) {
    let now = now_ts();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .build()
        .expect("HTTP client 构建失败");

    // 1) 逐源拉取（F710 多源分级）：单源失败只跳过该源，不拖垮其余源
    let mut total_added = 0usize;
    let mut total_blocked = 0usize;
    let mut failures = 0usize;
    let mut dropped = 0usize; // 网段（F770 决策依据）+ 超上限截断
    for source in &cfg.sources {
        if !source.valid() {
            tracing::warn!(
                "情报源 {} 配置非法（name/url/confidence/kind/ttl/format 检查），跳过",
                source.name
            );
            failures += 1;
            continue;
        }
        // F720：按 format 分发拉取器；crowdsec 需 key（环境变量最高优先，其次凭据管理器）——
        // 缺 key = 跳过该源 + 明确告警，不做静默降级（对齐 webhook 签名先例）
        let fetched = match source.format.as_str() {
            "crowdsec" => {
                let Some(key) = crowdsec_key() else {
                    failures += 1;
                    tracing::warn!(
                        "情报源 {} 需要 CrowdSec API key（环境变量 AISAFEGUARD_CROWDSEC_KEY 或凭据管理器 crowdsec-key）：跳过该源，不做静默降级",
                        source.name
                    );
                    continue;
                };
                aisafeguard_detect::intel::fetch_crowdsec_blocklist(&http, &source.url, &key)
                    .await
                    .map(|p| {
                        dropped += p.ranges.len() + p.malformed;
                        p.singles
                    })
            }
            _ => aisafeguard_detect::intel::fetch_blocklist(&http, &source.url)
                .await
                .map(|ips| {
                    if ips.len() as u64 > source.max_entries {
                        tracing::warn!(
                            "情报源 {} 单轮 {} 条超上限 {}：截断",
                            source.name,
                            ips.len(),
                            source.max_entries
                        );
                        dropped += (ips.len() as u64 - source.max_entries) as usize;
                    }
                    ips.into_iter().take(source.max_entries as usize).collect()
                }),
        };
        match fetched {
            Ok(ips) => {
                let (added, blocked) = apply_intel_source(
                    &eng.store,
                    eng.firewall.as_ref(),
                    &eng.bus,
                    source,
                    ips,
                    now,
                );
                total_added += added;
                total_blocked += blocked;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(
                    "情报源 {} 拉取失败（跳过该源，其余源照常）: {e}",
                    source.name
                );
            }
        }
    }

    // 2) 本地蜜罐源（最近 7 天命中过的来源，仅标注，永不自动封禁）
    let local = aisafeguard_core::config::IntelSource {
        name: "local_honeypot".into(),
        url: String::new(),
        confidence: "local".into(),
        kind: "scan_source".into(),
        auto_block: false,
        ttl_secs: 7 * 86400,
        format: "feodo".into(),
        max_entries: 2000,
    };
    let mut seen = std::collections::HashSet::new();
    let hits: Vec<String> = eng
        .store
        .recent_honeypot_hits(2000)
        .unwrap_or_default()
        .into_iter()
        .filter(|h| {
            !h.remote_ip.is_empty() && h.remote_ip != "unknown" && seen.insert(h.remote_ip.clone())
        })
        .map(|h| h.remote_ip)
        .collect();
    let (added_local, _) = apply_intel_source(
        &eng.store,
        eng.firewall.as_ref(),
        &eng.bus,
        &local,
        hits,
        now,
    );
    total_added += added_local;

    let _ = eng.store.prune_intel(now);
    let active = eng.store.intel_count(now).unwrap_or(0);
    let _ = eng.store.set_meta(
        "intel_last_fetch",
        &serde_json::json!({
            "ts": now, "ok": failures == 0, "added": total_added as i64,
            "active": active as i64, "blocked": total_blocked as i64,
            "dropped": dropped as i64,
        })
        .to_string(),
    );
    eng.bus.publish(SecurityEvent::engine(
        "info",
        format!(
            "威胁情报更新：入库 {total_added} 条（{} 个源，失败 {failures}），在库 {active}，自动封禁 {total_blocked}，丢弃 {dropped}（网段/截断）",
            cfg.sources.len()
        ),
    ));
}

/// F720：CrowdSec key 双通道——环境变量 `AISAFEGUARD_CROWDSEC_KEY` 最高优先
/// （CI/无头/服务注入），其次凭据管理器（crowdsec-key）。config 无秘密原则。
fn crowdsec_key() -> Option<String> {
    if let Ok(v) = std::env::var("AISAFEGUARD_CROWDSEC_KEY")
        && !v.is_empty()
    {
        return Some(v);
    }
    aisafeguard_core::secrets::crowdsec_key()
}

/// F710 单源入库 + 自动封禁。门控 = 源级 auto_block && confidence=="high"
/// 双条件（许可与信任缺一不可）；内网保护/已封跳过不变。
/// 拆成自由函数便于单测（MockFirewall + 临时库，无需网络）。
pub(crate) fn apply_intel_source(
    store: &Store,
    firewall: &dyn Firewall,
    bus: &EventBus,
    source: &aisafeguard_core::config::IntelSource,
    ips: Vec<String>,
    now: i64,
) -> (usize, usize) {
    let upserts: Vec<(String, String, String, String, i64, i64, bool)> = ips
        .iter()
        .map(|ip| {
            (
                source.name.clone(),
                source.kind.clone(),
                ip.clone(),
                source.confidence.clone(),
                now,
                now + source.ttl_secs as i64,
                source.auto_block && source.confidence == "high",
            )
        })
        .collect();
    let added = store.upsert_intel(&upserts).unwrap_or(0);

    let mut blocked = 0usize;
    if source.auto_block && source.confidence == "high" {
        let existing: std::collections::HashSet<String> = store
            .list_rules()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.remote_ip.parse::<IpAddr>().is_ok())
            .map(|r| r.remote_ip)
            .collect();
        for value in &ips {
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            if aisafeguard_core::is_protected_ip(ip) || existing.contains(value) {
                continue;
            }
            let spec = BlockSpec {
                direction: Direction::In,
                protocol: Protocol::Any,
                remote_ip: Some(ip),
                local_port: None,
                note: format!(
                    "威胁情报自动封禁（{} / TTL {}）",
                    source.name,
                    crate::explain::humanize_secs(source.ttl_secs as i64)
                ),
                tag: "情报".into(),
            };
            if apply_block(
                firewall,
                store,
                bus,
                &spec,
                "intel",
                Some(now + source.ttl_secs as i64),
            )
            .is_ok()
            {
                blocked += 1;
            }
        }
    }
    (added, blocked)
}

/// ai_running 复位守卫（F795）：触发分析的任务 panic 时随栈展开复位标志，
/// 防一次 panic 永久卡死手动+定时分析。
struct AiRunningGuard(Arc<EngineHandle>);
impl Drop for AiRunningGuard {
    fn drop(&mut self) {
        self.0.ai_running.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// F793 同元素判定：同 IP+方向+粒度交叠才共享元素；IP 级与端口级互不干扰。
    #[test]
    fn same_element_matches_ip_direction_and_scope() {
        let rule =
            |ip: &str, dir: &str, proto: &str, port: Option<u16>| aisafeguard_store::RuleRow {
                id: 0,
                created_ts: 0,
                name: String::new(),
                direction: dir.into(),
                protocol: proto.into(),
                remote_ip: ip.into(),
                local_port: port,
                origin: String::new(),
                enabled: true,
                note: String::new(),
                expires_ts: Some(0),
                tag: String::new(),
                promoted: false,
            };
        let a = rule("1.2.3.4", "in", "any", None);
        // 同 IP 同方向 IP 级 → 同元素（协议不同不分裂 IP 级元素）
        assert!(same_element(&a, &rule("1.2.3.4", "in", "any", None)));
        assert!(same_element(&a, &rule("1.2.3.4", "in", "tcp", None)));
        // IP 级 vs 端口级 = 不同集合
        assert!(!same_element(&a, &rule("1.2.3.4", "in", "tcp", Some(2222))));
        // 不同 IP / 不同方向
        assert!(!same_element(&a, &rule("5.6.7.8", "in", "any", None)));
        assert!(!same_element(&a, &rule("1.2.3.4", "out", "any", None)));
        // 端口级：同端口且协议有交集（any 与 tcp/udp 共享拼接集合）
        let t = rule("1.2.3.4", "in", "tcp", Some(8081));
        assert!(same_element(&t, &rule("1.2.3.4", "in", "tcp", Some(8081))));
        assert!(same_element(&t, &rule("1.2.3.4", "in", "any", Some(8081))));
        assert!(!same_element(&t, &rule("1.2.3.4", "in", "udp", Some(8081))));
        assert!(!same_element(&t, &rule("1.2.3.4", "in", "tcp", Some(8082))));
        // 空 IP 的规则不构成覆盖
        assert!(!same_element(&rule("", "in", "any", None), &a));
    }

    /// auto_apply 证据门控（F791 补全）：三层证据/豁免/日限额的完整分支覆盖。
    #[test]
    fn auto_apply_guard_requires_evidence_exemption_and_cap() {
        let dir = std::env::temp_dir().join(format!("asg-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("临时目录");
        let store = Store::open(&dir.join("t.db")).expect("临时库");
        let now = now_ts();
        let ai = AiConfig {
            auto_apply: true,
            ..Default::default()
        };
        let honeypot_hit = |ip: &str| SecurityEvent::HoneypotHit {
            ts: now,
            listener: "http".into(),
            kind: "http".into(),
            port: 8081,
            remote_ip: ip.into(),
            remote_port: 44444,
            summary: "GET / HTTP/1.1".into(),
            payload: String::new(),
            http_hint: None,
            interaction: None,
        };
        let detection = |ip: &str| SecurityEvent::Detection {
            ts: now,
            kind: "bruteforce".into(),
            src_ip: ip.into(),
            confidence: "high".into(),
            severity: "medium".into(),
            evidence: "60 秒内命中 10 次".into(),
            rule_id: None,
            http_hint: None,
            tls_fingerprint: None,
            tls_ja4: None,
        };

        // 单信号（仅蜜罐命中、无检测、无情报）：留灰度，不放行
        for _ in 0..3 {
            store.insert_event(&honeypot_hit("1.2.3.4")).unwrap();
        }
        assert!(!auto_apply_guard_ok(&store, &ai, "1.2.3.4", now));

        // 通道二（F795 补全）：带载荷蜜罐命中 ≥ min_honey_payload(默认3) 即定罪；
        // 纯端口探测（payload 空）不算数
        let payload_hit = |ip: &str| SecurityEvent::HoneypotHit {
            ts: now,
            listener: "telnet".into(),
            kind: "telnet".into(),
            port: 2323,
            remote_ip: ip.into(),
            remote_port: 55555,
            summary: "登录名提交二进制载荷".into(),
            payload: "binary-blob".into(),
            http_hint: None,
            interaction: None,
        };
        for _ in 0..2 {
            store.insert_event(&payload_hit("4.4.4.4")).unwrap();
        }
        assert!(
            !auto_apply_guard_ok(&store, &ai, "4.4.4.4", now),
            "2 次带载荷 < 3 不放行"
        );
        store.insert_event(&payload_hit("4.4.4.4")).unwrap();
        assert!(
            auto_apply_guard_ok(&store, &ai, "4.4.4.4", now),
            "3 次带载荷放行"
        );
        // 4 次空载荷探测 ≠ 定罪
        assert!(
            !auto_apply_guard_ok(&store, &ai, "1.2.3.4", now),
            "空载荷命中不计入通道二"
        );

        // 快路径已定罪（≥1 detection）放行——含多信号情形
        store.insert_event(&detection("1.2.3.4")).unwrap();
        assert!(auto_apply_guard_ok(&store, &ai, "1.2.3.4", now));

        // 情报命中：可自动封禁条目在库但零观测不放行；被观测到即放行
        store
            .upsert_intel(&[(
                "feodo_c2".into(),
                "c2".into(),
                "5.6.7.8".into(),
                "high".into(),
                now,
                now + 86_400,
                true,
            )])
            .unwrap();
        assert!(
            !auto_apply_guard_ok(&store, &ai, "5.6.7.8", now),
            "在库零观测不放行"
        );
        store.insert_event(&honeypot_hit("5.6.7.8")).unwrap();
        assert!(auto_apply_guard_ok(&store, &ai, "5.6.7.8", now));

        // 证据阈值（F792b）：min_detections=2 时单次检测不放行，两次放行
        let ai_strict = AiConfig {
            auto_apply_min_detections: 2,
            ..Default::default()
        };
        store.insert_event(&detection("3.3.3.3")).unwrap();
        assert!(
            !auto_apply_guard_ok(&store, &ai_strict, "3.3.3.3", now),
            "阈值=2 单次检测不放行"
        );
        store.insert_event(&detection("3.3.3.3")).unwrap();
        assert!(auto_apply_guard_ok(&store, &ai_strict, "3.3.3.3", now));

        // 情报观测阈值：intel_min_hits=2 时单次观测不放行，再次观测放行
        let ai_intel_strict = AiConfig {
            auto_apply_intel_min_hits: 2,
            ..Default::default()
        };
        assert!(
            !auto_apply_guard_ok(&store, &ai_intel_strict, "5.6.7.8", now),
            "阈值=2 单次观测不放行"
        );
        store.insert_event(&honeypot_hit("5.6.7.8")).unwrap();
        assert!(auto_apply_guard_ok(
            &store,
            &ai_intel_strict,
            "5.6.7.8",
            now
        ));

        // 运营者豁免：清单内 IP 即使有检测也不放行（人工批准不受此限）
        let ai_exempt = AiConfig {
            auto_apply_exempt_ips: vec!["1.2.3.4".into()],
            ..Default::default()
        };
        assert!(!auto_apply_guard_ok(&store, &ai_exempt, "1.2.3.4", now));

        // 日限额：24h 内 origin=ai 规则数达上限暂停（人工批准同占额）；0 = 不限
        for i in 0..ai.auto_apply_max_per_day {
            store
                .insert_rule(
                    &format!("blk-guard-{i}"),
                    "in",
                    "any",
                    "9.9.9.9",
                    None,
                    "ai",
                    "",
                    "",
                    Some(now + 3600),
                )
                .unwrap();
        }
        store.insert_event(&detection("2.2.2.2")).unwrap();
        assert!(
            !auto_apply_guard_ok(&store, &ai, "2.2.2.2", now),
            "达限额不放行"
        );
        let ai_uncapped = AiConfig {
            auto_apply_max_per_day: 0,
            ..Default::default()
        };
        assert!(auto_apply_guard_ok(&store, &ai_uncapped, "2.2.2.2", now));

        // 目标无法解析为 IP：按不可信处理，不放行
        assert!(!auto_apply_guard_ok(&store, &ai, "not-an-ip", now));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 记录调用参数的假防火墙：单机上真实流量源必是内网/回环（会被保护拦下），
    /// 封禁分支只有靠注入假后端才能在测试里确定性地走到。
    #[derive(Default)]
    struct MockFirewall {
        added: Mutex<Vec<(String, BlockSpec)>>,
        removed: Mutex<Vec<String>>,
    }

    impl Firewall for MockFirewall {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn is_elevated(&self) -> bool {
            true
        }
        fn add_block(&self, name: &str, spec: &BlockSpec) -> Result<()> {
            self.added
                .lock()
                .expect("mock 锁中毒")
                .push((name.to_string(), spec.clone()));
            Ok(())
        }
        fn remove(&self, name: &str, spec: &BlockSpec) -> Result<()> {
            self.removed
                .lock()
                .expect("mock 锁中毒")
                .push(name.to_string());
            let _ = spec;
            Ok(())
        }
    }

    struct Fixture {
        fw: MockFirewall,
        store: Store,
        bus: EventBus,
        dir: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("aisafeguard-test-{tag}-{}", uuid::Uuid::new_v4()));
            let store = Store::open(&dir.join("test.db")).expect("临时库打开失败");
            Self {
                fw: MockFirewall::default(),
                store,
                bus: EventBus::new(256),
                dir,
            }
        }

        fn dcfg(&self) -> DetectConfig {
            DetectConfig {
                auto_block: true,
                ttl_secs: 30,
                ..Default::default()
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn detection_blocks_public_ip_with_ttl_and_audit() {
        let f = Fixture::new("block");
        let mut rx = f.bus.subscribe();
        let before = now_ts();
        handle_detection(
            &DetectionSink {
                fw: &f.fw,
                store: &f.store,
                bus: &f.bus,
                fp_suppress_secs: 0,
            },
            "scan",
            "203.0.113.7".parse().unwrap(),
            "60 秒内对 3 个不同目标端口发送 SYN",
            Some("builtin.tcp_scan"),
            &f.dcfg(),
            f.dcfg().auto_block,
            "medium",
            L7Evidence::default(),
        );

        // 防火墙收到封禁（入站 / 任意协议 / 目标 IP）
        let added = f.fw.added.lock().unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].1.remote_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(added[0].1.direction, Direction::In);
        assert_eq!(added[0].1.protocol, Protocol::Any);
        drop(added);

        // 记账带 TTL 且来源为 engine
        let rules = f.store.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].origin, "engine");
        assert_eq!(rules[0].remote_ip, "203.0.113.7");
        let expires = rules[0].expires_ts.expect("自动封禁必须带 TTL");
        assert!((before + 29..=now_ts() + 30).contains(&expires));

        // 事件：Detection（含 rule_id）+ 规则加入 + 自动封禁留痕
        let mut kinds = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            kinds.push(ev.summary());
        }
        assert!(kinds.iter().any(|s| s.contains("[scan] 203.0.113.7")));
        assert!(kinds.iter().any(|s| s.contains("已自动封禁 203.0.113.7")));
    }

    /// F710 源分级门控：只有 auto_block && confidence=high 的源触发自动封禁；
    /// 内网保护/已封跳过不变；非特权源条目照常入库（标注面）。
    #[test]
    fn intel_source_gating_blocks_only_privileged() {
        let f = Fixture::new("intel-gate");
        let now = now_ts();
        let priv_src = aisafeguard_core::config::IntelSource {
            name: "feodo_c2".into(),
            url: "https://x".into(),
            confidence: "high".into(),
            kind: "c2".into(),
            auto_block: true,
            ttl_secs: 259_200,
            format: "feodo".into(),
            max_entries: 1000,
        };
        let pub_src = aisafeguard_core::config::IntelSource {
            name: "mirror".into(),
            url: "https://y".into(),
            confidence: "fed".into(),
            kind: "scan_source".into(),
            auto_block: false,
            ttl_secs: 604_800,
            format: "feodo".into(),
            max_entries: 1000,
        };
        let (added1, blocked1) = apply_intel_source(
            &f.store,
            &f.fw,
            &f.bus,
            &priv_src,
            vec!["203.0.113.7".into(), "192.168.1.50".into()],
            now,
        );
        assert_eq!(added1, 2, "内网条目照常入库（情报标注面）");
        assert_eq!(blocked1, 1, "内网地址永不自动封");
        let (added2, blocked2) = apply_intel_source(
            &f.store,
            &f.fw,
            &f.bus,
            &pub_src,
            vec!["203.0.113.8".into()],
            now,
        );
        assert_eq!(added2, 1, "非特权源条目照常入库");
        assert_eq!(blocked2, 0, "非特权源永不自动封禁");
        let (_, blocked3) = apply_intel_source(
            &f.store,
            &f.fw,
            &f.bus,
            &priv_src,
            vec!["203.0.113.7".into()],
            now,
        );
        assert_eq!(blocked3, 0, "已封跳过");
        assert_eq!(f.fw.added.lock().expect("mock 锁中毒").len(), 1);
    }

    #[test]
    fn detection_never_blocks_protected_ip() {
        let f = Fixture::new("protected");
        let mut rx = f.bus.subscribe();
        for ip in ["127.0.0.1", "192.168.1.10", "10.1.2.3", "fe80::1", "::1"] {
            handle_detection(
                &DetectionSink {
                    fw: &f.fw,
                    store: &f.store,
                    bus: &f.bus,
                    fp_suppress_secs: 0,
                },
                "flood",
                ip.parse().unwrap(),
                "100 个纯 SYN",
                Some("builtin.syn_flood"),
                &f.dcfg(),
                f.dcfg().auto_block,
                "medium",
                L7Evidence::default(),
            );
        }
        assert!(
            f.fw.added.lock().unwrap().is_empty(),
            "内网/回环地址必须零封禁"
        );
        assert!(f.store.list_rules().unwrap().is_empty());
        // 但判定事件与"内网保护"留痕照常
        let mut kinds = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            kinds.push(ev.summary());
        }
        assert_eq!(kinds.iter().filter(|s| s.contains("[flood]")).count(), 5);
        assert_eq!(kinds.iter().filter(|s| s.contains("内网保护")).count(), 5);
    }

    #[test]
    fn detection_respects_auto_block_off() {
        let f = Fixture::new("noblock");
        let mut dcfg = f.dcfg();
        dcfg.auto_block = false;
        handle_detection(
            &DetectionSink {
                fw: &f.fw,
                store: &f.store,
                bus: &f.bus,
                fp_suppress_secs: 0,
            },
            "scan",
            "203.0.113.9".parse().unwrap(),
            "证据",
            None,
            &dcfg,
            dcfg.auto_block,
            "medium",
            L7Evidence::default(),
        );
        assert!(
            f.fw.added.lock().unwrap().is_empty(),
            "auto_block=false 不得封禁"
        );
        assert_eq!(f.store.list_rules().unwrap().len(), 0);
    }

    #[test]
    fn rule_scan_hits_and_dedups_per_flow() {
        // F4/F6：规则命中 → scan_rules 放行；采样路径流级去重 10 分钟内只报一次
        let raw = b"alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:\"sqlmap probe\"; content:\"sqlmap\"; classtype:web-application-attack; sid:1000001; rev:1;)\n";
        let rs = Arc::new(aisafeguard_rules::loader::load_package(raw, 100).expect("规则包应合法"));
        let state = RulesState::default();
        state.set_current(Some(rs), "test.rules", "已加载 1 条规则");
        let rcfg = aisafeguard_core::config::RulesConfig {
            enabled: true,
            auto_block: false,
            ..Default::default()
        };
        let is_home = |ip: IpAddr| aisafeguard_core::is_protected_ip(ip);
        let session = aisafeguard_rules::matcher::Session {
            client_ip: "203.0.113.7".parse().unwrap(),
            client_port: 44444,
            server_ip: IpAddr::from([0, 0, 0, 0]),
            server_port: 8081,
            to_server: true,
            proto: aisafeguard_rules::ir::Proto::Tcp,
            is_home: &is_home,
        };
        let hits = scan_rules(
            &state,
            &rcfg,
            b"GET / HTTP/1.1 UA: sqlmap/1.7",
            &session,
            "203.0.113.7".parse().unwrap(),
            Some("flow-1"),
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "sid:1000001");
        assert_eq!(
            hits[0].severity, "critical",
            "classtype=web-application-attack → critical"
        );
        // 流级去重：同一流再扫不再放行
        let again = scan_rules(
            &state,
            &rcfg,
            b"GET / HTTP/1.1 UA: sqlmap/1.7",
            &session,
            "203.0.113.7".parse().unwrap(),
            Some("flow-1"),
        );
        assert!(again.is_empty());
        // 未启用 → 静默
        let mut off = rcfg.clone();
        off.enabled = false;
        assert!(
            scan_rules(
                &state,
                &off,
                b"sqlmap",
                &session,
                "203.0.113.7".parse().unwrap(),
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn rule_hit_default_alert_only_never_blocks() {
        // F6：[detect.rules].auto_block=false（默认）→ 规则命中只产事件，不写防火墙
        let f = Fixture::new("rulesig-noblock");
        let mut rx = f.bus.subscribe();
        let dcfg = f.dcfg();
        let rcfg = aisafeguard_core::config::RulesConfig::default(); // enabled=false, auto_block=false
        handle_detection(
            &DetectionSink {
                fw: &f.fw,
                store: &f.store,
                bus: &f.bus,
                fp_suppress_secs: 0,
            },
            "signature",
            "203.0.113.7".parse().unwrap(),
            "sqlmap probe（规则 sid:1000001 v1；203.0.113.7:44444 → 蜜罐[http]:8081）",
            Some("sid:1000001"),
            &dcfg,
            rcfg.auto_block,
            "critical",
            L7Evidence::default(),
        );
        // 事件照发（告警路径不受 auto_block 影响）
        let mut kinds = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            kinds.push(ev.summary());
        }
        assert!(
            kinds
                .iter()
                .any(|s| s.contains("[signature] 203.0.113.7: sqlmap probe"))
        );
        // 防火墙零写入
        assert!(f.fw.added.lock().unwrap().is_empty(), "规则默认只告警");
        assert!(f.store.list_rules().unwrap().is_empty());
        // auto_block=true 时才封禁
        let f2 = Fixture::new("rulesig-autoblock");
        handle_detection(
            &DetectionSink {
                fw: &f2.fw,
                store: &f2.store,
                bus: &f2.bus,
                fp_suppress_secs: 0,
            },
            "signature",
            "203.0.113.8".parse().unwrap(),
            "sqlmap probe（规则 sid:1000001）",
            Some("sid:1000001"),
            &dcfg,
            true,
            "critical",
            L7Evidence::default(),
        );
        assert_eq!(
            f2.fw.added.lock().unwrap().len(),
            1,
            "显式 auto_block=true 才自动封禁"
        );
    }

    #[test]
    fn detection_respects_false_positive_suppression_window() {
        // Batch 2 DoD：标误报后同 IP 在抑制期内不再被快路径自动封；抑制期外恢复
        let f = Fixture::new("fp-window");
        let ip: IpAddr = "203.0.113.88".parse().unwrap();
        let sink = |secs: i64| DetectionSink {
            fw: &f.fw,
            store: &f.store,
            bus: &f.bus,
            fp_suppress_secs: secs,
        };
        // 抑制期内（1 小时窗口，刚刚标记）：自动封禁跳过
        f.store
            .insert_fp_feedback("203.0.113.88", now_ts(), "误报", None)
            .unwrap();
        handle_detection(
            &sink(3600),
            "scan",
            ip,
            "证据",
            None,
            &f.dcfg(),
            true,
            "medium",
            L7Evidence::default(),
        );
        assert!(
            f.fw.added.lock().unwrap().is_empty(),
            "抑制期内不得自动封禁"
        );
        // 抑制期外（标记时间早于窗口）：恢复自动封禁资格
        f.store
            .insert_fp_feedback("203.0.113.88", now_ts() - 7200, "误报", None)
            .unwrap();
        handle_detection(
            &sink(3600),
            "scan",
            ip,
            "证据",
            None,
            &f.dcfg(),
            true,
            "medium",
            L7Evidence::default(),
        );
        assert_eq!(
            f.fw.added.lock().unwrap().len(),
            1,
            "抑制期外应恢复自动封禁"
        );
    }

    #[test]
    fn apply_block_rejects_empty_spec() {
        let f = Fixture::new("empty");
        let spec = BlockSpec {
            direction: Direction::In,
            protocol: Protocol::Any,
            remote_ip: None,
            local_port: None,
            note: "空".into(),
            tag: String::new(),
        };
        assert!(apply_block(&f.fw, &f.store, &f.bus, &spec, "test", None).is_err());
        assert!(f.fw.added.lock().unwrap().is_empty());
    }
}
