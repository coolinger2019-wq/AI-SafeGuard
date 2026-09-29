use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use aisafeguard_ai::AiClient;
use aisafeguard_core::config::{AppConfig, DetectConfig};
use aisafeguard_core::error::{Error, Result};
use aisafeguard_core::event::{EventBus, SecurityEvent};
use aisafeguard_core::{now_ts, secrets};
use aisafeguard_firewall::{BlockSpec, Direction, Firewall, Protocol, RULE_PREFIX};
use aisafeguard_store::{AiRunRow, EventRow, ProposalRow, RuleRow, StatsSummary, Store};
use serde::{Deserialize, Serialize};

use crate::console::Console;

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

    /// （H6 可观测接线后移除本 allow）
    #[allow(dead_code)]
    pub fn loaded_path(&self) -> String {
        self.loaded_path.lock().expect("规则路径锁中毒").clone()
    }

    #[allow(dead_code)]
    pub fn loaded_sha256(&self) -> String {
        self.loaded_sha256.lock().expect("规则哈希锁中毒").clone()
    }

    #[allow(dead_code)]
    pub fn note(&self) -> String {
        self.note.lock().expect("规则备注锁中毒").clone()
    }

    pub fn add_hit(&self) {
        *self.hits.lock().expect("规则命中锁中毒") += 1;
    }

    #[allow(dead_code)]
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
    pub rt: tokio::runtime::Handle,
    pub started: Instant,
    pub ai_running: Arc<AtomicBool>,
    pub honeypot: aisafeguard_honeypot::HoneypotHandle,
    pub token: String,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub name: String,
    pub port: u16,
    pub kind: String,
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
    pub detect_enabled: bool,
    pub capture: CaptureStatus,
    /// 价值指标（0.4.0 B5）：口径见 store::ValueMetrics，比率由展示层算
    pub metrics_24h: aisafeguard_store::ValueMetrics,
    pub metrics_7d: aisafeguard_store::ValueMetrics,
    pub ai: AiStatus,
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
        StatusReport {
            version: self.version.to_string(),
            uptime_secs: self.started.elapsed().as_secs(),
            backend: self.firewall.backend().to_string(),
            elevated: self.firewall.is_elevated(),
            honeypot_enabled: cfg.honeypot.enabled,
            listeners: self
                .honeypot
                .listeners
                .iter()
                .map(|l| ListenerInfo {
                    name: l.name.clone(),
                    port: l.port,
                    kind: l.kind.clone(),
                })
                .collect(),
            rule_count: self.store.count_rules().unwrap_or(0),
            pending_proposals: self.store.count_proposals("pending").unwrap_or(0),
            hits_24h,
            attackers_24h: stats.unique_ips,
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
        }
    }

    pub fn list_events(&self, limit: u32, ip_filter: Option<&str>) -> Result<Vec<EventRow>> {
        self.store.recent_events(limit, ip_filter)
    }

    pub fn list_rules(&self) -> Result<Vec<RuleRow>> {
        self.store.list_rules()
    }

    pub fn list_proposals(&self, status: Option<&str>, limit: u32) -> Result<Vec<ProposalRow>> {
        self.store.list_proposals(status, limit)
    }

    pub fn list_ai_runs(&self, limit: u32) -> Result<Vec<AiRunRow>> {
        self.store.list_ai_runs(limit)
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
        let p = self
            .store
            .get_proposal(id)?
            .ok_or_else(|| Error::Store(format!("建议 #{id} 不存在")))?;
        if p.status != "pending" {
            return Err(Error::Store(format!(
                "建议 #{id} 状态为 {}，无法应用",
                p.status
            )));
        }
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
        let spec = BlockSpec {
            direction,
            protocol,
            remote_ip,
            local_port: p.local_port,
            note: format!("AI 建议 #{}: {}", p.id, p.reason),
            tag: "AI".into(),
        };
        // 灰度执行（AI 深度介入 v1）：AI 建议应用即短 TTL 试运行，到期自动解封；
        // AI 明确给了 ttl_secs 用它的，否则用配置的默认灰度时长。人工"转正"才延长。
        let trial_ttl = p.ttl_secs.unwrap_or(self.config().ai.trial_ttl_secs as i64);
        let row = self.add_block_ex(&spec, "ai", Some(now_ts() + trial_ttl))?;
        self.store
            .set_proposal_status(id, "applied", Some(row.id))?;
        self.bus.publish(SecurityEvent::ProposalApplied {
            ts: now_ts(),
            proposal_id: id,
            rule_name: row.name.clone(),
        });
        Ok(row)
    }

    pub fn dismiss_proposal(&self, id: i64) -> Result<()> {
        let p = self
            .store
            .get_proposal(id)?
            .ok_or_else(|| Error::Store(format!("建议 #{id} 不存在")))?;
        if p.status == "pending" {
            self.store.set_proposal_status(id, "dismissed", None)?;
        }
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
        self.store.update_rule_expires(id, Some(expires))?;
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
                "误报反馈：{src} 已标记（自动封禁抑制 30 天；解封 {removed} 条规则，收弃 {dismissed} 条建议）"
            ),
        ));
        Ok((dismissed, removed))
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
        self.rt.spawn(async move {
            run_analysis(&eng).await;
            eng.ai_running.store(false, Ordering::Relaxed);
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

/// 快路径判定统一出口：广播 Detection；auto 时自动封禁（TTL + 内网保护 + 审计）。
/// 频次引擎（蜜罐源）与采样捕获（真实流量源）都走这里，行为一致。
/// F6 解耦：是否自动封禁由调用方决定——内置检测器看 [detect].auto_block，
/// 规则命中看 [detect.rules].auto_block（默认 false 只告警）。
#[allow(clippy::too_many_arguments)] // 证据/规则/L7 字段并列，语义清晰
fn handle_detection(
    sink: &DetectionSink<'_>,
    kind: &str,
    ip: IpAddr,
    evidence: &str,
    rule_id: Option<&str>,
    dcfg: &DetectConfig,
    auto_block: bool,
    severity: &str,
    hint: Option<aisafeguard_l7::HttpHint>,
    tls_fp: Option<String>,
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
        http_hint: hint,
        tls_fingerprint: tls_fp,
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
            sink.bus.publish(SecurityEvent::engine(
                "info",
                format!("已自动封禁 {src} 至 {until}（规则 {}）", row.name),
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
                            None,
                            None,
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
                                None,
                                None,
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
                            // 整包拒绝：新包不生效；旧包（若有）保持，避免规则引擎空窗
                            let note = format!("加载失败（整包拒绝）：{e}");
                            eng.rules.set_current(None, &cfg.path, &note);
                            eng.bus.publish(SecurityEvent::engine(
                                "error",
                                format!("规则包加载失败（整包拒绝，不半生效）: {e}"),
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
                            // E6：full 模式流前缀解析 HTTP 提示与 JA3（TLS 才有）
                            let (hint, tls_fp) = if cap_cfg.mode == "full" {
                                match pipeline.stream_bytes(&d.key) {
                                    Some(stream) => {
                                        let hint = std::str::from_utf8(&stream)
                                            .ok()
                                            .and_then(aisafeguard_l7::parse_http_hint);
                                        let tls_fp =
                                            aisafeguard_l7::parse_ja3(&stream).map(|j| j.md5);
                                        (hint, tls_fp)
                                    }
                                    None => (None, None),
                                }
                            } else {
                                (None, None)
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
                                hint,
                                tls_fp,
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
                                        None,
                                        None,
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

/// TTL 到期自动解封：每 60 秒扫一次到期规则，移除防火墙规则并留痕。
pub fn spawn_expiry_janitor(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok(expired) = eng.store.expired_rules(now_ts()) else {
                continue;
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
                if let Err(e) = eng.firewall.remove(&name, &spec) {
                    tracing::warn!("解封规则 {name} 失败: {e}");
                }
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

    let client = AiClient::new(&cfg.ai.base_url, &cfg.ai.model, &key);
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
            }),
        )
        .await;

    match result {
        Ok(content) => match aisafeguard_ai::parse_proposals(&content) {
            Ok((analysis, proposals)) => {
                let mut created = 0i64;
                let mut auto_applied = 0i64;
                for p in proposals {
                    if eng
                        .store
                        .pending_proposal_exists(&p.remote_ip, p.local_port)
                        .unwrap_or(true)
                    {
                        continue;
                    }
                    let Ok(pid) = eng.store.insert_proposal(
                        &cfg.ai.model,
                        &p.severity,
                        &p.direction,
                        &p.protocol,
                        &p.remote_ip,
                        p.local_port,
                        p.ttl_secs,
                        &p.reason,
                        &analysis,
                    ) else {
                        continue;
                    };
                    eng.bus.publish(SecurityEvent::ProposalCreated {
                        ts: now_ts(),
                        proposal_id: pid,
                        severity: p.severity.clone(),
                        reason: p.reason.clone(),
                    });
                    created += 1;
                    let severity_ok = aisafeguard_ai::severity_rank(&p.severity)
                        >= aisafeguard_ai::severity_rank(&cfg.ai.auto_apply_min_severity);
                    // 自动应用尊重误报反馈（人工确认的应用不受影响）；
                    // fp_ignore_min_severity 配置后，达到该档及以上的建议忽略抑制
                    let ignore_fp = !cfg.ai.fp_ignore_min_severity.is_empty()
                        && aisafeguard_ai::severity_rank(&p.severity)
                            >= aisafeguard_ai::severity_rank(&cfg.ai.fp_ignore_min_severity);
                    let fp_suppressed = p
                        .remote_ip
                        .parse::<IpAddr>()
                        .map(|ip| {
                            eng.store
                                .active_fp(
                                    &ip.to_string(),
                                    now_ts(),
                                    cfg.ai.fp_suppress_secs as i64,
                                    p.local_port,
                                )
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    // quorum（0.4.0 C3）：来源有协同上报但独立节点数不足时不自动应用；
                    // 无任何上报（本地判断）不阻塞——单节点部署不假死
                    let quorum_ok = if cfg.fed.min_peers == 0 {
                        true
                    } else {
                        match p.remote_ip.parse::<IpAddr>() {
                            Ok(ip) => {
                                let reporters = eng
                                    .store
                                    .fed_reporter_count(&ip.to_string(), now_ts() - 7 * 86_400)
                                    .unwrap_or(0);
                                reporters == 0 || reporters as u32 >= cfg.fed.min_peers
                            }
                            Err(_) => true,
                        }
                    };
                    if cfg.ai.auto_apply
                        && severity_ok
                        && quorum_ok
                        && (ignore_fp || !fp_suppressed)
                        && eng.apply_proposal(pid).is_ok()
                    {
                        auto_applied += 1;
                    }
                }
                let mut summary = format!("分析完成：生成 {created} 条建议");
                if auto_applied > 0 {
                    summary.push_str(&format!("，自动应用 {auto_applied} 条"));
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

    fn list_rules(&self) -> anyhow::Result<Vec<RuleRow>> {
        self.0.list_rules().map_err(anyhow::Error::msg)
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
    let mut entries: Vec<aisafeguard_detect::intel::IntelEntry> = Vec::new();

    // 1) 情报源（默认 Feodo C2，高置信度；feed_url 可覆盖）
    match aisafeguard_detect::intel::fetch_blocklist(&http, &cfg.feed_url).await {
        Ok(ips) => {
            for ip in ips {
                entries.push(aisafeguard_detect::intel::IntelEntry {
                    source: "feodo_c2".into(),
                    kind: "c2".into(),
                    value: ip,
                    confidence: "high".into(),
                    first_seen: now,
                    expires_ts: now + 3 * 86400,
                });
            }
        }
        Err(e) => {
            tracing::warn!("情报拉取失败（离线或源不可达，跳过本轮）: {e}");
            // 源不可达不产生空情报覆盖
            return;
        }
    }

    // 2) 本地蜜罐源（最近 7 天命中过的来源，仅标注，不自动封禁）
    if let Ok(hits) = eng.store.recent_honeypot_hits(2000) {
        let mut seen = std::collections::HashSet::new();
        for h in hits {
            if h.remote_ip.is_empty()
                || h.remote_ip == "unknown"
                || !seen.insert(h.remote_ip.clone())
            {
                continue;
            }
            entries.push(aisafeguard_detect::intel::IntelEntry {
                source: "local_honeypot".into(),
                kind: "scan_source".into(),
                value: h.remote_ip,
                confidence: "local".into(),
                first_seen: now,
                expires_ts: now + 7 * 86400,
            });
        }
    }

    let upserts: Vec<(String, String, String, String, i64, i64)> = entries
        .iter()
        .map(|e| {
            (
                e.source.clone(),
                e.kind.clone(),
                e.value.clone(),
                e.confidence.clone(),
                e.first_seen,
                e.expires_ts,
            )
        })
        .collect();
    let n = eng.store.upsert_intel(&upserts).unwrap_or(0);
    let _ = eng.store.prune_intel(now);

    // 3) 高置信度 C2 自动封禁（TTL 3 天，内网保护，已封跳过）
    let mut blocked = 0;
    if cfg.auto_block {
        let existing: std::collections::HashSet<String> = eng
            .store
            .list_rules()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.remote_ip.parse::<IpAddr>().is_ok())
            .map(|r| r.remote_ip)
            .collect();
        for e in &entries {
            if e.confidence != "high" || e.kind != "c2" {
                continue;
            }
            let Ok(ip) = e.value.parse::<IpAddr>() else {
                continue;
            };
            if aisafeguard_core::is_protected_ip(ip) || existing.contains(&e.value) {
                continue;
            }
            let spec = BlockSpec {
                direction: Direction::In,
                protocol: Protocol::Any,
                remote_ip: Some(ip),
                local_port: None,
                note: format!("威胁情报自动封禁（{} / TTL 3 天）", e.source),
                tag: "情报".into(),
            };
            if eng
                .add_block_ex(&spec, "intel", Some(now + 3 * 86400))
                .is_ok()
            {
                blocked += 1;
            }
        }
    }

    let active = eng.store.active_intel(now).map(|v| v.len()).unwrap_or(0);
    eng.bus.publish(SecurityEvent::engine(
        "info",
        format!(
            "威胁情报更新：入库 {n} 条（Feodo C2 {}），活跃 {active}，自动封禁 {blocked}",
            entries.iter().filter(|e| e.source == "feodo_c2").count()
        ),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
            None,
            None,
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
                None,
                None,
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
            None,
            None,
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
            None,
            None,
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
            None,
            None,
        );
        assert_eq!(
            f2.fw.added.lock().unwrap().len(),
            1,
            "显式 auto_block=true 才自动封禁"
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
