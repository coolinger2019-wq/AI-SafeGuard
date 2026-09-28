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
            ai: AiStatus {
                enabled: cfg.ai.enabled,
                model: cfg.ai.model.clone(),
                key_source: key_source().to_string(),
                running: self.ai_running.load(Ordering::Relaxed),
                auto_apply: cfg.ai.auto_apply,
                auto_apply_min_severity: cfg.ai.auto_apply_min_severity.clone(),
                analyze_interval_secs: cfg.ai.analyze_interval_secs,
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
    pub fn add_block_ex(&self, spec: &BlockSpec, origin: &str, expires_ts: Option<i64>) -> Result<RuleRow> {
        apply_block(&*self.firewall, &self.store, &self.bus, spec, origin, expires_ts)
    }

    pub fn remove_rule(&self, id: i64) -> Result<()> {
        let row = self
            .store
            .get_rule(id)?
            .ok_or_else(|| Error::Store(format!("规则 #{id} 不存在")))?;
        if !row.name.starts_with(RULE_PREFIX) {
            return Err(Error::Firewall(format!("拒绝删除非 AI-SafeGuard 规则: {}", row.name)));
        }
        let direction = if row.direction == "in" { Direction::In } else { Direction::Out };
        let remote_ip = row.remote_ip.parse::<IpAddr>().ok();
        self.firewall.remove(&row.name, remote_ip, direction)?;
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
            return Err(Error::Store(format!("建议 #{id} 状态为 {}，无法应用", p.status)));
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
        };
        let row = self.add_block(&spec, "ai")?;
        self.store.set_proposal_status(id, "applied", Some(row.id))?;
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

    pub fn save_config(&self, new_cfg: AppConfig) -> Result<()> {
        new_cfg.save(&self.cfg_path)?;
        *self.cfg.write().expect("配置锁中毒") = new_cfg;
        self.bus
            .publish(SecurityEvent::engine("info", "配置已保存（蜜罐/API 端口等重启后生效）"));
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
}

/// 快路径判定统一出口：广播 Detection；auto_block 时自动封禁（TTL + 内网保护 + 审计）。
/// 频次引擎（蜜罐源）与采样捕获（真实流量源）都走这里，行为一致。
fn handle_detection(
    sink: &DetectionSink<'_>,
    kind: &str,
    ip: IpAddr,
    evidence: &str,
    rule_id: Option<&str>,
    dcfg: &DetectConfig,
) {
    let src = ip.to_string();
    sink.bus.publish(SecurityEvent::Detection {
        ts: now_ts(),
        kind: kind.to_string(),
        src_ip: src.clone(),
        confidence: "high".into(),
        evidence: evidence.to_string(),
        rule_id: rule_id.map(str::to_string),
    });
    if !dcfg.auto_block {
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
    let spec = BlockSpec {
        direction: Direction::In,
        protocol: Protocol::Any,
        remote_ip: Some(ip),
        local_port: None,
        note: format!("检测器自动封禁（TTL {}s）: {evidence}", dcfg.ttl_secs),
    };
    match apply_block(sink.fw, sink.store, sink.bus, &spec, "engine", Some(now_ts() + dcfg.ttl_secs)) {
        Ok(row) => {
            let until = row
                .expires_ts
                .and_then(|t| {
                    chrono::DateTime::from_timestamp(t, 0)
                        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
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
                    ..
                }) => {
                    let Ok(ip) = remote_ip.parse::<IpAddr>() else {
                        continue;
                    };
                    let cfg = eng.config().detect;
                    for d in eng.detect.observe(now_ts(), ip, &listener, port, &cfg) {
                        handle_detection(&DetectionSink { fw: &*eng.firewall, store: &eng.store, bus: &eng.bus }, d.kind, ip, &d.evidence, None, &cfg);
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
                                if !snippet.is_empty() {
                                    evidence.push_str(&format!("；载荷摘要: {snippet}"));
                                }
                            }
                            let dcfg = eng.config().detect;
                            handle_detection(&DetectionSink { fw: &*eng.firewall, store: &eng.store, bus: &eng.bus }, d.kind, d.src, &evidence, Some(d.rule_id), &dcfg);
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let now = now_ts();
                        if now - last_sweep >= 10 {
                            pipeline.sweep(now, &eng.config().detect.capture);
                            last_sweep = now;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        eng.capture.set_error("捕获线程已退出（驱动停止或句柄关闭）");
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
                let direction = if row.direction == "in" { Direction::In } else { Direction::Out };
                let remote_ip = row.remote_ip.parse::<IpAddr>().ok();
                if let Err(e) = eng.firewall.remove(&name, remote_ip, direction) {
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
    let events_json = serde_json::json!(hits
        .iter()
        .map(|h| serde_json::json!({
            "ts": h.ts,
            "listener": h.listener,
            "remote_ip": h.remote_ip,
            "summary": h.summary,
            "payload": truncate(&h.payload, max_chars),
        }))
        .collect::<Vec<_>>())
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

    let client = AiClient::new(&cfg.ai.base_url, &cfg.ai.model, &key);
    let result = client
        .chat(
            aisafeguard_ai::SYSTEM_PROMPT,
            &aisafeguard_ai::build_user_prompt(
                &stats_json,
                &events_json,
                exposure_json.as_deref(),
                intel_json.as_deref(),
            ),
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
                    if cfg.ai.auto_apply && severity_ok && eng.apply_proposal(pid).is_ok() {
                        auto_applied += 1;
                    }
                }
                let mut summary = format!("分析完成：生成 {created} 条建议");
                if auto_applied > 0 {
                    summary.push_str(&format!("，自动应用 {auto_applied} 条"));
                }
                let _ = eng.store.insert_ai_run(&cfg.ai.model, true, &truncate(&summary, 500));
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
        self.0.list_events(limit, ip_filter).map_err(anyhow::Error::msg)
    }

    fn list_rules(&self) -> anyhow::Result<Vec<RuleRow>> {
        self.0.list_rules().map_err(anyhow::Error::msg)
    }

    fn list_proposals(&self, status: Option<&str>, limit: u32) -> anyhow::Result<Vec<ProposalRow>> {
        self.0.list_proposals(status, limit).map_err(anyhow::Error::msg)
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

pub async fn run_intel_refresh(eng: &Arc<EngineHandle>, cfg: &aisafeguard_core::config::IntelConfig) {
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
            if h.remote_ip.is_empty() || h.remote_ip == "unknown" || !seen.insert(h.remote_ip.clone()) {
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
            let Ok(ip) = e.value.parse::<IpAddr>() else { continue };
            if aisafeguard_core::is_protected_ip(ip) || existing.contains(&e.value) {
                continue;
            }
            let spec = BlockSpec {
                direction: Direction::In,
                protocol: Protocol::Any,
                remote_ip: Some(ip),
                local_port: None,
                note: format!("威胁情报自动封禁（{} / TTL 3 天）", e.source),
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
        fn remove(&self, name: &str, _ip: Option<IpAddr>, _d: Direction) -> Result<()> {
            self.removed.lock().expect("mock 锁中毒").push(name.to_string());
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
            let dir = std::env::temp_dir().join(format!("aisafeguard-test-{tag}-{}", uuid::Uuid::new_v4()));
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
            &DetectionSink { fw: &f.fw, store: &f.store, bus: &f.bus },
            "scan",
            "203.0.113.7".parse().unwrap(),
            "60 秒内对 3 个不同目标端口发送 SYN",
            Some("builtin.tcp_scan"),
            &f.dcfg(),
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
                &DetectionSink { fw: &f.fw, store: &f.store, bus: &f.bus },
                "flood",
                ip.parse().unwrap(),
                "100 个纯 SYN",
                Some("builtin.syn_flood"),
                &f.dcfg(),
            );
        }
        assert!(f.fw.added.lock().unwrap().is_empty(), "内网/回环地址必须零封禁");
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
            &DetectionSink { fw: &f.fw, store: &f.store, bus: &f.bus },
            "scan",
            "203.0.113.9".parse().unwrap(),
            "证据",
            None,
            &dcfg,
        );
        assert!(f.fw.added.lock().unwrap().is_empty(), "auto_block=false 不得封禁");
        assert_eq!(f.store.list_rules().unwrap().len(), 0);
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
        };
        assert!(apply_block(&f.fw, &f.store, &f.bus, &spec, "test", None).is_err());
        assert!(f.fw.added.lock().unwrap().is_empty());
    }
}
