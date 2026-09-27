use serde::Serialize;
use tokio::sync::broadcast;

/// 统一安全事件。所有模块只通过事件总线对话，互不直接依赖。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecurityEvent {
    HoneypotHit {
        ts: i64,
        listener: String,
        kind: String,
        port: u16,
        remote_ip: String,
        remote_port: u16,
        summary: String,
        payload: String,
    },
    FirewallRuleAdded {
        ts: i64,
        name: String,
        detail: String,
        origin: String,
    },
    FirewallRuleRemoved {
        ts: i64,
        name: String,
    },
    ProposalCreated {
        ts: i64,
        proposal_id: i64,
        severity: String,
        reason: String,
    },
    ProposalApplied {
        ts: i64,
        proposal_id: i64,
        rule_name: String,
    },
    AiRun {
        ts: i64,
        ok: bool,
        summary: String,
    },
    /// 快路径检测器产出（端口扫描/暴破/洪水等，见 docs/NGFW_EVOLUTION.md）。
    Detection {
        ts: i64,
        /// scan | bruteforce | flood | signature | intel_hit
        kind: String,
        src_ip: String,
        confidence: String,
        evidence: String,
        rule_id: Option<String>,
    },
    Engine {
        ts: i64,
        level: String,
        message: String,
    },
}

impl SecurityEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            SecurityEvent::HoneypotHit { .. } => "honeypot_hit",
            SecurityEvent::FirewallRuleAdded { .. } => "firewall_add",
            SecurityEvent::FirewallRuleRemoved { .. } => "firewall_remove",
            SecurityEvent::ProposalCreated { .. } => "proposal_created",
            SecurityEvent::ProposalApplied { .. } => "proposal_applied",
            SecurityEvent::AiRun { .. } => "ai_run",
            SecurityEvent::Detection { .. } => "detection",
            SecurityEvent::Engine { .. } => "engine",
        }
    }

    pub fn ts(&self) -> i64 {
        match self {
            SecurityEvent::HoneypotHit { ts, .. }
            | SecurityEvent::FirewallRuleAdded { ts, .. }
            | SecurityEvent::FirewallRuleRemoved { ts, .. }
            | SecurityEvent::ProposalCreated { ts, .. }
            | SecurityEvent::ProposalApplied { ts, .. }
            | SecurityEvent::AiRun { ts, .. }
            | SecurityEvent::Detection { ts, .. }
            | SecurityEvent::Engine { ts, .. } => *ts,
        }
    }

    /// 单行摘要，用于事件流水展示与入库。
    pub fn summary(&self) -> String {
        match self {
            SecurityEvent::HoneypotHit { summary, .. } => summary.clone(),
            SecurityEvent::FirewallRuleAdded { name, detail, .. } => {
                format!("{name}: {detail}")
            }
            SecurityEvent::FirewallRuleRemoved { name, .. } => {
                format!("移除规则 {name}")
            }
            SecurityEvent::ProposalCreated { severity, reason, .. } => {
                format!("[{severity}] {reason}")
            }
            SecurityEvent::ProposalApplied { rule_name, .. } => {
                format!("建议已应用为规则 {rule_name}")
            }
            SecurityEvent::AiRun { ok, summary, .. } => {
                format!("{}{summary}", if *ok { "✓ " } else { "✗ " })
            }
            SecurityEvent::Detection { kind, src_ip, evidence, .. } => {
                format!("[{kind}] {src_ip}: {evidence}")
            }
            SecurityEvent::Engine { level, message, .. } => {
                format!("[{level}] {message}")
            }
        }
    }

    pub fn engine(level: &str, message: impl Into<String>) -> Self {
        SecurityEvent::Engine {
            ts: crate::now_ts(),
            level: level.to_string(),
            message: message.into(),
        }
    }
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<SecurityEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(16));
        Self { tx }
    }

    /// 无订阅者时静默丢弃——事件总线不阻塞任何生产者。
    pub fn publish(&self, ev: SecurityEvent) {
        tracing::debug!(kind = ev.kind(), "{}", ev.summary());
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SecurityEvent> {
        self.tx.subscribe()
    }
}
