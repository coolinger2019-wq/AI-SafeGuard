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

    /// RFC 5424 严重度（0 emerg … 7 debug，数值越小越严重）。syslog 转发与
    /// webhook 告警共用同一映射，保证两条外发通道对"多严重"口径一致。
    pub fn severity(&self) -> u8 {
        match self {
            // 检测判定与封禁执行是安全产品最核心的告警
            SecurityEvent::Detection { .. } => 4, // warning
            SecurityEvent::FirewallRuleAdded { .. } => 4,
            SecurityEvent::ProposalApplied { .. } => 4,
            // 蜜罐被触碰、AI 产出建议：值得看但未执行处置
            SecurityEvent::HoneypotHit { .. } => 5, // notice
            SecurityEvent::ProposalCreated { .. } => 5,
            // 例行流水
            SecurityEvent::FirewallRuleRemoved { .. } => 6, // informational（TTL 到期解封是常态）
            SecurityEvent::AiRun { .. } => 6,
            SecurityEvent::Engine { level, .. } => match level.as_str() {
                "error" => 3, // err
                "warn" => 4,
                "info" => 6,
                _ => 5,
            },
        }
    }

    /// severity 数值 → RFC 5424 名称（展示与配置值共用）。
    pub fn severity_name(sev: u8) -> &'static str {
        match sev {
            0 => "emerg",
            1 => "alert",
            2 => "crit",
            3 => "error",
            4 => "warning",
            5 => "notice",
            6 => "info",
            _ => "debug",
        }
    }

    /// 告警通道的过滤配置值 → 数值阈值（非法值回退 warning）。
    pub fn severity_threshold(name: &str) -> u8 {
        match name {
            "error" => 3,
            "notice" => 5,
            "info" => 6,
            _ => 4,
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
