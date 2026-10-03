use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

// Detection 变体携带 L7 提示（0.5.0 E6）——aisafeguard-l7 是无依赖纯解析 crate
use aisafeguard_l7::HttpHint;

/// 蜜罐交互会话的逐命令记录（0.5.9 H102）：中交互假 Shell 每条命令记一条。
/// command/response 均为清洗截断后的文本——攻击者输入永远不可信，永不原样落库。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellStep {
    pub command: String,
    pub response: String,
}

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
        /// 结构化 HTTP 提示（0.5.6 F13：http 蜜罐可解析时出现）
        #[serde(skip_serializing_if = "Option::is_none")]
        http_hint: Option<HttpHint>,
        /// 交互会话逐命令记录（0.5.9 H102：中交互假 Shell 才有，低交互为 None。
        /// 不进哈希链 canonical——与 http_hint 同类的证据明细，保证存量链兼容）
        #[serde(skip_serializing_if = "Option::is_none")]
        interaction: Option<Vec<ShellStep>>,
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
        /// scan | bruteforce | flood | signature | intel_hit | mcp_ghost（F792a：蜜罐幽灵工具定罪）
        kind: String,
        src_ip: String,
        confidence: String,
        /// 判定严重度（0.5.0 F4）：critical|high|medium|low——规则命中按 classtype
        /// 映射（RULESET_SUBSET.md），内置检测器 scan/bruteforce/flood 归 medium
        severity: String,
        evidence: String,
        rule_id: Option<String>,
        /// HTTP 提示（0.5.0 E6：full 捕获流重组可解析时出现）
        #[serde(skip_serializing_if = "Option::is_none")]
        http_hint: Option<HttpHint>,
        /// JA3 客户端指纹 md5（0.5.0 E6：TLS ClientHello 可见时出现）
        #[serde(skip_serializing_if = "Option::is_none")]
        tls_fingerprint: Option<String>,
        /// JA4 客户端指纹（0.5.0 E5：[detect.l7].ja4 开启且 ClientHello 可见时出现）
        #[serde(skip_serializing_if = "Option::is_none")]
        tls_ja4: Option<String>,
    },
    /// 蜜罐凭证采集（0.5.10 H200）：蜜罐会话里的 用户名/口令 对。username 明文
    /// 用于与本地账号做喷洒比对；口令只携带 argon2id PHC 哈希（会话内加盐，不可逆），
    /// 明文在离开蜜罐 crate 前即被丢弃。pass_hash 为 None = 协议层面拿不到口令
    /// （MySQL 握手只有用户名，口令是不可逆的 scramble）。
    CredentialObserved {
        ts: i64,
        listener: String,
        /// 协议 kind（ssh | telnet | http | mysql | redis）
        kind: String,
        port: u16,
        remote_ip: String,
        remote_port: u16,
        username: String,
        /// argon2id PHC 串（含随机盐）；None = 无口令可采
        #[serde(skip_serializing_if = "Option::is_none")]
        pass_hash: Option<String>,
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
            SecurityEvent::CredentialObserved { .. } => "credential_observed",
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
            | SecurityEvent::CredentialObserved { ts, .. }
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
            SecurityEvent::ProposalCreated {
                severity, reason, ..
            } => {
                format!("[{severity}] {reason}")
            }
            SecurityEvent::ProposalApplied { rule_name, .. } => {
                format!("建议已应用为规则 {rule_name}")
            }
            SecurityEvent::AiRun { ok, summary, .. } => {
                format!("{}{summary}", if *ok { "✓ " } else { "✗ " })
            }
            SecurityEvent::Detection {
                kind,
                src_ip,
                evidence,
                ..
            } => {
                format!("[{kind}] {src_ip}: {evidence}")
            }
            SecurityEvent::CredentialObserved {
                username, listener, ..
            } => {
                format!("凭证采集: {username}@{listener}")
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
            // 蜜罐被触碰、AI 产出建议、凭证被采集：值得看但未执行处置
            SecurityEvent::HoneypotHit { .. } => 5, // notice
            SecurityEvent::ProposalCreated { .. } => 5,
            SecurityEvent::CredentialObserved { .. } => 5,
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
