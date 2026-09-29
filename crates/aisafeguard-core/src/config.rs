use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secrets;

/// 顶层配置。config.toml 中缺失的字段取默认值，写错的字段直接报错（不静默兼容）。
/// 配置文件不承载任何秘密：AI Key 在凭据管理器（或环境变量），API token 同理。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub api: ApiConfig,
    pub honeypot: HoneypotConfig,
    pub ai: AiConfig,
    pub detect: DetectConfig,
    pub xdp: XdpConfig,
    pub intel: IntelConfig,
    pub fed: FedConfig,
    pub syslog: SyslogConfig,
    pub notify: NotifyConfig,
    pub exposure: ExposureConfig,
    pub ui: UiConfig,
}

/// 界面外观（GUI 设置页可切换，保存后即时生效并保持）。
/// 配色方案与字号缩放的具体定义在 aisafeguard-app 的 gui/theme.rs
/// （core 不依赖 GUI，这里只做持久化；主题名写错时界面回退默认方案）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// deep_blue（默认深色）| light | warm | contrast（高对比）
    pub theme: String,
    /// 全局字号缩放，0.85–1.6，默认 1.15（正文约 16.7px，舒适档）
    pub font_scale: f32,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "deep_blue".into(),
            font_scale: 1.15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    /// 覆盖默认数据目录（%LOCALAPPDATA%\aisafeguard）。空 = 用默认。
    pub data_dir: PathBuf,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub enabled: bool,
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 7420,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HoneypotConfig {
    pub enabled: bool,
    pub listeners: Vec<ListenerConfig>,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listeners: vec![
                ListenerConfig {
                    name: "ssh".into(),
                    port: 2222,
                    kind: "ssh".into(),
                },
                ListenerConfig {
                    name: "http".into(),
                    port: 8081,
                    kind: "http".into(),
                },
                ListenerConfig {
                    name: "telnet".into(),
                    port: 2323,
                    kind: "telnet".into(),
                },
                ListenerConfig {
                    name: "generic".into(),
                    port: 1337,
                    kind: "generic".into(),
                },
            ],
        }
    }
}

/// kind 取值：ssh | http | telnet | generic
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    pub port: u16,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    pub enabled: bool,
    /// OpenAI 兼容端点，默认智谱 GLM；封闭内网可指向本地推理（Ollama/vLLM）。
    pub base_url: String,
    pub model: String,
    pub auto_apply: bool,
    /// auto_apply 生效的最低严重度：low | medium | high | critical
    pub auto_apply_min_severity: String,
    pub analyze_interval_secs: u64,
    /// 上送给 LLM 的单条 payload 最大字符数。
    pub max_snippet_chars: usize,
    /// 误报抑制期（秒，0.5.5 F8 可配置，默认 14 天，建议 7～14 天）：用户标记过
    /// 误报的来源，自动封禁/自动应用在此期间跳过；人工手动封禁不受影响。
    pub fp_suppress_secs: u64,
    /// 高严重度忽略抑制（0.4.0 B3 可选）：设为 medium|high|critical 时，
    /// 达到该档及以上的 AI 建议自动应用不再受误报抑制约束；空 = 不忽略（默认）。
    /// 仅作用于 auto_apply——检测器快路径的自动封禁始终尊重抑制。
    pub fp_ignore_min_severity: String,
    /// 灰度执行：AI 建议应用时的默认封禁时长（秒，AI 未给 ttl_secs 时使用）。
    /// AI 判断是概率性的——应用即短 TTL 试运行，到期自动解封，人工确认后转正。
    pub trial_ttl_secs: u64,
    /// 转正时长（秒）：灰度规则经人工"转正"后的封禁时长（默认 30 天）。
    pub promote_ttl_secs: u64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://open.bigmodel.cn/api/paas/v4".into(),
            model: "glm-4.7".into(),
            fp_suppress_secs: 1_209_600,
            fp_ignore_min_severity: String::new(),
            auto_apply: false,
            auto_apply_min_severity: "high".into(),
            analyze_interval_secs: 900,
            max_snippet_chars: 200,
            trial_ttl_secs: 900,
            promote_ttl_secs: 2_592_000,
        }
    }
}

impl AiConfig {
    /// Key 的优先级：环境变量 AISAFEGUARD_AI_KEY > 凭据管理器。
    pub fn effective_key(&self) -> String {
        if let Some(v) = std::env::var("AISAFEGUARD_AI_KEY")
            .ok()
            .filter(|v| !v.is_empty())
        {
            return v;
        }
        secrets::ai_key().unwrap_or_default()
    }
}

/// 本地频次检测（快路径第一块，设计见 docs/NGFW_EVOLUTION.md）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectConfig {
    pub enabled: bool,
    /// 触发后是否自动封禁（TTL 到期自动解封 + 内网保护）。
    pub auto_block: bool,
    /// 端口扫描判定：window_secs 内触达 ≥ scan_distinct_ports 个不同蜜罐端口。
    pub scan_distinct_ports: u32,
    /// 暴力探测判定：同一 (来源, 监听器) window_secs 内 ≥ bruteforce_hits 次。
    pub bruteforce_hits: u32,
    pub window_secs: i64,
    /// 自动封禁 TTL（秒），到期自动解封。
    pub ttl_secs: i64,
    /// 采样捕获（检测平台 MVP，0.3 第二批）：真实流量观测。
    pub capture: CaptureConfig,
    /// L7 解析与指纹（0.5.0 Batch E/H5）：full 捕获流前缀的 HttpHint / JA3。
    pub l7: L7Config,
    /// 开放规则子集引擎（0.5.0 Batch F，规范见 docs/RULESET_SUBSET.md）。
    pub rules: RulesConfig,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_block: true,
            scan_distinct_ports: 5,
            bruteforce_hits: 10,
            window_secs: 60,
            ttl_secs: 1800,
            capture: CaptureConfig::default(),
            l7: L7Config::default(),
            rules: RulesConfig::default(),
        }
    }
}

/// L7 解析门控（0.5.0 H5）。E6 的 http_hint/tls_fingerprint 只在
/// `[detect.capture].mode=full` 且本段 enabled 时产出（默认关闭——深检默认 off）。
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct L7Config {
    /// L7 解析总开关（HttpHint）
    pub enabled: bool,
    /// JA3 客户端指纹（TLS ClientHello 可见时）
    pub ja3: bool,
    /// JA4 客户端指纹（0.5.0 E5，默认关）
    pub ja4: bool,
}

impl Default for L7Config {
    fn default() -> Self {
        Self {
            enabled: false,
            ja3: true,
            ja4: false,
        }
    }
}

/// Suricata/ET 风格规则子集（0.5.0 Batch F）。命中只产事件；是否自动封禁
/// 由本段 auto_block 独立决定（默认 false 只告警——F6 与快路径 auto_block 解耦）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesConfig {
    /// 默认关闭：规则匹配逐窗执行，用户显式开启
    pub enabled: bool,
    /// 本地规则包路径（单文件）；空 = 不加载。默认不内置任何规则包
    pub path: String,
    /// 规则命中自动封禁（仍受内网保护 + 误报抑制约束）
    pub auto_block: bool,
    /// 规则条数上限（整包校验）
    pub max_rules: u32,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: String::new(),
            auto_block: false,
            max_rules: 5000,
        }
    }
}

/// 真实流量采样捕获（0.3 第二批，设计见 docs/NGFW_EVOLUTION.md §2.2/§3）。
/// 采集说明：control 模式只采集 TCP 纯 SYN 包头（元数据，无载荷）；
/// full 模式采集完整 TCP 段用于流重组取证，载荷仅在被判定可疑时随证据截断留存。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// 默认关闭：捕获需要驱动/提权，且是对本机网络面的行为，用户显式开启
    pub enabled: bool,
    /// control = 仅 TCP 纯 SYN（默认，只看元数据）| full = 全 TCP 段（启用流重组取证）
    pub mode: String,
    /// 端口扫描判定：window_secs 内对 ≥ scan_distinct_ports 个不同目标端口发 SYN
    pub scan_distinct_ports: u32,
    /// 驱动完整性校验（Windows，0.4.0 A3）：期望的 WinDivert64.sys SHA-256（hex，小写）。
    /// 空 = 不校验（默认）；非空且驱动文件存在但哈希不符 → 捕获降级并留事件
    /// （供应链防护：只认官方渠道获取的驱动）。Linux 无驱动文件，忽略。
    pub driver_sha256: String,
    /// SYN flood 判定：同一 (来源, 目标 IP:端口) window_secs 内 ≥ syn_flood_rate 个 SYN
    pub syn_flood_rate: u32,
    pub window_secs: i64,
    /// 流表空闲回收（秒）
    pub flow_idle_secs: i64,
    /// 流表容量上限（超限驱逐最旧流）
    pub flow_table_cap: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "control".into(),
            scan_distinct_ports: 15,
            driver_sha256: String::new(),
            syn_flood_rate: 100,
            window_secs: 60,
            flow_idle_secs: 120,
            flow_table_cap: 65536,
        }
    }
}

impl CaptureConfig {
    pub fn valid_mode(&self) -> bool {
        matches!(self.mode.as_str(), "control" | "full")
    }
}

/// XDP 快速执行层（0.3.7，仅 Linux；设计见 docs/NGFW_EVOLUTION.md）。
/// nftables 永远兜底，XDP 只镜像「入站 + Any 协议 + 无端口 + IPv4」的封禁规则，
/// 内核收包路径直接丢弃（微秒级生效）。附加失败自动降级为纯 nftables。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XdpConfig {
    /// 默认关闭：需要 root/CAP_BPF，且是对本机数据面的行为，用户显式开启
    pub enabled: bool,
    /// 附加 XDP 程序的网卡
    pub iface: String,
    /// skb（generic XDP，所有网卡可用）| native（驱动级，更快，需网卡驱动支持）
    pub mode: String,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            iface: "eth0".into(),
            mode: "skb".into(),
        }
    }
}

impl XdpConfig {
    pub fn valid_mode(&self) -> bool {
        matches!(self.mode.as_str(), "skb" | "native")
    }
}

/// 威胁情报（0.3 v1：abuse.ch Feodo C2 + 本地蜜罐源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {
    /// 默认关闭：情报拉取是对外网络请求，用户显式开启
    pub enabled: bool,
    /// 高置信度 C2 情报自动封禁（TTL + 内网保护）
    pub auto_block: bool,
    pub interval_secs: u64,
    /// 情报源地址（默认 abuse.ch Feodo C2；可指向自托管/镜像源，测试友好）
    pub feed_url: String,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_block: true,
            interval_secs: 21600, // 6h
            feed_url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".into(),
        }
    }
}

/// 组织协同（0.3，设计见 docs/NGFW_EVOLUTION.md §6）。
/// 0.3.6 起鉴权 = mTLS 每节点证书（组织 CA 签发，node↔证书指纹绑定），
/// 组织共享令牌已整体移除（无兼容层）。证书文件不进配置文件本身，只记路径。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FedConfig {
    pub enabled: bool,
    /// off | coordinator | agent
    pub role: String,
    /// 节点名（上报时标识自己，[a-zA-Z0-9_-]{1,32}；需与签发证书时的节点名一致）
    pub node: String,
    /// agent 角色：协调者地址，如 https://192.168.1.10:7421
    pub coordinator: String,
    /// quorum（0.4.0 C3，默认 0 = 不启用）：>0 时，某来源若有协同节点上报
    /// 但独立节点数 < min_peers，其 AI 建议不自动应用（仅慢路径人工确认）。
    /// 该来源无任何协同上报时按本地策略照常（单节点部署不假死）。
    pub min_peers: u32,
    pub interval_secs: u64,
    /// coordinator 角色：/fed 面 mTLS 监听地址（独立于 127.0.0.1 的本地 API）
    pub listen_addr: String,
    /// 组织 CA 证书路径（agent 用于验证协调者；coordinator 用于验证 agent）。
    /// 空 = <数据目录>/fed/ca.pem
    pub ca_path: String,
    /// 本节点证书路径（coordinator 的服务端证书 = agent 的客户端证书）。
    /// 空 = <数据目录>/fed/cert.pem
    pub cert_path: String,
    /// 本节点私钥路径。空 = <数据目录>/fed/key.pem
    pub key_path: String,
}

impl Default for FedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: "off".into(),
            node: String::new(),
            coordinator: String::new(),
            min_peers: 0,
            interval_secs: 60,
            listen_addr: "0.0.0.0:7421".into(),
            ca_path: String::new(),
            cert_path: String::new(),
            key_path: String::new(),
        }
    }
}

impl FedConfig {
    pub fn valid_role(&self) -> bool {
        matches!(self.role.as_str(), "off" | "coordinator" | "agent")
    }
}

/// 日志远程转发 [A.8.15]（0.3.5）：事件总线 → RFC 5424 syslog（UDP / TCP 换行分帧）。
/// 事件总线是唯一数据源（解耦），转发是 best-effort：目标不可达只丢该条并留 tracing，
/// 绝不阻塞引擎；完整性校验仍以本地哈希链（verify-log / export-events）为准。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyslogConfig {
    pub enabled: bool,
    /// 收集器地址，如 127.0.0.1:514
    pub target: String,
    /// udp（RFC 5426）| tcp（RFC 6587 非透明分帧，每条一行）
    pub protocol: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target: "127.0.0.1:514".into(),
            protocol: "udp".into(),
        }
    }
}

impl SyslogConfig {
    pub fn valid_protocol(&self) -> bool {
        matches!(self.protocol.as_str(), "udp" | "tcp")
    }
}

/// 告警通知 [报表/告警]（0.3.5）：事件总线 → Webhook POST JSON。
/// 只发达到 min_severity 的事件（severity 数值越小越严重）；请求失败丢弃并限频留痕。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    pub enabled: bool,
    /// 接收端 URL（http/https），如企业微信/钉钉/Slack 兼容网关或自建接收器
    pub url: String,
    /// info | notice | warning | error —— 转发的最低严重度（含更严重者）
    pub min_severity: String,
    pub timeout_secs: u64,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_severity: "warning".into(),
            timeout_secs: 10,
        }
    }
}

impl NotifyConfig {
    pub fn valid_min_severity(&self) -> bool {
        matches!(
            self.min_severity.as_str(),
            "info" | "notice" | "warning" | "error"
        )
    }
}

/// 主机暴露面盘点（0.2 已有手动扫描；0.3.5 加定时自动扫描）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExposureConfig {
    /// 定时扫描间隔（秒）；0 = 关闭自动扫描（手动扫描不受影响）。
    pub auto_scan_secs: u64,
}

impl AppConfig {
    /// 返回 (配置, 文件是否为本次新建)
    pub fn load(path: &Path) -> Result<(Self, bool)> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::Config(format!("创建配置目录失败: {e}")))?;
            }
            let cfg = Self::default();
            cfg.save(path)?;
            return Ok((cfg, true));
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("读取配置失败: {e}")))?;
        let cfg = Self::parse_with_migration(path, &raw)?;
        Ok((cfg, false))
    }

    /// 0.2 迁移：0.1 配置里明文的 ai.api_key 一次性搬进凭据管理器并从文件删除。
    /// 这是数据搬迁，不是兼容层——迁移完成后配置里不再允许出现 api_key 字段。
    fn parse_with_migration(path: &Path, raw: &str) -> Result<Self> {
        let mut value: toml::Value =
            toml::from_str(raw).map_err(|e| Error::Config(format!("解析 {path:?} 失败: {e}")))?;
        let legacy_key = value
            .get("ai")
            .and_then(|ai| ai.get("api_key"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !legacy_key.is_empty() {
            secrets::set_ai_key(&legacy_key)?;
            tracing::info!("已将配置文件中的明文 API Key 迁移到凭据管理器");
        }
        if legacy_key.is_empty() && value.get("ai").and_then(|ai| ai.get("api_key")).is_some() {
            // 空 key 也清掉，让新结构能解析
            if let Some(t) = value.get_mut("ai").and_then(|v| v.as_table_mut()) {
                t.remove("api_key");
            }
            let cleaned = toml::to_string_pretty(&value)
                .map_err(|e| Error::Config(format!("序列化配置失败: {e}")))?;
            std::fs::write(path, cleaned)
                .map_err(|e| Error::Config(format!("写回配置失败: {e}")))?;
        }
        let cfg: Self = value
            .try_into()
            .map_err(|e: toml::de::Error| Error::Config(format!("解析 {path:?} 失败: {e}")))?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("创建配置目录失败: {e}")))?;
        }
        let raw = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("序列化配置失败: {e}")))?;
        std::fs::write(path, raw).map_err(|e| Error::Config(format!("写入配置失败: {e}")))?;
        Ok(())
    }

    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("aisafeguard")
            .join("config.toml")
    }

    pub fn default_data_dir() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("aisafeguard")
    }

    pub fn data_dir(&self) -> PathBuf {
        if self.general.data_dir.as_os_str().is_empty() {
            Self::default_data_dir()
        } else {
            self.general.data_dir.clone()
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir().join("aisafeguard.db")
    }

    /// 热更/重启分界（0.4.0 A4/A5 契约）：比对保存前后配置，
    /// 返回**必须重启引擎才能生效**的项名列表。空 = 全部热更生效。
    ///
    /// 契约（与实现同源，改任何一边先改这里）：
    /// - **热更**（任务每轮/每事件读最新配置，无需重启）：[detect] 全部阈值与开关、
    ///   [detect.capture].driver_sha256、[detect.l7] 全部（解析按事件门控）、
    ///   [detect.rules] 全部（enabled/路径/上限热更，规则包文件变化整包热重载）、
    ///   [xdp].enabled（未附加时下次装配生效；已附加状态读 composite）、
    ///   [syslog] / [notify] / [exposure] 全部、[ai] 全部、
    ///   [intel]、[fed] 运行期参数（interval_secs）
    /// - **需重启**：蜜罐监听列表与开关（端口绑定）、API 端口/开关、
    ///   捕获开关与模式（后端过滤语义固定于附加时）、XDP 网卡与模式、
    ///   fed 角色与证书材料、[general].data_dir
    pub fn restart_required(old: &AppConfig, new: &AppConfig) -> Vec<&'static str> {
        let mut out = Vec::new();
        if old.honeypot.enabled != new.honeypot.enabled
            || old.honeypot.listeners != new.honeypot.listeners
        {
            out.push("蜜罐监听");
        }
        if old.api != new.api {
            out.push("API 服务");
        }
        if old.detect.capture.enabled != new.detect.capture.enabled
            || old.detect.capture.mode != new.detect.capture.mode
        {
            out.push("流量采样捕获");
        }
        if old.xdp != new.xdp {
            out.push("XDP 快速执行层");
        }
        if old.fed.enabled != new.fed.enabled
            || old.fed.role != new.fed.role
            || old.fed.node != new.fed.node
            || old.fed.listen_addr != new.fed.listen_addr
            || old.fed.ca_path != new.fed.ca_path
            || old.fed.cert_path != new.fed.cert_path
            || old.fed.key_path != new.fed.key_path
        {
            out.push("组织协同");
        }
        if old.general.data_dir != new.general.data_dir {
            out.push("数据目录");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roundtrips() {
        let cfg = AppConfig::default();
        let raw = toml::to_string_pretty(&cfg).unwrap();
        let back: AppConfig = toml::from_str(&raw).unwrap();
        assert_eq!(back.honeypot.listeners.len(), 4);
        assert_eq!(back.api.port, 7420);
        assert!(!back.ai.enabled);
        assert!(back.detect.enabled);
        // 配置序列化不包含任何秘密字段
        assert!(!raw.contains("api_key"));
        assert!(!raw.contains("token"));
    }

    #[test]
    fn unknown_field_rejected() {
        let raw = "[general]\nwat = 1\n";
        assert!(toml::from_str::<AppConfig>(raw).is_err());
    }

    #[test]
    fn legacy_empty_api_key_rejected_by_schema() {
        // 带 deny_unknown_fields 的结构直接拒绝 api_key 字段——
        // 明文 key 的搬移在 AppConfig::load 的 pre-pass 里完成，不靠结构体兼容
        let raw = "[ai]\napi_key = \"\"\n";
        assert!(toml::from_str::<AppConfig>(raw).is_err());
    }

    /// 热更/重启分界契约（0.4.0 A4/A5）：各需重启项的判定分支。
    #[test]
    fn restart_required_contract() {
        let base = AppConfig::default();
        // 无变化 → 空
        assert!(AppConfig::restart_required(&base, &base).is_empty());

        // 蜜罐：监听列表或开关变化
        let mut honeypot = base.clone();
        honeypot.honeypot.enabled = !honeypot.honeypot.enabled;
        assert_eq!(AppConfig::restart_required(&base, &honeypot), ["蜜罐监听"]);
        let mut listener = base.clone();
        listener.honeypot.listeners[0].port = 1234;
        assert_eq!(AppConfig::restart_required(&base, &listener), ["蜜罐监听"]);

        // API 端口
        let mut api = base.clone();
        api.api.port = 7999;
        assert_eq!(AppConfig::restart_required(&base, &api), ["API 服务"]);

        // 捕获开关/模式
        let mut capture = base.clone();
        capture.detect.capture.mode = "full".into();
        assert_eq!(
            AppConfig::restart_required(&base, &capture),
            ["流量采样捕获"]
        );

        // XDP
        let mut xdp = base.clone();
        xdp.xdp.enabled = true;
        assert_eq!(AppConfig::restart_required(&base, &xdp), ["XDP 快速执行层"]);

        // fed 运行期参数（interval_secs）不算需重启
        let mut fed_interval = base.clone();
        fed_interval.fed.interval_secs = 99;
        assert!(AppConfig::restart_required(&base, &fed_interval).is_empty());
        // fed 角色变化算
        let mut fed = base.clone();
        fed.fed.role = "coordinator".into();
        assert_eq!(AppConfig::restart_required(&base, &fed), ["组织协同"]);

        // 热更项不计入：detect 阈值 / syslog / notify / exposure / ai / intel
        let mut hot = base.clone();
        hot.detect.scan_distinct_ports = 9;
        hot.detect.ttl_secs = 99;
        hot.detect.l7.enabled = true;
        hot.detect.l7.ja3 = false;
        hot.detect.rules.enabled = true;
        hot.detect.rules.path = "/tmp/rules.rules".into();
        hot.detect.rules.max_rules = 100;
        hot.syslog.enabled = true;
        hot.notify.min_severity = "info".into();
        hot.exposure.auto_scan_secs = 300;
        hot.ai.auto_apply = true;
        hot.ai.analyze_interval_secs = 60;
        hot.intel.interval_secs = 3600;
        assert!(
            AppConfig::restart_required(&base, &hot).is_empty(),
            "热更项不应被标为需重启：{:?}",
            AppConfig::restart_required(&base, &hot)
        );

        // 多项同时变化 → 全部列出
        let mut multi = base.clone();
        multi.api.port = 7999;
        multi.xdp.enabled = true;
        let req = AppConfig::restart_required(&base, &multi);
        assert_eq!(req, ["API 服务", "XDP 快速执行层"]);
    }

    /// 默认安全基线（0.5.0 H DoD）：深检/规则/XDP 全关、处置克制——
    /// 新增采集类配置时必须在这里补默认关断言，防止"默认安全"漂移。
    #[test]
    fn default_config_security_baseline() {
        let cfg = AppConfig::default();
        // 采样捕获与 L7 深检默认关（full 模式才有的载荷解析更不可能默认开）
        assert!(!cfg.detect.capture.enabled);
        assert!(!cfg.detect.l7.enabled);
        // 规则引擎默认关，且默认只告警（F6：与快路径 auto_block 解耦）
        assert!(!cfg.detect.rules.enabled);
        assert!(!cfg.detect.rules.auto_block);
        assert!(cfg.detect.rules.path.is_empty(), "默认不内置任何规则包");
        // XDP / 情报 / 协同 / 外发通道默认关
        assert!(!cfg.xdp.enabled);
        assert!(!cfg.intel.enabled);
        assert!(!cfg.fed.enabled);
        assert!(!cfg.syslog.enabled);
        assert!(!cfg.notify.enabled);
        // 蜜罐是唯一默认开的数据面（诱捕面，对攻击者暴露是产品语义）
        assert!(cfg.honeypot.enabled);
        // AI 默认人工确认
        assert!(!cfg.ai.enabled);
        assert!(!cfg.ai.auto_apply);
    }
}
