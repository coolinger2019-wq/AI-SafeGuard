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
    pub intel: IntelConfig,
    pub fed: FedConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://open.bigmodel.cn/api/paas/v4".into(),
            model: "glm-4.7".into(),
            auto_apply: false,
            auto_apply_min_severity: "high".into(),
            analyze_interval_secs: 900,
            max_snippet_chars: 200,
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
        }
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

/// 组织协同骨架（0.3，设计见 docs/NGFW_EVOLUTION.md §6）。
/// v1 用组织共享令牌鉴权；mTLS 每节点证书为后续加固项。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FedConfig {
    pub enabled: bool,
    /// off | coordinator | agent
    pub role: String,
    /// 节点名（上报时标识自己，[a-zA-Z0-9_-]）
    pub node: String,
    /// agent 角色：协调者地址，如 http://192.168.1.10:7420
    pub coordinator: String,
    pub interval_secs: u64,
}

impl Default for FedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: "off".into(),
            node: String::new(),
            coordinator: String::new(),
            interval_secs: 60,
        }
    }
}

impl FedConfig {
    pub fn effective_token(&self) -> String {
        // 组织令牌只走环境变量 AISAFEGUARD_FED_TOKEN——它是能向全网注入
        // 情报的凭据，和 AI Key 一样不进配置文件。
        std::env::var("AISAFEGUARD_FED_TOKEN")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_default()
    }

    pub fn valid_role(&self) -> bool {
        matches!(self.role.as_str(), "off" | "coordinator" | "agent")
    }
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
        let mut value: toml::Value = toml::from_str(raw)
            .map_err(|e| Error::Config(format!("解析 {path:?} 失败: {e}")))?;
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
        if legacy_key.is_empty()
            && value
                .get("ai")
                .and_then(|ai| ai.get("api_key"))
                .is_some()
        {
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
}
