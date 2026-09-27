//! GUI 与引擎的控制台契约。
//!
//! 服务化拆分后 GUI 有两种运行形态：
//! - **内嵌**（EmbeddedConsole）：引擎跑在同进程内，直接调用（现状）；
//! - **远程**（RemoteConsole）：引擎是提权 Windows 服务，GUI 以普通权限经本地 API 调用。
//!
//! 两者实现同一 `Console` trait——GUI 代码不感知形态，这是 0.2 服务化与
//! 未来多主机控制台的共同地基（docs/NGFW_EVOLUTION.md §6 的"共享建议而非命令"也走此契约）。

use std::sync::mpsc::Receiver;

use aisafeguard_core::config::AppConfig;
use aisafeguard_firewall::BlockSpec;
use aisafeguard_store::{AiRunRow, EventRow, ProposalRow, RuleRow, StatsSummary};

use crate::engine::StatusReport;

/// 实时事件（GUI 滚动条目）。内嵌模式从事件总线桥接，远程模式从 API 轮询差量。
#[derive(Debug, Clone)]
pub struct LiveEvent {
    pub kind: String,
    pub ts: i64,
    pub summary: String,
}

pub trait Console: Send + Sync {
    fn version(&self) -> String;
    /// (配置文件路径, 数据目录) —— 仅内嵌模式有真实值，远程模式显示服务侧说明
    fn config_paths(&self) -> (String, String);
    fn config(&self) -> anyhow::Result<AppConfig>;
    fn status(&self) -> anyhow::Result<StatusReport>;
    fn list_events(&self, limit: u32, ip_filter: Option<&str>) -> anyhow::Result<Vec<EventRow>>;
    fn list_rules(&self) -> anyhow::Result<Vec<RuleRow>>;
    fn list_proposals(&self, status: Option<&str>, limit: u32) -> anyhow::Result<Vec<ProposalRow>>;
    fn list_ai_runs(&self, limit: u32) -> anyhow::Result<Vec<AiRunRow>>;
    fn stats_24h(&self) -> anyhow::Result<StatsSummary>;
    /// 主机暴露面盘点（扫描 + 存快照 + 广播）
    fn scan_exposure(&self) -> anyhow::Result<Vec<aisafeguard_detect::exposure::Entry>>;
    /// 最近一次暴露面快照（None = 从未扫描）
    fn latest_exposure(&self) -> anyhow::Result<Option<crate::engine::ExposureSnapshot>>;
    fn add_block(&self, spec: &BlockSpec, origin: &str) -> anyhow::Result<RuleRow>;
    fn remove_rule(&self, id: i64) -> anyhow::Result<()>;
    fn apply_proposal(&self, id: i64) -> anyhow::Result<RuleRow>;
    fn dismiss_proposal(&self, id: i64) -> anyhow::Result<()>;
    /// 返回 false = 已有分析在运行
    fn trigger_analysis(&self) -> bool;
    fn save_config(&self, cfg: AppConfig) -> anyhow::Result<()>;
    /// AI Key 凭据管理（内嵌走本机凭据管理器，远程走服务 API → 服务侧凭据管理器）
    fn ai_key_present(&self) -> anyhow::Result<bool>;
    fn set_ai_key(&self, value: &str) -> anyhow::Result<()>;
    fn delete_ai_key(&self) -> anyhow::Result<()>;
    /// 实时事件流。GUI 每帧 drain；远程模式由后台轮询线程喂数据。
    fn live_events(&self) -> Receiver<LiveEvent>;
}
