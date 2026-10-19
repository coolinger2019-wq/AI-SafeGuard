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
    /// 规则展示模型（0.5.4 F1）：可解释封禁（来源 / 原因 / TTL 文案）
    fn list_rules(&self) -> anyhow::Result<Vec<crate::explain::RuleExplain>>;
    fn list_proposals(&self, status: Option<&str>, limit: u32) -> anyhow::Result<Vec<ProposalRow>>;
    fn list_ai_runs(&self, limit: u32) -> anyhow::Result<Vec<AiRunRow>>;
    fn stats_24h(&self) -> anyhow::Result<StatsSummary>;
    /// 一键清空 XDP map（0.5.1 G3，仅 Linux 快速层已附加时有意义）
    fn clear_xdp_map(&self) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("XDP 快速执行层不可用（非 Linux 或未附加）"))
    }
    /// 主机暴露面盘点（扫描 + 存快照 + 广播）
    fn scan_exposure(&self) -> anyhow::Result<Vec<aisafeguard_detect::exposure::Entry>>;
    /// 最近一次暴露面快照（None = 从未扫描）
    fn latest_exposure(&self) -> anyhow::Result<Option<crate::engine::ExposureSnapshot>>;
    fn add_block(&self, spec: &BlockSpec, origin: &str) -> anyhow::Result<RuleRow>;
    fn remove_rule(&self, id: i64) -> anyhow::Result<()>;
    fn apply_proposal(&self, id: i64) -> anyhow::Result<RuleRow>;
    /// 确认凭证喷洒战役（H310 观察类建议的人工确认入口；不是封禁）
    fn confirm_campaign(&self, id: i64) -> anyhow::Result<()>;
    /// 蜜罐监听器热启停（0.5.12）：即时生效；run=true 启动 / false 停止
    fn toggle_listener(&self, name: &str, run: bool) -> anyhow::Result<()>;
    fn dismiss_proposal(&self, id: i64) -> anyhow::Result<()>;
    /// 灰度规则转正：TTL 延长到 promote_ttl_secs（人工确认后的长期封禁）
    fn promote_rule(&self, id: i64) -> anyhow::Result<RuleRow>;
    /// 误报反馈：记录（30 天抑制）+ 解除该来源自动封禁 + 收弃 pending 建议；
    /// 返回 (收弃建议数, 解封规则数)
    fn mark_false_positive(
        &self,
        ip: &str,
        note: &str,
        local_port: Option<u16>,
    ) -> anyhow::Result<(i64, usize)>;
    /// 抑制期内的误报反馈列表（0.4.0 B3）
    fn list_feedback(&self) -> anyhow::Result<Vec<aisafeguard_store::FpRow>>;
    /// 清除某来源的误报抑制（0.4.0 B3）；返回删除的记录数（0 = 无记录）
    fn clear_false_positive(&self, ip: &str) -> anyhow::Result<usize>;
    /// 返回 false = 已有分析在运行
    fn trigger_analysis(&self) -> bool;
    // F760-B 系统自审评审（双端同步——Web 与 egui 同源 API/存储）
    fn list_suggestions(&self, limit: u32)
    -> anyhow::Result<Vec<aisafeguard_store::SuggestionRow>>;
    fn decide_suggestion(&self, id: i64, status: &str, note: &str) -> anyhow::Result<()>;
    /// 人工修正建议内容（评审展开编辑——修正后的版本才是采纳/拒绝的记录）
    fn edit_suggestion(
        &self,
        id: i64,
        title: &str,
        priority: &str,
        evidence: &str,
        action: &str,
    ) -> anyhow::Result<()>;
    fn trigger_review(&self) -> bool;
    fn save_config(&self, cfg: AppConfig) -> anyhow::Result<()>;
    /// AI Key 凭据管理（内嵌走本机凭据管理器，远程走服务 API → 服务侧凭据管理器）
    fn ai_key_present(&self) -> anyhow::Result<bool>;
    fn set_ai_key(&self, value: &str) -> anyhow::Result<()>;
    fn delete_ai_key(&self) -> anyhow::Result<()>;
    /// 实时事件流。GUI 每帧 drain；远程模式由后台轮询线程喂数据。
    fn live_events(&self) -> Receiver<LiveEvent>;
    /// 手动触发一轮威胁情报拉取（fire-and-forget；结果进事件流）
    fn refresh_intel(&self) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("情报订阅不可用"))
    }
    // F740/F500 入伙向导与组织面板方法**无默认实现**：编译器强制内嵌/远程
    // 两个实现同步覆盖（三次漏内嵌的事故根因——默认 Err 会把协调者本人挡在
    // 门外，故结构性根治而非靠记性）。
    fn join_request_create(&self, node: &str) -> anyhow::Result<(String, String)>;
    fn join_approval_process(
        &self,
        request_json: &str,
        coord_addr: &str,
    ) -> anyhow::Result<(String, String)>;
    fn join_import(&self, approval_json: &str, coord_addr: &str) -> anyhow::Result<String>;
    fn revoke_member(&self, node: &str, reason: &str) -> anyhow::Result<String>;
    fn fed_panel(&self) -> anyhow::Result<crate::engine::FedPanel>;
    fn quarantine_member(
        &self,
        node: &str,
        lift: bool,
        lift_fp: &str,
        reason: &str,
    ) -> anyhow::Result<String>;
}
