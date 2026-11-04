mod ai_tab;
mod dashboard;
mod events_tab;
mod firewall_tab;
mod help_tab;
mod honeypot_tab;
pub(crate) mod i18n;
mod org_tab;
mod review_tab;
mod settings_tab;
pub(crate) use i18n::t;
pub(crate) mod theme;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use aisafeguard_core::config::AppConfig;
use aisafeguard_store::{AiRunRow, EventRow, ProposalRow, StatsSummary};
use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke};

use crate::console::{Console, LiveEvent};
use crate::engine::StatusReport;
use crate::explain::RuleExplain;

// 语义取色（多套配色方案可切换，定义与调色板见 gui/theme.rs）。
// 子页面的 `use super::*` 依赖这些再导出。
// 排版纪律：文本只选层级助手（display/title/section_title/body_text/caption/
// micro/mono_text），间距只取 theme::space 常量——禁止手写字号与裸间距数字。
pub(crate) use theme::type_scale;
pub(crate) use theme::{
    HEADER_H, ROW_H, ThemeId, accent, accent_soft, banner_bg, banner_text, bg_card, bg_panel,
    bg_sidebar, body_text, border, caption, danger, display, mono_text, ok, on_accent, orange,
    purple, section_title, space, text as text_color, text_dim, title, toast_bg, toast_text, warn,
};

/// 监听表协议枚举（H130 基础校验的合法取值；未知 kind 运行时按 generic 处理）。
/// F791/F794 新协议随批次加入——GUI 与后端 kind 集合必须同步（H150 教训）。
pub(crate) const LISTENER_KINDS: [&str; 11] = [
    "ssh",
    "http",
    "telnet",
    "generic",
    "mysql",
    "redis",
    "mcp",
    "smb",
    "rdp",
    "docker",
    "elasticsearch",
];

/// kind 原始值 → 显示名（蜜罐页卡片 / 监听表编辑器共用）
pub(crate) fn kind_display(kind: &str) -> &str {
    match kind {
        "ssh" => "SSH",
        "http" => "HTTP",
        "telnet" => "Telnet",
        "generic" => "Generic",
        "mysql" => "MySQL",
        "redis" => "Redis",
        "mcp" => "MCP",
        "smb" => "SMB",
        "rdp" => "RDP",
        "docker" => "Docker API",
        "elasticsearch" => "Elasticsearch",
        other => other,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tab {
    Dashboard,
    Events,
    Firewall,
    Honeypot,
    Org,
    Ai,
    Review,
    Settings,
    Help,
}

/// 设置页子页（0.5.8）：按功能域分页，替代单页长滚动。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SettingsPage {
    /// 外观（主题 / 字号）
    #[default]
    Look,
    /// AI 分析（含 API Key、误报抑制）
    Ai,
    /// 检测与感知（快路径 / 采样 / L7 / 规则引擎）
    Detect,
    /// 蜜罐与执行（蜜罐 / XDP）
    Honeypot,
    /// 通道与告警（API / syslog / webhook / 暴露面）
    Channels,
    /// 关于（版本 / 路径 / 许可）
    About,
}

impl SettingsPage {
    const ALL: [Self; 6] = [
        Self::Look,
        Self::Ai,
        Self::Detect,
        Self::Honeypot,
        Self::Channels,
        Self::About,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Look => "外观",
            Self::Ai => "AI 分析",
            Self::Detect => "检测与感知",
            Self::Honeypot => "蜜罐与执行",
            Self::Channels => "通道与告警",
            Self::About => "关于",
        }
    }
}

struct Cache {
    status: Option<StatusReport>,
    stats: StatsSummary,
    events: Vec<EventRow>,
    rules: Vec<RuleExplain>,
    proposals: Vec<ProposalRow>,
    runs: Vec<AiRunRow>,
    feedback: Vec<aisafeguard_store::FpRow>,
    fed_panel: Option<crate::engine::FedPanel>,
}

pub struct AisafeApp {
    eng: Arc<dyn Console>,
    tab: Tab,
    rx: Receiver<LiveEvent>,
    live: VecDeque<LiveEvent>,
    cache: Cache,
    cache_at: Instant,
    toast: Option<(Instant, String)>,
    // 防火墙表单
    new_ip: String,
    new_port: String,
    new_dir_out: bool,
    new_proto_idx: usize,
    new_note: String,
    new_tag: String,
    // F760-B 评审页
    review: review_tab::ReviewDraft,
    // 事件过滤
    event_filter: String,
    org_reason: String,
    org_lift_fp: String,
    org_node_name: String,
    org_coord_addr: String,
    org_pending_revoke: Option<String>,
    // 事件详情（0.5.6 F14）：选中事件的 id，详情面板从缓存按 id 取
    event_detail_id: Option<i64>,
    // 设置草稿（None = 未编辑；进入设置页时从引擎取）
    settings_draft: Option<AppConfig>,
    // 设置子页（0.5.8 分页）
    settings_page: SettingsPage,
    settings_interval: String,
    settings_port: String,
    settings_snippet: String,
    settings_key_input: String,
    settings_syslog_target: String,
    settings_notify_url: String,
    settings_exposure_secs: String,
    settings_xdp_iface: String,
    settings_fp_days: String,
    // 蜜罐域（0.5.10 H130）：假 Shell 命令上限 + 监听表端口列的文本输入缓冲
    settings_shell_max_cmds: String,
    settings_listener_ports: Vec<String>,
    // 蜜罐页监听器状态列表：当前展开配置的监听器索引 + 名称/端口编辑缓冲
    hp_config_open: Option<usize>,
    hp_name_buf: String,
    hp_port_buf: String,
    // 已保存的界面偏好（缓存值；每 2 秒随 cache 刷新）
    ui_prefs: (ThemeId, f32),
    // 界面语言（F796c：zh | en，设置页切换即改配置并热生效）
    language: String,
    // 上一帧已应用的主题+缩放（变化才重新 apply，避免每帧重建样式）
    applied_ui: Option<(ThemeId, f32)>,
    // 服务端版本（随 cache.status 刷新；远程控制台模式下不逐帧打 HTTP）
    srv_version: String,
    // 应用内自更新（0.8.2，仅 Windows 有升级按钮；状态机在 About 页驱动）
    #[cfg(windows)]
    update_state: UpdateUi,
}

/// 应用内自更新的界面状态机：检查/下载在后台线程，结果经 channel/atomic 回来，
/// 由每帧的 poll 落位；Ready 之后等用户点"以管理员身份升级"（UAC）。
#[cfg(windows)]
pub(crate) enum UpdateUi {
    Idle,
    Checking(std::sync::mpsc::Receiver<Result<Option<crate::update::Release>, String>>),
    UpToDate,
    Available(crate::update::Release),
    Downloading {
        rx: std::sync::mpsc::Receiver<Result<std::path::PathBuf, String>>,
        percent: Arc<std::sync::atomic::AtomicU8>,
        ver: String,
    },
    Ready {
        workdir: std::path::PathBuf,
        ver: String,
    },
    Failed(String),
}

pub fn run(console: Arc<dyn Console>) -> anyhow::Result<()> {
    // GUI 里的 panic 曾经只闪一下控制台就退出：落一份崩溃日志，
    // 下次"点某页就没了"至少能定位。
    install_panic_log();
    let rx = console.live_events();
    // 主题与字号来自持久化配置（读不到时用默认值，界面照常可打开）
    let (theme_id, font_scale, language) = console
        .config()
        .map(|c| {
            (
                ThemeId::from_str(&c.ui.theme),
                c.ui.font_scale,
                c.ui.language.clone(),
            )
        })
        .unwrap_or((
            ThemeId::default(),
            theme::FONT_SCALE_DEFAULT,
            "zh".to_string(),
        ));
    i18n::set_lang(&language);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("AI-SafeGuard 安全中心")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([1024.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "aisafeguard",
        options,
        Box::new(move |cc| {
            load_fonts(&cc.egui_ctx);
            theme::apply(&cc.egui_ctx, theme_id, font_scale);
            Ok(Box::new(AisafeApp::new(
                console,
                rx,
                (theme_id, font_scale),
                language,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("GUI 异常退出: {e}"))
}

impl AisafeApp {
    fn new(
        eng: Arc<dyn Console>,
        rx: Receiver<LiveEvent>,
        ui_prefs: (ThemeId, f32),
        language: String,
    ) -> Self {
        Self {
            eng,
            tab: Tab::Dashboard,
            rx,
            live: VecDeque::new(),
            cache: Cache {
                status: None,
                stats: StatsSummary::default(),
                events: Vec::new(),
                rules: Vec::new(),
                proposals: Vec::new(),
                runs: Vec::new(),
                feedback: Vec::new(),
                fed_panel: None,
            },
            cache_at: Instant::now() - Duration::from_secs(60),
            toast: None,
            new_ip: String::new(),
            new_port: String::new(),
            new_dir_out: false,
            new_proto_idx: 0,
            new_note: String::new(),
            new_tag: String::new(),
            event_filter: String::new(),
            review: review_tab::ReviewDraft {
                rows: Vec::new(),
                loaded: false,
                sel: None,
                note: String::new(),
                edit_title: String::new(),
                edit_priority: "P2".into(),
                edit_evidence: String::new(),
                edit_action: String::new(),
            },
            org_reason: String::new(),
            org_lift_fp: String::new(),
            org_node_name: String::new(),
            org_coord_addr: String::new(),
            org_pending_revoke: None,
            event_detail_id: None,
            settings_draft: None,
            settings_page: SettingsPage::default(),
            settings_interval: String::new(),
            settings_port: String::new(),
            settings_snippet: String::new(),
            settings_key_input: String::new(),
            settings_syslog_target: String::new(),
            settings_notify_url: String::new(),
            settings_exposure_secs: String::new(),
            settings_xdp_iface: String::new(),
            settings_fp_days: String::new(),
            settings_shell_max_cmds: String::new(),
            settings_listener_ports: Vec::new(),
            hp_config_open: None,
            hp_name_buf: String::new(),
            hp_port_buf: String::new(),
            ui_prefs,
            applied_ui: Some(ui_prefs),
            language,
            srv_version: String::new(),
            #[cfg(windows)]
            update_state: UpdateUi::Idle,
        }
    }

    /// 当前期望的界面偏好：设置页草稿优先（切主题/字号即时预览），否则用已保存值。
    fn desired_ui(&self) -> (ThemeId, f32) {
        match &self.settings_draft {
            Some(d) => (
                ThemeId::from_str(&d.ui.theme),
                theme::normalize_font_scale(d.ui.font_scale),
            ),
            None => self.ui_prefs,
        }
    }

    fn refresh_cache(&mut self) {
        self.cache_at = Instant::now();
        self.cache.status = self.eng.status().ok();
        // 服务端版本随状态缓存刷新；远程模式下避免每帧一次 HTTP
        if let Some(st) = &self.cache.status {
            self.srv_version = st.version.clone();
        }
        self.cache.stats = self.eng.stats_24h().unwrap_or_default();
        let filter = self.event_filter.trim().to_string();
        self.cache.events = self
            .eng
            .list_events(300, (!filter.is_empty()).then_some(filter.as_str()))
            .unwrap_or_default();
        self.cache.rules = self.eng.list_rules().unwrap_or_default();
        self.cache.proposals = self.eng.list_proposals(None, 100).unwrap_or_default();
        self.cache.runs = self.eng.list_ai_runs(8).unwrap_or_default();
        self.cache.feedback = self.eng.list_feedback().unwrap_or_default();
        self.cache.fed_panel = self.eng.fed_panel().ok();
        if let Ok(cfg) = self.eng.config() {
            self.ui_prefs = (
                ThemeId::from_str(&cfg.ui.theme),
                theme::normalize_font_scale(cfg.ui.font_scale),
            );
        }
    }

    fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((Instant::now(), msg.into()));
    }

    /// 误报一键入口（0.5.5 F7）：事件行 / 防火墙规则行 / AI 建议行三处共用
    /// 同一引擎逻辑与操作反馈（F10）——解封 N 条自动规则、收弃 M 条建议、
    /// 抑制至某时间。手动规则不受影响（引擎只动 engine/ai 来源）。
    fn mark_fp(&mut self, ip: &str) {
        let secs = self
            .eng
            .config()
            .map(|c| c.ai.fp_suppress_secs as i64)
            .unwrap_or(0);
        match self.eng.mark_false_positive(ip, "", None) {
            Ok((dismissed, removed)) => {
                let until = chrono::DateTime::from_timestamp(aisafeguard_core::now_ts() + secs, 0)
                    .map(|d| {
                        d.with_timezone(&chrono::Local)
                            .format("%Y-%m-%d %H:%M")
                            .to_string()
                    })
                    .unwrap_or_default();
                self.set_toast(format!(
                    "已标记误报：解封 {removed} 条自动规则、收弃 {dismissed} 条建议，{until} 前不再自动封禁该来源"
                ));
            }
            Err(e) => self.set_toast(format!("标记失败: {e}")),
        }
        self.refresh_cache();
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("nav")
            .exact_size(212.0)
            .resizable(false)
            .frame(Frame::new().fill(bg_sidebar()))
            .show(ui, |ui| {
                ui.add_space(space::L);
                ui.horizontal(|ui| {
                    ui.add_space(space::M);
                    ui.label(title("AI-SafeGuard").color(accent()));
                });
                // 版本徽章：随时可见、一眼区分版本（取缓存，不逐帧请求服务）
                ui.horizontal(|ui| {
                    ui.add_space(space::M);
                    let srv_ver = if self.srv_version.is_empty() {
                        "?".to_string()
                    } else {
                        self.srv_version.clone()
                    };
                    version_badge(ui, &srv_ver);
                    ui.label(caption("安全中心").color(text_dim()));
                    // 远程控制台下客户端与服务端可能不同版本：旧服务缺少新接口
                    // 会让新界面行为异常，明确提示升级而不是让人猜。
                    let client_ver = env!("CARGO_PKG_VERSION");
                    if srv_ver != "?" && srv_ver != client_ver {
                        ui.label(caption("版本不一致").color(danger())).on_hover_text(t(
                            "客户端与服务端版本不一致：旧服务可能缺少新接口。请升级服务（管理员：aisafeguard service stop → 替换 exe → service install → service start）。",
                            "Client and server versions differ; the old service may lack new APIs. Upgrade it (admin: aisafeguard service stop → replace exe → service install → service start).",
                        ));
                    }
                });
                ui.add_space(space::L);

                let tabs = [
                    (Tab::Dashboard, t("⌂  仪表盘", "⌂  Dashboard")),
                    (Tab::Events, t("≡  事件", "≡  Events")),
                    (Tab::Firewall, t("⛨  防火墙", "⛨  Firewall")),
                    (Tab::Honeypot, t("◉  蜜罐", "◉  Honeypot")),
                    (Tab::Org, t("⇄  组织", "⇄  Org")),
                    (Tab::Ai, t("✦  AI 助手", "✦  AI")),
                    (Tab::Review, t("☰  评审", "☰  Review")),
                    (Tab::Settings, t("⚙  设置", "⚙  Settings")),
                    (Tab::Help, t("?  帮助", "?  Help")),
                ];
                for (tab, label) in tabs {
                    let selected = self.tab == tab;
                    ui.horizontal(|ui| {
                        ui.add_space(space::S);
                        let text = RichText::new(label)
                            .size(type_scale::BODY)
                            .color(if selected { text_color() } else { text_dim() });
                        let fill = if selected {
                            accent_soft()
                        } else {
                            Color32::TRANSPARENT
                        };
                        if ui
                            .add(
                                egui::Button::new(text)
                                    .fill(fill)
                                    .corner_radius(CornerRadius::same(8))
                                    .min_size(egui::vec2(190.0, 34.0)),
                            )
                            .clicked()
                        {
                            self.tab = tab;
                        }
                    });
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(space::L);
                    if let Some(st) = &self.cache.status {
                        ui.horizontal(|ui| {
                            ui.add_space(space::M);
                            let (c, t) = if st.elevated {
                                (ok(), "管理员权限")
                            } else {
                                (warn(), "未提权 · 防火墙不可用")
                            };
                            ui.label(RichText::new("●").size(type_scale::CAPTION).color(c));
                            ui.label(caption(t).color(text_dim()));
                        });
                        ui.add_space(space::XS);
                        ui.horizontal(|ui| {
                            ui.add_space(space::M);
                            ui.label(
                                caption(format!("后端 {}", st.backend))
                                    .size(type_scale::MICRO)
                                    .color(text_dim()),
                            );
                        });
                    }
                });
            });
    }

    fn toast_ui(&mut self, ctx: &egui::Context) {
        let expired = self
            .toast
            .as_ref()
            .map(|(at, _)| at.elapsed() >= Duration::from_secs(4))
            .unwrap_or(false);
        if expired {
            self.toast = None;
        }
        if let Some((_, msg)) = &self.toast {
            let msg = msg.clone();
            egui::Area::new(egui::Id::new("toast"))
                .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -28.0])
                .show(ctx, |ui| {
                    Frame::new()
                        .fill(toast_bg())
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::same(12))
                        .stroke(Stroke::new(1.0, accent()))
                        .show(ui, |ui| {
                            ui.label(body_text(msg).color(toast_text()));
                        });
                });
        }
    }
}

impl eframe::App for AisafeApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        while let Ok(ev) = self.rx.try_recv() {
            self.live.push_front(ev);
            while self.live.len() > 200 {
                self.live.pop_back();
            }
        }
        // 自更新状态机推进（检查/下载线程的结果在这里落位）
        #[cfg(windows)]
        {
            self.update_state = match std::mem::replace(&mut self.update_state, UpdateUi::Idle) {
                UpdateUi::Checking(rx) => match rx.try_recv() {
                    Ok(Ok(Some(rel))) => UpdateUi::Available(rel),
                    Ok(Ok(None)) => UpdateUi::UpToDate,
                    Ok(Err(e)) => UpdateUi::Failed(e),
                    Err(std::sync::mpsc::TryRecvError::Empty) => UpdateUi::Checking(rx),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        UpdateUi::Failed("检查线程意外退出".into())
                    }
                },
                UpdateUi::Downloading { rx, percent, ver } => match rx.try_recv() {
                    Ok(Ok(workdir)) => UpdateUi::Ready { workdir, ver },
                    Ok(Err(e)) => UpdateUi::Failed(e),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        UpdateUi::Downloading { rx, percent, ver }
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        UpdateUi::Failed("下载线程意外退出".into())
                    }
                },
                other => other,
            };
        }
        if self.cache_at.elapsed() >= Duration::from_secs(2) {
            self.refresh_cache();
        }

        // 主题/字号变化（设置页即时预览或配置刷新）→ 重新应用
        let want = self.desired_ui();
        if self.applied_ui != Some(want) {
            theme::apply(&ctx, want.0, want.1);
            self.applied_ui = Some(want);
        }
        // 语言跟随设置草稿（未保存的即时预览语义与主题一致）
        i18n::set_lang(
            &self
                .settings_draft
                .as_ref()
                .map(|d| d.ui.language.clone())
                .unwrap_or_else(|| self.language.clone()),
        );

        self.sidebar(ui);

        egui::CentralPanel::default()
            .frame(Frame::new().fill(bg_panel()).inner_margin(Margin::same(16)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("main-scroll")
                    .show(ui, |ui| match self.tab {
                        Tab::Dashboard => self.dashboard_ui(ui),
                        Tab::Events => self.events_ui(ui),
                        Tab::Firewall => self.firewall_ui(ui),
                        Tab::Honeypot => self.honeypot_ui(ui),
                        Tab::Org => self.org_ui(ui),
                        Tab::Ai => self.ai_ui(ui),
                        Tab::Review => self.review_ui(ui),
                        Tab::Settings => self.settings_ui(ui),
                        Tab::Help => self.help_ui(ui),
                    });
            });

        self.toast_ui(&ctx);
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

// ---------- 共用小组件 ----------

/// 版本徽章：主色底 + 反色字，侧栏常驻，一眼区分版本。
/// GUI panic 落盘：%LOCALAPPDATA%/aisafeguard/gui-panic.log（Linux 为
/// ~/.local/share/aisafeguard/gui-panic.log）。默认 hook（stderr）照常执行；
/// 文件写失败不影响退出路径。用于"点某页就没了"这类无窗口崩溃的定位。
fn install_panic_log() {
    let Some(base) = dirs::data_local_dir() else {
        return;
    };
    let dir = base.join("aisafeguard");
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = std::fs::create_dir_all(&dir);
        let text = format!(
            "[{}] v{}\n{info}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            env!("CARGO_PKG_VERSION")
        );
        let _ = std::fs::write(dir.join("gui-panic.log"), text);
        prev(info);
    }));
}

fn version_badge(ui: &mut egui::Ui, version: &str) {
    Frame::new()
        .fill(accent())
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("v{version}"))
                    .size(type_scale::MICRO)
                    .strong()
                    .color(on_accent()),
            );
        });
}

/// eframe 默认字体不含 CJK，按优先级加载系统字体，不往仓库塞字体文件。
fn load_fonts(ctx: &egui::Context) {
    let candidates = [
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/simsun.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ];
    for path in candidates {
        if let Ok(data) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            // Windows 自带的符号字体：覆盖 ⌂ ⛨ ◉ ✦ 等默认字体缺失的字形
            if let Ok(sym) = std::fs::read("C:/Windows/Fonts/seguisym.ttf") {
                fonts.font_data.insert(
                    "sym".into(),
                    std::sync::Arc::new(egui::FontData::from_owned(sym)),
                );
                fonts
                    .families
                    .entry(egui::FontFamily::Proportional)
                    .or_default()
                    .push("sym".into());
                fonts
                    .families
                    .entry(egui::FontFamily::Monospace)
                    .or_default()
                    .push("sym".into());
            }
            // 追加在末尾：拉丁字符用默认字体，缺失字形依次回退 sym → cjk
            fonts.font_data.insert(
                "cjk".into(),
                std::sync::Arc::new(egui::FontData::from_owned(data)),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .push("cjk".into());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("cjk".into());
            ctx.set_fonts(fonts);
            tracing::info!("已加载中文字体: {path}");
            return;
        }
    }
    tracing::warn!("未找到中文字体，界面中文可能显示为方块");
}

fn card(ui: &mut egui::Ui, title: &str, value: &str, color: Color32) {
    Frame::new()
        .fill(bg_card())
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .stroke(Stroke::new(1.0, border()))
        .show(ui, |ui| {
            ui.set_min_width(132.0);
            ui.label(caption(title).color(text_dim()));
            ui.label(display(value).color(color));
        });
}

fn chip(ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.25))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text.to_uppercase())
                    .size(type_scale::MICRO)
                    .strong()
                    .color(color),
            );
        });
}

fn section(ui: &mut egui::Ui, title: impl Into<String>) {
    ui.add_space(space::S);
    ui.label(section_title(title));
    ui.add_space(space::XS);
}

fn warn_banner(ui: &mut egui::Ui, text: &str) {
    Frame::new()
        .fill(banner_bg())
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, warn()))
        .show(ui, |ui| {
            ui.label(body_text(text).color(banner_text()));
        });
    ui.add_space(space::S);
}

fn severity_color(severity: &str) -> Color32 {
    match severity {
        "critical" => danger(),
        "high" => orange(),
        "medium" => warn(),
        _ => text_dim(),
    }
}

fn event_color(kind: &str) -> Color32 {
    match kind {
        "honeypot_hit" => warn(),
        "firewall_add" | "proposal_applied" => ok(),
        "firewall_remove" => text_dim(),
        "proposal_created" => purple(),
        "ai_run" => accent(),
        "detection" => orange(),
        // 凭证采集（0.5.10 H200）：单独着色，事件页可辨识
        "credential_observed" => purple(),
        "engine" => text_dim(),
        _ => text_dim(),
    }
}

pub(crate) fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_default()
}

fn dir_cn(direction: &str) -> &'static str {
    match direction {
        "in" => "入站",
        _ => "出站",
    }
}

fn proto_up(protocol: &str) -> &'static str {
    match protocol {
        "tcp" => "TCP",
        "udp" => "UDP",
        _ => "ANY",
    }
}

fn target_desc(ip: &str, port: Option<u16>) -> String {
    let ip = if ip.is_empty() { "任意来源" } else { ip };
    match port {
        Some(p) => format!("{ip} → 端口 {p}"),
        None => format!("{ip}（全端口）"),
    }
}
