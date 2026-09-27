mod ai_tab;
mod dashboard;
mod events_tab;
mod firewall_tab;
mod honeypot_tab;
mod settings_tab;

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aisafeguard_core::config::AppConfig;
use aisafeguard_store::{AiRunRow, EventRow, ProposalRow, RuleRow, StatsSummary};
use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke};

use crate::console::{Console, LiveEvent};
use crate::engine::StatusReport;

const ACCENT: Color32 = Color32::from_rgb(59, 130, 246);
const BG_SIDEBAR: Color32 = Color32::from_rgb(9, 13, 21);
const BG_PANEL: Color32 = Color32::from_rgb(13, 18, 28);
const BG_CARD: Color32 = Color32::from_rgb(21, 28, 42);
const BORDER: Color32 = Color32::from_rgb(44, 54, 74);
const TEXT_DIM: Color32 = Color32::from_rgb(148, 163, 184);
const OK: Color32 = Color32::from_rgb(34, 197, 94);
const WARN: Color32 = Color32::from_rgb(245, 158, 11);
const DANGER: Color32 = Color32::from_rgb(239, 68, 68);
const ORANGE: Color32 = Color32::from_rgb(249, 115, 22);
const PURPLE: Color32 = Color32::from_rgb(167, 139, 250);

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tab {
    Dashboard,
    Events,
    Firewall,
    Honeypot,
    Ai,
    Settings,
}

struct Cache {
    status: Option<StatusReport>,
    stats: StatsSummary,
    events: Vec<EventRow>,
    rules: Vec<RuleRow>,
    proposals: Vec<ProposalRow>,
    runs: Vec<AiRunRow>,
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
    // 事件过滤
    event_filter: String,
    // 设置草稿（None = 未编辑；进入设置页时从引擎取）
    settings_draft: Option<AppConfig>,
    settings_interval: String,
    settings_port: String,
    settings_snippet: String,
    settings_key_input: String,
}

pub fn run(console: Arc<dyn Console>) -> anyhow::Result<()> {
    let rx = console.live_events();

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
            configure_style(&cc.egui_ctx);
            Ok(Box::new(AisafeApp::new(console, rx)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("GUI 异常退出: {e}"))
}

impl AisafeApp {
    fn new(eng: Arc<dyn Console>, rx: Receiver<LiveEvent>) -> Self {
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
            },
            cache_at: Instant::now() - Duration::from_secs(60),
            toast: None,
            new_ip: String::new(),
            new_port: String::new(),
            new_dir_out: false,
            new_proto_idx: 0,
            new_note: String::new(),
            event_filter: String::new(),
            settings_draft: None,
            settings_interval: String::new(),
            settings_port: String::new(),
            settings_snippet: String::new(),
            settings_key_input: String::new(),
        }
    }

    fn refresh_cache(&mut self) {
        self.cache_at = Instant::now();
        self.cache.status = self.eng.status().ok();
        self.cache.stats = self.eng.stats_24h().unwrap_or_default();
        let filter = self.event_filter.trim().to_string();
        self.cache.events = self
            .eng
            .list_events(300, (!filter.is_empty()).then_some(filter.as_str()))
            .unwrap_or_default();
        self.cache.rules = self.eng.list_rules().unwrap_or_default();
        self.cache.proposals = self.eng.list_proposals(None, 100).unwrap_or_default();
        self.cache.runs = self.eng.list_ai_runs(8).unwrap_or_default();
    }

    fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((Instant::now(), msg.into()));
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("nav")
            .exact_size(200.0)
            .resizable(false)
            .frame(Frame::new().fill(BG_SIDEBAR))
            .show(ui, |ui| {
                ui.add_space(22.0);
                ui.horizontal(|ui| {
                    ui.add_space(18.0);
                    ui.label(RichText::new("AI-SafeGuard").size(24.0).strong().color(ACCENT));
                });
                ui.horizontal(|ui| {
                    ui.add_space(18.0);
                    ui.label(
                        RichText::new(format!("安全中心 v{}", self.eng.version()))
                            .size(12.0)
                            .color(TEXT_DIM),
                    );
                });
                ui.add_space(24.0);

                let tabs = [
                    (Tab::Dashboard, "⌂  仪表盘"),
                    (Tab::Events, "≡  事件"),
                    (Tab::Firewall, "⛨  防火墙"),
                    (Tab::Honeypot, "◉  蜜罐"),
                    (Tab::Ai, "✦  AI 助手"),
                    (Tab::Settings, "⚙  设置"),
                ];
                for (tab, label) in tabs {
                    let selected = self.tab == tab;
                    ui.horizontal(|ui| {
                        ui.add_space(10.0);
                        let text =
                            RichText::new(label).size(15.0).color(if selected {
                                Color32::WHITE
                            } else {
                                TEXT_DIM
                            });
                        let fill = if selected {
                            Color32::from_rgb(24, 32, 48)
                        } else {
                            Color32::TRANSPARENT
                        };
                        if ui
                            .add(
                                egui::Button::new(text)
                                    .fill(fill)
                                    .corner_radius(CornerRadius::same(8))
                                    .min_size(egui::vec2(180.0, 34.0)),
                            )
                            .clicked()
                        {
                            self.tab = tab;
                        }
                    });
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(16.0);
                    if let Some(st) = &self.cache.status {
                        ui.horizontal(|ui| {
                            ui.add_space(18.0);
                            let (c, t) = if st.elevated {
                                (OK, "管理员权限")
                            } else {
                                (WARN, "未提权 · 防火墙不可用")
                            };
                            ui.label(RichText::new("●").color(c));
                            ui.label(RichText::new(t).size(12.0).color(TEXT_DIM));
                        });
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.add_space(18.0);
                            ui.label(
                                RichText::new(format!("后端 {}", st.backend))
                                    .size(11.0)
                                    .color(TEXT_DIM),
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
                        .fill(Color32::from_rgb(30, 41, 59))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::same(12))
                        .stroke(Stroke::new(1.0, ACCENT))
                        .show(ui, |ui| {
                            ui.label(RichText::new(msg).color(Color32::WHITE).size(13.0));
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
        if self.cache_at.elapsed() >= Duration::from_secs(2) {
            self.refresh_cache();
        }

        self.sidebar(ui);

        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG_PANEL).inner_margin(Margin::same(20)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("main-scroll")
                    .show(ui, |ui| match self.tab {
                        Tab::Dashboard => self.dashboard_ui(ui),
                        Tab::Events => self.events_ui(ui),
                        Tab::Firewall => self.firewall_ui(ui),
                        Tab::Honeypot => self.honeypot_ui(ui),
                        Tab::Ai => self.ai_ui(ui),
                        Tab::Settings => self.settings_ui(ui),
                    });
            });

        self.toast_ui(&ctx);
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

// ---------- 共用小组件 ----------

fn configure_style(ctx: &egui::Context) {
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        let v = &mut style.visuals;
        v.panel_fill = BG_PANEL;
        v.window_fill = BG_CARD;
        v.extreme_bg_color = Color32::from_rgb(10, 14, 22);
        v.faint_bg_color = Color32::from_rgb(17, 23, 35);
        v.selection.bg_fill = Color32::from_rgb(37, 99, 235);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.widgets.hovered.bg_fill = Color32::from_rgb(30, 40, 60);
        v.widgets.active.bg_fill = Color32::from_rgb(35, 46, 70);
        v.widgets.inactive.bg_fill = Color32::from_rgb(26, 34, 50);
        v.hyperlink_color = ACCENT;
        v.override_text_color = Some(Color32::from_rgb(226, 232, 240));
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
                fonts
                    .font_data
                    .insert("sym".into(), std::sync::Arc::new(egui::FontData::from_owned(sym)));
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
            fonts
                .font_data
                .insert("cjk".into(), std::sync::Arc::new(egui::FontData::from_owned(data)));
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
        .fill(BG_CARD)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .stroke(Stroke::new(1.0, BORDER))
        .show(ui, |ui| {
            ui.set_min_width(130.0);
            ui.label(RichText::new(title).size(12.0).color(TEXT_DIM));
            ui.label(RichText::new(value).size(24.0).strong().color(color));
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
                    .size(11.0)
                    .strong()
                    .color(color),
            );
        });
}

fn section(ui: &mut egui::Ui, title: impl Into<String>) {
    ui.add_space(8.0);
    ui.label(RichText::new(title.into()).size(16.0).strong());
    ui.add_space(4.0);
}

fn warn_banner(ui: &mut egui::Ui, text: &str) {
    Frame::new()
        .fill(Color32::from_rgb(69, 26, 3))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, WARN))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .color(Color32::from_rgb(251, 191, 36))
                    .size(13.0),
            );
        });
    ui.add_space(8.0);
}

fn severity_color(severity: &str) -> Color32 {
    match severity {
        "critical" => DANGER,
        "high" => ORANGE,
        "medium" => WARN,
        _ => TEXT_DIM,
    }
}

fn event_color(kind: &str) -> Color32 {
    match kind {
        "honeypot_hit" => WARN,
        "firewall_add" | "proposal_applied" => OK,
        "firewall_remove" => TEXT_DIM,
        "proposal_created" => PURPLE,
        "ai_run" => ACCENT,
        "detection" => ORANGE,
        "engine" => TEXT_DIM,
        _ => TEXT_DIM,
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
