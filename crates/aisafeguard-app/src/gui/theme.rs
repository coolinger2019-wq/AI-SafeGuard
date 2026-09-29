//! 界面主题系统：多套配色方案 + 全局字号缩放，运行时可切换。
//!
//! 依据仓库根 `ui.md`（UI 设计规范 v1.0）落地到 egui 桌面端：
//! - §2.1 语义色板：每套方案都提供 Primary(accent)/Success(ok)/Warning(warn)/Error(danger)
//!   与中性色（text/text_dim/border），各控件一律取语义色，不写死色值；
//! - §2.2 暗色不用纯黑：深色与暖色方案背景取自 #0B1220 / #14110E 一类，
//!   高对比方案属无障碍刻意例外（前景 #FFFFFF on #000000）；
//! - §3.2 字号阶梯：正文 14.5 / 辅助 12 / 标题 20（桌面端等比收敛），
//!   配合 `font_scale`（默认 1.15）整体缩放，用户可在设置页自由调整；
//! - §1 可访问性：高对比方案 + 字号放大共同覆盖弱视场景。
//!
//! 主题是"当前值"而非每帧构造：UI 绘制期间直接调用本模块的函数取色，
//! 切换时由 `apply` 一次性写入 egui 样式与缩放。

use std::sync::RwLock;

use egui::{Color32, FontFamily, FontId, Stroke, TextStyle};

/// 可用配色方案。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeId {
    /// 深邃蓝（深色，默认）
    #[default]
    DeepBlue,
    /// 浅色办公
    Light,
    /// 暖色护眼（低蓝光暗色）
    Warm,
    /// 高对比（无障碍）
    Contrast,
}

impl ThemeId {
    /// 配置文件中持久化的标识。
    pub fn as_str(self) -> &'static str {
        match self {
            ThemeId::DeepBlue => "deep_blue",
            ThemeId::Light => "light",
            ThemeId::Warm => "warm",
            ThemeId::Contrast => "contrast",
        }
    }

    /// 解析配置值；无法识别时回退默认（配置文件写错不至于打不开界面）。
    pub fn from_str(s: &str) -> Self {
        match s {
            "light" => ThemeId::Light,
            "warm" => ThemeId::Warm,
            "contrast" => ThemeId::Contrast,
            _ => ThemeId::DeepBlue,
        }
    }

    pub fn all() -> [ThemeId; 4] {
        [
            ThemeId::DeepBlue,
            ThemeId::Light,
            ThemeId::Warm,
            ThemeId::Contrast,
        ]
    }

    pub fn spec(self) -> &'static ThemeSpec {
        match self {
            ThemeId::DeepBlue => &DEEP_BLUE,
            ThemeId::Light => &LIGHT,
            ThemeId::Warm => &WARM,
            ThemeId::Contrast => &CONTRAST,
        }
    }
}

/// 一套配色方案的全部语义色。
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// Primary：主按钮、链接、选中态
    pub accent: Color32,
    /// 主色之上的文字色（浅色主色用深字）
    pub on_accent: Color32,
    /// 强选中背景（文本选区等）
    pub selection_bg: Color32,
    /// 弱强调填充（侧栏选中项、标签底）
    pub accent_soft: Color32,
    pub bg_sidebar: Color32,
    pub bg_panel: Color32,
    pub bg_card: Color32,
    /// 输入框/凹陷区域
    pub bg_input: Color32,
    /// 斑马纹等次要填充
    pub bg_faint: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_dim: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub danger: Color32,
    pub orange: Color32,
    pub purple: Color32,
    pub hover_bg: Color32,
    pub active_bg: Color32,
    pub inactive_bg: Color32,
    pub toast_bg: Color32,
    pub toast_text: Color32,
    pub banner_bg: Color32,
    pub banner_text: Color32,
}

pub struct ThemeSpec {
    pub name: &'static str,
    /// 设置页展示的一句话说明。
    pub desc: &'static str,
    /// 对应 egui 内置明/暗基底。
    pub dark: bool,
    pub p: Palette,
}

// ---------- 四套方案 ----------

static DEEP_BLUE: ThemeSpec = ThemeSpec {
    name: "深邃蓝（深色）",
    desc: "默认深色，长时盯屏舒适，背景非纯黑",
    dark: true,
    p: Palette {
        accent: Color32::from_rgb(76, 141, 255),
        on_accent: Color32::WHITE,
        selection_bg: Color32::from_rgb(37, 99, 235),
        accent_soft: Color32::from_rgb(27, 42, 69),
        bg_sidebar: Color32::from_rgb(11, 18, 32),
        bg_panel: Color32::from_rgb(15, 22, 38),
        bg_card: Color32::from_rgb(22, 31, 49),
        bg_input: Color32::from_rgb(10, 15, 26),
        bg_faint: Color32::from_rgb(19, 26, 41),
        border: Color32::from_rgb(44, 58, 82),
        text: Color32::from_rgb(230, 235, 242),
        text_dim: Color32::from_rgb(154, 169, 191),
        ok: Color32::from_rgb(34, 197, 94),
        warn: Color32::from_rgb(240, 167, 58),
        danger: Color32::from_rgb(242, 108, 108),
        orange: Color32::from_rgb(245, 138, 60),
        purple: Color32::from_rgb(167, 139, 250),
        hover_bg: Color32::from_rgb(34, 48, 74),
        active_bg: Color32::from_rgb(41, 57, 90),
        inactive_bg: Color32::from_rgb(26, 36, 56),
        toast_bg: Color32::from_rgb(30, 41, 59),
        toast_text: Color32::from_rgb(241, 245, 249),
        banner_bg: Color32::from_rgb(58, 36, 8),
        banner_text: Color32::from_rgb(251, 191, 36),
    },
};

static LIGHT: ThemeSpec = ThemeSpec {
    name: "浅色办公",
    desc: "亮环境/打印友好，白底深字高可读",
    dark: false,
    p: Palette {
        accent: Color32::from_rgb(37, 99, 235),
        on_accent: Color32::WHITE,
        selection_bg: Color32::from_rgb(37, 99, 235),
        accent_soft: Color32::from_rgb(219, 234, 254),
        bg_sidebar: Color32::from_rgb(233, 238, 245),
        bg_panel: Color32::from_rgb(245, 248, 252),
        bg_card: Color32::from_rgb(255, 255, 255),
        bg_input: Color32::from_rgb(255, 255, 255),
        bg_faint: Color32::from_rgb(239, 243, 248),
        border: Color32::from_rgb(203, 213, 225),
        text: Color32::from_rgb(30, 41, 59),
        text_dim: Color32::from_rgb(91, 107, 127),
        ok: Color32::from_rgb(21, 128, 61),
        warn: Color32::from_rgb(180, 83, 9),
        danger: Color32::from_rgb(220, 38, 38),
        orange: Color32::from_rgb(194, 65, 12),
        purple: Color32::from_rgb(124, 58, 237),
        hover_bg: Color32::from_rgb(226, 232, 240),
        active_bg: Color32::from_rgb(203, 213, 225),
        inactive_bg: Color32::from_rgb(255, 255, 255),
        toast_bg: Color32::from_rgb(30, 41, 59),
        toast_text: Color32::from_rgb(241, 245, 249),
        banner_bg: Color32::from_rgb(254, 243, 199),
        banner_text: Color32::from_rgb(146, 64, 14),
    },
};

static WARM: ThemeSpec = ThemeSpec {
    name: "暖色护眼",
    desc: "低蓝光暖调，夜间/长时间值守更轻松",
    dark: true,
    p: Palette {
        accent: Color32::from_rgb(224, 164, 88),
        on_accent: Color32::from_rgb(28, 22, 17),
        selection_bg: Color32::from_rgb(184, 121, 47),
        accent_soft: Color32::from_rgb(51, 40, 28),
        bg_sidebar: Color32::from_rgb(20, 17, 14),
        bg_panel: Color32::from_rgb(26, 22, 19),
        bg_card: Color32::from_rgb(36, 31, 26),
        bg_input: Color32::from_rgb(16, 13, 11),
        bg_faint: Color32::from_rgb(32, 27, 22),
        border: Color32::from_rgb(61, 52, 43),
        text: Color32::from_rgb(242, 233, 220),
        text_dim: Color32::from_rgb(179, 162, 140),
        ok: Color32::from_rgb(134, 184, 122),
        warn: Color32::from_rgb(227, 176, 75),
        danger: Color32::from_rgb(217, 100, 89),
        orange: Color32::from_rgb(224, 138, 60),
        purple: Color32::from_rgb(183, 156, 216),
        hover_bg: Color32::from_rgb(50, 42, 34),
        active_bg: Color32::from_rgb(59, 50, 42),
        inactive_bg: Color32::from_rgb(38, 32, 26),
        toast_bg: Color32::from_rgb(42, 35, 28),
        toast_text: Color32::from_rgb(245, 238, 227),
        banner_bg: Color32::from_rgb(58, 44, 20),
        banner_text: Color32::from_rgb(235, 201, 138),
    },
};

static CONTRAST: ThemeSpec = ThemeSpec {
    name: "高对比（无障碍）",
    desc: "纯黑底白字，弱视/强光环境可读性优先",
    dark: true,
    p: Palette {
        accent: Color32::from_rgb(89, 166, 255),
        on_accent: Color32::from_rgb(0, 0, 0),
        selection_bg: Color32::from_rgb(26, 79, 143),
        accent_soft: Color32::from_rgb(22, 50, 79),
        bg_sidebar: Color32::from_rgb(0, 0, 0),
        bg_panel: Color32::from_rgb(0, 0, 0),
        bg_card: Color32::from_rgb(13, 13, 13),
        bg_input: Color32::from_rgb(0, 0, 0),
        bg_faint: Color32::from_rgb(20, 20, 20),
        border: Color32::from_rgb(110, 110, 110),
        text: Color32::from_rgb(255, 255, 255),
        text_dim: Color32::from_rgb(208, 208, 208),
        ok: Color32::from_rgb(61, 220, 132),
        warn: Color32::from_rgb(255, 197, 61),
        danger: Color32::from_rgb(255, 122, 122),
        orange: Color32::from_rgb(255, 169, 77),
        purple: Color32::from_rgb(196, 181, 253),
        hover_bg: Color32::from_rgb(38, 38, 38),
        active_bg: Color32::from_rgb(51, 51, 51),
        inactive_bg: Color32::from_rgb(17, 17, 17),
        toast_bg: Color32::from_rgb(17, 17, 17),
        toast_text: Color32::from_rgb(255, 255, 255),
        banner_bg: Color32::from_rgb(58, 44, 0),
        banner_text: Color32::from_rgb(255, 214, 102),
    },
};

// ---------- 当前主题（UI 绘制期直接取色） ----------

static CURRENT: RwLock<ThemeId> = RwLock::new(ThemeId::DeepBlue);

pub fn set_current(id: ThemeId) {
    *CURRENT.write().expect("主题锁中毒") = id;
}

pub fn current() -> &'static ThemeSpec {
    CURRENT.read().expect("主题锁中毒").spec()
}

pub fn palette() -> &'static Palette {
    &current().p
}

/// 以下取色函数给 UI 代码用（语义名，避免到处写 palette().字段）。
pub fn accent() -> Color32 {
    palette().accent
}
pub fn on_accent() -> Color32 {
    palette().on_accent
}
pub fn accent_soft() -> Color32 {
    palette().accent_soft
}
pub fn bg_sidebar() -> Color32 {
    palette().bg_sidebar
}
pub fn bg_panel() -> Color32 {
    palette().bg_panel
}
pub fn bg_card() -> Color32 {
    palette().bg_card
}
pub fn border() -> Color32 {
    palette().border
}
pub fn text() -> Color32 {
    palette().text
}
pub fn text_dim() -> Color32 {
    palette().text_dim
}
pub fn ok() -> Color32 {
    palette().ok
}
pub fn warn() -> Color32 {
    palette().warn
}
pub fn danger() -> Color32 {
    palette().danger
}
pub fn orange() -> Color32 {
    palette().orange
}
pub fn purple() -> Color32 {
    palette().purple
}
pub fn toast_bg() -> Color32 {
    palette().toast_bg
}
pub fn toast_text() -> Color32 {
    palette().toast_text
}
pub fn banner_bg() -> Color32 {
    palette().banner_bg
}
pub fn banner_text() -> Color32 {
    palette().banner_text
}

/// 字号缩放的可调范围与默认值（默认放大一档，正文 ~16.7px，舒适可见）。
pub const FONT_SCALE_MIN: f32 = 0.85;
pub const FONT_SCALE_MAX: f32 = 1.6;
pub const FONT_SCALE_DEFAULT: f32 = 1.15;

/// 归一化字号缩放（越界收敛、NaN 回退默认）。
pub fn normalize_font_scale(v: f32) -> f32 {
    if !v.is_finite() {
        return FONT_SCALE_DEFAULT;
    }
    v.clamp(FONT_SCALE_MIN, FONT_SCALE_MAX)
}

/// egui 文本样式阶梯（ui.md §3.2 桌面收敛版）。
fn text_styles() -> std::collections::BTreeMap<TextStyle, FontId> {
    [
        (TextStyle::Small, 12.0),
        (TextStyle::Body, 14.5),
        (TextStyle::Button, 14.5),
        (TextStyle::Heading, 20.0),
        (TextStyle::Monospace, 13.5),
    ]
    .into_iter()
    .map(|(k, s)| (k, FontId::new(s, FontFamily::Proportional)))
    .collect()
}

/// 应用主题 + 字号缩放到 egui（幂等；切换时调用一次即可）。
pub fn apply(ctx: &egui::Context, id: ThemeId, font_scale: f32) {
    set_current(id);
    let spec = current();
    let p = &spec.p;

    // 字号阶梯（ui.md §3.2，桌面端收敛）：正文 14.5 / 辅助 12 / 标题 20
    let text_styles = text_styles();

    // 明/暗两套内置基底都写全：系统主题切换时不会露出默认配色
    for t in [egui::Theme::Dark, egui::Theme::Light] {
        ctx.style_mut_of(t, |style| {
            style.text_styles = text_styles.clone();
            let v = &mut style.visuals;
            v.dark_mode = spec.dark;
            v.panel_fill = p.bg_panel;
            v.window_fill = p.bg_card;
            v.extreme_bg_color = p.bg_input;
            v.faint_bg_color = p.bg_faint;
            v.window_stroke = Stroke::new(1.0, p.border);
            v.selection.bg_fill = p.selection_bg;
            v.selection.stroke = Stroke::new(1.0, p.text);
            v.hyperlink_color = p.accent;
            v.override_text_color = Some(p.text);
            v.widgets.inactive.bg_fill = p.inactive_bg;
            v.widgets.inactive.weak_bg_fill = p.inactive_bg;
            v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);
            v.widgets.hovered.bg_fill = p.hover_bg;
            v.widgets.hovered.weak_bg_fill = p.hover_bg;
            v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent);
            v.widgets.active.bg_fill = p.active_bg;
            v.widgets.active.weak_bg_fill = p.active_bg;
            v.widgets.active.bg_stroke = Stroke::new(1.0, p.accent);
            v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
        });
    }
    ctx.set_theme(if spec.dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    });
    ctx.set_zoom_factor(normalize_font_scale(font_scale));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_id_roundtrip_and_fallback() {
        for id in ThemeId::all() {
            assert_eq!(ThemeId::from_str(id.as_str()), id);
        }
        // 配置写错：回退默认而不是 panic/空界面
        assert_eq!(ThemeId::from_str("nonsense"), ThemeId::DeepBlue);
        assert_eq!(ThemeId::from_str(""), ThemeId::DeepBlue);
    }

    #[test]
    fn font_scale_normalization() {
        assert_eq!(normalize_font_scale(1.0), 1.0);
        assert_eq!(normalize_font_scale(f32::NAN), FONT_SCALE_DEFAULT);
        assert_eq!(normalize_font_scale(99.0), FONT_SCALE_MAX);
        assert_eq!(normalize_font_scale(0.0), FONT_SCALE_MIN);
    }

    #[test]
    fn every_theme_has_sane_contrast() {
        // 正文与背景的亮度差必须足够（粗粒度护栏，非 WCAG 认证），
        // 防止后续调色把某个方案调成"看不见的字"。
        for id in ThemeId::all() {
            let p = id.spec().p;
            for (name, fg, bg) in [
                ("text/panel", p.text, p.bg_panel),
                ("text/card", p.text, p.bg_card),
                ("dim/panel", p.text_dim, p.bg_panel),
                ("on_accent/accent", p.on_accent, p.accent),
            ] {
                let l1 = luminance(fg);
                let l2 = luminance(bg);
                let diff = (l1 - l2).abs();
                assert!(
                    diff >= 0.30,
                    "{} 的 {name} 对比不足: {diff:.3}",
                    id.as_str()
                );
            }
        }
    }

    /// 相对亮度（sRGB → 线性，WCAG 2.x 简式）。
    fn luminance(c: Color32) -> f32 {
        let f = |v: u8| {
            let s = v as f32 / 255.0;
            if s <= 0.04045 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
    }
}
