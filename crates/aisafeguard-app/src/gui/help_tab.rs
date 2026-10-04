//! 帮助页（0.5.10 H140）：内嵌渲染 `docs/MANUAL.md`（离线内置，不依赖网络，
//! 随版本发布更新）。渲染器只覆盖手册使用的 Markdown 子集——标题/列表/粗体/
//! 行内代码/代码块/表格(等宽)/分隔线；手册内容与渲染子集共同进 H150 审计。
//!
//! 换行是全篇硬约束：egui 的 `Label` 默认不换行，而手册里的段落与列表项最宽
//! 相当于内容区的 3 倍——不显式处理就会被右侧裁掉（非全屏时尤其明显）。
//! 因此所有正文一律走 `rich_inline` 组装 `LayoutJob` 并指定 `wrap.max_width`，
//! 列表项把项目符号与正文拼进同一个 job，避免 `ui.horizontal` 里分段而不换行。
//! 等宽内容（代码块/表格）无法折行，放进横向滚动区，需要时用户可横向查看。

use super::*;
use egui::text::LayoutJob;
use egui::{FontFamily, FontId, TextFormat};

/// 手册内容（编译期内嵌）
const MANUAL: &str = include_str!("../../../../docs/MANUAL.md");

impl AisafeApp {
    pub(crate) fn help_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(title(t("帮助", "Help")));
        ui.add_space(space::S);
        ui.label(
            RichText::new(format!(
                "{} v{}",
                t(
                    "集成操作手册（随版本内置更新）",
                    "Integrated manual (bundled with version"
                ),
                env!("CARGO_PKG_VERSION")
            ))
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );
        ui.add_space(space::M);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| render_markdown(ui, MANUAL));
    }
}

/// 最小 Markdown 渲染器：逐行分块，块内做粗体/行内代码的富文本。
/// 手册只用这个子集——多余语法不会被渲染（按原文展示）。
fn render_markdown(ui: &mut egui::Ui, text: &str) {
    let mut in_code = false;
    for line in text.lines() {
        if line.starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            mono_line(ui, line, type_scale::MONO);
            continue;
        }
        // 标题：标记与文本分开——标记单独占一格，文本显式指定折行宽度。
        // 注意不能把两者放进同一个 horizontal 里再靠 available_width，
        // 横向布局会让 available_width 变成无限，折行会再次失效。
        if let Some(rest) = line.strip_prefix("# ") {
            markdown_line(ui, rest, type_scale::TITLE, FontFamily::Proportional, None);
            ui.add_space(space::S);
            continue;
        }
        if let Some(rest) = line.strip_prefix("## ") {
            ui.add_space(space::S);
            heading_with_marker(ui, rest, "▍", type_scale::SECTION);
            ui.add_space(space::XS);
            continue;
        }
        if let Some(rest) = line.strip_prefix("### ") {
            ui.add_space(space::M);
            heading_with_marker(ui, rest, "▸", type_scale::BODY);
            ui.add_space(space::XS);
            continue;
        }
        // 分隔线
        if line.trim() == "---" {
            ui.add_space(space::XS);
            ui.separator();
            ui.add_space(space::XS);
            continue;
        }
        // 列表（无序/有序）：项目符号与正文拼进同一个 LayoutJob，
        // 这样整行（含符号）一起换行，而不是在横向布局里各占一段。
        let trimmed = line.trim_start();
        if let Some(content) = trimmed.strip_prefix("- ") {
            rich_inline(ui, content, Some(("• ", accent())));
            continue;
        }
        if let Some(rest) = numbered_prefix(trimmed) {
            let marker = format!("{rest} ");
            rich_inline(
                ui,
                trimmed[rest.len()..].trim_start(),
                Some((&marker, accent())),
            );
            continue;
        }
        // 表格行：等宽展示（手册里表格仅作对齐参考）
        if trimmed.starts_with('|') {
            mono_line(ui, trimmed, type_scale::MICRO);
            continue;
        }
        // 空行与普通段落
        if trimmed.is_empty() {
            ui.add_space(space::XS);
        } else if line.starts_with(' ') {
            mono_line(ui, line.trim_start(), type_scale::MONO);
        } else {
            rich_inline(ui, line, None);
        }
    }
}

/// 等宽内容（代码块/缩进块/表格行）：等宽字体无法在任意位置折行，
/// 放进横向滚动区，窄窗口下由用户横向查看，而不是被右侧裁掉。
fn mono_line(ui: &mut egui::Ui, text: &str, size: f32) {
    egui::ScrollArea::horizontal()
        .id_salt(("md-mono", text.len(), text.as_ptr() as usize))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .monospace()
                    .size(size)
                    .color(text_color()),
            );
        });
}

/// 标题行：先画语义标记（左侧竖条或三角），再画可换行的正文。
/// `wrap_override` 用于外层已有横向排布、`available_width` 不可靠的场合。
fn markdown_line(
    ui: &mut egui::Ui,
    text: &str,
    size: f32,
    family: FontFamily,
    wrap_override: Option<f32>,
) {
    let mut job = LayoutJob::default();
    job.wrap.max_width = wrap_override
        .unwrap_or_else(|| ui.available_width())
        .max(40.0);
    // 标题内也允许 **粗体** 与 `行内代码`
    job.append_inline(text, size, family, text_color());
    ui.label(job);
}

/// 带语义标记的标题：标记占固定一格，正文拿"剩余宽度 - 标记 - 间距"作为折行宽度。
fn heading_with_marker(ui: &mut egui::Ui, text: &str, marker: &str, size: f32) {
    let mark_w = 14.0;
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(mark_w, 0.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                let mut m = RichText::new(marker).size(size).color(accent());
                m = m.strong();
                ui.label(m);
            },
        );
        let wrap = (ui.available_width() - space::S).max(40.0);
        markdown_line(ui, text, size, FontFamily::Proportional, Some(wrap));
    });
}

/// 行内富文本：**粗体** 与 `行内代码`，整行可换行
fn rich_inline(ui: &mut egui::Ui, text: &str, marker: Option<(&str, Color32)>) {
    let mut job = LayoutJob::default();
    job.wrap.max_width = ui.available_width().max(40.0);
    // 项目符号与正文拼进同一个 job：整行（含符号）一起换行。
    // 若放进 ui.horizontal，available_width 会变成无限，折行失效。
    if let Some((m, color)) = marker {
        job.append(
            m,
            0.0,
            TextFormat {
                font_id: FontId::new(type_scale::BODY, FontFamily::Proportional),
                color,
                ..Default::default()
            },
        );
    }
    job.append_inline(
        text,
        type_scale::BODY,
        FontFamily::Proportional,
        text_color(),
    );
    ui.label(job);
}

/// 把一段带 **粗体** 与 `行内代码` 的文本追加进 LayoutJob。
/// 整行必须拼进同一个 job，egui 才能在整行范围内正确折行——
/// 拆成多个 `ui.label` 会各自独立换行，破坏排版。
trait AppendInline {
    fn append_inline(&mut self, text: &str, size: f32, family: FontFamily, color: Color32);
}

impl AppendInline for LayoutJob {
    fn append_inline(&mut self, text: &str, size: f32, family: FontFamily, color: Color32) {
        for (i, seg) in text.split("**").enumerate() {
            let bold = i % 2 == 1;
            for (j, code_seg) in seg.split('`').enumerate() {
                if code_seg.is_empty() {
                    continue;
                }
                // 奇数段 = 行内代码
                let is_code = j % 2 == 1;
                let (fam, col) = if is_code {
                    (FontFamily::Monospace, accent())
                } else if bold {
                    // 强调段用更亮的文字色表达，不改变字号，层级不乱
                    (family.clone(), text_color())
                } else {
                    (family.clone(), color)
                };
                self.append(
                    code_seg,
                    0.0,
                    TextFormat {
                        font_id: FontId::new(size, fam),
                        color: col,
                        ..Default::default()
                    },
                );
            }
        }
    }
}

/// 有序列表前缀（"1." "2)" 等）
fn numbered_prefix(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i > 0 && i < bytes.len() && (bytes[i] == b'.' || bytes[i] == b')') {
        Some(&line[..=i])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_is_present_and_uses_supported_subset() {
        // 手册必须非空且包含关键章节（H140 验收：帮助页离线可看）
        assert!(MANUAL.contains("# AI-SafeGuard"));
        assert!(MANUAL.contains("## "));
        // 渲染子集纪律：手册不使用渲染器不支持的前缀语法
        for (n, line) in MANUAL.lines().enumerate() {
            let t = line.trim_start();
            assert!(
                !t.starts_with("> ") && !t.starts_with("!["),
                "MANUAL.md 第 {} 行使用了渲染器不支持的语法: {line}",
                n + 1
            );
        }
    }

    #[test]
    fn numbered_prefix_parses() {
        assert_eq!(numbered_prefix("1. 安装"), Some("1."));
        assert_eq!(numbered_prefix("12) 启动"), Some("12)"));
        assert_eq!(numbered_prefix("abc"), None);
        assert_eq!(numbered_prefix(""), None);
    }
}
