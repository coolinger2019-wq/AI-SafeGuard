//! 帮助页（0.5.10 H140）：内嵌渲染 `docs/MANUAL.md`（离线内置，不依赖网络，
//! 随版本发布更新）。渲染器只覆盖手册使用的 Markdown 子集——标题/列表/粗体/
//! 行内代码/代码块/表格(等宽)/分隔线；手册内容与渲染子集共同进 H150 审计。

use super::*;

/// 手册内容（编译期内嵌）
const MANUAL: &str = include_str!("../../../../docs/MANUAL.md");

impl AisafeApp {
    pub(crate) fn help_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(title("帮助"));
        ui.add_space(space::S);
        ui.label(
            RichText::new(format!(
                "集成操作手册（随版本 v{} 内置更新）",
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
            ui.label(
                RichText::new(line)
                    .monospace()
                    .size(type_scale::MONO)
                    .color(text_color()),
            );
            continue;
        }
        // 标题
        if let Some(rest) = line.strip_prefix("# ") {
            ui.label(RichText::new(rest).size(type_scale::TITLE).strong());
            ui.add_space(space::S);
            continue;
        }
        if let Some(rest) = line.strip_prefix("## ") {
            ui.add_space(space::S);
            ui.label(RichText::new(rest).size(type_scale::SECTION).strong());
            ui.add_space(space::XS);
            continue;
        }
        if let Some(rest) = line.strip_prefix("### ") {
            ui.add_space(space::XS);
            ui.label(RichText::new(rest).size(type_scale::BODY).strong());
            continue;
        }
        // 分隔线
        if line.trim() == "---" {
            ui.add_space(space::XS);
            ui.separator();
            ui.add_space(space::XS);
            continue;
        }
        // 列表（无序/有序）
        let trimmed = line.trim_start();
        if trimmed.starts_with("- ") {
            let content = trimmed.trim_start_matches("- ");
            ui.horizontal(|ui| {
                ui.label(RichText::new("•").color(accent()));
                rich_inline(ui, content);
            });
            continue;
        }
        let bullet_num = numbered_prefix(trimmed);
        if let Some(rest) = bullet_num {
            ui.horizontal(|ui| {
                ui.label(RichText::new(rest).color(accent()));
                rich_inline(ui, trimmed[rest.len()..].trim_start());
            });
            continue;
        }
        // 表格行：等宽展示（手册里表格仅作对齐参考）
        if trimmed.starts_with('|') {
            ui.label(
                RichText::new(trimmed)
                    .monospace()
                    .size(type_scale::MICRO)
                    .color(text_dim()),
            );
            continue;
        }
        // 空行与普通段落
        if trimmed.is_empty() {
            ui.add_space(space::XS);
        } else if line.starts_with(' ') {
            ui.label(
                RichText::new(line.trim_start())
                    .monospace()
                    .size(type_scale::MONO),
            );
        } else {
            rich_inline(ui, line);
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

/// 行内富文本：**粗体** 与 `行内代码`
fn rich_inline(ui: &mut egui::Ui, text: &str) {
    for (i, seg) in text.split("**").enumerate() {
        for (j, code_seg) in seg.split('`').enumerate() {
            if code_seg.is_empty() {
                continue;
            }
            let mut rt = RichText::new(code_seg).size(type_scale::BODY);
            // 奇数段 = 行内代码
            if j % 2 == 1 {
                rt = rt.monospace().color(accent());
            }
            // 奇数段 = 粗体
            if i % 2 == 1 {
                rt = rt.strong();
            }
            ui.label(rt);
        }
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
