//! GUI 多语言（F796c v1：基建 + 导航/标题首扫，其余标签页增量跟进）。
//! 中文为源语言：调用点写 `t("中文原文", "English")`，语言为 zh 时零改动。
//! 语言态从 [ui].language 初始化，设置页切换后热生效（GUI 每帧重绘）。

use std::sync::atomic::{AtomicU8, Ordering};

static LANG: AtomicU8 = AtomicU8::new(0); // 0 = zh, 1 = en

pub fn set_lang(lang: &str) {
    LANG.store(u8::from(lang == "en"), Ordering::Relaxed);
}

pub fn is_en() -> bool {
    LANG.load(Ordering::Relaxed) == 1
}

/// 双语取值：zh 模式返回原文（零改动），en 模式返回译文。
pub fn t<'a>(zh: &'a str, en: &'a str) -> &'a str {
    if is_en() { en } else { zh }
}
