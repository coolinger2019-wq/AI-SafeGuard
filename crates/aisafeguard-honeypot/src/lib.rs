#![forbid(unsafe_code)]

//! TCP 蜜罐：低交互协议仿真（ssh / telnet / http / generic）按 kind 分派，
//! 中交互假 Shell 由 shell 模块提供（0.5.9 H103/H104 接入）。
//! 防御性设计：全局并发上限 + 交互会话独立小额上限、读写超时、payload 清洗截断——
//! 攻击者无法通过海量连接或超长输入拖垮本进程。
//!
//! 模块划分（0.5.9 H102）：[`listener`] 监听与并发预算、`http` HTTP 协议仿真、
//! `protocol` banner 级协议仿真；本文件是门面：公共 API 重导出 + 攻击者输入清洗。

mod http;
mod listener;
mod protocol;
pub mod shell;

use std::time::Duration;

use aisafeguard_l7 as l7;
use tokio::io::AsyncReadExt;

pub use http::{
    content_length, http_request_complete, is_decoy_path, is_login_path, redact_secrets,
    DECOY_PATHS,
};
pub use listener::{start, HoneypotHandle, ListenerState};

/// 单连接会话出口（0.5.9 H102 会话模型）：协议模块填齐，handle_conn 统一发事件。
pub(crate) struct SessionOutcome {
    pub summary: String,
    pub payload: String,
    pub http_hint: Option<l7::HttpHint>,
    /// 交互会话逐命令记录：中交互假 Shell 填充，低交互恒 None
    pub interaction: Option<Vec<aisafeguard_core::event::ShellStep>>,
}

pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_PAYLOAD: usize = 2048;

/// 攻击者输入永远当不可信数据：lossy UTF-8、去控制字符（C0+C1+DEL）、截断。
pub fn sanitize(bytes: &[u8], max_chars: usize) -> String {
    let lossy = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(lossy.len().min(max_chars * 2));
    for c in lossy.chars().take(max_chars) {
        match c {
            '\n' | '\t' => out.push(c),
            '\r' => {}
            // is_control 覆盖 C0 (U+0000-1F)、C1 (U+0080-9F)、DEL——
            // C1 常由多字节 UTF-8 序列产生，手写 (c as u32) < 0x20 会漏掉
            c if c.is_control() => out.push('·'),
            c => out.push(c),
        }
    }
    out
}

/// 清洗后的首行摘要（≤160 字符），任何字节输入都不会 panic。
pub fn request_summary(text: &str, fallback: &str) -> String {
    l7::request_summary(text, fallback)
}

/// 有界读一段：超时映射为 TimedOut（端口扫描只 connect 不发数据属常态路径）。
pub(crate) async fn read_with_timeout(
    s: &mut tokio::net::TcpStream,
    timeout: Duration,
) -> std::io::Result<(usize, Vec<u8>)> {
    let mut buf = vec![0u8; MAX_PAYLOAD];
    match tokio::time::timeout(timeout, s.read(&mut buf)).await {
        Ok(res) => {
            let n = res?;
            Ok((n, buf))
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timeout",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_and_truncates() {
        let raw = b"GET /x HTTP/1.1\r\nHost: a\x01b";
        let s = sanitize(raw, 100);
        assert!(s.contains("GET /x HTTP/1.1"));
        assert!(!s.contains('\r'));
        assert!(s.contains('·'));
        let long = sanitize(&[b'a'; 5000], 100);
        assert_eq!(long.chars().count(), 100);
    }
}
