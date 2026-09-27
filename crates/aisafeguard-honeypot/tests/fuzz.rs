#![forbid(unsafe_code)]

//! 结构化模糊测试（P0.5 [A.8.29]）：确定性 PRNG 生成随机输入，
//! 对蜜罐解析路径施加不变量断言。双平台 CI 可跑（cargo test）；
//! coverage-guided 的 cargo-fuzz 目标待 Linux CI 专项补充。

use aisafeguard_honeypot::{http_request_complete, request_summary, sanitize};

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn random_bytes(state: &mut u64, len: usize) -> Vec<u8> {
    (0..len).map(|_| (xorshift(state) & 0xFF) as u8).collect()
}

/// sanitize 的不变量：长度有界、无控制字符（\n\t 除外）、任意输入不 panic
#[test]
fn fuzz_sanitize_invariants() {
    let mut state = 0x243F_6A88_85A3_08D3u64;
    for _ in 0..20_000 {
        let len = (xorshift(&mut state) % 8192) as usize;
        let data = random_bytes(&mut state, len);
        let max = 1 + (xorshift(&mut state) % 4096) as usize;
        let s = sanitize(&data, max);
        assert!(
            s.chars().count() <= max,
            "sanitize 输出超过上限: {} > {max}",
            s.chars().count()
        );
        assert!(
            !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t'),
            "sanitize 输出残留控制字符: {s:?}"
        );
    }
}

/// 请求摘要的不变量：永不 panic、永远 ≤160 字符、空白输入走 fallback
#[test]
fn fuzz_request_summary_invariants() {
    let mut state = 0x1319_8A2E_0370_7344u64;
    for _ in 0..20_000 {
        let len = (xorshift(&mut state) % 4096) as usize;
        let data = random_bytes(&mut state, len);
        let text = sanitize(&data, 2048);
        let s = request_summary(&text, "FALLBACK");
        assert!(s.chars().count() <= 160, "摘要超长: {}", s.chars().count());
        assert!(!s.is_empty());
    }
    // 首行为空（清洗后无可见内容）确定走 fallback；
    // 注意 "\0\x01" 清洗后是可见的 "··"，属合法摘要而非 fallback
    for weird in ["", "\r\n", "\n\n", "   "] {
        let s = request_summary(&sanitize(weird.as_bytes(), 100), "FALLBACK");
        assert_eq!(s, "FALLBACK", "输入 {weird:?} 应走 fallback");
    }
}

/// HTTP 头完整性扫描：任意输入不 panic，\r\n\r\n 出现必判完整
#[test]
fn fuzz_http_request_complete_invariants() {
    let mut state = 0xA409_3822_299F_31D0u64;
    for _ in 0..20_000 {
        let len = (xorshift(&mut state) % 4096) as usize;
        let data = random_bytes(&mut state, len);
        let complete = http_request_complete(&data);
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            assert!(complete, "\\r\\n\\r\\n 存在却判不完整");
        }
        if data.len() >= 8192 {
            assert!(complete, "超限必判完整");
        }
    }
}
