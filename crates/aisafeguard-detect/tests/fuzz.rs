#![forbid(unsafe_code)]

//! 频次引擎的结构化模糊测试：随机事件序列 + 随机配置，断言不 panic 且
//! 输出判定数有界（每次 observe 最多 2 条：scan + bruteforce）。

use aisafeguard_core::config::DetectConfig;
use aisafeguard_detect::FreqEngine;
use std::net::IpAddr;

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn fuzz_freq_engine_never_panics_and_bounds_output() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let eng = FreqEngine::new();
    let listeners = ["ssh", "http", "telnet", "generic"];
    for round in 0..50_000u64 {
        let cfg = DetectConfig {
            enabled: !state.is_multiple_of(4), // 偶尔禁用
            auto_block: state.is_multiple_of(2),
            scan_distinct_ports: 1 + (xorshift(&mut state) % 8) as u32,
            bruteforce_hits: 1 + (xorshift(&mut state) % 12) as u32,
            window_secs: 1 + (xorshift(&mut state) % 600) as i64,
            ttl_secs: 60,
        };
        // 混合合法/畸形来源 IP
        let raw = xorshift(&mut state);
        let ip = match raw % 4 {
            0 => IpAddr::from([1 + (raw >> 8) as u8 % 254, (raw >> 16) as u8, (raw >> 24) as u8, (raw >> 32) as u8]),
            1 => IpAddr::from([127, 0, 0, 1]),
            2 => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            _ => IpAddr::from([192, 168, (raw >> 16) as u8, (raw >> 24) as u8]),
        };
        let listener = listeners[(xorshift(&mut state) % 4) as usize];
        let port = 1 + (xorshift(&mut state) % 65535) as u16;
        let ts = 1_000_000 + round as i64 * (1 + (raw % 5) as i64);

        let dets = eng.observe(ts, ip, listener, port, &cfg);
        assert!(
            dets.len() <= 2,
            "round {round}: 一次 observe 最多产出 2 条判定，得到 {}",
            dets.len()
        );
        for d in &dets {
            assert!(!d.evidence.is_empty());
            assert!(d.kind == "scan" || d.kind == "bruteforce");
        }
    }
}
