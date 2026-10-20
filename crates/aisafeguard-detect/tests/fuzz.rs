#![forbid(unsafe_code)]

//! 频次引擎的结构化模糊测试：随机事件序列 + 随机配置，断言不 panic 且
//! 输出判定数有界（每次 observe 最多 2 条：scan + bruteforce）。

use aisafeguard_core::config::DetectConfig;
use aisafeguard_detect::FreqEngine;
use aisafeguard_detect::capture::{l3_payload, passes_mode_filter};
use aisafeguard_detect::reasm::StreamReassembler;
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
            capture: Default::default(),
            exempt_ips: Vec::new(),
            l7: Default::default(),
            rules: Default::default(),
        };
        // 混合合法/畸形来源 IP
        let raw = xorshift(&mut state);
        let ip = match raw % 4 {
            0 => IpAddr::from([
                1 + (raw >> 8) as u8 % 254,
                (raw >> 16) as u8,
                (raw >> 24) as u8,
                (raw >> 32) as u8,
            ]),
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

/// 流重组不变量：任意乱序/重复分片序列，重组产出必须是源序列的前缀且不超过上限。
#[test]
fn fuzz_reasm_stream_is_ordered_prefix() {
    let mut state = 0xDEAD_BEEF_CAFE_0001u64;
    for round in 0..20_000u64 {
        let len = 1 + (xorshift(&mut state) % 512) as usize;
        let src: Vec<u8> = (0..len)
            .map(|_| (xorshift(&mut state) % 256) as u8)
            .collect();
        let mut r = StreamReassembler::new(4096);

        // 切成随机大小的段（offset o → seq 1000+o；ISN=999，SYN 占 1 序号）
        let mut pieces: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut offset = 0usize;
        while offset < src.len() {
            let n = (1 + (xorshift(&mut state) % 40) as usize).min(src.len() - offset);
            pieces.push((1000 + offset as u32, src[offset..offset + n].to_vec()));
            offset += n;
        }
        // 生产语义：SYN 先到，用 ISN+1 预置锚点；其后数据段任意乱序
        r.seed(1000);
        pieces.sort_by_cached_key(|_| xorshift(&mut state));
        // 随机插入一段重传（重复段）
        if pieces.len() > 1 {
            let idx = (xorshift(&mut state) % pieces.len() as u64) as usize;
            let dup = pieces[idx].clone();
            let at = (xorshift(&mut state) % (pieces.len() as u64)) as usize;
            pieces.insert(at, dup);
        }
        let mut order_log: Vec<(u32, Vec<u8>)> = Vec::new();
        for (seq, data) in pieces {
            order_log.push((seq, data.clone()));
            let _ = r.push(seq, &data);
        }

        let stream = r.stream();
        assert!(
            stream == &src[..stream.len()],
            "round {round}: 重组结果必须是源序列的前缀\nsrc={src:?}\nstream={stream:?}\npieces={pieces_dbg:?}",
            pieces_dbg = {
                let mut s = String::new();
                for (seq, d) in &order_log {
                    s.push_str(&format!("({seq},{:?}) ", d));
                }
                s
            }
        );
        assert!(stream.len() <= 4096, "round {round}: 产出不得超过上限");
    }
}

/// L2 剥离不变量：任意字节序列（合法帧/畸形帧/截断帧），l3_payload 不 panic，
/// 且产出必须是输入的后缀切片（偏移只可能是 14/18——以太网头与单层 VLAN 头）。
#[test]
fn fuzz_l3_payload_returns_suffix_of_input() {
    let mut state = 0x1_2F00_D000_0002u64;
    for round in 0..50_000u64 {
        // 随机长度（含超短帧）+ 偏向合法帧头的字节分布
        let len = (xorshift(&mut state) % 80) as usize;
        let mut frame: Vec<u8> = (0..len)
            .map(|_| (xorshift(&mut state) % 256) as u8)
            .collect();
        if len >= 14 && xorshift(&mut state).is_multiple_of(2) {
            // 一半概率放进合法 ethertype，覆盖直通/丢弃两条路径
            let et = match xorshift(&mut state) % 3 {
                0 => 0x0800u16,
                1 => 0x86DD,
                _ => 0x8100,
            };
            frame[12..14].copy_from_slice(&et.to_be_bytes());
            if et == 0x8100 && len >= 18 {
                frame[16..18].copy_from_slice(&[0x08, 0x00]);
            }
        }
        if let Some(ip) = l3_payload(&frame) {
            let off = frame.len() - ip.len();
            assert!(
                (off == 14 || off == 18) && frame.ends_with(ip),
                "round {round}: 产出必须是偏移 14/18 的后缀切片，得到偏移 {off}"
            );
            // 过滤器对同一输入不 panic（control / full 两种模式）
            let _ = passes_mode_filter(ip, false);
            let _ = passes_mode_filter(ip, true);
        }
    }
}
