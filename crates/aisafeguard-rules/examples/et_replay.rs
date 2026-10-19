//! F750 回放校准器（examples，不进产品二进制）。
//!
//! 用法：`cargo run --example et_replay -- <rules文件> <事件JSONL>`
//! JSONL 每行：{"ts":..,"ip":"..","port":..,"listener":"..","hex":"<载荷hex>"}
//!
//! 只读判定不执行：对每条事件窗口跑全部规则，输出每 sid 命中数 + 源样本，
//! 供终选判读（红线：误报是唯一硬淘汰项；零命中保留为保险单）。

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

fn is_home(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("用法: et_replay <rules文件> <事件JSONL>");
        std::process::exit(2);
    }
    let rules_path = PathBuf::from(&args[1]);
    let events_path = PathBuf::from(&args[2]);

    // 修复循环：引擎整包拒绝（pcre 体积/转义边角）时按报错行号剔除后重载——
    // selector 无法预知 rust regex 的编译体积，这里兜底到「可加载」形态，
    // 并把被剔行写回 <rules>.repaired 供终选打包。
    let orig_text = std::fs::read_to_string(&rules_path).expect("读规则包");
    let mut lines: Vec<String> = orig_text.lines().map(str::to_string).collect();
    let mut dropped: Vec<String> = Vec::new();
    let rs = loop {
        let raw = lines.join("\n");
        match aisafeguard_rules::loader::load_package(raw.as_bytes(), 5000) {
            Ok(rs) => break rs,
            Err(e) => {
                let msg = e.to_string();
                let line_no: Option<usize> = msg
                    .split("第 ")
                    .nth(1)
                    .and_then(|s| s.split(" 行").next())
                    .and_then(|s| s.parse().ok());
                let Some(n) = line_no else {
                    panic!("规则包拒绝且无法定位行: {msg}");
                };
                if n == 0 || n > lines.len() || dropped.len() > 500 {
                    panic!("规则包拒绝且剔行越界/超限: {msg}");
                }
                dropped.push(format!("第{n}行: {}", lines[n - 1].clone()));
                lines[n - 1] = format!("# [replay 剔除] {}", lines[n - 1]);
            }
        }
    };
    if !dropped.is_empty() {
        let repaired = rules_path.with_extension("repaired.rules");
        std::fs::write(&repaired, lines.join("\n")).expect("写 repaired");
        println!("整包修复: 剔 {} 行 → {}", dropped.len(), repaired.display());
        for d in &dropped {
            println!("  {d}");
        }
    }
    println!(
        "规则包加载: {} 条规则, sha256={}",
        rs.rule_count,
        &rs.sha256[..16]
    );

    let data = std::fs::read_to_string(&events_path).expect("读事件");
    let start = Instant::now();
    let mut total_events = 0usize;
    let mut total_window_bytes = 0usize;
    let mut empty_windows = 0usize;
    // sid -> (命中数, 源样本)
    let mut hits: BTreeMap<u32, (u64, HashSet<String>)> = BTreeMap::new();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 极简字段抽取（导出格式固定，值均为无转义安全字符）
        let grab = |key: &str| -> String {
            let pat = format!("\"{key}\":");
            let i = line
                .find(&pat)
                .unwrap_or_else(|| panic!("缺字段 {key}: {line}"));
            let rest = &line[i + pat.len()..];
            let v = rest.trim_start();
            if let Some(stripped) = v.strip_prefix('"') {
                stripped.split('"').next().unwrap_or("").to_string()
            } else {
                v.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("0")
                    .to_string()
            }
        };
        let ip: IpAddr = grab("ip").parse().expect("ip");
        let port: u16 = grab("port").parse().unwrap_or(0);
        let hex_str = grab("hex");
        let window = {
            let bytes = (0..hex_str.len() / 2)
                .map(|i| u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap_or(0))
                .collect::<Vec<u8>>();
            bytes
        };
        if window.is_empty() {
            empty_windows += 1;
            continue;
        }
        total_events += 1;
        total_window_bytes += window.len();
        let session = aisafeguard_rules::matcher::Session {
            client_ip: ip,
            client_port: 0,
            server_ip: "10.0.0.1".parse().unwrap(),
            server_port: port,
            to_server: true,
            proto: aisafeguard_rules::ir::Proto::Tcp,
            is_home: &is_home,
        };
        for rule in &rs.rules {
            if aisafeguard_rules::matcher::rule_matches(rule, &window, &session) {
                let e = hits.entry(rule.sid).or_insert((0, HashSet::new()));
                e.0 += 1;
                if e.1.len() < 5 {
                    e.1.insert(ip.to_string());
                }
            }
        }
    }
    let elapsed = start.elapsed();
    println!(
        "回放: {} 事件 / {} 字节窗口 / 空 windows {} / 耗时 {:.1?} ({:.0} ns/事件)",
        total_events,
        total_window_bytes,
        empty_windows,
        elapsed,
        elapsed.as_nanos() as f64 / total_events.max(1) as f64
    );
    println!("命中 sid 数: {} / 规则 {}", hits.len(), rs.rule_count);
    for (sid, (count, srcs)) in &hits {
        let msg = rs
            .rules
            .iter()
            .find(|r| r.sid == *sid)
            .map(|r| r.msg.clone())
            .unwrap_or_default();
        println!(
            "sid={} ×{} 源[{}] {}",
            sid,
            count,
            srcs.into_iter().cloned().collect::<Vec<_>>().join(","),
            msg
        );
    }
}
