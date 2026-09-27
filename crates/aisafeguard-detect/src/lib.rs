#![forbid(unsafe_code)]

//! 快路径频次检测引擎（快路径第一块，设计见 docs/NGFW_EVOLUTION.md §2.4）。
//!
//! 职责单一：消费蜜罐命中事件的时间序列，产出 `Detection` 判定。
//! 不碰防火墙、不碰存储——执行与留痕由上层（engine）完成。
//! 阈值每次 observe 传入，配置改动即时生效，无需重启。

pub mod exposure;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use aisafeguard_core::config::DetectConfig;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    /// scan | bruteforce
    pub kind: &'static str,
    pub evidence: String,
}

#[derive(Default)]
struct Inner {
    /// 每来源的蜜罐触达序列 (ts, port)
    scan: HashMap<IpAddr, VecDeque<(i64, u16)>>,
    /// 每 (来源, 监听器) 的命中序列
    bruteforce: HashMap<(IpAddr, String), VecDeque<i64>>,
    /// 上次触发时间，避免同一来源在窗口内反复刷判定
    fired_at: HashMap<String, i64>,
}

pub struct FreqEngine {
    inner: Mutex<Inner>,
}

impl FreqEngine {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// 记录一次蜜罐命中并检查是否达到判定阈值。
    /// 同一来源同一判定在 window_secs 内只触发一次。
    pub fn observe(&self, ts: i64, src: IpAddr, listener: &str, port: u16, cfg: &DetectConfig) -> Vec<Detection> {
        if !cfg.enabled {
            return Vec::new();
        }
        let mut inner = self.inner.lock().expect("频次引擎锁中毒");
        let mut out = Vec::new();

        // ---- 端口扫描：窗口内触达 ≥ N 个不同蜜罐端口 ----
        let scan_entry = inner.scan.entry(src).or_default();
        scan_entry.push_back((ts, port));
        let cutoff = ts - cfg.window_secs;
        while scan_entry.front().map(|(t, _)| *t < cutoff).unwrap_or(false) {
            scan_entry.pop_front();
        }
        let distinct: Vec<u16> = {
            let mut ports: Vec<u16> = scan_entry.iter().map(|(_, p)| *p).collect();
            ports.sort_unstable();
            ports.dedup();
            ports
        };
        if distinct.len() as u32 >= cfg.scan_distinct_ports && should_fire(&mut inner.fired_at, "scan", &src.to_string(), ts, cfg.window_secs) {
            out.push(Detection {
                kind: "scan",
                evidence: format!(
                    "{w} 秒内触达 {n} 个不同蜜罐端口（{ports:?}）",
                    w = cfg.window_secs,
                    n = distinct.len(),
                    ports = &distinct[..distinct.len().min(8)],
                ),
            });
        }

        // ---- 暴力探测：同一 (来源, 监听器) 窗口内 ≥ M 次 ----
        let bf_key = (src, listener.to_string());
        let bf_len = {
            let bf_entry = inner.bruteforce.entry(bf_key).or_default();
            bf_entry.push_back(ts);
            while bf_entry.front().map(|t| *t < cutoff).unwrap_or(false) {
                bf_entry.pop_front();
            }
            bf_entry.len() as u32
        };
        if bf_len >= cfg.bruteforce_hits
            && should_fire(&mut inner.fired_at, "bruteforce", &format!("{src}/{listener}"), ts, cfg.window_secs)
        {
            out.push(Detection {
                kind: "bruteforce",
                evidence: format!(
                    "{w} 秒内对蜜罐 [{l}] 命中 {n} 次",
                    w = cfg.window_secs,
                    l = listener,
                    n = bf_len,
                ),
            });
        }

        out
    }
}

fn should_fire(fired_at: &mut HashMap<String, i64>, kind: &str, key: &str, ts: i64, window: i64) -> bool {
    let k = format!("{kind}:{key}");
    match fired_at.get(&k) {
        Some(last) if ts - *last < window => false,
        _ => {
            fired_at.insert(k, ts);
            true
        }
    }
}

impl Default for FreqEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DetectConfig {
        DetectConfig {
            enabled: true,
            auto_block: true,
            scan_distinct_ports: 3,
            bruteforce_hits: 4,
            window_secs: 60,
            ttl_secs: 1800,
        }
    }

    #[test]
    fn scan_fires_on_distinct_ports() {
        let eng = FreqEngine::new();
        let c = cfg();
        let t0 = 1_000_000;
        // 阈值 3：第 3 个不同端口被触达的那次调用即触发
        assert!(eng.observe(t0, "203.0.113.7".parse().unwrap(), "ssh", 2222, &c).is_empty());
        assert!(eng.observe(t0 + 1, "203.0.113.7".parse().unwrap(), "http", 8081, &c).is_empty());
        let dets = eng.observe(t0 + 2, "203.0.113.7".parse().unwrap(), "telnet", 2323, &c);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].kind, "scan");
        assert!(dets[0].evidence.contains("3 个不同蜜罐端口"));
    }

    #[test]
    fn scan_does_not_refire_within_window() {
        let eng = FreqEngine::new();
        let c = cfg();
        let t0 = 1_000_000;
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for (i, p) in [2222u16, 8081, 2323, 1337].iter().enumerate() {
            let _ = eng.observe(t0 + i as i64, ip, "ssh", *p, &c);
        }
        // 首次触发发生在第 3 个端口（见上一测试）；窗口内继续触达不重复触发
        assert!(eng.observe(t0 + 5, ip, "ssh", 9999, &c).is_empty());
        // t0+3 的触达恰好压线仍在窗口，t0+63 时凑满 3 个不同端口 → 再次触发
        let dets = eng.observe(t0 + 63, ip, "ssh", 4441, &c);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].kind, "scan");
        // 新窗口内再抑制
        assert!(eng.observe(t0 + 64, ip, "ssh", 5555, &c).is_empty());
    }

    #[test]
    fn bruteforce_fires_on_repeat_hits() {
        let eng = FreqEngine::new();
        let c = cfg();
        let t0 = 2_000_000;
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        let mut dets = Vec::new();
        for i in 0..4 {
            dets = eng.observe(t0 + i, ip, "ssh", 2222, &c);
        }
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].kind, "bruteforce");
        assert!(dets[0].evidence.contains("对蜜罐 [ssh] 命中 4 次"));
    }

    #[test]
    fn disabled_engine_is_silent() {
        let eng = FreqEngine::new();
        let mut c = cfg();
        c.enabled = false;
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for i in 0..10 {
            assert!(eng.observe(1_000_000 + i, ip, "ssh", 2222, &c).is_empty());
        }
    }

    #[test]
    fn old_entries_slide_out_of_window() {
        let eng = FreqEngine::new();
        let c = cfg();
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        let _ = eng.observe(1_000_000, ip, "ssh", 2222, &c);
        let _ = eng.observe(1_000_001, ip, "http", 8081, &c);
        // 两个旧触达已滑出 60s 窗口，只剩 1 个端口
        let dets = eng.observe(1_000_062, ip, "telnet", 2323, &c);
        assert!(dets.is_empty());
    }
}
