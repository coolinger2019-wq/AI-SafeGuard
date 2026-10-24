#![forbid(unsafe_code)]

//! 快路径频次检测引擎（快路径第一块，设计见 docs/NGFW_EVOLUTION.md §2.4）。
//!
//! 职责单一：消费蜜罐命中事件的时间序列，产出 `Detection` 判定。
//! 不碰防火墙、不碰存储——执行与留痕由上层（engine）完成。
//! 阈值每次 observe 传入，配置改动即时生效，无需重启。

pub mod capture;
pub mod exposure;
pub mod flow;
pub mod inspect;
pub mod intel;
pub mod reasm;

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

/// 映射表键数上限：长跑内存有界（对齐 inspect.rs DETECTOR_MAP_CAP 先例——
/// 每个出现过的来源 IP 永久留一条空 deque 会无界增长）。溢出清空全表是
/// 可接受的退化：只影响窗口内正在累积的判定，不产生误判。
const DETECTOR_MAP_CAP: usize = 4096;

/// F802 重复犯聚合：同 IP 任意监听器在 REPEAT_WINDOW 内命中 ≥ REPEAT_HITS
/// → repeat 判定（扫描形状之外的「反复来犯」面——评审 #42：14978 命中只有
/// 1.1% 转化，主因是只认扫描形状）。固定内置阈值（宽松防噪；调优走 F760
/// Track A 的 tune 提案，不进配置面）。
const REPEAT_HITS: u32 = 20;
/// F802 聚合窗口（秒）：重复犯与凭据喷洒共用
const AGG_WINDOW_SECS: i64 = 600;
/// F802 凭据喷洒聚合：同 (来源, 用户名) 窗口内口令尝试 ≥ CRED_HITS →
/// cred_spray 判定（评审 #44 可行部分：NTLM/scramble 拿不到明文，计数即证据）
const CRED_HITS: u32 = 5;

#[derive(Default)]
struct Inner {
    /// 每来源的蜜罐触达序列 (ts, port)
    scan: HashMap<IpAddr, VecDeque<(i64, u16)>>,
    /// 每 (来源, 监听器) 的命中序列
    bruteforce: HashMap<(IpAddr, String), VecDeque<i64>>,
    /// F802：每来源的跨监听器命中序列（重复犯聚合）
    repeat: HashMap<IpAddr, VecDeque<i64>>,
    /// F802：每 (来源, 用户名) 的口令尝试序列（凭据喷洒聚合）
    creds: HashMap<(IpAddr, String), VecDeque<i64>>,
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
    pub fn observe(
        &self,
        ts: i64,
        src: IpAddr,
        listener: &str,
        port: u16,
        cfg: &DetectConfig,
    ) -> Vec<Detection> {
        if !cfg.enabled {
            return Vec::new();
        }
        let mut inner = self.inner.lock().expect("频次引擎锁中毒");
        // 键数上界：溢出清空全表（长跑内存有界；见 DETECTOR_MAP_CAP 注释）
        if inner.scan.len() > DETECTOR_MAP_CAP
            || inner.bruteforce.len() > DETECTOR_MAP_CAP
            || inner.repeat.len() > DETECTOR_MAP_CAP
            || inner.creds.len() > DETECTOR_MAP_CAP
            || inner.fired_at.len() > DETECTOR_MAP_CAP * 2
        {
            inner.scan.clear();
            inner.bruteforce.clear();
            inner.repeat.clear();
            inner.creds.clear();
            inner.fired_at.clear();
        }
        let mut out = Vec::new();

        // ---- 端口扫描：窗口内触达 ≥ N 个不同蜜罐端口 ----
        let scan_entry = inner.scan.entry(src).or_default();
        scan_entry.push_back((ts, port));
        let cutoff = ts - cfg.window_secs;
        while scan_entry
            .front()
            .map(|(t, _)| *t < cutoff)
            .unwrap_or(false)
        {
            scan_entry.pop_front();
        }
        let distinct: Vec<u16> = {
            let mut ports: Vec<u16> = scan_entry.iter().map(|(_, p)| *p).collect();
            ports.sort_unstable();
            ports.dedup();
            ports
        };
        if distinct.len() as u32 >= cfg.scan_distinct_ports
            && should_fire(
                &mut inner.fired_at,
                "scan",
                &src.to_string(),
                ts,
                cfg.window_secs,
            )
        {
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
            && should_fire(
                &mut inner.fired_at,
                "bruteforce",
                &format!("{src}/{listener}"),
                ts,
                cfg.window_secs,
            )
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

        // ---- F802 重复犯：同 IP 跨监听器窗口内命中 ≥ REPEAT_HITS ----
        let rep_len = {
            let rep = inner.repeat.entry(src).or_default();
            rep.push_back(ts);
            let rep_cutoff = ts - AGG_WINDOW_SECS;
            while rep.front().map(|t| *t < rep_cutoff).unwrap_or(false) {
                rep.pop_front();
            }
            rep.len()
        };
        if rep_len as u32 >= REPEAT_HITS
            && should_fire(
                &mut inner.fired_at,
                "repeat",
                &src.to_string(),
                ts,
                AGG_WINDOW_SECS,
            )
        {
            out.push(Detection {
                kind: "repeat",
                evidence: format!("{AGG_WINDOW_SECS} 秒内跨监听器命中蜜罐 {rep_len} 次"),
            });
        }

        out
    }

    /// F802 凭据喷洒：同 (来源, 用户名) 窗口内口令尝试 ≥ CRED_HITS →
    /// cred_spray 判定。正式凭证记录仍哈希-only（H200 红线），这里只计数。
    pub fn observe_credential(&self, ts: i64, src: IpAddr, username: &str) -> Vec<Detection> {
        let mut inner = self.inner.lock().expect("频次引擎锁中毒");
        if inner.creds.len() > DETECTOR_MAP_CAP || inner.fired_at.len() > DETECTOR_MAP_CAP * 2 {
            // 键数上界（对齐 observe()：fired_at 也经本路径增长，一并约束）
            inner.creds.clear();
            inner.fired_at.clear();
        }
        let entry = inner.creds.entry((src, username.to_string())).or_default();
        entry.push_back(ts);
        let cutoff = ts - AGG_WINDOW_SECS;
        while entry.front().map(|t| *t < cutoff).unwrap_or(false) {
            entry.pop_front();
        }
        let n = entry.len();
        if n as u32 >= CRED_HITS
            && should_fire(
                &mut inner.fired_at,
                "cred_spray",
                &format!("{src}/{username}"),
                ts,
                AGG_WINDOW_SECS,
            )
        {
            return vec![Detection {
                kind: "cred_spray",
                evidence: format!("{AGG_WINDOW_SECS} 秒内对用户 {username} 口令尝试 {n} 次"),
            }];
        }
        Vec::new()
    }
}

fn should_fire(
    fired_at: &mut HashMap<String, i64>,
    kind: &str,
    key: &str,
    ts: i64,
    window: i64,
) -> bool {
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
            capture: Default::default(),
            exempt_ips: Vec::new(),
            l7: Default::default(),
            rules: Default::default(),
        }
    }

    #[test]
    fn f802_repeat_and_cred_spray_aggregation() {
        // F802：跨监听器重复犯（20 次/600s）与凭据喷洒（5 次/600s）聚合判定
        let eng = FreqEngine::new();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let cfg = cfg();
        let mut fired = false;
        for i in 0..REPEAT_HITS {
            let out = eng.observe(1000 + i as i64, ip, "ssh", 2222, &cfg);
            if out.iter().any(|d| d.kind == "repeat") {
                fired = true;
            }
        }
        assert!(fired, "20 次命中必须触发 repeat 判定");
        // 冷却：窗口内不再重复触发
        let out = eng.observe(1200, ip, "http", 8081, &cfg);
        assert!(!out.iter().any(|d| d.kind == "repeat"), "窗口内冷却");

        // 凭据喷洒：同 (ip, user) 5 次 → cred_spray；不同用户不混计
        for i in 0..CRED_HITS - 1 {
            assert!(eng.observe_credential(2000 + i as i64, ip, "root").is_empty());
        }
        let out = eng.observe_credential(2000 + CRED_HITS as i64 - 1, ip, "root");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "cred_spray");
        assert!(out[0].evidence.contains("root"));
        assert!(
            eng.observe_credential(2100, ip, "admin").is_empty(),
            "不同用户名独立计数"
        );
    }

    #[test]
    fn scan_fires_on_distinct_ports() {
        let eng = FreqEngine::new();
        let c = cfg();
        let t0 = 1_000_000;
        // 阈值 3：第 3 个不同端口被触达的那次调用即触发
        assert!(
            eng.observe(t0, "203.0.113.7".parse().unwrap(), "ssh", 2222, &c)
                .is_empty()
        );
        assert!(
            eng.observe(t0 + 1, "203.0.113.7".parse().unwrap(), "http", 8081, &c)
                .is_empty()
        );
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
