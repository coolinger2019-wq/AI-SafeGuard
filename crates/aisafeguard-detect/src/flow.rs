//! 流统计表（设计见 docs/NGFW_EVOLUTION.md §2.1/§5 FlowTable）。
//!
//! 红线：只存元数据与计数，不存载荷。容量有上限，超限按最旧驱逐，
//! 空闲流由 sweep 回收——表规模与内存占用都有界。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// 5 元组流标识（观测方向：src 发起，dst 接收）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub first_ts: i64,
    pub last_ts: i64,
    /// 该流观测到的纯 SYN（无 ACK）个数——正常会话为 1（含重传），异常时显著增大
    pub syn_count: u32,
    /// 观测到的 TCP 段总数
    pub segments: u32,
    /// 观测到的载荷字节数（仅计数，不保留内容）
    pub payload_bytes: u64,
}

impl FlowStats {
    fn new(ts: i64) -> Self {
        Self {
            first_ts: ts,
            last_ts: ts,
            syn_count: 0,
            segments: 0,
            payload_bytes: 0,
        }
    }
}

#[derive(Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
    /// 插入顺序（用于超限驱逐最旧流）
    order: VecDeque<FlowKey>,
    cap: usize,
}

impl FlowTable {
    pub fn new(cap: u32) -> Self {
        Self {
            flows: HashMap::new(),
            order: VecDeque::new(),
            cap: (cap.max(64) as usize).min(1 << 20),
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// 记录一次纯 SYN 观测（新建或累计），返回该流的可变统计。
    pub fn observe_syn(&mut self, ts: i64, key: FlowKey) -> &FlowStats {
        if !self.flows.contains_key(&key) {
            self.push_order(key.clone());
            self.flows.insert(key.clone(), FlowStats::new(ts));
        }
        let entry = self.flows.get_mut(&key).expect("上一步刚插入");
        entry.last_ts = ts;
        entry.syn_count += 1;
        entry
    }

    /// 记录一次非 SYN 段观测（统计用途；full 模式下同时驱动流重组）。
    pub fn observe_segment(&mut self, ts: i64, key: &FlowKey, payload_bytes: usize) {
        if let Some(entry) = self.flows.get_mut(key) {
            entry.last_ts = ts;
            entry.segments += 1;
            entry.payload_bytes += payload_bytes as u64;
        }
    }

    /// 移除空闲超期的流，返回移除数量。
    pub fn sweep(&mut self, now: i64, idle_secs: i64) -> usize {
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, s)| now - s.last_ts > idle_secs)
            .map(|(k, _)| k.clone())
            .collect();
        let n = expired.len();
        for k in expired {
            self.flows.remove(&k);
        }
        if n > 0 {
            self.order.retain(|k| self.flows.contains_key(k));
        }
        n
    }

    fn push_order(&mut self, key: FlowKey) {
        self.order.push_back(key);
        while self.order.len() > self.cap {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.flows.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(src: &str, dp: u16) -> FlowKey {
        FlowKey {
            src: src.parse().unwrap(),
            dst: "10.0.0.1".parse().unwrap(),
            src_port: 40000,
            dst_port: dp,
        }
    }

    #[test]
    fn syn_accumulates_per_flow() {
        let mut t = FlowTable::new(1024);
        t.observe_syn(100, key("203.0.113.7", 80));
        t.observe_syn(101, key("203.0.113.7", 80));
        t.observe_syn(102, key("203.0.113.7", 443));
        assert_eq!(t.len(), 2);
        let s = t.observe_syn(103, key("203.0.113.7", 80));
        assert_eq!(s.syn_count, 3);
        assert_eq!(s.first_ts, 100);
        assert_eq!(s.last_ts, 103);
    }

    #[test]
    fn cap_evicts_oldest() {
        let mut t = FlowTable::new(64); // 下限 64
        for i in 0..80u16 {
            t.observe_syn(100 + i as i64, FlowKey {
                src: "203.0.113.7".parse().unwrap(),
                dst: "10.0.0.1".parse().unwrap(),
                src_port: 40000,
                dst_port: i,
            });
        }
        assert_eq!(t.len(), 64);
        // 最旧的（端口 0-15）已被驱逐
        let oldest = FlowKey {
            src: "203.0.113.7".parse().unwrap(),
            dst: "10.0.0.1".parse().unwrap(),
            src_port: 40000,
            dst_port: 0,
        };
        let s = t.observe_syn(999, oldest);
        // 重新创建，first_ts 是新时间而非 100
        assert_eq!(s.first_ts, 999);
    }

    #[test]
    fn sweep_removes_idle() {
        let mut t = FlowTable::new(1024);
        t.observe_syn(100, key("203.0.113.7", 80));
        t.observe_syn(200, key("203.0.113.8", 80));
        // idle 60：t=100 的流（last_ts=100）在 200 时刚好不超期（200-100=100 > 60 → 超期）
        let n = t.sweep(200, 60);
        assert_eq!(n, 1);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn segment_needs_existing_flow() {
        let mut t = FlowTable::new(1024);
        let k = key("203.0.113.7", 80);
        t.observe_segment(101, &k, 100);
        assert!(t.is_empty());
        t.observe_syn(100, k.clone());
        t.observe_segment(101, &k, 100);
        let s = &t.flows[&k];
        assert_eq!(s.segments, 1);
        assert_eq!(s.payload_bytes, 100);
    }
}
