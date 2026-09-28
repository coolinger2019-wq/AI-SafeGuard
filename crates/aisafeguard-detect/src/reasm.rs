//! TCP 流重组（RFC793 简化集，设计见 docs/NGFW_EVOLUTION.md §2.2 reasm 层）。
//!
//! 职责单一：把乱序/重复的 TCP 段按序号重排成连续字节流前缀并保留，
//! 供可疑流取证读取。总保留量有上限（证据只需要前缀），超限直接丢弃后续段。
//!
//! 序号比较用环绕感知的 32 位差值（RFC1982 简化式）：
//! `a` 在 `b` 之后 ⇔ `(a - b) as i32 > 0`。所有跨环绕（wrap）的比较都走这里，
//! 不要用裸的 `>`/`<`——绕回半个序号空间后结果必然反。

/// 单条流最多保留的已重排字节（证据截断用，见 CaptureConfig.mode=full）。
pub const STREAM_CAP: usize = 8 * 1024;

/// 环绕感知的序号比较：`seq` 是否落在 `start` 之后（不含）。
fn after(seq: u32, start: u32) -> bool {
    seq.wrapping_sub(start) != 0 && (seq.wrapping_sub(start) as i32) > 0
}

#[derive(Default)]
pub struct StreamReassembler {
    /// 期望的下一个序号；None = 尚未收到首段（ISN 未知，首段即锚点）。
    next: Option<u32>,
    /// 乱序暂存：键 = 段起始序号（已裁掉与产出前缀重叠的头部）。
    pending: std::collections::BTreeMap<u32, Vec<u8>>,
    /// 重排后的有序字节流前缀，长度 ≤ cap。
    stream: Vec<u8>,
    cap: usize,
}

impl StreamReassembler {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            ..Self::default()
        }
    }

    /// 以 SYN 的 ISN+1 预置期望序号（仅当尚未有锚点）。
    /// 有锚点的重组器对乱序段的容忍度才与真实 TCP 一致。
    pub fn seed(&mut self, next: u32) {
        if self.next.is_none() {
            self.next = Some(next);
        }
    }

    /// 送入一段 TCP 载荷。返回 true 表示有新字节产出。
    /// 重复段（重传）、完全过旧的段、超出上限后的段返回 false。
    pub fn push(&mut self, seq: u32, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let Some(next) = self.next else {
            // 首段即锚点
            let n = data.len().min(self.cap);
            self.stream.extend_from_slice(&data[..n]);
            self.next = Some(seq.wrapping_add(n as u32));
            return true;
        };

        if !after(seq.wrapping_add(data.len() as u32), next) {
            // 整段都在 next 之前（旧段/完全重复的重传）——丢弃
            return false;
        }
        // 裁掉与已产出前缀重叠的头部
        let skip = if after(next, seq) {
            (next.wrapping_sub(seq) as usize).min(data.len())
        } else {
            0
        };
        let seg = &data[skip..];
        if seg.is_empty() {
            return false;
        }
        let start = seq.wrapping_add(skip as u32);

        // 已到上限：不再缓存后续段（证据只需要前缀）
        if self.stream.len() >= self.cap {
            return false;
        }

        self.pending.insert(start, seg.to_vec());
        // 硬边界：乱序暂存过多说明该流病态（或恶意构造），直接放弃暂存保住内存
        if self.pending.len() > 64 {
            self.pending.clear();
            return false;
        }

        let mut new_data = false;
        let mut cursor = next;
        while self.pending.contains_key(&cursor) {
            let seg = self.pending.remove(&cursor).expect("contains_key 已确认");
            let room = self.cap - self.stream.len();
            if room == 0 {
                break;
            }
            let take = seg.len().min(room);
            self.stream.extend_from_slice(&seg[..take]);
            new_data = true;
            cursor = cursor.wrapping_add(take as u32);
            if take < seg.len() {
                break;
            }
        }
        self.next = Some(cursor);
        // cursor 已越过的缓存段永远不会再被消费（重复段先于本段到达的残留），
        // 按数值序清掉——环回绕时数值序与逻辑序的偏差仍在 TCP 窗口量级内，安全。
        let stale: Vec<u32> = self
            .pending
            .range(..cursor)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            self.pending.remove(&k);
        }
        new_data
    }

    /// 已重排的有序字节流前缀。
    pub fn stream(&self) -> &[u8] {
        &self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(r: &StreamReassembler) -> &[u8] {
        r.stream()
    }

    #[test]
    fn first_push_becomes_anchor() {
        let mut r = StreamReassembler::new(1024);
        assert!(r.push(1000, b"hello"));
        assert_eq!(stream(&r), b"hello");
    }

    #[test]
    fn in_order_pushes_concat() {
        let mut r = StreamReassembler::new(1024);
        assert!(r.push(100, b"ab"));
        assert!(r.push(102, b"cd"));
        assert!(r.push(104, b"ef"));
        assert_eq!(stream(&r), b"abcdef");
    }

    #[test]
    fn retransmit_is_dropped() {
        let mut r = StreamReassembler::new(1024);
        assert!(r.push(100, b"abcd"));
        // 完整重传：无新数据
        assert!(!r.push(100, b"abcd"));
        // 部分重叠重传（新数据只有尾巴）
        assert!(r.push(102, b"cdefg"));
        assert_eq!(stream(&r), b"abcdefg");
    }

    #[test]
    fn out_of_order_reassembles() {
        let mut r = StreamReassembler::new(1024);
        assert!(r.push(100, b"ab"));
        // 104 缺口先到：暂存
        assert!(!r.push(104, b"efgh"));
        // 补上 102 缺口：连带吐出 104 段
        assert!(r.push(102, b"cd"));
        assert_eq!(stream(&r), b"abcdefgh");
    }

    #[test]
    fn reverse_order_fills_gap_at_end() {
        let mut r = StreamReassembler::new(1024);
        assert!(r.push(100, b"ab"));
        // 逆序推送：106 → 104
        assert!(!r.push(106, b"xx"));
        assert!(!r.push(104, b"xx"));
        // 最后补上缺口头部：缓存中的 104/106 连锁吐出
        assert!(r.push(102, b"cd"));
        assert_eq!(stream(&r), b"abcdxxxx");
    }

    #[test]
    fn sequence_wrap_around_is_ordered() {
        let mut r = StreamReassembler::new(1024);
        // 首段锚点靠近 32 位序号顶端
        assert!(r.push(0xffff_fffe, b"ab"));
        // 跨越 0 环绕后的段必须续上，而不是被当作"旧段"
        assert!(r.push(0x0000_0000, b"cd"));
        assert!(r.push(0x0000_0002, b"ef"));
        assert_eq!(stream(&r), b"abcdef");
    }

    #[test]
    fn cap_stops_retention() {
        let mut r = StreamReassembler::new(4);
        assert!(r.push(100, b"abcd"));
        // 已到上限：后续段全部丢弃
        assert!(!r.push(104, b"efgh"));
        assert_eq!(stream(&r), b"abcd");
    }

    #[test]
    fn partial_overlap_with_pending_merges() {
        let mut r = StreamReassembler::new(1024);
        assert!(r.push(100, b"ab"));
        assert!(!r.push(104, b"efgh"));
        // 与缓存部分重叠的重传（102..108 覆盖缓存 104..108）
        assert!(r.push(102, b"cdefgh"));
        assert_eq!(stream(&r), b"abcdefgh");
        // 104 的原始段已成重复：丢弃
        assert!(!r.push(104, b"efgh"));
        assert_eq!(stream(&r), b"abcdefgh");
    }
}
