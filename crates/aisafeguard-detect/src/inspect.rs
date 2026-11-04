//! 采样检测管线（检测平台 MVP，设计见 docs/NGFW_EVOLUTION.md §2.2 inspect 层）。
//!
//! 职责单一：把捕获线程送来的 IP 帧解析归一，维护流统计与流重组，
//! 运行内置检测器（端口扫描 / SYN flood），产出 `FlowDetection` 判定。
//! 不碰防火墙、不碰存储——执行与留痕由上层（engine）完成，与频次引擎同一纪律。
//!
//! 红线：流表只存元数据与计数；载荷仅 full 模式下进入重组缓存，
//! 且只在判定可疑时随证据截断留存（隐私红线 §3）。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use aisafeguard_core::config::CaptureConfig;
use etherparse::{NetSlice, SlicedPacket, TcpSlice, TransportSlice};

use crate::flow::{FlowKey, FlowTable};
use crate::reasm::{STREAM_CAP, StreamReassembler};

/// 证据里载荷摘要的最大字符数。
const EVIDENCE_SNIPPET_CHARS: usize = 120;
/// 重组缓存表的容量上限（条数），超出不再为新流建重组器。
const REASM_MAP_CAP: usize = 1024;
/// 检测器映射表容量上限（每来源/每目标键数）。伪造源 IP 洪泛会不断制造新键，
/// 到达上限后只更新已跟踪的来源、不再收新来源——内存有界，降级可接受。
const DETECTOR_MAP_CAP: usize = 65536;

/// 内置检测器产出（扫描 / 洪水）。
#[derive(Debug, Clone)]
pub struct FlowDetection {
    /// scan | flood
    pub kind: &'static str,
    pub src: IpAddr,
    /// 触发判定的流（full 模式取证摘要用）
    pub key: FlowKey,
    pub evidence: String,
    /// 内置规则标识（审计可解释性：每条快路径执行都要能说出是哪条规则）。
    pub rule_id: &'static str,
}

#[derive(Default)]
pub struct CapturePipeline {
    table: FlowTable,
    /// 每来源的纯 SYN 目标端口序列 (ts, dst_port)
    scan: HashMap<IpAddr, VecDeque<(i64, u16)>>,
    /// 每 (来源, 目标, 目标端口) 的 SYN 序列
    flood: HashMap<(IpAddr, IpAddr, u16), VecDeque<i64>>,
    /// 上次触发时间，窗口内同一来源不重复刷判定
    fired_at: HashMap<String, i64>,
    /// full 模式下的流重组缓存（只服务取证，容量有界）
    reasm: HashMap<FlowKey, StreamReassembler>,
    /// 本帧有新载荷产出的流（规则子集匹配的扫描清单，take_dirty 取走即清）
    dirty: Vec<FlowKey>,
}

impl CapturePipeline {
    pub fn new(cfg: &CaptureConfig) -> Self {
        Self {
            table: FlowTable::new(cfg.flow_table_cap),
            ..Self::default()
        }
    }

    pub fn flow_count(&self) -> usize {
        self.table.len()
    }

    /// 流统计快照（AI 提示词输入用）：活跃流数 + 按纯 SYN 计数的前 n 名来源。
    /// 红线：只含元数据与计数，无载荷。
    pub fn flow_snapshot(&self, top_n: usize) -> (usize, Vec<(IpAddr, u32)>) {
        (self.table.len(), self.table.top_syn_sources(top_n))
    }

    /// 送入一帧（IP 包），返回本次触发的检测判定。
    pub fn on_frame(&mut self, ts: i64, data: &[u8], cfg: &CaptureConfig) -> Vec<FlowDetection> {
        if !cfg.enabled {
            return Vec::new();
        }
        // F808：SCTP（IP 协议 132）帧——CVE-2026-98548 捆绑块特征检测
        //（要求捕获线程已放行该帧：full 模式下 passes_mode_filter 放行）
        if let Some((src, dst, pdu)) = parse_sctp(data) {
            if let Some(d) = self.check_sctp_uaf(ts, src, dst, pdu, cfg) {
                return vec![d];
            }
            return Vec::new();
        }
        let Some((src, dst, tcp)) = parse(data) else {
            return Vec::new();
        };
        let key = FlowKey {
            src,
            dst,
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
        };

        if tcp.syn() && !tcp.ack() {
            // 纯 SYN：流表 + 两个内置检测器；full 模式下用 ISN+1 预置重组锚点
            self.table.observe_syn(ts, key.clone());
            if cfg.mode == "full" && self.reasm.len() < REASM_MAP_CAP {
                let entry = self
                    .reasm
                    .entry(key.clone())
                    .or_insert_with(|| StreamReassembler::new(STREAM_CAP));
                entry.seed(tcp.sequence_number().wrapping_add(1));
            }
            if let Some(entry) = self.scan.get_mut(&src) {
                entry.push_back((ts, key.dst_port));
                while entry
                    .front()
                    .map(|(t, _)| ts - *t > cfg.window_secs)
                    .unwrap_or(false)
                {
                    entry.pop_front();
                }
            } else if self.scan.len() < DETECTOR_MAP_CAP {
                self.scan.insert(src, VecDeque::from([(ts, key.dst_port)]));
            }
            let mut out = Vec::new();
            if let Some(d) = self.check_scan(ts, &key, cfg) {
                out.push(d);
            }
            if let Some(d) = self.check_flood(ts, &key, cfg) {
                out.push(d);
            }
            out
        } else {
            // 非 SYN 段：流统计（full 模式下载荷进重组缓存供取证/规则匹配）
            self.table.observe_segment(ts, &key, tcp.payload().len());
            if cfg.mode == "full" && !tcp.payload().is_empty() && self.reasm.len() < REASM_MAP_CAP {
                let pushed = self
                    .reasm
                    .entry(key.clone())
                    .or_insert_with(|| StreamReassembler::new(STREAM_CAP))
                    .push(tcp.sequence_number(), tcp.payload());
                if pushed {
                    self.dirty.push(key.clone());
                }
            }
            Vec::new()
        }
    }

    /// 取走本批「有新载荷产出」的流（0.5.0 F4：规则子集匹配的扫描清单）。
    pub fn take_dirty(&mut self) -> Vec<FlowKey> {
        std::mem::take(&mut self.dirty)
    }

    /// 流方向判定：该方向上是否观测到纯 SYN（client→server 即 SYN 方向）。
    /// 未知（捕获晚于握手）时由调用方决定缺省方向。
    pub fn observed_syn(&self, key: &FlowKey) -> bool {
        self.table.observed_syn(key)
    }

    /// 周期回收：空闲流、重组缓存、空的检测器序列。
    pub fn sweep(&mut self, now: i64, cfg: &CaptureConfig) {
        self.table.sweep(now, cfg.flow_idle_secs);
        self.reasm.clear();
        self.dirty.clear();
        self.scan.retain(|_, q| !q.is_empty());
        self.flood.retain(|_, q| !q.is_empty());
    }

    /// 原始重组流前缀（0.5.0 E6：L7/JA3 解析用，不清洗——调用方只读判断）
    pub fn stream_bytes(&self, key: &FlowKey) -> Option<Vec<u8>> {
        self.reasm.get(key).map(|r| r.stream().to_vec())
    }

    /// 载荷证据摘要（full 模式）：重组流的有序前缀 → 清洗 → 截断。
    pub fn payload_snippet(&self, key: &FlowKey) -> String {
        self.reasm
            .get(key)
            .map(|r| sanitize_snippet(r.stream()))
            .unwrap_or_default()
    }

    fn check_scan(&mut self, ts: i64, key: &FlowKey, cfg: &CaptureConfig) -> Option<FlowDetection> {
        let src = key.src;
        let ports: Vec<u16> = {
            let q = self.scan.get(&src)?;
            let mut ports: Vec<u16> = q.iter().map(|(_, p)| *p).collect();
            ports.sort_unstable();
            ports.dedup();
            ports
        };
        if (ports.len() as u32) < cfg.scan_distinct_ports {
            return None;
        }
        if !should_fire(
            &mut self.fired_at,
            "scan",
            &src.to_string(),
            ts,
            cfg.window_secs,
        ) {
            return None;
        }
        Some(FlowDetection {
            kind: "scan",
            src,
            key: key.clone(),
            evidence: format!(
                "{w} 秒内对 {n} 个不同目标端口发送 SYN（采样捕获，{ports:?}）",
                w = cfg.window_secs,
                n = ports.len(),
                ports = &ports[..ports.len().min(8)],
            ),
            rule_id: "builtin.tcp_scan",
        })
    }

    fn check_flood(
        &mut self,
        ts: i64,
        key: &FlowKey,
        cfg: &CaptureConfig,
    ) -> Option<FlowDetection> {
        let k = (key.src, key.dst, key.dst_port);
        let hits = match self.flood.get_mut(&k) {
            Some(q) => {
                q.push_back(ts);
                while q
                    .front()
                    .map(|t| ts - *t > cfg.window_secs)
                    .unwrap_or(false)
                {
                    q.pop_front();
                }
                q.len()
            }
            None => {
                if self.flood.len() >= DETECTOR_MAP_CAP {
                    return None;
                }
                self.flood.insert(k, VecDeque::from([ts]));
                1
            }
        };
        if (hits as u32) < cfg.syn_flood_rate {
            return None;
        }
        if !should_fire(
            &mut self.fired_at,
            "flood",
            &format!("{}->{}:{}", key.src, key.dst, key.dst_port),
            ts,
            cfg.window_secs,
        ) {
            return None;
        }
        Some(FlowDetection {
            kind: "flood",
            src: key.src,
            key: key.clone(),
            evidence: format!(
                "{w} 秒内对 {d}:{p} 发送 {n} 个纯 SYN（采样捕获）",
                w = cfg.window_secs,
                d = key.dst,
                p = key.dst_port,
                n = hits,
            ),
            rule_id: "builtin.syn_flood",
        })
    }

    /// F808 检测（CVE-2026-98548）：同一 SCTP 包内捆绑 [ERROR(Stale Cookie)] 与
    /// [DATA] 块——内核 stale-cookie 重试路径删除"包正在用的 transport"、兄弟 DATA
    /// 块又将其重新登记，构成悬垂指针（use-after-free）。合法协议行为不可能在
    /// 单包内出现此组合（Stale Cookie ERROR 意味着握手重启，DATA 不再有效），
    /// 出现即利用特征。冷却与 scan/flood 同一机制。
    fn check_sctp_uaf(
        &mut self,
        ts: i64,
        src: IpAddr,
        dst: IpAddr,
        pdu: &[u8],
        cfg: &CaptureConfig,
    ) -> Option<FlowDetection> {
        if pdu.len() < 16 {
            return None; // 公共头 12 + 至少一个块头 4
        }
        let sport = u16::from_be_bytes([pdu[0], pdu[1]]);
        let dport = u16::from_be_bytes([pdu[2], pdu[3]]);
        let mut off = 12usize;
        let mut seen_data = false;
        let mut seen_stale_cookie = false;
        while off + 4 <= pdu.len() {
            let ctype = pdu[off];
            let clen = u16::from_be_bytes([pdu[off + 2], pdu[off + 3]]) as usize;
            if clen < 4 {
                break; // 长度非法，停止解析（宁缺毋滥）
            }
            let cend = (off + clen).min(pdu.len());
            match ctype {
                0 => seen_data = true, // DATA 块
                // ERROR 块：值区 = [cause_code(2)][cause_len(2)][...]，
                // Stale Cookie Error 的 cause code = 11（0x000B，RFC 4960 §3.3.10.9）
                9 if off + 6 <= cend
                    && u16::from_be_bytes([pdu[off + 4], pdu[off + 5]]) == 0x000B =>
                {
                    seen_stale_cookie = true;
                }
                _ => {}
            }
            off = cend;
            if seen_data && seen_stale_cookie {
                break;
            }
        }
        if !(seen_data && seen_stale_cookie) {
            return None;
        }
        if !should_fire(
            &mut self.fired_at,
            "sctp_uaf",
            &src.to_string(),
            ts,
            cfg.window_secs,
        ) {
            return None;
        }
        Some(FlowDetection {
            kind: "sctp_uaf",
            src,
            key: FlowKey {
                src,
                dst,
                src_port: sport,
                dst_port: dport,
            },
            evidence: format!(
                "SCTP 单包捆绑 [ERROR(Stale Cookie)]+[DATA]（CVE-2026-98548 利用特征，采样捕获；源口 {sport} → 目的口 {dport}）"
            ),
            rule_id: "builtin.sctp_uaf",
        })
    }
}

/// 帧解析：IP(v4/v6) + TCP，非 TCP 帧返回 None。
fn parse(data: &[u8]) -> Option<(IpAddr, IpAddr, TcpSlice<'_>)> {
    let sp = SlicedPacket::from_ip(data).ok()?;
    let (src, dst) = match &sp.net {
        Some(NetSlice::Ipv4(v4)) => (
            IpAddr::from(v4.header().source()),
            IpAddr::from(v4.header().destination()),
        ),
        Some(NetSlice::Ipv6(v6)) => (
            IpAddr::from(v6.header().source()),
            IpAddr::from(v6.header().destination()),
        ),
        _ => return None,
    };
    let tcp = match sp.transport {
        Some(TransportSlice::Tcp(t)) => t,
        _ => return None,
    };
    Some((src, dst, tcp))
}

/// F808：SCTP over IPv4 帧解析（IP 协议 132）——返回 (源, 目的, SCTP PDU)。
/// 手工解析 IPv4 头（IHL + 总长，剔除链路层填充）；v6 SCTP 不在 F808 范围。
fn parse_sctp(data: &[u8]) -> Option<(IpAddr, IpAddr, &[u8])> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data[9] != 132 {
        return None;
    }
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    let end = total.min(data.len());
    if end < ihl + 12 {
        return None; // 装不下 SCTP 公共头
    }
    let src = IpAddr::from([data[12], data[13], data[14], data[15]]);
    let dst = IpAddr::from([data[16], data[17], data[18], data[19]]);
    Some((src, dst, &data[ihl..end]))
}

/// 载荷摘要清洗：控制字符归空格、截断——与蜜罐回显同一纪律，进证据的都当不可信输入。
fn sanitize_snippet(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control())
        .take(EVIDENCE_SNIPPET_CHARS)
        .collect()
}

/// 判定冷却：同一 key 在窗口内只触发一次。与频次引擎语义一致。
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

#[cfg(test)]
pub(crate) mod testkit {
    //! 测试帧构造：IPv4 + TCP，手工置 SYN/ACK 标志（偏移 = IP 头 20 + TCP 偏移 13）。
    use etherparse::PacketBuilder;

    /// 一段 IPv4/TCP 测试帧的全部参数。
    pub struct TcpFrame<'a> {
        pub src: &'a str,
        pub dst: &'a str,
        pub sport: u16,
        pub dport: u16,
        pub seq: u32,
        pub syn: bool,
        pub ack: bool,
        pub payload: &'a [u8],
    }

    pub fn frame(f: TcpFrame<'_>) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(
            f.src.parse::<std::net::Ipv4Addr>().unwrap().octets(),
            f.dst.parse::<std::net::Ipv4Addr>().unwrap().octets(),
            64,
        )
        .tcp(f.sport, f.dport, f.seq, 8192);
        let mut out = Vec::with_capacity(builder.size(f.payload.len()));
        builder.write(&mut out, f.payload).unwrap();
        const TCP_FLAGS_OFF: usize = 20 + 13;
        if f.syn {
            out[TCP_FLAGS_OFF] |= 0b0000_0010;
        }
        if f.ack {
            out[TCP_FLAGS_OFF] |= 0b0001_0000;
        }
        out
    }

    /// 测试主力：来自 src 发往 10.0.0.1 的 SYN 帧。
    pub fn syn_frame(src: &str, dport: u16, sport: u16) -> Vec<u8> {
        frame(TcpFrame {
            src,
            dst: "10.0.0.1",
            sport,
            dport,
            seq: 1000,
            syn: true,
            ack: false,
            payload: &[],
        })
    }

    /// 数据段（ACK，带载荷）。
    pub fn data_frame(src: &str, sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        frame(TcpFrame {
            src,
            dst: "10.0.0.1",
            sport,
            dport,
            seq,
            syn: false,
            ack: true,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    // ---- F808：SCTP UAF 检测测试 ----

    fn chunk(ctype: u8, body: &[u8]) -> Vec<u8> {
        let mut c = vec![ctype, 0];
        c.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        c.extend_from_slice(body);
        c
    }

    fn error_chunk(cause: u16) -> Vec<u8> {
        let mut body = cause.to_be_bytes().to_vec();
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        chunk(9, &body)
    }

    fn data_chunk() -> Vec<u8> {
        chunk(0, &[0x41; 8])
    }

    fn sctp_pdu(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&1234u16.to_be_bytes());
        pdu.extend_from_slice(&5678u16.to_be_bytes());
        pdu.extend_from_slice(&[0; 8]);
        for c in chunks {
            pdu.extend_from_slice(c);
        }
        pdu
    }

    fn sctp_frame(src: &str, dst: &str, pdu: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + pdu.len());
        out.push(0x45);
        out.push(0x00);
        out.extend_from_slice(&((20 + pdu.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 132, 0x00, 0x00]);
        out.extend_from_slice(&src.parse::<std::net::Ipv4Addr>().unwrap().octets());
        out.extend_from_slice(&dst.parse::<std::net::Ipv4Addr>().unwrap().octets());
        out.extend_from_slice(pdu);
        out
    }

    #[test]
    fn f808_sctp_uaf_bundle_fires_once() {
        let mut p = CapturePipeline::new(&cfg());
        let frame = sctp_frame(
            "203.0.113.7",
            "198.51.100.9",
            &sctp_pdu(&[error_chunk(0x000B), data_chunk()]),
        );
        let out = p.on_frame(1000, &frame, &cfg());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "sctp_uaf");
        assert_eq!(out[0].rule_id, "builtin.sctp_uaf");
        assert!(out[0].evidence.contains("CVE-2026-98548"));
        // 冷却：窗口（60s）内同源不重复触发
        let out = p.on_frame(1050, &frame, &cfg());
        assert!(out.is_empty(), "窗口内应冷却");
    }

    #[test]
    fn f808_sctp_non_bundles_do_not_fire() {
        let mut p = CapturePipeline::new(&cfg());
        let src = "203.0.113.7";
        let dst = "198.51.100.9";
        // 只有 ERROR(Stale Cookie)
        let f1 = sctp_frame(src, dst, &sctp_pdu(&[error_chunk(0x000B)]));
        assert!(p.on_frame(1000, &f1, &cfg()).is_empty());
        // 只有 DATA
        let f2 = sctp_frame(src, dst, &sctp_pdu(&[data_chunk()]));
        assert!(p.on_frame(1000, &f2, &cfg()).is_empty());
        // ERROR cause 不是 Stale Cookie（cause=1 无效流标识）
        let f3 = sctp_frame(src, dst, &sctp_pdu(&[error_chunk(1), data_chunk()]));
        assert!(p.on_frame(1000, &f3, &cfg()).is_empty());
        // 最后的捆绑包正常触发（前面的非捆绑不污染状态）
        let f4 = sctp_frame(src, dst, &sctp_pdu(&[error_chunk(0x000B), data_chunk()]));
        let out = p.on_frame(1200, &f4, &cfg());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "sctp_uaf");
    }

    fn cfg() -> CaptureConfig {
        CaptureConfig {
            enabled: true,
            enforce: false,
            mode: "control".into(),
            scan_distinct_ports: 3,
            driver_sha256: String::new(),
            syn_flood_rate: 4,
            window_secs: 60,
            flow_idle_secs: 120,
            flow_table_cap: 65536,
        }
    }

    #[test]
    fn scan_fires_on_distinct_ports() {
        let mut p = CapturePipeline::new(&cfg());
        let c = cfg();
        let t0 = 1_000_000;
        let src = "203.0.113.7";
        assert!(p.on_frame(t0, &syn_frame(src, 22, 40000), &c).is_empty());
        assert!(
            p.on_frame(t0 + 1, &syn_frame(src, 80, 40001), &c)
                .is_empty()
        );
        let dets = p.on_frame(t0 + 2, &syn_frame(src, 443, 40002), &c);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].kind, "scan");
        assert_eq!(dets[0].rule_id, "builtin.tcp_scan");
        assert!(dets[0].evidence.contains("3 个不同目标端口"));
    }

    #[test]
    fn flood_fires_on_syn_rate() {
        let mut p = CapturePipeline::new(&cfg());
        let c = cfg();
        let t0 = 2_000_000;
        let mut dets = Vec::new();
        for i in 0..4 {
            dets = p.on_frame(t0 + i, &syn_frame("198.51.100.9", 80, 40000 + i as u16), &c);
        }
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].kind, "flood");
        assert_eq!(dets[0].rule_id, "builtin.syn_flood");
        assert!(dets[0].evidence.contains("4 个纯 SYN"));
    }

    #[test]
    fn syn_ack_does_not_count() {
        let mut p = CapturePipeline::new(&cfg());
        let c = cfg();
        let t0 = 3_000_000;
        // SYN-ACK（回包）不算纯 SYN：连接的另一方向不触发判定
        for i in 0..6 {
            let dets = p.on_frame(
                t0 + i,
                &frame(TcpFrame {
                    src: "10.0.0.1",
                    dst: "203.0.113.9",
                    sport: 80,
                    dport: 40000 + i as u16,
                    seq: 2000,
                    syn: true,
                    ack: true,
                    payload: &[],
                }),
                &c,
            );
            assert!(dets.is_empty());
        }
    }

    #[test]
    fn window_slide_prevents_refire() {
        let mut p = CapturePipeline::new(&cfg());
        let c = cfg();
        let t0 = 4_000_000;
        assert!(
            p.on_frame(t0, &syn_frame("203.0.113.8", 22, 41000), &c)
                .is_empty()
        );
        assert!(
            p.on_frame(t0 + 1, &syn_frame("203.0.113.8", 80, 41001), &c)
                .is_empty()
        );
        assert_eq!(
            p.on_frame(t0 + 2, &syn_frame("203.0.113.8", 443, 41002), &c)
                .len(),
            1
        );
        // 窗口内继续扫不重复触发
        assert!(
            p.on_frame(t0 + 3, &syn_frame("203.0.113.8", 3389, 41003), &c)
                .is_empty()
        );
    }

    #[test]
    fn disabled_pipeline_is_silent() {
        let mut p = CapturePipeline::new(&cfg());
        let mut c = cfg();
        c.enabled = false;
        for i in 0..10 {
            assert!(
                p.on_frame(
                    1_000_000 + i,
                    &syn_frame("203.0.113.7", 22 + i as u16, 40000),
                    &c
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn full_mode_feeds_reasm_and_snippet() {
        let mut p = CapturePipeline::new(&cfg());
        let mut c = cfg();
        c.mode = "full".into();
        let t0 = 5_000_000;
        p.on_frame(t0, &syn_frame("203.0.113.7", 8081, 40000), &c);
        // 数据段：乱序送两段再补齐（seq 1001 + 21 = 1022 接续第一段）
        p.on_frame(
            t0 + 2,
            &data_frame("203.0.113.7", 40000, 8081, 1022, b"Host: x\r\n"),
            &c,
        );
        p.on_frame(
            t0 + 1,
            &data_frame("203.0.113.7", 40000, 8081, 1001, b"GET /admin HTTP/1.1\r\n"),
            &c,
        );
        let key = FlowKey {
            src: "203.0.113.7".parse().unwrap(),
            dst: "10.0.0.1".parse().unwrap(),
            src_port: 40000,
            dst_port: 8081,
        };
        // 乱序段重排成完整请求行；控制字符（CRLF）清洗掉
        assert_eq!(p.payload_snippet(&key), "GET /admin HTTP/1.1Host: x");
    }

    #[test]
    fn control_mode_keeps_no_payload() {
        let mut p = CapturePipeline::new(&cfg());
        let c = cfg(); // control 模式
        let t0 = 6_000_000;
        p.on_frame(t0, &syn_frame("203.0.113.7", 8081, 40000), &c);
        p.on_frame(
            t0 + 1,
            &data_frame("203.0.113.7", 40000, 8081, 1001, b"SECRET"),
            &c,
        );
        let key = FlowKey {
            src: "203.0.113.7".parse().unwrap(),
            dst: "10.0.0.1".parse().unwrap(),
            src_port: 40000,
            dst_port: 8081,
        };
        assert!(p.payload_snippet(&key).is_empty());
    }
}
