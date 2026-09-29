//! 匹配引擎（F3）：把已加载的规则在「匹配窗口」上执行，产出命中。
//!
//! 匹配窗口（子集规范冻结）：蜜罐 payload（完整）、采样 full 模式重组流前缀
//! （≤8KB）、control 模式不匹配。多 content 按出现顺序 AND（gaps 允许，
//! distance/within 收紧间隔，offset/depth 绝对锚定）。
//!
//! 头部语义：
//! - `$HOME_NET`/`$EXTERNAL_NET` 由调用方注入判定函数（本机/内网口径由上层定）；
//! - `->` 只按 client→server 方向对头，`<>` 两个方向都试；
//! - `flow:established` ≈ 窗口非空（有载荷必有握手完成，简化近似，文档钉住）；
//! - threshold 计时由调用方传 ts，纯函数可测试。

use std::net::IpAddr;

use crate::ir::{Addr, AddrSpec, Direction, Proto, Rule, Threshold, ThresholdKind};

/// HOME_NET 判定函数：由调用方注入（本机地址 + 内网/回环口径）。
pub type IsHome<'a> = &'a dyn Fn(IpAddr) -> bool;

/// 一次匹配的会话上下文。client = 连接发起方（蜜罐路径即访问蜜罐的一侧）。
pub struct Session<'a> {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    /// 载荷方向：true = client→server（蜜罐路径恒 true；采样路径按流方向）
    pub to_server: bool,
    pub proto: Proto,
    pub is_home: IsHome<'a>,
}

/// 一条规则命中（窗口证据由调用方决定如何截断留存）。
#[derive(Debug, Clone)]
pub struct RuleHit {
    pub rule_id: String,
    pub sid: u32,
    pub msg: String,
    /// classtype 映射的 severity（无 classtype 归 low）
    pub severity: &'static str,
}

/// 规则头部（协议/地址/端口/方向/flow）是否命中该会话。
fn header_matches(rule: &Rule, s: &Session<'_>, swapped: bool) -> bool {
    let (src_ip, src_port, dst_ip, dst_port) = if swapped {
        (s.server_ip, s.server_port, s.client_ip, s.client_port)
    } else {
        (s.client_ip, s.client_port, s.server_ip, s.server_port)
    };
    if rule.proto != s.proto {
        return false;
    }
    addr_matches(&rule.src, src_ip, s.is_home)
        && addr_matches(&rule.dst, dst_ip, s.is_home)
        && rule.src_port.matches(src_port)
        && rule.dst_port.matches(dst_port)
}

fn addr_matches(spec: &AddrSpec, ip: IpAddr, is_home: IsHome<'_>) -> bool {
    match spec {
        AddrSpec::Any => true,
        AddrSpec::HomeNet => is_home(ip),
        AddrSpec::ExternalNet => !is_home(ip),
        AddrSpec::List(items) => {
            // 任一否定项命中 → 不匹配；无肯定项（纯否定）→ 不被否定即匹配；
            // 否则需命中任一肯定项
            let mut has_pos = false;
            let mut hit = false;
            for item in items {
                let m = addr_item_matches(item, ip);
                if item.neg {
                    if m {
                        return false;
                    }
                } else {
                    has_pos = true;
                    hit |= m;
                }
            }
            hit || !has_pos
        }
    }
}

fn addr_item_matches(item: &crate::ir::AddrItem, ip: IpAddr) -> bool {
    match &item.addr {
        Addr::Ip(a) => *a == ip,
        Addr::Cidr { base, prefix } => cidr_contains(base, *prefix, ip),
    }
}

/// CIDR 包含判定：前缀位相等即包含（不做基址归零——解析时未强制网络位）。
fn cidr_contains(base: &IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (base, ip) {
        (std::net::IpAddr::V4(b), std::net::IpAddr::V4(i)) => {
            let max = 32u8;
            let p = prefix.min(max);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            (u32::from(*b) & mask) == (u32::from(i) & mask)
        }
        (std::net::IpAddr::V6(b), std::net::IpAddr::V6(i)) => {
            let max = 128u8;
            let p = prefix.min(max);
            let mask = if p == 0 {
                u128::MAX
            } else {
                u128::MAX << (128 - p)
            };
            // p=0 时移位 128 会 panic，上面已按 0 特判
            (u128::from(*b) & mask) == (u128::from(i) & mask)
        }
        _ => false, // 族不同不包含
    }
}

/// 选项匹配：窗口字节上顺序执行 content/pcre。
fn options_match(rule: &Rule, window: &[u8]) -> bool {
    let mut cursor: usize = 0; // 上一匹配的结束位置（顺序 AND 锚点）
    for c in &rule.contents {
        let pattern: Vec<u8> = if c.nocase {
            c.bytes.to_ascii_lowercase()
        } else {
            c.bytes.clone()
        };
        let haystack: Vec<u8> = if c.nocase {
            window.to_ascii_lowercase()
        } else {
            window.to_vec()
        };
        // 搜索区间：起点 = offset（绝对）或 prev_end + distance；终点 = depth（自 offset
        // 基准）/ within（自上一匹配结束）与窗口末尾取小
        let start = if let Some(o) = c.offset {
            o as usize
        } else {
            cursor.saturating_add(c.distance.unwrap_or(0) as usize)
        };
        let mut end = window.len();
        if let Some(d) = c.depth {
            let base = c.offset.unwrap_or(0) as usize;
            end = end.min(base.saturating_add(d as usize));
        }
        if let Some(w) = c.within {
            end = end.min(cursor.saturating_add(w as usize));
        }
        if start > end || start > haystack.len() {
            return false;
        }
        let end = end.min(haystack.len());
        let region = &haystack[start..end];
        let found = find_sub(region, &pattern).map(|i| i + start);
        match found {
            Some(pos) => cursor = pos + pattern.len(),
            None => return false,
        }
    }
    for p in &rule.pcre {
        // R 标志：从上一匹配结束处继续搜；否则整个窗口任意位置
        let region_start = if p.relative {
            cursor.min(window.len())
        } else {
            0
        };
        let m = std::str::from_utf8(&window[region_start..])
            .ok()
            .and_then(|text| p.re.find(text));
        match m {
            Some(m) => cursor = region_start + m.end(),
            None => return false,
        }
    }
    true
}

/// 朴素子串查找（窗口 ≤8KB、pattern ≤512B，性能足够；不用 memmem 免加依赖）。
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 规则是否命中：头部（含 flow 方向）+ 选项。
pub fn rule_matches(rule: &Rule, window: &[u8], s: &Session<'_>) -> bool {
    if rule.flow.to_server && !s.to_server {
        return false;
    }
    if rule.flow.from_server && s.to_server {
        return false;
    }
    if rule.flow.established && window.is_empty() {
        // 近似：有载荷必有已建立的连接（蜜罐 accept 后的数据、采样重组流同义）
        return false;
    }
    match rule.direction {
        // `->` 头部随载荷方向对齐（Suricata 语义：包从 src 流向 dst）——
        // to_server 的包源是 client，from_server 的包源是 server
        Direction::Uni => header_matches(rule, s, !s.to_server) && options_match(rule, window),
        Direction::Bi => {
            (header_matches(rule, s, false) && options_match(rule, window))
                || (header_matches(rule, s, true) && options_match(rule, window))
        }
    }
}

/// 把规则映射为命中记录（severity 取 classtype 映射，缺省 low）。
pub fn to_hit(rule: &Rule) -> RuleHit {
    RuleHit {
        rule_id: rule.rule_id(),
        sid: rule.sid,
        msg: rule.msg.clone(),
        severity: rule
            .classtype
            .as_deref()
            .and_then(crate::severity_for_classtype)
            .unwrap_or("low"),
    }
}

/// threshold 判定器（引擎侧按 (rule, 来源) 维护；整包热更时重建）。
#[derive(Default)]
pub struct ThresholdTracker {
    /// 每 key 的窗口内命中时间序列
    hits: HashMap<String, VecDeque<i64>>,
    /// 每 key 上次放行时间（limit 冷却）
    fired_at: HashMap<String, i64>,
}

use std::collections::{HashMap, VecDeque};

impl ThresholdTracker {
    /// 返回 true = 本次命中允许上报。
    pub fn allow(&mut self, t: &Threshold, key: &str, ts: i64) -> bool {
        let cutoff = ts - t.seconds;
        let seq = self.hits.entry(key.to_string()).or_default();
        seq.push_back(ts);
        while seq.front().map(|x| *x < cutoff).unwrap_or(false) {
            seq.pop_front();
        }
        let reached = seq.len() as u32 >= t.count.max(1);
        // limit：窗口内只放行一次（自上次放行起 seconds 内静默）
        if t.kind == ThresholdKind::Limit {
            if let Some(last) = self.fired_at.get(key)
                && ts - *last < t.seconds
            {
                return false;
            }
            if reached {
                self.fired_at.insert(key.to_string(), ts);
                return true;
            }
            return false;
        }
        // both：第 count 条触发，触发后进入 seconds 冷却
        if !reached {
            return false;
        }
        if let Some(last) = self.fired_at.get(key)
            && ts - *last < t.seconds
        {
            return false;
        }
        self.fired_at.insert(key.to_string(), ts);
        seq.clear();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_rule;
    use std::net::IpAddr;

    fn parse(line: &str) -> Rule {
        parse_rule(line).unwrap()
    }

    fn session(to_server: bool) -> Session<'static> {
        static IS_HOME: std::sync::OnceLock<Box<dyn Fn(IpAddr) -> bool + Send + Sync>> =
            std::sync::OnceLock::new();
        let f = IS_HOME.get_or_init(|| {
            Box::new(|ip: IpAddr| ip.is_loopback() || matches!(ip, IpAddr::V4(v) if v.is_private()))
        });
        Session {
            client_ip: "203.0.113.7".parse().unwrap(),
            client_port: 44444,
            server_ip: "192.168.1.5".parse().unwrap(),
            server_port: 8081,
            to_server,
            proto: Proto::Tcp,
            is_home: f.as_ref(),
        }
    }

    #[test]
    fn simple_content_matches() {
        let r = parse(
            r#"alert tcp $EXTERNAL_NET any -> $HOME_NET 8081 (msg:"probe"; content:"GET /admin"; sid:1;)"#,
        );
        assert!(rule_matches(
            &r,
            b"GET /admin/config HTTP/1.1",
            &session(true)
        ));
        // 无 classtype → 缺省 low
        assert_eq!(to_hit(&r).severity, "low");
        // classtype 映射 severity
        let rc = parse(
            r#"alert tcp any any -> any any (msg:"p"; content:"GET"; classtype:web-application-attack; sid:2;)"#,
        );
        assert_eq!(to_hit(&rc).severity, "critical");
    }

    #[test]
    fn header_gates_mismatch() {
        let r = parse(
            r#"alert tcp $EXTERNAL_NET any -> $HOME_NET 9999 (msg:"x"; content:"GET"; sid:1;)"#,
        );
        // 服务端口不匹配
        assert!(!rule_matches(&r, b"GET", &session(true)));
        // 服务端口对上 → 命中
        let mut s = session(true);
        s.server_port = 9999;
        assert!(rule_matches(&r, b"GET", &s));
    }

    #[test]
    fn external_net_rejects_home_source() {
        let r = parse(
            r#"alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"x"; content:"GET"; sid:1;)"#,
        );
        assert!(rule_matches(&r, b"GET", &session(true)));
        // 来自内网的载荷：src=HOME_NET → EXTERNAL_NET 不匹配
        let mut s = session(true);
        let mut s2 = s;
        s2.client_ip = "192.168.1.50".parse().unwrap();
        s = s2;
        assert!(!rule_matches(&r, b"GET", &s));
    }

    #[test]
    fn ordered_contents_with_gap() {
        let r = parse(
            r#"alert tcp any any -> any any (msg:"x"; content:"cmd.exe"; content:" Administr"; sid:1;)"#,
        );
        // 顺序 AND：前者在前，允许中间有间隔
        assert!(rule_matches(
            &r,
            b"GET /run HTTP/1.1\r\ncmd.exe Administr now",
            &session(true)
        ));
        // 逆序出现 → 不命中
        assert!(!rule_matches(&r, b"Administr cmd.exe", &session(true)));
    }

    #[test]
    fn nocase_and_depth_offset() {
        let r = parse(
            r#"alert tcp any any -> any any (msg:"x"; content:"GET"; nocase; offset:0; depth:5; sid:1;)"#,
        );
        assert!(rule_matches(&r, b"get /admin", &session(true)));
        // 超出 depth=5 的位置出现不算
        assert!(!rule_matches(&r, b"xx geT /admin", &session(true)));
    }

    #[test]
    fn distance_and_within_tighten() {
        let r = parse(
            r#"alert tcp any any -> any any (msg:"x"; content:"AB"; content:"CD"; distance:0; within:4; sid:1;)"#,
        );
        assert!(rule_matches(&r, b"xxABCDyy", &session(true)));
        assert!(
            rule_matches(&r, b"xxABxxCDyy", &session(true)),
            "间隔恰 2 字节仍在 within=4 内"
        );
        // 间隔 5 字节超过 within
        assert!(!rule_matches(&r, b"xxABxxxxxCDyy", &session(true)));
    }

    #[test]
    fn pcre_plain_and_relative() {
        let r = parse(
            r#"alert tcp any any -> any any (msg:"x"; content:"User-Agent"; pcre:"/[a-z]+(bot|scan)/i"; sid:1;)"#,
        );
        assert!(rule_matches(
            &r,
            b"User-Agent: EvilScanner/1.0",
            &session(true)
        ));
        assert!(!rule_matches(
            &r,
            b"User-Agent: Mozilla/5.0",
            &session(true)
        ));

        // R 标志：从上一匹配结束处起搜（^ 锚定区域起点）
        let rr = parse(
            r#"alert tcp any any -> any any (msg:"x"; content:"dir="; pcre:"/^\/[a-z]+/R"; sid:2;)"#,
        );
        assert!(rule_matches(&rr, b"dir=/etc/passwd", &session(true)));
        // dir= 之后不是路径 → 不命中
        assert!(!rule_matches(&rr, b"dir=x/etc", &session(true)));
    }

    #[test]
    fn flow_direction_gates() {
        let r = parse(
            r#"alert tcp any any -> any any (msg:"x"; content:"HTTP/1.1 200"; flow:from_server; sid:1;)"#,
        );
        // to_server 载荷不匹配 from_server 规则
        assert!(!rule_matches(&r, b"HTTP/1.1 200 OK", &session(true)));
        assert!(rule_matches(&r, b"HTTP/1.1 200 OK", &session(false)));
        // established 近似：空窗口不命中
        let r2 = parse(
            r#"alert tcp any any -> any any (msg:"x"; content:"a"; flow:established; sid:2;)"#,
        );
        assert!(!rule_matches(&r2, b"", &session(true)));
    }

    #[test]
    fn cidr_matching() {
        let r = parse(r#"alert tcp any any -> 192.168.0.0/16 any (msg:"x"; content:"x"; sid:1;)"#);
        assert!(rule_matches(&r, b"x", &session(true)));
        let r2 = parse(r#"alert tcp any any -> 10.0.0.0/8 any (msg:"x"; content:"x"; sid:2;)"#);
        assert!(!rule_matches(&r2, b"x", &session(true)));
    }

    #[test]
    fn bidirectional_header_tries_both() {
        let r = parse(r#"alert tcp any 8081 <> any any (msg:"x"; content:"y"; sid:1;)"#);
        // to_server：dst=8081 命中正向头
        assert!(rule_matches(&r, b"y", &session(true)));
    }

    #[test]
    fn threshold_limit_fires_once_per_window() {
        let mut tt = ThresholdTracker::default();
        let t = Threshold {
            kind: ThresholdKind::Limit,
            by_src: false,
            count: 1,
            seconds: 60,
        };
        let key = "1";
        assert!(tt.allow(&t, key, 1000));
        assert!(!tt.allow(&t, key, 1010));
        assert!(!tt.allow(&t, key, 1059));
        assert!(tt.allow(&t, key, 1061), "冷却期过后再次放行");
    }

    #[test]
    fn threshold_both_counts_up() {
        let mut tt = ThresholdTracker::default();
        let t = Threshold {
            kind: ThresholdKind::Both,
            by_src: false,
            count: 3,
            seconds: 60,
        };
        let key = "2";
        assert!(!tt.allow(&t, key, 1000));
        assert!(!tt.allow(&t, key, 1001));
        assert!(tt.allow(&t, key, 1002), "第 3 条触发");
        assert!(!tt.allow(&t, key, 1003), "触发后冷却");
        // 冷却过后重新从 1 累计到 count
        assert!(!tt.allow(&t, key, 1063));
        assert!(!tt.allow(&t, key, 1064));
        assert!(tt.allow(&t, key, 1065), "重新凑满 count 触发");
    }

    #[test]
    fn threshold_window_slide() {
        let mut tt = ThresholdTracker::default();
        let t = Threshold {
            kind: ThresholdKind::Both,
            by_src: false,
            count: 2,
            seconds: 10,
        };
        assert!(!tt.allow(&t, "3", 1000));
        // 第二条在窗口外 → 第一条已滑出，此时是窗口内第 1 条
        assert!(!tt.allow(&t, "3", 1011));
        assert!(tt.allow(&t, "3", 1012));
    }
}
