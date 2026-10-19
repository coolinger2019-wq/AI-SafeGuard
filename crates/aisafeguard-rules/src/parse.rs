//! 单条规则解析（v1 子集）。白名单外的关键字/动作/修饰符 → 拒绝。
//!
//! 语法入口：`parse_rule(line)`。规则必须单行：
//! `alert tcp $EXTERNAL_NET any -> $HOME_NET 8081 (msg:".."; content:".."; nocase; sid:1; rev:1;)`

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::ir::{
    Addr, AddrItem, AddrSpec, ContentMatch, Direction, Flow, PortRange, PortSpec, Proto, Rule,
    Threshold, ThresholdKind,
};
use crate::severity_for_classtype;

/// 单条 content 的字节上限（子集规范 F5）。
pub const MAX_CONTENT_BYTES: usize = 512;
/// msg 上限：进事件证据，与 content 同量级的治理口径。
const MAX_MSG_CHARS: usize = 512;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct RuleError(pub String);

type Result<T> = std::result::Result<T, RuleError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(RuleError(msg.into()))
}

/// 解析一条规则。行首尾空白不敏感；`#` 注释行与空行由 loader 处理。
pub fn parse_rule(line: &str) -> Result<Rule> {
    let line = line.trim();
    let Some(open) = line.find('(') else {
        return err("缺少选项括号");
    };
    let header = line[..open].trim();
    let tail = line[open + 1..].trim_end();
    let Some(opts_raw) = tail.strip_suffix(')') else {
        return err("选项括号未闭合");
    };

    let mut hp = header.split_whitespace();
    let toks: Vec<&str> = hp.by_ref().collect();
    if toks.len() != 7 {
        return err(format!(
            "规则头应为 7 段（动作 协议 源地址 源端口 方向 目标地址 目标端口），实际 {} 段",
            toks.len()
        ));
    }
    if toks[0] != "alert" {
        return err(format!(
            "不支持的动作 `{}`（子集仅 alert，处置归执行器）",
            toks[0]
        ));
    }
    let proto = match toks[1] {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => return err(format!("不支持的协议 `{other}`（子集仅 tcp/udp）")),
    };
    let direction = match toks[4] {
        "->" => Direction::Uni,
        "<>" => Direction::Bi,
        other => return err(format!("不支持的方向 `{other}`")),
    };
    let src = parse_addr(toks[2])?;
    let src_port = parse_port(toks[3])?;
    let dst = parse_addr(toks[5])?;
    let dst_port = parse_port(toks[6])?;

    let mut msg: Option<String> = None;
    let mut sid: Option<u32> = None;
    let mut rev: u32 = 0;
    let mut classtype: Option<String> = None;
    let mut metadata: Vec<String> = Vec::new();
    let mut flow = Flow::default();
    let mut contents: Vec<ContentMatch> = Vec::new();
    let mut pcre: Vec<crate::ir::PcreMatch> = Vec::new();
    let mut threshold: Option<Threshold> = None;
    // 修饰符目标：最近一条 content 的下标；content 后可连续跟修饰符，
    // 一旦出现其他关键字即置 None——修饰符脱离 content 立即报错。
    let mut cur_content: Option<usize> = None;
    // F780 粘性缓冲区：buffer 关键字设置；对其后所有 content/pcre 生效（直至
    // 下一个 buffer 关键字）；同时也回溯修饰紧邻的前一条 content（修饰符形态
    // content:"X"; http_uri; 两种写法等价支持）
    let mut cur_buf = crate::ir::ContentBuf::Raw;

    for opt in split_options(opts_raw)?.into_iter() {
        let (kw, val) = match opt.split_once(':') {
            // content/pcre/msg 的引号内可能含冒号，split_once 取首个冒号即关键字边界
            Some((k, v)) => (k.trim(), v.trim()),
            None => (opt.trim(), ""),
        };
        // 修饰符分支之外的任何关键字都会使后续修饰符失去挂接目标
        let is_modifier = matches!(kw, "nocase" | "offset" | "depth" | "distance" | "within");
        if is_modifier && cur_content.is_none() {
            return err(format!("修饰符 `{kw}` 必须紧跟在 content 之后"));
        }
        match kw {
            "msg" => {
                let raw = unquote(val, "msg")?;
                let s = unescape(raw).ok_or_else(|| RuleError("msg 含非法转义".into()))?;
                if s.chars().count() > MAX_MSG_CHARS {
                    return err(format!("msg 超过 {MAX_MSG_CHARS} 字符上限"));
                }
                msg = Some(s);
            }
            "sid" => {
                let n: u32 = val
                    .parse()
                    .map_err(|_| RuleError(format!("sid 非法：`{val}`")))?;
                if n == 0 {
                    return err("sid 不能为 0");
                }
                sid = Some(n);
            }
            "rev" => {
                rev = val
                    .parse()
                    .map_err(|_| RuleError(format!("rev 非法：`{val}`")))?;
            }
            "classtype" => {
                let ct = unquote(val, "classtype").unwrap_or(val);
                if severity_for_classtype(ct).is_none() {
                    return err(format!("classtype `{ct}` 不在子集白名单内"));
                }
                classtype = Some(ct.to_string());
            }
            "metadata" => {
                for part in val.split(',') {
                    let part = part.trim();
                    if !part.is_empty() {
                        metadata.push(part.to_string());
                    }
                }
            }
            "flow" => {
                for part in val.split(',') {
                    match part.trim() {
                        "established" => flow.established = true,
                        "to_server" => flow.to_server = true,
                        "from_server" => flow.from_server = true,
                        other => return err(format!("不支持的 flow 选项 `{other}`")),
                    }
                }
                if flow.to_server && flow.from_server {
                    return err("flow 同时要求 to_server 与 from_server");
                }
            }
            "content" => {
                let raw = unquote(val, "content")?;
                let bytes = parse_content(raw)?;
                if bytes.is_empty() {
                    return err("content 不能为空");
                }
                if bytes.len() > MAX_CONTENT_BYTES {
                    return err(format!("content 超过 {MAX_CONTENT_BYTES} 字节上限"));
                }
                contents.push(ContentMatch {
                    bytes,
                    nocase: false,
                    offset: None,
                    depth: None,
                    distance: None,
                    within: None,
                    buf: cur_buf,
                });
                cur_content = Some(contents.len() - 1);
            }
            "nocase" => {
                contents[cur_content.expect("上方已检查")].nocase = true;
            }
            "offset" => {
                contents[cur_content.expect("上方已检查")].offset = Some(parse_u32(val, "offset")?)
            }
            "depth" => {
                contents[cur_content.expect("上方已检查")].depth = Some(parse_u32(val, "depth")?)
            }
            "distance" => {
                contents[cur_content.expect("上方已检查")].distance =
                    Some(parse_u32(val, "distance")?)
            }
            "within" => {
                contents[cur_content.expect("上方已检查")].within = Some(parse_u32(val, "within")?)
            }
            kw if crate::ir::buffer_for_kw(kw).is_some() => {
                // F780：修饰符形态回溯紧邻 content（未指定时）；粘性对后续生效
                let b = crate::ir::buffer_for_kw(kw).expect("已判");
                if let Some(i) = cur_content
                    && contents[i].buf == crate::ir::ContentBuf::Raw
                {
                    contents[i].buf = b;
                }
                cur_buf = b;
            }
            "pcre" => {
                let body = unquote(val, "pcre").unwrap_or(val);
                let mut pm = parse_pcre(body)?;
                // 粘性只在 pcre 自身未带缓冲区标志时生效（/U 等自带优先）
                if pm.buf == crate::ir::ContentBuf::Raw {
                    pm.buf = cur_buf;
                }
                pcre.push(pm);
            }
            "threshold" => threshold = Some(parse_threshold(val)?),
            other => {
                return err(format!(
                    "不支持的关键字 `{other}`（超出子集规范 v1 白名单）"
                ));
            }
        }
        if !is_modifier {
            // content 分支已在内部重置 cur_content；这里只清「非 content 非修饰符」的目标
            if kw != "content" {
                cur_content = None;
            }
        }
    }

    let Some(msg) = msg else {
        return err("缺少必填的 msg");
    };
    let Some(sid) = sid else {
        return err("缺少必填的 sid");
    };
    if contents.is_empty() && pcre.is_empty() {
        return err(
            "规则缺少匹配条件（content/pcre 至少其一）——纯头部规则会匹配窗口内全部流量，拒绝加载",
        );
    }

    Ok(Rule {
        proto,
        src,
        src_port,
        direction,
        dst,
        dst_port,
        flow,
        msg,
        sid,
        rev,
        classtype,
        metadata,
        contents,
        pcre,
        threshold,
    })
}

fn parse_u32(val: &str, name: &str) -> Result<u32> {
    val.parse()
        .map_err(|_| RuleError(format!("{name} 需为非负整数，实际 `{val}`")))
}

/// 顶层按 `;` 切分选项，引号内的 `;` 不切分（content/msg/pcre 的引号值）。
fn split_options(opts: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = opts.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes && c == '\\' {
            cur.push(c);
            if let Some(&n) = chars.peek() {
                cur.push(n);
                chars.next();
            }
            continue;
        }
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ';' => {
                if in_quotes {
                    cur.push(c);
                } else {
                    out.push(cur.trim().to_string());
                    cur.clear();
                }
            }
            _ => cur.push(c),
        }
    }
    if in_quotes {
        return err("引号未闭合");
    }
    let tail = cur.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    Ok(out.into_iter().filter(|s| !s.is_empty()).collect())
}

/// 去掉成对引号。
fn unquote<'a>(val: &'a str, name: &str) -> Result<&'a str> {
    let val = val.trim();
    if val.len() < 2 || !val.starts_with('"') || !val.ends_with('"') {
        return err(format!("{name} 的值必须用双引号包裹"));
    }
    Ok(&val[1..val.len() - 1])
}

/// 反转义 `\"` `\\` `\;`，其他转义拒绝（严格子集）。
fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            ';' => out.push(';'),
            _ => return None,
        }
    }
    Some(out)
}

/// content 体解析：`|hex|` 段 + 转义 + 普通字符（UTF-8 原样保留字节）。
fn parse_content(raw: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('"') => out.push(b'"'),
                Some('\\') => out.push(b'\\'),
                Some(';') => out.push(b';'),
                other => {
                    return err(format!(
                        "content 含非法转义 `\\{}`",
                        other.map(|c| c.to_string()).unwrap_or_default()
                    ));
                }
            },
            '|' => {
                let mut hex = String::new();
                loop {
                    match chars.next() {
                        Some('|') => break,
                        Some(h) if h.is_ascii_hexdigit() || h == ' ' => hex.push(h),
                        Some(other) => {
                            return err(format!("content 的 hex 段含非法字符 `{other}`"));
                        }
                        None => return err("content 的 hex 段未闭合"),
                    }
                }
                let digits: Vec<char> = hex.chars().filter(|c| *c != ' ').collect();
                if !digits.len().is_multiple_of(2) {
                    return err("content 的 hex 段位数不是偶数");
                }
                for pair in digits.chunks(2) {
                    let byte = u8::from_str_radix(&pair.iter().collect::<String>(), 16)
                        .map_err(|_| RuleError("content 的 hex 段非法".into()))?;
                    out.push(byte);
                }
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    Ok(out)
}

/// pcre 体解析：`/pattern/flags`，标志白名单 i / R；用 rust regex 编译（线性时间，
/// 免疫灾难回溯；编译大小由 size_limit 限制）。
fn parse_pcre(body: &str) -> Result<crate::ir::PcreMatch> {
    let body = body.trim();
    let Some(rest) = body.strip_prefix('/') else {
        return err(format!("pcre 体必须以 / 开头：`{body}`"));
    };
    let Some(close) = rest.rfind('/') else {
        return err("pcre 缺少收尾 /");
    };
    let (pattern, flags) = (&rest[..close], &rest[close + 1..]);
    let mut case_insensitive = false;
    let mut relative = false;
    let mut buf = crate::ir::ContentBuf::Raw;
    for f in flags.chars() {
        match f {
            'i' => case_insensitive = true,
            'R' => relative = true,
            // F780 v2：pcre 缓冲区快捷标志（Suricata 语义，映射到粘性格子）
            'U' => buf = crate::ir::ContentBuf::Uri,
            'I' => {
                buf = crate::ir::ContentBuf::Uri;
                case_insensitive = true;
            }
            'P' => buf = crate::ir::ContentBuf::ClientBody,
            'H' => buf = crate::ir::ContentBuf::Header, // Hm/Hmi 的 m/ci 由 i 分支处理
            'm' => {} // multiline（rust regex 默认按行 ^/$ 已兼容常见用法）
            other => {
                return err(format!(
                    "不支持的 pcre 标志 `{other}`（子集仅 i / R / U / I / P / H）"
                ));
            }
        }
    }
    // PCRE 的 `\/` 在 rust regex 里是非法转义：按 PCRE 语义还原为字面 `/`
    let mut normalized = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('/') => normalized.push('/'),
                Some(n) => {
                    normalized.push('\\');
                    normalized.push(n);
                }
                None => normalized.push('\\'),
            }
        } else {
            normalized.push(c);
        }
    }
    let re = regex::RegexBuilder::new(&normalized)
        .case_insensitive(case_insensitive)
        .size_limit(4096)
        .build()
        .map_err(|e| RuleError(format!("pcre 无法编译（越界或超大小上限）：{e}")))?;
    Ok(crate::ir::PcreMatch { re, relative, buf })
}

/// threshold 子集：`type limit|both, track by_src, count N, seconds S`。
fn parse_threshold(val: &str) -> Result<Threshold> {
    let mut kind: Option<ThresholdKind> = None;
    let mut by_src = false;
    let mut count: Option<u32> = None;
    let mut seconds: Option<i64> = None;
    for part in val.split(',') {
        let part = part.trim();
        let Some((k, v)) = part.split_once(char::is_whitespace) else {
            return err(format!("threshold 段缺少值：`{part}`"));
        };
        let v = v.trim();
        match k {
            "type" => match v {
                "limit" => kind = Some(ThresholdKind::Limit),
                "both" => kind = Some(ThresholdKind::Both),
                other => {
                    return err(format!(
                        "不支持的 threshold 类型 `{other}`（子集仅 limit/both）"
                    ));
                }
            },
            "track" => match v {
                "by_src" => by_src = true,
                other => {
                    return err(format!(
                        "不支持的 threshold track `{other}`（子集仅 by_src）"
                    ));
                }
            },
            "count" => count = Some(parse_u32(v, "threshold count")?),
            "seconds" => {
                seconds = Some(
                    v.parse()
                        .map_err(|_| RuleError("threshold seconds 非法".into()))?,
                )
            }
            other => return err(format!("不支持的 threshold 字段 `{other}`")),
        }
    }
    let count = count.ok_or_else(|| RuleError("threshold 缺少 count".into()))?;
    let seconds = seconds.ok_or_else(|| RuleError("threshold 缺少 seconds".into()))?;
    if count == 0 {
        return err("threshold count 不能为 0");
    }
    if seconds <= 0 {
        return err("threshold seconds 必须为正");
    }
    let kind = kind.ok_or_else(|| RuleError("threshold 缺少 type".into()))?;
    Ok(Threshold {
        kind,
        by_src,
        count,
        seconds,
    })
}

/// 地址规格：any / $HOME_NET / $EXTERNAL_NET / [列表] / 单 IP·CIDR（可 ! 否定）。
fn parse_addr(tok: &str) -> Result<AddrSpec> {
    if tok == "any" {
        return Ok(AddrSpec::Any);
    }
    match tok {
        "$HOME_NET" => return Ok(AddrSpec::HomeNet),
        "$EXTERNAL_NET" => return Ok(AddrSpec::ExternalNet),
        t if t.starts_with('$') => {
            return err(format!(
                "自定义地址变量 `{t}` 不支持（子集仅内置 $HOME_NET/$EXTERNAL_NET）"
            ));
        }
        _ => {}
    }
    if let Some(inner) = tok.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        let mut items = Vec::new();
        for part in inner.split(',') {
            items.push(parse_addr_item(part.trim())?);
        }
        if items.is_empty() {
            return err("地址列表为空");
        }
        return Ok(AddrSpec::List(items));
    }
    Ok(AddrSpec::List(vec![parse_addr_item(tok)?]))
}

fn parse_addr_item(tok: &str) -> Result<AddrItem> {
    let (neg, tok) = match tok.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, tok),
    };
    if tok == "any" {
        return err("地址列表内不支持 any");
    }
    match tok {
        "$HOME_NET" => return err("地址列表内不支持变量（子集范围）"),
        "$EXTERNAL_NET" => return err("地址列表内不支持变量（子集范围）"),
        t if t.starts_with('$') => {
            return err(format!(
                "自定义地址变量 `{t}` 不支持（子集仅内置 $HOME_NET/$EXTERNAL_NET）"
            ));
        }
        _ => {}
    }
    Ok(AddrItem {
        neg,
        addr: parse_ip_or_cidr(tok)?,
    })
}

fn parse_ip_or_cidr(tok: &str) -> Result<Addr> {
    match tok.split_once('/') {
        None => {
            let ip: IpAddr = tok
                .parse()
                .map_err(|_| RuleError(format!("非法地址 `{tok}`")))?;
            Ok(Addr::Ip(ip))
        }
        Some((base, prefix)) => {
            let base: IpAddr = base
                .parse()
                .map_err(|_| RuleError(format!("非法 CIDR 基址 `{tok}`")))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| RuleError(format!("非法 CIDR 前缀 `{tok}`")))?;
            let max = match base {
                IpAddr::V4(Ipv4Addr { .. }) => 32,
                IpAddr::V6(Ipv6Addr { .. }) => 128,
            };
            if prefix > max {
                return err(format!("CIDR 前缀超界：`{tok}`（该族最大 /{max}）"));
            }
            Ok(Addr::Cidr { base, prefix })
        }
    }
}

/// 端口规格：any / 单端口 / a:b 范围 / [列表]（各项可带 ! 与范围）。
fn parse_port(tok: &str) -> Result<PortSpec> {
    if tok == "any" {
        return Ok(PortSpec::any());
    }
    if let Some(inner) = tok.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        let mut ranges = Vec::new();
        for part in inner.split(',') {
            ranges.push(parse_port_item(part.trim())?);
        }
        if ranges.is_empty() {
            return err("端口列表为空");
        }
        return Ok(PortSpec { ranges });
    }
    Ok(PortSpec {
        ranges: vec![parse_port_item(tok)?],
    })
}

fn parse_port_item(tok: &str) -> Result<PortRange> {
    let (neg, tok) = match tok.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, tok),
    };
    let (lo, hi) = match tok.split_once(':') {
        None => {
            let p: u16 = tok
                .parse()
                .map_err(|_| RuleError(format!("非法端口 `{tok}`")))?;
            (p, p)
        }
        Some((a, b)) => {
            let lo = if a.is_empty() {
                0
            } else {
                a.parse()
                    .map_err(|_| RuleError(format!("非法端口 `{a}`")))?
            };
            let hi = if b.is_empty() {
                u16::MAX
            } else {
                b.parse()
                    .map_err(|_| RuleError(format!("非法端口 `{b}`")))?
            };
            if lo > hi {
                return err(format!("端口范围上下界颠倒：`{tok}`"));
            }
            (lo, hi)
        }
    };
    Ok(PortRange { lo, hi, neg })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(line: &str) -> Rule {
        parse_rule(line).unwrap_or_else(|e| panic!("应解析成功: {e} — {line}"))
    }

    fn parse_err(line: &str) -> String {
        parse_rule(line).expect_err("应解析失败").to_string()
    }

    #[test]
    fn full_featured_rule_parses() {
        let r = parse_ok(
            r#"alert tcp $EXTERNAL_NET any -> $HOME_NET 8081 (msg:"Web 扫描器探测"; content:"GET /"; offset:0; depth:8; nocase; content:"sqlmap|3b|"; distance:0; within:512; pcre:"/User-Agent\x3a[^\r\n]*sqlmap/i"; flow:established,to_server; threshold:type limit, track by_src, count 1, seconds 60; metadata:category scanner; classtype:web-application-attack; sid:1000001; rev:2;)"#,
        );
        assert_eq!(r.proto, Proto::Tcp);
        assert_eq!(r.src, AddrSpec::ExternalNet);
        assert_eq!(r.dst, AddrSpec::HomeNet);
        assert_eq!(r.dst_port.ranges[0].lo, 8081);
        assert_eq!(r.direction, Direction::Uni);
        assert!(r.flow.established && r.flow.to_server);
        assert_eq!(r.msg, "Web 扫描器探测");
        assert_eq!(r.sid, 1_000_001);
        assert_eq!(r.rev, 2);
        assert_eq!(r.classtype.as_deref(), Some("web-application-attack"));
        assert_eq!(r.metadata, ["category scanner"]);
        assert_eq!(r.contents.len(), 2);
        assert_eq!(r.contents[0].bytes, b"GET /");
        assert!(r.contents[0].nocase);
        assert_eq!(r.contents[0].depth, Some(8));
        assert_eq!(r.contents[1].bytes, b"sqlmap;");
        assert_eq!(r.contents[1].within, Some(512));
        assert_eq!(r.pcre.len(), 1);
        assert!(r.threshold.is_some());
        assert_eq!(r.rule_id(), "sid:1000001");
    }

    #[test]
    fn hex_and_escapes_in_content() {
        let r = parse_ok(
            r#"alert tcp any any -> any any (msg:"t"; content:"A|41 42|C\"d\\e\;f"; sid:7;)"#,
        );
        // |41 42| → "AB"，两侧 A/C 是字面量；转义 " \ ; 原样
        assert_eq!(r.contents[0].bytes, b"AABC\"d\\e;f");
    }

    #[test]
    fn bidirectional_and_port_forms() {
        let r = parse_ok(
            r#"alert tcp any [1:1024,!80] <> [!192.0.2.0/24] !443 (msg:"t"; content:"x"; sid:8;)"#,
        );
        assert_eq!(r.direction, Direction::Bi);
        assert!(!r.src_port.matches(80));
        assert!(r.src_port.matches(81));
        assert!(r.src_port.matches(1));
        assert!(!r.dst_port.matches(443));
        assert!(r.dst_port.matches(8080));
    }

    #[test]
    fn reject_superset_keywords_and_actions() {
        assert!(
            parse_err(r#"drop tcp any any -> any any (msg:"t"; content:"x"; sid:1;)"#)
                .contains("不支持的动作")
        );
        assert!(
            parse_err(r#"alert icmp any any -> any any (msg:"t"; content:"x"; sid:1;)"#)
                .contains("不支持的协议")
        );
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; flowbits:set,x; sid:1;)"#)
                .contains("不支持的关键字")
        );
        assert!(
            parse_err(r#"alert http any any -> any any (msg:"t"; sid:1;)"#)
                .contains("不支持的协议")
        );
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; http.uri; content:"x"; sid:1;)"#)
                .contains("不支持的关键字")
        );
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x"; isdataat:4; sid:1;)"#)
                .contains("不支持的关键字")
        );
        assert!(parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x"; byte_test:4,>,100,0,relative; sid:1;)"#).contains("不支持的关键字"));
    }

    #[test]
    fn reject_missing_required_and_sanity() {
        // 缺 msg
        assert!(parse_err(r#"alert tcp any any -> any any (content:"x"; sid:1;)"#).contains("msg"));
        // 缺 sid
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x";)"#).contains("sid")
        );
        // sid=0
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x"; sid:0;)"#)
                .contains("sid")
        );
        // 无匹配条件
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; sid:1;)"#).contains("匹配条件")
        );
        // 引号未闭合
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t; content:"x"; sid:1;)"#)
                .contains("引号")
        );
    }

    #[test]
    fn reject_modifier_not_after_content() {
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; nocase; content:"x"; sid:1;)"#)
                .contains("紧跟")
        );
        // 修饰符隔着其他选项
        assert!(
            parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x"; sid:5; offset:2;)"#)
                .contains("紧跟")
        );
    }

    #[test]
    fn reject_bad_classtype_and_pcre_flags() {
        assert!(
            parse_err(
                r#"alert tcp any any -> any any (msg:"t"; content:"x"; classtype:kernel; sid:1;)"#
            )
            .contains("白名单")
        );
        assert!(
            parse_err(
                r#"alert tcp any any -> any any (msg:"t"; content:"x"; pcre:"/x/Q"; sid:1;)"#
            )
            .contains("pcre 标志")
        );
        // F780 v2：/U 映射 uri 格（合法）
        let p = parse_rule(
            r#"alert tcp any any -> any any (msg:"t"; content:"x"; pcre:"/x/U"; sid:2;)"#,
        )
        .unwrap();
        assert_eq!(p.pcre[0].buf, crate::ir::ContentBuf::Uri);
    }

    #[test]
    fn reject_backreference_pcre() {
        // 回溯引用：PCRE 支持、rust regex 不支持 → 编译失败 → 拒绝（防可疑正则）
        assert!(
            parse_err(
                r#"alert tcp any any -> any any (msg:"t"; content:"x"; pcre:"/(a)\1/"; sid:1;)"#
            )
            .contains("pcre 无法编译")
        );
    }

    #[test]
    fn reject_custom_vars_and_bad_addresses() {
        assert!(
            parse_err(r#"alert tcp $MY_NET any -> any any (msg:"t"; content:"x"; sid:1;)"#)
                .contains("自定义地址变量")
        );
        assert!(
            parse_err(r#"alert tcp any any -> 10.0.0.0/33 any (msg:"t"; content:"x"; sid:1;)"#)
                .contains("前缀超界")
        );
        assert!(
            parse_err(r#"alert tcp any any -> any 99999 (msg:"t"; content:"x"; sid:1;)"#)
                .contains("非法端口")
        );
    }

    #[test]
    fn content_over_limit_rejected() {
        let big = "a".repeat(513);
        assert!(
            parse_err(&format!(
                r#"alert tcp any any -> any any (msg:"t"; content:"{big}"; sid:1;)"#
            ))
            .contains("上限")
        );
    }

    #[test]
    fn pcre_relative_and_case_flags_parse() {
        let r = parse_ok(
            r#"alert tcp any any -> any any (msg:"t"; content:"x"; pcre:/abc/i; pcre:"/def/R"; sid:9;)"#,
        );
        assert!(!r.pcre[0].relative);
        assert!(r.pcre[1].relative);
        // \/ 还原为字面 /
        let r = parse_ok(
            r#"alert tcp any any -> any any (msg:"t"; content:"x"; pcre:"/a\/b/"; sid:10;)"#,
        );
        assert!(r.pcre[0].re.is_match("a/b"));
    }

    #[test]
    fn threshold_validation() {
        assert!(parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x"; threshold:type rate, track by_src, count 1, seconds 60; sid:1;)"#).contains("threshold 类型"));
        assert!(parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x"; threshold:type limit, track by_dst, count 1, seconds 60; sid:1;)"#).contains("track"));
        assert!(parse_err(r#"alert tcp any any -> any any (msg:"t"; content:"x"; threshold:type limit, track by_src, count 0, seconds 60; sid:1;)"#).contains("count"));
        let r = parse_ok(
            r#"alert tcp any any -> any any (msg:"t"; content:"x"; threshold: type both, track by_src, count 5, seconds 30; sid:1;)"#,
        );
        let t = r.threshold.unwrap();
        assert_eq!(t.kind, ThresholdKind::Both);
        assert!(t.by_src);
        assert_eq!((t.count, t.seconds), (5, 30));
    }

    #[test]
    fn trailing_semicolon_and_whitespace_tolerated() {
        let r =
            parse_ok("  alert tcp any any -> any any ( msg:\"t\" ; content:\"x\" ; sid:11 ; )  ");
        assert_eq!(r.sid, 11);
    }
}
