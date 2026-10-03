//! L7 解析与指纹基座（0.5.0 Batch E，设计见 docs/ROADMAP-0.5.md Batch E）。
//!
//! 蜜罐与采样捕获 full 模式**共用**的 HTTP 解析：同一输入产出同一 `HttpHint`。
//! 职责单一：只解析、只产结构化字段与标签——不做封禁、不依赖 firewall
//! （crate 依赖图禁止，见 ROADMAP-0.5 风险清单 #3）。
//!
//! 纪律：解析失败返回 None/空，绝不 panic（模糊测试钉住）；所有输出经清洗
//! （控制字符处理、长度上限）；调用方仍按不可信输入对待。

/// HttpHint schema 版本（0.5.0 E2）：字段只增不改义；新增字段走 schema_version bump。
/// v2（0.5.6 F13）：新增 `tags`——标签并入提示对象，蜜罐/采样共用同一套字段。
pub const HINT_SCHEMA_VERSION: u8 = 2;

/// 结构化 HTTP 提示（蜜罐/采样 full 模式两入口共用）。
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HttpHint {
    /// schema 版本（当前 2）
    pub schema_version: u8,
    /// 请求方法（白名单内）
    pub method: String,
    /// path 前缀（去查询串与片段，≤128 字符）
    pub path: String,
    /// Host 头（若有）
    pub host: Option<String>,
    /// User-Agent（若有，截断）
    pub user_agent: Option<String>,
    /// 可疑 UA 关键字命中（克制名单）
    pub ua_suspect: Vec<String>,
    /// 标签（v2）：`http:GET` / `path:/x/y` / `ua-suspect:sqlmap` 等，
    /// 与 `http_tags()` 输出同源（避免两套字段）；调用方可按场景追加自有标签
    pub tags: Vec<String>,
}

/// 可疑 UA 关键字（明确扫描器/攻击工具，克制名单——普通浏览器与 wget/curl 不在列，
/// 避免把运维脚本当攻击者）。小写包含匹配。
pub const SUSPECT_UA: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "dirbuster",
    "gobuster",
    "acunetix",
    "wpscan",
    "havij",
];

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

const MAX_PATH: usize = 128;
const MAX_HEADER_VALUE: usize = 256;

/// 从明文 HTTP 请求解析 HttpHint。非 HTTP / 畸形输入返回 None。
pub fn parse_http_hint(text: &str) -> Option<HttpHint> {
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let raw_path = parts.next()?;
    if !METHODS.contains(&method) {
        return None;
    }
    let method = clean(method, 16);
    let path = clean(raw_path.split(['?', '#']).next().unwrap_or(""), MAX_PATH);
    let mut host = None;
    let mut user_agent = None;
    let mut ua_suspect = Vec::new();
    for line in text.lines().skip(1) {
        if line.len() > 1024 {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = clean(v.trim(), MAX_HEADER_VALUE);
        if v.is_empty() {
            continue;
        }
        let key = k.trim();
        if key.eq_ignore_ascii_case("host") && host.is_none() {
            host = Some(v);
        } else if key.eq_ignore_ascii_case("user-agent") && user_agent.is_none() {
            let lower = v.to_ascii_lowercase();
            for kw in SUSPECT_UA {
                if lower.contains(kw) {
                    ua_suspect.push((*kw).to_string());
                    break;
                }
            }
            user_agent = Some(v);
        }
    }
    Some(HttpHint {
        schema_version: HINT_SCHEMA_VERSION,
        method: method.clone(),
        path: path.clone(),
        host,
        user_agent,
        ua_suspect: ua_suspect.clone(),
        tags: hint_tags(&method, &path, &ua_suspect),
    })
}

/// 由已解析字段拼装标签（http_tags 的单一来源，v2 起随 HttpHint 一起返回）
fn hint_tags(method: &str, path: &str, ua_suspect: &[String]) -> Vec<String> {
    let mut tags = vec![format!("http:{method}")];
    // 0.4 文案：path 标签取前 2 段前缀（HttpHint.path 是完整路径，两者用途不同）
    if !path.is_empty() {
        let prefix: String = path
            .split('/')
            .filter(|s| !s.is_empty())
            .take(2)
            .map(|s| format!("/{s}"))
            .collect();
        if !prefix.is_empty() {
            tags.push(format!("path:{prefix}"));
        }
    }
    for kw in ua_suspect {
        tags.push(format!("ua-suspect:{kw}"));
    }
    tags
}

/// 兼容 0.4 文案的标签形式（E3）：`http:GET` / `path:/x/y` / `ua-suspect:sqlmap`。
/// 非 HTTP / 畸形输入返回空。v2 起与 HttpHint.tags 同源（委托解析结果）。
pub fn http_tags(text: &str) -> Vec<String> {
    parse_http_hint(text).map(|h| h.tags).unwrap_or_default()
}

/// 标签序列化为摘要后缀（` [L7 a b c]`；空标签返回空串）。
pub fn tags_suffix(tags: &[String]) -> String {
    if tags.is_empty() {
        return String::new();
    }
    format!(" [L7 {}]", tags.join(" "))
}

/// 攻击者输入永远当不可信数据：lossy UTF-8、去控制字符（C0+C1+DEL）、截断。
pub fn sanitize(bytes: &[u8], max_chars: usize) -> String {
    let lossy = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(lossy.len().min(max_chars * 2));
    for c in lossy.chars().take(max_chars) {
        match c {
            '\n' | '\t' => out.push(c),
            '\r' => {}
            // is_control 覆盖 C0 (U+0000-1F)、C1 (U+0080-9F)、DEL——
            // C1 常由多字节 UTF-8 序列产生，手写 (c as u32) < 0x20 会漏掉
            c if c.is_control() => out.push('·'),
            c => out.push(c),
        }
    }
    out
}

/// 单行摘要（首行，截断 160 字符）。
pub fn first_line(text: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.chars().take(160).collect())
    }
}

/// 摘要 = 首行（无内容用 fallback）。
pub fn request_summary(text: &str, fallback: &str) -> String {
    first_line(text).unwrap_or_else(|| fallback.to_string())
}

/// HTTP 头部是否已完整收到（\r\n\r\n）或超出上限——供读循环与模糊测试共用。
pub fn http_request_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 8192
}

// ---------- E4：JA3（TLS ClientHello 指纹，算法见 ja3 项目公开定义） ----------

/// JA3 结果：raw = "版本,密码套件,扩展,椭圆曲线,点格式"（逗号分隔、列表内连字符），
/// md5 = raw 的 MD5 hex（小写）。
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Ja3 {
    pub raw: String,
    pub md5: String,
}

fn be16(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(off)?, *d.get(off + 1)?]))
}

fn be24(d: &[u8], off: usize) -> Option<u32> {
    Some(((*d.get(off)? as u32) << 16) | ((*d.get(off + 1)? as u32) << 8) | *d.get(off + 2)? as u32)
}

/// 从 TLS record 起始字节（一个 TCP 段的载荷起点）解析 ClientHello 并计算 JA3。
/// 数据不足 / 非 handshake record / 非 ClientHello → None（不阻断，调用方跳过）。
pub fn parse_ja3(data: &[u8]) -> Option<Ja3> {
    let ch = walk_client_hello(data)?;
    let ext_types: Vec<u16> = ch.extensions.iter().map(|(t, _)| *t).collect();
    let mut groups: Vec<u16> = Vec::new();
    let mut formats: Vec<u8> = Vec::new();
    for (etype, edata) in &ch.extensions {
        match *etype {
            0x000a => {
                // supported_groups: list_len(2) + 每项 2 字节
                if let Some(glen) = be16(edata, 0) {
                    let gend = (2 + glen as usize).min(edata.len());
                    let mut i = 2usize;
                    while i + 2 <= gend {
                        groups.push(u16::from_be_bytes([edata[i], edata[i + 1]]));
                        i += 2;
                    }
                }
            }
            0x000b => {
                // ec_point_formats: list_len(1) + 每项 1 字节
                if let Some(&flen) = edata.first() {
                    let fend = (1 + flen as usize).min(edata.len());
                    formats = edata[1..fend].to_vec();
                }
            }
            _ => {}
        }
    }
    let raw = format!(
        "{},{},{},{},{}",
        ch.legacy_version,
        ch.ciphers
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        ext_types
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    );
    use md5::Digest as _;
    let md5hex = {
        let d = md5::Md5::digest(raw.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    Some(Ja3 { raw, md5: md5hex })
}

/// TLS record 内的 ClientHello 原始字段（JA3/JA4 共用的解析底座）。
struct RawClientHello {
    /// ClientHello body 的 Protocol Version 字段（JA4 称 legacy version）
    legacy_version: u16,
    ciphers: Vec<u16>,
    /// (扩展类型, 原始数据)——按出现顺序
    extensions: Vec<(u16, Vec<u8>)>,
}

/// 从 TLS record 起始字节解析 ClientHello。
/// 语义与 JA3 基线一致：截断/畸形 → None，不 panic。
fn walk_client_hello(data: &[u8]) -> Option<RawClientHello> {
    // TLS record header: type(1)=0x16 handshake, version(2), length(2)
    if data.first() != Some(&0x16) {
        return None;
    }
    let rec_len = be16(data, 3)? as usize;
    let end = (5 + rec_len).min(data.len());
    let hs = &data[5..end];
    // handshake: type(1)=0x01 client_hello, length(3)
    if hs.first() != Some(&0x01) {
        return None;
    }
    let hs_len = be24(hs, 1)? as usize;
    let hs_end = (4 + hs_len).min(hs.len());
    let body = &hs[4..hs_end];
    let mut off = 0usize;
    let legacy_version = be16(body, off)?;
    off += 2;
    off += 32; // random
    // session_id
    let sid_len = *body.get(off)? as usize;
    off += 1 + sid_len;
    // cipher suites
    let cs_len = be16(body, off)? as usize;
    off += 2;
    if off + cs_len > body.len() || !cs_len.is_multiple_of(2) {
        return None;
    }
    let ciphers: Vec<u16> = (0..cs_len / 2)
        .map(|i| u16::from_be_bytes([body[off + i * 2], body[off + i * 2 + 1]]))
        .collect();
    off += cs_len;
    // compression methods
    let comp_len = *body.get(off)? as usize;
    off += 1 + comp_len;
    // extensions
    let mut extensions: Vec<(u16, Vec<u8>)> = Vec::new();
    if off + 2 <= body.len() {
        let ext_total = be16(body, off)? as usize;
        off += 2;
        let ext_end = (off + ext_total).min(body.len());
        while off + 4 <= ext_end {
            let etype = be16(body, off)?;
            let elen = be16(body, off + 2)? as usize;
            off += 4;
            let edata = body.get(off..(off + elen).min(body.len()))?;
            off += elen;
            extensions.push((etype, edata.to_vec()));
        }
    }
    Some(RawClientHello {
        legacy_version,
        ciphers,
        extensions,
    })
}

// ---------- E5：JA4（客户端指纹，算法对齐 FoxIO ja4 官方实现 python/ja4.py） ----------

/// JA4 指纹（客户端）：`t13d1516h2_8daaf6152771_b186095e22b6` 形式——
/// 三段下划线分隔：`协议+版本+SNI+套件数+扩展数+ALPN _ 套件哈希 _ 扩展哈希`，
/// 两段哈希为小写 SHA-256 截断 12 字符。
pub type Ja4 = String;

/// GREASE 判定（RFC 8701）：0x?A?A 模式；官方实现用 16 值表，同余式覆盖。
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

/// TLS 版本 → JA4 两字符（官方 TLS_MAPPER）：TLS1.2 是 "12"（不是并入 "13"）。
fn tls_version_str(v: u16) -> &'static str {
    match v {
        0x0002 => "s2",
        0x0300 => "s3",
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    }
}

/// sha256 前 12 字符（小写 hex）；空输入返回字面 0 串（官方 sha_encode 语义）。
fn sha12(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".into();
    }
    use sha2::Digest as _;
    let d = sha2::Sha256::digest(input.as_bytes());
    d.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .chars()
        .take(12)
        .collect()
}

/// 两字节列表扩展（supported_versions / signature_algorithms）→ u16 列表（去 GREASE）。
/// 线格式：list_len(2) + 每项 2 字节——跳过长度前缀取项。
fn ext_u16_list(edata: &[u8]) -> Vec<u16> {
    let Some(list_len) = be16(edata, 0) else {
        return Vec::new();
    };
    let end = (2 + list_len as usize).min(edata.len());
    let pairs: &[[u8; 2]] = edata[2..end].as_chunks::<2>().0;
    pairs
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .filter(|v| !is_grease(*v))
        .collect()
}

/// 计算 JA4。数据不足 / 非 ClientHello → None；supported_versions 存在但
/// 去 GREASE 后为空 → None（官方实现该情形异常跳过）。
pub fn parse_ja4(data: &[u8]) -> Option<Ja4> {
    let ch = walk_client_hello(data)?;

    // 版本：supported_versions(0x002b) 取最高（去 GREASE），否则用 legacy version
    let version = match ch.extensions.iter().find(|(t, _)| *t == 0x002b) {
        Some((_, d)) => {
            let mut vs = ext_u16_list(d);
            vs.sort_unstable();
            tls_version_str(*vs.last()?)
        }
        None => tls_version_str(ch.legacy_version),
    };
    // SNI：server_name(0x0000) 存在 → d（域名），否则 i（IP）
    let sni = if ch.extensions.iter().any(|(t, _)| *t == 0x0000) {
        "d"
    } else {
        "i"
    };
    // 套件：去 GREASE、4 位小写 hex、按字典序；计数封顶 99
    let mut ciphers: Vec<String> = ch
        .ciphers
        .iter()
        .filter(|c| !is_grease(**c))
        .map(|c| format!("{c:04x}"))
        .collect();
    let cipher_count = ciphers.len().min(99);
    ciphers.sort();
    let cipher_hash = sha12(&ciphers.join(","));
    // 扩展：去 GREASE，并剔除 SNI(0000) 与 ALPN(0010)——哈希对目标域名/ALPN 稳定
    let mut exts: Vec<String> = ch
        .extensions
        .iter()
        .filter(|(t, _)| !is_grease(*t) && *t != 0x0000 && *t != 0x0010)
        .map(|(t, _)| format!("{t:04x}"))
        .collect();
    let ext_count = ch
        .extensions
        .iter()
        .filter(|(t, _)| !is_grease(*t))
        .count()
        .min(99);
    exts.sort();
    let mut ext_input = exts.join(",");
    // 签名算法(0x000d)：原顺序、去 GREASE，加下划线缀在扩展列表后
    if let Some((_, d)) = ch.extensions.iter().find(|(t, _)| *t == 0x000d) {
        let sigs: Vec<String> = ext_u16_list(d).iter().map(|s| format!("{s:04x}")).collect();
        if !sigs.is_empty() {
            if !ext_input.is_empty() {
                ext_input.push('_');
            }
            ext_input.push_str(&sigs.join(","));
        }
    }
    let ext_hash = sha12(&ext_input);
    // ALPN：取第一个值；>2 字符取首尾字符；首字节非 ASCII → "99"；无 → "00"
    let alpn: String = match ch.extensions.iter().find(|(t, _)| *t == 0x0010) {
        Some((_, d)) => {
            // d = list_len(2) + [name_len(1) + name]*，取首项。
            // 畸形/空 ALPN 按官方 ja4.py 语义回退 "00"，不放弃整枚指纹
            //（否则攻击者发一个空 ALPN 扩展即可让本可算出的指纹消失）。
            let name = d
                .get(2)
                .map(|b| *b as usize)
                .filter(|n| 3 + n <= d.len())
                .and_then(|n| d.get(3..3 + n));
            match name {
                Some(name) if !name.is_empty() => {
                    let a: String = if name.len() > 2 {
                        [name[0], name[name.len() - 1]]
                            .iter()
                            .map(|b| *b as char)
                            .collect()
                    } else {
                        name.iter().map(|b| *b as char).collect()
                    };
                    if a.as_bytes()[0] > 127 {
                        "99".to_string()
                    } else {
                        a
                    }
                }
                _ => "00".to_string(),
            }
        }
        None => "00".to_string(),
    };

    Some(format!(
        "t{version}{sni}{cipher_count:02}{ext_count:02}{alpn}_{cipher_hash}_{ext_hash}"
    ))
}

fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_hint_extracts_all_fields() {
        let req = "GET /admin/config HTTP/1.1\r\nHost: x.test\r\nUser-Agent: sqlmap/1.7\r\n\r\n";
        let h = parse_http_hint(req).unwrap();
        assert_eq!(h.schema_version, 2);
        assert_eq!(h.method, "GET");
        assert_eq!(h.path, "/admin/config");
        assert_eq!(h.host.as_deref(), Some("x.test"));
        assert_eq!(h.user_agent.as_deref(), Some("sqlmap/1.7"));
        assert_eq!(h.ua_suspect, ["sqlmap"]);
        // v2：标签随提示对象一起返回（单一来源）
        assert_eq!(
            h.tags,
            ["http:GET", "path:/admin/config", "ua-suspect:sqlmap"]
        );
    }

    #[test]
    fn parse_http_hint_strips_query_and_caps_path() {
        let long = "/a/".to_string() + &"b".repeat(200);
        let req = format!("GET {long}?x=1 HTTP/1.1\r\n\r\n");
        let h = parse_http_hint(&req).unwrap();
        assert_eq!(h.path.len(), 128);
        assert!(!h.path.contains('?'));
    }

    #[test]
    fn parse_http_hint_non_http_or_malformed_is_none() {
        assert!(parse_http_hint("").is_none());
        assert!(parse_http_hint("SSH-2.0-x\r\n").is_none());
        assert!(parse_http_hint("\x01\x02\r\n\r\n").is_none());
        assert!(parse_http_hint("GET\r\n\r\n").is_none());
        assert!(
            parse_http_hint("GÉT / HTTP/1.1\r\n\r\n").is_none(),
            "非 ASCII 方法拒绝"
        );
    }

    #[test]
    fn http_tags_matches_04_output_format() {
        // E3：0.4 core::l7 的标签格式原样保留（旧文案可解释）
        let tags = http_tags("GET /admin/config HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n\r\n");
        assert_eq!(
            tags,
            ["http:GET", "path:/admin/config", "ua-suspect:sqlmap"]
        );
        let tags = http_tags("GET /a/b/c?x=1 HTTP/1.1\r\n\r\n");
        assert_eq!(tags, ["http:GET", "path:/a/b"]);
        assert!(http_tags("SSH-2.0-x\r\n").is_empty());
        assert!(http_tags("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n").len() == 1);
    }

    #[test]
    fn sanitize_strips_control_and_truncates() {
        let raw = b"GET /x HTTP/1.1\r\nHost: a\x01b";
        let s = sanitize(raw, 100);
        assert!(s.contains("GET /x HTTP/1.1"));
        assert!(!s.contains('\u{1}'));
        assert_eq!(sanitize(b"abcdef", 3), "abc");
    }

    #[test]
    fn http_request_complete_semantics() {
        assert!(http_request_complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
        assert!(!http_request_complete(b"GET / HTTP/1.1\r\n"));
        assert!(
            http_request_complete(&[0u8; 8192]),
            "超上限按完整处理（防堆积）"
        );
    }

    /// E4 已知向量：手工构造最小 ClientHello（version 771、单 cipher 47、
    /// 扩展 10(groups 29)/11(fmt 0)）→ raw 与 md5 精确断言。
    #[test]
    fn ja3_known_vector() {
        // ClientHello body
        let mut body = vec![0x03, 0x03]; // client_version TLS1.2 = 771
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id 空
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // ciphers: 1 个 = 47
        body.push(1);
        body.push(0); // compression: null
        // extensions: supported_groups(10) + ec_point_formats(11)
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]); // groups: [29]
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x03, 0x01, 0x00]); // formats: [0]
        let ext_total = (ext.len() as u16).to_be_bytes();
        body.extend_from_slice(&ext_total);
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        let hs_len = (body.len() as u32).to_be_bytes();
        hs.extend_from_slice(&hs_len[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let ja3 = parse_ja3(&rec).expect("合法 ClientHello 应解析成功");
        assert_eq!(ja3.raw, "771,47,10-11,29,0", "raw: {}", ja3.raw);
        // md5("771,47,10-11,29,0") 标准值（python hashlib 预计算）
        assert_eq!(ja3.md5, "a67dc37c8080882707748e4bba6cb513");
        assert_eq!(ja3.md5.len(), 32);
        // 同输入同输出
        assert_eq!(parse_ja3(&rec).unwrap(), ja3);
    }

    #[test]
    fn ja3_non_client_hello_is_none() {
        // TLS record 但 handshake type = 2 (ServerHello)
        let rec = [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
        assert!(parse_ja3(&rec).is_none());
        // 非 TLS
        assert!(parse_ja3(b"GET / HTTP/1.1").is_none());
        // 截断
        assert!(parse_ja3(&[0x16, 0x03]).is_none());
    }

    // ---------- E5：JA4 测试（算法对齐 FoxIO python/ja4.py，期望值 hashlib 预计算） ----------

    /// 测试用 ClientHello 构造器：record(0x16) + handshake(0x01) + body。
    fn build_client_hello(
        legacy_version: u16,
        ciphers: &[u16],
        exts: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut body = legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id 空
        body.extend_from_slice(&(ciphers.len() as u16 * 2).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.push(1);
        body.push(0); // compression: null
        let mut ext = Vec::new();
        for (etype, edata) in exts {
            ext.extend_from_slice(&etype.to_be_bytes());
            ext.extend_from_slice(&(edata.len() as u16).to_be_bytes());
            ext.extend_from_slice(edata);
        }
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        let hs_len = (body.len() as u32).to_be_bytes();
        hs.extend_from_slice(&hs_len[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// E5 已知向量 1：现代 TLS1.3 客户端——supported_versions 选 "13"、SNI→d、
    /// ALPN "h2"、GREASE（cipher 0x0a0a / 扩展 0x1a1a）被剔除、SNI/ALPN 不进
    /// 扩展哈希但计入扩展数（6）。期望值 = 官方算法 hashlib 预计算。
    #[test]
    fn ja4_known_vector_modern_client() {
        let sni = {
            let name = b"example.test";
            let mut d = vec![0x00, 0x0f]; // server_name_list 长度 = 3 + 12
            d.extend_from_slice(&[0x00, name.len() as u8]); // type=host_name + 长度
            d.extend_from_slice(name);
            d
        };
        let alpn = {
            let mut d = vec![0x00, 0x0e]; // 列表长 2 + (1+2) + (1+8)
            d.push(2);
            d.extend_from_slice(b"h2");
            d.push(8);
            d.extend_from_slice(b"http/1.1");
            d
        };
        let rec = build_client_hello(
            0x0303,
            &[0x1301, 0x0a0a, 0x1302, 0xc02f], // 0x0a0a 是 GREASE
            &[
                (0x0000, sni),
                (0x000a, vec![0x00, 0x02, 0x00, 0x1d]),
                (0x000b, vec![0x01, 0x00]),
                (0x000d, vec![0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01]),
                (0x0010, alpn),
                (0x002b, vec![0x00, 0x04, 0x03, 0x04, 0x03, 0x03]),
                (0x1a1a, vec![0x00]), // GREASE 扩展
            ],
        );
        let ja4 = parse_ja4(&rec).expect("应解析成功");
        assert_eq!(ja4, "t13d0306h2_40b44b994229_0d385148b956", "实际: {ja4}");
        // 同输入同输出
        assert_eq!(parse_ja4(&rec).unwrap(), ja4);
    }

    /// E5 已知向量 2：无 supported_versions（legacy 0x0303 → "12"）、无 SNI（i）、
    /// 无 ALPN（00）、SCSV 0x00ff 保留计数。无签名算法时扩展输入不带下划线段。
    #[test]
    fn ja4_known_vector_legacy_minimal() {
        let rec = build_client_hello(
            0x0303,
            &[0xc013, 0x00ff], // SCSV 保留（非 GREASE）
            &[
                (0x000a, vec![0x00, 0x02, 0x00, 0x1d]),
                (0x000b, vec![0x01, 0x00]),
                (0x000d, vec![0x00, 0x02, 0x04, 0x03]),
            ],
        );
        let ja4 = parse_ja4(&rec).expect("应解析成功");
        assert_eq!(ja4, "t12i020300_a0546e0689fc_2bbaf9536c97", "实际: {ja4}");
    }

    /// E5 差异语义：supported_versions 缺失时用 legacy version；未知版本 → "00"。
    #[test]
    fn ja4_version_fallback_and_unknown() {
        let exts = [(0x000a, vec![0x00, 0x02, 0x00, 0x1d])];
        // legacy 0x0304（无 supported_versions）→ "13"
        let rec = build_client_hello(0x0304, &[0x1301], &exts);
        let ja4 = parse_ja4(&rec).unwrap();
        assert!(ja4.starts_with("t13i"), "{ja4}");
        // 未知版本 0x0999 → "00"
        let rec = build_client_hello(0x0999, &[0x1301], &exts);
        let ja4 = parse_ja4(&rec).unwrap();
        assert!(ja4.starts_with("t00i"), "{ja4}");
        // 无签名算法：扩展哈希输入无下划线段
        let rec = build_client_hello(0x0303, &[0x1301], &[(0x000a, vec![0x00, 0x02, 0x00, 0x1d])]);
        let ja4 = parse_ja4(&rec).unwrap();
        assert!(!ja4.contains('-'));
    }

    #[test]
    fn ja4_non_client_hello_is_none() {
        assert!(parse_ja4(b"GET / HTTP/1.1").is_none());
        assert!(parse_ja4(&[0x16, 0x03]).is_none());
        let rec = [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]; // ServerHello
        assert!(parse_ja4(&rec).is_none());
    }

    /// 确定性模糊（E DoD）：随机字节喂 JA3/JA4 不 panic。
    #[test]
    fn ja3_ja4_fuzz_never_panics() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..10_000u32 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 33) as usize % 512;
            let bytes: Vec<u8> = std::iter::once(0x16)
                .chain((0..len).map(|j| ((state.wrapping_add(j as u64) >> 33) % 256) as u8))
                .collect();
            let _ = parse_ja3(&bytes);
            let _ = parse_ja4(&bytes);
        }
    }

    /// 确定性模糊（E DoD）：随机字节不 panic、hint 输出无控制字符、path 有上限。
    #[test]
    fn parse_http_hint_fuzz_never_panics() {
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..20_000u32 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 33) as usize % 96;
            let bytes: Vec<u8> = (0..len)
                .map(|j| ((state.wrapping_add(j as u64) >> 33) % 256) as u8)
                .chain(*b"\r\n\r\n")
                .collect();
            let text = String::from_utf8_lossy(&bytes).to_string();
            if let Some(h) = parse_http_hint(&text) {
                assert_eq!(h.schema_version, 1);
                assert!(h.path.len() <= 128);
                assert!(!h.method.chars().any(|c| c.is_control()));
                assert!(!h.path.chars().any(|c| c.is_control()));
            }
        }
    }
}
