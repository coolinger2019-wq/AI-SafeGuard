//! L7 解析与指纹基座（0.5.0 Batch E，设计见 docs/ROADMAP-0.5.md Batch E）。
//!
//! 蜜罐与采样捕获 full 模式**共用**的 HTTP 解析：同一输入产出同一 `HttpHint`。
//! 职责单一：只解析、只产结构化字段与标签——不做封禁、不依赖 firewall
//! （crate 依赖图禁止，见 ROADMAP-0.5 风险清单 #3）。
//!
//! 纪律：解析失败返回 None/空，绝不 panic（模糊测试钉住）；所有输出经清洗
//! （控制字符处理、长度上限）；调用方仍按不可信输入对待。

/// HttpHint schema 版本（0.5.0 E2）：字段只增不改义；新增字段走 schema_version bump。
pub const HINT_SCHEMA_VERSION: u8 = 1;

/// 结构化 HTTP 提示（蜜罐/采样 full 模式两入口共用）。
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct HttpHint {
    /// schema 版本（当前 1）
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
}

/// 可疑 UA 关键字（明确扫描器/攻击工具，克制名单——普通浏览器与 wget/curl 不在列，
/// 避免把运维脚本当攻击者）。小写包含匹配。
pub const SUSPECT_UA: &[&str] = &[
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster", "gobuster", "acunetix", "wpscan",
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
        let Some((k, v)) = line.split_once(':') else { continue };
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
        method,
        path,
        host,
        user_agent,
        ua_suspect,
    })
}

/// 兼容 0.4 文案的标签形式（E3）：`http:GET` / `path:/x/y` / `ua-suspect:sqlmap`。
/// 非 HTTP / 畸形输入返回空。
pub fn http_tags(text: &str) -> Vec<String> {
    let Some(hint) = parse_http_hint(text) else {
        return Vec::new();
    };
    let mut tags = vec![format!("http:{}", hint.method)];
    // 0.4 文案：path 标签取前 2 段前缀（HttpHint.path 是完整路径，两者用途不同）
    if !hint.path.is_empty() {
        let prefix: String = hint
            .path
            .split('/')
            .filter(|s| !s.is_empty())
            .take(2)
            .map(|s| format!("/{s}"))
            .collect();
        if !prefix.is_empty() {
            tags.push(format!("path:{prefix}"));
        }
    }
    for kw in &hint.ua_suspect {
        tags.push(format!("ua-suspect:{kw}"));
    }
    tags
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
    let client_version = be16(body, off)?;
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
    let mut ext_types: Vec<u16> = Vec::new();
    let mut groups: Vec<u16> = Vec::new();
    let mut formats: Vec<u8> = Vec::new();
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
            ext_types.push(etype);
            match etype {
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
    }
    let raw = format!(
        "{},{},{},{},{}",
        client_version,
        ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
        ext_types.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
        groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
        formats.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("-"),
    );
    use md5::Digest as _;
    let md5hex = {
        let d = md5::Md5::digest(raw.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    Some(Ja3 { raw, md5: md5hex })
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
        assert_eq!(h.schema_version, 1);
        assert_eq!(h.method, "GET");
        assert_eq!(h.path, "/admin/config");
        assert_eq!(h.host.as_deref(), Some("x.test"));
        assert_eq!(h.user_agent.as_deref(), Some("sqlmap/1.7"));
        assert_eq!(h.ua_suspect, ["sqlmap"]);
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
        assert!(parse_http_hint("GÉT / HTTP/1.1\r\n\r\n").is_none(), "非 ASCII 方法拒绝");
    }

    #[test]
    fn http_tags_matches_04_output_format() {
        // E3：0.4 core::l7 的标签格式原样保留（旧文案可解释）
        let tags = http_tags("GET /admin/config HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n\r\n");
        assert_eq!(tags, ["http:GET", "path:/admin/config", "ua-suspect:sqlmap"]);
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
        assert!(http_request_complete(&[0u8; 8192]), "超上限按完整处理（防堆积）");
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

    /// 确定性模糊（E DoD）：随机字节不 panic、hint 输出无控制字符、path 有上限。
    #[test]
    fn parse_http_hint_fuzz_never_panics() {
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..20_000u32 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let len = (state >> 33) as usize % 96;
            let bytes: Vec<u8> = (0..len)
                .map(|j| ((state.wrapping_add(j as u64) >> 33) % 256) as u8)
                .chain([b'\r', b'\n', b'\r', b'\n'])
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
