//! 轻量 L7 标签（0.4.0 B2）：对明文 HTTP 请求做**只读解析**，产出紧凑标签供
//! 事件摘要与 AI 上下文使用。定位是"标签"而非完整指纹/语义解析（0.5 才抽取
//! 正式解析器到 detect::l7）。
//!
//! 纪律：解析失败返回空（不打 parse_error 也绝不 panic）——标签缺失不影响
//! 主检测路径；所有输出经清洗（控制字符去除、截断），调用方仍按不可信输入对待。

/// 可疑 UA 关键字（明确扫描器/攻击工具，克制名单——普通浏览器与 wget/curl 不在此列，
/// 避免把运维脚本当攻击者）。小写包含匹配。
const SUSPECT_UA: &[&str] = &[
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster", "gobuster", "acunetix", "wpscan",
    "havij",
];

/// 从明文 HTTP 请求提取标签：
/// - `http:GET` —— 请求行方法（限已知方法，避免任意串进标签）
/// - `path:/admin` —— path 前 2 段前缀（不携带查询串）
/// - `ua-suspect:sqlmap` —— 命中可疑 UA 关键字
/// 非 HTTP / 畸形输入返回空。
pub fn http_tags(text: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let Some(line) = text.lines().next() else {
        return tags;
    };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return tags;
    };
    // 方法白名单：非标准方法不生成 http: 标签（但仍检查 UA）
    const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
    let is_http_method = METHODS.contains(&method);
    if is_http_method {
        tags.push(format!("http:{method}"));
        let path = path.split(['?', '#']).next().unwrap_or("");
        // path 前缀 = 前 2 段（/a/b），去尾斜杠，截断 64
        let prefix: String = path
            .split('/')
            .filter(|s| !s.is_empty())
            .take(2)
            .map(|s| format!("/{s}"))
            .collect();
        let prefix = prefix.chars().take(64).collect::<String>();
        if !prefix.is_empty() {
            tags.push(format!("path:{prefix}"));
        }
    }
    // UA：不区分大小写包含匹配可疑关键字
    for line in text.lines().skip(1) {
        if line.len() > 512 {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim().eq_ignore_ascii_case("user-agent") {
            let ua = v.trim().to_ascii_lowercase();
            for kw in SUSPECT_UA {
                if ua.contains(kw) {
                    tags.push(format!("ua-suspect:{kw}"));
                    break;
                }
            }
            break;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_tags_extracts_method_path_ua() {
        let req = "GET /admin/config HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n";
        let tags = http_tags(req);
        assert_eq!(tags, ["http:GET", "path:/admin/config", "ua-suspect:sqlmap"]);
    }

    #[test]
    fn http_tags_path_prefix_two_segments_and_strips_query() {
        let tags = http_tags("GET /a/b/c?x=1#f HTTP/1.1\r\n\r\n");
        assert_eq!(tags, ["http:GET", "path:/a/b"]);
        let root = http_tags("GET / HTTP/1.1\r\n\r\n");
        assert_eq!(root, ["http:GET"]);
    }

    #[test]
    fn http_tags_normal_ua_not_flagged() {
        let tags = http_tags("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n\r\n");
        assert_eq!(tags, ["http:GET"]);
    }

    #[test]
    fn http_tags_non_http_or_malformed_returns_empty() {
        assert!(http_tags("").is_empty());
        assert!(http_tags("SSH-2.0-x\r\n").is_empty());
        assert!(http_tags("\x01\x02\x03\r\n\r\n").is_empty());
        assert!(http_tags("GET\r\n\r\n").is_empty());
        assert!(http_tags("GÉT / HTTP/1.1\r\n\r\n").is_empty(), "非 ASCII 方法不产生 http: 标签");
    }

    #[test]
    fn tags_suffix_empty_when_no_tags() {
        assert_eq!(tags_suffix(&[]), "");
        assert_eq!(tags_suffix(&["http:GET".into()]), " [L7 http:GET]");
    }

    /// 确定性模糊：随机字节输入不 panic、输出不含控制字符。
    #[test]
    fn http_tags_fuzz_never_panics() {
        let mut state = 0x2545F4914F6CDD1Du64;
        for i in 0..20_000u32 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let len = (state >> 33) as usize % 64;
            let bytes: Vec<u8> = (0..len)
                .map(|j| {
                    let s2 = state.wrapping_add(j as u64);
                    ((s2 >> 33) % 256) as u8
                })
                .chain([b'\r', b'\n', b'\r', b'\n'])
                .collect();
            let text = String::from_utf8_lossy(&bytes).to_string();
            let tags = http_tags(&text);
            for t in &tags {
                assert!(!t.chars().any(|c| c.is_control()), "标签含控制字符: {t:?} (输入轮 {i})");
            }
        }
    }
}
