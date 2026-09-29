//! HTTP 协议仿真：诱饵路由（登录页/受限页/通用假页）+ 密码脱敏 + 有界读。
//! 全部响应是内置常量，无真实业务数据；请求按不可信数据处理。

use std::time::Duration;

use aisafeguard_l7 as l7;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{MAX_PAYLOAD, SessionOutcome, sanitize};

/// 内置 HTTP 诱饵路径（0.5.6 F11）：低交互边界内的常见敏感路径诱饵，
/// 未命中的请求走通用假页。不做完整 CMS/假文件系统（中交互边界，见 ROADMAP-0.5.3 §4.1）。
pub const DECOY_PATHS: &[&str] = &[
    "/admin",
    "/wp-login.php",
    "/.env",
    "/api/login",
    "/login",
    "/phpmyadmin",
    "/config.php",
    "/manager/html",
    "/actuator",
    "/.git/config",
];

/// 假登录页路径（DECOY_PATHS 子集）：GET 下发表单，POST 记提交（login:post）
const LOGIN_PATHS: &[&str] = &["/admin", "/login", "/api/login", "/wp-login.php"];

/// 密码类表单键名（词边界匹配）：值一律脱敏，不落库明文（0.5.6 F12）
const SECRET_KEYS: &[&str] = &["password", "passwd", "pwd", "pass"];

/// 请求路径 → 诱饵路由。path 为去查询串后的前缀（HttpHint.path 语义）；
/// 精确匹配或子路径（/admin/ → 命中 /admin）。
pub fn is_login_path(path: &str) -> bool {
    matches_list(path, LOGIN_PATHS)
}

pub fn is_decoy_path(path: &str) -> bool {
    matches_list(path, DECOY_PATHS)
}

fn matches_list(path: &str, list: &[&str]) -> bool {
    let lower = path.to_ascii_lowercase();
    list.iter()
        .any(|p| lower == *p || lower.starts_with(&format!("{p}/")))
}

/// HTTP 头里的 Content-Length（非法/缺失返回 0）
pub fn content_length(head_text: &str) -> usize {
    head_text
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// 敏感字段值脱敏（0.5.6 F12）：password/passwd/pwd/pass 键名的值替换为 ***，
/// 覆盖 form `k=v` 与 JSON `"k":"v"` 两种形态；键名原样保留——「出现过」可判定，
/// 明文不落库。键匹配按词边界：`user_password` 命中，`bypass` 不误伤。
pub fn redact_secrets(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let chars: Vec<char> = text.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        let mut matched = false;
        for key in SECRET_KEYS {
            let kc: Vec<char> = key.chars().collect();
            if lower_chars[i..].starts_with(&kc)
                && boundary_before(&lower_chars, i)
                && boundary_after(&lower_chars, i + kc.len())
            {
                let key_end = i + kc.len();
                // 键名原样保留，跳过分隔符（= 或 ": "）后把值替换为 ***
                out.extend(&chars[i..key_end]);
                i = key_end;
                let mut j = i;
                while j < chars.len()
                    && (chars[j] == '"' || chars[j] == ':' || chars[j] == '=' || chars[j] == ' ')
                {
                    out.push(chars[j]);
                    j += 1;
                }
                out.push_str("***");
                i = j;
                while i < chars.len()
                    && chars[i] != '&'
                    && chars[i] != '"'
                    && chars[i] != '\n'
                    && chars[i] != '\r'
                {
                    i += 1;
                }
                matched = true;
                break;
            }
        }
        if !matched {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// 词边界：字母数字以外都算分隔（含下划线——user_password 应命中，bypass 不误伤）
fn boundary_before(chars: &[char], i: usize) -> bool {
    i == 0 || !chars[i - 1].is_ascii_alphanumeric()
}

fn boundary_after(chars: &[char], i: usize) -> bool {
    i >= chars.len() || !chars[i].is_ascii_alphanumeric()
}

/// 假登录页（0.5.6 F12）：GET 短表单；POST 返回通用失败页，无真实会话。
fn login_page(path: &str, failed: bool) -> String {
    let msg = if failed {
        "<p style=\"color:#a00\">用户名或密码错误</p>"
    } else {
        ""
    };
    let path = l7::sanitize(path.as_bytes(), 128);
    format!(
        "<!DOCTYPE html><html><head><title>设备管理登录</title></head>\
         <body><h2>管理登录</h2>{msg}\
         <form method=\"POST\" action=\"{path}\">\
         <input name=\"username\" placeholder=\"用户名\">\
         <input type=\"password\" name=\"password\" placeholder=\"密码\">\
         <button type=\"submit\">登录</button></form></body></html>"
    )
}

/// 非登录诱饵页（受限区域风格）
fn decoy_page() -> String {
    "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>\
     <body><h2>403 Forbidden</h2><p>Access to this resource is restricted.</p></body></html>"
        .into()
}

/// 未命中诱饵路径的通用假页（像真站一点的短 HTML，诱导继续探测）
fn generic_page() -> String {
    "<!DOCTYPE html><html><head><title>Welcome</title></head>\
     <body><h1>It works!</h1><p>This page is served by the web server.</p></body></html>"
        .into()
}

pub(crate) async fn http_session(s: &mut TcpStream) -> std::io::Result<SessionOutcome> {
    let mut buf = read_http_request(s).await?;
    let head_text = String::from_utf8_lossy(&buf).to_string();
    let hint = l7::parse_http_hint(&head_text);
    let method = hint.as_ref().map(|h| h.method.clone()).unwrap_or_default();
    let path = hint.as_ref().map(|h| h.path.clone()).unwrap_or_default();

    // POST：头部完整后继续读 body（Content-Length 有界，总长仍不超 8 KiB）
    if method == "POST"
        && let Some(start) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    {
        let want = (start + content_length(&head_text).min(4096)).min(8192);
        let mut chunk = [0u8; 1024];
        for _ in 0..8 {
            if buf.len() >= want {
                break;
            }
            match tokio::time::timeout(Duration::from_secs(2), s.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    // 诱饵路由（F11）：登录路径 → 假登录页；其余诱饵 → 受限页；未匹配 → 通用假页
    let is_post = method == "POST";
    let login = hint.is_some() && is_login_path(&path);
    let decoy = hint.is_some() && is_decoy_path(&path);
    let (status, body) = if hint.is_none() {
        (b"HTTP/1.1 404 Not Found\r\n".as_slice(), Vec::new())
    } else if login {
        let page = login_page(&path, is_post);
        (b"HTTP/1.1 200 OK\r\n".as_slice(), page.into_bytes())
    } else if decoy {
        (
            b"HTTP/1.1 403 Forbidden\r\n".as_slice(),
            decoy_page().into_bytes(),
        )
    } else {
        (
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            generic_page().into_bytes(),
        )
    };
    s.write_all(
        format!(
            "{}Content-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nServer: nginx\r\n\r\n",
            String::from_utf8_lossy(status),
            body.len()
        )
        .as_bytes(),
    )
    .await?;
    if !body.is_empty() {
        s.write_all(&body).await?;
    }

    // 诱饵标签并入 hint.tags（F13 单一字段）与摘要后缀（人类可读）
    let mut tags = hint.as_ref().map(|h| h.tags.clone()).unwrap_or_default();
    if login {
        tags.push(if is_post {
            "login:post".into()
        } else {
            "login:get".into()
        });
    } else if decoy {
        tags.push("decoy".into());
    }
    let hint = hint.map(|mut h| {
        h.tags = tags.clone();
        h
    });
    let text = sanitize(redact_secrets(&head_text).as_bytes(), MAX_PAYLOAD);
    let summary = format!(
        "{}{}",
        l7::request_summary(&text, "空 HTTP 请求"),
        l7::tags_suffix(&tags)
    );
    Ok(SessionOutcome {
        summary,
        payload: text,
        http_hint: hint,
        interaction: None,
    })
}

/// 读 HTTP 请求直到头部完整（\r\n\r\n）或超出上限；调用方按需续读 body。
async fn read_http_request(s: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    for _ in 0..8 {
        if http_request_complete(&buf) {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Err(e)) => return Err(e),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    Ok(buf)
}

/// HTTP 头部是否已完整收到（\r\n\r\n）或超出上限——供读循环与模糊测试共用。
pub fn http_request_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 8192
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{start, HoneypotHandle};
    use aisafeguard_core::config::{HoneypotConfig, ListenerConfig};
    use aisafeguard_core::event::{EventBus, SecurityEvent};
    use std::time::Duration;

    #[test]
    fn decoy_route_exact_and_subpath() {
        // F11：精确 + 子路径匹配；非诱饵走通用假页
        for p in ["/admin", "/login", "/api/login", "/wp-login.php"] {
            assert!(is_login_path(p), "{p} 应为登录路径");
            assert!(is_decoy_path(p));
        }
        assert!(is_decoy_path("/.env"));
        assert!(is_decoy_path("/admin/") && is_login_path("/Admin/".trim_end_matches('/')));
        assert!(is_decoy_path("/.git/config"));
        assert!(!is_decoy_path("/index.html"));
        assert!(!is_login_path("/administrator"));
        assert!(is_decoy_path("/admin/console"), "子路径命中诱饵");
    }

    #[test]
    fn content_length_parses_and_defaults_zero() {
        let req = "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 27\r\n\r\n";
        assert_eq!(content_length(req), 27);
        assert_eq!(content_length("GET / HTTP/1.1\r\n\r\n"), 0);
        assert_eq!(
            content_length("POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n"),
            0
        );
    }

    #[test]
    fn redact_secrets_form_and_json() {
        // F12：密码只记「出现过」，值不落库明文
        let form = "POST /login HTTP/1.1\r\n\r\nusername=admin&password=s3cret!&x=1";
        let out = redact_secrets(form);
        assert!(out.contains("password=***"), "实际: {out}");
        assert!(out.contains("username=admin"));
        assert!(out.contains("x=1"));
        assert!(!out.contains("s3cret"));
        let json = r#"{"user":"a","password":"plain","passwd":"x2"}"#;
        let out = redact_secrets(json);
        assert!(!out.contains("plain") && !out.contains("x2"), "实际: {out}");
        assert!(
            out.contains(r#""password":"***""#)
                || out.contains("\"password\": \"***\"")
                || out.contains("password\":\"***"),
            "实际: {out}"
        );
        // 词边界：bypass / overpass 值不误伤
        assert_eq!(redact_secrets("bypass=ok&x=1"), "bypass=ok&x=1");
        assert_eq!(redact_secrets("user_password=abc"), "user_password=***");
    }

    #[test]
    fn redact_and_route_fuzz_never_panic() {
        // F16：畸形输入（含随机字节与截断请求）不 panic，摘要长度有上限
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..2000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = (state >> 33) as usize % 300;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            let text = String::from_utf8_lossy(&bytes).to_string();
            let _ = redact_secrets(&text);
            let _ = is_decoy_path(&text);
            let _ = content_length(&text);
            let _ = l7::parse_http_hint(&text);
            let summary = crate::request_summary(&text, "x");
            assert!(summary.chars().count() <= 160);
        }
    }

    /// 起 HTTP 蜜罐并等就绪。返回 handle 一并保活——HoneypotHandle drop 即停机。
    async fn http_listener() -> (
        u16,
        tokio::sync::broadcast::Receiver<SecurityEvent>,
        HoneypotHandle,
    ) {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let bus = EventBus::new(64);
        let rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            shell: Default::default(),
            listeners: vec![ListenerConfig {
                name: "http".into(),
                port,
                kind: "http".into(),
            }],
        };
        let handle = start(&cfg, bus, &std::env::temp_dir());
        let mut conn = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(c) => {
                    conn = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        assert!(conn.is_some(), "HTTP 蜜罐未在 2 秒内就绪");
        (port, rx, handle)
    }

    async fn wait_hit(rx: &mut tokio::sync::broadcast::Receiver<SecurityEvent>) -> SecurityEvent {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("超时未收到蜜罐事件")
                .expect("事件通道关闭");
            // 跳过探活连接的空命中（连接即断、未发数据）
            if let SecurityEvent::HoneypotHit { payload, .. } = &ev
                && !payload.is_empty()
            {
                return ev;
            }
        }
    }

    #[tokio::test]
    async fn http_login_get_serves_form_and_post_redacts_password() {
        // Batch 3 DoD：打开蜜罐 HTTP 端口可见假登录页；POST 记提交但不落库明文密码
        let (port, mut rx, _handle) = http_listener().await;

        // GET /login → 200 + 表单（含 password 字段），事件带 login:get 标签与结构化提示
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        c.write_all(b"GET /login HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 2048];
        let n = c.read(&mut resp).await.unwrap();
        let body = String::from_utf8_lossy(&resp[..n]).to_string();
        assert!(body.starts_with("HTTP/1.1 200 OK"));
        assert!(body.contains("type=\"password\""), "应含密码表单字段");
        drop(c);
        match wait_hit(&mut rx).await {
            SecurityEvent::HoneypotHit {
                summary, http_hint, ..
            } => {
                assert!(summary.contains("login:get"), "实际: {summary}");
                assert!(summary.contains("ua-suspect:sqlmap"));
                let hint = http_hint.expect("http 蜜罐事件必须带 HttpHint");
                assert_eq!(hint.method, "GET");
                assert_eq!(hint.path, "/login");
                assert!(hint.tags.contains(&"login:get".to_string()));
                assert!(hint.tags.contains(&"http:GET".to_string()));
            }
            _ => unreachable!(),
        }

        // POST /login → 表单提交：payload 落库密码脱敏，标签 login:post
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        c.write_all(
            b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 32\r\n\r\nusername=root&password=Tr0ub4dor&3",
        )
        .await
        .unwrap();
        let mut resp = vec![0u8; 2048];
        let n = c.read(&mut resp).await.unwrap();
        let body = String::from_utf8_lossy(&resp[..n]).to_string();
        assert!(
            body.contains("用户名或密码错误"),
            "POST 应返回失败页，无真实会话"
        );
        drop(c);
        match wait_hit(&mut rx).await {
            SecurityEvent::HoneypotHit {
                summary,
                payload,
                http_hint,
                ..
            } => {
                assert!(summary.contains("login:post"), "实际: {summary}");
                assert!(payload.contains("password=***"), "实际: {payload}");
                assert!(!payload.contains("Tr0ub4dor"), "明文密码不得落库");
                let hint = http_hint.expect("http 蜜罐事件必须带 HttpHint");
                assert!(hint.tags.contains(&"login:post".to_string()));
            }
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn http_decoy_and_generic_pages() {
        let (port, mut rx, _handle) = http_listener().await;

        // /.env → 诱饵响应 403；/index.html → 通用假页
        for (path, expect_status) in [("/.env", "HTTP/1.1 403"), ("/index.html", "HTTP/1.1 200")] {
            let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut resp = vec![0u8; 1024];
            let n = c.read(&mut resp).await.unwrap();
            assert!(
                String::from_utf8_lossy(&resp[..n]).starts_with(expect_status),
                "{path} 响应异常"
            );
            drop(c);
            match wait_hit(&mut rx).await {
                SecurityEvent::HoneypotHit {
                    summary, http_hint, ..
                } => {
                    if path == "/.env" {
                        assert!(summary.contains("decoy"), "实际: {summary}");
                        assert!(http_hint.unwrap().tags.contains(&"decoy".to_string()));
                    } else {
                        assert!(!summary.contains("decoy"));
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}
