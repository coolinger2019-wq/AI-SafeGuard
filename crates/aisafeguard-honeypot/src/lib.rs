#![forbid(unsafe_code)]

//! 低交互 TCP 蜜罐：accept 后按 kind 给出假响应，记录来源与首包内容。
//! 防御性设计：并发连接上限（信号量）、读写超时、payload 清洗截断，
//! 攻击者无法通过海量连接或超长输入拖垮本进程。

use std::sync::Arc;
use std::time::Duration;

use aisafeguard_core::config::{HoneypotConfig, ListenerConfig};
use aisafeguard_core::event::{EventBus, SecurityEvent};
use aisafeguard_core::now_ts;
use aisafeguard_l7 as l7;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

const MAX_CONCURRENT: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PAYLOAD: usize = 2048;

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

#[derive(Debug, Clone)]
pub struct ListenerState {
    pub name: String,
    pub port: u16,
    pub kind: String,
}

pub struct HoneypotHandle {
    pub listeners: Vec<ListenerState>,
    shutdown: watch::Sender<bool>,
}

impl HoneypotHandle {
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

/// 必须在 tokio runtime 上下文中调用。
pub fn start(cfg: &HoneypotConfig, bus: EventBus) -> HoneypotHandle {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut listeners = Vec::new();
    if cfg.enabled {
        for l in &cfg.listeners {
            tokio::spawn(run_listener(l.clone(), bus.clone(), shutdown_rx.clone()));
            listeners.push(ListenerState {
                name: l.name.clone(),
                port: l.port,
                kind: l.kind.clone(),
            });
        }
    }
    HoneypotHandle {
        listeners,
        shutdown: shutdown_tx,
    }
}

async fn run_listener(l: ListenerConfig, bus: EventBus, mut shutdown: watch::Receiver<bool>) {
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), l.port);
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            bus.publish(SecurityEvent::engine(
                "error",
                format!("蜜罐 [{}] 绑定 :{} 失败: {e}", l.name, l.port),
            ));
            return;
        }
    };
    bus.publish(SecurityEvent::engine(
        "info",
        format!("蜜罐 [{}] ({}) 已监听 :{}", l.name, l.kind, l.port),
    ));
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        let stream = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((s, _)) => s,
                Err(_) => continue,
            },
        };
        // 满载直接丢弃连接：蜜罐自身不能被打挂
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let bus = bus.clone();
        let name = l.name.clone();
        let kind = l.kind.clone();
        tokio::spawn(async move {
            handle_conn(stream, name, kind, bus).await;
            drop(permit);
        });
    }
    bus.publish(SecurityEvent::engine(
        "info",
        format!("蜜罐 [{}] 已停止", l.name),
    ));
}

async fn handle_conn(mut stream: TcpStream, listener: String, kind: String, bus: EventBus) {
    let (remote_ip, remote_port) = match stream.peer_addr() {
        Ok(a) => (a.ip().to_string(), a.port()),
        Err(_) => ("unknown".into(), 0),
    };

    let result: Result<(String, String, Option<l7::HttpHint>), std::io::Error> = match kind.as_str()
    {
        "ssh" => ssh_session(&mut stream).await,
        "http" => http_session(&mut stream).await,
        "telnet" => telnet_session(&mut stream).await,
        _ => generic_session(&mut stream).await,
    };

    let (summary, payload, http_hint) = match result {
        Ok(v) => v,
        Err(e) => {
            // 读超时属于常态（端口扫描只 connect 不发数据），不按错误处理
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::UnexpectedEof
            {
                (
                    "连接建立后未发送数据（疑似端口扫描）".to_string(),
                    String::new(),
                    None,
                )
            } else {
                (format!("会话异常: {e}"), String::new(), None)
            }
        }
    };

    let ev = SecurityEvent::HoneypotHit {
        ts: now_ts(),
        listener,
        kind,
        port: stream.local_addr().map(|a| a.port()).unwrap_or(0),
        remote_ip,
        remote_port,
        summary,
        payload,
        http_hint,
    };
    bus.publish(ev);
}

async fn ssh_session(
    s: &mut TcpStream,
) -> Result<(String, String, Option<l7::HttpHint>), std::io::Error> {
    s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary =
        l7::first_line(&text).unwrap_or_else(|| "SSH banner 已发送，等待客户端报文".into());
    Ok((summary, text, None))
}

async fn telnet_session(
    s: &mut TcpStream,
) -> Result<(String, String, Option<l7::HttpHint>), std::io::Error> {
    s.write_all(b"Welcome to Ubuntu 22.04 LTS\r\nlogin: ")
        .await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = l7::first_line(&text)
        .map(|l| format!("尝试登录: {l}"))
        .unwrap_or_else(|| "登录提示已发送".into());
    Ok((summary, text, None))
}

async fn http_session(
    s: &mut TcpStream,
) -> Result<(String, String, Option<l7::HttpHint>), std::io::Error> {
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
    Ok((summary, text, hint))
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

async fn generic_session(
    s: &mut TcpStream,
) -> Result<(String, String, Option<l7::HttpHint>), std::io::Error> {
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = request_summary(&text, "仅建立连接，未发送数据");
    Ok((summary, text, None))
}

async fn read_with_timeout(
    s: &mut TcpStream,
    timeout: Duration,
) -> Result<(usize, Vec<u8>), std::io::Error> {
    let mut buf = vec![0u8; MAX_PAYLOAD];
    match tokio::time::timeout(timeout, s.read(&mut buf)).await {
        Ok(res) => {
            let n = res?;
            Ok((n, buf))
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timeout",
        )),
    }
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

/// HTTP 头部是否已完整收到（\r\n\r\n）或超出上限——供读循环与模糊测试共用。
pub fn http_request_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 8192
}

/// 清洗后的首行摘要（≤160 字符），任何字节输入都不会 panic。
pub fn request_summary(text: &str, fallback: &str) -> String {
    l7::request_summary(text, fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_and_truncates() {
        let raw = b"GET /x HTTP/1.1\r\nHost: a\x01b";
        let s = sanitize(raw, 100);
        assert!(s.contains("GET /x HTTP/1.1"));
        assert!(!s.contains('\r'));
        assert!(s.contains('·'));
        let long = sanitize(&[b'a'; 5000], 100);
        assert_eq!(long.chars().count(), 100);
    }

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
        assert_eq!(content_length(&req), 27);
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
            let summary = request_summary(&text, "x");
            assert!(summary.chars().count() <= 160);
        }
    }

    #[tokio::test]
    async fn ssh_listener_captures_connection() {
        // 先占一个空闲端口再放开，避免测试端口冲突
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            listeners: vec![ListenerConfig {
                name: "ssh".into(),
                port,
                kind: "ssh".into(),
            }],
        };
        let _handle = start(&cfg, bus.clone());

        // 连接并读取 banner（start 异步 spawn，bind 与 connect 有竞态——重试等待）
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
        let mut conn = conn.expect("监听器未在 2 秒内就绪");
        let mut banner = [0u8; 32];
        let n = conn.read(&mut banner).await.unwrap();
        assert!(String::from_utf8_lossy(&banner[..n]).starts_with("SSH-2.0"));
        conn.write_all(b"SSH-2.0-attacker\r\n").await.unwrap();
        drop(conn);

        // 跳过 Engine 事件（如"已监听"），直到收到 HoneypotHit
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("超时未收到蜜罐事件")
                .expect("事件通道关闭");
            match ev {
                SecurityEvent::HoneypotHit {
                    remote_ip, payload, ..
                } => {
                    assert_eq!(remote_ip, "127.0.0.1");
                    assert!(payload.contains("SSH-2.0-attacker"));
                    break;
                }
                _ => continue,
            }
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
            listeners: vec![ListenerConfig {
                name: "http".into(),
                port,
                kind: "http".into(),
            }],
        };
        let handle = start(&cfg, bus);
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
