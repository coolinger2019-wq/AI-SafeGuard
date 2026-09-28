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
use tokio::sync::{watch, Semaphore};

const MAX_CONCURRENT: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PAYLOAD: usize = 2048;

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
    bus.publish(SecurityEvent::engine("info", format!("蜜罐 [{}] 已停止", l.name)));
}

async fn handle_conn(mut stream: TcpStream, listener: String, kind: String, bus: EventBus) {
    let (remote_ip, remote_port) = match stream.peer_addr() {
        Ok(a) => (a.ip().to_string(), a.port()),
        Err(_) => ("unknown".into(), 0),
    };

    let result: Result<(String, String), std::io::Error> = match kind.as_str() {
        "ssh" => ssh_session(&mut stream).await,
        "http" => http_session(&mut stream).await,
        "telnet" => telnet_session(&mut stream).await,
        _ => generic_session(&mut stream).await,
    };

    let (summary, payload) = match result {
        Ok(v) => v,
        Err(e) => {
            // 读超时属于常态（端口扫描只 connect 不发数据），不按错误处理
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::UnexpectedEof
            {
                ("连接建立后未发送数据（疑似端口扫描）".to_string(), String::new())
            } else {
                (format!("会话异常: {e}"), String::new())
            }
        }
    };

    let ev = SecurityEvent::HoneypotHit {
        ts: now_ts(),
        listener,
        kind,
        port: stream
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(0),
        remote_ip,
        remote_port,
        summary,
        payload,
    };
    bus.publish(ev);
}

async fn ssh_session(s: &mut TcpStream) -> Result<(String, String), std::io::Error> {
    s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = l7::first_line(&text).unwrap_or_else(|| "SSH banner 已发送，等待客户端报文".into());
    Ok((summary, text))
}

async fn telnet_session(s: &mut TcpStream) -> Result<(String, String), std::io::Error> {
    s.write_all(b"Welcome to Ubuntu 22.04 LTS\r\nlogin: ").await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = l7::first_line(&text)
        .map(|l| format!("尝试登录: {l}"))
        .unwrap_or_else(|| "登录提示已发送".into());
    Ok((summary, text))
}

async fn http_session(s: &mut TcpStream) -> Result<(String, String), std::io::Error> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    for _ in 0..8 {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk)).await;
        match n {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Err(e)) => return Err(e),
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if http_request_complete(&buf) {
                    break;
                }
            }
        }
    }
    s.write_all(
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\nServer: nginx\r\n\r\n",
    )
    .await?;
    let text = sanitize(&buf, MAX_PAYLOAD);
    let summary = format!(
        "{}{}",
        l7::request_summary(&text, "空 HTTP 请求"),
        l7::tags_suffix(&l7::http_tags(&text))
    );
    Ok((summary, text))
}

async fn generic_session(s: &mut TcpStream) -> Result<(String, String), std::io::Error> {
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = request_summary(&text, "仅建立连接，未发送数据");
    Ok((summary, text))
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
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout")),
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
}
