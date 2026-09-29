//! 监听器：bind / accept / 停机 + 会话分派与两级并发预算。
//!
//! 并发模型（0.5.9 H102）：全局信号量兜底所有蜜罐连接；交互会话（假 Shell 等
//! 有状态多轮）额外受独立小额预算约束——长会话不得挤占全局额度饿死其他监听器。
//! 满额一律静默丢连接（全局）或优雅拒绝并留事件（交互），蜜罐自身不能被打挂。

use std::sync::Arc;

use aisafeguard_core::config::{HoneypotConfig, ListenerConfig};
use aisafeguard_core::event::{EventBus, SecurityEvent};
use aisafeguard_core::now_ts;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use crate::{SessionOutcome, http, protocol};

const MAX_CONCURRENT: usize = 64;
/// 交互会话独立预算（0.5.9 跨任务红线）：默认 8，防止长会话刷满全局 64 额度。
const MAX_INTERACTIVE: usize = 8;

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
    let interactive_sem = Arc::new(Semaphore::new(MAX_INTERACTIVE));
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
        // 交互会话占独立小额预算：满额优雅拒绝并留痕（对齐 OpenSSH 正常拒连语义）
        let interactive_permit = if is_interactive_session(&l.kind) {
            match interactive_sem.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    bus.publish(SecurityEvent::engine(
                        "info",
                        format!(
                            "蜜罐 [{}] 交互会话并发已满（{}），拒绝新会话",
                            l.name, MAX_INTERACTIVE
                        ),
                    ));
                    drop(stream);
                    drop(permit);
                    continue;
                }
            }
        } else {
            None
        };
        let bus = bus.clone();
        let name = l.name.clone();
        let kind = l.kind.clone();
        tokio::spawn(async move {
            handle_conn(stream, name, kind, bus).await;
            drop(interactive_permit);
            drop(permit);
        });
    }
    bus.publish(SecurityEvent::engine(
        "info",
        format!("蜜罐 [{}] 已停止", l.name),
    ));
}

/// 该 kind 是否交互会话（有状态多轮）。0.5.8 基准下全部低交互；
/// H104 接线后由 [honeypot.shell].enabled 决定 ssh 是否升级为交互会话。
fn is_interactive_session(kind: &str) -> bool {
    let _ = kind;
    false
}

async fn handle_conn(mut stream: TcpStream, listener: String, kind: String, bus: EventBus) {
    let (remote_ip, remote_port) = match stream.peer_addr() {
        Ok(a) => (a.ip().to_string(), a.port()),
        Err(_) => ("unknown".into(), 0),
    };

    let result: std::io::Result<SessionOutcome> = match kind.as_str() {
        "ssh" => protocol::ssh_session(&mut stream).await,
        "http" => http::http_session(&mut stream).await,
        "telnet" => protocol::telnet_session(&mut stream).await,
        _ => protocol::generic_session(&mut stream).await,
    };

    let outcome = match result {
        Ok(v) => v,
        Err(e) => {
            // 读超时属于常态（端口扫描只 connect 不发数据），不按错误处理
            let summary = if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::UnexpectedEof
            {
                "连接建立后未发送数据（疑似端口扫描）".to_string()
            } else {
                format!("会话异常: {e}")
            };
            SessionOutcome {
                summary,
                payload: String::new(),
                http_hint: None,
                interaction: None,
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
        summary: outcome.summary,
        payload: outcome.payload,
        http_hint: outcome.http_hint,
        interaction: outcome.interaction,
    };
    bus.publish(ev);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn interactive_gate_off_until_shell_wiring() {
        // H102 基准：全部 kind 低交互；H104 接线后本断言随配置化改写
        for kind in ["ssh", "http", "telnet", "generic", "mysql", "redis"] {
            assert!(!is_interactive_session(kind), "{kind} 应为低交互");
        }
    }

    #[test]
    fn interactive_sem_exhaustion_graceful() {
        // 预算语义：8 个许可拿满后拒绝，归还后恢复
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sem = Arc::new(Semaphore::new(MAX_INTERACTIVE));
            let mut permits = Vec::new();
            for _ in 0..MAX_INTERACTIVE {
                permits.push(sem.clone().try_acquire_owned().unwrap());
            }
            assert!(sem.clone().try_acquire_owned().is_err());
            drop(permits);
            assert!(sem.clone().try_acquire_owned().is_ok());
        });
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
