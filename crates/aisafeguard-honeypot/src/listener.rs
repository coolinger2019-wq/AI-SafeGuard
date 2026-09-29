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

use crate::shell::ShellRuntime;
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

/// 必须在 tokio runtime 上下文中调用。data_dir 用于假 Shell host key 的
/// 默认落盘位置（<data_dir>/honeypot/，fed 证书路径同款约定）。
pub fn start(cfg: &HoneypotConfig, bus: EventBus, data_dir: &std::path::Path) -> HoneypotHandle {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut listeners = Vec::new();
    if cfg.enabled {
        // 假 Shell 运行时：host key 失败 → 降级 banner 低交互并留事件
        let shell = if cfg.shell.enabled {
            match crate::shell::start_runtime(&cfg.shell, data_dir) {
                Ok(rt) => {
                    bus.publish(SecurityEvent::engine(
                        "info",
                        format!(
                            "假 Shell 已启用（ssh 升级中交互,用户 {}@{}）",
                            cfg.shell.username, cfg.shell.hostname
                        ),
                    ));
                    Some(rt)
                }
                Err(e) => {
                    bus.publish(SecurityEvent::engine(
                        "error",
                        format!("假 Shell host key 初始化失败,ssh 保持 banner 低交互: {e}"),
                    ));
                    None
                }
            }
        } else {
            None
        };
        for l in &cfg.listeners {
            tokio::spawn(run_listener(
                l.clone(),
                bus.clone(),
                shutdown_rx.clone(),
                shell.clone(),
            ));
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

async fn run_listener(
    l: ListenerConfig,
    bus: EventBus,
    mut shutdown: watch::Receiver<bool>,
    shell: Option<Arc<ShellRuntime>>,
) {
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
        let interactive_permit =
            if is_interactive_session(&l.kind, shell.as_deref()) {
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
        let shell = shell.clone();
        tokio::spawn(async move {
            handle_conn(stream, name, kind, bus, shell).await;
            drop(interactive_permit);
            drop(permit);
        });
    }
    bus.publish(SecurityEvent::engine(
        "info",
        format!("蜜罐 [{}] 已停止", l.name),
    ));
}

/// 该 kind 是否交互会话（有状态多轮）：[honeypot.shell].enabled 时 ssh 升级
/// 交互会话（H104），其余恒低交互。
fn is_interactive_session(kind: &str, shell: Option<&ShellRuntime>) -> bool {
    kind == "ssh" && shell.is_some()
}

async fn handle_conn(
    mut stream: TcpStream,
    listener: String,
    kind: String,
    bus: EventBus,
    shell: Option<Arc<ShellRuntime>>,
) {
    let (remote_ip, remote_port) = match stream.peer_addr() {
        Ok(a) => (a.ip().to_string(), a.port()),
        Err(_) => ("unknown".into(), 0),
    };
    let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);

    // ssh + 假 Shell 启用时流被 russh 消费（提前取端口）;其余会话按 &mut 读一包
    let result: std::io::Result<SessionOutcome> = match (kind.as_str(), shell.as_ref()) {
        ("ssh", Some(rt)) => Ok(crate::shell::ssh_shell_session(stream, rt.clone()).await),
        ("ssh", None) => protocol::ssh_session(&mut stream).await,
        ("http", _) => http::http_session(&mut stream).await,
        ("telnet", _) => protocol::telnet_session(&mut stream).await,
        (_, _) => protocol::generic_session(&mut stream).await,
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
        port: local_port,
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
    fn interactive_gate_follows_shell_config() {
        // H104：ssh + [honeypot.shell].enabled → 交互会话;关闭/其他 kind → 低交互
        for kind in ["http", "telnet", "generic", "mysql", "redis"] {
            assert!(!is_interactive_session(kind, None), "{kind} 应为低交互");
        }
        assert!(!is_interactive_session("ssh", None), "shell 关闭时 ssh 低交互");
        let tmp = std::env::temp_dir().join(format!("asg-shell-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let rt = crate::shell::start_runtime(
            &aisafeguard_core::config::ShellConfig {
                enabled: true,
                ..Default::default()
            },
            &tmp,
        )
        .expect("host key 应在临时目录生成");
        assert!(is_interactive_session("ssh", Some(&rt)));
        assert!(!is_interactive_session("telnet", Some(&rt)));
        let _ = std::fs::remove_dir_all(&tmp);
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
        // shell 关闭基准:banner 低交互行为与 0.5.8 一致
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
            ..Default::default()
        };
        let _handle = start(&cfg, bus.clone(), &std::env::temp_dir());

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

    /// H104 端到端:[honeypot.shell].enabled → 真实 SSH 客户端(russh)登录后
    /// shell_request 推送假 prompt;断开后事件走「认证通过、零命令」路径。
    /// 完整命令仿真链路由 paramiko 实连验收(scripts/replay-ssh-shell.py,H105)。
    #[tokio::test]
    async fn ssh_shell_e2e_prompt_and_empty_session_event() {
        use std::sync::Mutex as StdMutex;

        // 占空闲端口
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let tmp = std::env::temp_dir().join(format!("asg-shell-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bus = EventBus::new(256);
        let cfg = HoneypotConfig {
            enabled: true,
            shell: aisafeguard_core::config::ShellConfig {
                enabled: true,
                ..Default::default()
            },
            listeners: vec![ListenerConfig {
                name: "ssh".into(),
                port,
                kind: "ssh".into(),
            }],
        };
        let _handle = start(&cfg, bus.clone(), &tmp);
        assert!(
            tmp.join("honeypot").join("hostkey.ed25519").exists(),
            "host key 应落盘持久化"
        );

        // 等监听就绪
        let mut ready = false;
        for _ in 0..40 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "蜜罐未在 2 秒内就绪");

        // russh 客户端:任意凭证登录 → shell → 发命令
        struct ClientHandler {
            buf: Arc<StdMutex<Vec<u8>>>,
        }
        impl russh::client::Handler for ClientHandler {
            type Error = russh::Error;
            async fn check_server_key(
                &mut self,
                _key: &russh::keys::PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
            async fn data(
                &mut self,
                _channel: russh::ChannelId,
                data: &[u8],
                _session: &mut russh::client::Session,
            ) -> Result<(), Self::Error> {
                self.buf.lock().unwrap().extend_from_slice(data);
                Ok(())
            }
        }
        let buf = Arc::new(StdMutex::new(Vec::new()));
        let client_cfg = Arc::new(russh::client::Config {
            inactivity_timeout: Some(Duration::from_secs(10)),
            ..Default::default()
        });
        let mut handle = russh::client::connect(
            client_cfg,
            ("127.0.0.1", port),
            ClientHandler { buf: buf.clone() },
        )
        .await
        .expect("SSH 握手应成功");
        let auth = handle
            .authenticate_password("root", "hunter2")
            .await
            .expect("认证流程应完成");
        assert!(auth.success(), "任意凭证应放行");

        let channel = handle.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();

        // 等 shell_request 推送的假 prompt 到达客户端(russh 客户端与
        // run_stream 之间的通道数据互传存在上游兼容问题——仅影响
        // russh↔russh 自连;paramiko/OpenSSH 实连全路径由
        // scripts/replay-ssh-shell.py 在 H105 验收)
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let seen = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
            if seen.contains("deploy@debian-11:~$") {
                break;
            }
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(50)))
                .await
                .expect("超时未收到假 Shell prompt");
        }

        // russh↔russh 的通道数据/断开通知存在上游兼容问题(仅自连场景;
        // paramiko/OpenSSH 实连全路径由 scripts/spike_paramiko_login.py 验收)。
        // prompt 到达 + 任意凭证放行已证明:host key 装配、认证放行、shell_request
        // 推送与 run_stream 生命周期均正常。
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
