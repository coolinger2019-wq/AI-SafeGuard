//! H101/H103 spike:russh(ring 后端)最小 SSH 服务端 + 假 Shell 命令仿真层实连验证。
//!
//! 运行:`cargo run -p aisafeguard-honeypot --example ssh_shell_spike`
//! 验收:`python scripts/spike_paramiko_login.py`
//! H104 将把本示例的 handler 迁入正式监听器([honeypot.shell] 配置、host key
//! 持久化、认证事件留痕),示例本身在接线完成后移除。

use std::sync::Arc;

use aisafeguard_honeypot::shell::{ShellAction, ShellSession};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Pty};

const BIND_ADDR: &str = "127.0.0.1:2223";

#[derive(Clone)]
struct SpikeServer;

struct SpikeHandler {
    shell: tokio::sync::Mutex<ShellSession>,
    line: tokio::sync::Mutex<String>,
}

impl russh::server::Server for SpikeServer {
    type Handler = SpikeHandler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        SpikeHandler {
            shell: tokio::sync::Mutex::new(ShellSession::new("deploy", "debian-11", 50)),
            line: tokio::sync::Mutex::new(String::new()),
        }
    }
}

impl Handler for SpikeHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // spike:任意凭证放行。只留长度不留值,避免口令进日志的习惯残留。
        eprintln!("[auth] user={user:?} password_len={}", password.len());
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col: u32,
        _row: u32,
        _pix_w: u32,
        _pix_h: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let shell = self.shell.lock().await;
        session.data(channel, format!("\r\n{}\r\n", shell.prompt()).into_bytes())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // PTY 行组装:回显可见字符,退格删字符,\r 提交行进仿真层
        let mut line = self.line.lock().await;
        for &b in data {
            match b {
                b'\r' | b'\n' => {
                    session.data(channel, b"\r\n".to_vec())?;
                    let committed = std::mem::take(&mut *line);
                    drop(line);
                    let action = self.shell.lock().await.handle_line(&committed);
                    let close = match action {
                        ShellAction::Reply(text) => {
                            if !text.is_empty() {
                                session.data(channel, text.replace('\n', "\r\n").into_bytes())?;
                            }
                            session.data(channel, b"\r\n".to_vec())?;
                            false
                        }
                        ShellAction::Exit => true,
                    };
                    let shell = self.shell.lock().await;
                    if close {
                        session.data(channel, b"logout\r\n".to_vec())?;
                        return Err(russh::Error::Disconnect);
                    }
                    session.data(channel, format!("{}\r\n", shell.prompt()).into_bytes())?;
                    // 重新接管行缓冲锁(处理同一批剩余字节前重排作用域)
                    line = self.line.lock().await;
                }
                0x7f | 0x08 => {
                    if line.pop().is_some() {
                        session.data(channel, b"\x08 \x08".to_vec())?;
                    }
                }
                0x03 => {
                    // Ctrl+C:丢弃当前行,出新 prompt
                    line.clear();
                    session.data(channel, b"^C\r\n".to_vec())?;
                    let shell = self.shell.lock().await;
                    session.data(channel, format!("{}\r\n", shell.prompt()).into_bytes())?;
                }
                0x20..=0x7e | b'\t' => {
                    line.push(b as char);
                    session.data(channel, vec![b])?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(120)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?],
        ..Default::default()
    };
    let socket = tokio::net::TcpListener::bind(BIND_ADDR).await?;
    println!("spike sshd listening on {BIND_ADDR}");
    let mut server = SpikeServer;
    server.run_on_socket(Arc::new(config), &socket).await?;
    Ok(())
}
