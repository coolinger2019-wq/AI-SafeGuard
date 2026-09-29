//! H101 spike:russh(ring 后端)最小 SSH 服务端——验证供应链门禁与真实客户端互通。
//!
//! 运行:`cargo run -p aisafeguard-honeypot --example ssh_shell_spike`
//! 验收:`python scripts/spike_paramiko_login.py`
//! 退出标准:任意凭证登录成功 + shell channel 收到 prompt + 命令有响应。
//! 这是 spike:凭证任意放行、无事件落库、host key 不持久化,H104 接线时全部替换。

use std::sync::Arc;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Pty};

const BIND_ADDR: &str = "127.0.0.1:2223";
const PROMPT: &str = "spike@aisafeguard:~$ ";

#[derive(Clone)]
struct SpikeServer;

struct SpikeHandler;

impl russh::server::Server for SpikeServer {
    type Handler = SpikeHandler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        SpikeHandler
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
        session.data(channel, PROMPT.as_bytes())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data);
        let cmd = cmd.trim_end_matches(['\r', '\n']);
        eprintln!("[data] {cmd:?}");
        if cmd == "exit" {
            return Err(russh::Error::Disconnect);
        }
        let resp = format!("bash: {cmd}: command not found\r\n{PROMPT}");
        session.data(channel, resp.into_bytes())?;
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
