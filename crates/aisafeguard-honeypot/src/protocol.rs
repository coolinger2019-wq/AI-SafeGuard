//! banner 级协议会话：发 banner + 读一包 + 清洗记录（低交互边界）。
//! 中交互（认证后的假 Shell 会话）见 H103/H104——本模块永不 fork 真实进程。

use aisafeguard_l7 as l7;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::{READ_TIMEOUT, MAX_PAYLOAD, SessionOutcome, read_with_timeout, sanitize};

pub(crate) async fn ssh_session(s: &mut TcpStream) -> std::io::Result<SessionOutcome> {
    s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary =
        l7::first_line(&text).unwrap_or_else(|| "SSH banner 已发送，等待客户端报文".into());
    Ok(SessionOutcome {
        summary,
        payload: text,
        http_hint: None,
        interaction: None,
    })
}

pub(crate) async fn telnet_session(s: &mut TcpStream) -> std::io::Result<SessionOutcome> {
    s.write_all(b"Welcome to Ubuntu 22.04 LTS\r\nlogin: ")
        .await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = l7::first_line(&text)
        .map(|l| format!("尝试登录: {l}"))
        .unwrap_or_else(|| "登录提示已发送".into());
    Ok(SessionOutcome {
        summary,
        payload: text,
        http_hint: None,
        interaction: None,
    })
}

pub(crate) async fn generic_session(s: &mut TcpStream) -> std::io::Result<SessionOutcome> {
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = crate::request_summary(&text, "仅建立连接，未发送数据");
    Ok(SessionOutcome {
        summary,
        payload: text,
        http_hint: None,
        interaction: None,
    })
}
