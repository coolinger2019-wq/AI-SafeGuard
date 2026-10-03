//! banner 级协议会话：发 banner + 读一包 + 清洗记录（低交互边界）。
//! 中交互（认证后的假 Shell 会话）见 H103/H104——本模块永不 fork 真实进程。

use aisafeguard_l7 as l7;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::cred::RawCredential;
use crate::{MAX_PAYLOAD, READ_TIMEOUT, SessionOutcome, read_with_timeout, sanitize};

/// SSH banner 级会话。banner 来自 [honeypot.fingerprint] 或模板覆盖（H320），
/// 发送时自动补 CRLF。
pub(crate) async fn ssh_session(
    s: &mut TcpStream,
    banner: &str,
) -> std::io::Result<SessionOutcome> {
    s.write_all(format!("{banner}\r\n").as_bytes()).await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary =
        l7::first_line(&text).unwrap_or_else(|| "SSH banner 已发送，等待客户端报文".into());
    Ok(SessionOutcome {
        summary,
        payload: text,
        http_hint: None,
        interaction: None,
        credentials: Vec::new(),
    })
}

/// Telnet banner 级会话。greeting 来自 [honeypot.fingerprint] 或模板覆盖，
/// 按配置字面原样发送（默认与 0.5.8 逐字节一致）。
pub(crate) async fn telnet_session(
    s: &mut TcpStream,
    greeting: &str,
) -> std::io::Result<SessionOutcome> {
    s.write_all(greeting.as_bytes()).await?;
    let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
    let text = sanitize(&buf[..n], MAX_PAYLOAD);
    let summary = l7::first_line(&text)
        .map(|l| format!("尝试登录: {l}"))
        .unwrap_or_else(|| "登录提示已发送".into());
    // banner 模式只收到一行 = login 提示后的用户名（无口令），进 H200 凭证库
    let credentials = l7::first_line(&text)
        .map(|user| {
            vec![RawCredential {
                username: user,
                password: None,
            }]
        })
        .unwrap_or_default();
    Ok(SessionOutcome {
        summary,
        payload: text,
        http_hint: None,
        interaction: None,
        credentials,
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
        credentials: Vec::new(),
    })
}
