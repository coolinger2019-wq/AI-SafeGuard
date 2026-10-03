//! RDP 蜜罐（F794a，低交互 v1）：3389 是 Windows 远程入口。X.224 连接协商应答
//! （真服务形态），捕获连接请求里的 mstshash（客户端主机名）与请求的协议栈；
//! 协商后客户端会继续发 MCS/安全交换——只留痕不深入（深入到 ClientInfo 凭证
//! 捕获归后续批次，需 CredSSP/NLA 会话状态）。

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{sanitize, SessionOutcome, MAX_PAYLOAD};

/// 连接请求解析结果
pub(crate) struct ClientHello {
    /// Cookie: mstshash=客户端主机名（客户端自报）
    pub mstshash: Option<String>,
    /// rdp_neg_req 的 requestedProtocols（0x1=SSL 0x2=NLA 0x8=RDSTLS）；无 nego = None
    pub requested_protocols: Option<u32>,
}

/// 解析 X.224 连接请求（CR）：TPKT + CR 头 + 变长段（Cookie / rdp_neg_req）。
pub(crate) fn parse_x224_cr(data: &[u8]) -> Option<ClientHello> {
    // TPKT: 03 00 len-hi len-lo；X.224 CR: li, 1110xxxx（类型 0xE0 掩码低 4 位类选项）
    if data.len() < 12 || data[0] != 3 || data[1] != 0 {
        return None;
    }
    let mut mstshash = None;
    // Cookie: mstshash=hostname\r\n（大小写不敏感）
    if let Some(pos) = data
        .to_ascii_lowercase()
        .windows(17)
        .position(|w| w == b"cookie: mstshash=")
    {
        let start = pos + 17;
        let end = data[start..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .map(|p| start + p)
            .unwrap_or(data.len());
        let name = sanitize(&data[start..end.min(start + 64)], 64);
        if !name.is_empty() {
            mstshash = Some(name);
        }
    }
    // rdp_neg_req：TYPE(0x01) FLAGS LEN(0x0008 LE) PROTOCOLS(4B LE)，通常在 PDU 尾部
    let mut requested_protocols = None;
    if data.len() >= 8 {
        for win in data.windows(8).rev() {
            if win[0] == 0x01 && win[2] == 0x08 && win[3] == 0x00 {
                requested_protocols = Some(u32::from_le_bytes([win[4], win[5], win[6], win[7]]));
                break;
            }
        }
    }
    Some(ClientHello {
        mstshash,
        requested_protocols,
    })
}

/// X.224 连接确认（CC）+ rdp_neg_rsp（选择标准 RDP 安全层——选 NLA/SSL 就要接
/// TLS/CredSSP 会话，低交互 v1 明确不进入）。
pub(crate) fn cc_response(with_nego: bool) -> Vec<u8> {
    let mut out = vec![0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00];
    if with_nego {
        out[2] = 0x00;
        out[3] = 0x13;
        out.extend_from_slice(&[0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
    out
}

pub(crate) async fn rdp_session(s: &mut TcpStream) -> std::io::Result<SessionOutcome> {
    // 读 TPKT：先 4 字节头，再按长度取 X.224 PDU
    let mut head = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut head))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timeout",
        )))?;
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    if head[0] != 3 || head[1] != 0 || !(11..=8192).contains(&len) {
        // 非 TPKT：按垃圾留痕，不应答
        let mut raw = head.to_vec();
        let mut chunk = vec![0u8; 256];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), s.read(&mut chunk)).await {
            raw.extend_from_slice(&chunk[..n]);
        }
        return Ok(SessionOutcome {
            summary: crate::request_summary(&crate::sanitize(&raw, 160), "非 RDP/TPKT 数据"),
            payload: crate::sanitize(&raw, MAX_PAYLOAD),
            http_hint: None,
            interaction: None,
            credentials: Vec::new(),
        });
    }
    let mut pdu = vec![0u8; len - 4];
    s.read_exact(&mut pdu).await?;
    let mut full = head.to_vec();
    full.extend_from_slice(&pdu);

    let hello = parse_x224_cr(&full);
    let with_nego = hello
        .as_ref()
        .map(|h| h.requested_protocols.is_some())
        .unwrap_or(false);
    let cc = cc_response(with_nego);
    s.write_all(&cc).await?;

    let client = hello
        .as_ref()
        .and_then(|h| h.mstshash.clone())
        .unwrap_or_else(|| "未知客户端".into());
    let protos = hello
        .as_ref()
        .map(|h| h.requested_protocols.unwrap_or(0))
        .unwrap_or(0);
    let proto_label = match protos {
        0x2 => "NLA/CredSSP",
        0x1 => "TLS",
        _ => "标准RDP",
    };

    // 协商后客户端继续发 MCS/安全交换——读一段留痕（不深入），然后收场
    let mut followup = Vec::new();
    let mut chunk = vec![0u8; 1024];
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk)).await {
        followup.extend_from_slice(&chunk[..n]);
    }

    Ok(SessionOutcome {
        summary: format!("RDP 连接协商: client={client} 协议={proto_label}"),
        payload: crate::sanitize(
            &redact(&full, &followup),
            MAX_PAYLOAD,
        ),
        http_hint: None,
        interaction: Some(vec![
            aisafeguard_core::event::ShellStep {
                command: "x224-cr".into(),
                response: format!("client={client} proto={protos:#x}"),
            },
            aisafeguard_core::event::ShellStep {
                command: "x224-cc".into(),
                response: if with_nego { "neg_rsp PROTOCOL_RDP" } else { "plain" }.into(),
            },
        ]),
        credentials: Vec::new(),
    })
}

fn redact(head: &[u8], followup: &[u8]) -> Vec<u8> {
    // mstshash 是客户端自报主机名，非敏感；整体清洗截断即可
    let mut all = head.to_vec();
    all.extend_from_slice(followup);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cr_with_cookie_and_nego() {
        // 手工构造：TPKT + CR(li) + type/class + cookie + rdp_neg_req
        let cookie = b"Cookie: mstshash=kali-attacker\r\n";
        let neg = [0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]; // SSL|NLA
        let mut pdu = vec![0xe0, 0x00, 0x00, 0x00, 0x00];
        pdu.extend_from_slice(cookie);
        pdu.extend_from_slice(&neg);
        let li = pdu.len() as u8;
        let mut data = vec![0x03, 0x00];
        data.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
        data.push(li);
        data.extend_from_slice(&pdu);

        let hello = parse_x224_cr(&data).expect("应解析成功");
        assert_eq!(hello.mstshash.as_deref(), Some("kali-attacker"));
        assert_eq!(hello.requested_protocols, Some(0x3));
    }

    #[test]
    fn cc_response_shape() {
        let plain = cc_response(false);
        assert_eq!(plain[..4], [0x03, 0x00, 0x00, 0x0b]);
        assert_eq!(plain[5], 0xd0);
        let nego = cc_response(true);
        assert_eq!(nego[..4], [0x03, 0x00, 0x00, 0x13]);
        assert_eq!(&nego[11..15], &[0x02, 0x00, 0x08, 0x00]);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_x224_cr(b"not rdp data at all!").is_none());
        assert!(parse_x224_cr(&[0x03, 0x00]).is_none());
    }

    /// 线上探针字节复现（探针把 li 位置写成了 0xe0 的畸形结构）——
    /// 按 F794b② 约定：检测向量逐字节钉住。
    #[test]
    fn probe_exact_live_bytes() {
        let cr: Vec<u8> = [
            0x03u8, 0x00, 0x00, 0x2e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
        .into_iter()
        .chain(b"Cookie: mstshash=kali-probe\r\n".iter().copied())
        .chain([0x01u8, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00])
        .collect();
        let hello = parse_x224_cr(&cr).expect("探针结构应解析");
        assert_eq!(hello.mstshash.as_deref(), Some("kali-probe"));
        assert_eq!(
            hello.requested_protocols,
            Some(0x3),
            "neg 应在畸形 li 下仍被识别"
        );
    }
}
