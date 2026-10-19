//! RDP 蜜罐（F794a 低交互 v1 + F799 NLA 凭证捕获）：3389 是 Windows 远程入口。
//! v1：X.224 连接协商应答（真服务形态），捕获 mstshash（客户端主机名）与请求协议栈。
//! F799：客户端请求 NLA（PROTOCOL_HYBRID）时——自签证书接 TLS（真客户端协商 NLA
//! 后下一个字节就是 TLS ClientHello，没有 TLS 永远停在协商外），CredSSP/TSRequest
//! 里应 NTLMSSP type2 挑战、解析 type3（user/domain/workstation，UTF-16LE），
//! 回 SEC_E_LOGON_DENIED 收场。NTLMv2 响应是不可逆 scramble——口令 None，与
//! SMB/MySQL 同红线（明文永不落盘）。NTLM 核心复用 smb.rs（协议同源）。

use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::{TlsAcceptor, rustls};

use crate::{MAX_PAYLOAD, SessionOutcome, sanitize};

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

/// X.224 连接确认（CC）+ rdp_neg_rsp。select = None（纯 RDP，无 nego 块）或
/// 选定的协议（NLA=0x2 时客户端随后发 TLS ClientHello）。
pub(crate) fn cc_response(select: Option<u32>) -> Vec<u8> {
    let mut out = vec![
        0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
    ];
    if let Some(proto) = select {
        out[2] = 0x00;
        out[3] = 0x13;
        out.extend_from_slice(&[0x02, 0x00, 0x08, 0x00]);
        out.extend_from_slice(&proto.to_le_bytes());
    }
    out
}

// ---------- F799：TSRequest（MS-CSSP）最小 DER ----------
// 结构：SEQUENCE { version [0] INTEGER, negoTokens [1] EXPLICIT SEQUENCE OF
// OCTET STRING, … errorCode [4] INTEGER }。只实现我们要说/要听的三种形态；
// 客户端真实编码（definite 长短形）实测与 MS-CSSP 一致。

fn der_len_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// 读一个 TLV 的长度域，返回 (长度, 长度域字节数)。
fn der_read_len(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *buf.get(pos)?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 2 {
            return None;
        }
        let bytes: Vec<u8> = buf.get(pos + 1..pos + 1 + n)?.to_vec();
        Some((
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize),
            n + 1,
        ))
    }
}

/// 服务端 TSRequest：version=2 + negoTokens=[NTLM blob]。
fn tsrequest_nego(ntlm: &[u8]) -> Vec<u8> {
    let mut ntlm_tlv = vec![0x04];
    ntlm_tlv.extend(der_len_bytes(ntlm.len()));
    ntlm_tlv.extend_from_slice(ntlm);
    let mut seq = vec![0x30];
    seq.extend(der_len_bytes(ntlm_tlv.len()));
    seq.extend_from_slice(&ntlm_tlv);
    let mut a1 = vec![0xA1];
    a1.extend(der_len_bytes(seq.len()));
    a1.extend_from_slice(&seq);
    let mut out = vec![0x30];
    out.extend(der_len_bytes(5 + a1.len()));
    out.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
    out.extend_from_slice(&a1);
    out
}

/// 服务端 TSRequest：version + errorCode（NLA 凭证拒绝 = SEC_E_LOGON_DENIED）。
fn tsrequest_error(code: u32) -> Vec<u8> {
    let int = [
        0x02,
        0x04,
        (code >> 24) as u8,
        (code >> 16) as u8,
        (code >> 8) as u8,
        code as u8,
    ];
    let mut a4 = vec![0xA4];
    a4.extend(der_len_bytes(int.len()));
    a4.extend_from_slice(&int);
    let mut out = vec![0x30];
    out.extend(der_len_bytes(5 + a4.len()));
    out.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
    out.extend_from_slice(&a4);
    out
}

/// 客户端 TSRequest → negoTokens 里第一个 NTLM blob。
fn parse_nego_blob(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.first() != Some(&0x30) {
        return None;
    }
    let (_, outer_used) = der_read_len(frame, 1)?;
    let end = (1 + outer_used + der_read_len(frame, 1)?.0).min(frame.len());
    // EXPLICIT 包装：0x04 嵌在 [1]→SEQUENCE 层里——递归下钻
    der_find_octet(&frame[1 + outer_used..end])
}

fn der_find_octet(buf: &[u8]) -> Option<Vec<u8>> {
    let mut j = 0usize;
    while j + 2 <= buf.len() {
        let tag = buf[j];
        let (tl, tu) = der_read_len(buf, j + 1)?;
        let bs = j + 1 + tu;
        let be = (bs + tl).min(buf.len());
        if tag == 0x04 {
            return Some(buf[bs..be].to_vec());
        }
        if tag == 0x30 || tag == 0xA1 {
            if let Some(found) = der_find_octet(&buf[bs..be]) {
                return Some(found);
            }
        }
        j = be;
    }
    None
}

/// NTLM 消息类型（blob 以 NTLMSSP\0 开头时）。
fn ntlm_msg_type(blob: &[u8]) -> Option<u32> {
    if blob.len() >= 12 && &blob[..8] == b"NTLMSSP\0" {
        Some(u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]))
    } else {
        None
    }
}

/// TLS 接受器：自签证书进程内一次（蜜罐身份不落盘；mstsc 会弹证书警告——
/// 无关紧要，这扇门本来就不给正常人开）。初始化失败 = NLA 捕获不可用，
/// 退回 v1 记录行为，绝不影响监听器存活。
fn tls_acceptor() -> Option<TlsAcceptor> {
    static ACCEPTOR: OnceLock<Option<TlsAcceptor>> = OnceLock::new();
    ACCEPTOR
        .get_or_init(|| {
            let key = rcgen::KeyPair::generate().ok()?;
            let mut params = rcgen::CertificateParams::new(vec!["aisafeguard-rdp".into()]).ok()?;
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "aisafeguard-rdp");
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
            params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
            let cert = params.self_signed(&key).ok()?;
            let cfg = rustls::ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .ok()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .ok()?;
            Some(TlsAcceptor::from(std::sync::Arc::new(cfg)))
        })
        .clone()
}

/// TLS 内读一帧 DER（CredSSP 消息不带 TPKT 头）；EOF/超时/非 SEQUENCE → None。
async fn read_der_frame<S>(s: &mut S) -> std::io::Result<Option<Vec<u8>>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = [0u8; 2];
    if tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut head))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timeout",
        )))
        .is_err()
    {
        return Ok(None);
    }
    if head[0] != 0x30 {
        return Ok(None);
    }
    let content_len = if head[1] < 0x80 {
        head[1] as usize
    } else {
        match head[1] {
            0x81 => {
                let mut b = [0u8; 1];
                s.read_exact(&mut b).await?;
                b[0] as usize
            }
            0x82 => {
                let mut b = [0u8; 2];
                s.read_exact(&mut b).await?;
                u16::from_be_bytes(b) as usize
            }
            _ => return Ok(None),
        }
    };
    let mut content = vec![0u8; content_len];
    if tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut content))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timeout",
        )))
        .is_err()
    {
        return Ok(None);
    }
    let mut frame = head.to_vec();
    frame.extend_from_slice(&content);
    Ok(Some(frame))
}

pub(crate) async fn rdp_session(stream: TcpStream) -> std::io::Result<SessionOutcome> {
    let mut s = stream;
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
    // 慢连接防护：帧体与包头同一超时
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut pdu)).await??;
    let mut full = head.to_vec();
    full.extend_from_slice(&pdu);

    let hello = parse_x224_cr(&full);
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
    let wants_nla = protos & 0x2 != 0;

    // 请求了 NLA 就选 NLA（selectedProtocol=0x2）——客户端随后发 TLS ClientHello
    let cc = cc_response(wants_nla.then_some(0x2));
    s.write_all(&cc).await?;

    let mut interaction = vec![
        aisafeguard_core::event::ShellStep {
            command: "x224-cr".into(),
            response: format!("client={client} proto={protos:#x}"),
        },
        aisafeguard_core::event::ShellStep {
            command: "x224-cc".into(),
            response: if wants_nla {
                "neg_rsp NLA/CredSSP".into()
            } else {
                "plain".into()
            },
        },
    ];

    if wants_nla {
        if let Some(acceptor) = tls_acceptor() {
            return nla_phase(s, acceptor, full, client, interaction).await;
        }
        // TLS 初始化失败：退回 v1 记录行为
        interaction.push(aisafeguard_core::event::ShellStep {
            command: "credssp-tls".into(),
            response: "TLS 初始化失败，退回记录模式".into(),
        });
    }

    // 协商后客户端继续发后续数据——读一段留痕（不深入），然后收场
    let mut followup = Vec::new();
    let mut chunk = vec![0u8; 1024];
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), s.read(&mut chunk)).await {
        followup.extend_from_slice(&chunk[..n]);
    }

    Ok(SessionOutcome {
        summary: format!("RDP 连接协商: client={client} 协议={proto_label}"),
        payload: crate::sanitize(&redact(&full, &followup), MAX_PAYLOAD),
        http_hint: None,
        interaction: Some(interaction),
        credentials: Vec::new(),
    })
}

/// NLA 阶段：TLS（自签证书）里走 CredSSP——type1 应 type2 挑战，type3 解析凭证
/// 后回 LOGON_DENIED。成功（对我们而言是蜜罐目标达成）即收场。
async fn nla_phase(
    s: TcpStream,
    acceptor: TlsAcceptor,
    full: Vec<u8>,
    client: String,
    mut interaction: Vec<aisafeguard_core::event::ShellStep>,
) -> std::io::Result<SessionOutcome> {
    let tls = match acceptor.accept(s).await {
        Ok(tls) => {
            interaction.push(aisafeguard_core::event::ShellStep {
                command: "credssp-tls".into(),
                response: "自签证书 TLS 握手完成".into(),
            });
            tls
        }
        Err(e) => {
            interaction.push(aisafeguard_core::event::ShellStep {
                command: "credssp-tls".into(),
                response: format!("TLS 握手失败: {e}"),
            });
            return Ok(SessionOutcome {
                summary: format!("RDP 连接协商: client={client} 协议=NLA/CredSSP（TLS 失败）"),
                payload: crate::sanitize(&full, MAX_PAYLOAD),
                http_hint: None,
                interaction: Some(interaction),
                credentials: Vec::new(),
            });
        }
    };
    // TLS 建立后 s 已被 move 进 tls——后续全部走 tls
    let mut tls = tls;
    let mut credentials = Vec::new();
    let mut note = String::new();
    // 正常 NLA 两轮（type1→type2→type3），留一档余量防工具重复发包
    for _ in 0..4 {
        let Some(frame) = read_der_frame(&mut tls).await? else {
            note = "客户端在 CredSSP 中途断开".into();
            break;
        };
        let Some(blob) = parse_nego_blob(&frame) else {
            note = "TSRequest 解析失败".into();
            interaction.push(aisafeguard_core::event::ShellStep {
                command: "credssp-parse".into(),
                response: crate::sanitize(&frame, 80),
            });
            break;
        };
        match ntlm_msg_type(&blob) {
            Some(1) => {
                let challenge = rand::random::<[u8; 8]>();
                let type2 = crate::smb::build_ntlm_type2(&challenge, "TERMSRV", "AISAFEGUARD");
                tls.write_all(&tsrequest_nego(&type2)).await?;
                interaction.push(aisafeguard_core::event::ShellStep {
                    command: "credssp-nego".into(),
                    response: "NTLMSSP type1 → type2 挑战".into(),
                });
            }
            Some(3) => {
                if let Some(t3) = crate::smb::parse_ntlm_type3(&blob) {
                    interaction.push(aisafeguard_core::event::ShellStep {
                        command: "credssp-auth".into(),
                        response: format!(
                            "user={} domain={} ws={} ntlmv2={} (LOGON_DENIED)",
                            t3.user, t3.domain, t3.workstation, t3.ntlmv2
                        ),
                    });
                    // NTLMv2 响应是不可逆 scramble——口令 None，用户名/域名照采
                    credentials.push(crate::cred::RawCredential {
                        username: t3.user.clone(),
                        password: None,
                    });
                    note = format!(
                        "凭证捕获: user={} domain={} ws={}",
                        t3.user, t3.domain, t3.workstation
                    );
                }
                tls.write_all(&tsrequest_error(0x8009_030C)).await?;
                break;
            }
            _ => {
                note = "非 NTLM 载荷".into();
                break;
            }
        }
    }

    let summary = if credentials.is_empty() {
        if note.is_empty() {
            format!("RDP NLA 会话: client={client}（未到凭证阶段）")
        } else {
            format!("RDP NLA 会话: client={client} {note}")
        }
    } else {
        format!("RDP NLA 凭证捕获: client={client} {note}（LOGON_DENIED）")
    };
    Ok(SessionOutcome {
        summary,
        payload: crate::sanitize(&full, MAX_PAYLOAD),
        http_hint: None,
        interaction: Some(interaction),
        credentials,
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
        data.extend_from_slice(&((pdu.len() + 5) as u16).to_be_bytes()); // TPKT 长度含 4 字节头（RFC1006）
        data.push(li);
        data.extend_from_slice(&pdu);

        let hello = parse_x224_cr(&data).expect("应解析成功");
        assert_eq!(hello.mstshash.as_deref(), Some("kali-attacker"));
        assert_eq!(hello.requested_protocols, Some(0x3));
    }

    #[test]
    fn cc_response_selects_nla() {
        let plain = cc_response(None);
        assert_eq!(plain[..4], [0x03, 0x00, 0x00, 0x0b]);
        assert_eq!(plain[5], 0xd0);
        assert_eq!(plain.len(), 11);
        let nla = cc_response(Some(0x2));
        assert_eq!(nla[..4], [0x03, 0x00, 0x00, 0x13]);
        // nego 块：type(02) flags(00) len(08 00) selected(02 00 00 00)
        assert_eq!(&nla[11..15], &[0x02, 0x00, 0x08, 0x00]);
        assert_eq!(&nla[15..19], &[0x02, 0x00, 0x00, 0x00]);
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
        let cr: Vec<u8> = [0x03u8, 0x00, 0x00, 0x2e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00]
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

    #[test]
    fn tsrequest_nego_byte_shape_and_roundtrip() {
        let blob: Vec<u8> = b"NTLMSSP\0"
            .iter()
            .copied()
            .chain([0x02, 0x00, 0x00, 0x00])
            .chain((0..=0x2F).collect::<Vec<u8>>())
            .collect();
        let resp = tsrequest_nego(&blob);
        // 逐字节钉形状：30 <len> a0 03 02 01 02 a1 <len> 30 <len> 04 <len> NTLMSSP\0
        assert_eq!(resp[0], 0x30);
        assert_eq!(&resp[2..7], &[0xA0, 0x03, 0x02, 0x01, 0x02]);
        assert_eq!(resp[7], 0xA1);
        assert_eq!(resp[9], 0x30);
        // 找到 OCTET STRING(04) 的位置：其长度域后紧跟 NTLMSSP 签名
        let pos04 = resp
            .windows(2)
            .position(|w| w == [0x04, blob.len() as u8])
            .expect("应有 04 <len> 标记");
        assert_eq!(&resp[pos04 + 2..pos04 + 10], b"NTLMSSP\0");
        // 长度 < 0x80 时用短形——blob 71 字节 > 127? 71<0x80 → 04 <71>
        // 回放往返：解析自己生成的事实必须原样取回
        assert_eq!(parse_nego_blob(&resp).unwrap(), blob);
        // 客户端形态（手工构造）：30 14 a0 03 02 01 02 a1 0d 30 0b 04 09 <9B>
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut client = vec![
            0x30, 0x14, 0xA0, 0x03, 0x02, 0x01, 0x02, 0xA1, 0x0D, 0x30, 0x0B, 0x04, 0x09,
        ];
        client.extend_from_slice(&payload);
        assert_eq!(parse_nego_blob(&client).unwrap(), payload);
    }

    #[test]
    fn tsrequest_error_shape() {
        let e = tsrequest_error(0x8009_030C);
        assert_eq!(e[0], 0x30);
        assert_eq!(&e[2..7], &[0xA0, 0x03, 0x02, 0x01, 0x02]);
        assert_eq!(e[7], 0xA4);
        // 尾部：02 04 80 09 03 0c
        assert_eq!(&e[e.len() - 6..], &[0x02, 0x04, 0x80, 0x09, 0x03, 0x0C]);
    }

    #[test]
    fn tsrequest_long_form_roundtrip() {
        // 212 字节 blob → 长形长度域（0x82）双层嵌套
        let blob: Vec<u8> = b"NTLMSSP\0"
            .iter()
            .copied()
            .chain((0..200u8).collect::<Vec<u8>>())
            .collect();
        let resp = tsrequest_nego(&blob);
        assert_eq!(parse_nego_blob(&resp).unwrap(), blob);
        // 600 字节载荷 → 外层 0x82 两字节长形
        let big: Vec<u8> = (0..600).map(|i| (i % 256) as u8).collect();
        let resp2 = tsrequest_nego(&big);
        assert_eq!(parse_nego_blob(&resp2).unwrap(), big);
    }

    #[test]
    fn ntlm_msg_type_discriminates() {
        let t1 = [b"NTLMSSP\0".as_slice(), &1u32.to_le_bytes()].concat();
        let t3 = [b"NTLMSSP\0".as_slice(), &3u32.to_le_bytes()].concat();
        assert_eq!(ntlm_msg_type(&t1), Some(1));
        assert_eq!(ntlm_msg_type(&t3), Some(3));
        assert_eq!(ntlm_msg_type(b"garbage!"), None);
        assert_eq!(ntlm_msg_type(b"NTLMSSP\0"), None); // 不足 12 字节
    }

    /// type3 端到端：手工构造带 user="admin" 的 type3 → 包进 TSRequest →
    /// 解析取回 → smb 的 parse_ntlm_type3 能读出用户名（DER 壳不得破坏 NTLM 体）。
    #[test]
    fn type3_end_to_end_through_der() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"NTLMSSP\0");
        blob.extend_from_slice(&3u32.to_le_bytes());
        // lm(8) ntlm(8) domain(8) user(8) ws(8) + flags(4)
        blob.extend_from_slice(&[0u8; 8]); // lm len/max 0
        blob.extend_from_slice(&[0u8; 8]); // ntlm len/max 0
        blob.extend_from_slice(&[0u8; 8]); // domain len/max 0, offset 0
        let user_u16: Vec<u8> = "admin"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        blob.extend_from_slice(&(user_u16.len() as u16).to_le_bytes());
        blob.extend_from_slice(&(user_u16.len() as u16).to_le_bytes());
        blob.extend_from_slice(&(56u32).to_le_bytes()); // user offset=56（8+4+8×4 后的字节位）
        blob.extend_from_slice(&[0u8; 8]); // ws
        blob.extend_from_slice(&[0u8; 4]); // flags
        while blob.len() < 48 {
            blob.push(0);
        }
        blob.extend_from_slice(&user_u16);
        assert_eq!(crate::smb::parse_ntlm_type3(&blob).unwrap().user, "admin");
        // 包进 DER 再解出，必须等值
        let wrapped = tsrequest_nego(&blob);
        assert_eq!(parse_nego_blob(&wrapped).unwrap(), blob);
        assert_eq!(
            crate::smb::parse_ntlm_type3(&parse_nego_blob(&wrapped).expect("DER 解析"))
                .unwrap()
                .user,
            "admin"
        );
    }
}
