//! SMB2 蜜罐（F794a，低交互）：445 是 Windows 内网横向第一通道（凭据投递/
//! 勒索软件落地的必经之路）。NBSS + SMB2 协商（选 2.0.2 方言，不进 preauth
//! 完整性）+ Session Setup 的 NTLMSSP 挑战——捕获攻击者自报的 user/domain/
//! workstation 与 NTLMv2 响应（TTP 与可归因材料），随后 STATUS_LOGON_FAILURE
//! 拒绝（不开放任何文件面）。凭证只进事件载荷，不进凭证库（NTLMv2 非口令
//! 明文，argon2 模型不适用；可归因材料的存储设计归后续批次单独拍板）。

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{sanitize, SessionOutcome, MAX_PAYLOAD};

const COMPUTER: &str = "prod-app-01";
const DOMAIN: &str = "PROD";
/// dialect = SMB 2.0.2（无 preauth integrity 上下文，结构最简）
const DIALECT_202: u16 = 0x0202;
const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_SUCCESS: u32 = 0;

/// NTLMSSP type3 解析结果（攻击者自报 + 可归因响应材料）
pub(crate) struct Type3Info {
    pub user: String,
    pub domain: String,
    pub workstation: String,
    pub ntlmv2: String,
}

/// SMB1 COM_NEGOTIATE（0x72）方言列表解析（F794 补丁）：仍在对 445 说 SMB1 的
/// 客户端不少见，方言列表（LANMAN1.0/LM1.2X002 等）是客户端工具指纹。
/// msg = NBSS(4) + SMB1 头(32) + WordCount(1) + ByteCount(2) + [0x02 + null 结尾名]×N。
pub(crate) fn parse_smb1_dialects(msg: &[u8]) -> Vec<String> {
    if msg.len() < 39 || msg[4..8] != [0xFF, b'S', b'M', b'B'] || msg[8] != 0x72 {
        return Vec::new();
    }
    let byte_count = u16le(msg, 37) as usize;
    let end = (39 + byte_count).min(msg.len());
    let mut out = Vec::new();
    let mut i = 39;
    while i < end && out.len() < 8 {
        if msg[i] != 0x02 {
            break;
        }
        i += 1;
        let start = i;
        while i < end && msg[i] != 0x00 {
            i += 1;
        }
        let name = sanitize(&msg[start..i], 32);
        if !name.is_empty() {
            out.push(name);
        }
        i += 1; // 跳过结尾 NUL
    }
    out
}

fn utf16le(bytes: &[u8]) -> String {
    let (pairs, _) = bytes.as_chunks::<2>();
    String::from_utf16_lossy(
        &pairs.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<u16>>(),
    )
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// 解析 NTLMSSP AUTH（type3）：user/domain/workstation（UTF-16LE）+ NTLMv2 响应。
pub(crate) fn parse_ntlm_type3(blob: &[u8]) -> Option<Type3Info> {
    if blob.len() < 64 || &blob[..8] != b"NTLMSSP\0" || u32le(blob, 8) != 3 {
        return None;
    }
    let field = |len_at: usize| {
        let len = u16le(blob, len_at) as usize;
        let off = u32le(blob, len_at + 4) as usize;
        if off >= blob.len() || len == 0 || off + len > blob.len() {
            None
        } else {
            Some(&blob[off..off + len])
        }
    };
    let ntlm = field(20).unwrap_or(&[]);
    let domain = field(28).map(utf16le).unwrap_or_default();
    let user = field(36).map(utf16le).unwrap_or_default();
    let ws = field(44).map(utf16le).unwrap_or_default();
    Some(Type3Info {
        user: sanitize(user.as_bytes(), 64),
        domain: sanitize(domain.as_bytes(), 64),
        workstation: sanitize(ws.as_bytes(), 64),
        ntlmv2: hex(&ntlm[..ntlm.len().min(48)]),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// NTLMSSP CHALLENGE（type2）：目标名 + AV pairs + 服务器挑战。
pub(crate) fn build_ntlm_type2(challenge: &[u8; 8], target: &str, computer: &str) -> Vec<u8> {
    let target_u16: Vec<u8> = target.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let comp_u16: Vec<u8> = computer.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let dom_u16: Vec<u8> = DOMAIN.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut av = Vec::new();
    for (t, v) in [(1u16, &comp_u16), (2u16, &dom_u16)] {
        av.extend_from_slice(&t.to_le_bytes());
        av.extend_from_slice(&(v.len() as u16).to_le_bytes());
        av.extend_from_slice(v);
    }
    av.extend_from_slice(&[0, 0, 0, 0]); // MsvAvEOL

    let mut out = Vec::new();
    out.extend_from_slice(b"NTLMSSP\0");
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(target_u16.len() as u16).to_le_bytes());
    out.extend_from_slice(&(target_u16.len() as u16).to_le_bytes());
    out.extend_from_slice(&48u32.to_le_bytes()); // TargetNameOffset（固定头 48B 后）
    // UNICODE | REQUEST_TARGET | NTLM | TARGET_INFO
    out.extend_from_slice(&0x0080_0205u32.to_le_bytes());
    out.extend_from_slice(challenge);
    out.extend_from_slice(&[0u8; 8]);
    let info_off = 48 + target_u16.len();
    out.extend_from_slice(&(av.len() as u16).to_le_bytes());
    out.extend_from_slice(&(av.len() as u16).to_le_bytes());
    out.extend_from_slice(&(info_off as u32).to_le_bytes());
    out.extend_from_slice(&target_u16);
    out.extend_from_slice(&av);
    out
}

/// SMB2 头（64B）：魔数/命令/状态/标志/会话 id 语义集中在一个构造器里。
fn smb2_header(command: u16, status: u32, session_id: u64, message_id: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(&[0xfe, b'S', b'M', b'B']);
    h.extend_from_slice(&64u16.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&status.to_le_bytes());
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes()); // Credits granted
    h.extend_from_slice(&1u32.to_le_bytes()); // Flags: SERVER_TO_REDIR
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&message_id.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&session_id.to_le_bytes());
    h.extend_from_slice(&[0u8; 16]); // Signature
    h
}

/// NEGOTIATE 响应：选 2.0.2 方言 + NTLMSSP 挑战 blob。
pub(crate) fn build_negotiate_response(
    challenge: &[u8; 8],
    session_id: u64,
    message_id: u64,
) -> Vec<u8> {
    let blob = build_ntlm_type2(challenge, DOMAIN, COMPUTER);
    let mut r = smb2_header(0, STATUS_SUCCESS, session_id, message_id);
    r.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    r.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    r.extend_from_slice(&DIALECT_202.to_le_bytes());
    r.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    let guid: [u8; 16] = rand::random();
    r.extend_from_slice(&guid);
    r.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    r.extend_from_slice(&65536u32.to_le_bytes()); // MaxTransaction
    r.extend_from_slice(&65536u32.to_le_bytes()); // MaxRead
    r.extend_from_slice(&65536u32.to_le_bytes()); // MaxWrite
    let now = filetime_now();
    r.extend_from_slice(&now.to_le_bytes());
    r.extend_from_slice(&now.to_le_bytes()); // ServerStartTime
    r.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset（64 头 + 64 固定结构）
    r.extend_from_slice(&(blob.len() as u16).to_le_bytes()); // SecurityBufferLength
    r.extend_from_slice(&0u32.to_le_bytes());
    r.extend_from_slice(&blob);
    r
}

/// SESSION_SETUP 响应：MORE_PROCESSING（带挑战）或 LOGON_FAILURE。
pub(crate) fn build_session_setup_response(
    status: u32,
    blob: Option<&[u8]>,
    session_id: u64,
    message_id: u64,
) -> Vec<u8> {
    let mut r = smb2_header(1, status, session_id, message_id);
    r.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    r.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
    let off = 72u16;
    match blob {
        Some(b) => {
            r.extend_from_slice(&(off).to_le_bytes());
            r.extend_from_slice(&(b.len() as u16).to_le_bytes());
            while r.len() < off as usize {
                r.push(0);
            }
            r.extend_from_slice(b);
        }
        None => {
            r.extend_from_slice(&0u16.to_le_bytes());
            r.extend_from_slice(&0u16.to_le_bytes());
        }
    }
    r
}

fn filetime_now() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Windows FILETIME：1601-01-01 起 100ns 单位
    (secs + 11_644_473_600) * 10_000_000
}

/// NBSS 头 + 负载拼回完整消息（SMB1 方言解析的输入形态）
fn nbss_head(head: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut msg = head.to_vec();
    msg.extend_from_slice(payload);
    msg
}

fn wrap_nbss(smb: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    out.extend_from_slice(&(smb.len() as u16).to_be_bytes());
    out.extend_from_slice(smb);
    out
}

pub(crate) async fn smb_session(s: &mut TcpStream) -> std::io::Result<SessionOutcome> {
    let challenge = rand::random::<u64>().to_le_bytes();
    let session_id: u64 = rand::random();
    let mut steps = Vec::new();
    let mut payloads: Vec<String> = Vec::new();
    let mut creds: Vec<String> = Vec::new();
    // 首包超时/断开 = 纯端口探测（445 的多数流量），不落「非 SMB」误导标注
    let mut quiet = false;

    'outer: for _ in 0..8 {
        // NBSS 头：type(0)=flags(0)=len u16 BE
        let mut nb = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut nb)).await {
            Ok(Ok(_)) => {}
            _ => {
                quiet = steps.is_empty();
                break;
            }
        }
        let len = u16::from_be_bytes([nb[2], nb[3]]) as usize;
        if nb[0] != 0x00 || len > 16_384 {
            break;
        }
        if len < 64 {
            // SMB2 头最小 64：短消息常见为 SMB1 协商（FF SMB 0x72）——记录方言后收场
            let mut msg = vec![0u8; len];
            if len > 0 {
                s.read_exact(&mut msg).await?;
            }
            payloads.push(sanitize(&msg, MAX_PAYLOAD));
            let dialects = parse_smb1_dialects(&nbss_head(nb, &msg));
            let label = if dialects.is_empty() {
                "smb1_short(未识别)".to_string()
            } else {
                format!("smb1_negotiate(方言 {})", dialects.join(","))
            };
            steps.push(aisafeguard_core::event::ShellStep {
                command: label,
                response: "no-reply(低交互)".into(),
            });
            break 'outer;
        }
        let mut msg = vec![0u8; len];
        if s.read_exact(&mut msg).await.is_err() {
            break;
        }
        payloads.push(sanitize(&msg, MAX_PAYLOAD));
        if msg[..4] != [0xfe, b'S', b'M', b'B'] {
            break;
        }
        let command = u16le(&msg, 12);
        let message_id = u64::from_le_bytes([
            msg[24], msg[25], msg[26], msg[27], msg[28], msg[29], msg[30], msg[31],
        ]);
        let (resp, label, deny): (Vec<u8>, String, bool) = match command {
            0 => {
                (
                    build_negotiate_response(&challenge, session_id, message_id),
                    "negotiate".into(),
                    false,
                )
            }
            1 => {
                // SESSION_SETUP：security blob 在 SecBufOff（自 SMB2 头起）
                let off = u16le(&msg, 68) as usize;
                let blen = u16le(&msg, 70) as usize;
                let blob = if off < msg.len() && blen > 0 && off + blen <= msg.len() {
                    &msg[off..off + blen]
                } else {
                    &[][..]
                };
                if blob.len() >= 12 && &blob[..8] == b"NTLMSSP\0" {
                    let mtype = u32le(blob, 8);
                    if mtype == 1 {
                        (
                            build_session_setup_response(
                                STATUS_MORE_PROCESSING,
                                Some(&build_ntlm_type2(&challenge, DOMAIN, COMPUTER)),
                                session_id,
                                message_id,
                            ),
                            "session_setup(ntlm_type1)".into(),
                            false,
                        )
                    } else if mtype == 3 {
                        match parse_ntlm_type3(blob) {
                            Some(t3) => {
                                creds.push(format!(
                                    "{}@{} ws={} ntlmv2={}",
                                    t3.user,
                                    if t3.domain.is_empty() { "-" } else { &t3.domain },
                                    if t3.workstation.is_empty() { "-" } else { &t3.workstation },
                                    &t3.ntlmv2[..t3.ntlmv2.len().min(24)]
                                ));
                                (
                                    build_session_setup_response(
                                        STATUS_LOGON_FAILURE,
                                        None,
                                        session_id,
                                        message_id,
                                    ),
                                    format!("session_setup(user={})→logon_denied", t3.user),
                                    true,
                                )
                            }
                            None => (
                                build_session_setup_response(STATUS_LOGON_FAILURE, None, session_id, message_id),
                                "session_setup(malformed_type3)→logon_denied".into(),
                                true,
                            ),
                        }
                    } else {
                        (
                            build_session_setup_response(STATUS_LOGON_FAILURE, None, session_id, message_id),
                            "session_setup(unknown_type)→logon_denied".into(),
                            true,
                        )
                    }
                } else {
                    (
                        build_session_setup_response(STATUS_LOGON_FAILURE, None, session_id, message_id),
                        "session_setup(no_ntlm)→logon_denied".into(),
                        true,
                    )
                }
            }
            2 => (
                build_session_setup_response(STATUS_SUCCESS, None, session_id, message_id),
                "logoff".into(),
                false,
            ),
            _ => {
                // TreeConnect/Create 等一律拒绝：会话未通过认证
                (
                    build_session_setup_response(STATUS_LOGON_FAILURE, None, session_id, message_id),
                    format!("cmd_{command:#06x}→logon_denied"),
                    true,
                )
            }
        };
        if s.write_all(&wrap_nbss(&resp)).await.is_err() {
            break;
        }
        steps.push(aisafeguard_core::event::ShellStep {
            command: label.clone(),
            response: "sent".into(),
        });
        if deny && creds.is_empty() {
            // 拒绝后无凭证可等的场景（no_ntlm/unknown）直接收场
            break 'outer;
        }
        if command == 2 {
            break;
        }
    }

    let summary = if quiet {
        "连接建立后未发送数据（疑似端口扫描）".into()
    } else if steps.is_empty() {
        "非 SMB/NBSS 数据".into()
    } else {
        let labels: Vec<String> = steps.iter().map(|x| x.command.clone()).collect();
        let mut sm = format!("SMB2 会话({} 步): {}", labels.len(), labels.join(" → "));
        if !creds.is_empty() {
            sm.push_str(&format!(" 凭证[{}]", creds.join("; ")));
        }
        if sm.chars().count() > 160 {
            sm = sm.chars().take(157).collect::<String>() + "...";
        }
        sm
    };
    Ok(SessionOutcome {
        summary,
        payload: payloads.join("\n"),
        http_hint: None,
        interaction: (!steps.is_empty()).then_some(steps),
        credentials: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SMB1 方言解析（F794 补丁）字节级断言：魔数 FF 53 4D 42 = ffSMB 的转义形态，
    /// 命令 0x72，方言项 = 0x02 + 名字 + 0x00。
    #[test]
    fn smb1_dialects_parsed_from_negotiate() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x00, 0x00]);           // NBSS type/flags
        msg.extend_from_slice(&0u16.to_be_bytes());     // len 占位后填
        msg.extend_from_slice(&[0xFF, 0x53, 0x4D, 0x42]); // SMB1 魔数（FF SMB）
        msg.extend_from_slice(&[0x72, 0x00, 0x00, 0x00, 0x00]); // COM_NEGOTIATE + 状态
        msg.extend_from_slice(&[0u8; 23]);              // 头部其余（flags2/pid/tid/mid）
        let dialects: [&[u8]; 3] = [b"LANMAN1.0", b"LM1.2X002", b"NT LM 0.12"];
        let mut bytes_area = Vec::new();
        for d in dialects {
            bytes_area.push(0x02);
            bytes_area.extend_from_slice(d);
            bytes_area.push(0x00);
        }
        msg.extend_from_slice(&[0x00]);                 // WordCount = 0
        msg.extend_from_slice(&(bytes_area.len() as u16).to_le_bytes());
        msg.extend_from_slice(&bytes_area);
        let len = (msg.len() - 4) as u16;
        msg[2..4].copy_from_slice(&len.to_be_bytes());

        let parsed = parse_smb1_dialects(&msg);
        assert_eq!(parsed, vec!["LANMAN1.0", "LM1.2X002", "NT LM 0.12"]);
        // 非 SMB1（SMB2 魔数/其他命令）不误判
        let mut smb2ish = msg.clone();
        smb2ish[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        assert!(parse_smb1_dialects(&smb2ish).is_empty());
        let mut other_cmd = msg.clone();
        other_cmd[8] = 0x73;
        assert!(parse_smb1_dialects(&other_cmd).is_empty());
    }

    #[test]
    fn type2_challenge_structure_roundtrip() {
        let challenge = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let blob = build_ntlm_type2(&challenge, DOMAIN, COMPUTER);
        assert_eq!(&blob[..8], b"NTLMSSP\0");
        assert_eq!(u32le(&blob, 8), 2);
        assert_eq!(&blob[24..32], &challenge);
        // target name 在 offset 48 可读（固定头 48B 后）
        let tlen = u16le(&blob, 12) as usize;
        assert_eq!(utf16le(&blob[48..48 + tlen]), DOMAIN);
        // target info 含 computer name
        let ilen = u16le(&blob, 40) as usize;
        let ioff = u32le(&blob, 44) as usize;
        let info = &blob[ioff..ioff + ilen];
        let comp_len = u16le(info, 2) as usize;
        assert_eq!(utf16le(&info[4..4 + comp_len]), COMPUTER);
    }

    #[test]
    fn type3_parse_extracts_user_domain_ws() {
        // 手工构造 type3：头 64B（8 魔数 + 4 类型 + 6 三元组@12..60 + flags@60..64）+ 载荷
        let user: Vec<u8> = "admin".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let domain: Vec<u8> = "PROD".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let ws: Vec<u8> = "KALI".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let nt = [0xaau8; 32];
        let mut patch = Vec::new();
        let mut payload = Vec::new();
        for v in [&[] as &[u8], &nt, &domain, &user, &ws, &[] as &[u8]] {
            let off = 64 + payload.len(); // 偏移按已写入的载荷量累计
            patch.extend_from_slice(&(v.len() as u16).to_le_bytes());
            patch.extend_from_slice(&(v.len() as u16).to_le_bytes());
            patch.extend_from_slice(&(off as u32).to_le_bytes());
            payload.extend_from_slice(v);
        }
        patch.extend_from_slice(&0u32.to_le_bytes()); // NegotiateFlags @60..64
        let mut blob = Vec::new();
        blob.extend_from_slice(b"NTLMSSP\0");
        blob.extend_from_slice(&3u32.to_le_bytes());
        blob.extend_from_slice(&patch);
        // 载荷按登记偏移追加：nt@64 domain@96 user@104 ws@112
        blob.extend_from_slice(&payload);

        let t3 = parse_ntlm_type3(&blob).expect("type3 应解析成功");
        assert_eq!(t3.user, "admin");
        assert_eq!(t3.domain, "PROD");
        assert_eq!(t3.workstation, "KALI");
        assert!(t3.ntlmv2.contains("aa"), "NTLMv2 响应应捕获: {}", t3.ntlmv2);
    }

    #[test]
    fn negotiate_response_shape() {
        let challenge = [0u8; 8];
        let r = build_negotiate_response(&challenge, 0x42, 0);
        assert_eq!(&r[..4], [0xfe, b'S', b'M', b'B']);
        assert_eq!(u16le(&r, 4), 64);
        assert_eq!(u16le(&r, 12), 0); // NEGOTIATE
        assert_eq!(u32le(&r, 16) & 1, 1, "响应标志应含 SERVER_TO_REDIR");
        assert_eq!(u64le_from(&r, 40), 0x42, "session id 回显");
        assert_eq!(u16le(&r, 64), 65); // StructureSize（响应结构从 64 起）
        assert_eq!(u16le(&r, 68), DIALECT_202);
        // NBSS 包装长度
        let w = wrap_nbss(&r);
        assert_eq!(&w[..2], &[0x00, 0x00]);
        assert_eq!(u16::from_be_bytes([w[2], w[3]]) as usize, r.len());
    }

    fn u64le_from(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3], b[at + 4], b[at + 5], b[at + 6], b[at + 7]])
    }

    #[test]
    fn logon_failure_shape() {
        let r = build_session_setup_response(STATUS_LOGON_FAILURE, None, 1, 0);
        assert_eq!(u32le(&r, 8), STATUS_LOGON_FAILURE);
        assert_eq!(u16le(&r, 64), 9); // StructureSize（响应结构从 64 起）
    }
}
