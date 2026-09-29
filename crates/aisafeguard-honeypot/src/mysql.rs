//! MySQL 蜜罐（0.5.9 H110）：握手协议 + 认证后简单语句假响应，抓口令爆破与
//! 僵尸网络证据。协议解析只读不解码执行；任何真实业务数据都不得进入假响应。
//!
//! 策略：任意凭证放行（对齐蜜罐「留客采集」语义），记录握手用户名与全部语句；
//! 协议畸形时回对齐真实 mysqld 的 Access denied 文案后断开，不泄漏蜜罐特征。
//! banner 版本可配化归 0.5.11 H320，本任务内置贴近真实的默认值。

use std::time::Duration;

use aisafeguard_core::event::ShellStep;

use crate::{sanitize, SessionOutcome, MAX_PAYLOAD};

const MYSQL_VERSION: &str = "8.0.36";
/// 单会话语句数上限（与假 Shell 同款防刷纪律）
const MAX_QUERIES: usize = 200;
/// 单条 SQL 截断上限
const MAX_SQL_CHARS: usize = 2048;
const PACKET_TIMEOUT: Duration = Duration::from_secs(10);

// ---------- 包帧 ----------

/// 读一个 MySQL 包:[len 3LE][seq][payload]。超长包视为畸形 → Err（调用方断开）。
async fn read_packet(
    s: &mut tokio::net::TcpStream,
) -> std::io::Result<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut hdr = [0u8; 4];
    tokio::time::timeout(PACKET_TIMEOUT, s.read_exact(&mut hdr)).await??;
    let len = hdr[0] as usize | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    if len > MAX_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mysql 包超长",
        ));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        tokio::time::timeout(PACKET_TIMEOUT, s.read_exact(&mut payload)).await??;
    }
    Ok((hdr[3], payload))
}

async fn write_packet(
    s: &mut tokio::net::TcpStream,
    seq: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let len = payload.len();
    let mut frame = Vec::with_capacity(len + 4);
    frame.extend_from_slice(&[
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        seq,
    ]);
    frame.extend_from_slice(payload);
    s.write_all(&frame).await
}

// ---------- 协议构造（全部合成常量,零真实数据） ----------

/// 认证挑战(合成固定值——蜜罐指纹一致性归 H320 处理)
const AUTH_SCRAMBLE: [u8; 20] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x1a, 0x2b,
    0x3c, 0x4d, 0x5e, 0x6f,
];
const AUTH_PLUGIN: &str = "mysql_native_password";

/// 能力位:LONG_PASSWORD | PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH
const CAPABILITIES: u32 = 0x0001 | (1 << 9) | (1 << 15) | (1 << 19);

/// 服务端 greeting(handshake v10)
pub(crate) fn greeting_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0x0a); // protocol version 10
    p.extend_from_slice(MYSQL_VERSION.as_bytes());
    p.push(0x00);
    p.extend_from_slice(&1u32.to_le_bytes()); // thread id(合成)
    p.extend_from_slice(&AUTH_SCRAMBLE[..8]); // auth data part 1
    p.push(0x00); // filler
    p.extend_from_slice(&(CAPABILITIES as u16).to_le_bytes()); // caps lower
    p.push(0x21); // charset utf8_general_ci
    p.extend_from_slice(&0x0002u16.to_le_bytes()); // status: autocommit
    p.extend_from_slice(&((CAPABILITIES >> 16) as u16).to_le_bytes()); // caps upper
    p.push(21); // auth data len(8 + 12 + 1)
    p.extend_from_slice(&[0u8; 10]); // reserved
    p.extend_from_slice(&AUTH_SCRAMBLE[8..20]); // auth data part 2
    p.push(0x00);
    p.extend_from_slice(AUTH_PLUGIN.as_bytes());
    p.push(0x00);
    p
}

/// OK 包(受影响行 0)
fn ok_payload() -> Vec<u8> {
    let mut p = vec![0x00, 0x00, 0x00]; // OK + affected_rows(0) + last_insert_id(0)
    p.extend_from_slice(&0x0002u16.to_le_bytes()); // SERVER_STATUS_AUTOCOMMIT
    p.extend_from_slice(&0x0000u16.to_le_bytes()); // warnings
    p
}

/// ERR 包:文案对齐真实 mysqld 的认证失败(反识别,不泄漏蜜罐特征)
fn access_denied_payload(user: &str, host: &str) -> Vec<u8> {
    let mut p = vec![0xff];
    p.extend_from_slice(&1045u16.to_le_bytes()); // ER_ACCESS_DENIED_ERROR
    p.extend_from_slice(b"#28000");
    p.extend_from_slice(
        format!("Access denied for user '{user}'@'{host}' (using password: YES)").as_bytes(),
    );
    p
}

/// 空 RESULTSET 的列定义包(name 为列名)。
/// 列定义的字符串是 **lenenc 长度前缀**(非 NUL 结尾)——NUL 结尾会让真实
/// mysql 客户端把首字节当长度读爆(2008 out of memory,0.5.9 WSL 实测抓到)。
fn column_def_payload(name: &str) -> Vec<u8> {
    let mut p = Vec::new();
    for field in ["def", "", "", "", name, ""] {
        p.push(field.len() as u8);
        p.extend_from_slice(field.as_bytes());
    }
    p.push(0x0c); // length of fixed fields
    p.extend_from_slice(&0x21u16.to_le_bytes()); // charset
    p.extend_from_slice(&255u32.to_le_bytes()); // column length
    p.push(0xfd); // type VAR_STRING
    p.extend_from_slice(&0x0000u16.to_le_bytes()); // flags
    p.push(0x00); // decimals
    p.extend_from_slice(&[0x00, 0x00]); // filler
    p
}

fn eof_payload() -> Vec<u8> {
    let mut p = vec![0xfe];
    p.extend_from_slice(&0x0000u16.to_le_bytes()); // warnings
    p.extend_from_slice(&0x0002u16.to_le_bytes()); // status
    p
}

fn text_row_payload(values: &[&str]) -> Vec<u8> {
    let mut p = Vec::new();
    for v in values {
        p.push(v.len() as u8);
        p.extend_from_slice(v.as_bytes());
    }
    p
}

/// 结果集:列名 + 行(全部内置假数据)
async fn send_resultset(
    s: &mut tokio::net::TcpStream,
    seq: &mut u8,
    columns: &[&str],
    rows: &[Vec<&str>],
) -> std::io::Result<()> {
    let head = vec![columns.len() as u8];
    write_packet(s, *seq, &head).await?;
    *seq += 1;
    for col in columns {
        write_packet(s, *seq, &column_def_payload(col)).await?;
        *seq += 1;
    }
    write_packet(s, *seq, &eof_payload()).await?;
    *seq += 1;
    for row in rows {
        write_packet(s, *seq, &text_row_payload(row)).await?;
        *seq += 1;
    }
    write_packet(s, *seq, &eof_payload()).await?;
    *seq += 1;
    Ok(())
}

// ---------- 解析（纯函数,fuzz 护栏对象） ----------

/// 从 HandshakeResponse41 payload 提取用户名(清洗截断)。畸形返回 None。
pub(crate) fn parse_handshake_username(payload: &[u8]) -> Option<String> {
    // capabilities(4) max_packet(4) charset(1) reserved(23) = 32 字节头
    if payload.len() < 33 {
        return None;
    }
    let rest = &payload[32..];
    let user_len = rest.iter().position(|&b| b == 0x00)?;
    if user_len == 0 {
        return None;
    }
    Some(sanitize(&rest[..user_len], 128))
}

/// 语句分类(只看前缀,不解析执行 SQL)
pub(crate) enum QueryKind {
    Select,
    ShowDatabases,
    Show,
    Other,
}

pub(crate) fn classify_query(sql: &str) -> QueryKind {
    let lower = sql.trim_start().to_ascii_lowercase();
    if lower.starts_with("select") {
        QueryKind::Select
    } else if lower.starts_with("show databases") {
        QueryKind::ShowDatabases
    } else if lower.starts_with("show") {
        QueryKind::Show
    } else {
        QueryKind::Other
    }
}

// ---------- 会话 ----------

pub(crate) async fn mysql_session(s: &mut tokio::net::TcpStream) -> std::io::Result<SessionOutcome> {
    // 1. greeting(seq 0)
    write_packet(s, 0, &greeting_payload()).await?;

    // 2. 客户端 HandshakeResponse
    let (seq, payload) = match read_packet(s).await {
        Ok(v) => v,
        Err(_) => {
            // 扫描器只连不发/乱字节:静默结束,不回错误细节
            return Ok(empty_outcome("MySQL 握手未完成"));
        }
    };
    let _ = seq;
    let username = parse_handshake_username(&payload).unwrap_or_default();
    if username.is_empty() {
        // 畸形握手:对齐真实 mysqld 的失败文案后断开
        let _ = write_packet(s, 2, &access_denied_payload("", "unknown")).await;
        return Ok(empty_outcome("MySQL 握手畸形,已回 Access denied"));
    }

    // 3. 任意凭证放行 → OK,进入命令循环(留客采集)
    write_packet(s, 2, &ok_payload()).await?;

    let mut steps: Vec<ShellStep> = Vec::new();
    loop {
        let (seq, payload) = match read_packet(s).await {
            Ok(v) => v,
            Err(_) => break,
        };
        if steps.len() >= MAX_QUERIES {
            break;
        }
        let Some(&cmd) = payload.first() else {
            break;
        };
        match cmd {
            0x01 => break, // COM_QUIT
            0x0e => {
                // COM_PING
                write_packet(s, seq.wrapping_add(1), &ok_payload()).await?;
                steps.push(ShellStep {
                    command: "COM_PING".into(),
                    response: "OK".into(),
                });
            }
            0x03 => {
                // COM_QUERY
                let sql = sanitize(&payload[1..], MAX_SQL_CHARS);
                let kind = classify_query(&sql);
                let mut seq_out = seq.wrapping_add(1);
                let response_form = match kind {
                    QueryKind::Select => {
                        send_resultset(s, &mut seq_out, &["RESULT"], &[]).await?;
                        "空结果集".to_string()
                    }
                    QueryKind::ShowDatabases => {
                        send_resultset(
                            s,
                            &mut seq_out,
                            &["Database"],
                            &[
                                vec!["information_schema"],
                                vec!["mysql"],
                                vec!["performance_schema"],
                                vec!["sys"],
                            ],
                        )
                        .await?;
                        "4 rows".to_string()
                    }
                    QueryKind::Show => {
                        send_resultset(s, &mut seq_out, &["Value"], &[]).await?;
                        "空结果集".to_string()
                    }
                    QueryKind::Other => {
                        write_packet(s, seq_out, &ok_payload()).await?;
                        "OK".to_string()
                    }
                };
                steps.push(ShellStep {
                    command: sql,
                    response: response_form,
                });
            }
            _ => {
                // 其他命令(COM_FIELD_LIST/COM_STMT_*)回不支持并断开——
                // prepared statement 全协议在范围外(ROADMAP Out)
                let _ = write_packet(
                    s,
                    seq.wrapping_add(1),
                    &access_denied_payload(&username, "unknown"),
                )
                .await;
                break;
            }
        }
    }

    let summary = if steps.is_empty() {
        format!("MySQL 认证通过(用户 {username}),未发送语句")
    } else {
        format!("MySQL 查询会话({} 条,用户 {username})", steps.len())
    };
    let payload_text = steps
        .iter()
        .map(|s| s.command.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(SessionOutcome {
        summary,
        payload: payload_text,
        http_hint: None,
        interaction: if steps.is_empty() {
            None
        } else {
            Some(steps)
        },
    })
}

fn empty_outcome(summary: &str) -> SessionOutcome {
    SessionOutcome {
        summary: summary.to_string(),
        payload: String::new(),
        http_hint: None,
        interaction: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_is_protocol10_with_version() {
        let g = greeting_payload();
        assert_eq!(g[0], 0x0a);
        let text = String::from_utf8_lossy(&g);
        assert!(text.contains(MYSQL_VERSION));
        assert!(text.contains(AUTH_PLUGIN));
    }

    #[test]
    fn parse_username_from_handshake() {
        // 合法 HandshakeResponse41:32 字节头 + user\0 + scramble
        let mut p = vec![0u8; 32];
        p[0..4].copy_from_slice(&CAPABILITIES.to_le_bytes());
        p.extend_from_slice(b"root\0");
        p.push(20);
        p.extend_from_slice(&[0u8; 20]);
        p.extend_from_slice(AUTH_PLUGIN.as_bytes());
        p.push(0x00);
        assert_eq!(parse_handshake_username(&p).as_deref(), Some("root"));

        // 畸形:过短/空用户名/缺 NUL
        assert_eq!(parse_handshake_username(&[0u8; 10]), None);
        let mut empty_user = vec![0u8; 32];
        empty_user.push(0x00);
        assert_eq!(parse_handshake_username(&empty_user), None);
        let mut no_nul = vec![0u8; 32];
        no_nul.extend_from_slice(b"admin");
        assert_eq!(parse_handshake_username(&no_nul), None);
    }

    #[test]
    fn fuzz_username_and_classify_never_panic() {
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..5000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = (state >> 33) as usize % 120;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            let _ = parse_handshake_username(&bytes);
            if let Ok(text) = std::str::from_utf8(&bytes) {
                match classify_query(text) {
                    QueryKind::Select | QueryKind::Show | QueryKind::ShowDatabases
                    | QueryKind::Other => {}
                }
            }
        }
    }

    #[test]
    fn column_def_uses_lenenc_strings_not_nul() {
        // Protocol::ColumnDefinition41 字符串为长度前缀;NUL 结尾会让真实
        // mysql 客户端把 'd'(0x64) 当长度读爆(2008 out of memory)
        let p = column_def_payload("RESULT");
        assert_eq!(&p[..4], &[0x03, b'd', b'e', b'f']);
        assert_eq!(&p[4..5], &[0x00]); // 空 schema lenenc
        assert!(p.contains(&0x06), "name 应带长度前缀");
        assert_eq!(&p[p.len() - 5..], &[0xfd, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn access_denied_matches_mysqld_text() {
        let e = access_denied_payload("root", "1.2.3.4");
        assert_eq!(e[0], 0xff, "ERR 包首字节");
        assert_eq!(&e[1..3], &1045u16.to_le_bytes());
        let text = String::from_utf8_lossy(&e[7..]);
        assert!(
            text.contains("Access denied for user 'root'@'1.2.3.4' (using password: YES)"),
            "实际: {text}"
        );
    }

    #[tokio::test]
    async fn mysql_listener_roundtrip() {
        use crate::{start, HoneypotHandle};
        use aisafeguard_core::config::{HoneypotConfig, ListenerConfig};
        use aisafeguard_core::event::{EventBus, SecurityEvent};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            listeners: vec![ListenerConfig {
                name: "mysql".into(),
                port,
                kind: "mysql".into(),
            }],
            ..Default::default()
        };
        let _handle: HoneypotHandle = start(&cfg, bus, &std::env::temp_dir());
        let mut c = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(v) => {
                    c = Some(v);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        let mut c = c.expect("mysql 蜜罐未就绪");

        // 读 greeting:帧头 + 协议 10 + 版本串
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).await.unwrap();
        let len = hdr[0] as usize | ((hdr[1] as usize) << 8);
        let mut greeting = vec![0u8; len];
        c.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 0x0a);
        assert!(String::from_utf8_lossy(&greeting).contains(MYSQL_VERSION));

        // 发 HandshakeResponse41(root)
        let mut resp = vec![0u8; 32];
        resp[0..4].copy_from_slice(&CAPABILITIES.to_le_bytes());
        resp.extend_from_slice(b"root\0");
        resp.push(20);
        resp.extend_from_slice(&[0u8; 20]);
        resp.extend_from_slice(AUTH_PLUGIN.as_bytes());
        resp.push(0x00);
        c.write_all(&{
            let mut f = vec![(resp.len() & 0xff) as u8, 0x00, 0x00, 1];
            f.extend_from_slice(&resp);
            f
        })
        .await
        .unwrap();

        // 收 OK 包(seq 2,首字节 0x00)
        c.read_exact(&mut hdr).await.unwrap();
        let mut ok = vec![0u8; hdr[0] as usize];
        c.read_exact(&mut ok).await.unwrap();
        assert_eq!(ok[0], 0x00, "任意凭证应放行");
        assert_eq!(hdr[3], 2, "应答 seq 应为客户端 seq+1");

        // COM_QUERY:SELECT 1 → 空 RESULTSET(列数 1)
        let query = {
            let mut p = vec![0x03];
            p.extend_from_slice(b"SELECT 1");
            let mut f = vec![(p.len() & 0xff) as u8, 0x00, 0x00, 0];
            f.extend_from_slice(&p);
            f
        };
        c.write_all(&query).await.unwrap();
        let mut resp_bytes = Vec::new();
        // 列数 + 列定义 + EOF
        for _ in 0..3 {
            c.read_exact(&mut hdr).await.unwrap();
            let mut p = vec![0u8; hdr[0] as usize];
            c.read_exact(&mut p).await.unwrap();
            resp_bytes.extend_from_slice(&p);
        }
        assert_eq!(resp_bytes[0], 1, "SELECT 应返回 1 列");

        // COM_QUERY:SHOW DATABASES → 4 行假数据
        let show = {
            let mut p = vec![0x03];
            p.extend_from_slice(b"SHOW DATABASES");
            let mut f = vec![(p.len() & 0xff) as u8, 0x00, 0x00, 0];
            f.extend_from_slice(&p);
            f
        };
        c.write_all(&show).await.unwrap();
        // 列数 + 列定义 + EOF + 4 行 + EOF = 8 包
        let mut saw_db = false;
        for _ in 0..8 {
            c.read_exact(&mut hdr).await.unwrap();
            let mut p = vec![0u8; hdr[0] as usize];
            c.read_exact(&mut p).await.unwrap();
            // 行包是 [len 前缀字节][数据],直接在整包字节里找假库名
            if String::from_utf8_lossy(&p).contains("information_schema") {
                saw_db = true;
            }
        }
        assert!(saw_db, "SHOW DATABASES 应含内置假库");

        // COM_QUIT 断开
        let quit = vec![1u8, 0x00, 0x00, 0, 0x01];
        c.write_all(&quit).await.unwrap();
        drop(c);

        // 事件:interaction 记录语句,summary 含用户名
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("超时未收到蜜罐事件")
                .expect("事件通道关闭");
            if let SecurityEvent::HoneypotHit {
                summary,
                interaction,
                ..
            } = ev
                && let Some(steps) = interaction
            {
                assert!(
                    summary.contains("MySQL 查询会话(2 条,用户 root)"),
                    "实际: {summary}"
                );
                assert_eq!(steps[0].command, "SELECT 1");
                assert_eq!(steps[1].command, "SHOW DATABASES");
                assert_eq!(steps[0].response, "空结果集");
                break;
            }
        }
    }
}
