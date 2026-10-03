//! Redis 蜜罐（0.5.9 H110）：RESP 协议解析 + 假响应，让攻击脚本继续运行以
//! 采集更多行为。零真实数据；AUTH 口令按仓库纪律脱敏不落明文（H200 以加盐
//! 哈希统一入库）；写命令（SLAVEOF/SET/CONFIG）逐条留痕。
//!
//! banner 版本可配化归 0.5.11 H320，本任务内置贴近真实的默认值。
//! 协议解析与响应引擎是纯函数（fuzz 护栏），IO 循环只做搬运。

use aisafeguard_core::event::ShellStep;

use crate::{MAX_PAYLOAD, READ_TIMEOUT, SessionOutcome, read_with_timeout, sanitize};

const REDIS_VERSION: &str = "7.2.4";
/// 单会话命令数上限（与假 Shell 同款防刷纪律）
const MAX_COMMANDS: usize = 200;
/// 单参数截断上限
const MAX_ARG_CHARS: usize = 512;
/// RESP 数组元素数上限——超过即视为畸形
const MAX_ARGS: usize = 64;

/// 增量解析结果：一条完整命令 / 还没读够 / 畸形流
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RespParse {
    Complete { args: Vec<String>, consumed: usize },
    Incomplete,
    Malformed,
}

/// 从缓冲区解析一条 RESP 命令（数组式 `*N` 或内联式），任何输入不 panic。
pub(crate) fn parse_resp(buf: &[u8]) -> RespParse {
    let Some(&first) = buf.first() else {
        return RespParse::Incomplete;
    };
    if first == b'*' {
        parse_resp_array(buf)
    } else {
        parse_inline(buf)
    }
}

fn parse_resp_array(buf: &[u8]) -> RespParse {
    let Some(nl) = find_crlf(buf) else {
        return RespParse::Incomplete;
    };
    let Ok(count) = std::str::from_utf8(&buf[1..nl])
        .map_err(|_| ())
        .and_then(|s| s.trim().parse::<usize>().map_err(|_| ()))
    else {
        return RespParse::Malformed;
    };
    if count > MAX_ARGS {
        return RespParse::Malformed;
    }
    let mut pos = nl + 2;
    let mut args = Vec::with_capacity(count.min(MAX_ARGS));
    for _ in 0..count {
        if pos >= buf.len() || buf[pos] != b'$' {
            return RespParse::Malformed;
        }
        let Some(nl) = find_crlf(&buf[pos..]) else {
            return RespParse::Incomplete;
        };
        let Ok(len) = std::str::from_utf8(&buf[pos + 1..pos + nl])
            .map_err(|_| ())
            .and_then(|s| s.trim().parse::<usize>().map_err(|_| ()))
        else {
            return RespParse::Malformed;
        };
        if len > MAX_PAYLOAD {
            return RespParse::Malformed;
        }
        let data_start = pos + nl + 2;
        let Some(data_end) = data_start.checked_add(len) else {
            return RespParse::Malformed;
        };
        if data_end > buf.len() {
            return RespParse::Incomplete;
        }
        let Some(arg_end) = data_end.checked_add(2) else {
            return RespParse::Malformed;
        };
        if arg_end > buf.len() {
            return RespParse::Incomplete;
        }
        args.push(sanitize(&buf[data_start..data_end], MAX_ARG_CHARS));
        pos = arg_end;
    }
    RespParse::Complete {
        args,
        consumed: pos,
    }
}

fn parse_inline(buf: &[u8]) -> RespParse {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        // 没有换行也没超限：可能还没读完整行
        return if buf.len() > MAX_PAYLOAD {
            RespParse::Malformed
        } else {
            RespParse::Incomplete
        };
    };
    let line = sanitize(&buf[..nl], MAX_ARG_CHARS);
    let args: Vec<String> = line
        .trim_end_matches('\r')
        .split_whitespace()
        .map(String::from)
        .collect();
    RespParse::Complete {
        args,
        consumed: nl + 1,
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// 响应引擎（纯函数）：返回 (RESP 回复, 留痕命令[口令已脱敏], 是否退出)。
pub(crate) fn respond(args: &[String]) -> (String, Option<String>, bool) {
    let Some(cmd) = args.first().map(|s| s.to_ascii_uppercase()) else {
        return (String::new(), None, false);
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "PING" => ("+PONG\r\n".into(), Some(render_line(args)), false),
        "AUTH" => {
            // 口令脱敏:命令名保留,值一律 *** (COMPLIANCE 纪律,H200 接管采集)
            let masked: Vec<String> = std::iter::once(cmd.clone())
                .chain(rest.iter().map(|_| "***".to_string()))
                .collect();
            ("+OK\r\n".into(), Some(masked.join(" ")), false)
        }
        "INFO" => {
            let info = format!(
                "# Server\r\nredis_version:{REDIS_VERSION}\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nos:Linux 6.1.0-18-amd64 x86_64\r\nrun_id:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\ntcp_port:6379\r\nuptime_in_seconds:86400\r\n\r\n# Clients\r\nconnected_clients:1\r\n\r\n# Memory\r\nused_memory_human:2.05M\r\n\r\n# Replication\r\nrole:master\r\nconnected_slaves:0\r\n\r\n# Keyspace\r\ndb0:keys=1,expires=0\r\n"
            );
            (
                format!("${}\r\n{info}\r\n", info.len()),
                Some(render_line(args)),
                false,
            )
        }
        "CONFIG" => {
            if rest.first().map(|s| s.to_ascii_uppercase()).as_deref() == Some("GET") {
                let mut out = format!("*{}\r\n", rest.len() - 1);
                for param in &rest[1..] {
                    out.push_str(&format!("${}\r\n{param}\r\n", param.len()));
                    out.push_str("$1\r\n0\r\n");
                }
                (out, Some(render_line(args)), false)
            } else {
                ("+OK\r\n".into(), Some(render_line(args)), false)
            }
        }
        "SLAVEOF" | "REPLCONF" | "PSYNC" | "SYNC" => {
            // 复制类命令是高价值行为证据,原样留痕
            ("+OK\r\n".into(), Some(render_line(args)), false)
        }
        "GET" | "MGET" => ("$-1\r\n".into(), Some(render_line(args)), false),
        "SET" | "SETNX" | "DEL" | "EXPIRE" | "HSET" | "LPUSH" | "RPUSH" | "SADD" => {
            let reply = if cmd == "DEL" || cmd == "EXPIRE" {
                ":1\r\n".to_string()
            } else {
                "+OK\r\n".to_string()
            };
            (reply, Some(render_line(args)), false)
        }
        "KEYS" => ("*0\r\n".into(), Some(render_line(args)), false),
        "DBSIZE" => (":1\r\n".into(), Some(render_line(args)), false),
        "FLUSHALL" | "FLUSHDB" => (":1\r\n".into(), Some(render_line(args)), false),
        "EVAL" | "EVALSHA" => {
            // 脚本执行是典型攻击载荷,记录但只回通用错误(不假装执行成功)
            (
                "-ERR Error running script (call to function)\r\n".into(),
                Some(render_line(args)),
                false,
            )
        }
        "QUIT" => ("+OK\r\n".into(), Some(render_line(args)), true),
        other => (
            format!("-ERR unknown command '{other}'\r\n"),
            Some(render_line(args)),
            false,
        ),
    }
}

/// 留痕行:命令 + 参数(已是清洗截断后的文本)
fn render_line(args: &[String]) -> String {
    args.join(" ")
}

pub(crate) async fn redis_session(
    s: &mut tokio::net::TcpStream,
) -> std::io::Result<SessionOutcome> {
    use tokio::io::AsyncWriteExt;
    let mut steps: Vec<ShellStep> = Vec::new();
    let mut credentials: Vec<crate::cred::RawCredential> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    'session: loop {
        let (n, buf) = read_with_timeout(s, READ_TIMEOUT).await?;
        if n == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..n]);
        loop {
            match take_command(&mut pending) {
                TakeOutcome::Command(args) => {
                    if steps.len() >= MAX_COMMANDS {
                        break 'session;
                    }
                    // AUTH 凭证采集（H200）：AUTH [user] password——口令进凭证对，
                    // 留痕行仍走 respond 的脱敏（***）
                    if args.first().map(|s| s.to_ascii_uppercase()).as_deref() == Some("AUTH") {
                        // AUTH <password>（2 词）或 AUTH <user> <password>（3 词）；
                        // 更多参数 = 畸形，不采集（避免把 b 当口令记成 a 的错位材料）
                        let (user, pw) = match args.len() {
                            2 => ("default".to_string(), args[1].clone()),
                            3 => (args[1].clone(), args[2].clone()),
                            _ => (String::new(), String::new()),
                        };
                        if !user.is_empty() {
                            credentials.push(crate::cred::RawCredential {
                                username: user,
                                password: Some(pw),
                            });
                        }
                    }
                    let (response, recorded, quit) = respond(&args);
                    s.write_all(response.as_bytes()).await?;
                    if let Some(line) = recorded {
                        steps.push(ShellStep {
                            command: line,
                            response: response.trim_end().to_string(),
                        });
                    }
                    if quit {
                        break 'session;
                    }
                }
                TakeOutcome::Incomplete => break,
                TakeOutcome::Malformed => {
                    // 畸形流:回协议错误后断开
                    let _ = s.write_all(b"-ERR Protocol error\r\n").await;
                    break 'session;
                }
            }
        }
    }
    let summary = if steps.is_empty() {
        "Redis 连接,未发送命令".to_string()
    } else {
        format!("Redis 命令会话({} 条)", steps.len())
    };
    let payload = steps
        .iter()
        .map(|s| s.command.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(SessionOutcome {
        summary,
        payload,
        http_hint: None,
        interaction: if steps.is_empty() { None } else { Some(steps) },
        credentials,
    })
}

/// 从缓冲取命令的 Outcome
enum TakeOutcome {
    Command(Vec<String>),
    /// 缓冲里没有完整命令,继续读
    Incomplete,
    /// 畸形流,应断开
    Malformed,
}

/// 从缓冲取一条完整命令:消费掉字节。
fn take_command(pending: &mut Vec<u8>) -> TakeOutcome {
    loop {
        match parse_resp(pending) {
            RespParse::Complete { args, consumed } => {
                pending.drain(..consumed);
                if args.is_empty() {
                    continue; // 空行/空数组:跳过
                }
                return TakeOutcome::Command(args);
            }
            RespParse::Incomplete => return TakeOutcome::Incomplete,
            RespParse::Malformed => return TakeOutcome::Malformed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(args: &[&str]) -> Vec<u8> {
        let mut out = format!("*{}\r\n", args.len()).into_bytes();
        for a in args {
            out.extend_from_slice(format!("${}\r\n{a}\r\n", a.len()).as_bytes());
        }
        out
    }

    #[test]
    fn parse_resp_array_complete_and_partial() {
        let buf = resp(&["GET", "foo"]);
        match parse_resp(&buf) {
            RespParse::Complete { args, consumed } => {
                assert_eq!(args, vec!["GET", "foo"]);
                assert_eq!(consumed, buf.len());
            }
            _ => panic!("应完整解析"),
        }
        // 半条命令:Incomplete
        assert_eq!(parse_resp(&buf[..buf.len() - 2]), RespParse::Incomplete);
        assert_eq!(parse_resp(b"*2\r\n$3\r\nGE"), RespParse::Incomplete);
    }

    #[test]
    fn parse_inline_and_malformed() {
        match parse_resp(b"PING\r\n") {
            RespParse::Complete { args, .. } => assert_eq!(args, vec!["PING"]),
            _ => panic!("内联命令应解析"),
        }
        assert_eq!(parse_resp(b"*-1\r\n"), RespParse::Malformed);
        assert_eq!(parse_resp(b"*99999\r\n"), RespParse::Malformed);
        assert_eq!(parse_resp(b"*1\r\n$999999\r\n"), RespParse::Malformed);
        assert_eq!(parse_resp(b"*abc\r\n"), RespParse::Malformed);
    }

    #[test]
    fn fuzz_parse_resp_never_panic() {
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..5000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = (state >> 33) as usize % 200;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            if let RespParse::Complete { args, .. } = parse_resp(&bytes) {
                let _ = respond(&args);
            }
        }
    }

    #[test]
    fn auth_password_is_redacted_in_record() {
        let args: Vec<String> = vec!["AUTH".into(), "s3cret!".into()];
        let (response, recorded, quit) = respond(&args);
        assert_eq!(response, "+OK\r\n");
        assert!(!quit);
        let line = recorded.expect("AUTH 必须留痕");
        assert!(line.starts_with("AUTH "));
        assert!(line.contains("***"), "实际: {line}");
        assert!(!line.contains("s3cret"), "口令明文不得留痕");
    }

    #[test]
    fn fake_responses_for_common_commands() {
        for (args, expect) in [
            (vec!["PING"], "+PONG"),
            (vec!["GET", "k"], "$-1"),
            (vec!["SET", "k", "v"], "+OK"),
            (vec!["SLAVEOF", "1.2.3.4", "6379"], "+OK"),
            (vec!["KEYS", "*"], "*0"),
            (vec!["NOSUCH", "x"], "-ERR unknown command 'NOSUCH'"),
        ] {
            let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let (response, _, _) = respond(&a);
            assert!(response.starts_with(expect), "{args:?} => {response}");
        }
        // INFO 假数据带版本号
        let a: Vec<String> = vec!["INFO".into()];
        let (response, _, _) = respond(&a);
        assert!(response.contains(REDIS_VERSION));
        assert!(response.starts_with('$'));
    }

    #[tokio::test]
    async fn redis_listener_roundtrip() {
        use crate::{HoneypotHandle, start};
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
                name: "redis".into(),
                port,
                kind: "redis".into(),
                enabled: true,
            }],
            ..Default::default()
        };
        let _handle: HoneypotHandle = start(&cfg, bus, &std::env::temp_dir());
        let mut conn = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(c) => {
                    conn = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        let mut c = conn.expect("redis 蜜罐未就绪");
        c.write_all(&resp(&["PING"])).await.unwrap();
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"+PONG\r\n");
        // 写命令 + AUTH:留痕且口令脱敏
        c.write_all(&resp(&["SET", "k", "v"])).await.unwrap();
        c.write_all(&resp(&["AUTH", "hunter2"])).await.unwrap();
        c.write_all(&resp(&["QUIT"])).await.unwrap();
        let mut tail = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let n = c.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                tail.extend_from_slice(&buf[..n]);
            }
        })
        .await;
        assert!(tail.starts_with(b"+OK\r\n+OK\r\n+OK\r\n"), "实际: {tail:?}");

        // 事件:interaction 含三条留痕,AUTH 口令脱敏
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("超时未收到蜜罐事件")
                .expect("事件通道关闭");
            if let SecurityEvent::HoneypotHit {
                summary,
                payload,
                interaction: Some(steps),
                ..
            } = ev
            {
                // PING + SET + AUTH + QUIT 共 4 条留痕
                assert!(summary.contains("Redis 命令会话(4 条)"), "实际: {summary}");
                assert_eq!(steps.len(), 4);
                assert_eq!(steps[0].command, "PING");
                assert_eq!(steps[1].command, "SET k v");
                assert!(steps[2].command.contains("***"));
                assert_eq!(steps[3].command, "QUIT");
                assert!(!payload.contains("hunter2"), "口令明文不得落 payload");
                break;
            }
        }
    }
}
