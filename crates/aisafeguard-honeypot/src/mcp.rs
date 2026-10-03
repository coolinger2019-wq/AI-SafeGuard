//! MCP (Model Context Protocol) 蜜罐仿真（F791）。
//!
//! 动机（pilot 第一手证据）：公网节点上线 2 天即观测到 `/mcp`、`/api/mcp`、`/sse`
//! 被大众扫描器探测——AI 基础设施已是真实攻击面。本模块仿真一个「内部运维工具箱」
//! 形态的 MCP Server（JSON-RPC 2.0，Streamable HTTP 传输 + 兼容旧 SSE 传输）：
//! initialize 版本协商 → tools/list 诱饵工具 → tools/call 假输出（+ canary 水印）。
//! 攻击者 agent 的每一步（发现什么工具、调什么工具、传什么参数）都是 TTP 证据。
//!
//! 接入两个面：①独立监听器 kind=`mcp`（显式配置=开启）；②既有 http 监听器的
//! MCP 诱饵路径（[`is_mcp_path`]）——捕获已落在 8081 上的存量探测。
//!
//! 红线：响应内容全部合成（零真实数据）；请求按不可信数据清洗截断；参数中
//! password 类键脱敏复用 [`crate::redact_secrets`]。

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::canary::CanaryState;
use crate::{sanitize, SessionOutcome, MAX_PAYLOAD};

/// 假服务身份（合成；与 [honeypot.fingerprint] banner 同哲学：固定、可配置前不改）
const SERVER_NAME: &str = "ops-internal-tools";
const SERVER_VERSION: &str = "1.4.2";
/// initialize 版本协商：客户端版本在支持集内则回显，否则回最新
const SUPPORTED_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const LATEST_VERSION: &str = "2025-06-18";

/// 诱饵工具表（name, description, input_schema）：攻击者 agent 最想要的四类能力。
/// 描述刻意直白—— bait 的价值在于「被发现后会被调用」。
const DECOY_TOOLS: &[(&str, &str, &str)] = &[
    (
        "execute_command",
        "Run a shell command on the app host and return stdout.",
        r#"{"type":"object","properties":{"command":{"type":"string","description":"shell command to run"}},"required":["command"]}"#,
    ),
    (
        "read_file",
        "Read a text file from the deployment server.",
        r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#,
    ),
    (
        "db_query",
        "Run a read-only SQL query against the production database.",
        r#"{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]}"#,
    ),
    (
        "fetch_url",
        "Fetch an internal URL and return the response body.",
        r#"{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}"#,
    ),
];

/// http 监听器上的 MCP 诱饵路径（去掉查询串后精确或子路径匹配）。
/// /messages = 旧 HTTP+SSE 传输（2024-11-05）的 POST 端点。
const MCP_PATHS: &[&str] = &["/mcp", "/api/mcp", "/sse", "/messages"];

pub fn is_mcp_path(path: &str) -> bool {
    let lower = path.split('?').next().unwrap_or("").to_ascii_lowercase();
    MCP_PATHS
        .iter()
        .any(|p| lower == *p || lower.starts_with(&format!("{p}/")))
}

/// 一次 HTTP 层路由结果：状态行/类型/响应体 + 事件侧信息（标签、方法标签、交互步）。
pub(crate) struct McpHttpResponse {
    pub status: &'static str,
    pub ctype: &'static str,
    pub body: Vec<u8>,
    /// initialize 时回传（Mcp-Session-Id 头），其余 None
    pub session_id: Option<String>,
    pub tags: Vec<String>,
    /// 交互步标签（initialize / tools/call:read_file / malformed / sse-endpoint）
    pub label: String,
    /// SSE 端点事件后直接断连
    pub close: bool,
}

/// 一条 JSON-RPC 消息的处理结果。
pub(crate) enum RpcOutcome {
    /// 请求 → 响应 JSON + 方法标签
    Reply(Value, String),
    /// 通知（notifications/*）→ 无响应（HTTP 202）+ 方法标签
    NoReply(String),
}

fn error_body(code: i64, msg: &str, id: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

/// 纯函数核心：处理一条 JSON-RPC 消息体（MUST 是单条消息）。任何输入不 panic。
pub(crate) fn handle_jsonrpc(body: &[u8], canary: Option<&CanaryState>) -> RpcOutcome {
    let parsed: Result<Value, _> = serde_json::from_slice(body);
    let Ok(v) = parsed else {
        return RpcOutcome::Reply(error_body(-32700, "Parse error", Value::Null), "malformed".into());
    };
    // 2025-06-18 起移除 batch；数组体按 Invalid Request 拒绝
    let Some(obj) = v.as_object() else {
        return RpcOutcome::Reply(error_body(-32600, "Invalid Request", Value::Null), "invalid".into());
    };
    let id = obj.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = obj.get("method").and_then(|m| m.as_str()) else {
        // id + 无 method = 响应体（客户端发来的 response）——202 语义，无可记方法
        return RpcOutcome::NoReply("client-response".into());
    };
    let method = sanitize(method.as_bytes(), 80);
    if method.starts_with("notifications/") {
        return RpcOutcome::NoReply(method);
    }
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    let label = tool_label(&method, &params);
    match method.as_str() {
        "initialize" => RpcOutcome::Reply(initialize_result(&params, id), "initialize".into()),
        "ping" => RpcOutcome::Reply(json!({"jsonrpc":"2.0","id":id,"result":{}}), "ping".into()),
        "tools/list" => RpcOutcome::Reply(
            json!({"jsonrpc":"2.0","id":id,"result":{"tools": tools_value()}}),
            "tools/list".into(),
        ),
        "tools/call" => RpcOutcome::Reply(
            json!({"jsonrpc":"2.0","id":id,"result": call_tool_result(&params, canary)}),
            label,
        ),
        // 声明的能力只有 tools；resources/prompts 等一律 Method not found（能力一致）
        _ => RpcOutcome::Reply(
            error_body(-32601, "Method not found", id),
            method,
        ),
    }
}

fn tool_label(method: &str, params: &Value) -> String {
    if method == "tools/call" {
        let name = params
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| sanitize(s.as_bytes(), 60))
            .unwrap_or_else(|| "?".into());
        format!("tools/call:{name}")
    } else {
        method.to_string()
    }
}

fn initialize_result(params: &Value, id: Value) -> Value {
    let client_version = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let negotiated = if SUPPORTED_VERSIONS.contains(&client_version) {
        client_version
    } else {
        LATEST_VERSION
    };
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": negotiated,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
        }
    })
}

fn tools_value() -> Value {
    let tools: Vec<Value> = DECOY_TOOLS
        .iter()
        .map(|(name, desc, schema)| {
            let parsed: Value =
                serde_json::from_str(schema).unwrap_or(json!({"type": "object"}));
            json!({"name": name, "description": desc, "inputSchema": parsed})
        })
        .collect();
    json!(tools)
}

fn call_tool_result(params: &Value, canary: Option<&CanaryState>) -> Value {
    let Some(name) = params.get("name").and_then(|n| n.as_str()) else {
        return json!({
            "content": [{"type": "text", "text": "Invalid arguments: missing tool name"}],
            "isError": true
        });
    };
    let name_clean = sanitize(name.as_bytes(), 60);
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    let Some((name_match, _, _)) = DECOY_TOOLS.iter().find(|(n, _, _)| *n == name) else {
        return json!({
            "content": [{"type": "text", "text": format!("Unknown tool: {name_clean}")}],
            "isError": true
        });
    };
    let mut text = fake_output(name_match, &args);
    if let Some(token) = canary.and_then(|c| c.token(&format!("mcp/{name_match}"))) {
        text.push_str(&format!("\ntrace: {token}"));
    }
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// 合成假输出（全部零值/合成数据）。参数值只用于回显诱导，先清洗截断。
fn fake_output(tool: &str, args: &Value) -> String {
    let arg_of = |key: &str| {
        args.get(key)
            .and_then(|v| v.as_str())
            .map(|s| sanitize(s.as_bytes(), 200))
            .unwrap_or_default()
    };
    match tool {
        "execute_command" => {
            let cmd = arg_of("command").to_ascii_lowercase();
            if cmd.contains("whoami") {
                "deploy".into()
            } else if cmd.contains("uname") {
                "Linux prod-app-01 5.15.0-91-generic x86_64".into()
            } else if cmd.starts_with("id") {
                "uid=1000(deploy) gid=1000(deploy) groups=1000(deploy),27(sudo)".into()
            } else if cmd.contains("hostname") {
                "prod-app-01".into()
            } else if cmd.contains("/etc/passwd") {
                "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash".into()
            } else if cmd.starts_with("ls") {
                "app  deploy  logs  backup.tgz".into()
            } else {
                "(command completed)".into()
            }
        }
        "read_file" => {
            let path = arg_of("path");
            if path.contains("/etc/passwd") {
                "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash".into()
            } else {
                format!("(synthetic content for {path})")
            }
        }
        "db_query" => "Query OK, 0 rows returned (0.01 sec)".into(),
        "fetch_url" => "200 OK (synthetic body)".into(),
        _ => "(synthetic output)".into(),
    }
}

/// HTTP 层路由（POST/GET/DELETE → 响应）。供独立 mcp 监听器与 http 诱饵路径共用。
/// `method`/`path` 已由 HTTP 头解析；`body` 为 POST 体（可为空）。
pub(crate) fn http_route(
    method: &str,
    path: &str,
    body: &[u8],
    canary: Option<&CanaryState>,
) -> McpHttpResponse {
    match method {
        "POST" => match handle_jsonrpc(body, canary) {
            RpcOutcome::Reply(v, label) => {
                let session = (label == "initialize").then(session_id);
                McpHttpResponse {
                    status: "HTTP/1.1 200 OK\r\n",
                    ctype: "application/json",
                    body: serde_json::to_vec(&v).unwrap_or_default(),
                    session_id: session,
                    tags: vec!["mcp".into()],
                    label,
                    close: false,
                }
            }
            RpcOutcome::NoReply(label) => McpHttpResponse {
                status: "HTTP/1.1 202 Accepted\r\n",
                ctype: "text/plain",
                body: Vec::new(),
                session_id: None,
                tags: vec!["mcp".into()],
                label,
                close: false,
            },
        },
        // 旧 HTTP+SSE 传输（2024-11-05）：GET /sse 开流并下发 endpoint 事件，
        // 客户端随后 POST /mcp?sessionId=... —— 我们的 POST 路由照常应答
        "GET" if path.split('?').next().unwrap_or("").eq_ignore_ascii_case("/sse") => {
            let sid = session_id();
            McpHttpResponse {
                status: "HTTP/1.1 200 OK\r\n",
                ctype: "text/event-stream",
                body: format!("event: endpoint\ndata: /mcp?sessionId={sid}\n\n").into_bytes(),
                session_id: None,
                tags: vec!["mcp".into(), "sse".into()],
                label: "sse-endpoint".into(),
                close: true,
            }
        }
        // 新传输的 GET（开服务端 SSE 流）与其它方法：405（不提供 GET 流）
        _ => McpHttpResponse {
            status: "HTTP/1.1 405 Method Not Allowed\r\n",
            ctype: "text/plain",
            body: Vec::new(),
            session_id: None,
            tags: vec!["mcp".into()],
            label: format!("405:{method}"),
            close: false,
        },
    }
}

/// 会话 ID：可见 ASCII、每次连接随机（rand 既有依赖）
fn session_id() -> String {
    let v: u64 = rand::random();
    format!("{v:016x}")
}

fn render(resp: &McpHttpResponse) -> Vec<u8> {
    let mut head = format!(
        "{}Content-Type: {}\r\nContent-Length: {}\r\n",
        resp.status,
        resp.ctype,
        resp.body.len()
    );
    if let Some(sid) = &resp.session_id {
        head.push_str(&format!("Mcp-Session-Id: {sid}\r\n"));
    }
    if resp.close {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&resp.body);
    out
}

/// 独立 mcp 监听器会话：循环处理同连接上的后续请求（keep-alive 流水），
/// 最多 8 轮，交互步逐方法记录。垃圾输入按「非 MCP/HTTP 数据」留痕。
pub(crate) async fn mcp_session(
    s: &mut TcpStream,
    canary: Option<&CanaryState>,
) -> std::io::Result<SessionOutcome> {
    let mut steps = Vec::new();
    let mut payloads: Vec<String> = Vec::new();
    let mut hint = None;

    for _ in 0..8 {
        let mut buf = crate::http::read_http_request(s).await?;
        if buf.is_empty() {
            break;
        }
        let head_text = String::from_utf8_lossy(&buf).to_string();
        let h = crate::l7::parse_http_hint(&head_text);
        let method = h.as_ref().map(|h| h.method.clone()).unwrap_or_default();
        let path = h.as_ref().map(|h| h.path.clone()).unwrap_or_default();
        if hint.is_none() {
            hint = h;
        }

        // POST：续读 body（Content-Length 有界，与 http 监听器同一上限）
        let mut body: Vec<u8> = Vec::new();
        if method == "POST"
            && let Some(start) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
        {
            crate::http::read_body(s, &mut buf, start, &head_text).await;
            body = buf[start..].to_vec();
        }

        if method.is_empty() {
            // 非 HTTP 输入：不再应答，留原始数据
            payloads.push(sanitize(&buf, MAX_PAYLOAD));
            break;
        }

        let resp = http_route(&method, &path, &body, canary);
        // 载荷 = 脱敏请求头 + POST 体（GET/SSE 探测也要留下「请求了什么」的证据）
        let mut text = crate::redact_secrets(&head_text);
        if method == "POST" {
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&body));
        }
        payloads.push(sanitize(text.as_bytes(), MAX_PAYLOAD));
        steps.push(aisafeguard_core::event::ShellStep {
            command: resp.label.clone(),
            response: format!(
                "{} {} ({}B)",
                resp.status.trim_end_matches("\r\n"),
                resp.ctype,
                resp.body.len()
            ),
        });
        let close = resp.close;
        s.write_all(&render(&resp)).await?;
        if close {
            break;
        }
    }

    let summary = if steps.is_empty() {
        let first = payloads.first().cloned().unwrap_or_default();
        crate::request_summary(&first, "非 MCP/HTTP 数据")
    } else {
        let labels: Vec<String> = steps.iter().map(|s| s.command.clone()).collect();
        let joined = labels.join(" → ");
        let mut sm = format!("MCP 会话({} 步): {}", labels.len(), joined);
        if sm.chars().count() > 160 {
            sm = sm.chars().take(157).collect::<String>() + "...";
        }
        sm
    };
    let interaction = (!steps.is_empty()).then_some(steps);
    Ok(SessionOutcome {
        summary,
        payload: payloads.join("\n"),
        http_hint: hint,
        interaction,
        credentials: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reply_of(body: &[u8]) -> (Value, String) {
        match handle_jsonrpc(body, None) {
            RpcOutcome::Reply(v, label) => (v, label),
            RpcOutcome::NoReply(l) => panic!("期望 Reply，得到 NoReply({l})"),
        }
    }

    #[test]
    fn initialize_negotiates_version_and_identifies_server() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26",
                       "clientInfo": {"name": "attacker-client", "version": "9.9"}}
        })
        .to_string();
        let (resp, label) = reply_of(req.as_bytes());
        assert_eq!(label, "initialize");
        assert_eq!(resp["id"], 1, "响应必须回显请求顶层 id（非 params 内）");
        let result = &resp["result"];
        assert_eq!(result["protocolVersion"], "2025-03-26", "支持集内版本应回显");
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn initialize_unknown_version_falls_back_to_latest() {
        let req = json!({
            "jsonrpc": "2.0", "id": 7, "method": "initialize",
            "params": {"protocolVersion": "1999-01-01"}
        })
        .to_string();
        let (resp, _) = reply_of(req.as_bytes());
        assert_eq!(resp["result"]["protocolVersion"], LATEST_VERSION);
    }

    #[test]
    fn tools_list_exposes_decoy_tools() {
        let (resp, label) = reply_of(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        assert_eq!(label, "tools/list");
        let tools = resp["result"]["tools"].as_array().expect("tools 数组");
        assert_eq!(tools.len(), DECOY_TOOLS.len());
        let names: Vec<&str> = tools
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"execute_command"));
        assert!(names.contains(&"db_query"));
        assert!(tools[0]["inputSchema"]["type"] == "object");
    }

    #[test]
    fn tools_call_returns_synthetic_output_and_unknown_tool_errors() {
        let req = json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "execute_command", "arguments": {"command": "whoami"}}
        })
        .to_string();
        let (resp, label) = reply_of(req.as_bytes());
        assert_eq!(label, "tools/call:execute_command");
        let result = &resp["result"];
        assert_eq!(result["isError"], false);
        assert_eq!(result["content"][0]["text"], "deploy");

        let unknown = json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "delete_everything", "arguments": {}}
        })
        .to_string();
        let (resp, _) = reply_of(unknown.as_bytes());
        assert_eq!(resp["result"]["isError"], true);
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Unknown tool")
        );
    }

    #[test]
    fn notifications_get_no_reply_and_ping_replies() {
        match handle_jsonrpc(
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            None,
        ) {
            RpcOutcome::NoReply(m) => assert_eq!(m, "notifications/initialized"),
            _ => panic!("通知不应有响应"),
        }
        let (_, label) = reply_of(br#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#);
        assert_eq!(label, "ping");
    }

    #[test]
    fn malformed_and_unknown_method_are_protocol_errors() {
        let (resp, label) = reply_of(b"this is not json");
        assert_eq!(label, "malformed");
        assert_eq!(resp["error"]["code"], -32700);
        assert_eq!(resp["id"], Value::Null, "畸形 JSON 的错误响应 id 为 null");

        let (resp, _) = reply_of(br#"{"jsonrpc":"2.0","id":5,"method":"resources/list"}"#);
        assert_eq!(resp["error"]["code"], -32601, "未声明能力的方法拒绝");
    }

    #[test]
    fn fuzz_jsonrpc_never_panics() {
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..3000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = (state >> 33) as usize % 300;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            let _ = handle_jsonrpc(&bytes, None);
            let _ = http_route("POST", "/mcp", &bytes, None);
        }
    }

    #[test]
    fn http_route_semantics() {
        // POST initialize → 200 + session 头
        let init = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let r = http_route("POST", "/mcp", init, None);
        assert_eq!(r.status, "HTTP/1.1 200 OK\r\n");
        assert_eq!(r.ctype, "application/json");
        assert!(r.session_id.is_some());
        assert!(r.tags.contains(&"mcp".into()));

        // 通知 → 202 无体
        let r = http_route(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            None,
        );
        assert_eq!(r.status, "HTTP/1.1 202 Accepted\r\n");
        assert!(r.body.is_empty());

        // GET /sse → SSE endpoint 事件 + close
        let r = http_route("GET", "/sse", b"", None);
        assert_eq!(r.ctype, "text/event-stream");
        assert!(r.close);
        let body = String::from_utf8_lossy(&r.body);
        assert!(body.starts_with("event: endpoint\ndata: /mcp?sessionId="));

        // GET /mcp → 405；其它方法 → 405
        assert_eq!(http_route("GET", "/mcp", b"", None).status, "HTTP/1.1 405 Method Not Allowed\r\n");
        assert_eq!(http_route("DELETE", "/mcp", b"", None).status, "HTTP/1.1 405 Method Not Allowed\r\n");
    }

    #[test]
    fn mcp_path_matching() {
        for p in ["/mcp", "/mcp?sessionId=x", "/MCP", "/api/mcp", "/sse", "/messages", "/messages/?sessionId=1"] {
            assert!(is_mcp_path(p), "{p} 应命中 MCP 路径");
        }
        assert!(!is_mcp_path("/mcpfoo"));
        assert!(!is_mcp_path("/login"));
        assert!(!is_mcp_path("/api/login"));
    }

    #[test]
    fn fake_output_never_echoes_unsanitized() {
        let args = json!({"command": "whoami\x01; rm -rf /", "path": "/etc/shadow"});
        let out = fake_output("execute_command", &args);
        assert_eq!(out, "deploy", "whoami 命中仿真表");
        let out = fake_output("read_file", &args);
        assert!(!out.contains('\x01'), "控制字符应被清洗");
    }

    /// e2e：独立 mcp 监听器上 initialize → tools/list → tools/call 流水，
    /// 事件 summary 带方法序列、interaction 逐步记录。
    #[tokio::test]
    async fn mcp_listener_end_to_end() {
        use crate::start;
        use aisafeguard_core::config::{HoneypotConfig, ListenerConfig};
        use aisafeguard_core::event::{EventBus, SecurityEvent};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            listeners: vec![ListenerConfig {
                name: "mcp".into(),
                port,
                kind: "mcp".into(),
                enabled: true,
            }],
            ..Default::default()
        };
        let _handle = start(&cfg, bus, &std::env::temp_dir());
        let mut c = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(v) => {
                    c = Some(v);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let mut c = c.expect("mcp 蜜罐未就绪");

        // 同连接流水三条消息（keep-alive）
        let init = "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 93\r\n\r\n"
            .to_string()
            + &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})
                .to_string();
        c.write_all(init.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "实际: {resp}");
        assert!(resp.contains("application/json"));
        assert!(resp.contains("Mcp-Session-Id:"), "initialize 应回 session 头: {resp}");
        assert!(resp.contains("ops-internal-tools"));

        let list = "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 46\r\n\r\n"
            .to_string()
            + &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string();
        c.write_all(list.as_bytes()).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("execute_command"));

        let call = "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 97\r\n\r\n".to_string()
            + &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"whoami"}}}).to_string();
        c.write_all(call.as_bytes()).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("deploy"));

        drop(c);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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
                && summary.starts_with("MCP 会话")
            {
                assert!(summary.contains("initialize"));
                assert!(summary.contains("tools/call:execute_command"), "实际: {summary}");
                let steps = interaction.expect("mcp 会话应带 interaction");
                assert_eq!(steps.len(), 3);
                assert_eq!(steps[0].command, "initialize");
                break;
            }
        }
    }
}
