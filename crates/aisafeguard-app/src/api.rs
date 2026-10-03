//! 本地 REST API：仅绑定 127.0.0.1 + Bearer token。
//! 0.1 供脚本/外部工具使用，0.2 的远程控制台与 GUI/服务分离也走这套接口。

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header, header::AUTHORIZATION};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::engine::EngineHandle;
use aisafeguard_firewall::{BlockSpec, Direction, Protocol};

#[derive(Clone)]
struct AppState {
    engine: Arc<EngineHandle>,
}

pub async fn serve(engine: Arc<EngineHandle>) {
    let port = engine.config().api.port;
    let state = AppState { engine };
    // /api/* 走 Bearer 认证；静态控制台壳（F760）不设 token——页面本身无任何数据，
    // 登录在页面内完成，数据请求全部带 Bearer。仍只听回环，跨机只能走 SSH 隧道。
    let api = Router::new()
        .route("/api/status", get(status))
        .route("/api/events", get(events))
        .route("/api/rules", get(list_rules).post(add_rule))
        .route("/api/rules/{id}", delete(remove_rule))
        .route("/api/rules/{id}/promote", post(promote_rule))
        .route("/api/proposals", get(list_proposals))
        .route("/api/proposals/{id}/apply", post(apply_proposal))
        .route("/api/proposals/{id}/confirm", post(confirm_campaign))
        .route(
            "/api/honeypot/listeners/{name}/start",
            post(honeypot_listener_start),
        )
        .route(
            "/api/honeypot/listeners/{name}/stop",
            post(honeypot_listener_stop),
        )
        .route("/api/proposals/{id}/dismiss", post(dismiss_proposal))
        .route(
            "/api/feedback",
            get(list_feedback).post(mark_false_positive),
        )
        .route("/api/feedback/{value}", delete(clear_feedback))
        .route("/api/stats", get(stats))
        .route("/api/exposure", get(get_exposure))
        .route("/api/exposure/scan", post(scan_exposure))
        .route("/api/xdp/clear", post(xdp_clear))
        .route("/api/fed/panel", get(fed_panel))
        .route(
            "/api/fed/members/{node}/quarantine",
            post(fed_member_quarantine),
        )
        .route("/api/fed/members/{node}/revoke", post(fed_member_revoke))
        .route("/api/fed/join/request", post(fed_join_request))
        .route("/api/fed/join/approve", post(fed_join_approve))
        .route("/api/fed/join/import", post(fed_join_import))
        .route("/api/fed/members/{node}/lift", post(fed_member_lift))
        .route("/api/intel", get(get_intel))
        .route("/api/intel/refresh", post(refresh_intel))
        .route("/api/config", get(get_config).post(put_config))
        .route("/api/config/raw", get(get_config_raw).put(put_config_raw))
        .route("/api/service/restart", post(service_restart))
        .route(
            "/api/ai/key",
            get(ai_key_present).post(ai_key_set).delete(ai_key_delete),
        )
        .route("/api/ai/runs", get(ai_runs))
        .route("/api/ai/analyze", post(ai_analyze))
        .layer(middleware::from_fn_with_state(state.clone(), auth));
    let app = Router::new()
        .route("/", get(web_console))
        .merge(api)
        .with_state(state);

    match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => {
            tracing::info!("API 已监听 127.0.0.1:{port}");
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("API 服务退出: {e}");
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                tracing::error!(
                    "API 绑定 127.0.0.1:{port} 失败：端口已被占用——很可能另一个 AI-SafeGuard 实例正在运行（单机只应运行一个实例）"
                );
            } else {
                tracing::error!("API 绑定 127.0.0.1:{port} 失败: {e}");
            }
        }
    }
}

async fn auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let ok = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == format!("Bearer {}", state.engine.token));
    if ok {
        next.run(req).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

fn err_resp(e: aisafeguard_core::error::Error) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}

async fn status(State(s): State<AppState>) -> Json<crate::engine::StatusReport> {
    Json(s.engine.status())
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<u32>,
    ip: Option<String>,
}

async fn events(State(s): State<AppState>, Query(q): Query<EventsQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).min(1000);
    match s.engine.list_events(limit, q.ip.as_deref()) {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err_resp(e),
    }
}

/// 一键清空 XDP map（0.5.1 G3）：封禁镜像与内核流表全清，nftables 兜底不受影响
async fn xdp_clear(State(s): State<AppState>) -> Response {
    match s.engine.xdp_clear_map() {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn list_rules(State(s): State<AppState>) -> Response {
    match s.engine.list_rules_explain() {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err_resp(e),
    }
}

#[derive(Deserialize)]
struct AddRuleBody {
    direction: String,
    protocol: Option<String>,
    remote_ip: Option<String>,
    local_port: Option<u16>,
    note: Option<String>,
    /// 可选标签（0.4.0 B1）：来源/用途分组
    tag: Option<String>,
}

async fn add_rule(State(s): State<AppState>, Json(body): Json<AddRuleBody>) -> Response {
    let direction = match body.direction.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        other => {
            return err_resp(aisafeguard_core::error::Error::Firewall(format!(
                "direction 必须是 in/out，得到 {other}"
            )));
        }
    };
    let protocol = match body.protocol.as_deref().unwrap_or("any") {
        "any" => Protocol::Any,
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => {
            return err_resp(aisafeguard_core::error::Error::Firewall(format!(
                "protocol 必须是 any/tcp/udp，得到 {other}"
            )));
        }
    };
    let remote_ip = match body.remote_ip.as_deref() {
        None | Some("") => None,
        Some(ip) => match ip.trim().parse::<IpAddr>() {
            Ok(v) => Some(v),
            Err(e) => {
                return err_resp(aisafeguard_core::error::Error::Firewall(format!(
                    "remote_ip 非法: {e}"
                )));
            }
        },
    };
    let spec = BlockSpec {
        direction,
        protocol,
        remote_ip,
        local_port: body.local_port,
        note: body.note.unwrap_or_else(|| "API 手动添加".into()),
        tag: body.tag.clone().unwrap_or_default(),
    };
    match s.engine.add_block(&spec, "manual") {
        Ok(row) => Json(row).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn remove_rule(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match s.engine.remove_rule(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn list_proposals(State(s): State<AppState>) -> Response {
    match s.engine.list_proposals(None, 100) {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn apply_proposal(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match s.engine.apply_proposal(id) {
        Ok(row) => Json(row).into_response(),
        Err(e) => err_resp(e),
    }
}

/// 0.5.12：蜜罐监听器热启停（即时生效）
/// F500 组织面板数据（只读）
async fn fed_panel(State(s): State<AppState>) -> Response {
    Json(s.engine.fed_panel()).into_response()
}

/// F740 吊销驱离（面板与 CLI 同一通路；立即断一切连接）
#[derive(Deserialize, Default)]
struct RevokeBody {
    #[serde(default)]
    reason: String,
}

async fn fed_member_revoke(
    State(s): State<AppState>,
    Path(node): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let reason = serde_json::from_slice::<RevokeBody>(&body)
        .map(|b| b.reason)
        .unwrap_or_default();
    match s.engine.revoke_member(&node, &reason) {
        Ok(msg) => Json(json!({ "ok": true, "message": msg })).into_response(),
        Err(e) => err_resp(aisafeguard_core::error::Error::Config(e.to_string())),
    }
}

/// F740 入伙向导：成员生成入伙申请
async fn fed_join_request(State(s): State<AppState>, body: axum::body::Bytes) -> Response {
    let node = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["node"].as_str().map(str::to_string));
    let Some(node) = node else {
        return err_resp(aisafeguard_core::error::Error::Config(
            "缺少 node 字段".into(),
        ));
    };
    match s.engine.join_request_create(&node) {
        Ok((request_json, fingerprint)) => Json(json!({
            "ok": true, "request_json": request_json, "fingerprint": fingerprint,
        }))
        .into_response(),
        Err(e) => err_resp(aisafeguard_core::error::Error::Config(e.to_string())),
    }
}

/// F740 入伙向导：协调者处理申请（签名 + 预登记 + 批准包）
#[derive(Deserialize)]
struct JoinApproveBody {
    request_json: String,
    coord_addr: String,
}

async fn fed_join_approve(State(s): State<AppState>, body: axum::body::Bytes) -> Response {
    let Ok(b) = serde_json::from_slice::<JoinApproveBody>(&body) else {
        return err_resp(aisafeguard_core::error::Error::Config(
            "缺少 request_json/coord_addr 字段".into(),
        ));
    };
    match s
        .engine
        .join_approval_process(&b.request_json, &b.coord_addr)
    {
        Ok((approval_json, node)) => Json(json!({
            "ok": true, "approval_json": approval_json, "node": node,
        }))
        .into_response(),
        Err(e) => err_resp(aisafeguard_core::error::Error::Config(e.to_string())),
    }
}

/// F740 入伙向导：成员导入批准包（证书落位 + [fed] 配置写入）
#[derive(Deserialize)]
struct JoinImportBody {
    approval_json: String,
    coord_addr: String,
}

async fn fed_join_import(State(s): State<AppState>, body: axum::body::Bytes) -> Response {
    let Ok(b) = serde_json::from_slice::<JoinImportBody>(&body) else {
        return err_resp(aisafeguard_core::error::Error::Config(
            "缺少 approval_json/coord_addr 字段".into(),
        ));
    };
    match s.engine.join_import(&b.approval_json, &b.coord_addr) {
        Ok(message) => Json(json!({ "ok": true, "message": message })).into_response(),
        Err(e) => err_resp(aisafeguard_core::error::Error::Config(e.to_string())),
    }
}

/// F500 软隔离（面板与 CLI 同一 DB 通路；reason 可选）
#[derive(Deserialize, Default)]
struct QuarantineBody {
    #[serde(default)]
    reason: String,
}

async fn fed_member_quarantine(
    State(s): State<AppState>,
    Path(node): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let reason = serde_json::from_slice::<QuarantineBody>(&body)
        .map(|b| b.reason)
        .unwrap_or_default();
    match s.engine.quarantine_member(&node, false, "", &reason) {
        Ok(msg) => Json(json!({ "ok": true, "message": msg })).into_response(),
        Err(e) => err_resp(e),
    }
}

/// F500 解除隔离（须指纹前缀确认，≥16 位十六进制）
#[derive(Deserialize)]
struct LiftBody {
    fp: String,
}

async fn fed_member_lift(
    State(s): State<AppState>,
    Path(node): Path<String>,
    Json(body): Json<LiftBody>,
) -> Response {
    match s.engine.quarantine_member(&node, true, &body.fp, "") {
        Ok(msg) => Json(json!({ "ok": true, "message": msg })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn honeypot_listener_start(State(s): State<AppState>, Path(name): Path<String>) -> Response {
    match s.engine.toggle_listener(&name, true) {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn honeypot_listener_stop(State(s): State<AppState>, Path(name): Path<String>) -> Response {
    match s.engine.toggle_listener(&name, false) {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

/// H310：确认凭证喷洒战役（人工确认，非封禁动作）
async fn confirm_campaign(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match s.engine.confirm_campaign(id) {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn dismiss_proposal(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match s.engine.dismiss_proposal(id) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

/// 灰度规则转正：TTL 延长到 promote_ttl_secs。
async fn promote_rule(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match s.engine.promote_rule(id) {
        Ok(row) => Json(row).into_response(),
        Err(e) => err_resp(e),
    }
}

#[derive(Deserialize)]
struct FeedbackBody {
    remote_ip: String,
    note: Option<String>,
    /// 可选端口粒度（0.4.0 B4）：仅抑制该端口的处置；缺省 = 按 IP 整体
    local_port: Option<u16>,
}

/// 误报反馈：记录（30 天抑制）+ 解除该来源自动封禁 + 收弃 pending 建议。
async fn mark_false_positive(
    State(s): State<AppState>,
    Json(body): Json<FeedbackBody>,
) -> Response {
    match s.engine.mark_false_positive(
        &body.remote_ip,
        body.note.as_deref().unwrap_or(""),
        body.local_port,
    ) {
        Ok((dismissed, removed)) => Json(json!({
            "ok": true,
            "dismissed_proposals": dismissed,
            "removed_rules": removed,
        }))
        .into_response(),
        Err(e) => err_resp(e),
    }
}

/// 抑制期内的误报反馈列表（抑制期时长取 [ai].fp_suppress_secs）。
async fn list_feedback(State(s): State<AppState>) -> Response {
    let secs = s.engine.config().ai.fp_suppress_secs as i64;
    match s
        .engine
        .store
        .list_active_feedback(aisafeguard_core::now_ts(), secs, 100)
    {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err_resp(e),
    }
}

/// 清除某来源的误报抑制（0.4.0 B3）：删除记录后该来源恢复自动封禁资格。
async fn clear_feedback(State(s): State<AppState>, Path(value): Path<String>) -> Response {
    match s.engine.clear_false_positive(value.trim()) {
        Ok(removed) => {
            if removed > 0 {
                Json(json!({ "ok": true, "removed": removed })).into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "该来源没有抑制期内的误报记录" })),
                )
                    .into_response()
            }
        }
        Err(e) => err_resp(e),
    }
}

async fn ai_analyze(State(s): State<AppState>) -> Response {
    if s.engine.trigger_analysis() {
        Json(json!({ "ok": true, "message": "分析已开始" })).into_response()
    } else {
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": "已有分析在运行" })),
        )
            .into_response()
    }
}

async fn get_exposure(State(s): State<AppState>) -> Response {
    match s.engine.latest_exposure() {
        Ok(Some(snap)) => Json(snap).into_response(),
        Ok(None) => Json(json!({ "ts": null, "entries": [] })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn scan_exposure(State(s): State<AppState>) -> Response {
    match s.engine.scan_exposure() {
        Ok(entries) => {
            let ts = aisafeguard_core::now_ts();
            Json(json!({ "ts": ts, "entries": entries })).into_response()
        }
        Err(e) => err_resp(e),
    }
}

async fn get_intel(State(s): State<AppState>) -> Response {
    match s.engine.store.active_intel(aisafeguard_core::now_ts()) {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn refresh_intel(State(s): State<AppState>) -> Response {
    let eng = s.engine.clone();
    s.engine.rt.spawn(async move {
        let cfg = eng.config().intel;
        crate::engine::run_intel_refresh(&eng, &cfg).await;
    });
    Json(json!({ "ok": true, "message": "情报刷新已开始" })).into_response()
}

async fn stats(State(s): State<AppState>) -> Response {
    match s.engine.stats_24h() {
        Ok(v) => Json(v).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn get_config(State(s): State<AppState>) -> Json<aisafeguard_core::config::AppConfig> {
    Json(s.engine.config())
}

async fn put_config(
    State(s): State<AppState>,
    Json(cfg): Json<aisafeguard_core::config::AppConfig>,
) -> Response {
    match s.engine.save_config(cfg) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

/// Web 控制台静态壳（F790）：单文件 HTML，include_str! 内嵌，无外部依赖。
/// 磁盘优先：`<data_dir>/web/index.html` 存在则覆盖内嵌版（开发热改，改完刷新浏览器
/// 即生效、删除该文件即回归内嵌），保证发布仍是单二进制且页面版本与 API 必然匹配。
/// 页面内不含任何数据；数据一律经页面内 Bearer token 调 /api/*。
async fn web_console(State(s): State<AppState>) -> Response {
    let override_path = s.engine.config().data_dir().join("web").join("index.html");
    if let Ok(raw) = std::fs::read_to_string(&override_path) {
        return Html(raw).into_response();
    }
    Html(include_str!("web/index.html")).into_response()
}

/// 面板触发服务重启（F790）：Linux systemd `restart --no-block`——先落一条 warn
/// 审计事件再执行。Windows 服务/GUI 无自重启通路，明确报错引导服务管理器。
async fn service_restart(State(s): State<AppState>) -> Response {
    if cfg!(windows) {
        return err_resp(aisafeguard_core::error::Error::Config(
            "面板重启仅支持 Linux systemd 部署；Windows 请用服务管理器重启 AISafeGuard 服务".into(),
        ));
    }
    s.engine
        .bus
        .publish(aisafeguard_core::event::SecurityEvent::engine(
            "warn",
            "面板触发服务重启",
        ));
    // 延迟 1 秒再重启：让 HTTP 响应先走完（直接 restart 会和响应竞态，curl/页面只会看到断连）
    match std::process::Command::new("sh")
        .args([
            "-c",
            "sleep 1; systemctl restart --no-block aisafeguard.service",
        ])
        .spawn()
    {
        Ok(_) => {
            Json(json!({ "ok": true, "message": "重启已触发，服务将在数秒内回来" })).into_response()
        }
        Err(e) => err_resp(aisafeguard_core::error::Error::Config(format!(
            "执行 systemctl 失败: {e}"
        ))),
    }
}

/// config.toml 原文（文本编辑器加载用）。
async fn get_config_raw(State(s): State<AppState>) -> Response {
    match s.engine.config_raw() {
        Ok(raw) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], raw).into_response(),
        Err(e) => err_resp(e),
    }
}

/// 原文应用配置：服务端先解析校验，非法 TOML 返回 400 不落盘；
/// 成功返回需重启项列表（空 = 全部热更）。
async fn put_config_raw(State(s): State<AppState>, body: axum::body::Bytes) -> Response {
    let text = match std::str::from_utf8(&body) {
        Ok(t) => t,
        Err(e) => {
            return err_resp(aisafeguard_core::error::Error::Config(format!(
                "请求体不是合法 UTF-8: {e}"
            )));
        }
    };
    match s.engine.apply_config_raw(text) {
        Ok(restart_required) => Json(json!({
            "ok": true,
            "restart_required": restart_required,
        }))
        .into_response(),
        Err(e) => err_resp(e),
    }
}

async fn ai_key_present(State(_s): State<AppState>) -> Response {
    // 服务模式下 Key 存服务账号（LocalSystem）的凭据管理器
    let present = aisafeguard_core::secrets::ai_key_present();
    Json(json!({ "present": present })).into_response()
}

#[derive(Deserialize)]
struct KeyBody {
    key: String,
}

async fn ai_key_set(State(_s): State<AppState>, Json(body): Json<KeyBody>) -> Response {
    match aisafeguard_core::secrets::set_ai_key(body.key.trim()) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn ai_key_delete(State(_s): State<AppState>) -> Response {
    match aisafeguard_core::secrets::delete_ai_key() {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn ai_runs(State(s): State<AppState>) -> Response {
    match s.engine.list_ai_runs(20) {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err_resp(e),
    }
}
