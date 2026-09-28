//! 本地 REST API：仅绑定 127.0.0.1 + Bearer token。
//! 0.1 供脚本/外部工具使用，0.2 的远程控制台与 GUI/服务分离也走这套接口。

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
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
    let app = Router::new()
        .route("/api/status", get(status))
        .route("/api/events", get(events))
        .route("/api/rules", get(list_rules).post(add_rule))
        .route("/api/rules/{id}", delete(remove_rule))
        .route("/api/rules/{id}/promote", post(promote_rule))
        .route("/api/proposals", get(list_proposals))
        .route("/api/proposals/{id}/apply", post(apply_proposal))
        .route("/api/proposals/{id}/dismiss", post(dismiss_proposal))
        .route("/api/feedback", get(list_feedback).post(mark_false_positive))
        .route("/api/feedback/{value}", delete(clear_feedback))
        .route("/api/stats", get(stats))
        .route("/api/exposure", get(get_exposure))
        .route("/api/exposure/scan", post(scan_exposure))
        .route("/api/intel", get(get_intel))
        .route("/api/intel/refresh", post(refresh_intel))
        .route("/api/config", get(get_config).post(put_config))
        .route("/api/ai/key", get(ai_key_present).post(ai_key_set).delete(ai_key_delete))
        .route("/api/ai/runs", get(ai_runs))
        .route("/api/ai/analyze", post(ai_analyze))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state);

    match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => {
            tracing::info!("API 已监听 127.0.0.1:{port}");
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("API 服务退出: {e}");
            }
        }
        Err(e) => {
            tracing::error!("API 绑定 127.0.0.1:{port} 失败: {e}");
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
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response()
}

async fn status(State(s): State<AppState>) -> Json<crate::engine::StatusReport> {
    Json(s.engine.status())
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<u32>,
    ip: Option<String>,
}

async fn events(
    State(s): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(100).min(1000);
    match s.engine.list_events(limit, q.ip.as_deref()) {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err_resp(e),
    }
}

async fn list_rules(State(s): State<AppState>) -> Response {
    match s.engine.list_rules() {
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
            )))
        }
    };
    let protocol = match body.protocol.as_deref().unwrap_or("any") {
        "any" => Protocol::Any,
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => {
            return err_resp(aisafeguard_core::error::Error::Firewall(format!(
                "protocol 必须是 any/tcp/udp，得到 {other}"
            )))
        }
    };
    let remote_ip = match body.remote_ip.as_deref() {
        None | Some("") => None,
        Some(ip) => match ip.trim().parse::<IpAddr>() {
            Ok(v) => Some(v),
            Err(e) => {
                return err_resp(aisafeguard_core::error::Error::Firewall(format!(
                    "remote_ip 非法: {e}"
                )))
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
async fn mark_false_positive(State(s): State<AppState>, Json(body): Json<FeedbackBody>) -> Response {
    match s.engine.mark_false_positive(&body.remote_ip, body.note.as_deref().unwrap_or(""), body.local_port) {
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
        (StatusCode::CONFLICT, Json(json!({ "error": "已有分析在运行" }))).into_response()
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
