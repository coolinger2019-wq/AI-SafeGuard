//! 组织协同骨架（0.3，设计见 docs/NGFW_EVOLUTION.md §6）。
//!
//! 三条链路：事件上报（agent→协调者）、情报同步（双向）、AI 建议推送（仅慢路径）。
//! 鉴权 v1 = 组织共享令牌（Bearer）；mTLS 每节点证书为后续加固项（ROADMAP 0.3）。
//! 防投毒基线：远端情报 confidence="fed" 永不自动封禁；远端建议过本地 allowlist
//! 复验后仅进慢路径；内网保护全局生效。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::engine::EngineHandle;
use aisafeguard_core::event::SecurityEvent;
use aisafeguard_core::now_ts;
use aisafeguard_store::{IntelRow, Store};

/// 节点名合法性：[A-Za-z0-9_-]{1,32}
pub fn valid_node_name(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= 32
        && node
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(Clone)]
pub struct FedState {
    engine: Arc<EngineHandle>,
}

pub fn fed_router(engine: Arc<EngineHandle>) -> Router {
    let state = FedState { engine };
    Router::new()
        .route("/fed/events", post(fed_events))
        .route("/fed/intel", get(fed_intel_get).post(fed_intel_post))
        .route("/fed/proposals", post(fed_proposals))
        .route("/fed/members", get(fed_members))
        .layer(middleware::from_fn_with_state(state.clone(), fed_auth))
        .with_state(state)
}

async fn fed_auth(
    State(state): State<FedState>,
    headers: axum::http::HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let expected = state.engine.config().fed.effective_token();
    let ok = !expected.is_empty()
        && headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {expected}"));
    if ok {
        next.run(req).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

fn err(e: impl std::fmt::Display) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response()
}

// ---------- agent → 协调者：事件上报 ----------

#[derive(Deserialize)]
struct FedEventBody {
    node: String,
    events: Vec<FedEvent>,
}

#[derive(Deserialize)]
struct FedEvent {
    ts: i64,
    kind: String,
    listener: String,
    remote_ip: String,
    remote_port: u16,
    summary: String,
}

async fn fed_events(
    State(state): State<FedState>,
    Json(body): Json<FedEventBody>,
) -> Response {
    if !valid_node_name(&body.node) {
        return err("node 名不合法（限字母数字_-，≤32 字符）");
    }
    if body.events.len() > 100 {
        return err("单次上报最多 100 条事件");
    }
    let now = now_ts();
    let mut stored = 0usize;
    for ev in &body.events {
        // 时钟窗校验：±1 小时外的记录拒收（防重放/时钟漂移污染）
        if (ev.ts - now).abs() > 3600 {
            continue;
        }
        let se = if ev.kind == "honeypot_hit" {
            SecurityEvent::HoneypotHit {
                ts: ev.ts,
                listener: format!("fed:{}:{}", body.node, ev.listener),
                kind: ev.kind.clone(),
                port: 0,
                remote_ip: ev.remote_ip.clone(),
                remote_port: ev.remote_port,
                summary: ev.summary.clone(),
                payload: String::new(),
            }
        } else {
            SecurityEvent::Engine {
                ts: ev.ts,
                level: "fed".into(),
                message: format!("[{}] {}", body.node, ev.summary),
            }
        };
        if state.engine.store.insert_event(&se).is_ok() {
            stored += 1;
        }
    }
    let _ = state.engine.store.upsert_fed_member(&body.node, now);
    Json(json!({ "ok": true, "stored": stored })).into_response()
}

// ---------- 情报同步（双向） ----------

async fn fed_intel_get(State(state): State<FedState>) -> Response {
    // 下发给 agent 的情报不含 fed:* 来源（避免回灌），且已过滤过期
    let rows: Vec<IntelRow> = state
        .engine
        .store
        .active_intel(now_ts())
        .unwrap_or_default()
        .into_iter()
        .filter(|r| !r.source.starts_with("fed:"))
        .collect();
    Json(rows).into_response()
}

#[derive(Deserialize)]
struct FedIntelBody {
    node: String,
    entries: Vec<FedIntelEntry>,
}

#[derive(Deserialize)]
struct FedIntelEntry {
    value: String,
    kind: String,
}

async fn fed_intel_post(
    State(state): State<FedState>,
    Json(body): Json<FedIntelBody>,
) -> Response {
    if !valid_node_name(&body.node) {
        return err("node 名不合法");
    }
    if body.entries.len() > 500 {
        return err("单次同步最多 500 条情报");
    }
    let now = now_ts();
    let upserts: Vec<(String, String, String, String, i64, i64)> = body
        .entries
        .iter()
        // 来源 IP 的内网保护在 upsert 前置拒绝（防投毒锁网）
        .filter(|e| {
            e.value
                .parse::<std::net::IpAddr>()
                .map(|ip| !aisafeguard_core::is_protected_ip(ip))
                .unwrap_or(false)
        })
        .map(|e| {
            (
                format!("fed:{}", body.node),
                e.kind.clone(),
                e.value.clone(),
                "fed".into(),
                now,
                now + 7 * 86400,
            )
        })
        .collect();
    let n = state.engine.store.upsert_intel(&upserts).unwrap_or(0);
    let _ = state.engine.store.upsert_fed_member(&body.node, now);
    state.engine.bus.publish(SecurityEvent::engine(
        "info",
        format!("组织情报同步：来自 {} 的 {} 条（仅标注，不自动封禁）", body.node, n),
    ));
    Json(json!({ "ok": true, "accepted": n })).into_response()
}

// ---------- 协调者 → agent：情报下发（agent 拉取同上）；AI 建议推送 ----------

#[derive(Deserialize)]
struct FedProposalBody {
    node: String,
    proposals: Vec<serde_json::Value>,
}

async fn fed_proposals(
    State(state): State<FedState>,
    Json(body): Json<FedProposalBody>,
) -> Response {
    if !valid_node_name(&body.node) {
        return err("node 名不合法");
    }
    if body.proposals.len() > 10 {
        return err("单次推送最多 10 条建议");
    }
    let mut accepted = 0usize;
    for p in &body.proposals {
        // 本地复验：与 LLM 输出同一套 allowlist（字段非法即作废）
        let Some(valid) = aisafeguard_ai::validate_fed_proposal(p) else {
            continue;
        };
        // 远端建议仅进慢路径：pending 状态，人工确认
        if state
            .engine
            .store
            .pending_proposal_exists(&valid.remote_ip, valid.local_port)
            .unwrap_or(true)
        {
            continue;
        }
        if let Ok(pid) = state.engine.store.insert_proposal(
            &format!("fed:{}", body.node),
            &valid.severity,
            &valid.direction,
            &valid.protocol,
            &valid.remote_ip,
            valid.local_port,
            valid.ttl_secs,
            &valid.reason,
            "组织协同共享建议（接收方本地复验通过，待人工确认）",
        ) {
            state.engine.bus.publish(SecurityEvent::ProposalCreated {
                ts: now_ts(),
                proposal_id: pid,
                severity: valid.severity.clone(),
                reason: valid.reason.clone(),
            });
            accepted += 1;
        }
    }
    Json(json!({ "ok": true, "accepted": accepted })).into_response()
}

async fn fed_members(State(state): State<FedState>) -> Response {
    let members: Vec<serde_json::Value> = state
        .engine
        .store
        .list_fed_members()
        .unwrap_or_default()
        .into_iter()
        .map(|(node, last_seen)| json!({ "node": node, "last_seen": last_seen }))
        .collect();
    Json(members).into_response()
}

// ---------- agent 侧：定时上报/拉取/推送任务 ----------

#[derive(Serialize)]
struct PushEvent {
    ts: i64,
    kind: String,
    listener: String,
    remote_ip: String,
    remote_port: u16,
    summary: String,
}

/// agent 角色：周期性向协调者上报本地事件、拉取组织情报、推送待确认建议。
/// 协调者失联只记警告，本节点一切功能照常（独立运行优先）。
pub fn spawn_fed_agent_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("HTTP client 构建失败");
        let mut last_event_id: i64 = eng.store.recent_events(1, None).map(|v| v.first().map(|e| e.id).unwrap_or(0)).unwrap_or(0);
        let mut last_proposal_id: i64 = eng
            .store
            .list_proposals(None, 1)
            .map(|v| v.first().map(|p| p.id).unwrap_or(0))
            .unwrap_or(0);

        let cfg0 = eng.config().fed;
        let base = cfg0.coordinator.trim_end_matches('/').to_string();

        loop {
            let interval = eng.config().fed.interval_secs.clamp(15, 3600);
            tokio::time::sleep(Duration::from_secs(interval)).await;
            let cfg = eng.config().fed;
            if !cfg.enabled || cfg.role != "agent" || cfg.effective_token().is_empty() {
                continue;
            }
            let auth = format!("Bearer {}", cfg.effective_token());

            // 1) 上报本地事件（蜜罐命中 + 检测判定）
            if let Ok(rows) = eng.store.recent_events(100, None) {
                let new_events: Vec<PushEvent> = rows
                    .iter()
                    .filter(|e| e.id > last_event_id)
                    .filter(|e| matches!(e.kind.as_str(), "honeypot_hit" | "detection"))
                    .map(|e| PushEvent {
                        ts: e.ts,
                        kind: e.kind.clone(),
                        listener: e.listener.clone(),
                        remote_ip: e.remote_ip.clone(),
                        remote_port: e.remote_port,
                        summary: e.summary.clone(),
                    })
                    .collect();
                if !new_events.is_empty() {
                    let resp = http
                        .post(format!("{base}/fed/events"))
                        .header(AUTHORIZATION, &auth)
                        .json(&json!({ "node": cfg.node, "events": new_events }))
                        .send()
                        .await;
                    match resp {
                        Ok(r) if r.status().is_success() => {
                            if let Some(max) = rows.iter().map(|e| e.id).max() {
                                last_event_id = last_event_id.max(max);
                            }
                        }
                        Ok(r) => tracing::warn!("组织事件上报被拒: HTTP {}", r.status()),
                        Err(e) => tracing::warn!("协调者失联（本节点独立运行）: {e}"),
                    }
                }
            }

            // 2) 拉取组织情报（来源标 fed:coordinator，仅标注）
            if let Ok(resp) = http
                .get(format!("{base}/fed/intel"))
                .header(AUTHORIZATION, &auth)
                .send()
                .await
                && resp.status().is_success()
                && let Ok(list) = resp.json::<Vec<serde_json::Value>>().await
            {
                let now = now_ts();
                let upserts: Vec<(String, String, String, String, i64, i64)> = list
                    .iter()
                    .filter_map(|v| {
                        let value = v["value"].as_str()?.to_string();
                        let kind = v["kind"].as_str()?.to_string();
                        Some((
                            "fed:coordinator".to_string(),
                            kind,
                            value,
                            "fed".to_string(),
                            now,
                            now + 7 * 86400,
                        ))
                    })
                    .collect();
                if !upserts.is_empty() {
                    let _ = eng.store.upsert_intel(&upserts);
                }
            }

            // 3) 推送待确认建议（仅慢路径，接收方复验）
            if let Ok(rows) = eng.store.list_proposals(None, 100) {
                let new_proposals: Vec<serde_json::Value> = rows
                    .iter()
                    .filter(|p| p.id > last_proposal_id && p.status == "pending")
                    .map(|p| {
                        json!({
                            "action": "block",
                            "direction": p.direction,
                            "protocol": p.protocol,
                            "remote_ip": p.remote_ip,
                            "local_port": p.local_port,
                            "severity": p.severity,
                            "reason": p.reason,
                        })
                    })
                    .collect();
                if !new_proposals.is_empty()
                    && let Ok(r) = http
                        .post(format!("{base}/fed/proposals"))
                        .header(AUTHORIZATION, &auth)
                        .json(&json!({ "node": cfg.node, "proposals": new_proposals }))
                        .send()
                        .await
                    && r.status().is_success()
                    && let Some(max) = rows.iter().map(|p| p.id).max()
                {
                    last_proposal_id = last_proposal_id.max(max);
                }
            }
        }
    });
}

// Store 引用占位（fed handlers 里用到 store，避免未使用告警的显式引用）
#[allow(dead_code)]
fn _store_type_check(_s: &Store) {}
