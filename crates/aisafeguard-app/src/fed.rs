//! 组织协同（0.3，设计见 docs/NGFW_EVOLUTION.md §6；0.6 协议见 fedproto.rs）。
//!
//! 三条链路：事件上报（agent→协调者）、情报同步（双向）、AI 建议推送（仅慢路径）。
//! 0.3.6 起鉴权 = mTLS：协调者在**独立监听面**（`[fed].listen_addr`，默认 0.0.0.0:7421）
//! 上要求客户端证书链到组织 CA（rustls WebPkiClientVerifier，手写 accept 循环——
//! 避免 axum-server 的 tls-rustls 特性把 aws-lc-rs 拉进依赖树）；node ↔ 证书指纹
//! 在首次接触时绑定（TOFU），之后冒用其他节点名即被拒。组织共享令牌已整体移除。
//! PKI 文件布局（数据目录 /fed/）：`ca.pem` + `ca-key.pem`（`fed init-ca` 生成，
//! 仅协调者侧持有私钥）；`certs/<node>.pem` + `certs/<node>-key.pem`
//! （`fed issue-cert <node>` 签发，人工分发到节点）。
//! 0.6 F100 起所有请求走统一信封（fedproto::Envelope）：版本协商（major 拒连）、
//! 消息级签名（节点证书钥，防抵赖）、node+seq 幂等去重与回退拒收、24h 补传窗。
//! 防投毒基线不变：远端情报 confidence="fed" 永不自动封禁；远端建议过本地 allowlist
//! 复验后仅进慢路径；内网保护前置拒收。

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::corroboration::{Dim, Observation, OrgCorroboration};
use crate::engine::EngineHandle;
use crate::fedproto::{self, DedupSet, Envelope, InboundLimiter};
use aisafeguard_core::event::SecurityEvent;
use aisafeguard_core::now_ts;
use aisafeguard_store::IntelRow;

/// 节点名合法性：[A-Za-z0-9_-]{1,32}
pub fn valid_node_name(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= 32
        && node
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// 证书指纹：叶子证书 DER 的 SHA-256 hex（与 `fed issue-cert` 输出一致）。
pub fn cert_fp_of(der: &[u8]) -> String {
    let d = Sha256::digest(der);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// TLS 层解析出的对端身份（中间件从 axum_server 的 TlsInfo 提取后插入）。
/// cert_der 供消息级验签（fedproto）提取 SPKI 公钥。
#[derive(Clone)]
pub struct FedPeer {
    pub cert_fp: String,
    pub cert_der: Vec<u8>,
}

/// 协议层计数（F100：畸形/签名失败/回退必须可见）。hello 响应带出，
/// GUI 告警只发「首次」，风暴计数在这里累计（F400 限频另行统一实现）。
#[derive(Default)]
pub struct FedStats {
    pub malformed: AtomicU64,
    pub sig_fail: AtomicU64,
    pub seq_reject: AtomicU64,
    pub duplicates: AtomicU64,
    pub archived_events: AtomicU64,
    /// F400：隔离期被拦的消息数
    pub quarantined: AtomicU64,
    /// F400：限频降级期被拦的消息数
    pub rate_limited: AtomicU64,
}

impl FedStats {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "malformed": self.malformed.load(Ordering::Relaxed),
            "sig_fail": self.sig_fail.load(Ordering::Relaxed),
            "seq_reject": self.seq_reject.load(Ordering::Relaxed),
            "duplicates": self.duplicates.load(Ordering::Relaxed),
            "archived_events": self.archived_events.load(Ordering::Relaxed),
            "quarantined": self.quarantined.load(Ordering::Relaxed),
            "rate_limited": self.rate_limited.load(Ordering::Relaxed),
        })
    }
}

/// 接收侧进程内小状态：seen 去重集合 + 已告警节点（避免同因重复刷 GUI 事件）。
#[derive(Default)]
struct GateState {
    dedup: Option<DedupSet>,
    version_warned: HashSet<String>,
    sig_warned: HashSet<String>,
    /// F400：已广播过的成员隔离状态（node → status），状态变更才广播
    quarantine_announced: std::collections::HashMap<String, String>,
}

impl GateState {
    fn dedup(&mut self) -> &mut DedupSet {
        self.dedup.get_or_insert_with(|| DedupSet::new(50_000))
    }
}

#[derive(Clone)]
pub struct FedState {
    engine: Arc<EngineHandle>,
    gate: Arc<Mutex<GateState>>,
    stats: Arc<FedStats>,
    /// org-feed 广播环（F200）：印证事件等组织消息，节点经 GET /fed/org-feed 拉取。
    /// 有界内存环——重启清零，节点按消息 id 幂等去重。
    feed: Arc<Mutex<OrgFeed>>,
    /// F400：协调者入站限频器（每节点滑动分钟窗，超限降级仅心跳）
    limiter: Arc<Mutex<InboundLimiter>>,
}

/// 组织消息广播环：单调 id + 有界队列（旧消息被挤出后，落后节点的 after 游标
/// 自然取到空段，等下一轮印证即可——观测在节点本地，不丢）。
#[derive(Default)]
struct OrgFeed {
    next_id: u64,
    items: VecDeque<(u64, serde_json::Value)>,
}

impl OrgFeed {
    const CAP: usize = 1000;

    fn push(&mut self, v: serde_json::Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.items.push_back((id, v));
        while self.items.len() > Self::CAP {
            self.items.pop_front();
        }
        id
    }

    fn since(&self, after: u64) -> (Vec<(u64, serde_json::Value)>, u64) {
        (
            self.items.iter().filter(|(id, _)| *id > after).cloned().collect(),
            self.next_id,
        )
    }
}

// ---------- 有界审计日志（拍板决议②：协调者留滚动原始消息，不做事件库） ----------

/// 原始签名信封追加进 <data_dir>/fed/audit.jsonl（可离线验签）；超 10MB 轮转
/// 为 audit.jsonl.1（只保一代）。写失败只记日志——审计是外发副本，不阻塞主流程。
fn append_audit_log(data_dir: &Path, env: &Envelope, now: i64) {
    let dir = fed_dir(data_dir);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("audit.jsonl");
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > 10 * 1024 * 1024
    {
        let _ = std::fs::rename(&path, dir.join("audit.jsonl.1"));
    }
    let line = json!({
        "received_ts": now,
        "node": env.node,
        "seq": env.seq,
        "type": env.ty,
        "envelope": env,
    });
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}

/// 审计日志尾部 N 行（cmd_audit 用）。
fn audit_log_tail(data_dir: &Path, n: usize) -> Vec<serde_json::Value> {
    let Ok(raw) = std::fs::read_to_string(fed_dir(data_dir).join("audit.jsonl")) else {
        return Vec::new();
    };
    raw.lines()
        .rev()
        .take(n)
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// /fed 路由面。只挂在 mTLS 监听上：rustls 已验证客户端证书链到组织 CA，
/// accept 循环把对端叶子指纹与 DER 以 Extension 注入，handlers 经 FedPeer 取用。
/// 所有端点（含 hello）吃同一信封：Bytes 手工解析——畸形消息要计数告警，
/// 不能交给 axum Json 提取器的默认 422。
pub fn fed_router(engine: Arc<EngineHandle>) -> Router {
    let state = FedState {
        engine,
        gate: Arc::new(Mutex::new(GateState::default())),
        stats: Arc::new(FedStats::default()),
        feed: Arc::new(Mutex::new(OrgFeed::default())),
        limiter: Arc::new(Mutex::new(InboundLimiter::default())),
    };
    Router::new()
        .route("/fed/hello", post(fed_hello))
        .route("/fed/events", post(fed_events))
        .route("/fed/intel", get(fed_intel_get).post(fed_intel_post))
        .route("/fed/org-feed", get(fed_org_feed))
        .route("/fed/reports", post(fed_reports))
        .route("/fed/proposals", post(fed_proposals))
        .route("/fed/members", get(fed_members))
        .with_state(state)
}

fn err(e: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": e.to_string(), "server_proto": fedproto::PROTO })),
    )
        .into_response()
}

fn err_status(status: StatusCode, e: impl std::fmt::Display) -> Response {
    (
        status,
        Json(json!({ "error": e.to_string(), "server_proto": fedproto::PROTO })),
    )
        .into_response()
}

fn forbidden(node: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": format!(
            "node {node} 的证书指纹与注册时不符（冒用他人节点名或证书已更换需管理员删除成员记录）"
        )})),
    )
        .into_response()
}

/// node ↔ 证书指纹校验（TOFU）：首次登记，之后指纹必须一致；一致时刷新 last_seen。
/// 空指纹（理论上 mTLS 强制客户端证书后不该出现）按未接入处理。
#[allow(clippy::result_large_err)] // Response 是该模块统一的错误载体
fn check_member(state: &FedState, node: &str, fp: &str) -> Result<(), Response> {
    if fp.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "缺少客户端证书").into_response());
    }
    // 预登记校验（0.4.0 C2）：已预登记节点关闭 TOFU 抢注窗口
    let data_dir = state.engine.config().general.data_dir.clone();
    if !expected_ok(&load_expected(&data_dir), node, fp) {
        state.engine.bus.publish(SecurityEvent::engine(
            "warn",
            format!("协同接入被拒：{node} 指纹与预登记不符（可能的冒用/换证）"),
        ));
        return Err((StatusCode::FORBIDDEN, "指纹与预登记（fed expect）不符").into_response());
    }
    match state.engine.store.upsert_fed_member(node, now_ts(), fp) {
        Ok(true) => Ok(()),
        Ok(false) => Err(forbidden(node)),
        Err(e) => Err(err(format!("成员登记失败: {e}"))),
    }
}

// ---------- 信封闸门：所有 /fed 端点的统一入校验 ----------

enum Gate {
    /// 首见合法消息，照常处理
    Fresh(Box<Envelope>),
    /// 窗口内重复（补传重发），幂等跳过但按成功应答
    Duplicate(Box<Envelope>),
}

/// F400 隔离状态变更广播（一次性）：闸门处发现成员状态与上次广播不同 →
/// 事件流 + org-feed 广播。首次接触的 active 节点不广播（免噪音）。
fn announce_quarantine(state: &FedState, node: &str, status: &str) {
    let announce = {
        let mut gate = state.gate.lock().unwrap();
        match gate.quarantine_announced.get(node) {
            None => {
                if status == "quarantined" {
                    gate.quarantine_announced
                        .insert(node.to_string(), status.to_string());
                    true
                } else {
                    false
                }
            }
            Some(prev) if prev != status => {
                gate.quarantine_announced
                    .insert(node.to_string(), status.to_string());
                true
            }
            _ => false,
        }
    };
    if announce {
        let quarantined = status == "quarantined";
        state.engine.bus.publish(SecurityEvent::engine(
            if quarantined { "warn" } else { "info" },
            if quarantined {
                format!("节点 {node} 处于软隔离状态（事件/建议通道暂停，心跳与审计保留）")
            } else {
                format!("节点 {node} 软隔离已解除，协同通道恢复")
            },
        ));
        let msg = json!({
            "type": "quarantine",
            "quarantine": { "node": node, "status": status },
        });
        state.feed.lock().unwrap().push(msg);
    }
}

/// 解析信封并过五道闸：解析 → 版本协商 → 时间窗 → 消息验签 → 成员绑定 → 幂等/序列号。
/// 任何一道失败都是「单条拒绝 + 计数」，不断连不 panic（畸形消息不刷 GUI 事件，
/// 版本/签名失败只对每节点首次发告警事件）。
#[allow(clippy::result_large_err)] // Response 是该模块统一的错误载体（同 check_member）
fn gate_envelope(state: &FedState, peer: &FedPeer, body: &Bytes) -> Result<Gate, Response> {
    let now = now_ts();
    // 1) 解析：畸形单条丢弃 + 计数（不 publish——fuzz/扫描风暴不能灌爆事件总线）
    let env: Envelope = match serde_json::from_slice(body) {
        Ok(e) => e,
        Err(e) => {
            state.stats.malformed.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("fed 信封解析失败（已计数）: {e}");
            return Err(err_status(
                StatusCode::BAD_REQUEST,
                format!("信封解析失败（server_proto {}）: {e}", fedproto::PROTO),
            ));
        }
    };
    // 2) 版本协商：major 不同拒连，GUI 可见双方版本号（每节点只告警一次）
    if let Err(reason) = fedproto::version_compatible(&env.proto) {
        let mut gate = state.gate.lock().unwrap();
        if gate.version_warned.insert(env.node.clone()) {
            state.engine.bus.publish(SecurityEvent::engine(
                "warn",
                format!("协同协议版本失配（{}）：{reason}", env.node),
            ));
        }
        return Err(err_status(StatusCode::UPGRADE_REQUIRED, reason));
    }
    // 3) 信封时间窗：偏移超 24h 按重放拒收（这也是补传窗口的硬上限）
    if (env.ts - now).abs() > fedproto::REPLAY_WINDOW_SECS {
        state.stats.malformed.fetch_add(1, Ordering::Relaxed);
        return Err(err_status(
            StatusCode::BAD_REQUEST,
            format!(
                "信封时间戳超出 ±{}s 窗口（疑似重放/时钟失同步）",
                fedproto::REPLAY_WINDOW_SECS
            ),
        ));
    }
    // 3b) 节点名合法性（旧 handler 校验迁移至此，信封是唯一的 node 来源）
    if !valid_node_name(&env.node) {
        state.stats.malformed.fetch_add(1, Ordering::Relaxed);
        return Err(err("node 名不合法（限字母数字_-，≤32 字符）"));
    }
    // 4) 消息级验签：对端证书钥签名，防抵赖（mTLS 只保连接，签名跟着消息走）
    let pubkey = match fedproto::public_point_from_cert_der(&peer.cert_der) {
        Ok(p) => p,
        Err(e) => {
            state.stats.sig_fail.fetch_add(1, Ordering::Relaxed);
            return Err(err_status(StatusCode::UNAUTHORIZED, e));
        }
    };
    if !fedproto::verify_signature(&pubkey, &fedproto::signing_bytes(&env), &env.sig) {
        state.stats.sig_fail.fetch_add(1, Ordering::Relaxed);
        let mut gate = state.gate.lock().unwrap();
        if gate.sig_warned.insert(env.node.clone()) {
            state.engine.bus.publish(SecurityEvent::engine(
                "warn",
                format!(
                    "协同消息签名校验失败（{}，指纹 {}）：消息被篡改或私钥与证书不符",
                    env.node, peer.cert_fp
                ),
            ));
        }
        return Err(err_status(
            StatusCode::UNAUTHORIZED,
            "消息签名校验失败（须以本节点证书私钥签名）",
        ));
    }
    // 5) 成员绑定（TOFU/预登记 + last_seen 刷新）
    check_member(state, &env.node, &peer.cert_fp)?;
    // F400 软隔离与限频（成员状态以 DB 为真源，fed quarantine CLI 即时生效）
    let member_status = state
        .engine
        .store
        .fed_member_status(&env.node)
        .ok()
        .flatten()
        .unwrap_or_else(|| "active".into());
    announce_quarantine(state, &env.node, &member_status);
    if member_status == "quarantined"
        && matches!(
            env.ty.as_str(),
            fedproto::types::EVENTS | fedproto::types::PROPOSALS | fedproto::types::REPORTS
        )
    {
        state.stats.quarantined.fetch_add(1, Ordering::Relaxed);
        // 审计通道保留：隔离期消息仍留原始信封（可离线验签取证）
        append_audit_log(&state.engine.config().general.data_dir, &env, now);
        return Err(err_status(
            StatusCode::FORBIDDEN,
            "节点已被软隔离（心跳与审计保留，事件/建议通道暂停）；解除：协调者侧 fed quarantine <node> --lift <指纹前缀>",
        ));
    }
    let cap = state.engine.config().fed.inbound_rate_per_min;
    if !state.limiter.lock().unwrap().check(&env.node, now, cap)
        && env.ty != fedproto::types::HELLO
    {
        state.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Err(err_status(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "入站消息速率超限（{cap}/分钟）：该节点降级为仅心跳模式 {} 分钟（防广播放大）",
                fedproto::InboundLimiter::COOLDOWN_SECS / 60
            ),
        ));
    }
    let mut gate = state.gate.lock().unwrap();
    // 6a) 幂等：24h 窗内 (node, seq) 已见 = 补传重发，跳过但按成功应答
    if !gate.dedup().first_time(&env.node, env.seq, now, fedproto::REPLAY_WINDOW_SECS) {
        state.stats.duplicates.fetch_add(1, Ordering::Relaxed);
        return Ok(Gate::Duplicate(Box::new(env)));
    }
    // 6b) 序列号高水位：低于已见最大值 = 备份恢复/伪造重放，拒收留痕
    match state.engine.store.check_fed_seq(&env.node, env.seq) {
        Ok(true) => Ok(Gate::Fresh(Box::new(env))),
        Ok(false) => {
            state.stats.seq_reject.fetch_add(1, Ordering::Relaxed);
            let node = env.node.clone();
            drop(gate);
            state.engine.bus.publish(SecurityEvent::engine(
                "warn",
                format!(
                    "协同消息序列号回退（{node} seq {}）：疑似从备份恢复或伪造重放，已拒收",
                    env.seq
                ),
            ));
            Err(err_status(
                StatusCode::CONFLICT,
                format!(
                    "序列号 {} 不大于该节点已见最大值（疑似备份恢复/重放），拒收",
                    env.seq
                ),
            ))
        }
        Err(e) => Err(err(format!("序列号校验失败: {e}"))),
    }
}

/// hello：心跳 + 版本协商 + 组织状态问询，兼职 last_seen 刷新（F110 租约检测的地基）。
async fn fed_hello(
    State(state): State<FedState>,
    peer: axum::Extension<FedPeer>,
    body: Bytes,
) -> Response {
    let env = match gate_envelope(&state, &peer, &body) {
        Ok(Gate::Duplicate(e)) | Ok(Gate::Fresh(e)) => e,
        Err(resp) => return resp,
    };
    // 节点时钟偏移上报（F320 并入）：agent 用上一轮 hello 响应的 server_ts 算出偏移，
    // 随本轮 hello 带回；超阈值 → 该节点观测在印证计算中被剔除（宁少勿错）
    if let Some(offset) = env.payload["offset_secs"].as_i64() {
        state
            .engine
            .corroboration
            .lock()
            .map(|mut c| c.set_offset(&env.node, offset))
            .ok();
    }
    let members = state.engine.store.list_fed_members().unwrap_or_default().len();
    Json(json!({
        "ok": true,
        "proto": fedproto::PROTO,
        "version": env!("CARGO_PKG_VERSION"),
        "server_ts": now_ts(),
        "members": members,
        "stats": state.stats.to_json(),
        "echo": { "node": env.node, "seq": env.seq },
    }))
    .into_response()
}

// ---------- agent → 协调者：事件上报 ----------

#[derive(Clone, Deserialize)]
struct FedEvent {
    ts: i64,
    kind: String,
    remote_ip: String,
    /// JA3 md5（detect 事件才有；F200 指纹维度输入）
    #[serde(default)]
    tls_fp: String,
    /// JA4（同上）
    #[serde(default)]
    tls_ja4: String,
    // listener/remote_port/summary 不参与印证——完整载荷已随原始信封进审计日志
}

#[derive(Clone, Deserialize)]
struct FedCred {
    ts: i64,
    username: String,
}

#[derive(Deserialize)]
struct FedEventsPayload {
    events: Vec<FedEvent>,
    /// 凭证观测（F200 凭证维度，v1 用户名比对；无可逆材料——见 corroboration.rs 头注）
    #[serde(default)]
    credentials: Vec<FedCred>,
}

/// 观测投影：节点事件 → 印证窗口的原始观测（只取节点/时间/维度/键四元组）。
fn observations_of(node: &str, p: &FedEventsPayload) -> Vec<Observation> {
    let mut obs = Vec::new();
    for ev in &p.events {
        obs.push(Observation {
            node: node.to_string(),
            ts: ev.ts,
            dim: Dim::Ip,
            key: ev.remote_ip.clone(),
        });
        if !ev.tls_fp.is_empty() {
            obs.push(Observation {
                node: node.to_string(),
                ts: ev.ts,
                dim: Dim::Fingerprint,
                key: ev.tls_fp.clone(),
            });
        }
        if !ev.tls_ja4.is_empty() {
            obs.push(Observation {
                node: node.to_string(),
                ts: ev.ts,
                dim: Dim::Fingerprint,
                key: ev.tls_ja4.clone(),
            });
        }
        if ev.kind == "canary" {
            // 蜜饵水印触发（0.5.10 canary 事件）：横向移动线索维度
            obs.push(Observation {
                node: node.to_string(),
                ts: ev.ts,
                dim: Dim::Canary,
                key: ev.remote_ip.clone(),
            });
        }
    }
    for c in &p.credentials {
        obs.push(Observation {
            node: node.to_string(),
            ts: c.ts,
            dim: Dim::Credential,
            key: c.username.clone(),
        });
    }
    obs
}

async fn fed_events(
    State(state): State<FedState>,
    peer: axum::Extension<FedPeer>,
    body: Bytes,
) -> Response {
    let env = match gate_envelope(&state, &peer, &body) {
        Ok(Gate::Duplicate(_)) => {
            return Json(json!({ "ok": true, "duplicate": true })).into_response();
        }
        Ok(Gate::Fresh(e)) => e,
        Err(resp) => return resp,
    };
    let payload: FedEventsPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(v) => v,
        Err(e) => {
            state.stats.malformed.fetch_add(1, Ordering::Relaxed);
            return err(format!("events payload 非法: {e}"));
        }
    };
    if payload.events.len() > 100 {
        return err("单次上报最多 100 条事件");
    }
    if payload.credentials.len() > 100 {
        return err("单次上报最多 100 条凭证观测");
    }
    let now = now_ts();
    let mut archived = 0usize;
    // 补传窗过滤在投影前做（>24h 的旧事件不进印证，只计数；本地哈希链是归档真源）
    let fresh: Vec<FedEvent> = payload
        .events
        .iter()
        .filter(|ev| {
            if now - ev.ts > fedproto::REPLAY_WINDOW_SECS {
                archived += 1;
                return false;
            }
            ev.ts - now <= 3600
        })
        .cloned()
        .collect();
    let filtered = FedEventsPayload {
        events: fresh,
        credentials: payload
            .credentials
            .iter()
            .filter(|c| now - c.ts <= fedproto::REPLAY_WINDOW_SECS && c.ts - now <= 3600)
            .cloned()
            .collect(),
    };
    if archived > 0 {
        state
            .stats
            .archived_events
            .fetch_add(archived as u64, Ordering::Relaxed);
    }
    // 拍板决议②：协调者不再把节点事件写进自己的 events 表——原始签名信封进
    // 有界审计日志（可离线验签），观测进内存印证窗口
    append_audit_log(&state.engine.config().general.data_dir, &env, now);
    // 观测 → 印证评估；新产出的组织事件进广播环 + 协调者事件流（GUI 可见）
    let mut emitted: Vec<OrgCorroboration> = Vec::new();
    for obs in observations_of(&env.node, &filtered) {
        let hit = state
            .engine
            .corroboration
            .lock()
            .ok()
            .and_then(|mut c| c.record(&obs, now));
        if let Some(mut oc) = hit {
            let msg = json!({
                "type": "corroboration",
                "corroboration": oc.to_json(),
            });
            let feed_id = state.feed.lock().unwrap().push(msg);
            oc.id = feed_id; // 对外 id 统一用 feed 游标（agent 去重键）
            // F300：印证驱动的组织建议（F300 产生源之一）。仅 ip/canary 维度有
            // 可封禁目标；进各节点慢路径 pending，人工确认——印证只加置信不变
            if matches!(oc.dim, Dim::Ip | Dim::Canary) {
                // F300：该键已达组织推荐 → 推送时提高默认严重度（仍是建议）
                let boosted = state
                    .engine
                    .corroboration
                    .lock()
                    .map(|c| {
                        c.adoption.recommended(
                            &format!("block:{}:any", oc.key),
                            state.engine.config().fed.org_adoption_percent.clamp(1, 100),
                            2,
                        )
                    })
                    .unwrap_or(false);
                let severity = if boosted { "critical" } else { oc.severity.as_str() };
                let sugg = json!({
                    "type": "org-suggestion",
                    "suggestion": {
                        "origin": "corroboration",
                        "key": format!("block:{}:any", oc.key),
                        "action": "block",
                        "direction": "in",
                        "protocol": "any",
                        "remote_ip": oc.key,
                        "local_port": serde_json::Value::Null,
                        "severity": severity,
                        "reason": format!(
                            "组织印证（{} 个节点独立观测到 {}）",
                            oc.nodes.len(),
                            oc.key
                        ),
                    },
                });
                state.feed.lock().unwrap().push(sugg);
            }
            emitted.push(oc);
        }
    }
    for oc in &emitted {
        state.engine.bus.publish(SecurityEvent::engine(
            if oc.severity == "critical" { "warn" } else { "info" },
            format!(
                "组织印证：{} 「{}」由 {} 个节点独立观测（{}）——仅加置信，处置仍归各节点本地决策",
                oc.dim.as_str(),
                oc.key,
                oc.nodes.len(),
                oc.nodes.join("、")
            ),
        ));
    }
    Json(json!({
        "ok": true,
        "accepted_events": filtered.events.len(),
        "accepted_credentials": filtered.credentials.len(),
        "archived": archived,
        "corroborations": emitted.len(),
    }))
    .into_response()
}

// ---------- agent 拉取组织消息（F200）：印证事件广播 ----------

#[derive(Deserialize)]
struct OrgFeedQuery {
    node: String,
    #[serde(default)]
    after: u64,
}

async fn fed_org_feed(
    State(state): State<FedState>,
    peer: axum::Extension<FedPeer>,
    axum::extract::Query(q): axum::extract::Query<OrgFeedQuery>,
) -> Response {
    if !valid_node_name(&q.node) {
        return err("node 名不合法");
    }
    if let Err(resp) = check_member(&state, &q.node, &peer.cert_fp) {
        return resp;
    }
    let (messages, cursor) = state.feed.lock().unwrap().since(q.after);
    Json(json!({
        "ok": true,
        "cursor": cursor,
        "messages": messages.iter().map(|(id, m)| json!({ "id": id, "msg": m })).collect::<Vec<_>>(),
    }))
    .into_response()
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
struct FedIntelEntry {
    value: String,
    kind: String,
}

async fn fed_intel_post(
    State(state): State<FedState>,
    peer: axum::Extension<FedPeer>,
    body: Bytes,
) -> Response {
    let env = match gate_envelope(&state, &peer, &body) {
        Ok(Gate::Duplicate(_)) => {
            return Json(json!({ "ok": true, "duplicate": true })).into_response();
        }
        Ok(Gate::Fresh(e)) => e,
        Err(resp) => return resp,
    };
    let entries: Vec<FedIntelEntry> = match serde_json::from_value(env.payload.clone()) {
        Ok(v) => v,
        Err(e) => {
            state.stats.malformed.fetch_add(1, Ordering::Relaxed);
            return err(format!("intel payload 非法: {e}"));
        }
    };
    if entries.len() > 500 {
        return err("单次同步最多 500 条情报");
    }
    let now = now_ts();
    let upserts: Vec<(String, String, String, String, i64, i64)> = entries
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
                format!("fed:{}", env.node),
                e.kind.clone(),
                e.value.clone(),
                "fed".into(),
                now,
                now + 7 * 86400,
            )
        })
        .collect();
    let n = state.engine.store.upsert_intel(&upserts).unwrap_or(0);
    state.engine.bus.publish(SecurityEvent::engine(
        "info",
        format!(
            "组织情报同步：来自 {} 的 {} 条（仅标注，不自动封禁）",
            env.node, n
        ),
    ));
    Json(json!({ "ok": true, "accepted": n })).into_response()
}

// ---------- 协调者 → agent：情报下发（agent 拉取同上）；AI 建议推送 ----------

async fn fed_proposals(
    State(state): State<FedState>,
    peer: axum::Extension<FedPeer>,
    body: Bytes,
) -> Response {
    let env = match gate_envelope(&state, &peer, &body) {
        Ok(Gate::Duplicate(_)) => {
            return Json(json!({ "ok": true, "duplicate": true })).into_response();
        }
        Ok(Gate::Fresh(e)) => e,
        Err(resp) => return resp,
    };
    let proposals: Vec<serde_json::Value> = match serde_json::from_value(env.payload.clone()) {
        Ok(v) => v,
        Err(e) => {
            state.stats.malformed.fetch_add(1, Ordering::Relaxed);
            return err(format!("proposals payload 非法: {e}"));
        }
    };
    if proposals.len() > 10 {
        return err("单次推送最多 10 条建议");
    }
    let mut accepted = 0usize;
    for p in &proposals {
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
            &format!("fed:{}", env.node),
            "block",
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
            // F300：推送全组织（产生源之二：节点 AI 建议组织共享）——协调者本地
            // 留一份 pending，其余节点经 org-feed 拉取后各自复验
            let key = format!(
                "block:{}:{}",
                valid.remote_ip,
                valid.local_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "any".into())
            );
            // F300：该键已达组织推荐 → 推送时提高默认严重度（仍是建议）
            let boosted = state
                .engine
                .corroboration
                .lock()
                .map(|c| {
                    c.adoption.recommended(
                        &key,
                        state.engine.config().fed.org_adoption_percent.clamp(1, 100),
                        2,
                    )
                })
                .unwrap_or(false);
            let severity = if boosted { "critical" } else { valid.severity.as_str() };
            let sugg = json!({
                "type": "org-suggestion",
                "suggestion": {
                    "origin": env.node,
                    "key": key,
                    "action": "block",
                    "direction": valid.direction,
                    "protocol": valid.protocol,
                    "remote_ip": valid.remote_ip,
                    "local_port": valid.local_port,
                    "severity": severity,
                    "reason": valid.reason,
                },
            });
            state.feed.lock().unwrap().push(sugg);
        }
    }
    Json(json!({ "ok": true, "accepted": accepted })).into_response()
}

// ---------- F300：建议生命周期回流（采纳/收弃/误报）与组织推荐升级 ----------

#[derive(Deserialize)]
struct FedReport {
    key: String,
    /// applied | promoted | dismissed | fp
    outcome: String,
    /// 提议方去重引用（建议 id / 误报 last_ts）
    ref_id: i64,
}

async fn fed_reports(
    State(state): State<FedState>,
    peer: axum::Extension<FedPeer>,
    body: Bytes,
) -> Response {
    let env = match gate_envelope(&state, &peer, &body) {
        Ok(Gate::Duplicate(_)) => {
            return Json(json!({ "ok": true, "duplicate": true })).into_response();
        }
        Ok(Gate::Fresh(e)) => e,
        Err(resp) => return resp,
    };
    let payload: Vec<FedReport> = match serde_json::from_value(env.payload.clone()) {
        Ok(v) => v,
        Err(e) => {
            state.stats.malformed.fetch_add(1, Ordering::Relaxed);
            return err(format!("reports payload 非法: {e}"));
        }
    };
    if payload.len() > 100 {
        return err("单次回流最多 100 条");
    }
    append_audit_log(&state.engine.config().general.data_dir, &env, now_ts());
    let threshold = state.engine.config().fed.org_adoption_percent.clamp(1, 100);
    let mut accepted = 0usize;
    // 触发的推荐升级先收集再广播（不持锁推 feed/总线）
    let mut fires: Vec<(String, crate::corroboration::AdoptionStats)> = Vec::new();
    let mut fp_flags: Vec<(String, u32)> = Vec::new();
    if let Ok(mut c) = state.engine.corroboration.lock() {
        for r in &payload {
            if !c.adoption.record(&env.node, r.ref_id, &r.key, &r.outcome) {
                continue;
            }
            accepted += 1;
            // 误报标记 → fp-flag 广播（建议性质，接收方只提示不动作）
            if r.outcome == "fp" {
                let st = c.adoption.stats_of(&r.key);
                fp_flags.push((r.key.clone(), st.fp));
            }
            if c.adoption.should_fire(&r.key, threshold, 2) {
                c.adoption.mark_recommended(&r.key);
                fires.push((r.key.clone(), c.adoption.stats_of(&r.key)));
            }
        }
    }
    for (key, count) in fp_flags {
        let msg = json!({
            "type": "fp-flag",
            "fp": { "key": key, "count": count, "origin": env.node },
        });
        state.feed.lock().unwrap().push(msg);
    }
    for (key, st) in fires {
        let msg = json!({
            "type": "quorum",
            "quorum": {
                "key": key,
                "applied": st.applied,
                "dismissed": st.dismissed,
                "threshold": threshold,
            },
        });
        state.feed.lock().unwrap().push(msg);
        state.engine.bus.publish(SecurityEvent::engine(
            "info",
            format!(
                "组织推荐升级：「{key}」采纳 {} / 收弃 {}（采纳率 ≥ {threshold}%，零误报）——各节点复验默认严重度提高，仍为建议",
                st.applied, st.dismissed
            ),
        ));
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
        .map(|(node, cert_fp, last_seen, status)| {
            json!({ "node": node, "cert_fp": cert_fp, "last_seen": last_seen, "status": status })
        })
        .collect();
    Json(members).into_response()
}

// ---------- PKI：fed init-ca / fed issue-cert ----------

fn fed_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("fed")
}

fn certs_dir(data_dir: &Path) -> PathBuf {
    fed_dir(data_dir).join("certs")
}

/// `fed init-ca [组织名]`：生成组织 CA（自签 10 年）写入 <数据目录>/fed/。
/// 组织名只是「公章上刻的字」（展示用，成员面板/证书 CN 可见），不是加入凭据——
/// 加入凭据是本 CA 签发的节点证书。已存在时明确拒绝（覆盖 CA = 全网信任重置，
/// 绝不能静默发生）。
pub fn cmd_init_ca(data_dir: &Path, org_name: &str) -> anyhow::Result<()> {
    let dir = fed_dir(data_dir);
    std::fs::create_dir_all(certs_dir(data_dir))?;
    let ca_pem = dir.join("ca.pem");
    let ca_key = dir.join("ca-key.pem");
    if ca_pem.exists() || ca_key.exists() {
        anyhow::bail!(
            "组织 CA 已存在（{}），避免覆盖；确需重建请先手动删除",
            ca_pem.display()
        );
    }
    // 组织名进证书 CN：限可见 ASCII 可打印、≤64 字符，缺省沿用内置名
    let org_name = org_name.trim();
    let org_name = if org_name.is_empty() {
        "AI-SafeGuard Organization CA"
    } else {
        if org_name.len() > 64
            || !org_name
                .chars()
                .all(|c| c.is_ascii_graphic())
        {
            anyhow::bail!("组织名限 ≤64 个可见 ASCII 字符（证书 CN 字段约束）");
        }
        org_name
    };
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, org_name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    // 回拨 1 小时容忍节点间时钟漂移；有效期 10 年
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    std::fs::write(&ca_pem, cert.pem())?;
    write_private(&ca_key, key.serialize_pem())?;
    println!("✓ 组织 CA 已生成（有效期 10 年）：");
    println!("  证书: {}", ca_pem.display());
    println!("  私钥: {}（仅协调者侧保管，勿分发）", ca_key.display());
    Ok(())
}

/// `fed issue-cert <node> [--san <dns|ip> ...]`：用组织 CA 签发节点证书。
/// 默认 SAN = 节点名（DNS）；协调者需追加其对外地址（如 --san 127.0.0.1）。
/// 证书同时含 clientAuth 与 serverAuth EKU——每节点一张证书，两用。
pub fn cmd_issue_cert(data_dir: &Path, node: &str, sans: &[String]) -> anyhow::Result<()> {
    if !valid_node_name(node) {
        anyhow::bail!("node 名不合法（限字母数字_-，≤32 字符）");
    }
    let ca_pem = fed_dir(data_dir).join("ca.pem");
    let ca_key_pem = fed_dir(data_dir).join("ca-key.pem");
    if !ca_pem.exists() || !ca_key_pem.exists() {
        anyhow::bail!("组织 CA 不存在，先执行 fed init-ca（{}）", ca_pem.display());
    }
    // 加载 CA：from_ca_cert_pem 提取签发所需元数据（DN/密钥标识法）；
    // signed_by 的 issuer 形参是 Certificate——用同一参数+同一密钥重建 issuer
    // 元数据（SKI/AKI 由公钥确定性派生，DN 从文件读取；重建的 DER 不落盘）
    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(&std::fs::read_to_string(&ca_pem)?)?;
    let ca_key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(&ca_key_pem)?)?;
    let issuer_cert = ca_params.clone().self_signed(&ca_key)?;

    let mut san_values: Vec<rcgen::SanType> = vec![rcgen::SanType::DnsName(
        rcgen::Ia5String::try_from(node.to_string())?,
    )];
    for s in sans {
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            san_values.push(rcgen::SanType::IpAddress(ip));
        } else {
            san_values.push(rcgen::SanType::DnsName(rcgen::Ia5String::try_from(
                s.clone(),
            )?));
        }
    }
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, node);
    params.subject_alt_names = san_values;
    params.is_ca = rcgen::IsCa::NoCa;
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
    let key = rcgen::KeyPair::generate()?;
    let cert = params.signed_by(&key, &issuer_cert, &ca_key)?;

    let out_pem = certs_dir(data_dir).join(format!("{node}.pem"));
    let out_key = certs_dir(data_dir).join(format!("{node}-key.pem"));
    std::fs::create_dir_all(certs_dir(data_dir))?;
    std::fs::write(&out_pem, cert.pem())?;
    write_private(&out_key, key.serialize_pem())?;
    println!("✓ 节点证书已签发：");
    println!("  证书: {}", out_pem.display());
    println!("  私钥: {}（分发到对应节点保管）", out_key.display());
    println!("  指纹（SHA-256）: {}", cert_fp_of(cert.der()));
    println!("  分发后节点配置 [fed] 节点: ca/cert/key 路径（或放到 <数据目录>/fed/ 默认位置）");
    Ok(())
}

/// 私钥文件落盘：Unix 收紧到 0600（Windows 继承用户 profile ACL）。
fn write_private(path: &Path, pem: String) -> anyhow::Result<()> {
    std::fs::write(path, pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------- 协调者：独立 mTLS 监听面 ----------

/// 吊销列表文件（0.4.0 C1，手动 CRL）：`[{fp, ts, reason}]`，JSON 数组。
pub fn revocations_path(data_dir: &Path) -> PathBuf {
    fed_dir(data_dir).join("revoked.json")
}

/// 读吊销指纹集合；文件不存在/损坏返回空集（损坏留由命令侧提示）。
pub fn load_revocations(data_dir: &Path) -> std::collections::HashSet<String> {
    let raw = match std::fs::read(revocations_path(data_dir)) {
        Ok(b) => b,
        Err(_) => return Default::default(),
    };
    serde_json::from_str::<Vec<serde_json::Value>>(&String::from_utf8_lossy(&raw))
        .map(|v| {
            v.iter()
                .filter_map(|e| e["fp"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `fed revoke <fp|node> [原因]`：按指纹或节点名（读 certs/<node>.pem 算指纹）吊销。
/// 立即生效——协调者每次连接检查该集合，不依赖证书有效期。
pub fn cmd_revoke(data_dir: &Path, target: &str, reason: &str) -> anyhow::Result<String> {
    let fp = if target.len() == 64 && target.chars().all(|c| c.is_ascii_hexdigit()) {
        target.to_ascii_lowercase()
    } else {
        let cert = certs_dir(data_dir).join(format!("{target}.pem"));
        let der = read_pem_certs(&cert)
            .map_err(|e| anyhow::anyhow!("节点证书不可读（{cert:?}）: {e}"))?
            .remove(0);
        cert_fp_of(der.as_ref())
    };
    std::fs::create_dir_all(fed_dir(data_dir))?;
    let path = revocations_path(data_dir);
    let mut list: Vec<serde_json::Value> = std::fs::read(&path)
        .map(|b| serde_json::from_str(&String::from_utf8_lossy(&b)).unwrap_or_default())
        .unwrap_or_default();
    if list.iter().any(|e| e["fp"].as_str() == Some(fp.as_str())) {
        anyhow::bail!("该指纹已在吊销列表中");
    }
    list.push(serde_json::json!({
        "fp": fp, "ts": now_ts(), "reason": reason,
    }));
    std::fs::write(&path, serde_json::to_string_pretty(&list)?)?;
    Ok(fp)
}

/// 连接级吊销检查：指纹在吊销集合中返回 false（并给拒绝原因）。
/// Some(原因) = 已吊销应拒连；None = 通过。
pub fn check_not_revoked(data_dir: &Path, cert_fp: &str) -> Option<String> {
    if load_revocations(data_dir).contains(cert_fp) {
        return Some("该证书已被吊销（fed revoke），组织同步被拒绝".to_string());
    }
    None
}

/// 预登记表（0.4.0 C2）：`{node: expected_fp}` JSON——关闭该节点的 TOFU 抢注窗口：
/// 预登记后，非匹配指纹的首次绑定也被拒。
pub fn expected_path(data_dir: &Path) -> PathBuf {
    fed_dir(data_dir).join("expected.json")
}

/// 读预登记表（文件不存在/损坏返回空表）。
pub fn load_expected(data_dir: &Path) -> std::collections::HashMap<String, String> {
    std::fs::read(expected_path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// 预登记校验：节点已预登记时指纹必须精确匹配；未预登记走 TOFU。
pub fn expected_ok(
    expected: &std::collections::HashMap<String, String>,
    node: &str,
    cert_fp: &str,
) -> bool {
    match expected.get(node) {
        Some(want) => want == cert_fp,
        None => true,
    }
}

/// `fed audit <out.json>`（0.4.0 C4）：协同审计导出——成员表、吊销表、
/// 窗口内协同上报统计与最近协同事件样例。需读数据目录（含 DB）。
pub fn cmd_audit(data_dir: &Path, out: &Path, window_secs: i64) -> anyhow::Result<()> {
    let db = data_dir.join("aisafeguard.db");
    let store = aisafeguard_store::Store::open(&db)?;
    let now = now_ts();
    let members: Vec<serde_json::Value> = store
        .list_fed_members()?
        .into_iter()
        .map(|(node, cert_fp, last_seen, status)| {
            serde_json::json!({ "node": node, "cert_fp": cert_fp, "last_seen": last_seen, "status": status })
        })
        .collect();
    let revocations: Vec<serde_json::Value> = std::fs::read(revocations_path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    // 最近收到的原始签名信封（F200 起：协调者不留事件库，审计看 audit.jsonl）
    let fed_envelopes = audit_log_tail(data_dir, 50);
    let doc = serde_json::json!({
        "exported_ts": now,
        "window_secs": window_secs,
        "members": members,
        "revocations": revocations,
        "recent_fed_envelopes": fed_envelopes,
    });
    std::fs::write(out, serde_json::to_string_pretty(&doc)?)?;
    println!(
        "✓ 协同审计已导出 {}（成员 {} · 吊销 {} · 近期原始信封 {}）",
        out.display(),
        members.len(),
        revocations.len(),
        fed_envelopes.len()
    );
    Ok(())
}

/// `fed expect <node> <fp>`：预登记节点指纹（签发后、节点上线前执行）。
pub fn cmd_expect(data_dir: &Path, node: &str, fp: &str) -> anyhow::Result<()> {
    if !valid_node_name(node) {
        anyhow::bail!("node 名不合法（限字母数字_-，≤32 字符）");
    }
    let fp = fp.to_ascii_lowercase();
    if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("指纹须为 64 位十六进制（fed issue-cert 输出的 SHA-256）");
    }
    std::fs::create_dir_all(fed_dir(data_dir))?;
    let path = expected_path(data_dir);
    let mut map = load_expected(data_dir);
    map.insert(node.to_string(), fp);
    std::fs::write(&path, serde_json::to_string_pretty(&map)?)?;
    println!("✓ 已预登记 {node} 的证书指纹（该节点非匹配指纹的接入将被拒）");
    Ok(())
}

/// `fed quarantine <node> [原因]` / `fed quarantine <node> --lift <指纹前缀>`（F400 软隔离）。
/// 与吊销的区别：吊销断一切连接（驱离），隔离保留心跳与审计、只断事件/建议通道
/// （留观察的停权）。解除需管理员提供证书指纹前缀（≥16 位十六进制）确认——防误操作。
pub fn cmd_quarantine(data_dir: &Path, node: &str, lift_fp: &str, reason: &str) -> anyhow::Result<()> {
    if !valid_node_name(node) {
        anyhow::bail!("node 名不合法（限字母数字_-，≤32 字符）");
    }
    let db = data_dir.join("aisafeguard.db");
    let store = aisafeguard_store::Store::open(&db)?;
    if lift_fp.is_empty() {
        let reason = reason.trim();
        let reason = if reason.is_empty() { "（管理员未注明原因）" } else { reason };
        if !store.set_fed_member_status(node, "quarantined")? {
            anyhow::bail!("成员 {node} 不存在（先 issue-cert 并等其上线）");
        }
        store
            .insert_event(&SecurityEvent::engine(
                "warn",
                format!("节点 {node} 已软隔离：{reason}（心跳与审计保留，事件/建议通道暂停）"),
            ))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("✓ 已软隔离 {node}");
        println!("  解除：fed quarantine {node} --lift <证书指纹前缀≥16位>");
        println!("  指纹查询：fed audit 导出或 GET /fed/members 的 cert_fp 字段");
        Ok(())
    } else {
        let fp = lift_fp.to_ascii_lowercase();
        if fp.len() < 16 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("解除隔离需提供证书指纹前缀（≥16 位十六进制）——防误操作解除");
        }
        let members = store.list_fed_members()?;
        let Some((_, cert_fp, _, _)) = members.iter().find(|(n, _, _, _)| n == node) else {
            anyhow::bail!("成员 {node} 不存在");
        };
        if !cert_fp.starts_with(&fp) {
            anyhow::bail!("指纹前缀与 {node} 的证书指纹不符，拒绝解除（宁停勿乱）");
        }
        if !store.set_fed_member_status(node, "active")? {
            anyhow::bail!("成员 {node} 不存在");
        }
        store
            .insert_event(&SecurityEvent::engine(
                "info",
                format!("节点 {node} 软隔离已解除（指纹前缀 {fp}… 验证通过）"),
            ))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("✓ 已解除 {node} 的软隔离（指纹前缀验证通过）");
        Ok(())
    }
}

/// 解析 fed 证书文件路径：空配置回退 <数据目录>/fed/ 默认位置。
pub fn resolve_fed_path(data_dir: &Path, configured: &str, default_name: &str) -> PathBuf {
    if configured.is_empty() {
        fed_dir(data_dir).join(default_name)
    } else {
        PathBuf::from(configured)
    }
}

/// 节点证书对（cert+key）解析：显式路径优先；否则 cert.pem/key.pem，
/// 其次 issue-cert 的产出位置 certs/<node>.pem（协调者本机自签自用的自然布局）。
fn resolve_node_pair(
    data_dir: &Path,
    cert_cfg: &str,
    key_cfg: &str,
    node: &str,
) -> (PathBuf, PathBuf) {
    let cert = match resolve_fed_path(data_dir, cert_cfg, "cert.pem") {
        p if p.exists() || !cert_cfg.is_empty() => p,
        _ => certs_dir(data_dir).join(format!("{node}.pem")),
    };
    let key = match resolve_fed_path(data_dir, key_cfg, "key.pem") {
        p if p.exists() || !key_cfg.is_empty() => p,
        _ => certs_dir(data_dir).join(format!("{node}-key.pem")),
    };
    (cert, key)
}

/// 提取 PEM 文件里所有 `-----BEGIN <label>-----…-----END <label>-----` 的 base64 体。
/// 手写解析（纯函数）：依赖树把 rustls-pki-types 钉在无 pem 特性的旧版，
/// 特性合并防不胜防（LESSONS），15 行换零图风险。
fn pem_blocks(text: &str, label: &str) -> Vec<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&begin) {
        let Some(j) = rest[i..].find(&end) else { break };
        let body: String = rest[i + begin.len()..i + j]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        out.push(body);
        rest = &rest[i + j + end.len()..];
    }
    out
}

fn read_pem_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let mut out = Vec::new();
    for block in pem_blocks(&String::from_utf8_lossy(&raw), "CERTIFICATE") {
        let der = base64::engine::general_purpose::STANDARD
            .decode(block)
            .map_err(|e| format!("{} 内 base64 解码失败: {e}", path.display()))?;
        out.push(rustls::pki_types::CertificateDer::from(der));
    }
    if out.is_empty() {
        return Err(format!("{} 中没有 CERTIFICATE 块", path.display()));
    }
    Ok(out)
}

/// 私钥一律 PKCS#8（rcgen 签发即此格式）。
fn read_pem_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let block = pem_blocks(&String::from_utf8_lossy(&raw), "PRIVATE KEY")
        .into_iter()
        .next()
        .ok_or_else(|| format!("{} 中没有 PRIVATE KEY 块", path.display()))?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(block)
        .map_err(|e| format!("{} 内 base64 解码失败: {e}", path.display()))?;
    Ok(rustls::pki_types::PrivatePkcs8KeyDer::from(der).into())
}

/// 协调者 /fed 面：mTLS 监听（rustls 强制客户端证书链到组织 CA）。
/// 材料缺失/非法时返回 Err，由调用方降级留痕（不影响引擎其余功能）。
pub async fn serve_coordinator(engine: Arc<EngineHandle>) -> Result<(), String> {
    let cfg = engine.config().fed;
    let data_dir = engine.config().general.data_dir.clone();
    let ca_path = resolve_fed_path(&data_dir, &cfg.ca_path, "ca.pem");
    let (cert_path, key_path) =
        resolve_node_pair(&data_dir, &cfg.cert_path, &cfg.key_path, &cfg.node);

    let mut roots = rustls::RootCertStore::empty();
    for c in read_pem_certs(&ca_path)? {
        roots
            .add(c)
            .map_err(|e| format!("组织 CA 加入信任库失败: {e}"))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
        .build()
        .map_err(|e| format!("客户端证书校验器构建失败: {e}"))?;
    let server_certs = read_pem_certs(&cert_path)?;
    let server_key = read_pem_private_key(&key_path)?;
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| format!("本节点证书/私钥装配失败: {e}"))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let addr: SocketAddr = cfg
        .listen_addr
        .parse()
        .map_err(|_| format!("listen_addr 非法: {}", cfg.listen_addr))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("mTLS 监听 {addr} 绑定失败: {e}"))?;
    tracing::info!("组织协同 mTLS 面已监听 {addr}");
    let app = fed_router(engine.clone());
    let (audit_bus, audit_dir) = {
        let eng = engine.clone();
        (eng.bus.clone(), eng.config().general.data_dir.clone())
    };

    loop {
        let (tcp, _) = listener
            .accept()
            .await
            .map_err(|e| format!("mTLS 监听器错误: {e}"))?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        let (bus, data_dir) = (audit_bus.clone(), audit_dir.clone());
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(tcp).await else {
                return; // 握手失败（无证书/链不可信/协议错误）：连接层拒绝即可
            };
            // 客户端证书已验证；叶子指纹 + DER 注入请求扩展（DER 供消息级验签取公钥）
            let leaf_der = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec());
            let cert_fp = leaf_der
                .as_ref()
                .map(|d| cert_fp_of(d))
                .unwrap_or_default();
            // 吊销检查（0.4.0 C1）：立即生效（每次连接读文件），命中拒连并留审计事件
            if let Some(reason) = check_not_revoked(&data_dir, &cert_fp) {
                bus.publish(SecurityEvent::engine(
                    "warn",
                    format!("协同连接被拒：{reason}"),
                ));
                return;
            }
            // Router 直接实现 tower Service<Request<Incoming>>，TowerToHyperService 适配
            let svc = hyper_util::service::TowerToHyperService::new(app.layer(axum::Extension(
                FedPeer {
                    cert_fp,
                    cert_der: leaf_der.unwrap_or_default(),
                },
            )));
            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
        });
    }
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
    #[serde(skip_serializing_if = "String::is_empty")]
    tls_fp: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tls_ja4: String,
}

/// agent 的 mTLS HTTP 客户端：携带本节点证书（clientAuth）+ 组织 CA 验证协调者。
fn build_agent_client(eng: &EngineHandle) -> Result<reqwest::Client, String> {
    let cfg = eng.config().fed;
    let data_dir = eng.config().general.data_dir.clone();
    let ca_path = resolve_fed_path(&data_dir, &cfg.ca_path, "ca.pem");
    let (cert_path, key_path) =
        resolve_node_pair(&data_dir, &cfg.cert_path, &cfg.key_path, &cfg.node);
    let ca_pem = std::fs::read(&ca_path).map_err(|e| {
        format!(
            "组织 CA 不可读（{}）: {e} —— 先向协调者管理员获取 ca.pem",
            ca_path.display()
        )
    })?;
    let mut cert_pem = std::fs::read(&cert_path).map_err(|e| {
        format!(
            "本节点证书不可读（{}）: {e} —— 向协调者管理员执行 fed issue-cert {}",
            cert_path.display(),
            cfg.node
        )
    })?;
    let key_pem = std::fs::read(&key_path)
        .map_err(|e| format!("本节点私钥不可读（{}）: {e}", key_path.display()))?;
    cert_pem.extend_from_slice(&key_pem);
    let identity = reqwest::Identity::from_pem(&cert_pem)
        .map_err(|e| format!("节点证书/私钥装配失败: {e}"))?;
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .identity(identity)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| format!("组织 CA 解析失败: {e}"))?,
        )
        .build()
        .map_err(|e| format!("HTTP client 构建失败: {e}"))
}

/// agent 角色：周期性向协调者上报本地事件、拉取组织情报、推送待确认建议。
/// 0.6 F100：每条消息走统一信封（版本协商 / 消息签名 / node+seq 幂等）；
/// hello 兼职心跳与版本探测。发送失败同信封重发（接收方去重，语义幂等）；
/// 收到 4xx 丢弃信封下轮重建（游标未推进，不会丢数据）。协调者失联或
/// 证书材料缺失只记警告，本节点一切功能照常（独立运行优先）。
enum SendOutcome {
    Ok(serde_json::Value),
    Network(String),
    Rejected(u16, String),
}

async fn post_envelope(
    http: &reqwest::Client,
    base: &str,
    path: &str,
    bytes: &[u8],
) -> SendOutcome {
    match http
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .body(bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            if (200..300).contains(&status) {
                serde_json::from_str(&body).map(SendOutcome::Ok).unwrap_or(SendOutcome::Ok(json!({})))
            } else {
                SendOutcome::Rejected(status, body)
            }
        }
        Err(e) => SendOutcome::Network(e.to_string()),
    }
}

/// 组装并签名一条信封。seq 先落盘后发送：崩溃可容忍间隙（单调 ≠ 连续），
/// 不可容忍回退（接收方按高水位拒收）。
fn seal_envelope(
    eng: &EngineHandle,
    node: &str,
    key: &ring::signature::EcdsaKeyPair,
    seq: &mut u64,
    ty: &str,
    payload: serde_json::Value,
) -> Option<(Envelope, Vec<u8>)> {
    *seq += 1;
    let mut env = Envelope {
        proto: fedproto::PROTO.to_string(),
        node: node.to_string(),
        seq: *seq,
        ts: now_ts(),
        ty: ty.to_string(),
        payload,
        sig: String::new(),
    };
    env.sig = fedproto::sign_with_key(key, &fedproto::signing_bytes(&env)).ok()?;
    let _ = eng.store.set_meta("fed_seq", &seq.to_string());
    let bytes = serde_json::to_vec(&env).ok()?;
    Some((env, bytes))
}

pub fn spawn_fed_agent_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut last_event_id: i64 = eng
            .store
            .recent_events(1, None)
            .map(|v| v.first().map(|e| e.id).unwrap_or(0))
            .unwrap_or(0);
        let mut last_proposal_id: i64 = eng
            .store
            .list_proposals(None, 1)
            .map(|v| v.first().map(|p| p.id).unwrap_or(0))
            .unwrap_or(0);
        // 发送序列号：跨重启从 meta 恢复（不清零——清零会被协调者按回退拒收）
        let mut seq: u64 = eng
            .store
            .get_meta("fed_seq")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let mut http: Option<reqwest::Client> = None;
        let mut key: Option<ring::signature::EcdsaKeyPair> = None;
        let mut warned_material = false;
        // 未确认信封（按类型各一槽）：网络失败保留重发，被 4xx 拒收丢弃重建。
        // events 槽附带该批凭证游标与批次最大事件 id（成功应答后才推进）
        let mut pending_events: Option<(Vec<u8>, Option<i64>, i64)> = None;
        let mut pending_proposals: Option<Vec<u8>> = None;
        // 版本失配阻断：只发 hello 探测，直到协调者侧接受（节点需升级）
        let mut version_blocked: Option<String> = None;
        // 已告警过的失配版本（避免每周期刷同一条告警）
        let mut warned_version = String::new();
        // F200：凭证观测上传游标（按 ts，内存态；重复观测在协调者按集合语义幂等）
        let mut last_cred_ts: i64 = 0;
        // F200：组织消息拉取游标 + 已处理消息去重（feed id）
        let mut feed_cursor: u64 = 0;
        let mut feed_seen = fedproto::DedupSet::new(2000);
        // F320 并入：本节点时钟偏移（上轮 hello 算出）与告警状态
        let mut last_offset: Option<i64> = None;
        let mut offset_alerted = false;
        // F300：生命周期回流游标（已上报的本地建议 id）与误报回流 ts 游标
        let mut reported: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut last_fp_ts: i64 = 0;

        loop {
            let interval = eng.config().fed.interval_secs.clamp(15, 3600);
            tokio::time::sleep(Duration::from_secs(interval)).await;
            let cfg = eng.config().fed;
            if !cfg.enabled || cfg.role != "agent" || cfg.coordinator.is_empty() {
                continue;
            }
            // 证书材料惰性构建：失败下轮重试（管理员补齐文件后自动恢复）
            if http.is_none() || key.is_none() {
                match build_agent_client(&eng) {
                    Ok(c) => {
                        let key_path = {
                            let data_dir = eng.config().general.data_dir.clone();
                            let (_, key_path) =
                                resolve_node_pair(&data_dir, &cfg.cert_path, &cfg.key_path, &cfg.node);
                            key_path
                        };
                        match std::fs::read_to_string(&key_path)
                            .map_err(|e| e.to_string())
                            .and_then(|p| fedproto::load_signing_key(&p))
                        {
                            Ok(k) => {
                                http = Some(c);
                                key = Some(k);
                                warned_material = false;
                            }
                            Err(e) => {
                                if !warned_material {
                                    eng.bus.publish(SecurityEvent::engine(
                                        "error",
                                        format!("组织协同未启用：{e}"),
                                    ));
                                    warned_material = true;
                                }
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        if !warned_material {
                            eng.bus.publish(SecurityEvent::engine(
                                "error",
                                format!("组织协同未启用：{e}"),
                            ));
                            warned_material = true;
                        }
                        continue;
                    }
                }
            }
            let http_ref = http.as_ref().expect("client 已构建");
            let key_ref = key.as_ref().expect("签名钥已构建");
            let base = cfg.coordinator.trim_end_matches('/').to_string();
            let mut material_stale = false;

            // 0) hello：心跳 + 版本探测 + last_seen + 时钟偏移上报。版本失配时这是唯一发出的消息。
            let hello_payload = json!({ "offset_secs": last_offset });
            if let Some((_, bytes)) =
                seal_envelope(&eng, &cfg.node, key_ref, &mut seq, fedproto::types::HELLO, hello_payload)
            {
                match post_envelope(http_ref, &base, "/fed/hello", &bytes).await {
                    SendOutcome::Ok(v) => {
                        // F320 并入：与协调者时钟对表；偏移超阈值本节点告警（恢复自动解除）
                        if let Some(server_ts) = v["server_ts"].as_i64() {
                            let offset = server_ts - now_ts();
                            last_offset = Some(offset);
                            let skewed = offset.abs() > 5;
                            if skewed && !offset_alerted {
                                offset_alerted = true;
                                eng.bus.publish(SecurityEvent::engine(
                                    "warn",
                                    format!(
                                        "本节点时钟偏移 {offset}s（协调者对表）：超阈值将被组织印证降权，请校准系统时间/NTP"
                                    ),
                                ));
                            } else if !skewed && offset_alerted {
                                offset_alerted = false;
                                eng.bus.publish(SecurityEvent::engine(
                                    "info",
                                    "本节点时钟偏移已恢复（组织印证降权解除）",
                                ));
                            }
                        }
                        if version_blocked.is_some() {
                            eng.bus.publish(SecurityEvent::engine(
                                "info",
                                format!(
                                    "协同协议协商通过：协调者 {} 已接受本节点（版本失配解除）",
                                    v["proto"].as_str().unwrap_or("?")
                                ),
                            ));
                        }
                        version_blocked = None;
                        warned_version.clear();
                    }
                    SendOutcome::Rejected(426, body) => {
                        let server = serde_json::from_str::<serde_json::Value>(&body)
                            .ok()
                            .and_then(|b| {
                                b["server_proto"].as_str().map(str::to_string)
                            })
                            .unwrap_or_else(|| "未知".into());
                        version_blocked = Some(server.clone());
                        if warned_version != server {
                            warned_version = server.clone();
                            eng.bus.publish(SecurityEvent::engine(
                                "warn",
                                format!(
                                    "协同协议版本失配：协调者 {server}，本节点 {}（major 不同拒绝连接，请升级节点或协调者）",
                                    fedproto::PROTO
                                ),
                            ));
                        }
                        continue;
                    }
                    SendOutcome::Rejected(code, _) => {
                        tracing::debug!("fed hello 被拒: HTTP {code}");
                    }
                    SendOutcome::Network(e) => {
                        tracing::debug!("协调者失联（本节点独立运行）: {e}");
                    }
                }
            }
            if version_blocked.is_some() {
                continue;
            }

            // 1) 上报本地事件（蜜罐命中 + 检测判定；超 24h 的旧事件不再外发，
            //    本地哈希链是归档真源）。未确认信封原样重发，不重建。
            let bytes = match pending_events.take() {
                Some((b, m, batch)) => Some((b, m, batch)),
                None => {
                    // F400 出站有界队列：丢新留旧——积压超上限先推进游标牺牲最新段
                    // （本地哈希链是事件完整性真源，外发本来就是副本）
                    let newest = eng
                        .store
                        .recent_events(1, None)
                        .ok()
                        .and_then(|v| v.first().map(|e| e.id))
                        .unwrap_or(0);
                    let (cursor, dropped) = fedproto::backlog_drop(
                        last_event_id,
                        newest,
                        fedproto::OUTBOUND_BACKLOG,
                    );
                    if dropped > 0 {
                        last_event_id = cursor;
                        eng.bus.publish(SecurityEvent::engine(
                            "warn",
                            format!(
                                "出站积压超 {} 条：按丢新留旧策略丢弃最新 {dropped} 条（本地哈希链完整保留）",
                                fedproto::OUTBOUND_BACKLOG
                            ),
                        ));
                    }
                    // 最旧优先取一批（F400：建议风暴既有单建议幂等游标，印证广播
                    // 有协调者侧攻击者键冷却——出站限频由此结构性满足）
                    eng.store
                        .events_since_asc(cursor, 100)
                        .ok()
                        .and_then(|rows| {
                    let new_events: Vec<PushEvent> = rows
                        .iter()
                        .filter(|e| {
                            matches!(e.kind.as_str(), "honeypot_hit" | "detection" | "canary")
                        })
                        .filter(|e| now_ts() - e.ts <= fedproto::REPLAY_WINDOW_SECS)
                        .map(|e| PushEvent {
                            ts: e.ts,
                            kind: e.kind.clone(),
                            listener: e.listener.clone(),
                            remote_ip: e.remote_ip.clone(),
                            remote_port: e.remote_port,
                            summary: e.summary.clone(),
                            tls_fp: e.tls_fp.clone(),
                            tls_ja4: e.tls_ja4.clone(),
                        })
                        .collect();
                    // F200：凭证观测随行（v1 用户名比对；无可逆材料出参）。
                    // 无事件但有新凭证时也独立成封
                    let creds_rows = eng
                        .credentials
                        .recent(last_cred_ts, 100)
                        .unwrap_or_default();
                    let cred_max = creds_rows.iter().map(|c| c.ts).max();
                    let creds: Vec<serde_json::Value> = creds_rows
                        .iter()
                        .filter(|c| now_ts() - c.ts <= fedproto::REPLAY_WINDOW_SECS)
                        .map(|c| json!({ "ts": c.ts, "remote_ip": c.remote_ip, "username": c.username }))
                        .collect();
                            if new_events.is_empty() && creds.is_empty() {
                                None
                            } else {
                                seal_envelope(
                                    &eng,
                                    &cfg.node,
                                    key_ref,
                                    &mut seq,
                                    fedproto::types::EVENTS,
                                    json!({ "events": new_events, "credentials": creds }),
                                )
                                .map(|(_, b)| {
                                    (b, cred_max, rows.last().map(|e| e.id).unwrap_or(0))
                                })
                            }
                        })
                }
            };
            if let Some((bytes, cred_max, batch_max)) = bytes {
                match post_envelope(http_ref, &base, "/fed/events", &bytes).await {
                    SendOutcome::Ok(_) => {
                        pending_events = None;
                        if let Some(m) = cred_max {
                            last_cred_ts = last_cred_ts.max(m);
                        }
                        // F400 最旧优先：游标推进到本批最大 id（未被选取的
                        // kind/过老行本就永不外发，不阻塞游标）
                        last_event_id = last_event_id.max(batch_max);
                    }
                    SendOutcome::Rejected(code, body) => {
                        // 4xx = 这份信封本身有问题（重发无意义），丢弃下轮重建；
                        // 游标未推进，事件仍在队列。401 = 证书/签名材料过期，重建。
                        pending_events = None;
                        material_stale |= code == 401;
                        tracing::warn!("组织事件上报被拒: HTTP {code} {body}");
                    }
                    SendOutcome::Network(_) => {
                        pending_events = Some((bytes, cred_max, batch_max));
                        tracing::debug!("协调者失联，事件信封留待重发");
                    }
                }
            }

            // 2) 拉取组织情报（来源标 fed:coordinator，仅标注）
            if let Ok(resp) = http_ref.get(format!("{base}/fed/intel")).send().await
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

            // 2.5) 拉取组织消息（F200 印证 + F300 建议/误报/推荐）：逐条本地复验，
            //      复验失败静默丢弃 + 留痕；一切消息只加置信，永不自动处置
            if let Ok(resp) = http_ref
                .get(format!("{base}/fed/org-feed?node={}&after={}", cfg.node, feed_cursor))
                .send()
                .await
                && resp.status().is_success()
                && let Ok(v) = resp.json::<serde_json::Value>().await
            {
                feed_cursor = v["cursor"].as_u64().unwrap_or(feed_cursor);
                let now = now_ts();
                let since = now - 86_400;
                for m in v["messages"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                    let id = m["id"].as_u64().unwrap_or(0);
                    if !feed_seen.first_time("__feed__", id, now, 86_400) {
                        continue;
                    }
                    let msg = &m["msg"];
                    match msg["type"].as_str().unwrap_or("") {
                        "corroboration" => {
                            let oc = &msg["corroboration"];
                            let (Some(dim), Some(key)) = (oc["dim"].as_str(), oc["key"].as_str())
                            else {
                                continue;
                            };
                            let nodes = oc["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
                            let hit = match dim {
                                "fingerprint" => eng
                                    .store
                                    .has_recent_observation("fp", key, since)
                                    .unwrap_or(false),
                                "credential" => eng
                                    .credentials
                                    .username_seen(key, since)
                                    .unwrap_or(false),
                                // ip / canary 都按源 IP 查本节点活动
                                _ => eng
                                    .store
                                    .has_recent_observation("ip", key, since)
                                    .unwrap_or(false),
                            };
                            let _ = eng.store.insert_org_event(
                                now,
                                "corroboration",
                                dim,
                                key,
                                nodes as i64,
                                if hit { "hit" } else { "miss" },
                            );
                            if hit {
                                eng.bus.publish(SecurityEvent::engine(
                                    if oc["severity"].as_str() == Some("critical") {
                                        "warn"
                                    } else {
                                        "info"
                                    },
                                    format!(
                                        "组织印证复验命中：{dim} 「{key}」组织内 {nodes} 节点独立观测，本节点亦有活动记录（仅加置信，处置仍走本地路径）"
                                    ),
                                ));
                            } else {
                                tracing::debug!("组织印证复验未命中（留痕）：{dim} {key}");
                            }
                        }
                        "org-suggestion" => {
                            let sg = &msg["suggestion"];
                            // 自己产的建议不回灌（组织广播全量到达）
                            if sg["origin"].as_str() == Some(cfg.node.as_str()) {
                                continue;
                            }
                            let (Some(key), Some(remote_ip)) =
                                (sg["key"].as_str(), sg["remote_ip"].as_str())
                            else {
                                continue;
                            };
                            // 复验四关：IP 合法、非内网保护、本节点有观测、未被误报抑制
                            let Ok(ip) = remote_ip.parse::<std::net::IpAddr>() else {
                                continue;
                            };
                            if aisafeguard_core::is_protected_ip(ip) {
                                tracing::debug!("组织建议复验拒绝（内网保护）：{key}");
                                continue;
                            }
                            if !eng
                                .store
                                .has_recent_observation("ip", remote_ip, since)
                                .unwrap_or(false)
                            {
                                tracing::debug!("组织建议复验未命中（本节点无该源活动）：{key}");
                                continue;
                            }
                            if eng
                                .store
                                .active_fp(
                                    remote_ip,
                                    now,
                                    eng.config().ai.fp_suppress_secs as i64,
                                    None,
                                )
                                .unwrap_or(false)
                            {
                                tracing::debug!("组织建议复验拒绝（误报抑制中）：{key}");
                                continue;
                            }
                            if eng
                                .store
                                .pending_proposal_exists(remote_ip, None)
                                .unwrap_or(true)
                            {
                                continue;
                            }
                            let severity = sg["severity"].as_str().unwrap_or("high");
                            let reason = sg["reason"].as_str().unwrap_or("组织建议");
                            let direction = sg["direction"].as_str().unwrap_or("in");
                            let protocol = sg["protocol"].as_str().unwrap_or("any");
                            if let Ok(pid) = eng.store.insert_proposal(
                                "fed:org",
                                "block",
                                severity,
                                direction,
                                protocol,
                                remote_ip,
                                None,
                                None,
                                reason,
                                "组织建议（本地复验通过，待人工确认）",
                            ) {
                                let _ =
                                    eng.store.insert_org_event(now, "suggestion", "", key, 0, "");
                                eng.bus.publish(SecurityEvent::ProposalCreated {
                                    ts: now,
                                    proposal_id: pid,
                                    severity: severity.to_string(),
                                    reason: reason.to_string(),
                                });
                            }
                        }
                        "fp-flag" => {
                            let f = &msg["fp"];
                            if f["origin"].as_str() == Some(cfg.node.as_str()) {
                                continue;
                            }
                            let Some(key) = f["key"].as_str() else {
                                continue;
                            };
                            let count = f["count"].as_u64().unwrap_or(0);
                            let _ = eng.store.insert_org_event(
                                now,
                                "fp-flag",
                                "",
                                key,
                                count as i64,
                                "",
                            );
                            eng.bus.publish(SecurityEvent::engine(
                                "info",
                                format!(
                                    "组织误报提示：组织内 {count} 个节点把「{key}」标记为误报（建议性质，是否跟进由本节点决定）"
                                ),
                            ));
                        }
                        "quarantine" => {
                            let q = &msg["quarantine"];
                            let (Some(n), Some(st)) =
                                (q["node"].as_str(), q["status"].as_str())
                            else {
                                continue;
                            };
                            let _ = eng
                                .store
                                .insert_org_event(now, "quarantine", "", n, 0, st);
                            eng.bus.publish(SecurityEvent::engine(
                                if st == "quarantined" { "warn" } else { "info" },
                                format!("组织隔离广播：节点 {n} 状态 → {st}（隔离 = 留观察停权，吊销 = 驱离）"),
                            ));
                        }
                        "quorum" => {
                            let q = &msg["quorum"];
                            let Some(key) = q["key"].as_str() else {
                                continue;
                            };
                            let applied = q["applied"].as_u64().unwrap_or(0);
                            let _ = eng.store.insert_org_event(
                                now,
                                "quorum",
                                "",
                                key,
                                applied as i64,
                                "",
                            );
                            eng.bus.publish(SecurityEvent::engine(
                                "info",
                                format!(
                                    "组织推荐：「{key}」已获组织采纳升级（{applied} 节点采纳、零误报）——后续同类建议默认严重度提高，仍为建议"
                                ),
                            ));
                        }
                        _ => {}
                    }
                }
            }

            // 2.6) 生命周期回流（F300）：已定局的组织建议 + （share_fp 开启时）
            //      本地误报标记。协调者按 (node, ref) 去重，重启重报无害。
            {
                let mut results: Vec<serde_json::Value> = Vec::new();
                if let Ok(rows) = eng.store.list_proposals(None, 100) {
                    for p in rows.iter().filter(|p| {
                        p.status != "pending"
                            && p.model.starts_with("fed:")
                            && !reported.contains(&p.id)
                    }) {
                        let key = format!(
                            "{}:{}:{}",
                            p.action,
                            p.remote_ip,
                            p.local_port
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "any".into())
                        );
                        results.push(json!({
                            "key": key, "outcome": p.status, "ref_id": p.id,
                        }));
                    }
                }
                if eng.config().fed.share_fp
                    && let Ok(rows) = eng.store.recent_fp(last_fp_ts)
                {
                    for (value, _count, last_ts) in &rows {
                        results.push(json!({
                            "key": value, "outcome": "fp", "ref_id": last_ts,
                        }));
                    }
                    if let Some(max) = rows.iter().map(|r| r.2).max() {
                        last_fp_ts = last_fp_ts.max(max);
                    }
                }
                results.truncate(100);
                if !results.is_empty()
                    && let Some((_, bytes)) = seal_envelope(
                        &eng,
                        &cfg.node,
                        key_ref,
                        &mut seq,
                        fedproto::types::REPORTS,
                        serde_json::Value::Array(results.clone()),
                    )
                {
                    match post_envelope(http_ref, &base, "/fed/reports", &bytes).await {
                        SendOutcome::Ok(_) => {
                            for r in &results {
                                if let Some(id) = r["ref_id"].as_i64() {
                                    reported.insert(id);
                                }
                            }
                            if reported.len() > 10_000 {
                                reported.clear();
                            }
                        }
                        SendOutcome::Rejected(code, body) => {
                            material_stale |= code == 401;
                            tracing::warn!("组织回流被拒: HTTP {code} {body}");
                        }
                        SendOutcome::Network(_) => {
                            tracing::debug!("协调者失联，回流留待下轮");
                        }
                    }
                }
            }

            // 3) 推送待确认建议（仅慢路径，接收方复验）。最旧优先、单封 ≤10 条
            //    （协调者硬上限），未确认信封原样重发。
            let bytes: Option<(Vec<u8>, i64)> = match pending_proposals.take() {
                Some(b) => Some((b, 0)),
                None => eng.store.list_proposals(None, 100).ok().and_then(|rows| {
                    let mut new_proposals: Vec<(i64, serde_json::Value)> = rows
                        .iter()
                        .filter(|p| p.id > last_proposal_id && p.status == "pending")
                        .map(|p| {
                            (
                                p.id,
                                json!({
                                    "action": "block",
                                    "direction": p.direction,
                                    "protocol": p.protocol,
                                    "remote_ip": p.remote_ip,
                                    "local_port": p.local_port,
                                    "severity": p.severity,
                                    "reason": p.reason,
                                }),
                            )
                        })
                        .collect();
                    new_proposals.sort_by_key(|(id, _)| *id);
                    new_proposals.truncate(10);
                    if new_proposals.is_empty() {
                        return None;
                    }
                    let batch_max = new_proposals.last().map(|(id, _)| *id).unwrap_or(0);
                    seal_envelope(
                        &eng,
                        &cfg.node,
                        key_ref,
                        &mut seq,
                        fedproto::types::PROPOSALS,
                        serde_json::Value::Array(
                            new_proposals.into_iter().map(|(_, v)| v).collect(),
                        ),
                    )
                    .map(|(_, b)| (b, batch_max))
                }),
            };
            if let Some((bytes, batch_max)) = bytes {
                match post_envelope(http_ref, &base, "/fed/proposals", &bytes).await {
                    SendOutcome::Ok(_) => {
                        pending_proposals = None;
                        last_proposal_id = last_proposal_id.max(batch_max);
                    }
                    SendOutcome::Rejected(code, body) => {
                        pending_proposals = None;
                        material_stale |= code == 401;
                        tracing::warn!("组织建议推送被拒: HTTP {code} {body}");
                    }
                    SendOutcome::Network(_) => {
                        pending_proposals = Some(bytes);
                        tracing::debug!("协调者失联，建议信封留待重发");
                    }
                }
            }

            // 证书/签名材料被判过期（401）：整体重建，下轮重读证书与私钥文件
            if material_stale {
                http = None;
                key = None;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C1/C2：吊销列表读写 + 预登记校验（文件为真源，纯函数断言）。
    #[test]
    fn revocations_and_expected_registration() {
        let dir = std::env::temp_dir().join(format!("asg-fed-c1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 空表：不吊销任何人
        assert!(load_revocations(&dir).is_empty());
        assert!(check_not_revoked(&dir, "aabb").is_none());

        // 吊销：按指纹写入后立即可查；重复吊销拒绝
        let fp = cmd_revoke(&dir, "aabbccdd".repeat(8).as_str(), "测试吊销").unwrap();
        assert_eq!(fp.len(), 64);
        assert!(load_revocations(&dir).contains(&fp));
        assert!(check_not_revoked(&dir, &fp).is_some());
        assert!(check_not_revoked(&dir, "ffff").is_none());
        assert!(cmd_revoke(&dir, &fp, "重复").is_err(), "重复吊销应拒绝");

        // 按节点名吊销：certs/<node>.pem 存在时算指纹
        cmd_init_ca(&dir, "").unwrap();
        cmd_issue_cert(&dir, "node-x", &[]).unwrap();
        let fp2 = cmd_revoke(&dir, "node-x", "换证前吊销").unwrap();
        assert_eq!(fp2.len(), 64);

        // 预登记：写入后 expected_ok 生效
        cmd_expect(&dir, "agent1", &"e".repeat(64)).unwrap();
        let expected = load_expected(&dir);
        assert!(expected_ok(&expected, "agent1", &"e".repeat(64)));
        assert!(
            !expected_ok(&expected, "agent1", &"f".repeat(64)),
            "指纹不符必须拒"
        );
        assert!(
            expected_ok(&expected, "未登记节点", "任意指纹"),
            "未预登记走 TOFU"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cert_fp_matches_sha256() {
        // sha256("abc") 的已知值
        assert_eq!(
            cert_fp_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn node_name_validation() {
        assert!(valid_node_name("agent-1"));
        assert!(valid_node_name("coord_x"));
        assert!(!valid_node_name(""));
        assert!(!valid_node_name("带中文"));
        assert!(!valid_node_name("a;b"));
        assert!(!valid_node_name(&"x".repeat(33)));
    }

    #[test]
    fn pki_roundtrip_init_ca_and_issue_cert() {
        let dir = std::env::temp_dir().join(format!("asg-fed-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        cmd_init_ca(&dir, "").unwrap();
        // 重复 init-ca 必须拒绝（不能覆盖信任根）
        assert!(cmd_init_ca(&dir, "").is_err());

        cmd_issue_cert(&dir, "node-1", &["127.0.0.1".to_string()]).unwrap();
        let cert_path = dir.join("fed").join("certs").join("node-1.pem");
        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        let der = read_pem_certs(&cert_path).unwrap().remove(0);
        assert_eq!(cert_fp_of(der.as_ref()).len(), 64);
        // 私钥可按 PKCS#8 读回
        read_pem_private_key(&dir.join("fed").join("certs").join("node-1-key.pem")).unwrap();
        // 非法节点名拒绝
        assert!(cmd_issue_cert(&dir, "bad;name", &[]).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
