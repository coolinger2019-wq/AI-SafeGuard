//! 组织协同（0.3，设计见 docs/NGFW_EVOLUTION.md §6）。
//!
//! 三条链路：事件上报（agent→协调者）、情报同步（双向）、AI 建议推送（仅慢路径）。
//! 0.3.6 起鉴权 = mTLS：协调者在**独立监听面**（`[fed].listen_addr`，默认 0.0.0.0:7421）
//! 上要求客户端证书链到组织 CA（rustls WebPkiClientVerifier，手写 accept 循环——
//! 避免 axum-server 的 tls-rustls 特性把 aws-lc-rs 拉进依赖树）；node ↔ 证书指纹
//! 在首次接触时绑定（TOFU），之后冒用其他节点名即被拒。组织共享令牌已整体移除。
//! PKI 文件布局（数据目录 /fed/）：`ca.pem` + `ca-key.pem`（`fed init-ca` 生成，
//! 仅协调者侧持有私钥）；`certs/<node>.pem` + `certs/<node>-key.pem`
//! （`fed issue-cert <node>` 签发，人工分发到节点）。
//! 防投毒基线不变：远端情报 confidence="fed" 永不自动封禁；远端建议过本地 allowlist
//! 复验后仅进慢路径；内网保护前置拒收；时钟窗校验防重放。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use base64::Engine as _;

use crate::engine::EngineHandle;
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
#[derive(Clone)]
pub struct FedPeer {
    pub cert_fp: String,
}

#[derive(Clone)]
pub struct FedState {
    engine: Arc<EngineHandle>,
}

/// /fed 路由面。只挂在 mTLS 监听上：rustls 已验证客户端证书链到组织 CA，
/// accept 循环把对端叶子指纹以 Extension 注入，handlers 经 FedPeer 取用。
pub fn fed_router(engine: Arc<EngineHandle>) -> Router {
    let state = FedState { engine };
    Router::new()
        .route("/fed/events", post(fed_events))
        .route("/fed/intel", get(fed_intel_get).post(fed_intel_post))
        .route("/fed/proposals", post(fed_proposals))
        .route("/fed/members", get(fed_members))
        .with_state(state)
}

fn err(e: impl std::fmt::Display) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response()
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
    peer: axum::Extension<FedPeer>,
    Json(body): Json<FedEventBody>,
) -> Response {
    if !valid_node_name(&body.node) {
        return err("node 名不合法（限字母数字_-，≤32 字符）");
    }
    if body.events.len() > 100 {
        return err("单次上报最多 100 条事件");
    }
    if let Err(resp) = check_member(&state, &body.node, &peer.cert_fp) {
        return resp;
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
    peer: axum::Extension<FedPeer>,
    Json(body): Json<FedIntelBody>,
) -> Response {
    if !valid_node_name(&body.node) {
        return err("node 名不合法");
    }
    if body.entries.len() > 500 {
        return err("单次同步最多 500 条情报");
    }
    if let Err(resp) = check_member(&state, &body.node, &peer.cert_fp) {
        return resp;
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
    peer: axum::Extension<FedPeer>,
    Json(body): Json<FedProposalBody>,
) -> Response {
    if !valid_node_name(&body.node) {
        return err("node 名不合法");
    }
    if body.proposals.len() > 10 {
        return err("单次推送最多 10 条建议");
    }
    if let Err(resp) = check_member(&state, &body.node, &peer.cert_fp) {
        return resp;
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
        .map(|(node, cert_fp, last_seen)| {
            json!({ "node": node, "cert_fp": cert_fp, "last_seen": last_seen })
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

/// `fed init-ca`：生成组织 CA（自签 10 年）写入 <数据目录>/fed/。
/// 已存在时明确拒绝（覆盖 CA = 全网信任重置，绝不能静默发生）。
pub fn cmd_init_ca(data_dir: &Path) -> anyhow::Result<()> {
    let dir = fed_dir(data_dir);
    std::fs::create_dir_all(certs_dir(data_dir))?;
    let ca_pem = dir.join("ca.pem");
    let ca_key = dir.join("ca-key.pem");
    if ca_pem.exists() || ca_key.exists() {
        anyhow::bail!("组织 CA 已存在（{}），避免覆盖；确需重建请先手动删除", ca_pem.display());
    }
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "AI-SafeGuard Organization CA",
    );
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
    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(
        &std::fs::read_to_string(&ca_pem)?,
    )?;
    let ca_key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(&ca_key_pem)?)?;
    let issuer_cert = ca_params.clone().self_signed(&ca_key)?;

    let mut san_values: Vec<rcgen::SanType> = vec![rcgen::SanType::DnsName(
        rcgen::Ia5String::try_from(node.to_string())?,
    )];
    for s in sans {
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            san_values.push(rcgen::SanType::IpAddress(ip));
        } else {
            san_values.push(rcgen::SanType::DnsName(rcgen::Ia5String::try_from(s.clone())?));
        }
    }
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params.distinguished_name.push(rcgen::DnType::CommonName, node);
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
    println!("  指纹（SHA-256）: {}", cert_fp_of(&cert.der().to_vec()));
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
pub fn check_not_revoked(data_dir: &Path, cert_fp: &str) -> Result<(), String> {
    if load_revocations(data_dir).contains(cert_fp) {
        return Err("该证书已被吊销（fed revoke），组织同步被拒绝".to_string());
    }
    Ok(())
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
        .map(|(node, cert_fp, last_seen)| {
            serde_json::json!({ "node": node, "cert_fp": cert_fp, "last_seen": last_seen })
        })
        .collect();
    let revocations: Vec<serde_json::Value> = std::fs::read(revocations_path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    // 最近协同事件（fed: 前缀 listener）
    let recent = store.recent_events(50, None).unwrap_or_default();
    let fed_events: Vec<serde_json::Value> = recent
        .iter()
        .filter(|e| e.listener.starts_with("fed:") || e.summary.contains("[fed]"))
        .map(|e| serde_json::json!({ "ts": e.ts, "kind": e.kind, "listener": e.listener, "remote_ip": e.remote_ip, "summary": e.summary }))
        .collect();
    let doc = serde_json::json!({
        "exported_ts": now,
        "window_secs": window_secs,
        "members": members,
        "revocations": revocations,
        "recent_fed_events": fed_events,
    });
    std::fs::write(out, serde_json::to_string_pretty(&doc)?)?;
    println!("✓ 协同审计已导出 {}（成员 {} · 吊销 {} · 近期协同事件 {}）",
        out.display(), members.len(), revocations.len(), fed_events.len());
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
fn resolve_node_pair(data_dir: &Path, cert_cfg: &str, key_cfg: &str, node: &str) -> (PathBuf, PathBuf) {
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
    let (cert_path, key_path) = resolve_node_pair(&data_dir, &cfg.cert_path, &cfg.key_path, &cfg.node);

    let mut roots = rustls::RootCertStore::empty();
    for c in read_pem_certs(&ca_path)? {
        roots.add(c).map_err(|e| format!("组织 CA 加入信任库失败: {e}"))?;
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
        (
            eng.bus.clone(),
            eng.config().general.data_dir.clone(),
        )
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
            // 客户端证书已验证；叶子指纹注入请求扩展供 node 绑定用
            let cert_fp = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| cert_fp_of(c.as_ref()))
                .unwrap_or_default();
            // 吊销检查（0.4.0 C1）：立即生效（每次连接读文件），命中拒连并留审计事件
            if let Err(reason) = check_not_revoked(&data_dir, &cert_fp) {
                bus.publish(SecurityEvent::engine("warn", format!("协同连接被拒：{reason}")));
                return;
            }
            // Router 直接实现 tower Service<Request<Incoming>>，TowerToHyperService 适配
            let svc =
                hyper_util::service::TowerToHyperService::new(app.layer(axum::Extension(FedPeer {
                    cert_fp,
                })));
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
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
}

/// agent 的 mTLS HTTP 客户端：携带本节点证书（clientAuth）+ 组织 CA 验证协调者。
fn build_agent_client(eng: &EngineHandle) -> Result<reqwest::Client, String> {
    let cfg = eng.config().fed;
    let data_dir = eng.config().general.data_dir.clone();
    let ca_path = resolve_fed_path(&data_dir, &cfg.ca_path, "ca.pem");
    let (cert_path, key_path) = resolve_node_pair(&data_dir, &cfg.cert_path, &cfg.key_path, &cfg.node);
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
    let key_pem = std::fs::read(&key_path).map_err(|e| {
        format!(
            "本节点私钥不可读（{}）: {e}",
            key_path.display()
        )
    })?;
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
/// 协调者失联或证书材料缺失只记警告，本节点一切功能照常（独立运行优先）。
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

        let mut http: Option<reqwest::Client> = None;
        let mut warned_material = false;
        loop {
            let interval = eng.config().fed.interval_secs.clamp(15, 3600);
            tokio::time::sleep(Duration::from_secs(interval)).await;
            let cfg = eng.config().fed;
            if !cfg.enabled || cfg.role != "agent" || cfg.coordinator.is_empty() {
                continue;
            }
            // 证书材料惰性构建：失败下轮重试（管理员补齐文件后自动恢复）
            if http.is_none() {
                match build_agent_client(&eng) {
                    Ok(c) => {
                        http = Some(c);
                        warned_material = false;
                    }
                    Err(e) => {
                        if !warned_material {
                            eng.bus.publish(SecurityEvent::engine("error", format!("组织协同未启用：{e}")));
                            warned_material = true;
                        }
                        continue;
                    }
                }
            }
            let http = http.as_ref().expect("client 已构建");
            let base = cfg.coordinator.trim_end_matches('/').to_string();

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
                    match http
                        .post(format!("{base}/fed/events"))
                        .json(&json!({ "node": cfg.node, "events": new_events }))
                        .send()
                        .await
                    {
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
            if let Ok(resp) = http.get(format!("{base}/fed/intel")).send().await
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
        assert!(check_not_revoked(&dir, "aabb").is_ok());

        // 吊销：按指纹写入后立即可查；重复吊销拒绝
        let fp = cmd_revoke(&dir, "aabbccdd" .repeat(8).as_str(), "测试吊销").unwrap();
        assert_eq!(fp.len(), 64);
        assert!(load_revocations(&dir).contains(&fp));
        assert!(check_not_revoked(&dir, &fp).is_err());
        assert!(check_not_revoked(&dir, "ffff").is_ok());
        assert!(cmd_revoke(&dir, &fp, "重复").is_err(), "重复吊销应拒绝");

        // 按节点名吊销：certs/<node>.pem 存在时算指纹
        cmd_init_ca(&dir).unwrap();
        cmd_issue_cert(&dir, "node-x", &[]).unwrap();
        let fp2 = cmd_revoke(&dir, "node-x", "换证前吊销").unwrap();
        assert_eq!(fp2.len(), 64);

        // 预登记：写入后 expected_ok 生效
        cmd_expect(&dir, "agent1", &"e".repeat(64)).unwrap();
        let expected = load_expected(&dir);
        assert!(expected_ok(&expected, "agent1", &"e".repeat(64)));
        assert!(!expected_ok(&expected, "agent1", &"f".repeat(64)), "指纹不符必须拒");
        assert!(expected_ok(&expected, "未登记节点", "任意指纹"), "未预登记走 TOFU");

        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

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

        cmd_init_ca(&dir).unwrap();
        // 重复 init-ca 必须拒绝（不能覆盖信任根）
        assert!(cmd_init_ca(&dir).is_err());

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
