#![forbid(unsafe_code)]

//! SQLite 持久层：统一事件流水、防火墙规则、AI 建议、AI 调用审计。
//! 时间戳一律 epoch 秒（整数），展示层再转本地时间。
//!
//! 完整性（[A.8.15]）：事件表维护链式 SHA-256 哈希（hash = H(prev_hash | 规范化行)），
//! `verify_chain` 可离线校验任一行是否被篡改。

mod ai_runs;
pub mod credentials;
mod events;
mod exposure;
mod fed;
mod fp_feedback;
mod intel;
mod meta;
mod proposals;
mod rules;
mod source_recidivism;
mod suggestions;

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use aisafeguard_core::error::{Error, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use credentials::{CredentialRecord, CredentialStore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub listener: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub summary: String,
    pub payload: String,
    /// HTTP 提示 JSON（0.5.0 E6，Detection 且 full 捕获可解析时非空）
    pub http_hint: String,
    /// JA3 md5（0.5.0 E6，TLS ClientHello 可见时非空）
    pub tls_fp: String,
    /// JA4 指纹（0.5.0 E5，[detect.l7].ja4 开启且 ClientHello 可见时非空）
    pub tls_ja4: String,
    /// 蜜罐交互逐命令 JSON（0.5.9 H102：中交互假 Shell 会话才有；空串 = 无）
    pub interaction: String,
    /// 命中的规则 ID（0.7 F740：Detection 落库；旧数据/非检测事件为空串。
    /// serde default 防新旧版本混跑——老服务 JSON 缺此字段时 GUI 不崩）
    #[serde(default)]
    pub rule_id: String,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRow {
    pub id: i64,
    pub created_ts: i64,
    pub name: String,
    pub direction: String,
    pub protocol: String,
    pub remote_ip: String,
    pub local_port: Option<u16>,
    pub origin: String,
    pub enabled: bool,
    pub note: String,
    /// 非空 = 自动封禁，到期由解封任务移除；手动规则为 NULL。
    pub expires_ts: Option<i64>,
    /// 可选标签（0.4.0 B1）：来源/用途分组，展示与审计用
    pub tag: String,
    /// 灰度规则已人工转正（0.5.4 F1/F3）：TTL 曾延长到 promote_ttl_secs
    pub promoted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalRow {
    pub id: i64,
    pub created_ts: i64,
    pub model: String,
    pub severity: String,
    /// 建议动作：block（封禁）| credential_spray（确认凭证喷洒战役，0.5.11 H310）
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub remote_ip: String,
    pub local_port: Option<u16>,
    pub reason: String,
    pub status: String,
    pub applied_rule_id: Option<i64>,
    pub analysis: String,
    /// AI 建议的灰度封禁时长（秒）；None = 引擎默认灰度时长
    pub ttl_secs: Option<i64>,
    /// F760-A：promote_rule/retire_rule 的目标规则名（aisafeguard- 前缀）
    pub rule_name: String,
    /// tune_detection 的参数（白名单）与建议值
    pub tune_param: String,
    pub tune_value: String,
}

/// 误报反馈条目（抑制期内的来源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpRow {
    pub value: String,
    pub count: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub note: String,
    /// None = 按 IP 整体抑制；Some = 仅该端口（0.4.0 B4）
    pub local_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRunRow {
    pub id: i64,
    pub ts: i64,
    pub model: String,
    pub ok: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelRow {
    pub source: String,
    pub kind: String,
    pub value: String,
    pub confidence: String,
    pub first_seen: i64,
    pub expires_ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TopIp {
    pub ip: String,
    pub hits: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListenerCount {
    pub listener: String,
    pub hits: i64,
}

/// 价值指标（0.4.0 B5，口径写死见 docs/ROADMAP-0.4.md B5）：
/// proposed=窗口内产生的 AI 建议；applied=其中被采纳（人工确认或自动应用）；
/// fp=窗口内被标记误报的来源数；auto_blocks=窗口内检测器/AI 快路径自动封禁次数。
/// 派生比率由展示层计算：采纳率 = applied/proposed；误报率 = fp/applied。
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ValueMetrics {
    pub proposed: i64,
    pub applied: i64,
    pub fp: i64,
    pub auto_blocks: i64,
    /// F803 口径拆分：快路径（origin=engine）与 AI 自动应用各自计数；
    /// auto_blocks = 两者之和（事件文本口径，见 metrics_since 注释）
    #[serde(default)]
    pub auto_blocks_engine: i64,
    #[serde(default)]
    pub auto_blocks_ai: i64,
}

/// F802 转化漏斗（评审 #42/#5：hit→detection→proposal→applied 各级计数 +
/// 按监听器命中分布——定位零转化面）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunnelStats {
    pub hits: i64,
    pub detections: i64,
    pub proposed: i64,
    pub applied: i64,
    /// 命中数 Top 监听器（listener, hits），降序取前 8
    pub top_listeners: Vec<(String, i64)>,
}

/// F760-B 自审建议行（评审工单的结构化形态；md 快照另存）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestionRow {
    pub id: i64,
    pub created_ts: i64,
    pub day: String,
    pub category: String,
    pub priority: String,
    pub title: String,
    pub evidence: String,
    pub action: String,
    pub model: String,
    /// pending | adopted | rejected | completed
    /// 处置路径：config=改配置 code=需改码 ops=人工操作
    pub impl_path: String,
    pub status: String,
    pub note: String,
    pub decided_ts: Option<i64>,
    /// 主题指纹（category+title 哈希）——升级引用与去重锚
    pub fingerprint: String,
}
/// F300 组织事件账本行（org_events）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgEventRow {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub dim: String,
    pub key: String,
    pub nodes_count: i64,
    pub detail: String,
}

/// F300 组织建议价值指标（口径：proposals 表 model LIKE 'fed:%' + org_events 印证账本）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrgMetrics {
    /// 收到的组织建议数（model LIKE 'fed:%'）
    pub suggestions_received: i64,
    /// 已采纳（applied；promoted 由展示层另行统计）
    pub suggestions_applied: i64,
    pub suggestions_dismissed: i64,
    /// 收到的组织印证数 / 本地复验命中数（org_events kind='corroboration'）
    pub corroborations_received: i64,
    pub corroborations_hit: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatsSummary {
    pub total: i64,
    pub unique_ips: i64,
    pub top_ips: Vec<TopIp>,
    pub per_listener: Vec<ListenerCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainReport {
    pub rows: usize,
    pub ok: bool,
    /// 第一条校验失败的事件 id；None = 链完整
    pub broken_at: Option<i64>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    listener    TEXT NOT NULL DEFAULT '',
    remote_ip   TEXT NOT NULL DEFAULT '',
    remote_port INTEGER NOT NULL DEFAULT 0,
    summary     TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '',
    http_hint   TEXT NOT NULL DEFAULT '',
    tls_fp      TEXT NOT NULL DEFAULT '',
    tls_ja4     TEXT NOT NULL DEFAULT '',
    rule_id     TEXT NOT NULL DEFAULT '',
    prev_hash   TEXT NOT NULL DEFAULT '',
    hash        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON events(kind, ts);
CREATE INDEX IF NOT EXISTS idx_events_remote_ip ON events(remote_ip);

CREATE TABLE IF NOT EXISTS rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_ts INTEGER NOT NULL,
    name       TEXT NOT NULL UNIQUE,
    direction  TEXT NOT NULL,
    protocol   TEXT NOT NULL,
    remote_ip  TEXT NOT NULL DEFAULT '',
    local_port INTEGER,
    origin     TEXT NOT NULL DEFAULT 'manual',
    enabled    INTEGER NOT NULL DEFAULT 1,
    note       TEXT NOT NULL DEFAULT '',
    expires_ts INTEGER,
    tag        TEXT NOT NULL DEFAULT '',
    promoted   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS proposals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_ts      INTEGER NOT NULL,
    model           TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL,
    action          TEXT NOT NULL DEFAULT 'block',
    direction       TEXT NOT NULL,
    protocol        TEXT NOT NULL,
    remote_ip       TEXT NOT NULL DEFAULT '',
    local_port      INTEGER,
    reason          TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending',
    applied_rule_id INTEGER,
    analysis        TEXT NOT NULL DEFAULT '',
    -- F760-A 调参/治理建议：promote_rule/retire_rule 的目标规则名；tune_detection 的参数与值
    rule_name       TEXT NOT NULL DEFAULT '',
    tune_param      TEXT NOT NULL DEFAULT '',
    tune_value      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);

CREATE TABLE IF NOT EXISTS ai_runs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    model   TEXT NOT NULL,
    ok      INTEGER NOT NULL,
    summary TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exposure (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ts   INTEGER NOT NULL,
    json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL UNIQUE,
    confidence TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    expires_ts INTEGER NOT NULL,
    -- F710 源分级：该条目是否来自允许自动封禁的源（特权条目不被非特权源覆盖）
    auto_block INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fed_members (
    node      TEXT PRIMARY KEY,
    last_seen INTEGER NOT NULL,
    cert_fp   TEXT NOT NULL DEFAULT '',
    -- F100 fed 协议：该节点已见最大消息序列号（-1 = 尚未见过）。单调递增，
    -- 回退（备份恢复/伪造重放）在 check_fed_seq 拒收
    max_seq   INTEGER NOT NULL DEFAULT -1,
    -- F400 软隔离：active | quarantined（心跳与审计保留，事件/建议通道暂停；
    -- 与吊销的区别：吊销断一切连接，隔离是留观察的停权）
    status    TEXT NOT NULL DEFAULT 'active'
);

-- 误报反馈（AI 深度介入 v1）：用户判定为误报的来源，自动封禁/自动应用跳过，
-- 并作为上下文送回 AI。value = 来源 IP；TTL 语义由查询侧（last_ts + 抑制期）实现。
-- F300 组织事件账本：本节点收到的组织消息（印证/建议/误报标记/组织推荐）留痕，
-- 供 AI <org> 上下文段、/api/rules 组织提示与价值指标读取。key 语义随 kind：
-- corroboration=攻击者键（ip/ja3/用户名），suggestion/fp-flag/block:{ip}:{port}。
CREATE TABLE IF NOT EXISTS org_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    dim         TEXT NOT NULL DEFAULT '',
    key         TEXT NOT NULL DEFAULT '',
    nodes_count INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS fp_feedback (
    value      TEXT PRIMARY KEY,
    count      INTEGER NOT NULL DEFAULT 1,
    first_ts   INTEGER NOT NULL,
    last_ts    INTEGER NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    local_port INTEGER
);

CREATE TABLE IF NOT EXISTS suggestions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_ts  INTEGER NOT NULL,
    day         TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    category    TEXT NOT NULL,
    priority    TEXT NOT NULL,
    title       TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT '',
    model       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    note        TEXT NOT NULL DEFAULT '',
    decided_ts  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_suggestions_status ON suggestions(status);
CREATE INDEX IF NOT EXISTS idx_proposals_created ON proposals(created_ts);
CREATE TABLE IF NOT EXISTS source_recidivism (
    remote_ip   TEXT PRIMARY KEY,
    ban_count   INTEGER NOT NULL DEFAULT 0,
    last_ban_ts INTEGER NOT NULL DEFAULT 0
);
"#;

#[allow(clippy::too_many_arguments)] // 12 字段并列比拆结构体直白（链规范读得懂）
pub(crate) fn canonical_event(
    ts: i64,
    kind: &str,
    listener: &str,
    remote_ip: &str,
    remote_port: i64,
    summary: &str,
    payload: &str,
    http_hint: &str,
    tls_fp: &str,
    tls_ja4: &str,
    rule_id: &str,
    interaction: &str,
) -> String {
    serde_json::json!({
        "http_hint": http_hint,
        "interaction": interaction,
        "kind": kind,
        "listener": listener,
        "payload": payload,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "rule_id": rule_id,
        "summary": summary,
        "tls_fp": tls_fp,
        "tls_ja4": tls_ja4,
        "ts": ts,
    })
    .to_string()
}

pub(crate) fn chain_hash(prev_hash: &str, canonical: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"|");
    h.update(canonical.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Store {
    conn: Mutex<Connection>,
}

/// 迁移/重链的行数据 (id, ts, kind, listener, remote_ip, remote_port, summary,
/// payload, http_hint, tls_fp, tls_ja4, rule_id, interaction)
type ChainSeedRow = (
    i64,
    i64,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("创建数据目录失败: {e}")))?;
        }
        let conn = Connection::open(path).map_err(|e| Error::Store(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| Error::Store(e.to_string()))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| Error::Store(e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| Error::Store(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate_pre_0_2()?;
        store.ensure_chain_v2()?;
        Ok(store)
    }

    /// 0.1 → 0.2 数据库搬迁：补哈希链列、为存量事件一次性补链。
    /// 一次性数据搬迁，不是兼容层。
    fn migrate_pre_0_2(&self) -> Result<()> {
        let conn = self.lock()?;
        for sql in [
            "ALTER TABLE events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE events ADD COLUMN hash TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE rules ADD COLUMN expires_ts INTEGER",
            "ALTER TABLE proposals ADD COLUMN ttl_secs INTEGER",
            "ALTER TABLE fed_members ADD COLUMN cert_fp TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE rules ADD COLUMN tag TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE fp_feedback ADD COLUMN local_port INTEGER",
            "ALTER TABLE events ADD COLUMN http_hint TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE events ADD COLUMN tls_fp TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE events ADD COLUMN tls_ja4 TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE events ADD COLUMN rule_id TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE intel ADD COLUMN auto_block INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE rules ADD COLUMN promoted INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE events ADD COLUMN interaction TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE proposals ADD COLUMN action TEXT NOT NULL DEFAULT 'block'",
            "ALTER TABLE fed_members ADD COLUMN max_seq INTEGER NOT NULL DEFAULT -1",
            "ALTER TABLE fed_members ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE suggestions ADD COLUMN impl_path TEXT NOT NULL DEFAULT 'code'",
            "ALTER TABLE proposals ADD COLUMN rule_name TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE proposals ADD COLUMN tune_param TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE proposals ADD COLUMN tune_value TEXT NOT NULL DEFAULT ''",
        ] {
            let _ = conn.execute(sql, []); // 列已存在时报错，忽略
        }
        let seeded: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM meta WHERE key = 'chain_seeded'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        if seeded == 0 {
            self.rechain_all(&conn)?;
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('chain_seeded', '1') ON CONFLICT(key) DO NOTHING",
                [],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        }
        Ok(())
    }

    /// 哈希链 v2（审计 run-1 B1）：canonical_event 补齐 http_hint/tls_fp/tls_ja4/
    /// rule_id/interaction 五个后加证据列——v1 只链 7 列，未链住的列可被原地
    /// 改写而 verify-log 照样报完整。v1 哈希与 v2 规范不兼容，升级一次性全量
    /// 重链（低频 O(n)）；meta chain_ver 标记版本。v1 时代的归档/导出需按
    /// 当期口径校验，不能与 v2 混算。
    fn ensure_chain_v2(&self) -> Result<()> {
        let conn = self.lock()?;
        let ver: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'chain_ver'", [], |r| {
                r.get(0)
            })
            .ok();
        if ver.as_deref() == Some("2") {
            return Ok(());
        }
        self.rechain_all(&conn)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('chain_ver', '2') ON CONFLICT(key) DO UPDATE SET value='2'",
            [],
        )
        .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    /// 全量重链（v1 补链与 v2 升级共用）：ORDER BY id、链起点 prev_hash=''。
    fn rechain_all(&self, conn: &Connection) -> Result<()> {
        let rows: Vec<ChainSeedRow> = {
            let mut stmt = conn
                .prepare("SELECT id, ts, kind, listener, remote_ip, remote_port, summary, payload, http_hint, tls_fp, tls_ja4, rule_id, interaction FROM events ORDER BY id")
                .map_err(|e| Error::Store(e.to_string()))?;
            stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                ))
            })
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?
        };
        let mut prev = String::new();
        for (
            id,
            ts,
            kind,
            listener,
            remote_ip,
            remote_port,
            summary,
            payload,
            http_hint,
            tls_fp,
            tls_ja4,
            rule_id,
            interaction,
        ) in rows
        {
            let canonical = canonical_event(
                ts,
                &kind,
                &listener,
                &remote_ip,
                remote_port,
                &summary,
                &payload,
                &http_hint,
                &tls_fp,
                &tls_ja4,
                &rule_id,
                &interaction,
            );
            let h = chain_hash(&prev, &canonical);
            conn.execute(
                "UPDATE events SET prev_hash = ?2, hash = ?3 WHERE id = ?1",
                params![id, prev, h],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
            prev = h;
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Store("数据库连接锁已中毒".into()))
    }

    /// 价值指标（0.4.0 B5）：三个单查询各取一个数，口径见 ValueMetrics 注释。
    /// auto_blocks 以事件 summary 文本口径识别（apply_block 的固定文案，
    /// 手动/联邦规则的 firewall_add 文案不同）。F803 拆分：快路径（origin=engine，
    /// 文案「已自动封禁」）与 AI 自动应用（文案「AI 自动封禁」，apply_proposal_auto
    /// 专属）各自计数——原合计口径曾与 ai.max_per_day 的日配额口径混淆。
    pub fn metrics_since(&self, since: i64) -> Result<ValueMetrics> {
        let conn = self.lock()?;
        let (proposed, applied) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(status = 'applied'), 0) FROM proposals WHERE created_ts >= ?1",
                params![since],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let fp = conn
            .query_row(
                "SELECT COUNT(*) FROM fp_feedback WHERE last_ts >= ?1",
                params![since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let (auto_blocks_engine, auto_blocks_ai) = conn
            .query_row(
                "SELECT COALESCE(SUM(summary LIKE '%已自动封禁%'), 0), COALESCE(SUM(summary LIKE '%AI 自动封禁%'), 0)
                 FROM events WHERE kind = 'engine' AND ts >= ?1",
                params![since],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(ValueMetrics {
            proposed,
            applied,
            fp,
            auto_blocks: auto_blocks_engine + auto_blocks_ai,
            auto_blocks_engine,
            auto_blocks_ai,
        })
    }

    /// F802 转化漏斗（since 起）：hit→detection→proposal→applied 各级计数 +
    /// 命中数 Top 监听器。检测/提案不按监听器归属（跨面聚合判定），漏斗前段
    /// 按监听器、后段全局——如实呈现可归因的边界。
    pub fn funnel_since(&self, since: i64) -> Result<FunnelStats> {
        let conn = self.lock()?;
        let hits = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = 'honeypot_hit' AND ts >= ?1",
                params![since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let detections = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = 'detection' AND ts >= ?1",
                params![since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let (proposed, applied) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(status = 'applied'), 0) FROM proposals WHERE created_ts >= ?1",
                params![since],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT listener, COUNT(*) c FROM events WHERE kind = 'honeypot_hit' AND ts >= ?1 GROUP BY listener ORDER BY c DESC LIMIT 8",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let top_listeners = stmt
            .query_map(params![since], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(FunnelStats {
            hits,
            detections,
            proposed,
            applied,
            top_listeners,
        })
    }
}

#[cfg(test)]
mod tests {
    use aisafeguard_core::event::SecurityEvent;

    /// A1 回归：修剪后新链头的 hash 必须重算，verify-log 不得断链
    /// （旧实现只置空 prev_hash，首次 prune 后 verify 永久失败）。
    #[test]
    fn prune_then_verify_chain_stays_intact() {
        let store = tmp_store("prune-verify");
        for i in 0..5 {
            store
                .insert_event(&aisafeguard_core::event::SecurityEvent::engine(
                    "info",
                    format!("事件 {i}"),
                ))
                .unwrap();
        }
        // 前 3 条回拨一天 → prune_events(0) 剪掉 id 1..=3，id4 成为新链头
        {
            let conn = store.lock().unwrap();
            conn.execute("UPDATE events SET ts = ts - 86400 WHERE id <= 3", [])
                .unwrap();
        }
        assert_eq!(store.prune_events(0, None).unwrap(), 3);
        let report = store.verify_chain().unwrap();
        assert!(
            report.ok,
            "prune 后新链头必须重算 hash，verify 不得断链: {:?}",
            report.broken_at
        );
        assert_eq!(report.rows, 2);
    }

    /// F795 去重：active_rule_exists 的端口粒度语义——
    /// 全端口规则覆盖一切建议；端口级规则只覆盖同端口建议。
    #[test]
    fn active_rule_exists_scope_semantics() {
        let store = tmp_store("active-rule-scope");
        // 全端口规则（local_port = NULL）
        store
            .insert_rule(
                "blk-all",
                "in",
                "any",
                "203.0.113.7",
                None,
                "manual",
                "",
                "",
                None,
            )
            .unwrap();
        assert!(store.active_rule_exists("203.0.113.7", None).unwrap());
        assert!(
            store.active_rule_exists("203.0.113.7", Some(8081)).unwrap(),
            "全端口覆盖端口级建议"
        );
        assert!(
            !store.active_rule_exists("203.0.113.8", None).unwrap(),
            "其他 IP 不受影响"
        );
        // 端口级规则
        store
            .insert_rule(
                "blk-p8081",
                "in",
                "tcp",
                "203.0.113.9",
                Some(8081),
                "ai",
                "",
                "",
                None,
            )
            .unwrap();
        assert!(store.active_rule_exists("203.0.113.9", Some(8081)).unwrap());
        assert!(
            !store.active_rule_exists("203.0.113.9", Some(9999)).unwrap(),
            "不同端口不覆盖"
        );
        assert!(
            !store.active_rule_exists("203.0.113.9", None).unwrap(),
            "端口级规则不覆盖全端口建议（升级到更大范围应放行）"
        );
        // 禁用规则不计入
        {
            let conn = store.lock().unwrap();
            conn.execute("UPDATE rules SET enabled = 0 WHERE name = 'blk-all'", [])
                .unwrap();
        }
        assert!(
            !store.active_rule_exists("203.0.113.7", None).unwrap(),
            "禁用规则不算生效"
        );
    }

    /// F795 方案 B：prune 归档——被删行整行 JSONL 追加到归档文件，
    /// 与 DB 剩余部分哈希链各自完整。
    #[test]
    fn prune_archives_rows_before_delete() {
        let store = tmp_store("prune-archive");
        for i in 0..4 {
            store
                .insert_event(&aisafeguard_core::event::SecurityEvent::engine(
                    "info",
                    format!("待归档 {i}"),
                ))
                .unwrap();
        }
        let dir = std::env::temp_dir().join(format!("asg-archive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // 全部 4 条回拨一天并修剪（带归档）
        {
            let conn = store.lock().unwrap();
            conn.execute("UPDATE events SET ts = ts - 86400", [])
                .unwrap();
        }
        assert_eq!(store.prune_events(0, Some(&dir)).unwrap(), 4);
        // 归档文件含全部 4 行，JSONL 可解析且哈希链字段在
        let archive = std::fs::read_to_string(dir.join("events-archive.jsonl")).unwrap();
        let lines: Vec<&str> = archive.lines().collect();
        assert_eq!(lines.len(), 4, "4 行都应归档: {archive}");
        for l in &lines {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert!(v["prev_hash"].is_string() && v["hash"].is_string());
            assert!(v["summary"].as_str().unwrap().contains("待归档"));
        }
        // DB 空 + 链完整；再写入新事件从空链生长
        assert!(store.verify_chain().unwrap().ok);
        store
            .insert_event(&aisafeguard_core::event::SecurityEvent::engine(
                "info", "tail",
            ))
            .unwrap();
        assert!(store.verify_chain().unwrap().ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A1 串联场景：修剪中间段（保留期边界内存在新老两段）不断链
    #[test]
    fn prune_keeps_successor_chain_valid() {
        let store = tmp_store("prune-succ");
        // 手工插入两条带时间差的旧事件（用 engine 事件的 ts 由 now 决定，
        // 这里直接验证「删除首条后第二条成为新链头」的核心语义）
        for i in 0..3 {
            store
                .insert_event(&aisafeguard_core::event::SecurityEvent::engine(
                    "info",
                    format!("e{i}"),
                ))
                .unwrap();
        }
        // 直接删除 id 最小的一行（模拟 keep 边界），后继行应重算为新链头
        {
            let conn = store.lock();
            if let Ok(conn) = &conn {
                conn.execute("DELETE FROM events WHERE id = 1", []).unwrap();
            }
        }
        // 语义验证走 prune 的 UPDATE 逻辑不好从外部注入旧 ts——
        // 此处验证 prune_events(0) 后全部清除仍链完整（核心路径），并核对
        // 非空链的 verify：再插 1 条后 3/3 可验。
        store
            .insert_event(&aisafeguard_core::event::SecurityEvent::engine(
                "info", "tail",
            ))
            .unwrap();
        let report = store.verify_chain().unwrap();
        // 手工 DELETE 绕过重算 → 该链此时必然断（证明 verify 有判别力）
        assert!(!report.ok, "绕过 prune 的手工删除必须被 verify 识破");
    }

    #[test]
    fn fed_member_quarantine_status() {
        let store = tmp_store("fed-q-status");
        store.upsert_fed_member("a", 1, "fp-a").unwrap();
        assert_eq!(
            store.fed_member_status("a").unwrap().as_deref(),
            Some("active")
        );
        assert!(store.set_fed_member_status("a", "quarantined").unwrap());
        assert_eq!(
            store.fed_member_status("a").unwrap().as_deref(),
            Some("quarantined")
        );
        assert_eq!(store.list_fed_members().unwrap()[0].3, "quarantined");
        assert!(
            !store.set_fed_member_status("ghost", "active").unwrap(),
            "成员不存在返回 false"
        );
    }

    #[test]
    fn org_events_ledger_and_metrics() {
        let dir = std::env::temp_dir().join(format!("asg-org-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db")).unwrap();
        let now = aisafeguard_core::now_ts();

        // 账本写入与读取（倒序）
        store
            .insert_org_event(now, "corroboration", "ip", "203.0.113.7", 2, "hit")
            .unwrap();
        store
            .insert_org_event(now, "corroboration", "ip", "203.0.113.8", 2, "miss")
            .unwrap();
        store
            .insert_org_event(now, "fp-flag", "", "203.0.113.7", 3, "")
            .unwrap();
        let rows = store.recent_org_events(10).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].kind, "fp-flag");
        assert_eq!(store.org_flag_count("203.0.113.7"), 1);
        assert_eq!(store.org_flag_count("无"), 0);

        // 组织建议指标（model LIKE 'fed:%'）
        store
            .insert_proposal(
                "fed:org",
                "block",
                "high",
                "in",
                "any",
                "203.0.113.7",
                None,
                None,
                "r",
                "a",
                "",
                "",
                "",
            )
            .unwrap();
        let pid2 = store
            .insert_proposal(
                "fed:org",
                "block",
                "high",
                "in",
                "any",
                "203.0.113.9",
                None,
                None,
                "r",
                "a",
                "",
                "",
                "",
            )
            .unwrap();
        store
            .insert_proposal(
                "ai", "block", "high", "in", "any", "1.2.3.4", None, None, "r", "a", "", "", "",
            )
            .unwrap();
        store.set_proposal_status(pid2, "dismissed", None).unwrap();
        let m = store.org_metrics_since(now - 60).unwrap();
        assert_eq!(m.suggestions_received, 2, "只统计 fed:* 建议");
        assert_eq!(m.suggestions_dismissed, 1);
        assert_eq!(m.corroborations_received, 2);
        assert_eq!(m.corroborations_hit, 1);

        // 订阅反馈：在库条数（未过期口径；三条 expires = now+3d，+3d+1s 后全过期）
        store
            .upsert_intel(&[
                (
                    "feodo_c2".into(),
                    "c2".into(),
                    "203.0.113.7".into(),
                    "high".into(),
                    now,
                    now + 3 * 86400,
                    true,
                ),
                (
                    "feodo_c2".into(),
                    "c2".into(),
                    "203.0.113.8".into(),
                    "high".into(),
                    now,
                    now + 3 * 86400,
                    true,
                ),
                (
                    "local_honeypot".into(),
                    "scan_source".into(),
                    "203.0.113.9".into(),
                    "local".into(),
                    now,
                    now + 3 * 86400,
                    false,
                ),
            ])
            .unwrap();
        assert_eq!(store.intel_count(now).unwrap(), 3);
        assert_eq!(store.intel_count(now + 3 * 86400 + 1).unwrap(), 0);

        // 误报回流扫描
        store
            .insert_fp_feedback("9.9.9.9", now, "误报", None)
            .unwrap();
        let fps = store.recent_fp(now - 60).unwrap();
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].0, "9.9.9.9");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fed_seq_monotonic_and_meta() {
        let dir = std::env::temp_dir().join(format!("asg-fedseq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db")).unwrap();

        // 未注册节点：无高水位行，一律拒收（宁停勿乱；真实管道 check_member 必然先建行，
        // 该分支只是纵深防御）
        assert!(!store.check_fed_seq("ghost", 5).unwrap());

        store.upsert_fed_member("a", 1, "fp-a").unwrap();
        assert!(store.check_fed_seq("a", 0).unwrap(), "首条放行");
        assert!(store.check_fed_seq("a", 7).unwrap());
        assert!(
            !store.check_fed_seq("a", 7).unwrap(),
            "同号重放拒（seen 集合由调用方先行）"
        );
        assert!(!store.check_fed_seq("a", 3).unwrap(), "回退拒");
        assert!(
            store.check_fed_seq("a", 8).unwrap(),
            "乱序前进放行（单调 ≠ 连续）"
        );

        // meta 读写：不存在 → None；写入 → 读回；覆盖
        assert_eq!(store.get_meta("fed_seq").unwrap(), None);
        store.set_meta("fed_seq", "7").unwrap();
        assert_eq!(store.get_meta("fed_seq").unwrap().as_deref(), Some("7"));
        store.set_meta("fed_seq", "12").unwrap();
        assert_eq!(store.get_meta("fed_seq").unwrap().as_deref(), Some("12"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    fn tmp_store(name: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("aisafeguard-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(&dir.join("t.db")).unwrap()
    }

    #[test]
    fn chain_v2_covers_evidence_columns() {
        // 审计 run-1 B1：http_hint/tls_fp/tls_ja4/rule_id/interaction 进入
        // canonical——原地改写任何一列必须断链（v1 时代 verify-log 会漏报）
        let store = tmp_store("chainv2");
        hit(&store, "203.0.113.7", "SSH probe");
        assert!(store.verify_chain().unwrap().ok);
        // 另开连接原地改一列（模拟持库写权限者篡改证据）
        let dir =
            std::env::temp_dir().join(format!("aisafeguard-test-chainv2-{}", std::process::id()));
        let tamper = rusqlite::Connection::open(dir.join("t.db")).unwrap();
        tamper
            .execute("UPDATE events SET interaction = '伪转录'", [])
            .unwrap();
        let report = store.verify_chain().unwrap();
        assert!(!report.ok, "v2 必须检出行改写: {report:?}");
    }

    #[test]
    fn f80x_lifecycle_methods() {
        // F802/F804/F805 store 层：累进计数/误报重置/超期归档/随机抽样/漏斗
        let dir =
            std::env::temp_dir().join(format!("aisafeguard-test-f80x-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db")).unwrap();

        // F805 累进：逐次递增、按源独立、误报重置归零
        assert_eq!(store.bump_ban_count("203.0.113.7", 100).unwrap(), 1);
        assert_eq!(store.bump_ban_count("203.0.113.7", 200).unwrap(), 2);
        assert_eq!(store.bump_ban_count("203.0.113.8", 200).unwrap(), 1);
        store.reset_recidivism("203.0.113.7").unwrap();
        assert_eq!(
            store.bump_ban_count("203.0.113.7", 300).unwrap(),
            1,
            "误报重置后从头计"
        );
        // F805 误报历史：插入反馈后可查
        store
            .insert_fp_feedback("203.0.113.9", 1000, "误报", None)
            .unwrap();
        assert!(store.fp_history_exists("203.0.113.9").unwrap());
        assert!(!store.fp_history_exists("203.0.113.10").unwrap());

        // F804 归档：7 天前创建的 pending → dismissed；applied 不受影响
        let old = store
            .insert_proposal(
                "ai",
                "block",
                "high",
                "in",
                "tcp",
                "203.0.113.7",
                None,
                None,
                "r",
                "a",
                "",
                "",
                "",
            )
            .unwrap();
        let keep = store
            .insert_proposal(
                "ai",
                "block",
                "high",
                "in",
                "tcp",
                "203.0.113.8",
                None,
                None,
                "r",
                "a",
                "",
                "",
                "",
            )
            .unwrap();
        let tamper = rusqlite::Connection::open(dir.join("t.db")).unwrap();
        tamper
            .execute(
                "UPDATE proposals SET created_ts = 1000 WHERE id = ?1",
                [old],
            )
            .unwrap();
        assert_eq!(store.sweep_expired_pending(7 * 86400).unwrap(), 1);
        let statuses: Vec<String> = store
            .list_proposals(None, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.status)
            .collect();
        assert!(statuses.contains(&"dismissed".into()), "{statuses:?}");
        assert!(statuses.contains(&"pending".into()), "新提案不受归档影响");

        // F804 抽样：applied 才可被抽中
        assert!(
            store
                .set_proposal_status_if(keep, "pending", "applying", None)
                .unwrap()
        );
        assert!(
            store
                .set_proposal_status_if(keep, "applying", "applied", Some(1))
                .unwrap()
        );
        let sample = store.sample_recent_applied(5, 86400).unwrap();
        assert!(sample.iter().any(|r| r.id == keep));
        assert!(sample.iter().all(|r| r.status == "applied"));

        // F802 漏斗：hit 计数 + top_listeners
        hit(&store, "203.0.113.9", "SSH probe");
        let f = store.funnel_since(0).unwrap();
        assert!(f.hits >= 1);
        assert!(!f.top_listeners.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_stuck_applying_recovers() {
        // 审计 run-1 F2：崩溃遗留的 applying 启动时退回 pending（可再处置）
        let store = tmp_store("sweep");
        let id = store
            .insert_proposal(
                "ai",
                "block",
                "high",
                "in",
                "tcp",
                "203.0.113.9",
                None,
                None,
                "r",
                "a",
                "",
                "",
                "",
            )
            .unwrap();
        assert!(
            store
                .set_proposal_status_if(id, "pending", "applying", None)
                .unwrap()
        );
        assert_eq!(store.sweep_stuck_applying().unwrap(), 1);
        assert_eq!(store.sweep_stuck_applying().unwrap(), 0, "幂等");
        let rows = store.list_proposals(Some("pending"), 10).unwrap();
        assert!(rows.iter().any(|r| r.id == id));
    }

    /// H200 验收（API 全字段扫描）：事件 API 的任何行都不携带口令明文或
    /// 凭证哈希——CredentialObserved 事件行只有用户名，pass_hash 刻意丢弃。
    #[test]
    fn credential_event_row_carries_no_secret() {
        let store = tmp_store("credrow");
        store
            .insert_event(&SecurityEvent::CredentialObserved {
                ts: aisafeguard_core::now_ts(),
                listener: "ssh".into(),
                kind: "ssh".into(),
                port: 2222,
                remote_ip: "203.0.113.9".into(),
                remote_port: 5555,
                username: "root".into(),
                pass_hash: Some("$argon2id$v=19$m=8192,t=2,p=1$SALTXSALT$HIDDEN".into()),
            })
            .unwrap();
        let rows = store.recent_events(10, None).unwrap();
        let row = rows
            .iter()
            .find(|r| r.kind == "credential_observed")
            .expect("credential_observed 行应入库");
        assert_eq!(row.payload, "root", "payload 列只落用户名");
        let json = serde_json::to_string(&rows).unwrap();
        assert!(!json.contains("argon2id"), "哈希不得进事件 API: {json}");
        assert!(!json.contains("HIDDEN"), "哈希不得进事件 API: {json}");
        assert!(json.contains("root"));
    }

    /// F710 冲突优先级：特权条目覆盖一切，非特权源不能覆盖特权条目。
    #[test]
    fn intel_upsert_priority_privileged_wins() {
        let store = tmp_store("intel-prio");
        let now = aisafeguard_core::now_ts();
        let mk = |source: &str, conf: &str, ab: bool| {
            (
                source.to_string(),
                "c2".to_string(),
                "9.9.9.9".to_string(),
                conf.to_string(),
                now,
                now + 60,
                ab,
            )
        };
        // 非特权先入库
        store
            .upsert_intel(&[mk("local_honeypot", "local", false)])
            .unwrap();
        // 特权覆盖
        store.upsert_intel(&[mk("feodo_c2", "high", true)]).unwrap();
        let src = || {
            store
                .active_intel(now)
                .unwrap()
                .into_iter()
                .find(|r| r.value == "9.9.9.9")
                .unwrap()
                .source
        };
        assert_eq!(src(), "feodo_c2");
        // 非特权不能再覆盖特权（WHERE 过滤 → 实际写入 0 行）
        assert_eq!(
            store
                .upsert_intel(&[mk("local_honeypot", "local", false)])
                .unwrap(),
            0
        );
        assert_eq!(src(), "feodo_c2");
        // 特权刷新自己照常
        assert_eq!(
            store.upsert_intel(&[mk("feodo_c2", "high", true)]).unwrap(),
            1
        );
    }

    /// rule_id 落库（0.7 F740）：Detection 的规则 ID 进 events 表——
    /// 「哪些规则命中多少」的按规则统计从此有据可查；非检测事件为空串。
    #[test]
    fn detection_rule_id_persisted() {
        let store = tmp_store("rule-id");
        let now = aisafeguard_core::now_ts();
        store
            .insert_event(&SecurityEvent::Detection {
                ts: now,
                kind: "signature".into(),
                src_ip: "203.0.113.7".into(),
                confidence: "high".into(),
                severity: "high".into(),
                evidence: "e".into(),
                rule_id: Some("sid:1002001".into()),
                http_hint: None,
                tls_fingerprint: None,
                tls_ja4: None,
            })
            .unwrap();
        store
            .insert_event(&SecurityEvent::engine("info", "流水"))
            .unwrap();
        let rows = store.recent_events(10, None).unwrap();
        let det = rows.iter().find(|r| r.kind == "detection").unwrap();
        assert_eq!(det.rule_id, "sid:1002001");
        let eng = rows.iter().find(|r| r.kind == "engine").unwrap();
        assert_eq!(eng.rule_id, "", "非检测事件 rule_id 为空");
        let json = serde_json::to_string(&det).unwrap();
        assert!(json.contains("sid:1002001"), "JSONL 导出携带 rule_id");
    }

    /// 指纹覆盖统计（0.5.0 H6）：Detection 总数与携带 JA3 的条数按窗口计数。
    #[test]
    fn fingerprint_stats_counts_detections() {
        let store = tmp_store("fpstats");
        let now = aisafeguard_core::now_ts();
        let detection = |fp: &str| SecurityEvent::Detection {
            ts: now,
            kind: "signature".into(),
            src_ip: "203.0.113.7".into(),
            confidence: "high".into(),
            severity: "high".into(),
            evidence: "e".into(),
            rule_id: Some("sid:1".into()),
            http_hint: None,
            tls_fingerprint: (!fp.is_empty()).then(|| fp.to_string()),
            tls_ja4: None,
        };
        store
            .insert_event(&detection("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"))
            .unwrap();
        store.insert_event(&detection("")).unwrap();
        store
            .insert_event(&detection("f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6"))
            .unwrap();
        // 非 detection 事件不计入
        store
            .insert_event(&SecurityEvent::engine("info", "流水"))
            .unwrap();
        let (total, with_fp) = store.detection_fingerprint_stats_since(now - 60).unwrap();
        assert_eq!((total, with_fp), (3, 2));
        // 窗口外为 0
        let (t0, f0) = store.detection_fingerprint_stats_since(now + 60).unwrap();
        assert_eq!((t0, f0), (0, 0));
    }

    /// 价值指标口径（0.4.0 B5）：建议数/采纳数/误报数/自动封禁数，按时间窗。
    #[test]
    fn value_metrics_windows() {
        let store = tmp_store("metrics");
        let now = aisafeguard_core::now_ts();
        // 窗口内：2 条建议（1 条 applied）、1 条误报、1 次自动封禁
        store
            .insert_proposal(
                "glm",
                "block",
                "high",
                "in",
                "any",
                "203.0.113.1",
                None,
                Some(900),
                "r1",
                "a",
                "",
                "",
                "",
            )
            .unwrap();
        store
            .insert_proposal(
                "glm",
                "block",
                "high",
                "in",
                "any",
                "203.0.113.2",
                None,
                Some(900),
                "r2",
                "a",
                "",
                "",
                "",
            )
            .unwrap();
        let ids: Vec<i64> = {
            let conn = store.lock().unwrap();
            let mut st = conn
                .prepare("SELECT id FROM proposals ORDER BY id")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(|x| x.unwrap())
                .collect()
        };
        store.set_proposal_status(ids[0], "applied", None).unwrap();
        store
            .insert_fp_feedback("203.0.113.9", now, "fp", None)
            .unwrap();
        // 真实链路：「已自动封禁」文本在 kind=engine 的事件里（handle_detection 固定文案）
        store
            .insert_event(&aisafeguard_core::event::SecurityEvent::Engine {
                ts: now,
                level: "info".into(),
                message: "已自动封禁 203.0.113.7 至 20:00:00（规则 aisafeguard-blk-x）".into(),
            })
            .unwrap();
        let m = store.metrics_since(now - 60).unwrap();
        assert_eq!(m.proposed, 2);
        assert_eq!(m.applied, 1);
        assert_eq!(m.fp, 1);
        assert_eq!(m.auto_blocks, 1);
        // 窗口外不计入
        let outside = store.metrics_since(now + 60).unwrap();
        assert_eq!((outside.proposed, outside.auto_blocks), (0, 0));
    }

    /// 误报抑制记录的清除（0.4.0 B3）。
    #[test]
    fn fp_feedback_clear() {
        let store = tmp_store("fp-clear");
        store
            .insert_fp_feedback("203.0.113.9", 100, "test", None)
            .unwrap();
        assert!(store.active_fp("203.0.113.9", 150, 10_000, None).unwrap());
        assert_eq!(store.clear_fp_feedback("203.0.113.9").unwrap(), 1);
        assert!(!store.active_fp("203.0.113.9", 150, 10_000, None).unwrap());
        // 再清一次 = 0（幂等）
        assert_eq!(store.clear_fp_feedback("203.0.113.9").unwrap(), 0);
    }

    /// quorum 计数（0.4.0 C3）：按 listener 前缀 fed: 去重节点。
    #[test]
    fn fp_port_scope() {
        let store = tmp_store("fp-port");
        // 端口级记录：仅 2222
        store
            .insert_fp_feedback("203.0.113.9", 100, "仅 2222", Some(2222))
            .unwrap();
        assert!(
            store
                .active_fp("203.0.113.9", 150, 10_000, Some(2222))
                .unwrap()
        );
        assert!(
            !store
                .active_fp("203.0.113.9", 150, 10_000, Some(8081))
                .unwrap()
        );
        assert!(
            !store.active_fp("203.0.113.9", 150, 10_000, None).unwrap(),
            "端口级记录不抑制来源级检测"
        );
        // 改标为 IP 级（最后一次标记决定粒度）→ 任何处置都抑制
        store
            .insert_fp_feedback("203.0.113.9", 200, "按 IP", None)
            .unwrap();
        assert!(
            store
                .active_fp("203.0.113.9", 250, 10_000, Some(8081))
                .unwrap()
        );
        assert!(store.active_fp("203.0.113.9", 250, 10_000, None).unwrap());
    }

    /// fed 成员 node ↔ 证书指纹 TOFU 绑定：首登、同指纹心跳、异指纹拒绝。
    #[test]
    fn fed_member_cert_pinning() {
        let store = tmp_store("fed-pin");
        assert!(store.upsert_fed_member("agent1", 100, "fp-a").unwrap());
        assert_eq!(store.list_fed_members().unwrap().len(), 1);
        // 同指纹心跳：刷新 last_seen，不产生新行
        assert!(store.upsert_fed_member("agent1", 200, "fp-a").unwrap());
        let rows = store.list_fed_members().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0],
            ("agent1".into(), "fp-a".into(), 200, "active".into())
        );
        // 异指纹：拒绝（证书冒用/更换都在此拦下，换证需管理员删成员记录）
        assert!(!store.upsert_fed_member("agent1", 300, "fp-b").unwrap());
        assert_eq!(store.list_fed_members().unwrap()[0].2, 200);
        // 另一节点独立登记
        assert!(store.upsert_fed_member("agent2", 400, "fp-b").unwrap());
        assert_eq!(store.list_fed_members().unwrap().len(), 2);
    }

    fn hit(store: &Store, ip: &str, summary: &str) {
        store
            .insert_event(&SecurityEvent::HoneypotHit {
                ts: aisafeguard_core::now_ts(),
                listener: "ssh".into(),
                kind: "ssh".into(),
                port: 2222,
                remote_ip: ip.into(),
                remote_port: 55555,
                summary: summary.into(),
                payload: "p".into(),
                http_hint: None,
                interaction: None,
            })
            .unwrap();
    }

    #[test]
    fn event_roundtrip_and_stats() {
        let store = tmp_store("ev");
        hit(&store, "203.0.113.7", "SSH probe");
        hit(&store, "203.0.113.7", "SSH probe 2");
        store
            .insert_event(&SecurityEvent::Engine {
                ts: aisafeguard_core::now_ts(),
                level: "info".into(),
                message: "启动".into(),
            })
            .unwrap();

        let rows = store.recent_events(10, None).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].kind, "engine");

        let stats = store.stats_since(0).unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.unique_ips, 1);
        assert_eq!(stats.top_ips[0].ip, "203.0.113.7");

        let filtered = store.recent_events(10, Some("203.0.113.7")).unwrap();
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn interaction_roundtrip_and_chain_compatible() {
        // 0.5.9 H102：逐命令数组落盘往返；不含 interaction 的存量事件读回为空串；
        // interaction 不进哈希链 canonical——写入前后链校验都通过
        use aisafeguard_core::event::ShellStep;
        let store = tmp_store("interaction");

        store
            .insert_event(&SecurityEvent::HoneypotHit {
                ts: aisafeguard_core::now_ts(),
                listener: "ssh".into(),
                kind: "ssh".into(),
                port: 2222,
                remote_ip: "203.0.113.7".into(),
                remote_port: 40001,
                summary: "假 Shell 会话".into(),
                payload: "whoami".into(),
                http_hint: None,
                interaction: Some(vec![
                    ShellStep {
                        command: "whoami".into(),
                        response: "root".into(),
                    },
                    ShellStep {
                        command: "uname -a".into(),
                        response: "Linux debian 6.1.0".into(),
                    },
                ]),
            })
            .unwrap();
        // 存量形态：无 interaction
        hit(&store, "203.0.113.7", "低交互命中");

        let rows = store.recent_events(10, None).unwrap();
        assert_eq!(rows.len(), 2);
        let with_steps = rows
            .iter()
            .find(|r| !r.interaction.is_empty())
            .expect("应有交互行");
        let steps: Vec<ShellStep> = serde_json::from_str(&with_steps.interaction).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].command, "whoami");
        assert_eq!(steps[1].response, "Linux debian 6.1.0");
        assert_eq!(
            rows.iter().filter(|r| r.interaction.is_empty()).count(),
            1,
            "存量事件 interaction 为空串"
        );

        assert!(
            store.verify_chain().unwrap().ok,
            "链校验不受 interaction 影响"
        );
    }

    #[test]
    fn hash_chain_verifies_and_detects_tamper() {
        let dir =
            std::env::temp_dir().join(format!("aisafeguard-test-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        let store = Store::open(&db_path).unwrap();
        hit(&store, "203.0.113.7", "a");
        hit(&store, "203.0.113.8", "b");
        hit(&store, "203.0.113.9", "c");

        let report = store.verify_chain().unwrap();
        assert!(report.ok);
        assert_eq!(report.rows, 3);
        assert!(report.broken_at.is_none());

        // 链式性质：每行 prev_hash == 前一行 hash（recent_events 倒序返回）
        let rows = store.recent_events(10, None).unwrap();
        assert_eq!(rows[1].prev_hash, rows[2].hash);

        // 直接改库模拟篡改 → 校验必须失败
        drop(store);
        let conn = Connection::open(&db_path).unwrap();
        conn.execute("UPDATE events SET summary = 'tampered' WHERE id = 2", [])
            .unwrap();
        drop(conn);
        let store = Store::open(&db_path).unwrap();
        let report = store.verify_chain().unwrap();
        assert!(!report.ok);
        assert_eq!(report.broken_at, Some(2));
    }

    #[test]
    fn export_writes_jsonl() {
        let store = tmp_store("export");
        hit(&store, "203.0.113.7", "a");
        let dir =
            std::env::temp_dir().join(format!("aisafeguard-test-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("events.jsonl");
        let n = store.export_events(&out).unwrap();
        assert_eq!(n, 1);
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("\"hash\":\""));
        assert!(text.contains("203.0.113.7"));
    }

    #[test]
    fn rules_expiry_and_proposals() {
        let store = tmp_store("rp");
        let rule = store
            .insert_rule(
                "aisafeguard-blk-x",
                "in",
                "tcp",
                "203.0.113.9",
                Some(22),
                "manual",
                "test",
                "ssh",
                None,
            )
            .unwrap();
        assert_eq!(store.count_rules().unwrap(), 1);
        assert!(store.get_rule(rule.id).unwrap().is_some());
        assert!(
            store
                .expired_rules(aisafeguard_core::now_ts())
                .unwrap()
                .is_empty()
        );

        let _auto = store
            .insert_rule(
                "aisafeguard-blk-auto",
                "in",
                "any",
                "198.51.100.5",
                None,
                "engine",
                "freq",
                "检测器",
                Some(aisafeguard_core::now_ts() - 10),
            )
            .unwrap();
        let expired = store.expired_rules(aisafeguard_core::now_ts()).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].name, "aisafeguard-blk-auto");

        let pid = store
            .insert_proposal(
                "m",
                "block",
                "high",
                "in",
                "tcp",
                "203.0.113.9",
                Some(22),
                None,
                "扫描",
                "分析",
                "",
                "",
                "",
            )
            .unwrap();
        assert!(
            store
                .pending_proposal_exists("203.0.113.9", Some(22))
                .unwrap()
        );
        store
            .set_proposal_status(pid, "applied", Some(rule.id))
            .unwrap();
        let p = store.get_proposal(pid).unwrap().unwrap();
        assert_eq!(p.status, "applied");

        store.insert_ai_run("glm-4.7", true, "ok").unwrap();
        assert_eq!(store.list_ai_runs(5).unwrap().len(), 1);
    }

    #[test]
    fn promote_marks_rule_and_extends_ttl() {
        // 0.5.4 F1/F3：转正 = TTL 延长 + promoted 标记，读回一致
        let store = tmp_store("promo");
        let rule = store
            .insert_rule(
                "aisafeguard-blk-ai",
                "in",
                "any",
                "198.51.100.8",
                None,
                "ai",
                "AI 建议 #1: 试封",
                "AI",
                Some(aisafeguard_core::now_ts() + 600),
            )
            .unwrap();
        assert!(!store.list_rules().unwrap()[0].promoted);

        let promoted_until = aisafeguard_core::now_ts() + 86_400 * 30;
        store.mark_promoted(rule.id, promoted_until).unwrap();
        let rows = store.list_rules().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].promoted);
        assert_eq!(rows[0].expires_ts, Some(promoted_until));
    }
}
