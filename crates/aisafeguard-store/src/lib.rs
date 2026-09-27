#![forbid(unsafe_code)]

//! SQLite 持久层：统一事件流水、防火墙规则、AI 建议、AI 调用审计。
//! 时间戳一律 epoch 秒（整数），展示层再转本地时间。
//!
//! 完整性（[A.8.15]）：事件表维护链式 SHA-256 哈希（hash = H(prev_hash | 规范化行)），
//! `verify_chain` 可离线校验任一行是否被篡改。

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use aisafeguard_core::error::{Error, Result};
use aisafeguard_core::event::SecurityEvent;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalRow {
    pub id: i64,
    pub created_ts: i64,
    pub model: String,
    pub severity: String,
    pub direction: String,
    pub protocol: String,
    pub remote_ip: String,
    pub local_port: Option<u16>,
    pub reason: String,
    pub status: String,
    pub applied_rule_id: Option<i64>,
    pub analysis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRunRow {
    pub id: i64,
    pub ts: i64,
    pub model: String,
    pub ok: bool,
    pub summary: String,
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
    expires_ts INTEGER
);

CREATE TABLE IF NOT EXISTS proposals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_ts      INTEGER NOT NULL,
    model           TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL,
    direction       TEXT NOT NULL,
    protocol        TEXT NOT NULL,
    remote_ip       TEXT NOT NULL DEFAULT '',
    local_port      INTEGER,
    reason          TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending',
    applied_rule_id INTEGER,
    analysis        TEXT NOT NULL DEFAULT ''
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
"#;

/// 事件链哈希：H(prev_hash | 规范化行)。规范化用 serde_json 默认的字典序键，
/// 同一行数据在任何平台重算结果一致。
fn canonical_event(
    ts: i64,
    kind: &str,
    listener: &str,
    remote_ip: &str,
    remote_port: i64,
    summary: &str,
    payload: &str,
) -> String {
    serde_json::json!({
        "kind": kind,
        "listener": listener,
        "payload": payload,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "summary": summary,
        "ts": ts,
    })
    .to_string()
}

fn chain_hash(prev_hash: &str, canonical: &str) -> String {
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

/// 迁移补链的行数据 (id, ts, kind, listener, remote_ip, remote_port, summary, payload)
type ChainSeedRow = (i64, i64, String, String, String, i64, String, String);

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
        conn.execute_batch(SCHEMA).map_err(|e| Error::Store(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate_pre_0_2()?;
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
        if seeded > 0 {
            return Ok(());
        }
        let unchained: i64 = conn
            .query_row("SELECT COUNT(*) FROM events WHERE hash = ''", [], |r| r.get(0))
            .map_err(|e| Error::Store(e.to_string()))?;
        if unchained > 0 {
            let rows: Vec<ChainSeedRow> = {
                let mut stmt = conn
                    .prepare("SELECT id, ts, kind, listener, remote_ip, remote_port, summary, payload FROM events ORDER BY id")
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
                    ))
                })
                .map_err(|e| Error::Store(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::Store(e.to_string()))?
            };
            let mut prev = String::new();
            for (id, ts, kind, listener, remote_ip, remote_port, summary, payload) in rows {
                let canonical = canonical_event(ts, &kind, &listener, &remote_ip, remote_port, &summary, &payload);
                let h = chain_hash(&prev, &canonical);
                conn.execute(
                    "UPDATE events SET prev_hash = ?2, hash = ?3 WHERE id = ?1",
                    params![id, prev, h],
                )
                .map_err(|e| Error::Store(e.to_string()))?;
                prev = h;
            }
        }
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('chain_seeded', '1') ON CONFLICT(key) DO NOTHING",
            [],
        )
        .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Store("数据库连接锁已中毒".into()))
    }

    // ---------- 事件 ----------

    pub fn insert_event(&self, ev: &SecurityEvent) -> Result<()> {
        let (listener, remote_ip, remote_port, payload) = match ev {
            SecurityEvent::HoneypotHit {
                listener,
                remote_ip,
                remote_port,
                payload,
                ..
            } => (
                listener.clone(),
                remote_ip.clone(),
                *remote_port as i64,
                payload.clone(),
            ),
            SecurityEvent::Detection { src_ip, .. } => {
                (String::new(), src_ip.clone(), 0, String::new())
            }
            _ => (String::new(), String::new(), 0, String::new()),
        };
        let summary = ev.summary();
        let ts = ev.ts();
        let kind = ev.kind();
        let conn = self.lock()?;
        let prev_hash: String = conn
            .query_row("SELECT hash FROM events ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .unwrap_or_default();
        let canonical =
            canonical_event(ts, kind, &listener, &remote_ip, remote_port, &summary, &payload);
        let hash = chain_hash(&prev_hash, &canonical);
        conn.execute(
            "INSERT INTO events (ts, kind, listener, remote_ip, remote_port, summary, payload, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![ts, kind, listener, remote_ip, remote_port, summary, payload, prev_hash, hash],
        )
        .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    pub fn recent_events(&self, limit: u32, ip_filter: Option<&str>) -> Result<Vec<EventRow>> {
        let conn = self.lock()?;
        let sql = match ip_filter {
            Some(_) => {
                "SELECT id, ts, kind, listener, remote_ip, remote_port, summary, payload, prev_hash, hash
                 FROM events WHERE remote_ip LIKE ?1 ORDER BY id DESC LIMIT ?2"
            }
            None => {
                "SELECT id, ts, kind, listener, remote_ip, remote_port, summary, payload, prev_hash, hash
                 FROM events ORDER BY id DESC LIMIT ?2"
            }
        };
        let mut stmt = conn.prepare(sql).map_err(|e| Error::Store(e.to_string()))?;
        let like = ip_filter.map(|s| format!("%{s}%"));
        let rows = stmt
            .query_map(
                params![like, limit],
                |r| {
                    Ok(EventRow {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        kind: r.get(2)?,
                        listener: r.get(3)?,
                        remote_ip: r.get(4)?,
                        remote_port: r.get::<_, i64>(5)? as u16,
                        summary: r.get(6)?,
                        payload: r.get(7)?,
                        prev_hash: r.get(8)?,
                        hash: r.get(9)?,
                    })
                },
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn count_events_kind_since(&self, kind: &str, since: i64) -> Result<i64> {
        self.lock()?
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = ?1 AND ts >= ?2",
                params![kind, since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn stats_since(&self, since: i64) -> Result<StatsSummary> {
        let conn = self.lock()?;
        let (total, unique) = conn
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT remote_ip) FROM events
                 WHERE kind = 'honeypot_hit' AND ts >= ?1 AND remote_ip <> ''",
                params![since],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT remote_ip, COUNT(*) c FROM events
                 WHERE kind = 'honeypot_hit' AND ts >= ?1 AND remote_ip <> ''
                 GROUP BY remote_ip ORDER BY c DESC LIMIT 10",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let top_ips = stmt
            .query_map(params![since], |r| {
                Ok(TopIp {
                    ip: r.get(0)?,
                    hits: r.get(1)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT listener, COUNT(*) c FROM events
                 WHERE kind = 'honeypot_hit' AND ts >= ?1 AND listener <> ''
                 GROUP BY listener ORDER BY c DESC",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let per_listener = stmt
            .query_map(params![since], |r| {
                Ok(ListenerCount {
                    listener: r.get(0)?,
                    hits: r.get(1)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(StatsSummary {
            total,
            unique_ips: unique,
            top_ips,
            per_listener,
        })
    }

    /// 蜜罐原始记录（供 AI 分析），只取必要字段。
    pub fn recent_honeypot_hits(&self, limit: u32) -> Result<Vec<EventRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, kind, listener, remote_ip, remote_port, summary, payload, prev_hash, hash
                 FROM events WHERE kind = 'honeypot_hit' ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(EventRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    kind: r.get(2)?,
                    listener: r.get(3)?,
                    remote_ip: r.get(4)?,
                    remote_port: r.get::<_, i64>(5)? as u16,
                    summary: r.get(6)?,
                    payload: r.get(7)?,
                    prev_hash: r.get(8)?,
                    hash: r.get(9)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// 修剪过期事件。删除会断链——只做整段修剪，并把断点行的 prev_hash 置空，
    /// 校验器把 prev_hash = '' 的行视为新链起点。
    pub fn prune_events(&self, keep_days: u32) -> Result<usize> {
        let cutoff = aisafeguard_core::now_ts() - (keep_days as i64) * 86400;
        let conn = self.lock()?;
        let boundary: Option<i64> = conn
            .query_row(
                "SELECT MAX(id) FROM events WHERE ts < ?1",
                params![cutoff],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let Some(boundary) = boundary else {
            return Ok(0);
        };
        let successor: Option<i64> = conn
            .query_row(
                "SELECT MIN(id) FROM events WHERE id > ?1",
                params![boundary],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        conn.execute("DELETE FROM events WHERE id <= ?1", params![boundary])
            .map_err(|e| Error::Store(e.to_string()))?;
        let deleted = conn.changes();
        if let Some(succ) = successor {
            conn.execute("UPDATE events SET prev_hash = '' WHERE id = ?1", params![succ])
                .map_err(|e| Error::Store(e.to_string()))?;
        }
        Ok(deleted as usize)
    }

    /// 离线校验哈希链。prev_hash 为空的行视为链起点（prune 造成的新链头）。
    pub fn verify_chain(&self) -> Result<ChainReport> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, kind, listener, remote_ip, remote_port, summary, payload, prev_hash, hash
                 FROM events ORDER BY id",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(EventRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    kind: r.get(2)?,
                    listener: r.get(3)?,
                    remote_ip: r.get(4)?,
                    remote_port: r.get::<_, i64>(5)? as u16,
                    summary: r.get(6)?,
                    payload: r.get(7)?,
                    prev_hash: r.get(8)?,
                    hash: r.get(9)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        let mut prev = String::new();
        let mut count = 0usize;
        for row in rows {
            let row = row.map_err(|e| Error::Store(e.to_string()))?;
            count += 1;
            let canonical = canonical_event(
                row.ts,
                &row.kind,
                &row.listener,
                &row.remote_ip,
                row.remote_port as i64,
                &row.summary,
                &row.payload,
            );
            let expect = if row.prev_hash.is_empty() {
                chain_hash("", &canonical)
            } else {
                chain_hash(&prev, &canonical)
            };
            if row.hash != expect {
                return Ok(ChainReport {
                    rows: count,
                    ok: false,
                    broken_at: Some(row.id),
                });
            }
            prev = row.hash.clone();
        }
        Ok(ChainReport {
            rows: count,
            ok: true,
            broken_at: None,
        })
    }

    /// 导出全部事件（含哈希字段）为 JSONL，供离线留档。
    pub fn export_events(&self, out: &Path) -> Result<usize> {
        use std::io::Write;
        let rows = self.recent_events(u32::MAX, None)?;
        let mut f = std::fs::File::create(out)
            .map_err(|e| Error::Store(format!("创建导出文件失败: {e}")))?;
        for r in &rows {
            let line = serde_json::to_string(r).map_err(|e| Error::Store(e.to_string()))?;
            f.write_all(line.as_bytes())
                .and_then(|_| f.write_all(b"\n"))
                .map_err(|e| Error::Store(format!("写入导出失败: {e}")))?;
        }
        Ok(rows.len())
    }

    // ---------- 规则 ----------

    #[allow(clippy::too_many_arguments)]
    pub fn insert_rule(
        &self,
        name: &str,
        direction: &str,
        protocol: &str,
        remote_ip: &str,
        local_port: Option<u16>,
        origin: &str,
        note: &str,
        expires_ts: Option<i64>,
    ) -> Result<RuleRow> {
        let ts = aisafeguard_core::now_ts();
        self.lock()?
            .execute(
                "INSERT INTO rules (created_ts, name, direction, protocol, remote_ip, local_port, origin, enabled, note, expires_ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9)",
                params![ts, name, direction, protocol, remote_ip, local_port, origin, note, expires_ts],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let id = self
            .lock()?
            .query_row(
                "SELECT id FROM rules WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(RuleRow {
            id,
            created_ts: ts,
            name: name.into(),
            direction: direction.into(),
            protocol: protocol.into(),
            remote_ip: remote_ip.into(),
            local_port,
            origin: origin.into(),
            enabled: true,
            note: note.into(),
            expires_ts,
        })
    }

    pub fn list_rules(&self) -> Result<Vec<RuleRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, created_ts, name, direction, protocol, remote_ip, local_port, origin, enabled, note, expires_ts
                 FROM rules ORDER BY id DESC",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(RuleRow {
                    id: r.get(0)?,
                    created_ts: r.get(1)?,
                    name: r.get(2)?,
                    direction: r.get(3)?,
                    protocol: r.get(4)?,
                    remote_ip: r.get(5)?,
                    local_port: r.get(6)?,
                    origin: r.get(7)?,
                    enabled: r.get::<_, i64>(8)? != 0,
                    note: r.get(9)?,
                    expires_ts: r.get(10)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn count_rules(&self) -> Result<i64> {
        self.lock()?
            .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn get_rule(&self, id: i64) -> Result<Option<RuleRow>> {
        Ok(self.list_rules()?.into_iter().find(|r| r.id == id))
    }

    pub fn delete_rule(&self, id: i64) -> Result<()> {
        self.lock()?
            .execute("DELETE FROM rules WHERE id = ?1", params![id])
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    /// 到期未解封的自动封禁规则。
    pub fn expired_rules(&self, now: i64) -> Result<Vec<RuleRow>> {
        Ok(self
            .list_rules()?
            .into_iter()
            .filter(|r| matches!(r.expires_ts, Some(exp) if exp <= now))
            .collect())
    }

    // ---------- AI 建议 ----------

    pub fn pending_proposal_exists(&self, remote_ip: &str, local_port: Option<u16>) -> Result<bool> {
        let n: i64 = self
            .lock()?
            .query_row(
                "SELECT COUNT(*) FROM proposals
                 WHERE status = 'pending' AND remote_ip = ?1 AND local_port IS ?2",
                params![remote_ip, local_port],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n > 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_proposal(
        &self,
        model: &str,
        severity: &str,
        direction: &str,
        protocol: &str,
        remote_ip: &str,
        local_port: Option<u16>,
        reason: &str,
        analysis: &str,
    ) -> Result<i64> {
        self.lock()?
            .execute(
                "INSERT INTO proposals (created_ts, model, severity, direction, protocol, remote_ip, local_port, reason, status, analysis)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9)",
                params![
                    aisafeguard_core::now_ts(),
                    model,
                    severity,
                    direction,
                    protocol,
                    remote_ip,
                    local_port,
                    reason,
                    analysis
                ],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        self.lock()?
            .query_row("SELECT last_insert_rowid()", [], |r| r.get(0))
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn list_proposals(&self, status: Option<&str>, limit: u32) -> Result<Vec<ProposalRow>> {
        let conn = self.lock()?;
        let sql = match status {
            Some(_) => {
                "SELECT id, created_ts, model, severity, direction, protocol, remote_ip, local_port, reason, status, applied_rule_id, analysis
                 FROM proposals WHERE status = ?1 ORDER BY id DESC LIMIT ?2"
            }
            None => {
                "SELECT id, created_ts, model, severity, direction, protocol, remote_ip, local_port, reason, status, applied_rule_id, analysis
                 FROM proposals ORDER BY id DESC LIMIT ?2"
            }
        };
        let mut stmt = conn.prepare(sql).map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![status, limit], |r| {
                Ok(ProposalRow {
                    id: r.get(0)?,
                    created_ts: r.get(1)?,
                    model: r.get(2)?,
                    severity: r.get(3)?,
                    direction: r.get(4)?,
                    protocol: r.get(5)?,
                    remote_ip: r.get(6)?,
                    local_port: r.get(7)?,
                    reason: r.get(8)?,
                    status: r.get(9)?,
                    applied_rule_id: r.get(10)?,
                    analysis: r.get(11)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn get_proposal(&self, id: i64) -> Result<Option<ProposalRow>> {
        Ok(self
            .list_proposals(None, 1000)?
            .into_iter()
            .find(|p| p.id == id))
    }

    pub fn count_proposals(&self, status: &str) -> Result<i64> {
        self.lock()?
            .query_row(
                "SELECT COUNT(*) FROM proposals WHERE status = ?1",
                params![status],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn set_proposal_status(&self, id: i64, status: &str, applied_rule_id: Option<i64>) -> Result<()> {
        self.lock()?
            .execute(
                "UPDATE proposals SET status = ?2, applied_rule_id = ?3 WHERE id = ?1",
                params![id, status, applied_rule_id],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    // ---------- 暴露面快照 ----------

    pub fn insert_exposure(&self, ts: i64, json: &str) -> Result<()> {
        self.lock()?
            .execute(
                "INSERT INTO exposure (ts, json) VALUES (?1, ?2)",
                params![ts, json],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        // 只保留最近 10 份快照
        self.lock()?
            .execute(
                "DELETE FROM exposure WHERE id NOT IN (SELECT id FROM exposure ORDER BY id DESC LIMIT 10)",
                [],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    pub fn latest_exposure(&self) -> Result<Option<(i64, String)>> {
        self.lock()?
            .query_row(
                "SELECT ts, json FROM exposure ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(Error::Store(other.to_string())),
            })
    }

    // ---------- AI 调用审计 ----------

    pub fn insert_ai_run(&self, model: &str, ok: bool, summary: &str) -> Result<()> {
        self.lock()?
            .execute(
                "INSERT INTO ai_runs (ts, model, ok, summary) VALUES (?1, ?2, ?3, ?4)",
                params![aisafeguard_core::now_ts(), model, ok, summary],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    pub fn list_ai_runs(&self, limit: u32) -> Result<Vec<AiRunRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, ts, model, ok, summary FROM ai_runs ORDER BY id DESC LIMIT ?1")
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(AiRunRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    model: r.get(2)?,
                    ok: r.get::<_, i64>(3)? != 0,
                    summary: r.get(4)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("aisafeguard-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(&dir.join("t.db")).unwrap()
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
    fn hash_chain_verifies_and_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("aisafeguard-test-chain-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("aisafeguard-test-export-{}", std::process::id()));
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
            .insert_rule("aisafeguard-blk-x", "in", "tcp", "203.0.113.9", Some(22), "manual", "test", None)
            .unwrap();
        assert_eq!(store.count_rules().unwrap(), 1);
        assert!(store.get_rule(rule.id).unwrap().is_some());
        assert!(store.expired_rules(aisafeguard_core::now_ts()).unwrap().is_empty());

        let _auto = store
            .insert_rule(
                "aisafeguard-blk-auto",
                "in",
                "any",
                "198.51.100.5",
                None,
                "engine",
                "freq",
                Some(aisafeguard_core::now_ts() - 10),
            )
            .unwrap();
        let expired = store.expired_rules(aisafeguard_core::now_ts()).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].name, "aisafeguard-blk-auto");

        let pid = store
            .insert_proposal("m", "high", "in", "tcp", "203.0.113.9", Some(22), "扫描", "分析")
            .unwrap();
        assert!(store.pending_proposal_exists("203.0.113.9", Some(22)).unwrap());
        store.set_proposal_status(pid, "applied", Some(rule.id)).unwrap();
        let p = store.get_proposal(pid).unwrap().unwrap();
        assert_eq!(p.status, "applied");

        store.insert_ai_run("glm-4.7", true, "ok").unwrap();
        assert_eq!(store.list_ai_runs(5).unwrap().len(), 1);
    }
}
