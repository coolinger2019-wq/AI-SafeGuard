//! events 表域（P1-4 自 lib.rs 拆出）：事件流水与哈希链（insert/verify/prune/导出）。

use crate::{
    ChainReport, EventRow, ListenerCount, StatsSummary, Store, TopIp, canonical_event, chain_hash,
};
use aisafeguard_core::error::{Error, Result};
use aisafeguard_core::event::SecurityEvent;
use rusqlite::params;
use std::io::Write;
use std::path::Path;

/// events 表完整列清单（三处查询共用：recent_events / recent_honeypot_hits / verify_chain）。
/// 新列追加在 tls_ja4 之后、prev_hash/hash 之前——链列永远最后两列。
const EVENT_COLUMNS: &str = "id, ts, kind, listener, remote_ip, remote_port, summary, payload, http_hint, tls_fp, tls_ja4, rule_id, interaction, prev_hash, hash";

fn event_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        id: r.get(0)?,
        ts: r.get(1)?,
        kind: r.get(2)?,
        listener: r.get(3)?,
        remote_ip: r.get(4)?,
        remote_port: r.get::<_, i64>(5)? as u16,
        summary: r.get(6)?,
        payload: r.get(7)?,
        http_hint: r.get(8)?,
        tls_fp: r.get(9)?,
        tls_ja4: r.get(10)?,
        rule_id: r.get(11)?,
        interaction: r.get(12)?,
        prev_hash: r.get(13)?,
        hash: r.get(14)?,
    })
}

/// 事件链哈希：H(prev_hash | 规范化行)。规范化用 serde_json 默认的字典序键，
/// 同一行数据在任何平台重算结果一致。
/// v2（审计 run-1 B1）：canonical 补齐 http_hint/tls_fp/tls_ja4/rule_id/
/// interaction 全部证据列——旧 v1 只链 7 列，未被链住的证据列可被原地改写
/// 而 verify-log 照样报完整。升级由 ensure_chain_v2 一次性全量重链。
/// prune 级联重链的行元组（id + canonical_event 所需 12 字段）
type PruneRow = (
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
    // ---------- 事件 ----------

    pub fn insert_event(&self, ev: &SecurityEvent) -> Result<()> {
        let (
            listener,
            remote_ip,
            remote_port,
            payload,
            http_hint,
            tls_fp,
            tls_ja4,
            rule_id,
            interaction,
        ) = match ev {
            SecurityEvent::HoneypotHit {
                listener,
                remote_ip,
                remote_port,
                payload,
                http_hint,
                interaction,
                ..
            } => (
                listener.clone(),
                remote_ip.clone(),
                *remote_port as i64,
                payload.clone(),
                http_hint
                    .as_ref()
                    .map(|h| serde_json::to_string(h).unwrap_or_default())
                    .unwrap_or_default(),
                String::new(),
                String::new(),
                String::new(),
                interaction
                    .as_ref()
                    .map(|steps| serde_json::to_string(steps).unwrap_or_default())
                    .unwrap_or_default(),
            ),
            SecurityEvent::Detection {
                src_ip,
                http_hint,
                tls_fingerprint,
                tls_ja4,
                rule_id,
                ..
            } => (
                String::new(),
                src_ip.clone(),
                0,
                String::new(),
                http_hint
                    .as_ref()
                    .map(|h| serde_json::to_string(h).unwrap_or_default())
                    .unwrap_or_default(),
                tls_fingerprint.clone().unwrap_or_default(),
                tls_ja4.clone().unwrap_or_default(),
                rule_id.clone().unwrap_or_default(),
                String::new(),
            ),
            // 凭证采集（0.5.10 H200）：事件行只落用户名（payload 列），
            // pass_hash 刻意不出现在任何落库列——哈希只进独立凭证库
            SecurityEvent::CredentialObserved {
                listener,
                remote_ip,
                remote_port,
                username,
                ..
            } => (
                listener.clone(),
                remote_ip.clone(),
                *remote_port as i64,
                username.clone(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
            _ => (
                String::new(),
                String::new(),
                0,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
        };
        let summary = ev.summary();
        let ts = ev.ts();
        let kind = ev.kind();
        let conn = self.lock()?;
        // 空表 = 链头起点（合法）；其余错误（磁盘 I/O 等）上抛——静默吞成
        // 空串会让坏行成为被 verify 认可的链起点，完整性出现无痕缺口。
        let prev_hash: String = match conn.query_row(
            "SELECT hash FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        ) {
            Ok(h) => h,
            Err(rusqlite::Error::QueryReturnedNoRows) => String::new(),
            Err(e) => return Err(Error::Store(e.to_string())),
        };
        let canonical = canonical_event(
            ts,
            kind,
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
        let hash = chain_hash(&prev_hash, &canonical);
        conn.execute(
            "INSERT INTO events (ts, kind, listener, remote_ip, remote_port, summary, payload, http_hint, tls_fp, tls_ja4, rule_id, interaction, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![ts, kind, listener, remote_ip, remote_port, summary, payload, http_hint, tls_fp, tls_ja4, rule_id, interaction, prev_hash, hash],
        )
        .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    pub fn recent_events(&self, limit: u32, ip_filter: Option<&str>) -> Result<Vec<EventRow>> {
        let conn = self.lock()?;
        let sql = match ip_filter {
            Some(_) => {
                format!(
                    "SELECT {EVENT_COLUMNS} FROM events WHERE remote_ip LIKE ?1 ORDER BY id DESC LIMIT ?2"
                )
            }
            None => {
                format!("SELECT {EVENT_COLUMNS} FROM events ORDER BY id DESC LIMIT ?2")
            }
        };
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| Error::Store(e.to_string()))?;
        let like = ip_filter.map(|s| format!("%{s}%"));
        let rows = stmt
            .query_map(params![like, limit], event_row)
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

    /// 指纹覆盖统计（0.5.0 H6 可观测）：时间窗内 Detection 事件总数与携带
    /// JA3 指纹（tls_fp 非空）的条数——比率由展示层计算。
    pub fn detection_fingerprint_stats_since(&self, since: i64) -> Result<(i64, i64)> {
        let conn = self.lock()?;
        let total: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = 'detection' AND ts >= ?1",
                params![since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let with_fp: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = 'detection' AND ts >= ?1 AND tls_fp != ''",
                params![since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok((total, with_fp))
    }

    /// 全量口径（F795 补全）：部署至今的事件总数与独立来源数（任意 kind，
    /// remote_ip 非空）。与 24h 的 stats_since 是两个口径——仪表盘两类卡片
    /// 曾因共用同一 24h 查询而恒等（用户实测发现）。
    pub fn totals_all(&self) -> Result<(i64, i64)> {
        let conn = self.lock()?;
        let (total, unique) = conn
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT remote_ip) FROM events WHERE remote_ip <> ''",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok((total, unique))
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
            .prepare(&format!(
                "SELECT {EVENT_COLUMNS} FROM events WHERE kind = 'honeypot_hit' ORDER BY id DESC LIMIT ?1"
            ))
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit], event_row)
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// 修剪过期事件。删除会断链——只做整段修剪，并把断点行的 prev_hash 置空，
    /// 校验器把 prev_hash = '' 的行视为新链起点。
    /// 修剪超保留期事件（F795 方案 B）：删除前先把将删行整行 JSONL 追加到
    /// 归档文件（与 `export-events` 同格式，含哈希链字段，离线可自验段内链），
    /// 证据永续——DB 只保留热数据。`archive` 为 None = 不归档直接删。
    pub fn prune_events(&self, keep_days: u32, archive: Option<&std::path::Path>) -> Result<usize> {
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
        // 归档先于删除：追加整行 JSONL（含 prev_hash/hash，段内链可离线自验）
        if let Some(dir) = archive {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::Store(format!("创建归档目录失败: {e}")))?;
            let path = dir.join("events-archive.jsonl");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {EVENT_COLUMNS} FROM events WHERE id <= ?1 ORDER BY id"
                ))
                .map_err(|e| Error::Store(e.to_string()))?;
            let rows = stmt
                .query_map(params![boundary], event_row)
                .map_err(|e| Error::Store(e.to_string()))?;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| Error::Store(format!("打开归档文件失败: {e}")))?;
            for row in rows {
                let r = row.map_err(|e| Error::Store(e.to_string()))?;
                let line = serde_json::to_string(&r).map_err(|e| Error::Store(e.to_string()))?;
                f.write_all(line.as_bytes())
                    .and_then(|_| {
                        f.write_all(
                            b"
",
                        )
                    })
                    .map_err(|e| Error::Store(format!("写入归档失败: {e}")))?;
            }
        }
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
        if successor.is_some() {
            // 新链头 + 级联重链：后继行的 prev_hash 都指向被删行哈希，只重算
            // 新链头会让下一段断链——从 succ 起整段按新链重算（prev_hash='' 起，
            // 每行 hash = chain_hash(前一行新 hash, canonical)）。prune 低频，
            // O(n) 可接受。
            let mut stmt = conn
                .prepare(
                    "SELECT id, ts, kind, listener, remote_ip, remote_port, summary, payload, http_hint, tls_fp, tls_ja4, rule_id, interaction FROM events WHERE id > ?1 ORDER BY id",
                )
                .map_err(|e| Error::Store(e.to_string()))?;
            let rows: Vec<PruneRow> = stmt
                .query_map(params![boundary], |r| {
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
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| Error::Store(e.to_string()))?;
            drop(stmt);
            let mut prev = String::new();
            for (
                i,
                (
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
                ),
            ) in rows.into_iter().enumerate()
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
                let hash = chain_hash(&prev, &canonical);
                if i == 0 {
                    // 仅新链头置空 prev_hash（verify 的「链起点」信号）；
                    // 后继行保留原 prev_hash（verify 对非空行用前一行实际 hash 链接，
                    // 不比对存储值），只重算 hash。
                    conn.execute(
                        "UPDATE events SET prev_hash = '', hash = ?2 WHERE id = ?1",
                        params![id, hash],
                    )
                    .map_err(|e| Error::Store(e.to_string()))?;
                } else {
                    conn.execute(
                        "UPDATE events SET hash = ?2 WHERE id = ?1",
                        params![id, hash],
                    )
                    .map_err(|e| Error::Store(e.to_string()))?;
                }
                prev = hash;
            }
        }
        Ok(deleted as usize)
    }

    /// 离线校验哈希链。prev_hash 为空的行视为链起点（prune 造成的新链头）。
    pub fn verify_chain(&self) -> Result<ChainReport> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!("SELECT {EVENT_COLUMNS} FROM events ORDER BY id"))
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map([], event_row)
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
                &row.http_hint,
                &row.tls_fp,
                &row.tls_ja4,
                &row.rule_id,
                &row.interaction,
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

    /// 某来源 IP 的独立协同上报节点数（0.4.0 C3 quorum）：
    /// 事件 listener 形如 `fed:<节点>:<监听器>`，按节点去重。
    /// F200 组织印证本地复验：本节点近期是否观测过某来源（ip 维度查 remote_ip，
    /// fp 维度查 JA3/JA4 两列）。返回首条命中即 true。
    pub fn has_recent_observation(&self, dim: &str, value: &str, since: i64) -> Result<bool> {
        let sql = match dim {
            "fp" => {
                "SELECT EXISTS(SELECT 1 FROM events WHERE ts >= ?3 AND (tls_fp = ?1 OR tls_ja4 = ?1))"
            }
            _ => "SELECT EXISTS(SELECT 1 FROM events WHERE ts >= ?3 AND remote_ip = ?1)",
        };
        let hit: i64 = self
            .lock()?
            .query_row(sql, params![value, value, since], |r| r.get(0))
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(hit != 0)
    }

    // ---------- auto_apply 证据门控（F791 补全，2026-10-03 用户拍板） ----------
    /// 证据广度：该来源 IP 近窗口内的 (蜜罐总命中, 带载荷蜜罐命中, 快路径检测数)。
    /// auto_apply 的门控输入——带载荷 = 攻击者真发了数据（telnet 登录名塞二进制/
    /// HTTP 利用串），比裸端口探测强一档；分层语义见 engine 的 auto_apply_guard_ok。
    pub fn evidence_breadth(&self, remote_ip: &str, since_ts: i64) -> Result<(i64, i64, i64)> {
        self.lock()?
            .query_row(
                "SELECT
                   COALESCE(SUM(CASE WHEN kind = 'honeypot_hit' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN kind = 'honeypot_hit' AND payload != '' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN kind = 'detection'    THEN 1 ELSE 0 END), 0)
                 FROM events WHERE remote_ip = ?1 AND ts >= ?2 AND remote_ip != ''",
                params![remote_ip, since_ts],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// F400 事件补传（丢新留旧有界队列的取数侧）：id 升序取一段。
    pub fn events_since_asc(&self, after_id: i64, limit: u32) -> Result<Vec<EventRow>> {
        let conn = self.lock()?;
        let sql =
            format!("SELECT {EVENT_COLUMNS} FROM events WHERE id > ?1 ORDER BY id ASC LIMIT ?2");
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![after_id, limit], event_row)
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }
}
