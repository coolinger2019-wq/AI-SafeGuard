//! fed_members + org_events 表域（P1-4 自 lib.rs 拆出）：组织协同成员账与组织事件账本。

use crate::{OrgEventRow, OrgMetrics, Store};
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
    // ---------- F300 组织事件账本 ----------

    pub fn insert_org_event(
        &self,
        ts: i64,
        kind: &str,
        dim: &str,
        key: &str,
        nodes_count: i64,
        detail: &str,
    ) -> Result<i64> {
        self.lock()?
            .execute(
                "INSERT INTO org_events (ts, kind, dim, key, nodes_count, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![ts, kind, dim, key, nodes_count, detail],
            )
            .map(|id| id as i64)
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn recent_org_events(&self, limit: u32) -> Result<Vec<OrgEventRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, ts, kind, dim, key, nodes_count, detail FROM org_events ORDER BY id DESC LIMIT ?1")
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(OrgEventRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    kind: r.get(2)?,
                    dim: r.get(3)?,
                    key: r.get(4)?,
                    nodes_count: r.get(5)?,
                    detail: r.get(6)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(rows)
    }

    /// 某来源键的组织误报标记条数（/api/rules 组织提示用）。
    pub fn org_flag_count(&self, key: &str) -> i64 {
        match self.lock().ok().and_then(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM org_events WHERE kind = 'fp-flag' AND key = ?1",
                params![key],
                |r| r.get::<_, i64>(0),
            )
            .ok()
        }) {
            Some(n) => n,
            None => {
                tracing::warn!("org_flag_count 查询失败（锁中毒/DB 错误），按 0 降级: key={key}");
                0
            }
        }
    }

    /// F300 价值指标：组织建议（proposals model LIKE 'fed:%'）+ 印证命中。
    pub fn org_metrics_since(&self, since: i64) -> Result<OrgMetrics> {
        let conn = self.lock()?;
        let (received, applied, dismissed) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(status = 'applied'), 0), COALESCE(SUM(status = 'dismissed'), 0)
                 FROM proposals WHERE model LIKE 'fed:%' AND created_ts >= ?1",
                params![since],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let (corr_received, corr_hit) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(detail = 'hit'), 0) FROM org_events
                 WHERE kind = 'corroboration' AND ts >= ?1",
                params![since],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(OrgMetrics {
            suggestions_received: received,
            suggestions_applied: applied,
            suggestions_dismissed: dismissed,
            corroborations_received: corr_received,
            corroborations_hit: corr_hit,
        })
    }

    // ---------- 组织协同 ----------
    /// 成员注册/心跳：node ↔ 证书指纹首次绑定（TOFU），之后每次上报校验指纹一致。
    pub fn upsert_fed_member(&self, node: &str, ts: i64, cert_fp: &str) -> Result<bool> {
        let conn = self.lock()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT cert_fp FROM fed_members WHERE node = ?1",
                params![node],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        match existing {
            // 已注册：指纹必须一致（证书被盗用冒充其他节点在此被拒）
            Some(fp) if fp == cert_fp => {
                conn.execute(
                    "UPDATE fed_members SET last_seen = ?2 WHERE node = ?1",
                    params![node, ts],
                )
                .map_err(|e| Error::Store(e.to_string()))?;
                Ok(true)
            }
            Some(_) => Ok(false),
            // 首次登记
            None => {
                conn.execute(
                    "INSERT INTO fed_members (node, last_seen, cert_fp) VALUES (?1, ?2, ?3)",
                    params![node, ts, cert_fp],
                )
                .map_err(|e| Error::Store(e.to_string()))?;
                Ok(true)
            }
        }
    }

    /// F100 序列号门：seq 大于该节点已见高水位则推进水位并放行（true）；
    /// 否则判回退拒收（false）——合法重复由调用侧 seen 集合先行拦截，到这里
    /// 还撞低水位的只剩备份恢复/伪造重放。
    pub fn check_fed_seq(&self, node: &str, seq: u64) -> Result<bool> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "UPDATE fed_members SET max_seq = ?2 WHERE node = ?1 AND max_seq < ?2",
                params![node, seq as i64],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        if n == 1 {
            return Ok(true);
        }
        let max: Option<i64> = conn
            .query_row(
                "SELECT max_seq FROM fed_members WHERE node = ?1",
                params![node],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(matches!(max, Some(m) if m < seq as i64))
    }

    /// F400 软隔离状态切换（active | quarantined）。返回 false = 成员不存在。
    pub fn set_fed_member_status(&self, node: &str, status: &str) -> Result<bool> {
        let n = self
            .lock()?
            .execute(
                "UPDATE fed_members SET status = ?2 WHERE node = ?1",
                params![node, status],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n > 0)
    }

    pub fn fed_member_status(&self, node: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        let v: Option<String> = conn
            .query_row(
                "SELECT status FROM fed_members WHERE node = ?1",
                params![node],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(v)
    }

    pub fn list_fed_members(&self) -> Result<Vec<(String, String, i64, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            // 按节点名稳定排序：last_seen 排序会因心跳交替导致面板行跳动
            .prepare("SELECT node, cert_fp, last_seen, status FROM fed_members ORDER BY node")
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }
}
