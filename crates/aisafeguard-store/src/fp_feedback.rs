//! fp_feedback 表（P1-4 自 lib.rs 拆出）：误报反馈（AI 深度介入 v1）。

use crate::{FpRow, Store};
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
    // ---------- 误报反馈 ----------

    /// 记录一次误报标记（同来源聚合：count+1、last_ts/note 刷新为最新）。
    /// 误报标记：value=来源 IP；local_port=None 表示按 IP 整体抑制，
    /// Some(port) 表示仅抑制该端口的处置（0.4.0 B4）。
    pub fn insert_fp_feedback(
        &self,
        value: &str,
        ts: i64,
        note: &str,
        local_port: Option<u16>,
    ) -> Result<()> {
        // 最后一次标记决定粒度（IP 级 / 端口级）：行以 value 为主键
        self.lock()?
            .execute(
                "INSERT INTO fp_feedback (value, count, first_ts, last_ts, note, local_port)
                 VALUES (?1, 1, ?2, ?2, ?3, ?4)
                 ON CONFLICT(value) DO UPDATE SET count = count + 1, last_ts = excluded.last_ts, note = excluded.note, local_port = excluded.local_port",
                params![value, ts, note, local_port],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    /// 该来源是否处于误报抑制期（0.4.0 B4 端口粒度）：
    /// 记录 local_port=NULL = 按 IP 整体抑制（对任何处置生效）；
    /// 记录 Some(port) = 仅对处置端口相同的动作抑制（action_port=None 的
    /// 来源级检测不被端口级记录抑制）。
    pub fn active_fp(
        &self,
        value: &str,
        now: i64,
        suppress_ttl_secs: i64,
        action_port: Option<u16>,
    ) -> Result<bool> {
        let n: i64 = self
            .lock()?
            .query_row(
                "SELECT COUNT(*) FROM fp_feedback
                 WHERE value = ?1 AND last_ts + ?2 > ?3 AND (local_port IS NULL OR local_port IS ?4)",
                params![value, suppress_ttl_secs, now, action_port],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n > 0)
    }

    /// 清除某来源的误报抑制记录（0.4.0 B3）：删除后该来源恢复自动封禁资格。
    /// 返回删除的行数（0 = 本来就没有抑制记录）。
    pub fn clear_fp_feedback(&self, value: &str) -> Result<usize> {
        let conn = self.lock()?;
        let n = conn
            .execute("DELETE FROM fp_feedback WHERE value = ?1", params![value])
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n)
    }

    pub fn list_active_feedback(
        &self,
        now: i64,
        suppress_ttl_secs: i64,
        limit: u32,
    ) -> Result<Vec<FpRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT value, count, first_ts, last_ts, note, local_port FROM fp_feedback
                 WHERE last_ts + ?2 > ?1 ORDER BY last_ts DESC LIMIT ?3",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![now, suppress_ttl_secs, limit], |r| {
                Ok(FpRow {
                    value: r.get(0)?,
                    count: r.get(1)?,
                    first_ts: r.get(2)?,
                    last_ts: r.get(3)?,
                    note: r.get(4)?,
                    local_port: r.get(5)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// F804：该源是否有历史误报反馈（有 → 自动应用永久降级为 pending，
    /// 纠错信号传导；人工应用不受影响）。
    pub fn fp_history_exists(&self, remote_ip: &str) -> Result<bool> {
        self.lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM fp_feedback WHERE value = ?1)",
                params![remote_ip],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v == 1)
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// F300 误报回流扫描：since 以来有更新的本地误报标记。
    pub fn recent_fp(&self, since: i64) -> Result<Vec<(String, i64, i64)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT value, count, last_ts FROM fp_feedback WHERE last_ts >= ?1 ORDER BY last_ts")
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![since], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(rows)
    }
}
