//! intel 表（P1-4 自 lib.rs 拆出）：威胁情报订阅与源分级（F710）。

use crate::{IntelRow, Store};
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
    // ---------- 威胁情报 ----------
    /// upsert：同 value 更新来源/置信度/过期时间，first_seen 保留最初值
    /// F710 多源分级 upsert：第 7 元素 = 该条目是否来自允许自动封禁的源（特权）。
    /// 冲突优先级：特权条目覆盖一切，非特权条目只能覆盖非特权——换源不再同等信任。
    /// 返回实际写入行数（被优先级过滤掉的不计）。
    pub fn upsert_intel(
        &self,
        entries: &[(String, String, String, String, i64, i64, bool)],
    ) -> Result<usize> {
        let conn = self.lock()?;
        let mut n = 0;
        for (source, kind, value, confidence, first_seen, expires_ts, auto_block) in entries {
            let changed = conn
                .execute(
                    "INSERT INTO intel (source, kind, value, confidence, first_seen, expires_ts, auto_block)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(value) DO UPDATE SET
                       source = excluded.source, kind = excluded.kind,
                       confidence = excluded.confidence, expires_ts = excluded.expires_ts,
                       auto_block = excluded.auto_block
                     WHERE ?7 = 1 OR intel.auto_block = 0",
                    params![source, kind, value, confidence, first_seen, expires_ts, auto_block],
                )
                .map_err(|e| Error::Store(e.to_string()))?;
            n += changed;
        }
        Ok(n)
    }

    pub fn active_intel(&self, now: i64) -> Result<Vec<IntelRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT source, kind, value, confidence, first_seen, expires_ts
                 FROM intel WHERE expires_ts > ?1 ORDER BY confidence, value",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![now], |r| {
                Ok(IntelRow {
                    source: r.get(0)?,
                    kind: r.get(1)?,
                    value: r.get(2)?,
                    confidence: r.get(3)?,
                    first_seen: r.get(4)?,
                    expires_ts: r.get(5)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn prune_intel(&self, now: i64) -> Result<usize> {
        self.lock()?
            .execute("DELETE FROM intel WHERE expires_ts <= ?1", params![now])
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// 情报订阅反馈：当前在库（未过期）条目数。
    pub fn intel_count(&self, now: i64) -> Result<i64> {
        let conn = self.lock()?;
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM intel WHERE expires_ts > ?1",
                params![now],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n)
    }

    /// 该 IP 是否为「允许自动封禁的源」的在库情报条目（且未过期）——情报命中层。
    pub fn intel_auto_block_hit(&self, value: &str, now: i64) -> Result<bool> {
        let n: i64 = self
            .lock()?
            .query_row(
                "SELECT COUNT(*) FROM intel
                 WHERE value = ?1 AND auto_block = 1 AND expires_ts > ?2",
                params![value, now],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n > 0)
    }
}
