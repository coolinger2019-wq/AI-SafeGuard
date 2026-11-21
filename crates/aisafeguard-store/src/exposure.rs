//! exposure 表（P1-4 自 lib.rs 拆出）：暴露面快照，只保留最近 10 份。

use crate::Store;
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
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
}
