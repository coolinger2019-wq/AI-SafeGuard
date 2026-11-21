//! meta 表（P1-4 自 lib.rs 拆出）：跨域共用的小状态 KV（fed 序列号游标等）。

use crate::Store;
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
    /// meta 表通用读（fed 序列号游标等进程间持久化小状态）。
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        let v: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(v)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.lock()?
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
                params![key, value],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }
}
