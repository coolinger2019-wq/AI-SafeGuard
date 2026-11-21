//! ai_runs 表（P1-4 自 lib.rs 拆出）：AI 调用审计。

use crate::{AiRunRow, Store};
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
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
