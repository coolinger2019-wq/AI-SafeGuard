//! source_recidivism 表（P1-4 自 lib.rs 拆出）：F805 累进阶梯封禁计数。

use crate::Store;
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
    /// F805 累进阶梯：自动封禁时累加该源的历史封禁次数，返回新次数（第 N 犯）。
    /// 误报反馈（mark_false_positive）会清零——被判定误报的源不该继续受罚。
    /// RETURNING 单语句原子自增（审查修正：execute+SELECT 两段在并发下可跳档）。
    pub fn bump_ban_count(&self, remote_ip: &str, now: i64) -> Result<i64> {
        self.lock()?
            .query_row(
                "INSERT INTO source_recidivism (remote_ip, ban_count, last_ban_ts) VALUES (?1, 1, ?2)
                 ON CONFLICT(remote_ip) DO UPDATE SET ban_count = ban_count + 1, last_ban_ts = ?2
                 RETURNING ban_count",
                params![remote_ip, now],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// F805：该源当前的历史封禁次数（0 = 初犯）——阶梯选档用，不改动计数。
    pub fn peek_ban_count(&self, remote_ip: &str) -> Result<i64> {
        self.lock()?
            .query_row(
                "SELECT ban_count FROM source_recidivism WHERE remote_ip = ?1",
                params![remote_ip],
                |r| r.get(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(0),
                e => Err(Error::Store(e.to_string())),
            })
    }

    /// F805：误报反馈后重置累进计数。
    pub fn reset_recidivism(&self, remote_ip: &str) -> Result<()> {
        self.lock()?
            .execute(
                "DELETE FROM source_recidivism WHERE remote_ip = ?1",
                params![remote_ip],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }
}
