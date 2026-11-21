//! proposals 表（P1-4 自 lib.rs 拆出）：AI 建议生命周期（状态机/清扫/抽样）。

use crate::{ProposalRow, Store};
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
    // ---------- AI 建议 ----------

    pub fn pending_proposal_exists(
        &self,
        remote_ip: &str,
        local_port: Option<u16>,
    ) -> Result<bool> {
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
    #[allow(clippy::too_many_arguments)]
    pub fn insert_proposal(
        &self,
        model: &str,
        action: &str,
        severity: &str,
        direction: &str,
        protocol: &str,
        remote_ip: &str,
        local_port: Option<u16>,
        ttl_secs: Option<u64>,
        reason: &str,
        analysis: &str,
        rule_name: &str,
        tune_param: &str,
        tune_value: &str,
    ) -> Result<i64> {
        // 同一锁作用域内 INSERT + 取 rowid——两锁间隙他人插入会拿到别人的 id
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO proposals (created_ts, model, action, severity, direction, protocol, remote_ip, local_port, ttl_secs, reason, status, analysis, rule_name, tune_param, tune_value)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11, ?12, ?13, ?14)",
            params![
                aisafeguard_core::now_ts(),
                model,
                action,
                severity,
                direction,
                protocol,
                remote_ip,
                local_port,
                ttl_secs.map(|t| t as i64),
                reason,
                analysis,
                rule_name,
                tune_param,
                tune_value
            ],
        )
        .map_err(|e| Error::Store(e.to_string()))?;
        conn.query_row("SELECT last_insert_rowid()", [], |r| r.get(0))
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// 建议状态原子迁移（F795 C2）：`UPDATE ... WHERE status = from` 的 rows==1
    /// 才算认领成功——Web/API/自动应用三通道并发时不会双应用双封禁。
    pub fn set_proposal_status_if(
        &self,
        id: i64,
        from: &str,
        to: &str,
        applied_rule_id: Option<i64>,
    ) -> Result<bool> {
        let n = self.lock()?
            .execute(
                "UPDATE proposals SET status = ?2, applied_rule_id = ?3 WHERE id = ?1 AND status = ?4",
                params![id, to, applied_rule_id, from],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n == 1)
    }

    /// 启动清扫（审计 run-1 F2）：进程崩溃可能把建议遗留在 applying——
    /// 认领是进程内语义，重启后无人持有；启动时全部退回 pending。
    pub fn sweep_stuck_applying(&self) -> Result<usize> {
        let n = self
            .lock()?
            .execute(
                "UPDATE proposals SET status = 'pending' WHERE status = 'applying'",
                [],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        if n > 0 {
            tracing::info!("启动清扫：{n} 条建议从 applying 退回 pending");
        }
        Ok(n)
    }

    pub fn list_proposals(&self, status: Option<&str>, limit: u32) -> Result<Vec<ProposalRow>> {
        let conn = self.lock()?;
        let sql = match status {
            Some(_) => {
                "SELECT id, created_ts, model, action, severity, direction, protocol, remote_ip, local_port, reason, status, applied_rule_id, analysis, ttl_secs, rule_name, tune_param, tune_value
                 FROM proposals WHERE status = ?1 ORDER BY id DESC LIMIT ?2"
            }
            None => {
                "SELECT id, created_ts, model, action, severity, direction, protocol, remote_ip, local_port, reason, status, applied_rule_id, analysis, ttl_secs, rule_name, tune_param, tune_value
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
                    action: r.get(3)?,
                    severity: r.get(4)?,
                    direction: r.get(5)?,
                    protocol: r.get(6)?,
                    remote_ip: r.get(7)?,
                    local_port: r.get(8)?,
                    reason: r.get(9)?,
                    status: r.get(10)?,
                    applied_rule_id: r.get(11)?,
                    analysis: r.get(12)?,
                    ttl_secs: r.get(13)?,
                    rule_name: r.get(14)?,
                    tune_param: r.get(15)?,
                    tune_value: r.get(16)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    pub fn get_proposal(&self, id: i64) -> Result<Option<ProposalRow>> {
        // 直查：list_proposals(None, 1000) 只回最新 1000 条，老建议会「凭空消失」
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, created_ts, model, severity, action, direction, protocol, remote_ip, local_port, reason, status, applied_rule_id, analysis, ttl_secs, rule_name, tune_param, tune_value
                 FROM proposals WHERE id = ?1",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let mut rows = stmt
            .query_map(params![id], |r| {
                Ok(ProposalRow {
                    id: r.get(0)?,
                    created_ts: r.get(1)?,
                    model: r.get(2)?,
                    severity: r.get(3)?,
                    action: r.get(4)?,
                    direction: r.get(5)?,
                    protocol: r.get(6)?,
                    remote_ip: r.get(7)?,
                    local_port: r.get(8)?,
                    reason: r.get(9)?,
                    status: r.get(10)?,
                    applied_rule_id: r.get(11)?,
                    analysis: r.get(12)?,
                    ttl_secs: r.get(13)?,
                    rule_name: r.get(14)?,
                    tune_param: r.get(15)?,
                    tune_value: r.get(16)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        match rows.next() {
            Some(row) => row.map(Some).map_err(|e| Error::Store(e.to_string())),
            None => Ok(None),
        }
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

    pub fn set_proposal_status(
        &self,
        id: i64,
        status: &str,
        applied_rule_id: Option<i64>,
    ) -> Result<()> {
        self.lock()?
            .execute(
                "UPDATE proposals SET status = ?2, applied_rule_id = ?3 WHERE id = ?1",
                params![id, status, applied_rule_id],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    /// F804：超期未决提案自动归档转 dismissed（带事件留痕由调用方发布）。
    pub fn sweep_expired_pending(&self, older_than_secs: i64) -> Result<usize> {
        let cutoff = aisafeguard_core::now_ts() - older_than_secs;
        let n = self
            .lock()?
            .execute(
                "UPDATE proposals SET status = 'dismissed' WHERE status = 'pending' AND created_ts < ?1",
                params![cutoff],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n)
    }

    /// F804：近 since 秒已应用提案随机抽样 n 条（每日评审桥复核用）。
    pub fn sample_recent_applied(&self, n: u32, since: i64) -> Result<Vec<ProposalRow>> {
        let now = aisafeguard_core::now_ts();
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, created_ts, model, action, severity, direction, protocol, remote_ip, local_port, reason, status, applied_rule_id, analysis, ttl_secs, rule_name, tune_param, tune_value
                 FROM proposals WHERE status = 'applied' AND created_ts >= ?1 ORDER BY RANDOM() LIMIT ?2",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![now - since, n], |r| {
                Ok(ProposalRow {
                    id: r.get(0)?,
                    created_ts: r.get(1)?,
                    model: r.get(2)?,
                    action: r.get(3)?,
                    severity: r.get(4)?,
                    direction: r.get(5)?,
                    protocol: r.get(6)?,
                    remote_ip: r.get(7)?,
                    local_port: r.get(8)?,
                    reason: r.get(9)?,
                    status: r.get(10)?,
                    applied_rule_id: r.get(11)?,
                    analysis: r.get(12)?,
                    ttl_secs: r.get(13)?,
                    rule_name: r.get(14)?,
                    tune_param: r.get(15)?,
                    tune_value: r.get(16)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(rows)
    }

    /// 误报标记：把该来源的全部 pending 建议一并收弃（用户已判定其为正常）。
    /// 返回收弃条数。
    pub fn dismiss_pending_proposals_for_ip(&self, remote_ip: &str) -> Result<i64> {
        let n = self
            .lock()?
            .execute(
                "UPDATE proposals SET status = 'dismissed'
                 WHERE status = 'pending' AND remote_ip = ?1 AND remote_ip != ''",
                params![remote_ip],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n as i64)
    }
}
