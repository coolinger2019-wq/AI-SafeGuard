//! rules 表（P1-4 自 lib.rs 拆出）：防火墙规则、到期解封与灰度转正。

use crate::{RuleRow, Store};
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
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
        tag: &str,
        expires_ts: Option<i64>,
    ) -> Result<RuleRow> {
        let ts = aisafeguard_core::now_ts();
        self.lock()?
            .execute(
                "INSERT INTO rules (created_ts, name, direction, protocol, remote_ip, local_port, origin, enabled, note, tag, expires_ts, promoted)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, 0)",
                params![ts, name, direction, protocol, remote_ip, local_port, origin, note, tag, expires_ts],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let id = self
            .lock()?
            .query_row("SELECT id FROM rules WHERE name = ?1", params![name], |r| {
                r.get(0)
            })
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
            tag: tag.into(),
            expires_ts,
            promoted: false,
        })
    }

    pub fn list_rules(&self) -> Result<Vec<RuleRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, created_ts, name, direction, protocol, remote_ip, local_port, origin, enabled, note, tag, expires_ts, promoted
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
                    tag: r.get(10)?,
                    expires_ts: r.get(11)?,
                    promoted: r.get::<_, i64>(12)? != 0,
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

    /// 转正：延长规则 TTL（灰度 → 长期）并落转正标记（0.5.4 F3）。
    /// 只改记账，防火墙规则本体不动。
    pub fn mark_promoted(&self, id: i64, expires_ts: i64) -> Result<()> {
        self.lock()?
            .execute(
                "UPDATE rules SET expires_ts = ?2, promoted = 1 WHERE id = ?1",
                params![id, expires_ts],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    /// 该目标是否已有生效中的封禁规则（F795 去重补全，2026-10-10 数据分析驱动：
    /// 同一攻击者每轮被 AI 重复提名 → 重复应用 churn，实测单 IP 被应用 38 次）。
    /// 覆盖语义：规则为任意端口（覆盖建议的任何端口粒度）；规则为具体端口时
    /// 需与建议端口一致（全端口建议不被端口级规则覆盖——升级到更大范围仍放行）。
    pub fn active_rule_exists(&self, remote_ip: &str, local_port: Option<u16>) -> Result<bool> {
        let n: i64 = self
            .lock()?
            .query_row(
                "SELECT COUNT(*) FROM rules
                 WHERE enabled = 1 AND remote_ip = ?1 AND (local_port IS NULL OR local_port IS ?2)",
                params![remote_ip, local_port],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n > 0)
    }

    /// 近窗口内 origin=ai 的规则数——auto_apply 日限额的计数口径。含人工批准的
    /// AI 建议：限额约束的是 AI 规则的总 churn（人工批准也占额），不是某一类来源。
    pub fn ai_rules_since(&self, since_ts: i64) -> Result<i64> {
        let n: i64 = self
            .lock()?
            .query_row(
                "SELECT COUNT(*) FROM rules WHERE origin = 'ai' AND created_ts >= ?1",
                params![since_ts],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n)
    }
}
