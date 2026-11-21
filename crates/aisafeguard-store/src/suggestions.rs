//! suggestions 表（P1-4 自 lib.rs 拆出）：F760-B 系统自审建议（评审工单）。

use crate::{Store, SuggestionRow};
use aisafeguard_core::error::{Error, Result};
use rusqlite::params;

impl Store {
    // ---------- F760-B 系统自审建议（评审工单）----------

    /// 入库一条自审建议；fingerprint 去重（同主题重复评审不重复建行）。
    /// 返回是否新建（false = 已存在）。
    #[allow(clippy::too_many_arguments)] // 与 canonical_event 同款：字段并列比拆结构体直白
    pub fn insert_suggestion(
        &self,
        day: &str,
        fingerprint: &str,
        category: &str,
        priority: &str,
        title: &str,
        evidence: &str,
        action: &str,
        model: &str,
        impl_path: &str,
    ) -> Result<bool> {
        let n = self
            .lock()?
            .execute(
                "INSERT OR IGNORE INTO suggestions(created_ts, day, fingerprint, category, priority, title, evidence, action, model, impl_path) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![aisafeguard_core::now_ts(), day, fingerprint, category, priority, title, evidence, action, model, impl_path],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n == 1)
    }

    pub fn list_suggestions(&self, limit: u32) -> Result<Vec<SuggestionRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, created_ts, day, category, priority, title, evidence, action, model, status, impl_path, note, decided_ts, fingerprint FROM suggestions ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(SuggestionRow {
                    id: r.get(0)?,
                    created_ts: r.get(1)?,
                    day: r.get(2)?,
                    category: r.get(3)?,
                    priority: r.get(4)?,
                    title: r.get(5)?,
                    evidence: r.get(6)?,
                    action: r.get(7)?,
                    model: r.get(8)?,
                    status: r.get(9)?,
                    impl_path: r.get(10)?,
                    note: r.get(11)?,
                    decided_ts: r.get(12)?,
                    fingerprint: r.get(13)?,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))
    }

    /// 状态机：pending→adopted/rejected；adopted→completed。其余转换拒绝（返回 false）。
    /// note 记录决策去向/理由，decided_ts 记最后决策时间——进度留痕。
    pub fn set_suggestion_status(&self, id: i64, status: &str, note: &str) -> Result<bool> {
        let allowed_from = match status {
            "adopted" | "rejected" => vec!["pending"],
            "completed" => vec!["adopted"],
            _ => return Ok(false),
        };
        let marks = allowed_from
            .iter()
            .map(|f| format!("'{f}'"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "UPDATE suggestions SET status = ?1, note = ?2, decided_ts = ?3 WHERE id = ?4 AND status IN ({marks})"
        );
        let n = self
            .lock()?
            .execute(&sql, params![status, note, aisafeguard_core::now_ts(), id])
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n == 1)
    }

    /// AI 升级已有未决建议（key 引用命中）：只更新内容字段与模型署名，
    /// status/note（人类决策区）不动——升级不是决策。
    pub fn update_suggestion_content(
        &self,
        id: i64,
        priority: &str,
        evidence: &str,
        action: &str,
        model: &str,
    ) -> Result<bool> {
        let n = self
            .lock()?
            .execute(
                "UPDATE suggestions SET priority = ?1, evidence = ?2, action = ?3, model = ?4 WHERE id = ?5 AND status IN ('pending','adopted')",
                params![priority, evidence, action, model, id],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n == 1)
    }

    /// 人工修正建议内容（评审页展开编辑——评审者可能改写提案本体，如把
    /// 累进阶梯 1h→24h→7d→永久 改成 1h→24h→7d→31d→6month→1year）。
    /// 只允许未决/已采纳状态（终态是历史记录）；title 可改但 fingerprint
    /// 不动（去重锚保持原始主题）。
    pub fn edit_suggestion(
        &self,
        id: i64,
        title: &str,
        priority: &str,
        evidence: &str,
        action: &str,
    ) -> Result<bool> {
        let n = self
            .lock()?
            .execute(
                "UPDATE suggestions SET title = ?1, priority = ?2, evidence = ?3, action = ?4 WHERE id = ?5 AND status IN ('pending','adopted')",
                params![title, priority, evidence, action, id],
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n == 1)
    }
}
