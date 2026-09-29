//! 封禁规则的可解释投影（0.5.4 Batch 1，F1–F3/F5）：
//! 存储行（RuleRow）→ 展示模型（谁封的、为啥、多久）。GUI 与 `/api/rules`
//! 共用同一投影，保证两条通道的文案一致。

use aisafeguard_store::RuleRow;
use serde::{Deserialize, Serialize};

const MAX_SUMMARY: usize = 80;

/// 规则展示模型：防火墙页与 /api/rules 的统一出口。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExplain {
    pub id: i64,
    pub created_ts: i64,
    pub name: String,
    pub direction: String,
    pub protocol: String,
    pub remote_ip: String,
    pub local_port: Option<u16>,
    pub origin: String,
    pub enabled: bool,
    pub tag: String,
    pub expires_ts: Option<i64>,
    /// 来源（F5）：手动 / 检测引擎 / AI / 情报；未识别给「未知」（旧数据默认文案）
    pub source: String,
    /// TTL 状态（F3）：trial / promoted / engine / manual
    pub ttl_state: String,
    /// TTL 固定文案（F3）：试封中 / 已转正 / 自动封禁 / 手动，带剩余时间
    pub ttl_text: String,
    /// 原因摘要（F2）：按来源模板生成一句话，清洗 + 截断，
    /// 绝不把原始不可信 payload 整段塞进标题
    pub reason_summary: String,
}

impl RuleExplain {
    pub fn of_list(rows: Vec<RuleRow>) -> Vec<Self> {
        rows.into_iter().map(Self::of).collect()
    }

    pub fn of(row: RuleRow) -> Self {
        let source = source_label(&row.origin);
        let ttl_state = ttl_state(&row);
        let ttl_text = ttl_text(ttl_state, row.expires_ts);
        let reason_summary = reason_summary(&row.origin, &row.note);
        Self {
            id: row.id,
            created_ts: row.created_ts,
            name: row.name,
            direction: row.direction,
            protocol: row.protocol,
            remote_ip: row.remote_ip,
            local_port: row.local_port,
            origin: row.origin,
            enabled: row.enabled,
            tag: row.tag,
            expires_ts: row.expires_ts,
            source: source.to_string(),
            ttl_state: ttl_state.to_string(),
            ttl_text,
            reason_summary,
        }
    }
}

/// 来源列可读（F5）。0.6 多机协同将新增「组织」来源，本版仅预留文案位。
fn source_label(origin: &str) -> &'static str {
    match origin {
        "manual" => "手动",
        "engine" => "检测引擎",
        "ai" => "AI",
        "intel" => "情报",
        "org" => "组织",
        _ => "未知",
    }
}

fn ttl_state(row: &RuleRow) -> &'static str {
    match row.expires_ts {
        None => "manual",
        Some(_) if row.promoted => "promoted",
        Some(_) => match row.origin.as_str() {
            "ai" => "trial",
            "engine" | "intel" => "engine",
            _ => "manual",
        },
    }
}

fn ttl_text(state: &str, expires_ts: Option<i64>) -> String {
    match state {
        "manual" => "手动添加 · 长期有效".into(),
        _ => {
            let Some(exp) = expires_ts else {
                return "到期自动解封".into();
            };
            let remain = exp - aisafeguard_core::now_ts();
            if remain <= 0 {
                return "已到期 · 等待自动解封".into();
            }
            let prefix = match state {
                "trial" => "试封中",
                "promoted" => "已转正",
                _ => "自动封禁",
            };
            format!("{prefix} · 剩余 {}（到期自动解封）", humanize_secs(remain))
        }
    }
}

fn humanize_secs(secs: i64) -> String {
    match secs {
        s if s < 90 => format!("{s} 秒"),
        m if m < 5400 => format!("{} 分钟", (m + 30) / 60),
        h if h < 129_600 => format!("{} 小时", (h + 1800) / 3600),
        d => format!("{} 天", (d + 43_200) / 86_400),
    }
}

/// 原因摘要（F2）：按来源模板生成一句话。蜜罐命中 / 端口扫描 / SYN flood /
/// 规则 sid 等都在引擎证据文案里；AI 建议取 reason；情报取来源说明。
fn reason_summary(origin: &str, note: &str) -> String {
    let cleaned = clean(note);
    match origin {
        // 引擎规则 note = "检测器自动封禁（TTL {n}s）: {evidence}"，取证据段
        "engine" => match cleaned.split_once(": ") {
            Some((_, evidence)) if !evidence.is_empty() => format!("检测判定：{evidence}"),
            _ => fallback(&cleaned),
        },
        // AI 规则 note = "AI 建议 #{id}: {reason}"
        "ai" => match cleaned.split_once(": ") {
            Some((_, reason)) if !reason.is_empty() => format!("AI 建议：{reason}"),
            _ => fallback(&cleaned),
        },
        "intel" => format!("情报命中：{cleaned}"),
        "manual" => fallback(&cleaned),
        _ => fallback(&cleaned),
    }
}

/// 未知来源或空备注的默认文案（F1：旧规则无字段时给「来源未知 / 长期」）
fn fallback(cleaned: &str) -> String {
    if cleaned.is_empty() {
        "来源未知 / 长期".into()
    } else {
        cleaned.to_string()
    }
}

/// 不可信输入清洗：去控制字符（C0/C1/DEL）+ 截断
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_SUMMARY)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(origin: &str, note: &str, expires_ts: Option<i64>, promoted: bool) -> RuleRow {
        RuleRow {
            id: 1,
            created_ts: 0,
            name: "aisafeguard-blk-test".into(),
            direction: "in".into(),
            protocol: "any".into(),
            remote_ip: "203.0.113.7".into(),
            local_port: None,
            origin: origin.into(),
            enabled: true,
            note: note.into(),
            tag: String::new(),
            expires_ts,
            promoted,
        }
    }

    #[test]
    fn ttl_states_match_origin_and_promotion() {
        // 手动（无 TTL）
        assert_eq!(ttl_state(&row("manual", "n", None, false)), "manual");
        // AI 灰度（带 TTL 未转正）
        assert_eq!(
            ttl_state(&row(
                "ai",
                "n",
                Some(aisafeguard_core::now_ts() + 600),
                false
            )),
            "trial"
        );
        // AI 已转正
        assert_eq!(
            ttl_state(&row(
                "ai",
                "n",
                Some(aisafeguard_core::now_ts() + 600),
                true
            )),
            "promoted"
        );
        // 引擎 / 情报自动封禁
        assert_eq!(ttl_state(&row("engine", "n", Some(0), false)), "engine");
        assert_eq!(ttl_state(&row("intel", "n", Some(0), false)), "engine");
    }

    #[test]
    fn ttl_text_fixed_wording() {
        assert_eq!(ttl_text("manual", None), "手动添加 · 长期有效");
        let t = ttl_text("trial", Some(aisafeguard_core::now_ts() + 600));
        assert!(t.starts_with("试封中 · 剩余 "), "实际: {t}");
        assert!(t.contains("到期自动解封"));
        let p = ttl_text("promoted", Some(aisafeguard_core::now_ts() + 86_400 * 28));
        assert!(p.starts_with("已转正 · 剩余 "), "实际: {p}");
        assert!(ttl_text("engine", Some(0)).contains("已到期"));
    }

    #[test]
    fn reason_summary_templates_per_origin() {
        assert_eq!(
            reason_summary(
                "engine",
                "检测器自动封禁（TTL 1800s）: 60 秒内对 3 个不同目标端口发送 SYN"
            ),
            "检测判定：60 秒内对 3 个不同目标端口发送 SYN"
        );
        assert_eq!(
            reason_summary("ai", "AI 建议 #3: 该 IP 频繁触碰蜜罐"),
            "AI 建议：该 IP 频繁触碰蜜罐"
        );
        assert!(
            reason_summary("intel", "威胁情报自动封禁（feodo_c2 / TTL 3 天）")
                .starts_with("情报命中：")
        );
        assert_eq!(reason_summary("manual", "手工拉黑"), "手工拉黑");
        // 未知来源默认文案
        assert_eq!(reason_summary("legacy", ""), "来源未知 / 长期");
    }

    #[test]
    fn reason_summary_never_carries_control_chars_or_overlong() {
        let dirty = "扫描\u{1}\u{7f}器\u{0}payload".repeat(20);
        let s = reason_summary("manual", &dirty);
        assert!(!s.chars().any(|c| c.is_control()), "控制字符必须被清洗");
        assert!(s.chars().count() <= MAX_SUMMARY);
    }
}
