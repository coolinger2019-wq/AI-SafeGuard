#![forbid(unsafe_code)]

//! Suricata/ET 风格规则子集引擎（0.5.0 Batch F，规范见 docs/RULESET_SUBSET.md v1）。
//!
//! 职责单一：规则文本 → IR（[`parse`]）→ 整包加载治理（[`loader`]）→ 匹配（[`matcher`]）。
//! 只产判定、不执行——本 crate **禁止依赖 aisafeguard-firewall**（crate 依赖图强制，
//! 规则命中是否封禁由上层 `handle_detection` 出口与 `[detect.rules].auto_block` 决定）。
//!
//! 纪律：任何一条越界（超集关键字/动作/修饰符、白名单外 classtype、重复 sid、
//! 超上限）→ **整包拒绝**，不半生效；pcre 用 rust regex（线性时间）编译执行，
//! 编译失败即拒绝该包，不存在回溯超时问题。

pub mod ir;
pub mod loader;
pub mod parse;

pub use ir::Rule;
pub use loader::load_package;
pub use parse::{RuleError, parse_rule};

/// 规则包允许的最大规则条数（子集规范 F5：max_rules 默认 5000）。
pub const MAX_RULES: u32 = 5000;

/// classtype → severity 映射（子集规范冻结表）。白名单外 → None → 整包拒绝。
/// 白名单共 10 类：前 9 类按表定级，第 10 类 attempted-recon 归入「其余 → low」。
pub fn severity_for_classtype(ct: &str) -> Option<&'static str> {
    match ct {
        "attempted-admin" | "web-application-attack" | "attempted-user" => Some("critical"),
        "malware-cnc" | "trojan-activity" | "policy-violation" => Some("high"),
        "scan" | "attempted-dos" | "bad-unknown" => Some("medium"),
        "attempted-recon" => Some("low"),
        _ => None,
    }
}
