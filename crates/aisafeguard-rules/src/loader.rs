//! 规则包加载治理（F5）：整包拒绝、上限、sid 唯一、SHA-256 留痕。
//!
//! 治理纪律（子集规范冻结）：任何一条规则失败（语法错/越界关键字/重复 sid/
//! 白名单外 classtype）→ **整包拒绝**，不半生效；默认不内置任何规则包。

use std::path::Path;

use sha2::Digest as _;
use thiserror::Error;

use crate::ir::Rule;
use crate::parse::{RuleError, parse_rule};

/// 单个规则包文件上限（子集规范：≤ 5MB）。
pub const MAX_FILE_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct LoadError(pub String);

/// 加载完成的规则包。
#[derive(Debug, Clone)]
pub struct LoadedRuleset {
    pub rules: Vec<Rule>,
    /// 规则文件原始字节的 SHA-256（hex 小写）——加载事件留痕与可选钉扎比对
    pub sha256: String,
    pub rule_count: usize,
}

/// 从内存字节加载规则包（供文件入口与测试共用）。
pub fn load_package(raw: &[u8], max_rules: u32) -> Result<LoadedRuleset, LoadError> {
    if raw.len() > MAX_FILE_BYTES {
        return Err(LoadError(format!(
            "规则包 {} MB 超过 {} MB 上限",
            raw.len() / 1024 / 1024,
            MAX_FILE_BYTES / 1024 / 1024
        )));
    }
    let sha256 = {
        let digest = sha2::Sha256::digest(raw);
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    let text = String::from_utf8_lossy(raw);
    let mut rules: Vec<Rule> = Vec::new();
    let mut sids = std::collections::HashSet::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if rules.len() as u32 >= max_rules.max(1) {
            return Err(LoadError(format!(
                "规则数超过 max_rules={max_rules} 上限（第 {} 行起不再接受）",
                idx + 1
            )));
        }
        let rule = parse_rule(line)
            .map_err(|RuleError(m)| LoadError(format!("第 {} 行: {m}", idx + 1)))?;
        if !sids.insert(rule.sid) {
            return Err(LoadError(format!(
                "第 {} 行: sid {} 重复（重复 sid 整包拒绝）",
                idx + 1,
                rule.sid
            )));
        }
        rules.push(rule);
    }
    if rules.is_empty() {
        return Err(LoadError(
            "规则包内没有有效规则（检查路径与注释格式）".into(),
        ));
    }
    let rule_count = rules.len();
    Ok(LoadedRuleset {
        rules,
        sha256,
        rule_count,
    })
}

/// 从文件路径加载规则包。
pub fn load_package_file(path: &Path, max_rules: u32) -> Result<LoadedRuleset, LoadError> {
    let raw = std::fs::read(path).map_err(|e| LoadError(format!("读取规则包失败: {e}")))?;
    load_package(&raw, max_rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_RULES;

    fn assert_load_err(raw: &str, needle: &str) {
        let e = load_package(raw.as_bytes(), MAX_RULES).expect_err("应整包拒绝");
        assert!(
            e.to_string().contains(needle),
            "错误信息应含 `{needle}`：{e}"
        );
    }

    #[test]
    fn loads_valid_package() {
        let raw = "\
# 示例规则包
alert tcp $EXTERNAL_NET any -> $HOME_NET 8081 (msg:\"A\"; content:\"sqlmap\"; sid:1; rev:1;)
alert udp any any -> any 53 (msg:\"B\"; content:\"|00 01|\"; sid:2;)
";
        let rs = load_package(raw.as_bytes(), MAX_RULES).unwrap();
        assert_eq!(rs.rule_count, 2);
        assert_eq!(rs.rules[1].proto.name(), "udp");
        assert_eq!(rs.sha256.len(), 64);
        // 同输入同哈希
        let again = load_package(raw.as_bytes(), MAX_RULES).unwrap();
        assert_eq!(again.sha256, rs.sha256);
    }

    #[test]
    fn one_bad_rule_rejects_whole_package() {
        // 第 2 条越界：整包拒绝，第 1 条也不生效
        let raw = "\
alert tcp any any -> any any (msg:\"ok\"; content:\"x\"; sid:1;)
alert tcp any any -> any any (msg:\"bad\"; flowbits:set,x; content:\"x\"; sid:2;)
";
        assert_load_err(raw, "第 2 行");
        assert_load_err(raw, "不支持的关键字");
    }

    #[test]
    fn duplicate_sid_rejects_package() {
        let raw = "\
alert tcp any any -> any any (msg:\"a\"; content:\"x\"; sid:1;)
alert tcp any any -> any any (msg:\"b\"; content:\"y\"; sid:1;)
";
        assert_load_err(raw, "sid 1 重复");
    }

    #[test]
    fn empty_package_rejected() {
        assert_load_err("# 只有注释\n\n", "没有有效规则");
    }

    #[test]
    fn max_rules_enforced() {
        let mut raw = String::new();
        for i in 1..=5 {
            raw.push_str(&format!(
                "alert tcp any any -> any any (msg:\"r{i}\"; content:\"x\"; sid:{i};)\n"
            ));
        }
        let rs = load_package(raw.as_bytes(), 5).unwrap();
        assert_eq!(rs.rule_count, 5);
        let e = load_package(raw.as_bytes(), 4).expect_err("应拒绝");
        assert!(e.to_string().contains("max_rules=4"), "{e}");
    }

    #[test]
    fn file_too_large_rejected() {
        // 6MB 的合法规则行，超过 5MB 文件上限
        let line = "alert tcp any any -> any any (msg:\"t\"; content:\"x\"; sid:1;)\n";
        let raw = line.repeat(120_000);
        assert!(raw.len() > 5 * 1024 * 1024);
        let e = load_package(raw.as_bytes(), MAX_RULES).expect_err("应拒绝");
        assert!(e.to_string().contains("上限"), "{e}");
    }

    #[test]
    fn load_package_file_reports_io_error() {
        let e = load_package_file(Path::new("Z:/definitely/not/here.rules"), MAX_RULES)
            .expect_err("应失败");
        assert!(e.to_string().contains("读取规则包失败"));
    }
}
