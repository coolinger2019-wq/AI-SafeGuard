#![forbid(unsafe_code)]

//! 威胁情报管道 v1（0.3，设计见 docs/NGFW_EVOLUTION.md §2.5）。
//! 源：abuse.ch Feodo Tracker（C2 IP，高置信度，可自动封禁）+ 本地蜜罐源（仅标注）。
//! 治理：TTL 过期、单源一键禁用（关闭 intel.enabled 即停）、内网保护全局生效。

use aisafeguard_core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const FEODO_C2_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelEntry {
    pub source: String,
    /// c2 | malware_distro | scan_source
    pub kind: String,
    pub value: String,
    /// high（可自动封禁）| local | fed（仅标注）
    pub confidence: String,
    pub first_seen: i64,
    pub expires_ts: i64,
}

/// 解析 Feodo Tracker ipblocklist.txt：`#` 注释行跳过，每行一个 IP
pub fn parse_feodo_ipblocklist(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().next().unwrap_or(l).to_string())
        .collect()
}

pub async fn fetch_blocklist(http: &reqwest::Client, url: &str) -> Result<Vec<String>> {
    let resp = http
        .get(url)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| Error::Ai(format!("拉取情报失败: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Ai(format!("情报源返回 HTTP {}", resp.status())));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| Error::Ai(format!("读取情报失败: {e}")))?;
    Ok(parse_feodo_ipblocklist(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feodo_skips_comments_and_extracts_ips() {
        let sample = "# Feodo Tracker recommended blocklist
# Generated: 2026-09-28
185.234.219.13
45.133.1.35 test

# eof
";
        let ips = parse_feodo_ipblocklist(sample);
        assert_eq!(ips, vec!["185.234.219.13", "45.133.1.35"]);
    }

    #[test]
    fn parse_feodo_tolerates_garbage() {
        assert!(parse_feodo_ipblocklist("").is_empty());
        assert!(parse_feodo_ipblocklist("# only comments

").is_empty());
    }
}
