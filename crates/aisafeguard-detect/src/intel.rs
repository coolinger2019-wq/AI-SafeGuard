#![forbid(unsafe_code)]

//! 威胁情报管道 v1（0.3，设计见 docs/NGFW_EVOLUTION.md §2.5）。
//! 源：abuse.ch Feodo Tracker（C2 IP，高置信度，可自动封禁）+ 本地蜜罐源（仅标注）。
//! 治理：TTL 过期、单源一键禁用（关闭 intel.enabled 即停）、内网保护全局生效。

use aisafeguard_core::error::{Error, Result};
use std::time::Duration;

pub const FEODO_C2_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";

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

/// F720 CrowdSec security-blocklist 解析结果：
/// singles = 单 IP（可入库）；ranges = CIDR 网段（一期丢弃，计数是 F770 决策依据）；
/// malformed = 既不是 IP 也不是网段的行（并入丢弃口径）。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ParsedBlocklist {
    pub singles: Vec<String>,
    pub ranges: Vec<String>,
    pub malformed: usize,
}

/// 解析 CrowdSec security-blocklist 文本：每行一个 IP 或 CIDR 网段，
/// `#` 注释与空行跳过（官方格式）。
pub fn parse_crowdsec_blocklist(text: &str) -> ParsedBlocklist {
    let mut out = ParsedBlocklist::default();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.contains('/') {
            // 网段：格式合法才计入 ranges（否则按畸形丢弃口径）
            let ok = l
                .split_once('/')
                .and_then(|(ip, prefix)| {
                    ip.parse::<std::net::IpAddr>().ok().zip(prefix.parse::<u8>().ok())
                })
                .is_some();
            if ok {
                out.ranges.push(l.to_string());
            } else {
                out.malformed += 1;
            }
            continue;
        }
        match l.parse::<std::net::IpAddr>() {
            Ok(_) => out.singles.push(l.to_string()),
            Err(_) => out.malformed += 1,
        }
    }
    out
}

/// F720 拉取 CrowdSec security-blocklist（需 API key：请求头 `Authorization: Key-<key>`）。
pub async fn fetch_crowdsec_blocklist(
    http: &reqwest::Client,
    url: &str,
    key: &str,
) -> Result<ParsedBlocklist> {
    let resp = http
        .get(url)
        .timeout(Duration::from_secs(90))
        .header("Authorization", format!("Key-{key}"))
        .send()
        .await
        .map_err(|e| Error::Ai(format!("CrowdSec 拉取失败: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Ai(format!(
            "CrowdSec 源返回 HTTP {}（key 无效/过期或限流）",
            resp.status()
        )));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| Error::Ai(format!("CrowdSec 响应读取失败: {e}")))?;
    Ok(parse_crowdsec_blocklist(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F720 解析器：单 IP / 网段分桶、注释空行跳过、畸形行计数。
    #[test]
    fn parse_crowdsec_splits_singles_and_ranges() {
        let text = "# Format: ip\n# Updated: 2026-10-01\n\n203.0.113.7\n198.51.100.0/24\nnot-an-ip\n2001:db8::1\n300.1.2.3/24\n";
        let p = parse_crowdsec_blocklist(text);
        assert_eq!(p.singles, vec!["203.0.113.7", "2001:db8::1"]);
        assert_eq!(p.ranges, vec!["198.51.100.0/24"]);
        assert_eq!(p.malformed, 2, "裸畸形行 + 非法网段都算丢弃口径");
    }

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
        assert!(
            parse_feodo_ipblocklist(
                "# only comments

"
            )
            .is_empty()
        );
    }
}
