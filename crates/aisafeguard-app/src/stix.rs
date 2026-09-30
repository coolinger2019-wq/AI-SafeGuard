//! STIX 2.1 导入导出（0.6 F310，设计见 docs/ROADMAP-0.6.md）。组织级情报的价值
//! 不在收集在共享：节点产出的 IOC 组织内标准化交换，外部/组织清单导入本地命中。
//!
//! 范围冻结（四类对象，其余明确不做）：`identity`（节点）、`indicator`（IP/域名/
//! JA3/JA4）、`observed-data`（蜜罐交互摘要，含 ipv4-addr SCO）、`sighting`
//! （印证/情报命中，只挂能映射到已导出 indicator 的键）。TAXII 明确不做。
//!
//! 红线（自动化断言在 tests）：
//! - 凭证永不导出（无 username/pass_hash/口令材料字段，含计数指标也不含哈希）；
//! - 内网/回环 IP 不导出（防内网拓扑泄漏，is_protected_ip 前置跳过）；
//! - 导入清单默认只告警不自动封（confidence="fed" + kind="imported_ioc"，
//!   自动封禁门控要求 confidence=high && kind=c2，双保险排除）；
//! - 导出包必须签名（节点证书 ECDSA P-256 对 bundle 规范化字节），导入验签
//!   失败拒收（复用 fedproto 签名栈，证书来源 = 组织内成员证书）。

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::fedproto::{canonical_json, sign_with_key, verify_signature};

/// 导出条数上限（整包有界，防内存放大）
pub const EXPORT_CAP_INTEL: usize = 2_000;
pub const EXPORT_CAP_OBSERVED: usize = 50;
pub const EXPORT_CAP_SIGHTINGS: usize = 50;
/// 导入上限：indicator 条数 / 包对象总数
pub const IMPORT_CAP_INDICATORS: usize = 5_000;
pub const IMPORT_CAP_OBJECTS: usize = 20_000;
/// 导入文件大小上限（字节）
pub const IMPORT_CAP_BYTES: u64 = 5 * 1024 * 1024;
/// 无 valid_until 的导入 IOC 默认有效期（对齐 fed 情报 7 天 TTL 哲学）
pub const DEFAULT_IOC_TTL_SECS: i64 = 7 * 86400;

const SPEC_VERSION: &str = "2.1";

pub fn rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn parse_rfc3339(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp())
}

fn stix_id(type_name: &str) -> String {
    format!("{type_name}--{}", uuid::Uuid::new_v4())
}

// ---------- 导出 ----------

/// 导出数据供给（调用方从 store 取好，本模块只做纯转换——可测）。
#[derive(Debug, Default, Clone)]
pub struct ExportFeed {
    /// (kind, value, confidence, expires_ts)——调用方须已过滤 fed:*/stix:* 回灌源
    pub intel: Vec<(String, String, String, i64)>,
    /// (源 IP, 命中次数, 首次, 末次)——蜜罐交互摘要（24h 窗聚合）
    pub honeypot: Vec<(String, i64, i64, i64)>,
    /// (dim, key, 节点数, 时间)——组织印证命中（ip 维度才可挂 sighting）
    pub corr_hits: Vec<(String, String, i64, i64)>,
}

/// value → STIX pattern；无法表达/内网地址返回 None（导出侧静默跳过）。
pub fn value_to_pattern(kind: &str, value: &str) -> Option<String> {
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        if aisafeguard_core::is_protected_ip(ip) {
            return None;
        }
        return Some(match ip {
            std::net::IpAddr::V4(_) => format!("[ipv4-addr:value = '{value}']"),
            std::net::IpAddr::V6(_) => format!("[ipv6-addr:value = '{value}']"),
        });
    }
    match kind {
        "ja3" => Some(format!("[network-traffic:protocols[*] = 'ja3={value}']")),
        "ja4" => Some(format!("[network-traffic:protocols[*] = 'ja4={value}']")),
        _ => {
            // 域名启发：含点、无冒号、可见 ASCII 域名字符
            let ok = value.contains('.')
                && !value.contains(':')
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            ok.then(|| format!("[domain-name:value = '{value}']"))
        }
    }
}

/// 组装 STIX 2.1 bundle（四类对象）。全部纯函数，now 注入可测。
pub fn build_bundle(node: &str, version: &str, feed: &ExportFeed, now: i64) -> Value {
    let created = rfc3339(now);
    let mut objects: Vec<Value> = Vec::new();

    // identity：导出方节点
    objects.push(json!({
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": stix_id("identity"),
        "created": created,
        "modified": created,
        "name": node,
        "description": format!("AI-SafeGuard node v{version}"),
        "identity_class": "organization",
    }));

    // indicator：intel 表（value 形态可表达的才导）
    let mut indicator_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (kind, value, confidence, expires) in feed.intel.iter().take(EXPORT_CAP_INTEL) {
        let Some(pattern) = value_to_pattern(kind, value) else {
            continue;
        };
        let id = stix_id("indicator");
        indicator_ids.insert(value.clone(), id.clone());
        objects.push(json!({
            "type": "indicator",
            "spec_version": SPEC_VERSION,
            "id": id,
            "created": created,
            "modified": created,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created,
            // STIX 规格约束：valid_until 必须严格大于 valid_from（同秒也不行）——
            // python-stix2 实测抓到，此处保底 +1s
            "valid_until": rfc3339((*expires).max(now + 1)),
            "confidence": if confidence == "high" { 80 } else { 50 },
            "description": format!("source confidence: {confidence}"),
        }));
    }

    // observed-data + ipv4-addr SCO：蜜罐交互摘要（每攻击者 IP 一条，含计数）
    for (ip, count, first, last) in feed.honeypot.iter().take(EXPORT_CAP_OBSERVED) {
        let Ok(parsed) = ip.parse::<std::net::IpAddr>() else {
            continue;
        };
        if aisafeguard_core::is_protected_ip(parsed) {
            continue;
        }
        let sco_id = stix_id("ipv4-addr");
        objects.push(json!({
            "type": "ipv4-addr",
            "spec_version": SPEC_VERSION,
            "id": sco_id,
            "value": ip,
        }));
        objects.push(json!({
            "type": "observed-data",
            "spec_version": SPEC_VERSION,
            "id": stix_id("observed-data"),
            "created": created,
            "modified": created,
            "first_observed": rfc3339(*first),
            "last_observed": rfc3339(*last),
            "number_observed": (*count).clamp(1, i64::MAX),
            "object_refs": [sco_id],
        }));
    }

    // sighting：组织印证命中（只挂能映射到已导出 indicator 的 ip 键）
    for (dim, key, nodes, ts) in feed.corr_hits.iter().take(EXPORT_CAP_SIGHTINGS) {
        if dim != "ip" {
            continue;
        }
        let Some(indicator_id) = indicator_ids.get(key) else {
            continue;
        };
        objects.push(json!({
            "type": "sighting",
            "spec_version": SPEC_VERSION,
            "id": stix_id("sighting"),
            "created": created,
            "modified": created,
            "sighting_of_ref": indicator_id,
            "first_seen": rfc3339(*ts),
            "last_seen": rfc3339(*ts),
            "count": (*nodes).clamp(1, i64::MAX),
            "description": "corroborated by multiple org nodes",
        }));
    }

    json!({
        "type": "bundle",
        "id": stix_id("bundle"),
        "objects": objects,
    })
}

/// 导出包信封：bundle + 节点签名（防篡改/防抵赖，接收方验签失败拒收）。
pub fn sign_package(
    node: &str,
    key: &ring::signature::EcdsaKeyPair,
    bundle: &Value,
    now: i64,
) -> Result<Value, String> {
    let digest = Sha256::digest(canonical_json(bundle).as_bytes());
    let sig = sign_with_key(key, &digest)?;
    Ok(json!({
        "kind": "asg-stix-bundle",
        "node": node,
        "created_ts": now,
        "bundle": bundle,
        "sig": sig,
    }))
}

// ---------- 导入 ----------

/// 解析导出包信封（不验签——验签需要签发方证书，见 verify_package）。
/// 返回 (签发节点, 完整包)；bundle 在 pkg["bundle"]。
pub fn parse_package(bytes: &[u8]) -> Result<(String, Value), String> {
    if bytes.len() as u64 > IMPORT_CAP_BYTES {
        return Err(format!("包大小超上限 {} 字节", IMPORT_CAP_BYTES));
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("包解析失败: {e}"))?;
    if v["kind"].as_str() != Some("asg-stix-bundle") {
        return Err("不是 asg-stix-bundle 包（kind 字段不符）".into());
    }
    let Some(node) = v["node"].as_str() else {
        return Err("包缺少 node 字段".into());
    };
    if v["bundle"]["type"].as_str() != Some("bundle") {
        return Err("包缺少 STIX bundle".into());
    }
    if v["sig"].as_str().is_none() {
        return Err("包缺少签名（导入要求签名包，防投毒）".into());
    }
    Ok((node.to_string(), v))
}

/// 验签：用签发方节点证书验 bundle 签名。证书不在本地成员证书目录 → 拒收。
pub fn verify_package(pkg: &Value, signer_cert_der: &[u8]) -> Result<(), String> {
    let Some(sig) = pkg["sig"].as_str() else {
        return Err("包缺少签名".into());
    };
    let digest = Sha256::digest(canonical_json(&pkg["bundle"]).as_bytes());
    let point = crate::fedproto::public_point_from_cert_der(signer_cert_der)?;
    if !verify_signature(&point, &digest, sig) {
        return Err("签名校验失败（包被篡改或证书不符）——拒收".into());
    }
    Ok(())
}

/// 一条导入 IOC（映射进 intel 表）。
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedIoc {
    pub kind: String,
    pub value: String,
    pub expires_ts: i64,
}

/// STIX pattern → (kind, value)。只接受冻结的表达子集，其余拒收（负路径：
/// 不认识的模式不猜）。
pub fn pattern_to_ioc(pattern: &str) -> Option<(String, String)> {
    let inner = pattern.trim().strip_prefix('[')?.strip_suffix(']')?.trim();
    let (path, value) = inner.split_once(" = ")?;
    let value = value.trim().strip_prefix('\'')?.strip_suffix('\'')?;
    if value.is_empty() || value.len() > 256 {
        return None;
    }
    match path.trim() {
        "ipv4-addr:value" | "ipv6-addr:value" => Some(("ip".into(), value.to_string())),
        "domain-name:value" => Some(("domain".into(), value.to_string())),
        "network-traffic:protocols[*]" => {
            let (tag, rest) = value.split_once('=')?;
            match tag {
                "ja3" | "ja4" => Some((tag.to_string(), rest.to_string())),
                _ => None,
            }
        }
        _ => None,
    }
}

/// 从 bundle 提取 indicator → IOC 清单（valid_until 到期失效交给 intel prune）。
pub fn parse_indicators(bundle: &Value, now: i64) -> Result<Vec<ImportedIoc>, String> {
    let Some(objects) = bundle["objects"].as_array() else {
        return Err("bundle 无 objects".into());
    };
    if objects.len() > IMPORT_CAP_OBJECTS {
        return Err(format!("包对象数超上限 {IMPORT_CAP_OBJECTS}"));
    }
    let mut out: Vec<ImportedIoc> = Vec::new();
    for o in objects {
        if o["type"].as_str() != Some("indicator") {
            continue;
        }
        let Some(pattern) = o["pattern"].as_str() else {
            continue;
        };
        let Some((kind, value)) = pattern_to_ioc(pattern) else {
            continue; // 不认识的模式静默跳过（计数可见于返回清单差异）
        };
        let expires_ts = o["valid_until"]
            .as_str()
            .and_then(parse_rfc3339)
            .filter(|&e| e > now)
            .unwrap_or(now + DEFAULT_IOC_TTL_SECS);
        out.push(ImportedIoc {
            kind,
            value,
            expires_ts,
        });
        if out.len() >= IMPORT_CAP_INDICATORS {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed() -> ExportFeed {
        ExportFeed {
            intel: vec![
                ("c2".into(), "203.0.113.7".into(), "high".into(), 1_800_000_000),
                ("scan_source".into(), "evil.example.com".into(), "local".into(), 1_800_000_000),
                ("ja3".into(), "a67dc37ce3543d3d0f9e9e6ab1b0e5c9".into(), "fed".into(), 1_800_000_000),
                // 内网地址：导出侧必须跳过（防内网拓扑泄漏）
                ("scan_source".into(), "192.168.1.50".into(), "local".into(), 1_800_000_000),
            ],
            honeypot: vec![("203.0.113.7".into(), 12, 1_799_990_000, 1_800_000_000)],
            corr_hits: vec![
                ("ip".into(), "203.0.113.7".into(), 3, 1_800_000_000),
                ("ip".into(), "198.51.100.9".into(), 2, 1_800_000_000), // 无 indicator → 不挂 sighting
            ],
        }
    }

    #[test]
    fn bundle_has_four_object_types_and_valid_shapes() {
        let b = build_bundle("node-a", "0.5.12", &feed(), 1_800_000_000);
        assert_eq!(b["type"], "bundle");
        assert!(b["id"].as_str().unwrap().starts_with("bundle--"));
        let objs = b["objects"].as_array().unwrap();
        for t in ["identity", "indicator", "observed-data", "sighting", "ipv4-addr"] {
            assert!(
                objs.iter().any(|o| o["type"] == t),
                "缺少 {t} 对象"
            );
        }
        for o in objs {
            assert_eq!(o["spec_version"], "2.1", "每个对象带 spec_version");
            let id = o["id"].as_str().unwrap();
            assert!(id.starts_with(o["type"].as_str().unwrap()), "id 前缀 = 类型");
        }
        // indicator pattern 形态
        let ind = objs
            .iter()
            .find(|o| o["type"] == "indicator" && o["pattern"].as_str().unwrap().contains("ipv4"))
            .unwrap();
        assert_eq!(ind["pattern"], "[ipv4-addr:value = '203.0.113.7']");
        assert_eq!(ind["pattern_type"], "stix");
        // sighting 只挂有 indicator 的键
        let sightings: Vec<&Value> = objs.iter().filter(|o| o["type"] == "sighting").collect();
        assert_eq!(sightings.len(), 1, "无 indicator 的印证键不产 sighting");
        assert_eq!(sightings[0]["count"], 3);
        // observed-data 引用 SCO
        let od = objs.iter().find(|o| o["type"] == "observed-data").unwrap();
        assert_eq!(od["number_observed"], 12);
        let sco_ref = od["object_refs"].as_array().unwrap()[0].as_str().unwrap();
        assert!(objs.iter().any(|o| o["id"] == sco_ref && o["type"] == "ipv4-addr"));
        // 内网 IP 不出现在包里（脱敏红线）
        let text = b.to_string();
        assert!(!text.contains("192.168.1.50"), "内网地址不得导出");
    }

    /// 红线自动化断言：包内无任何凭证材料/口令字段/文件系统路径。
    #[test]
    fn bundle_never_carries_credential_material() {
        let mut f = feed();
        // 恶意构造：intel value 里混入口令样貌的字符串也只进 pattern（不可信数据）
        f.intel.push(("domain".into(), "x".into(), "local".into(), 1_800_000_000));
        let b = build_bundle("node-a", "0.5.12", &f, 1_800_000_000);
        let text = b.to_string();
        for token in ["pass_hash", "password", "username", "argon", "credentials.db", "listener"] {
            assert!(!text.to_lowercase().contains(token), "包内出现红线字段: {token}");
        }
    }

    #[test]
    fn package_sign_verify_and_tamper_reject() {
        let dir = std::env::temp_dir().join(format!("asg-stix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::fed::cmd_init_ca(&dir, "").unwrap();
        crate::fed::cmd_issue_cert(&dir, "node-a", &[]).unwrap();
        crate::fed::cmd_issue_cert(&dir, "node-b", &[]).unwrap();
        let key_pem =
            std::fs::read_to_string(dir.join("fed").join("certs").join("node-a-key.pem")).unwrap();
        let key = crate::fedproto::load_signing_key(&key_pem).unwrap();
        let cert_b_pem =
            std::fs::read_to_string(dir.join("fed").join("certs").join("node-b.pem")).unwrap();

        let bundle = build_bundle("node-a", "0.5.12", &feed(), 1_800_000_000);
        let pkg = sign_package("node-a", &key, &bundle, 1_800_000_000).unwrap();

        // 正向：签发方证书验签通过
        let (node, pkg) = parse_package(pkg.to_string().as_bytes()).unwrap();
        assert_eq!(node, "node-a");
        assert_eq!(pkg["bundle"], bundle);
        let der_b = pem_cert_der(&cert_b_pem);
        let der_a = {
            let pem =
                std::fs::read_to_string(dir.join("fed").join("certs").join("node-a.pem")).unwrap();
            pem_cert_der(&pem)
        };
        assert!(verify_package(&pkg, &der_a).is_ok());
        // 他人证书 → 拒收
        assert!(verify_package(&pkg, &der_b).is_err(), "非签发方证书必须拒收");
        // 篡改 bundle → 拒收
        let mut tampered = pkg.clone();
        tampered["bundle"]["objects"][0]["name"] = json!("attacker");
        assert!(verify_package(&tampered, &der_a).is_err());
        // 缺签名 → parse_package 拒
        let mut unsigned = pkg.clone();
        unsigned["sig"] = json!(null);
        assert!(parse_package(unsigned.to_string().as_bytes()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn pem_cert_der(pem: &str) -> Vec<u8> {
        let begin = "-----BEGIN CERTIFICATE-----";
        let end = "-----END CERTIFICATE-----";
        let i = pem.find(begin).unwrap();
        let j = pem[i..].find(end).unwrap();
        let body: String = pem[i + begin.len()..i + j]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(body).unwrap()
    }

    #[test]
    fn import_parses_frozen_pattern_subset_only() {
        let bundle = json!({
            "type": "bundle",
            "id": "bundle--x",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.7']", "valid_until": rfc3339(1_800_000_000)},
                {"type": "indicator", "pattern": "[domain-name:value = 'c2.example.net']"},
                {"type": "indicator", "pattern": "[network-traffic:protocols[*] = 'ja4=t13d1516h2_8daaf6152771_b0da82dd1658']"},
                {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'abc']"},
                {"type": "indicator", "pattern": "not a pattern"},
                {"type": "identity", "name": "x"},
            ],
        });
        let iocs = parse_indicators(&bundle, 1_790_000_000).unwrap();
        assert_eq!(iocs.len(), 3, "冻结子集之外的模式拒收");
        assert_eq!(iocs[0], ImportedIoc { kind: "ip".into(), value: "203.0.113.7".into(), expires_ts: 1_800_000_000 });
        assert_eq!(iocs[1].kind, "domain");
        // 无 valid_until → 默认 7 天
        assert_eq!(iocs[1].expires_ts, 1_790_000_000 + DEFAULT_IOC_TTL_SECS);
        assert_eq!(iocs[2].kind, "ja4");
        // 已过期的 valid_until → 落回默认 TTL（立即失效的清单没有导入意义）
        let expired = json!({
            "type": "bundle", "id": "bundle--x",
            "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']", "valid_until": rfc3339(1_000)}],
        });
        let iocs = parse_indicators(&expired, 1_790_000_000).unwrap();
        assert_eq!(iocs[0].expires_ts, 1_790_000_000 + DEFAULT_IOC_TTL_SECS);
    }

    /// F310 验收辅助：把样例包写到 target/stix-sample.json，供现成 STIX 库
    /// （python-stix2）实测解析——docs/FEDERATION.md 记录验证命令。
    #[test]
    fn write_sample_for_external_validation() {
        let dir = std::env::temp_dir().join(format!("asg-stix-w-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::fed::cmd_init_ca(&dir, "").unwrap();
        crate::fed::cmd_issue_cert(&dir, "sample-node", &[]).unwrap();
        let key_pem = std::fs::read_to_string(dir.join("fed").join("certs").join("sample-node-key.pem"))
            .unwrap();
        let key = crate::fedproto::load_signing_key(&key_pem).unwrap();
        let feed = ExportFeed {
            intel: vec![
                ("c2".into(), "203.0.113.7".into(), "high".into(), 1_800_000_000),
                ("scan_source".into(), "evil.example.com".into(), "local".into(), 1_800_000_000),
                ("ja4".into(), "t13d1516h2_8daaf6152771_b0da82dd1658".into(), "fed".into(), 1_800_000_000),
            ],
            honeypot: vec![("203.0.113.7".into(), 12, 1_799_990_000, 1_800_000_000)],
            corr_hits: vec![("ip".into(), "203.0.113.7".into(), 3, 1_800_000_000)],
        };
        let bundle = build_bundle("sample-node", "0.5.12", &feed, 1_800_000_000);
        let pkg = sign_package("sample-node", &key, &bundle, 1_800_000_000).unwrap();
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/stix-sample.json");
        std::fs::write(&out, serde_json::to_string_pretty(&pkg).unwrap()).unwrap();
        println!("sample written to {}", out.display());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rfc3339_roundtrip() {
        let s = rfc3339(1_800_000_000);
        assert!(s.ends_with('Z'), "STIX 时间须 UTC Z 形态: {s}");
        assert_eq!(parse_rfc3339(&s), Some(1_800_000_000));
        assert_eq!(parse_rfc3339("不是时间"), None);
    }
}
