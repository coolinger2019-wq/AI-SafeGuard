//! Elasticsearch 蜜罐（F794a）：9200 是公网高频扫描端口，也是内网开发机常见
//! 暴露面。假集群返回合成集群形态（集群名/UUID 内嵌 canary——被复制到攻击者
//! 报告里可归因）；数据写入/脚本注入是确定性攻击证据，ghost 定罪零误报
//! （CVE-2014-3120 / CVE-2015-1427 类脚本利用在 _search body 里可见）。

use serde_json::{json, Value};
use crate::canary::CanaryState;
use crate::http::JsonRoute;
use crate::{sanitize, GhostVerdict};

const ES_VERSION: &str = "8.11.3";

/// 集群名/UUID：canary 可用时内嵌水印段（外泄即归因）
fn cluster_name(canary: Option<&CanaryState>) -> String {
    match canary.and_then(|c| c.token("es/cluster")) {
        Some(t) => {
            let seg: String = t
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(8)
                .collect();
            format!("prod-es-cluster-{seg}")
        }
        None => "prod-es-cluster".into(),
    }
}

fn cluster_uuid(canary: Option<&CanaryState>) -> String {
    let mut u = String::with_capacity(36);
    if let Some(t) = canary.and_then(|c| c.token("es/uuid")) {
        let clean: Vec<char> = t.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        for (i, c) in clean.iter().take(32).enumerate() {
            if i == 8 || i == 12 || i == 16 || i == 20 {
                u.push('-');
            }
            u.push(c.to_ascii_lowercase());
        }
    }
    while u.len() < 36 {
        let i = u.len();
        if i == 8 || i == 12 || i == 16 || i == 20 {
            u.push('-');
        }
        let hexc = format!("{:x}", rand::random::<u8>());
        u.push(hexc.chars().next().unwrap_or('0'));
    }
    u
}

fn ok(label: &str, v: Value) -> JsonRoute {
    JsonRoute {
        status: "HTTP/1.1 200 OK\r\n",
        ctype: "application/json",
        body: serde_json::to_vec(&v).unwrap_or_default(),
        label: label.into(),
        ghost: None,
    }
}

fn cat_indices(canary: Option<&CanaryState>) -> String {
    let watermark = canary
        .and_then(|c| c.token("es/cat"))
        .map(|t| {
            let seg: String = t.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
            format!("backup-{seg}    ")
        })
        .unwrap_or_else(|| "backup-synthetic".into());
    format!(
        "health status index                          docs.count store.size pri.store.size\n\
         green  open   logs-2026.10.03                   58231     12mb        6mb\n\
         green  open   {watermark}                3     4.5kb       4.5kb\n\
         green  open   users                                 2      3kb         3kb"
    )
}

fn fake_search(index: &str) -> Value {
    json!({
        "took": 12,
        "timed_out": false,
        "hits": {
            "total": {"value": 2, "relation": "eq"},
            "max_score": 1.0,
            "hits": [
                {
                    "_index": index,
                    "_id": "SYNTH001",
                    "_score": 1.0,
                    "_source": {"user": "deploy", "action": "login", "@timestamp": "2026-10-03T09:14:02Z"}
                },
                {
                    "_index": index,
                    "_id": "SYNTH002",
                    "_score": 0.9,
                    "_source": {"user": "backup", "action": "logout", "@timestamp": "2026-10-03T03:40:11Z"}
                }
            ]
        }
    })
}

/// 路由主表：方法 + 路径 → 合成响应。写入/脚本注入 ghost 定罪。
pub(crate) fn route(
    method: &str,
    path: &str,
    body: &[u8],
    canary: Option<&CanaryState>,
) -> JsonRoute {
    let path = path.split('?').next().unwrap_or("");
    let cluster = cluster_name(canary);
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    match (method, path) {
        ("GET", "/") => ok(
            "root",
            json!({
                "name": "node-1",
                "cluster_name": cluster,
                "cluster_uuid": cluster_uuid(canary),
                "version": {
                    "number": ES_VERSION,
                    "build_flavor": "default",
                    "build_type": "tar",
                    "build_hash": "synthetic",
                    "build_date": "2026-01-01T00:00:00.000000Z",
                    "lucene_version": "9.8.0",
                    "minimum_wire_compatibility_version": "7.17.0",
                    "minimum_index_compatibility_version": "7.0.0"
                },
                "tagline": "You Know, for Search"
            }),
        ),
        ("GET", "/_cluster/health") => ok(
            "cluster-health",
            json!({
                "cluster_name": cluster,
                "status": "green",
                "timed_out": false,
                "number_of_nodes": 3,
                "number_of_data_nodes": 2,
                "active_primary_shards": 5,
                "active_shards": 10,
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 0
            }),
        ),
        ("GET", "/_cat/indices") => JsonRoute {
            status: "HTTP/1.1 200 OK\r\n",
            ctype: "text/plain; charset=UTF-8",
            body: cat_indices(canary).into_bytes(),
            label: "_cat/indices".into(),
            ghost: None,
        },
        ("GET", "/_cat/health") => JsonRoute {
            status: "HTTP/1.1 200 OK\r\n",
            ctype: "text/plain; charset=UTF-8",
            body: b"1696000000 07:00:00 prod-es-cluster green 3 2 5 10 0 0 0".to_vec(),
            label: "_cat/health".into(),
            ghost: None,
        },
        _ => {
            // _search：索引级或全局，body 含 script = 脚本注入利用（CVE-2015-1427 类）
            if path.ends_with("_search") || path == "_msearch" {
                let index = segs.first().copied().unwrap_or("_all");
                let body_clean = sanitize(body, 300);
                let body_lower = body_clean.to_ascii_lowercase();
                let ghost = if body_lower.contains("script") || body_lower.contains("painless") {
                    Some(GhostVerdict {
                        kind: "es_ghost".into(),
                        threat: "critical".into(),
                        evidence: format!("ES 脚本注入利用尝试（{index}）: {body_clean}"),
                    })
                } else {
                    None
                };
                let mut r = ok("search", fake_search(index));
                r.ghost = ghost;
                return r;
            }
            // 数据写入（_doc/_bulk/create）——向陌生集群写数据 = 确定性攻击
            if (method == "PUT" || method == "POST")
                && (path.contains("/_doc") || path.contains("/_bulk") || path.contains("/_create"))
            {
                let body_clean = sanitize(body, 400);
                return JsonRoute {
                    status: "HTTP/1.1 201 Created\r\n",
                    ctype: "application/json",
                    body: serde_json::to_vec(&json!({
                        "_index": segs.first().copied().unwrap_or("synthetic"),
                        "_id": "SYNTH003",
                        "result": "created",
                        "_shards": {"total": 2, "successful": 1, "failed": 0}
                    }))
                    .unwrap_or_default(),
                    label: format!("write {path}"),
                    ghost: Some(GhostVerdict {
                        kind: "es_ghost".into(),
                        threat: "high".into(),
                        evidence: format!("ES 数据写入（{method} {path}）: {body_clean}"),
                    }),
                };
            }
            // 索引元信息 GET /{index}
            if method == "GET" && segs.len() == 1 && !segs[0].starts_with('_') {
                return ok(
                    "index-info",
                    json!({
                        segs[0]: {
                            "aliases": {},
                            "mappings": {"properties": {"user": {"type": "keyword"}}},
                            "settings": {"index": {"number_of_shards": "1", "uuid": cluster_uuid(canary)}}
                        }
                    }),
                );
            }
            JsonRoute {
                status: "HTTP/1.1 400 Bad Request\r\n",
                ctype: "application/json",
                body: serde_json::to_vec(&json!({
                    "error": {"root_cause": [{"type": "invalid_index_name_exception", "reason": "synthetic"}], "status": 400}
                }))
                .unwrap_or_default(),
                label: format!("400:{method} {path}"),
                ghost: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_health_look_like_es() {
        let r = route("GET", "/", b"", None);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["tagline"], "You Know, for Search");
        assert_eq!(v["version"]["number"], ES_VERSION);
        let r = route("GET", "/_cluster/health", b"", None);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["status"], "green");
    }

    #[test]
    fn script_injection_is_ghost_convicted() {
        let body = br#"{"query":{"match_all":{}},"script_fields":{"x":{"script":"java.lang.Runtime.getRuntime()"}}}"#;
        let r = route("POST", "/logs-2026.10.03/_search", body, None);
        let ghost = r.ghost.expect("脚本注入应定罪");
        assert_eq!(ghost.threat, "critical");
        assert!(ghost.evidence.contains("Runtime"), "证据应含载荷: {}", ghost.evidence);
    }

    #[test]
    fn data_write_is_ghost_convicted_and_plain_search_is_not() {
        let r = route(
            "POST",
            "/creds/_doc",
            br#"{"user":"admin","pass":"x"}"#,
            None,
        );
        assert!(r.ghost.is_some(), "写入应定罪");
        assert_eq!(r.status, "HTTP/1.1 201 Created\r\n");
        let r = route("POST", "/logs-2026.10.03/_search", br#"{"query":{"match_all":{}}}"#, None);
        assert!(r.ghost.is_none(), "普通查询不定罪");
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["hits"]["total"]["value"], 2);
    }
}
