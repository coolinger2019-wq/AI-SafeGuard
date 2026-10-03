//! Docker Engine HTTP API 蜜罐（F794a）：无 TLS 的 Docker daemon（2375）是
//! 2024-2026 最热的入侵路径之一——扫描器/僵尸网络直接 POST /containers/create
//! 部署恶意镜像（Kinsing 类挖矿）。假 daemon 返回合成集群形态；容器创建/exec
//! 的请求体本身就是 TTP（镜像名、挂载、命令），ghost 定罪零误报——合法客户端
//! 不会在别人的 daemon 上建容器。

use serde_json::{json, Value};
use crate::canary::CanaryState;
use crate::http::JsonRoute;
use crate::{sanitize, GhostVerdict};

const API_VERSION: &str = "1.43";
const DOCKER_VERSION: &str = "24.0.7";

fn not_found() -> JsonRoute {
    JsonRoute {
        status: "HTTP/1.1 404 Not Found\r\n",
        ctype: "application/json",
        body: br#"{"message":"page not found"}"#.to_vec(),
        label: "404".into(),
        ghost: None,
    }
}

/// 64 位十六进制容器/镜像 ID（合成；canary 可用时前 32 位内嵌水印段）
fn synthetic_id(canary: Option<&CanaryState>, res: &str) -> String {
    let token = canary.and_then(|c| c.token(res));
    let mut id = String::with_capacity(64);
    match token {
        Some(t) => {
            let clean: String = t
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(24)
                .collect();
            id.push_str(&clean.to_lowercase());
            while id.len() < 64 {
                id.push_str(&format!("{:02x}", rand::random::<u8>()));
            }
        }
        None => {
            for _ in 0..32 {
                id.push_str(&format!("{:02x}", rand::random::<u8>()));
            }
        }
    }
    id
}

/// 路由主表：方法 + 路径 → 合成响应。攻写操作（create/exec）ghost 定罪。
pub(crate) fn route(
    method: &str,
    path: &str,
    body: &[u8],
    canary: Option<&CanaryState>,
) -> JsonRoute {
    let path = path.split('?').next().unwrap_or("");
    let ok_json = |label: &str, v: Value| JsonRoute {
        status: "HTTP/1.1 200 OK\r\n",
        ctype: "application/json",
        body: serde_json::to_vec(&v).unwrap_or_default(),
        label: label.into(),
        ghost: None,
    };
    match (method, path) {
        ("GET", "/_ping") => JsonRoute {
            status: "HTTP/1.1 200 OK\r\n",
            ctype: "text/plain; charset=utf-8",
            body: b"OK".to_vec(),
            label: "_ping".into(),
            ghost: None,
        },
        ("GET", "/version") => ok_json(
            "version",
            json!({
                "Version": DOCKER_VERSION,
                "ApiVersion": API_VERSION,
                "MinAPIVersion": "1.12",
                "GitCommit": "synthetic-decoy",
                "GoVersion": "go1.21.3",
                "Os": "linux",
                "Arch": "amd64",
                "KernelVersion": "5.15.0-91-generic",
                "BuildTime": "2026-01-01T00:00:00Z"
            }),
        ),
        ("GET", "/info") => ok_json(
            "info",
            json!({
                "ID": synthetic_id(canary, "docker/info"),
                "Containers": 2,
                "ContainersRunning": 1,
                "ContainersPaused": 0,
                "ContainersStopped": 1,
                "Images": 5,
                "Name": "prod-app-01",
                "ServerVersion": DOCKER_VERSION,
                "OperatingSystem": "Ubuntu 22.04 LTS",
                "Architecture": "x86_64",
                "NCPU": 2,
                "MemTotal": 2_147_483_648u64
            }),
        ),
        ("GET", "/images/json") => ok_json(
            "images",
            json!([
                {
                    "Id": format!("sha256:{}", synthetic_id(canary, "docker/image-app")),
                    "RepoTags": ["registry.internal:5000/app:latest"],
                    "Created": "2026-09-20T08:00:00Z",
                    "Size": 187_400_704u64
                },
                {
                    "Id": format!("sha256:{}", synthetic_id(canary, "docker/image-base")),
                    "RepoTags": ["ubuntu:22.04"],
                    "Created": "2026-08-01T08:00:00Z",
                    "Size": 77_800_448u64
                }
            ]),
        ),
        ("GET", "/containers/json") => ok_json(
            "containers",
            json!([
                {
                    "Id": synthetic_id(canary, "docker/ctr-web"),
                    "Names": ["/app-web"],
                    "Image": "registry.internal:5000/app:latest",
                    "State": "running",
                    "Status": "Up 3 days",
                    "Ports": [{"PrivatePort": 8080, "Type": "tcp"}]
                }
            ]),
        ),
        ("POST", "/containers/create") => {
            let body_clean = sanitize(body, 400);
            let id = synthetic_id(canary, "docker/create");
            JsonRoute {
                status: "HTTP/1.1 201 Created\r\n",
                ctype: "application/json",
                body: serde_json::to_vec(&json!({"Id": id, "Warnings": []})).unwrap_or_default(),
                label: "containers/create".into(),
                ghost: Some(GhostVerdict {
                    kind: "docker_ghost".into(),
                    threat: "critical".into(),
                    evidence: format!("Docker API 容器创建请求（镜像部署 TTP）: {body_clean}"),
                }),
            }
        }
        ("POST", p) if p.starts_with("/containers/") && (p.ends_with("/exec") || p.contains("/exec")) => {
            let body_clean = sanitize(body, 400);
            JsonRoute {
                status: "HTTP/1.1 201 Created\r\n",
                ctype: "application/json",
                body: serde_json::to_vec(&json!({"Id": synthetic_id(canary, "docker/exec"), "Warnings": []}))
                    .unwrap_or_default(),
                label: "containers/exec".into(),
                ghost: Some(GhostVerdict {
                    kind: "docker_ghost".into(),
                    threat: "critical".into(),
                    evidence: format!("Docker API exec 创建（容器内执行命令）: {body_clean}"),
                }),
            }
        }
        ("POST", p) if p.starts_with("/containers/") => JsonRoute {
            status: "HTTP/1.1 204 No Content\r\n",
            ctype: "text/plain; charset=utf-8",
            body: Vec::new(),
            label: format!("POST {p}"),
            ghost: None,
        },
        ("DELETE", p) if p.starts_with("/containers/") || p.starts_with("/images/") => JsonRoute {
            status: "HTTP/1.1 204 No Content\r\n",
            ctype: "text/plain; charset=utf-8",
            body: Vec::new(),
            label: format!("DELETE {p}"),
            ghost: None,
        },
        ("GET", p) if p.starts_with("/containers/") => ok_json(
            "container-inspect",
            json!({
                "Id": synthetic_id(canary, "docker/inspect"),
                "Name": "/app-web",
                "State": {"Status": "running", "Running": true},
                "Config": {"Image": "registry.internal:5000/app:latest"}
            }),
        ),
        _ => not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_ping_look_like_docker() {
        let r = route("GET", "/_ping", b"", None);
        assert_eq!(String::from_utf8_lossy(&r.body), "OK");
        let r = route("GET", "/version", b"", None);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["ApiVersion"], API_VERSION);
        assert_eq!(v["Os"], "linux");
    }

    #[test]
    fn container_create_is_ghost_convicted() {
        let cfg = json!({"Image": "alpine:latest", "Cmd": ["sh", "-c", "xmrig -o pool"]}).to_string();
        let r = route("POST", "/containers/create", cfg.as_bytes(), None);
        assert_eq!(r.status, "HTTP/1.1 201 Created\r\n");
        let ghost = r.ghost.expect("容器创建应定罪");
        assert_eq!(ghost.threat, "critical");
        assert!(ghost.evidence.contains("xmrig"), "证据应含攻击者配置: {}", ghost.evidence);
    }

    #[test]
    fn exec_and_regular_stubs() {
        let r = route("POST", "/containers/abc/exec", br#"{"Cmd":["whoami"]}"#, None);
        assert!(r.ghost.is_some(), "exec 应定罪");
        let r = route("POST", "/containers/abc/start", b"", None);
        assert!(r.ghost.is_none());
        assert_eq!(r.status, "HTTP/1.1 204 No Content\r\n");
        let r = route("GET", "/nonexistent", b"", None);
        assert_eq!(r.status, "HTTP/1.1 404 Not Found\r\n");
    }
}
