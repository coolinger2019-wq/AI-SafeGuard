//! 蜜罐模板（0.5.11 H300）：把「假业务系统」做成可配置资产。
//!
//! 目录约定：`<root>/<模板名>/template.toml`（+ http 模板的页面文件）。
//! 加载治理对齐规则引擎的「整包加载」哲学的单模板化：**单模板解析失败 →
//! 只拒绝该模板并告警，不影响其他模板与内置默认**。端口与已有监听器冲突
//! → 拒绝该模板（启动期）。模板内容变更（页面/表单字段/banner）自动热重载；
//! 新增/删除模板目录 = 监听器增删 = 需重启（轮询检测到只告警提示）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use aisafeguard_core::config::ListenerConfig;
use aisafeguard_core::event::{EventBus, SecurityEvent};
use serde::{Deserialize, Serialize};

/// 轮询周期（mtime + 长度），规则引擎热重载同款先例
const POLL_SECS: u64 = 5;

/// 模板关联文件快照：(路径, mtime, 长度)
type WatchedFile = (PathBuf, SystemTime, u64);

/// load_one 结果：(http 内容, banner 覆盖, 额外监听器, 关联文件)
type LoadedTemplate = (
    Option<HttpTemplate>,
    Option<String>,
    Option<ListenerConfig>,
    Vec<WatchedFile>,
);

/// 单个 http 模板的可渲染内容
#[derive(Clone)]
pub(crate) struct HttpTemplate {
    /// 页面 HTML（模板文件内容原样返回）
    pub page: String,
    /// 表单用户名字段名（小写；追加到内置键名表后做词边界匹配）
    pub user_keys: Vec<String>,
    /// 表单口令字段名
    pub pass_keys: Vec<String>,
    /// 敏感路径列表（前缀匹配，命中返回 403 诱饵页）
    pub decoy_paths: Vec<String>,
}

/// 模板注册表内容（热重载整体替换）
#[derive(Default)]
pub(crate) struct TemplateSet {
    /// 监听器名（= 模板名）→ http 模板
    pub http: HashMap<String, HttpTemplate>,
    /// ssh/telnet 监听器名 → banner 覆盖
    pub banners: HashMap<String, String>,
}

/// 模板注册表：启动加载 + 周期轮询热重载。
pub(crate) struct TemplateRegistry {
    set: RwLock<TemplateSet>,
    root: PathBuf,
    /// 模板名 → 关联文件快照（路径, mtime, 长度）
    files: Mutex<HashMap<String, Vec<WatchedFile>>>,
    /// 已告警过的新模板目录（去重：轮询每 5s 一次，不去重会刷屏）
    warned_new: Mutex<std::collections::HashSet<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TemplateSpec {
    /// http | ssh | telnet（generic 不需要模板）
    protocol: String,
    /// 模板监听器端口
    port: u16,
    /// http 模板：页面文件（相对模板目录）
    #[serde(default)]
    page: String,
    /// http 模板：表单用户名字段名（逗号分隔可写多个）
    #[serde(default)]
    form_user: String,
    /// http 模板：表单口令字段名
    #[serde(default)]
    form_pass: String,
    /// http 模板：敏感路径（TOML 数组）
    #[serde(default)]
    decoy_paths: Vec<String>,
    /// ssh/telnet 模板：banner 覆盖
    #[serde(default)]
    banner: String,
}

impl TemplateRegistry {
    /// 扫描目录加载全部模板。返回注册表 + 模板生成的额外监听器。
    /// 单模板失败只告警拒绝；root 不存在 = 无模板（正常空态，不告警）。
    pub fn load(
        root: &Path,
        occupied_ports: &[u16],
        bus: &EventBus,
    ) -> (Arc<Self>, Vec<ListenerConfig>) {
        let mut set = TemplateSet::default();
        let mut extra_listeners = Vec::new();
        let mut files: HashMap<String, Vec<WatchedFile>> = HashMap::new();
        if root.is_dir() {
            let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.path())
                        .filter(|p| p.is_dir())
                        .collect()
                })
                .unwrap_or_default();
            dirs.sort();
            let mut used_ports: Vec<u16> = occupied_ports.to_vec();
            for dir in dirs {
                let name = dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                match load_one(&name, &dir, &mut used_ports) {
                    Ok((tpl_http, tpl_banner, listener, watched)) => {
                        if let Some(http) = tpl_http {
                            set.http.insert(name.clone(), http);
                        }
                        if let Some(banner) = tpl_banner {
                            set.banners.insert(name.clone(), banner);
                        }
                        if let Some(listener) = listener {
                            extra_listeners.push(listener);
                        }
                        files.insert(name, watched);
                    }
                    Err(e) => {
                        // 整包哲学的单模板化：只拒绝这一个模板
                        bus.publish(SecurityEvent::engine(
                            "warn",
                            format!(
                                "模板 [{name}] 解析失败已拒绝（不影响其他模板与内置默认）: {e}"
                            ),
                        ));
                    }
                }
            }
        }
        bus.publish(SecurityEvent::engine(
            "info",
            format!(
                "模板加载完成: {} 个 http 页面模板 / {} 个 banner 模板 / {} 个新监听器",
                set.http.len(),
                set.banners.len(),
                extra_listeners.len()
            ),
        ));
        (
            Arc::new(Self {
                set: RwLock::new(set),
                root: root.to_path_buf(),
                files: Mutex::new(files),
                warned_new: Mutex::new(std::collections::HashSet::new()),
            }),
            extra_listeners,
        )
    }

    pub fn http_tpl(&self, listener: &str) -> Option<HttpTemplate> {
        self.set.read().ok()?.http.get(listener).cloned()
    }

    pub fn banner(&self, listener: &str) -> Option<String> {
        self.set.read().ok()?.banners.get(listener).cloned()
    }

    /// 周期轮询（mtime + 长度）：已知模板的内容变更 → 重读该模板（失败保留
    /// 上一份好内容并告警）；新增模板目录 → 告警提示需重启（监听器不能热增）。
    pub fn poll_reload(&self, bus: &EventBus) {
        let mut files = match self.files.lock() {
            Ok(f) => f,
            Err(_) => return,
        };
        for (name, watched) in files.iter_mut() {
            let mut changed = false;
            for (path, mtime, len) in watched.iter_mut() {
                let Ok(md) = std::fs::metadata(path.as_path()) else {
                    changed = true; // 文件被删：保留旧内容，告警
                    bus.publish(SecurityEvent::engine(
                        "warn",
                        format!(
                            "模板 [{name}] 的文件丢失: {}（沿用上一份内容）",
                            path.display()
                        ),
                    ));
                    continue;
                };
                let Ok(modified) = md.modified() else {
                    continue;
                };
                if md.len() != *len || modified != *mtime {
                    *mtime = modified;
                    *len = md.len();
                    changed = true;
                }
            }
            if changed {
                let dir = self.root.join(name);
                let mut used_ports = Vec::new();
                match load_one(name, &dir, &mut used_ports) {
                    Ok((tpl_http, tpl_banner, _listener, watched_new)) => {
                        let mut set = match self.set.write() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        match tpl_http {
                            Some(http) => {
                                set.http.insert(name.clone(), http);
                            }
                            None => {
                                set.http.remove(name);
                            }
                        }
                        match tpl_banner {
                            Some(banner) => {
                                set.banners.insert(name.clone(), banner);
                            }
                            None => {
                                set.banners.remove(name);
                            }
                        }
                        *watched = watched_new;
                        bus.publish(SecurityEvent::engine(
                            "info",
                            format!("模板 [{name}] 内容已热重载"),
                        ));
                    }
                    Err(e) => {
                        bus.publish(SecurityEvent::engine(
                            "warn",
                            format!("模板 [{name}] 热重载失败（沿用上一份内容）: {e}"),
                        ));
                    }
                }
            }
        }
        // 新模板目录出现 = 结构性变更，只能重启生效（告警去重：同一目录只发一次）
        if let Ok(rd) = std::fs::read_dir(&self.root) {
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let first_warn = !name.is_empty()
                    && !files.contains_key(&name)
                    && self
                        .warned_new
                        .lock()
                        .map(|mut s| s.insert(name.clone()))
                        .unwrap_or(false);
                if first_warn {
                    bus.publish(SecurityEvent::engine(
                        "warn",
                        format!("检测到新模板 [{name}]：增删模板需重启程序生效"),
                    ));
                }
            }
        }
    }
}

/// 加载单个模板。成功返回 (http 内容, banner 覆盖, 额外监听器, 关联文件)。
fn load_one(name: &str, dir: &Path, used_ports: &mut Vec<u16>) -> Result<LoadedTemplate, String> {
    let spec_path = dir.join("template.toml");
    let spec_text =
        std::fs::read_to_string(&spec_path).map_err(|e| format!("读取 template.toml 失败: {e}"))?;
    let spec: TemplateSpec =
        toml::from_str(&spec_text).map_err(|e| format!("template.toml 解析失败: {e}"))?;

    let mut watched: Vec<WatchedFile> = vec![(
        spec_path.clone(),
        file_stamp(&spec_path)?,
        file_len(&spec_path)?,
    )];

    // 端口冲突：与已有监听器或其他模板拒绝（沿用「占用检查启动拒绝」思路）。
    // 注意：只在成功时登记端口——失败的模板不得占坑
    if used_ports.contains(&spec.port) {
        return Err(format!("端口 {} 与已有监听器冲突", spec.port));
    }

    let listener = ListenerConfig {
        name: name.to_string(),
        port: spec.port,
        kind: spec.protocol.clone(),
        enabled: true,
    };
    let banner = match spec.protocol.as_str() {
        "ssh" | "telnet" => {
            if spec.banner.is_empty() {
                None // 用 [honeypot.fingerprint] 的全局默认
            } else {
                Some(spec.banner.clone())
            }
        }
        "http" => None,
        other => return Err(format!("不支持的模板协议: {other}")),
    };
    let http = if spec.protocol == "http" {
        if spec.page.is_empty() {
            return Err("http 模板缺少 page 字段".into());
        }
        let page_path = dir.join(&spec.page);
        let page = std::fs::read_to_string(&page_path)
            .map_err(|e| format!("页面文件 {} 读取失败: {e}", page_path.display()))?;
        watched.push((
            page_path,
            file_stamp(&dir.join(&spec.page))?,
            file_len(&dir.join(&spec.page))?,
        ));
        let split_keys = |raw: &str| {
            raw.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        Some(HttpTemplate {
            page,
            user_keys: split_keys(&spec.form_user),
            pass_keys: split_keys(&spec.form_pass),
            decoy_paths: spec.decoy_paths.clone(),
        })
    } else {
        None
    };
    used_ports.push(spec.port);
    Ok((http, banner, Some(listener), watched))
}

fn file_stamp(path: &Path) -> Result<SystemTime, String> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map_err(|e| format!("读取文件元数据失败 {}: {e}", path.display()))
}

fn file_len(path: &Path) -> Result<u64, String> {
    std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| format!("读取文件元数据失败 {}: {e}", path.display()))
}

/// 周期轮询任务（模板启用时启动；mtime+长度变化 → 内容热重载）
pub(crate) fn spawn_template_poller(registry: Arc<TemplateRegistry>, bus: EventBus) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(POLL_SECS));
            registry.poll_reload(&bus);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::start;
    use aisafeguard_core::config::HoneypotConfig;
    use aisafeguard_core::event::SecurityEvent;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn write_template(root: &Path, name: &str, toml_text: &str, page: Option<&str>) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("template.toml"), toml_text).unwrap();
        if let Some(p) = page {
            std::fs::write(dir.join("page.html"), p).unwrap();
        }
        dir
    }

    #[tokio::test]
    async fn load_isolates_broken_templates_and_detects_port_conflict() {
        let bus = EventBus::new(256);
        let mut rx = bus.subscribe();
        let root = std::env::temp_dir().join(format!("asg-tpl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let good = write_template(
            &root,
            "grafana",
            "protocol = \"http\"\nport = 3000\npage = \"page.html\"\nform_user = \"user\"\nform_pass = \"password\"\ndecoy_paths = []\n",
            Some("<html>GRAFANA-DECOY</html>"),
        );
        // 覆盖 decoy_paths（上面写错键名演示隔离不行——重新写正确的）
        std::fs::write(
            good.join("template.toml"),
            "protocol = \"http\"\nport = 3000\npage = \"page.html\"\nform_user = \"user\"\nform_pass = \"password\"\ndecoy_paths = []\n",
        )
        .unwrap();
        // 损坏模板：引用不存在的页面文件
        write_template(
            &root,
            "broken",
            "protocol = \"http\"\nport = 3001\npage = \"missing.html\"\n",
            None,
        );
        // 端口冲突模板：与 grafana 同端口
        write_template(
            &root,
            "conflict",
            "protocol = \"http\"\nport = 3000\npage = \"p.html\"\n",
            Some("<html>x</html>"),
        );

        let (registry, extra) = TemplateRegistry::load(&root, &[], &bus);
        assert_eq!(extra.len(), 1, "只加载有效模板: {extra:?}");
        assert_eq!(extra[0].name, "grafana");
        assert_eq!(extra[0].port, 3000);
        let tpl = registry.http_tpl("grafana").expect("有效模板应加载");
        assert!(tpl.page.contains("GRAFANA-DECOY"));
        assert!(tpl.user_keys.contains(&"user".to_string()));
        assert!(registry.http_tpl("broken").is_none());

        // 两个拒绝事件（损坏 + 端口冲突）
        let mut rejects = 0;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Ok(SecurityEvent::Engine { message, .. })) => {
                    if message.contains("已拒绝") {
                        rejects += 1;
                    }
                    if rejects == 2 {
                        break;
                    }
                }
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
        assert_eq!(rejects, 2, "损坏与冲突模板都应有拒绝告警");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ssh_template_overrides_banner() {
        let bus = EventBus::new(64);
        let root = std::env::temp_dir().join(format!("asg-tpl-ssh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write_template(
            &root,
            "fake-ssh",
            "protocol = \"ssh\"\nport = 2299\nbanner = \"SSH-2.0-OpenSSH_9.2\"\n",
            None,
        );
        let (registry, extra) = TemplateRegistry::load(&root, &[], &bus);
        assert_eq!(extra.len(), 1);
        assert_eq!(
            registry.banner("fake-ssh").as_deref(),
            Some("SSH-2.0-OpenSSH_9.2")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// H300 端到端：模板监听器对外服务页面，敏感路径 403，事件带 template 标签
    #[tokio::test]
    async fn template_listener_serves_page_and_tags_event() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let root = std::env::temp_dir().join(format!("asg-tpl-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write_template(
            &root,
            "oa",
            &format!(
                "protocol = \"http\"\nport = {port}\npage = \"page.html\"\nform_user = \"account\"\nform_pass = \"secret\"\ndecoy_paths = [\"/api/admin\"]\n"
            ),
            Some("<html><body>OFFICE-LOGIN-DECOY</body></html>"),
        );

        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            templates: aisafeguard_core::config::TemplatesConfig {
                enabled: true,
                dir: root.display().to_string(),
            },
            listeners: vec![],
            ..Default::default()
        };
        let _handle = start(&cfg, bus, &std::env::temp_dir());
        // 等模板监听器 bind
        let mut conn = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(c) => {
                    conn = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        let mut c = conn.expect("模板监听器未就绪");
        c.write_all(b"GET /login HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp).await;
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "实际: {text}");
        assert!(text.contains("OFFICE-LOGIN-DECOY"));
        drop(c);

        // POST 提交 → 200 模板页 + template 标签事件
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        c.write_all(
            b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\naccount=bob&secret=pw",
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp).await;
        drop(c);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_template_tag = false;
        let mut saw_credential = false;
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Ok(SecurityEvent::HoneypotHit {
                    summary,
                    http_hint,
                    interaction,
                    ..
                })) => {
                    if let Some(hint) = &http_hint
                        && hint.tags.contains(&"template".to_string())
                    {
                        saw_template_tag = true;
                    }
                    if interaction.is_none() && summary.contains("POST") && http_hint.is_some() {
                        // 凭证采集:模板表单字段(account/secret)也应被采集
                        saw_credential = summary.contains("bob") || summary.contains("bob=");
                    }
                }
                Ok(Ok(SecurityEvent::CredentialObserved {
                    username,
                    pass_hash,
                    ..
                })) => {
                    assert_eq!(username, "bob");
                    assert!(pass_hash.is_some(), "模板表单口令应被哈希采集");
                    saw_credential = true;
                }
                Ok(Ok(_)) => {}
                _ => break,
            }
            if saw_template_tag && saw_credential {
                break;
            }
        }
        assert!(saw_template_tag, "应产生 template 标签事件");
        assert!(saw_credential, "模板表单字段应进凭证采集");
        let _ = std::fs::remove_dir_all(&root);
    }
}
