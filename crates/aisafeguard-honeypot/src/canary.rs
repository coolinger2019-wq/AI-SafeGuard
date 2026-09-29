//! 蜜饵 canary（0.5.10 H210）：主动埋雷。HTTP 蜜饵由 [`crate::http`] 按内置
//! 诱饵资源表下发（本模块提供水印状态）；文件系统蜜饵在本模块（v1 仅 Linux，
//! notify/inotify 只读监听「文件被读取」——Windows 用户态无对等通知 API，
//! ReadDirectoryChangesW 只报属性/名称变更，v1 不做打折的伪对等）。
//!
//! 红线：诱饵内容全部合成（结构对齐真实文件、数据为零值/明显假数据）；
//! 配置的 fs 路径已存在 = 可能是真实文件 → 拒绝该条并告警，绝不覆盖。

use std::path::Path;
// PathBuf 仅 Linux 蜜饵放置逻辑使用
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::sync::Arc;

use aisafeguard_core::canary::{CanaryPayload, make_token};
use aisafeguard_core::event::{EventBus, SecurityEvent};
use aisafeguard_core::now_ts;

/// HTTP/文件系统蜜饵共享的水印状态。
pub(crate) struct CanaryState {
    key: Vec<u8>,
    node: String,
    deployed_ts: i64,
}

impl CanaryState {
    /// 密钥来源：配置显式 key 优先；否则 <data_dir>/honeypot/canary.key
    /// （缺失生成 32 字节随机值的 hex，0600——host key 同款落盘纪律）。
    /// canary-decode 读同一文件，保证离线可溯源。
    pub fn resolve(key_cfg: &str, data_dir: &Path) -> std::io::Result<CanaryState> {
        let key = if key_cfg.is_empty() {
            let path = data_dir.join("honeypot").join("canary.key");
            std::fs::read_to_string(&path)
                .map(|s| s.trim().to_string())
                .or_else(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        generate_key_file(&path)
                    } else {
                        Err(e)
                    }
                })?
        } else {
            key_cfg.to_string()
        };
        Ok(CanaryState {
            key: key.into_bytes(),
            node: aisafeguard_core::canary::node_id(),
            deployed_ts: now_ts(),
        })
    }

    /// 某蜜饵资源的水印 token（投放时间 = 引擎本次启动时刻）
    pub fn token(&self, res: &str) -> Option<String> {
        make_token(
            &self.key,
            &CanaryPayload {
                node: self.node.clone(),
                ts: self.deployed_ts,
                res: res.to_string(),
            },
        )
    }
}

/// 生成 32 字节随机密钥（hex 存储），0600 落盘（Unix）。
fn generate_key_file(path: &Path) -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    // rand 已在依赖树（russh host key 同款用法）；0.10 起统一为 Rng trait
    use rand::Rng;
    rand::rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(hex.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, hex.as_bytes())?;
    Ok(hex)
}

// ---------- 文件系统蜜饵（v1 仅 Linux） ----------

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// 蜜饵读取事件的 60s 去重窗口：正常业务进程批量扫描目录时会反复触发
/// IN_OPEN/IN_ACCESS，不压制会高频刷屏（负路径「诱饵误读抑制」）。
const FS_DEDUP_SECS: i64 = 60;

/// 放置文件系统蜜饵并启动只读监控（v1 仅 Linux；Windows 降级告警）。
/// 路径已存在/父目录缺失 → 拒绝该条并留 engine 事件（不中断其他蜜饵）。
/// 返回实际放置成功的条数。
#[cfg(target_os = "linux")]
pub(crate) fn place_and_watch_fs_canaries(
    paths: &[String],
    bus: &EventBus,
    canary: &Arc<CanaryState>,
) -> usize {
    let mut watched: Vec<PathBuf> = Vec::new();
    for raw in paths {
        let path = PathBuf::from(raw.trim());
        let (level, note) = match validate_fs_path(&path) {
            Ok(()) => {
                let content = fs_canary_content(&path, canary);
                match std::fs::write(&path, content) {
                    Ok(()) => {
                        watched.push(path.clone());
                        ("info", format!("蜜饵文件已放置: {}", path.display()))
                    }
                    Err(e) => (
                        "warn",
                        format!("蜜饵文件写入失败 {}: {e}", path.display()),
                    ),
                }
            }
            Err(e) => (
                "warn",
                format!("蜜饵路径被拒绝 {}: {e}", path.display()),
            ),
        };
        bus.publish(SecurityEvent::engine(level, note));
    }
    if watched.is_empty() {
        return 0;
    }
    start_fs_watcher(watched, bus.clone(), canary.clone())
}

/// Windows v1 降级：不写文件、不监听，只明示不支持（README/THREAT_MODEL 同口径）。
#[cfg(not(target_os = "linux"))]
pub(crate) fn place_and_watch_fs_canaries(
    paths: &[String],
    bus: &EventBus,
    _canary: &Arc<CanaryState>,
) -> usize {
    bus.publish(SecurityEvent::engine(
        "warn",
        format!(
            "文件系统蜜饵仅 Linux 支持（v1），已忽略 {} 条路径配置",
            paths.len()
        ),
    ));
    0
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// 路径合法性：已存在（可能真实文件）或父目录缺失 → Err
fn validate_fs_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("路径为空".into());
    }
    if path.exists() {
        return Err("路径已存在（可能是真实文件，不覆盖）".into());
    }
    if path.parent().is_none_or(|p| !p.is_dir()) {
        return Err("父目录不存在".into());
    }
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// 按扩展名选合成诱饵模板（{token} 占位）。全部零值/明显假数据。
fn fs_canary_content(path: &Path, canary: &CanaryState) -> String {
    let token = canary
        .token(&path.display().to_string())
        .unwrap_or_else(|| "AC1.<水印不可用>".into());
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let tpl = if name.ends_with(".env") {
        "# Deployment environment\nDB_HOST=127.0.0.1\nDB_PORT=0\nDB_USER=deploy\nDB_PASS=DECOY-NOT-A-REAL-SECRET\n# {token}\n"
    } else if name.ends_with(".yml") || name.ends_with(".yaml") {
        "server:\n  port: 0\n  host: 127.0.0.1\ndebug: false\ncredentials: DECOY-NOT-A-REAL-SECRET\n# {token}\n"
    } else {
        "# AUTO-GENERATED DECOY FILE — 数据为零值，不是真实配置\n# {token}\n"
    };
    tpl.replace("{token}", &token)
}

/// 只读监听诱饵文件的读取行为（Linux inotify Access 事件），触发即发蜜罐事件。
#[cfg(target_os = "linux")]
fn start_fs_watcher(paths: Vec<PathBuf>, bus: EventBus, canary: Arc<CanaryState>) -> usize {    use notify::Watcher;
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            bus.publish(SecurityEvent::engine(
                "error",
                format!("文件系统蜜饵监听初始化失败（inotify 不可用？）: {e}"),
            ));
            return 0;
        }
    };
    for p in &paths {
        if let Err(e) = watcher.watch(p, notify::RecursiveMode::NonRecursive) {
            bus.publish(SecurityEvent::engine(
                "warn",
                format!("蜜饵监听失败 {}: {e}", p.display()),
            ));
        }
    }
    // notify 回调是同步的：独立 OS 线程搬运事件；watcher 必须保活（drop 即停）
    std::thread::spawn(move || {
        let mut last_fired: std::collections::HashMap<PathBuf, i64> =
            std::collections::HashMap::new();
        for event in rx {
            let Ok(event) = event else { continue };
            let is_access = matches!(event.kind, notify::EventKind::Access(_));
            if !is_access {
                continue;
            }
            let now = now_ts();
            for p in event.paths {
                let fired_at = last_fired.get(&p).copied().unwrap_or(0);
                if now - fired_at < FS_DEDUP_SECS {
                    continue;
                }
                last_fired.insert(p.clone(), now);
                if last_fired.len() > 4096 {
                    last_fired.retain(|_, t| now - *t < FS_DEDUP_SECS);
                }
                let display = p.display().to_string();
                let token = canary
                    .token(&display)
                    .unwrap_or_else(|| "AC1.<水印不可用>".into());
                bus.publish(SecurityEvent::HoneypotHit {
                    ts: now,
                    listener: "canary-fs".into(),
                    kind: "canary".into(),
                    port: 0,
                    remote_ip: "local".into(),
                    remote_port: 0,
                    summary: format!("蜜饵文件被读取: {display}（水印 {token}）"),
                    payload: display,
                    http_hint: None,
                    interaction: None,
                });
            }
        }
    });
    paths.len()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_generates_persistent_key_file() {
        let dir = std::env::temp_dir().join(format!("asg-canary-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = CanaryState::resolve("", &dir).expect("首次应生成密钥文件");
        let key_path = dir.join("honeypot").join("canary.key");
        assert!(key_path.exists(), "canary.key 应落盘");
        let saved = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(saved.len(), 64, "32 字节随机值的 hex");
        // 重启复用同一密钥：token 可继续解码（同一 key → 相同 token）
        let token = state.token("backup.zip").unwrap();
        let state2 = CanaryState::resolve("", &dir).unwrap();
        assert_eq!(state2.token("backup.zip").unwrap(), token);
        // 配置显式密钥优先，不读文件
        let state3 = CanaryState::resolve("my-key", &dir).unwrap();
        assert_ne!(state3.token("backup.zip").unwrap(), token);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_content_is_synthetic_and_watermarked() {
        let state = CanaryState::resolve("k", &std::env::temp_dir()).unwrap();
        let content = fs_canary_content(Path::new("/tmp/app/.env"), &state);
        assert!(content.contains("DECOY"), "应含明显假数据标记");
        assert!(content.contains("AC1."), "应含水印 token");
    }

    #[test]
    fn fs_path_validation_rejects_existing_and_missing_parent() {
        let existing = std::env::temp_dir().join("asg-canary-exists");
        std::fs::write(&existing, b"x").unwrap();
        assert!(validate_fs_path(&existing).is_err(), "已存在路径必须拒绝");
        let _ = std::fs::remove_file(&existing);
        let orphan = std::env::temp_dir().join(format!("no-such-dir-{}", std::process::id())).join("x.env");
        assert!(validate_fs_path(&orphan).is_err(), "父目录缺失必须拒绝");
    }
}
