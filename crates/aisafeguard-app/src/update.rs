//! 应用自更新（0.8.2，Windows 一键升级）。
//!
//! 两条路径共用同一套底层：
//! - **检查更新**：Gitee Release API 优先、GitHub 兜底，取 `aisafeguard-windows-x64.zip`
//!   与同名 `.sha256` 的下载地址，与本地 `CARGO_PKG_VERSION` 比较；
//! - **应用升级**（需管理员，UAC 由 GUI/CLI 发起时弹出）：停服务 → 备份旧 exe →
//!   覆盖服务二进制 → 重启服务；GUI 副本（若与服务不同路径）用"改名腾位再复制"刷新。
//!
//! 单二进制设计：服务与 GUI 是同一个 exe——升级服务即升级程序本体。
//! GUI 里的入口在「设置 → 关于 → 更新」；CLI 入口 `aisafeguard self-update [--check]`。
//!
//! 为什么由"新版 exe 自己"执行替换：正在运行的映像文件不可覆盖，但改名可以——
//! 所以替换动作交给下载好的新版本（不在运行），旧 GUI 在发起后立即退出让位。

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Release 源：Gitee 优先（国内直连稳），GitHub 兜底。两者 API 返回同形 JSON。
const SOURCES: [&str; 2] = [
    "https://gitee.com/api/v5/repos/coolinger/ai-safe-guard/releases/latest",
    "https://api.github.com/repos/coolinger2019-wq/AI-SafeGuard/releases/latest",
];
const ZIP_NAME: &str = "aisafeguard-windows-x64.zip";

#[derive(Debug, Clone)]
pub struct Release {
    /// 去掉 v 前缀的纯版本号，如 "0.8.2"
    pub version: String,
    pub zip_url: String,
    pub sha_url: Option<String>,
    /// 该源是否经环境代理取到（下载沿用同一网络路径）
    pub prefer_proxy: bool,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// 解析 "v0.8.2" / "0.8.2" / "0.8.2-pre" → (0,8,2)；解析失败返回 None。
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().trim_start_matches(['v', 'V']);
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// 从 release API 的 JSON 提取升级信息（Gitee/GitHub 同形，便于单测）。
fn release_from_json(raw: &str) -> Result<Release> {
    let api: ApiRelease =
        serde_json::from_str(raw).map_err(|e| anyhow!("release JSON 解析失败: {e}"))?;
    let zip = api
        .assets
        .iter()
        .find(|a| a.name == ZIP_NAME)
        .ok_or_else(|| anyhow!("release 里没有 {ZIP_NAME}"))?
        .browser_download_url
        .clone();
    let sha = api
        .assets
        .iter()
        .find(|a| a.name == format!("{ZIP_NAME}.sha256"))
        .map(|a| a.browser_download_url.clone());
    let version = api
        .tag_name
        .trim_start_matches(['v', 'V'])
        .trim()
        .to_string();
    if parse_version(&version).is_none() {
        bail!("无法解析远端版本号: {}", api.tag_name);
    }
    Ok(Release {
        version,
        zip_url: zip,
        sha_url: sha,
        prefer_proxy: false,
    })
}

fn http(prefer_proxy: bool) -> Result<reqwest::blocking::Client> {
    // 环境代理可能是失效的（本机曾长期挂着死 7890 变量）：Gitee 一律先直连，
    // GitHub 先走环境代理（国内常需要），各留一条兜底路径。谁成功用谁下载。
    let mut b = reqwest::blocking::Client::builder()
        .user_agent("aisafeguard-self-update")
        .connect_timeout(std::time::Duration::from_secs(30))
        // 慢链路下载 14MB 可能要几分钟，总超时放宽；连接失败快速暴露
        .timeout(std::time::Duration::from_secs(600));
    if !prefer_proxy {
        b = b.no_proxy();
    }
    b.build().context("HTTP 客户端构建失败")
}

/// 取最新 release 信息（不与本地版本比较）。供 check_latest 与网络 E2E 测试共用。
fn fetch_latest_release() -> Result<Release> {
    let attempts = [
        (SOURCES[0], false),
        (SOURCES[0], true),
        (SOURCES[1], true),
        (SOURCES[1], false),
    ];
    let mut last_err = None;
    let mut rel = None;
    for (url, prefer_proxy) in attempts {
        let cli = http(prefer_proxy)?;
        match cli
            .get(url)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.text())
        {
            Ok(text) => match release_from_json(&text) {
                Ok(mut r) => {
                    r.prefer_proxy = prefer_proxy;
                    rel = Some(r);
                    break;
                }
                Err(e) => last_err = Some(e),
            },
            Err(e) => last_err = Some(anyhow!("{url}: {e}")),
        }
    }
    match rel {
        Some(r) => Ok(r),
        None => Err(last_err.unwrap_or_else(|| anyhow!("所有更新源都不可用"))),
    }
}

/// 检查最新版本。返回 Ok(Some(release)) = 有更新；Ok(None) = 已是最新。
pub fn check_latest() -> Result<Option<Release>> {
    let rel = fetch_latest_release()?;
    let cur = parse_version(current_version()).ok_or_else(|| anyhow!("本地版本号异常"))?;
    let new = parse_version(&rel.version).expect("release_from_json 已校验");
    Ok(if new > cur { Some(rel) } else { None })
}

/// 下载 zip（+sha256 校验）并解出 aisafeguard.exe。progress 收到 0-100 的百分比。
/// 解压走 PowerShell Expand-Archive（系统自带，不引 zip 依赖）。
/// 目前仅 Windows 有"应用内升级"语义：其他平台直接报错，不做无谓下载。
pub fn download_and_prepare(
    rel: &Release,
    workdir: &std::path::Path,
    progress: &dyn Fn(u8),
) -> Result<std::path::PathBuf> {
    if !cfg!(windows) {
        bail!("应用内升级目前仅支持 Windows（Linux 用 install.sh / deploy.sh）");
    }
    std::fs::create_dir_all(workdir).context("创建更新工作目录失败")?;
    let zip_path = workdir.join(ZIP_NAME);
    let cli = http(rel.prefer_proxy)?;
    download_to(&cli, &rel.zip_url, &zip_path, progress)?;

    // sha256 校验（.sha256 内容形如 "<hex>  <文件名>"，与 GitHub/Gitee 发布物一致）
    if let Some(sha_url) = &rel.sha_url {
        let sha_text = cli
            .get(sha_url)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.text())
            .context("下载校验文件失败")?;
        let want = sha_text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();
        let got = sha256_hex(&zip_path)?;
        if want.len() == 64 && want != got {
            bail!("SHA-256 校验失败：期望 {want}，实际 {got}");
        }
    }

    let dest = workdir.join("extracted");
    // ps_quote 自带单引号（并做 ' → '' 转义），这里不要再包一层
    let script = format!(
        "Expand-Archive -LiteralPath {} -DestinationPath {} -Force",
        ps_quote(&zip_path),
        ps_quote(&dest)
    );
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .context("启动 PowerShell 解压失败")?;
    if !out.status.success() {
        bail!("解压失败: {}", String::from_utf8_lossy(&out.stderr).trim());
    }

    let exe = std::fs::read_dir(&dest)?
        .filter_map(|e| e.ok())
        .find(|e| {
            e.file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case("aisafeguard.exe")
        })
        .map(|e| e.path())
        .ok_or_else(|| anyhow!("解压后没有 aisafeguard.exe"))?;
    Ok(exe)
}

fn download_to(
    cli: &reqwest::blocking::Client,
    url: &str,
    dest: &std::path::Path,
    progress: &dyn Fn(u8),
) -> Result<()> {
    let mut resp = cli
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .context("下载失败")?;
    let total = resp.content_length().unwrap_or(0);
    let mut file = std::io::BufWriter::new(
        std::fs::File::create(dest).with_context(|| format!("创建 {dest:?} 失败"))?,
    );
    // blocking Response 实现了 Read：分块读以汇报进度
    use std::io::{Read as _, Write};
    let mut received: u64 = 0;
    let mut last_percent: u8 = 0;
    let mut buf = [0u8; 65536];
    loop {
        let n = resp.read(&mut buf).context("下载中断")?;
        if n == 0 {
            break; // EOF：正常结束
        }
        file.write_all(&buf[..n])?;
        received += n as u64;
        if total > 0 {
            let p = received
                .min(total)
                .checked_mul(100)
                .map(|v| (v / total) as u8)
                .unwrap_or(100);
            if p != last_percent {
                last_percent = p;
                progress(p);
            }
        }
    }
    file.flush()?;
    Ok(())
}

fn sha256_hex(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path).with_context(|| format!("读取 {path:?} 失败"))?;
    let mut h = Sha256::new();
    h.update(&data);
    Ok(format!("{:x}", h.finalize()))
}

/// PowerShell 单引号字符串：' → ''（不插值）。
fn ps_quote(p: &std::path::Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "''"))
}

/// 以管理员身份启动"新版 exe 自己"执行替换（UAC 弹窗）。
/// 返回 Ok 表示 UAC 已同意且升级进程已拉起；Err 表示被取消或启动失败。
pub fn spawn_elevated_apply(
    new_exe: &std::path::Path,
    workdir: &std::path::Path,
    relaunch_gui: bool,
) -> Result<(), String> {
    let mut args = vec![
        ps_quote(new_exe),
        "--apply-update".to_string(),
        ps_quote(workdir),
    ];
    if let Ok(gui) = std::env::current_exe() {
        args.push("--gui-path".to_string());
        args.push(ps_quote(&gui));
    }
    if relaunch_gui {
        args.push("--relaunch-gui".to_string());
    }
    let script = format!(
        "Start-Process -Verb RunAs -FilePath {} -ArgumentList {}",
        ps_quote(new_exe),
        args.join(",")
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if msg.is_empty() {
            "UAC 升级未完成（可能已取消）".to_string()
        } else {
            msg
        })
    }
}

/// CLI：`aisafeguard self-update [--check]`。
pub fn cmd_self_update(check_only: bool) -> Result<()> {
    println!("检查更新（Gitee → GitHub）...");
    let Some(rel) = check_latest()? else {
        println!("已是最新版本 v{}，无需升级", current_version());
        return Ok(());
    };
    println!("发现新版本 v{}：{}", rel.version, rel.zip_url);
    if check_only {
        return Ok(());
    }
    let workdir = update_workdir();
    let exe = download_and_prepare(&rel, &workdir, &|p| {
        print!("\r下载 {p}% ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    })?;
    println!();
    println!("即将弹出 UAC 提权窗口，确认后自动完成升级（停服务 → 替换 → 重启服务）。");
    spawn_elevated_apply(&exe, &workdir, false).map_err(|e| anyhow!("{e}"))?;
    println!("升级进程已启动；完成后此窗口可关闭。");
    Ok(())
}

/// CLI/GUI 共用的工作目录名（同一 tag 只生成一次）。
pub fn update_workdir() -> std::path::PathBuf {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    std::env::temp_dir().join(format!("aisafeguard-update-{ts}"))
}

/// 提权后的替换执行体：`aisafeguard --apply-update <workdir> [--gui-path <p>] [--relaunch-gui]`。
/// 必须已提权；由 spawn_elevated_apply 拉起的新版 exe 自己运行。
#[cfg(windows)]
pub fn cmd_apply(
    workdir: &std::path::Path,
    gui_path: Option<&std::path::Path>,
    relaunch_gui: bool,
) -> Result<()> {
    if !aisafeguard_firewall::create_backend().is_elevated() {
        bail!("需要管理员权限：请从 GUI 的「设置 → 关于 → 更新」发起升级");
    }
    let new_exe = workdir.join("aisafeguard.exe");
    if !new_exe.exists() {
        bail!("升级目录里没有 aisafeguard.exe: {}", workdir.display());
    }
    println!(
        "AI-SafeGuard v{} 升级中（停服务 → 备份 → 替换 → 重启服务）...",
        current_version()
    );

    // 1) 服务侧
    let mut svc_path: Option<std::path::PathBuf> = None;
    match crate::service::binary_path() {
        Ok(svc) => {
            println!("  服务二进制: {}", svc.display());
            crate::service::stop()?;
            crate::service::wait_state(windows_service::service::ServiceState::Stopped, 60)?;
            let backup_dir = svc.parent().unwrap_or(workdir).join("backup");
            std::fs::create_dir_all(&backup_dir)?;
            let backup = backup_dir.join(format!(
                "aisafeguard-{}.exe",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            std::fs::copy(&svc, &backup)
                .with_context(|| format!("备份旧 exe 失败: {}", svc.display()))?;
            println!("  旧版已备份: {}", backup.display());
            // GUI 进程可能还没退干净（映像锁），重试至多 10 秒
            let mut copied = false;
            for _ in 0..20 {
                if std::fs::copy(&new_exe, &svc).is_ok() {
                    copied = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            if !copied {
                bail!("覆盖服务二进制失败（文件被占用）：请关闭所有 aisafeguard 窗口后重试");
            }
            crate::service::start()?;
            crate::service::wait_state(windows_service::service::ServiceState::Running, 90)?;
            println!("  服务已重启并运行（v{}）", current_version());
            svc_path = Some(svc);
        }
        Err(_) => {
            println!("  未安装 Windows 服务：跳过服务升级（只刷新界面副本）");
        }
    }

    // 2) GUI 副本（与服务不同路径时刷新；同名即服务路径本身，已替换过）
    if let Some(gui) = gui_path {
        let same_as_svc = svc_path.as_ref().is_some_and(|s| s.as_path() == gui);
        if !same_as_svc && gui.exists() {
            let old = gui.with_extension(format!(
                "exe.old-{}",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            match std::fs::rename(gui, &old).and_then(|_| std::fs::copy(&new_exe, gui)) {
                Ok(_) => println!("  界面副本已更新: {}", gui.display()),
                Err(e) => println!("  界面副本未更新（文件被占用，可手动替换）: {e}"),
            }
        }
    }

    // 3) 重新打开界面（经 explorer 启动 = 非提权，与服务分离）
    if relaunch_gui && let Some(exe) = svc_path.as_deref().or(gui_path) {
        let _ = std::process::Command::new("explorer.exe").arg(exe).spawn();
    }

    let _ = std::fs::remove_dir_all(workdir);
    println!("升级完成，此窗口可关闭。");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse() {
        assert_eq!(parse_version("0.8.2"), Some((0, 8, 2)));
        assert_eq!(parse_version("v0.8.2"), Some((0, 8, 2)));
        assert_eq!(parse_version("0.6.1-pre"), Some((0, 6, 1)));
        assert_eq!(parse_version("garbage"), None);
        assert!(parse_version("0.8.2") > parse_version("0.8.1"));
    }

    #[test]
    fn release_from_gitee_json() {
        let raw = r#"{
            "tag_name": "v0.8.2",
            "assets": [
                {"name": "aisafeguard", "browser_download_url": "https://g/aisafeguard"},
                {"name": "aisafeguard-windows-x64.zip", "browser_download_url": "https://g/zip"},
                {"name": "aisafeguard-windows-x64.zip.sha256", "browser_download_url": "https://g/zip.sha"}
            ]
        }"#;
        let rel = release_from_json(raw).expect("解析成功");
        assert_eq!(rel.version, "0.8.2");
        assert_eq!(rel.zip_url, "https://g/zip");
        assert_eq!(rel.sha_url.as_deref(), Some("https://g/zip.sha"));
    }

    #[test]
    fn release_missing_zip_is_error() {
        let raw =
            r#"{"tag_name":"v0.8.2","assets":[{"name":"aisafeguard","browser_download_url":"x"}]}"#;
        assert!(release_from_json(raw).is_err());
    }

    #[test]
    fn sha256_hex_known_vector() {
        let dir = std::env::temp_dir().join(format!("asg-update-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("probe.txt");
        std::fs::write(&f, b"hello").unwrap();
        assert_eq!(
            sha256_hex(&f).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 下载 → sha256 校验 → 解压 → 解出的 exe 能跑 --version 的全链路。
    /// 网络测试：`cargo test --bin aisafeguard download_e2e -- --ignored`
    #[test]
    #[ignore = "网络 E2E（真实访问 Gitee/GitHub 与 14MB 下载）"]
    fn download_e2e() {
        let rel = fetch_latest_release().expect("取最新 release");
        let workdir = update_workdir();
        let last = std::cell::Cell::new(0u8);
        let exe = download_and_prepare(&rel, &workdir, &|p| last.set(p)).expect("下载+解压");
        assert!(exe.exists(), "解出的 aisafeguard.exe 应存在");
        assert_eq!(last.get(), 100, "进度应到达 100%");
        let out = std::process::Command::new(&exe)
            .arg("--version")
            .output()
            .expect("运行解出的 exe");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(&format!("aisafeguard {}", rel.version)),
            "解出的应是 v{}，实际输出: {text}",
            rel.version
        );
        let _ = std::fs::remove_dir_all(&workdir);
    }
}
