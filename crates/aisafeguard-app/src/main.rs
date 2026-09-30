mod api;
mod console;
mod engine;
mod explain;
mod fed;
mod forward;
mod gui;
#[cfg(windows)]
mod service;
#[cfg(not(windows))]
mod service {
    pub fn service_data_dir() -> Option<std::path::PathBuf> {
        None
    }

    pub fn unsupported() -> anyhow::Result<()> {
        anyhow::bail!("Windows 服务管理当前仅支持 Windows")
    }
}

/// Linux systemd 服务安装：写 unit（数据目录 /var/lib/aisafeguard）+ 启用自启动。
/// systemd 未运行（如未启用 systemd 的 WSL）时照写 unit 并提示。
#[cfg_attr(windows, allow(dead_code))] // Windows 上该命令在编译期就拒绝
fn install_systemd_unit() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let unit = format!(
        "[Unit]
Description=AI-SafeGuard Engine
After=network.target

[Service]
ExecStart={} --headless --data-dir /var/lib/aisafeguard
Restart=on-failure
RestartSec=5
User=root
# 最小权限（0.4.0 A2）：白名单式授权 + 禁止提权。
#   CAP_NET_ADMIN —— nftables 封禁（inet aisafeguard 表）
#   CAP_NET_RAW   —— AF_PACKET 采样捕获（[detect.capture].enabled=true 才需要）
#   两个能力都不用（仅蜜罐+API，且蜜罐端口>1024）时可将 AmbientCapabilities
#   整行删除，服务降级为无特权运行（捕获/封禁功能自动降级并留事件）。
#   进一步收权可改 User= 为专用低权用户（需 chown /var/lib/aisafeguard）。
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
",
        exe.display(),
    );
    std::fs::create_dir_all("/var/lib/aisafeguard")?;
    std::fs::write("/etc/systemd/system/aisafeguard.service", unit)?;
    let running = std::process::Command::new("systemctl")
        .args(["is-system-running"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "running")
        .unwrap_or(false);
    if !running {
        println!("unit 文件已写入 /etc/systemd/system/aisafeguard.service");
        println!(
            "⚠ systemd 未运行：启用后执行 sudo systemctl daemon-reload && sudo systemctl enable --now aisafeguard"
        );
        return Ok(());
    }
    let ok = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status()?
        .success()
        && std::process::Command::new("systemctl")
            .args(["enable", "--now", "aisafeguard"])
            .status()?
            .success();
    if ok {
        println!("✓ 服务已安装并启动（systemctl status aisafeguard 查看）");
        Ok(())
    } else {
        anyhow::bail!("systemctl 启用失败，请检查 systemd 日志")
    }
}
mod remote;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use aisafeguard_core::config::AppConfig;
use aisafeguard_core::event::{EventBus, SecurityEvent};
// secrets 只在 Windows 凭据管理器分支用到（Linux 落文件，见 load_or_create_token）
#[cfg(windows)]
use aisafeguard_core::secrets;
use aisafeguard_store::{CredentialStore, Store};
use console::Console;
use engine::EngineHandle;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> anyhow::Result<()> {
    let mut headless = false;
    let mut uac_child = false;
    let mut service_mode = false;
    let mut print_token = false;
    let mut cfg_path: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut command: Option<(String, Option<String>)> = None;
    let mut fed_sans: Vec<String> = Vec::new();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--headless" => headless = true,
            // 提权重启后的子进程标记：跳过再次提权（防循环）
            "--uac-child" => uac_child = true,
            "--service" => service_mode = true,
            "--print-token" => print_token = true,
            "--version" => {
                println!("aisafeguard {VERSION}");
                println!("© 2026 coolinger · vibe coding · MIT License");
                return Ok(());
            }
            "--config" => {
                i += 1;
                cfg_path = args.get(i).map(PathBuf::from);
            }
            "--data-dir" => {
                i += 1;
                data_dir = args.get(i).map(PathBuf::from);
            }
            "verify-log" => command = Some(("verify-log".into(), None)),
            "canary-decode" => {
                i += 1;
                match args.get(i) {
                    Some(t) => command = Some(("canary-decode".into(), Some(t.clone()))),
                    None => {
                        eprintln!("用法: aisafeguard canary-decode <token>");
                        std::process::exit(2);
                    }
                }
            }
            "export-events" => {
                i += 1;
                match args.get(i) {
                    Some(p) => command = Some(("export-events".into(), Some(p.clone()))),
                    None => {
                        eprintln!("用法: aisafeguard export-events <输出.jsonl>");
                        std::process::exit(2);
                    }
                }
            }
            "fed" => {
                i += 1;
                match args.get(i).map(|s| s.as_str()) {
                    Some("init-ca") => command = Some(("fed-init-ca".into(), None)),
                    Some("issue-cert") => {
                        i += 1;
                        match args.get(i) {
                            Some(node) => {
                                command = Some(("fed-issue-cert".into(), Some(node.clone())))
                            }
                            None => {
                                eprintln!(
                                    "用法: aisafeguard fed issue-cert <node> [--san <dns|ip> ...]"
                                );
                                std::process::exit(2);
                            }
                        }
                    }
                    Some("revoke") => {
                        i += 1;
                        match args.get(i) {
                            Some(target) => {
                                command = Some(("fed-revoke".into(), Some(target.clone())))
                            }
                            None => {
                                eprintln!("用法: aisafeguard fed revoke <节点名|指纹> [原因]");
                                std::process::exit(2);
                            }
                        }
                    }
                    Some("audit") => {
                        i += 1;
                        match args.get(i) {
                            Some(out) => command = Some(("fed-audit".into(), Some(out.clone()))),
                            None => {
                                eprintln!("用法: aisafeguard fed audit <out.json> [窗口秒=604800]");
                                std::process::exit(2);
                            }
                        }
                    }
                    Some("expect") => {
                        i += 1;
                        match (args.get(i), args.get(i + 1)) {
                            (Some(node), Some(fp)) => {
                                i += 1;
                                command =
                                    Some(("fed-expect".into(), Some(format!("{node}\u{1}{fp}"))));
                            }
                            _ => {
                                eprintln!("用法: aisafeguard fed expect <node> <指纹>");
                                std::process::exit(2);
                            }
                        }
                    }
                    _ => {
                        eprintln!(
                            "用法: aisafeguard fed init-ca | issue-cert <node> [--san ...] | revoke <node|fp> [原因] | expect <node> <fp> | audit <out.json>"
                        );
                        std::process::exit(2);
                    }
                }
            }
            "--san" => {
                i += 1;
                match args.get(i) {
                    Some(v) => fed_sans.push(v.clone()),
                    None => {
                        eprintln!("--san 需要一个值（DNS 名或 IP）");
                        std::process::exit(2);
                    }
                }
            }
            "service" => {
                i += 1;
                match args.get(i).map(|s| s.as_str()) {
                    Some(w @ ("install" | "uninstall" | "start" | "stop" | "install-systemd")) => {
                        command = Some((format!("service-{w}"), None))
                    }
                    _ => {
                        eprintln!(
                            "用法: aisafeguard service install|uninstall|start|stop (Windows)"
                        );
                        eprintln!(
                            "      aisafeguard service install-systemd        (Linux，需 root)"
                        );
                        std::process::exit(2);
                    }
                }
            }
            other => {
                eprintln!("未知参数: {other}");
                eprintln!("用法: aisafeguard [--headless] [--config <path>] [--data-dir <path>]");
                eprintln!(
                    "      aisafeguard verify-log | export-events <out.jsonl> | --print-token | --version"
                );
                eprintln!("      aisafeguard canary-decode <token>                (蜜饵水印溯源)");
                eprintln!("      aisafeguard service install|uninstall|start|stop   (需管理员)");
                eprintln!(
                    "      aisafeguard --service                              (由服务管理器调用)"
                );
                std::process::exit(2);
            }
        }
        i += 1;
    }

    // 子命令
    if let Some((cmd, arg)) = command {
        match cmd.as_str() {
            "verify-log" => return cmd_verify_log(resolve_cfg(cfg_path, data_dir)?),
            "canary-decode" => return cmd_canary_decode(resolve_cfg(cfg_path, data_dir)?, arg),
            "export-events" => return cmd_export_events(resolve_cfg(cfg_path, data_dir)?, arg),
            "service-install"
            | "service-uninstall"
            | "service-start"
            | "service-stop"
            | "service-install-systemd" => {
                #[cfg(windows)]
                {
                    let r = match cmd.as_str() {
                        "service-install" => service::install(),
                        "service-uninstall" => service::uninstall(),
                        "service-start" => service::start(),
                        "service-stop" => service::stop(),
                        _ => {
                            eprintln!("service install-systemd 仅支持 Linux");
                            std::process::exit(2);
                        }
                    };
                    match r {
                        Ok(()) => println!("✓ 服务操作成功: {}", &cmd["service-".len()..]),
                        Err(e) => {
                            eprintln!("✗ {e}");
                            std::process::exit(1);
                        }
                    }
                }
                #[cfg(not(windows))]
                {
                    let r = match cmd.as_str() {
                        "service-install-systemd" => install_systemd_unit(),
                        _ => service::unsupported(),
                    };
                    return match r {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            eprintln!("✗ {e}");
                            std::process::exit(1);
                        }
                    };
                }
                #[cfg(windows)]
                return Ok(());
            }
            "fed-init-ca" => {
                return fed::cmd_init_ca(&resolve_cfg(cfg_path, data_dir)?.0.data_dir());
            }
            "fed-issue-cert" => {
                let Some(node) = arg else {
                    eprintln!("用法: aisafeguard fed issue-cert <node> [--san <dns|ip> ...]");
                    std::process::exit(2);
                };
                return fed::cmd_issue_cert(
                    &resolve_cfg(cfg_path, data_dir)?.0.data_dir(),
                    &node,
                    &fed_sans,
                );
            }
            "fed-revoke" => {
                let Some(target) = arg else {
                    eprintln!("用法: aisafeguard fed revoke <节点名|指纹> [原因]");
                    std::process::exit(2);
                };
                let reason = fed_sans.into_iter().next().unwrap_or_default();
                return match fed::cmd_revoke(
                    &resolve_cfg(cfg_path, data_dir)?.0.data_dir(),
                    &target,
                    &reason,
                ) {
                    Ok(fp) => {
                        println!("✓ 已吊销 {fp}（协调者立即拒绝其连接）");
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("✗ {e}");
                        std::process::exit(1);
                    }
                };
            }
            "fed-audit" => {
                let Some(out) = arg else {
                    eprintln!("用法: aisafeguard fed audit <out.json>");
                    std::process::exit(2);
                };
                let data_dir = resolve_cfg(cfg_path, data_dir)?.0.data_dir();
                return fed::cmd_audit(&data_dir, Path::new(&out), 604_800)
                    .map_err(|e| anyhow::anyhow!("{e}"));
            }
            "fed-expect" => {
                let Some(joined) = arg else {
                    eprintln!("用法: aisafeguard fed expect <node> <指纹>");
                    std::process::exit(2);
                };
                let (node, fp) = joined.split_once('\u{1}').unwrap_or((joined.as_str(), ""));
                return fed::cmd_expect(&resolve_cfg(cfg_path, data_dir)?.0.data_dir(), node, fp)
                    .map_err(|e| anyhow::anyhow!("{e}"));
            }
            _ => unreachable!(),
        }
    }

    if print_token {
        // 供部署脚本取回本地 API token（本机操作员自用）
        let (cfg, _) = resolve_cfg(cfg_path, data_dir)?;
        println!("{}", load_or_create_token(&cfg.data_dir())?);
        return Ok(());
    }

    if service_mode {
        #[cfg(windows)]
        return service::dispatch();
        #[cfg(not(windows))]
        return service::unsupported();
    }

    // ---------- 引擎形态 ----------
    if headless {
        let (cfg, cfg_path) = resolve_cfg(cfg_path, data_dir)?;
        let bundle = assemble_engine(cfg, cfg_path)?;
        println!("AI-SafeGuard {VERSION} headless 运行中");
        println!(
            "  API:      http://127.0.0.1:{}  (Bearer token: 凭据管理器 AISafeGuard/api-token，或 --print-token)",
            bundle.cfg.api.port
        );
        println!("  数据目录: {:?}", bundle.cfg.data_dir());
        println!("  Ctrl+C 退出");
        rt_wait_ctrl_c(&bundle)?;
        println!("正在停止…");
        bundle.engine.honeypot.stop();
        Ok(())
    } else {
        // GUI：已提权 → 内嵌引擎；未提权 → 优先连接提权服务；
        // 无服务 → 自动弹 UAC 请求管理员权限（拒绝则未提权内嵌回退，防火墙功能受限）
        let elevated = aisafeguard_firewall::create_backend().is_elevated();
        let console: Arc<dyn Console> = if elevated {
            let (cfg, cfg_path) = resolve_cfg(cfg_path, data_dir)?;
            println!("内嵌引擎模式（管理员）");
            embedded_console(cfg, cfg_path)?
        } else if let Some(rc) = remote::probe_service() {
            println!("远程控制台模式：已连接 AI-SafeGuard 服务");
            Arc::new(rc)
        } else {
            #[cfg(windows)]
            if !uac_child && try_relaunch_elevated() {
                // UAC 已同意、提权实例已拉起：本进程退出
                return Ok(());
            }
            if uac_child {
                println!("提权未成功，以普通权限继续（防火墙功能受限）");
            } else {
                println!("未检测到提权服务，回退内嵌模式（防火墙功能需管理员）");
            }
            let (cfg, cfg_path) = resolve_cfg(cfg_path, data_dir)?;
            embedded_console(cfg, cfg_path)?
        };
        gui::run(console)
    }
}

/// Windows：以管理员身份重启自身（UAC 弹窗，0.5.12）。PowerShell Start-Process
/// -Verb RunAs 触发系统提权对话框；std CommandExt::creation_flags 是安全 API，
/// 不破 forbid(unsafe_code)。返回 true = 提权实例已拉起（调用方应退出本进程）；
/// false = 用户拒绝 UAC 或 PowerShell 不可用（调用方按未提权继续）。
#[cfg(windows)]
fn try_relaunch_elevated() -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--uac-child")
        .chain(["--uac-child".to_string()])
        .collect();
    // PowerShell 单引号字符串不插值：' → '' 转义，避免路径里的 $ / 空格踩坑
    let ps_quote = |v: &str| format!("'{}'", v.replace('\'', "''"));
    let arglist = args
        .iter()
        .map(|a| ps_quote(a))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "Start-Process -FilePath {} -ArgumentList @({}) -Verb RunAs",
        ps_quote(&exe.to_string_lossy()),
        arglist
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("已请求管理员权限…");
            true
        }
        _ => false,
    }
}

/// 内嵌控制台组装。runtime 故意泄漏：所有引擎后台任务（蜜罐监听/API/事件入库/
/// TTL 清扫）都跑在 `EngineBundle.rt` 上，bundle 在本函数返回后即销毁——若 runtime
/// 随之 drop，任务全部被中止，引擎只剩同步读（GUI 显示的「监听中」来自配置快照，
/// 是假象；0.2 服务化引入 bundle 起的静默僵尸）。GUI 进程生命周期 = runtime
/// 生命周期，泄漏先例同 init_tracing 的 guard（std::mem::forget）。
fn embedded_console(cfg: AppConfig, cfg_path: PathBuf) -> anyhow::Result<Arc<dyn Console>> {
    let bundle = assemble_engine(cfg, cfg_path)?;
    std::mem::forget(bundle.rt);
    Ok(Arc::new(engine::EmbeddedConsole(bundle.engine)))
}

fn resolve_cfg(
    cfg_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
) -> anyhow::Result<(AppConfig, PathBuf)> {
    let cfg_path = cfg_path.unwrap_or_else(AppConfig::default_path);
    let (mut cfg, created) = AppConfig::load(&cfg_path)?;
    if let Some(d) = data_dir {
        cfg.general.data_dir = d; // CLI 优先于配置文件，但不写回
    }
    std::fs::create_dir_all(cfg.data_dir())?;
    if created {
        println!("已生成默认配置: {}", cfg_path.display());
    }
    Ok((cfg, cfg_path))
}

/// H210 蜜饵水印溯源：`aisafeguard canary-decode <token>`。
/// 密钥来源与引擎侧一致：配置 [honeypot.canary].key 优先，否则读
/// <data_dir>/honeypot/canary.key（跨节点溯源需拷贝密钥文件或配相同密钥）。
fn cmd_canary_decode((cfg, _): (AppConfig, PathBuf), token: Option<String>) -> anyhow::Result<()> {
    let Some(token) = token.filter(|t| !t.trim().is_empty()) else {
        anyhow::bail!("缺少 token 参数（用法: aisafeguard canary-decode <token>）");
    };
    let key = if !cfg.honeypot.canary.key.is_empty() {
        cfg.honeypot.canary.key.clone()
    } else {
        let path = cfg.data_dir().join("honeypot").join("canary.key");
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|e| {
                anyhow::anyhow!(
                    "读取水印密钥失败 {}: {e}（跨节点溯源需拷贝密钥文件，或用 --data-dir 指向密钥所在数据目录）",
                    path.display()
                )
            })?
    };
    let payload = aisafeguard_core::canary::decode_token(key.as_bytes(), token.trim())
        .map_err(|e| anyhow::anyhow!("解码失败: {e}"))?;
    let ts = chrono::DateTime::from_timestamp(payload.ts, 0)
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| payload.ts.to_string());
    println!("蜜饵水印解码成功");
    println!("  来源节点: {}", payload.node);
    println!("  投放时间: {ts}");
    println!("  蜜饵资源: {}", payload.res);
    Ok(())
}

fn cmd_verify_log((cfg, _): (AppConfig, PathBuf)) -> anyhow::Result<()> {
    let store = Store::open(&cfg.db_path())?;
    let report = store.verify_chain()?;
    if report.ok {
        println!(
            "✓ 哈希链完整：{}/{} 条事件校验通过",
            report.rows, report.rows
        );
    } else {
        eprintln!(
            "✗ 哈希链损坏：第 {} 条事件校验失败（共检查 {} 条）——事件可能被篡改或删除",
            report.broken_at.unwrap_or_default(),
            report.rows
        );
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_export_events((cfg, _): (AppConfig, PathBuf), out: Option<String>) -> anyhow::Result<()> {
    let out = PathBuf::from(out.expect("export 输出路径"));
    let store = Store::open(&cfg.db_path())?;
    let n = store.export_events(&out)?;
    println!("已导出 {n} 条事件（含哈希字段）→ {}", out.display());
    Ok(())
}

/// 服务模式：引擎钉死在 ProgramData 数据目录（LocalSystem 的 LOCALAPPDATA
/// 是 systemprofile 私有目录，DB/日志落那里用户无法 inspect），token 发布为
/// 用户可读文件供 GUI 远程模式使用，直到 SCM 发出停止信号。
/// `set_running` 在引擎就绪后被调用（向 SCM 报告 Running）。
pub fn run_engine_until_stop(
    stop: &std::sync::mpsc::Receiver<()>,
    set_running: &dyn Fn(),
) -> anyhow::Result<()> {
    let data_dir =
        service::service_data_dir().ok_or_else(|| anyhow::anyhow!("PROGRAMDATA 环境变量不可用"))?;
    std::fs::create_dir_all(&data_dir)?;
    let cfg_path = data_dir.join("config.toml");
    let (mut cfg, _) = AppConfig::load(&cfg_path)?;
    cfg.general.data_dir = data_dir.clone(); // 钉死：LocalSystem 的默认目录不可用
    let bundle = assemble_engine(cfg, cfg_path)?;
    std::fs::write(data_dir.join("api-token"), &bundle.engine.token)?;
    set_running();
    loop {
        match stop.recv_timeout(Duration::from_millis(500)) {
            Ok(()) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    bundle.engine.honeypot.stop();
    Ok(())
}

struct EngineBundle {
    engine: Arc<EngineHandle>,
    cfg: AppConfig,
    #[allow(dead_code)]
    rt: tokio::runtime::Runtime,
}

fn assemble_engine(cfg: AppConfig, cfg_path: PathBuf) -> anyhow::Result<EngineBundle> {
    let data_dir = cfg.data_dir();
    std::fs::create_dir_all(&data_dir)?;
    init_tracing(&data_dir)?;

    let store = Arc::new(Store::open(&cfg.db_path())?);
    let pruned = store.prune_events(30)?;
    if pruned > 0 {
        tracing::info!("清理 {pruned} 条超过 30 天的事件");
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let bus = EventBus::new(2048);
    // 防火墙执行器：平台后端兜底；Linux 上 [xdp].enabled 时叠加 XDP 快速层
    // （组合执行器：全部规则 nftables 兜底，IP 级入站规则镜像进 eBPF map 微秒级生效）
    let (firewall, xdp): (
        std::sync::Arc<dyn aisafeguard_firewall::Firewall>,
        Option<std::sync::Arc<aisafeguard_xdp::composite::CompositeFirewall>>,
    ) = {
        let base = aisafeguard_firewall::create_backend();
        #[cfg(target_os = "linux")]
        {
            if cfg.xdp.enabled {
                use aisafeguard_xdp::composite::{CompositeFirewall, XdpMode};
                if !cfg.xdp.valid_mode() {
                    bus.publish(SecurityEvent::engine(
                        "error",
                        format!(
                            "XDP 模式非法：{}（可用 skb | native），快速层未启用",
                            cfg.xdp.mode
                        ),
                    ));
                    (base, None)
                } else {
                    let composite = std::sync::Arc::new(CompositeFirewall::new(base));
                    let mode = XdpMode::parse(&cfg.xdp.mode).unwrap_or(XdpMode::Skb);
                    match composite.attach_fast(&cfg.xdp.iface, mode) {
                        Ok(()) => {
                            tracing::info!(
                                "XDP 快速执行层已附加（{} / {} 模式）",
                                cfg.xdp.iface,
                                mode.as_str()
                            );
                            bus.publish(SecurityEvent::engine(
                                "info",
                                format!(
                                    "XDP 快速执行层已附加（{} / {} 模式）：IP 级入站封禁内核直丢",
                                    cfg.xdp.iface,
                                    mode.as_str()
                                ),
                            ));
                            let xdp = std::sync::Arc::clone(&composite);
                            (composite, Some(xdp))
                        }
                        Err(e) => {
                            tracing::error!("XDP 快速执行层未启用: {e}");
                            bus.publish(SecurityEvent::engine(
                                "error",
                                format!("XDP 快速执行层未启用（nftables 兜底不受影响）: {e}"),
                            ));
                            (composite, None)
                        }
                    }
                }
            } else {
                (base, None)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            (base, None)
        }
    };
    let token = load_or_create_token(&data_dir)?;

    // 事件流水 → SQLite（含哈希链计算，失败只记日志不拖垮总线）
    {
        let bus = bus.clone();
        let store = store.clone();
        rt.spawn(async move {
            let mut rx = bus.subscribe();
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if let Err(e) = store.insert_event(&ev) {
                            tracing::error!("事件入库失败: {e}");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("事件入库通道落后 {n} 条");
                    }
                    Err(_) => break,
                }
            }
        });
    }

    let honeypot =
        rt.block_on(async { aisafeguard_honeypot::start(&cfg.honeypot, bus.clone(), &cfg.data_dir()) });
    if !cfg.honeypot.enabled {
        bus.publish(SecurityEvent::engine("info", "蜜罐功能已禁用"));
    }

    // 凭证库（0.5.10 H200）：与主库同级的独立文件，启动失败按配置错误处理
    let credentials = Arc::new(CredentialStore::open(
        &cfg.data_dir().join("honeypot").join("credentials.db"),
    )?);
    let engine = Arc::new(EngineHandle {
        cfg: RwLock::new(cfg.clone()),
        cfg_path: cfg_path.clone(),
        store,
        bus: bus.clone(),
        firewall: firewall.clone(),
        detect: Arc::new(aisafeguard_detect::FreqEngine::new()),
        capture: Arc::new(engine::CaptureState::default()),
        rules: Arc::new(engine::RulesState::default()),
        xdp,

        rt: rt.handle().clone(),
        started: Instant::now(),
        ai_running: Arc::new(AtomicBool::new(false)),
        honeypot,
        local_accounts: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        credentials,
        token,
        version: VERSION,
    });

    // 快路径频次检测 + TTL 自动解封
    engine::spawn_detect_task(&engine);
    engine::spawn_expiry_janitor(&engine);

    // 凭证采集与本地喷洒检测（0.5.10 H200，默认开；[honeypot.credentials] 门控）
    engine::spawn_credential_task(&engine);

    // 规则子集引擎（0.5.0 Batch F，默认关闭）：启动加载 + 文件签名变化整包热重载
    engine::spawn_rules_task(&engine);

    // 采样捕获（检测平台 MVP，默认关闭；不可用时只降级并留痕）
    engine::spawn_capture_task(&engine);

    // 事件外发（0.3.5，默认关闭）：syslog 转发 / webhook 告警 / 暴露面定时扫描
    forward::spawn_syslog_task(&engine);
    forward::spawn_notify_task(&engine);
    forward::spawn_exposure_task(&engine);

    // AI 定时分析（0.4.0 A4 接线）：任务自门控 [ai].enabled，interval/enabled 全热更
    engine.spawn_ai_task();

    // 威胁情报（默认关闭，[intel].enabled 开启）
    if cfg.intel.enabled {
        engine::spawn_intel_task(&engine);
    } else {
        bus.publish(SecurityEvent::engine(
            "info",
            "威胁情报未启用（[intel].enabled）",
        ));
    }

    // 启动时把 DB 中已启用的来源 IP 封禁同步回防火墙
    // （nftables 的 set 是易失的；Windows COM 规则持久，resync 为空实现）
    if let Ok(rules) = engine.store.list_rules() {
        let specs: Vec<aisafeguard_firewall::BlockSpec> = rules
            .iter()
            .filter(|r| r.enabled && !r.remote_ip.is_empty())
            .map(|r| aisafeguard_firewall::BlockSpec {
                direction: if r.direction == "in" {
                    aisafeguard_firewall::Direction::In
                } else {
                    aisafeguard_firewall::Direction::Out
                },
                protocol: r
                    .protocol
                    .parse()
                    .unwrap_or(aisafeguard_firewall::Protocol::Any),
                remote_ip: r.remote_ip.parse::<std::net::IpAddr>().ok(),
                local_port: r.local_port,
                note: r.note.clone(),
                tag: r.tag.clone(),
            })
            .collect();
        if let Err(e) = engine.firewall.resync(&specs) {
            tracing::warn!("防火墙规则同步失败: {e}");
        }
    }

    if cfg.api.enabled {
        let engine = engine.clone();
        rt.spawn(async move { api::serve(engine).await });
    }

    // 组织协同（0.3）：coordinator 起独立 mTLS 监听面，agent 起上报任务
    if cfg.fed.enabled {
        if !cfg.fed.valid_role() || cfg.fed.node.is_empty() {
            bus.publish(SecurityEvent::engine(
                "error",
                format!(
                    "组织协同配置无效：role={} node={:?}",
                    cfg.fed.role, cfg.fed.node
                ),
            ));
        } else {
            match cfg.fed.role.as_str() {
                "coordinator" => {
                    bus.publish(SecurityEvent::engine(
                        "info",
                        format!(
                            "组织协同：本节点为协调者（{}），mTLS 面监听 {}",
                            cfg.fed.node, cfg.fed.listen_addr
                        ),
                    ));
                    // C5 绑定建议（0.4.0）：监听公网地址或所有地址时提示——
                    // 组织面应绑内网；暴露面盘点已把该端口计入
                    if let Ok(addr) = cfg.fed.listen_addr.parse::<std::net::SocketAddr>() {
                        let ip = addr.ip();
                        let public = !ip.is_loopback()
                            && !aisafeguard_core::is_protected_ip(ip)
                            && !ip.is_unspecified();
                        if public || ip.is_unspecified() {
                            bus.publish(SecurityEvent::engine(
                                "warn",
                                "协同面绑定到非内网地址：建议改为内网地址（组织同步不需要公网可达；已入暴露面盘点）",
                            ));
                        }
                    }
                    let eng = engine.clone();
                    let bus = bus.clone();
                    rt.spawn(async move {
                        if let Err(e) = fed::serve_coordinator(eng).await {
                            // 材料缺失/端口占用等只降级留痕，不影响引擎其余功能
                            bus.publish(SecurityEvent::engine(
                                "error",
                                format!("组织协同 mTLS 面未启动：{e}"),
                            ));
                        }
                    });
                }
                "agent" => {
                    if cfg.fed.coordinator.is_empty() {
                        bus.publish(SecurityEvent::engine(
                            "error",
                            "组织协同：agent 需要 coordinator 地址（https://协调者:7421）",
                        ));
                    } else {
                        bus.publish(SecurityEvent::engine(
                            "info",
                            format!(
                                "组织协同：agent {} → {}（mTLS）",
                                cfg.fed.node, cfg.fed.coordinator
                            ),
                        ));
                        fed::spawn_fed_agent_task(&engine);
                    }
                }
                _ => {}
            }
        }
    }

    bus.publish(SecurityEvent::engine(
        "info",
        format!(
            "AI-SafeGuard {VERSION} 已启动：防火墙后端 {}（提权: {}），蜜罐 {} 个监听，频次检测 {}",
            firewall.backend(),
            firewall.is_elevated(),
            engine.honeypot.listeners().len(),
            if cfg.detect.enabled {
                "开启"
            } else {
                "关闭"
            },
        ),
    ));

    Ok(EngineBundle { engine, cfg, rt })
}

fn rt_wait_ctrl_c(bundle: &EngineBundle) -> anyhow::Result<()> {
    bundle.rt.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    Ok(())
}

/// 本地 API token 存凭据管理器（AISafeGuard/api-token），内嵌模式使用。
/// 服务模式不用此函数（token 发布为 ProgramData 文件，见 run_engine_until_stop）。
// Windows 走凭据管理器（data_dir 仅 Linux 分支使用），平台分支各自以块值为返回
#[cfg_attr(windows, allow(unused_variables, clippy::needless_return))]
fn load_or_create_token(data_dir: &Path) -> anyhow::Result<String> {
    // Windows：凭据管理器（跨进程可见）。Linux：keyring v3 无平台特性时是
    // 进程内 mock——token 跨进程不可见且 set 静默"成功"，绝不能用；一律落文件。
    #[cfg(windows)]
    {
        if let Some(t) = secrets::api_token() {
            return Ok(t);
        }
        // 0.1 遗留文件 → 迁入凭据管理器
        let legacy = dirs::data_local_dir()
            .map(|d| d.join("aisafeguard").join("api-token"))
            .filter(|p| p.exists());
        if let Some(p) = legacy {
            let t = std::fs::read_to_string(&p)?.trim().to_string();
            if !t.is_empty() {
                if secrets::set_api_token(&t).is_ok() {
                    std::fs::remove_file(&p)?;
                    tracing::info!("已将 API token 从文件迁入凭据管理器");
                    return Ok(t);
                }
                return Ok(t);
            }
            let _ = std::fs::remove_file(&p);
        }
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        secrets::set_api_token(&token)?;
        return Ok(token);
    }
    #[cfg(not(windows))]
    {
        let p = data_dir.join("api-token");
        if let Ok(t) = std::fs::read_to_string(&p) {
            let t = t.trim().to_string();
            if !t.is_empty() {
                return Ok(t);
            }
        }
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        std::fs::write(&p, &token)?;
        tracing::info!(
            "API token 写入 {p:?}（Linux 0.2 无凭据管理器后端，请确保目录仅本用户/管理员可读）"
        );
        Ok(token)
    }
}

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn init_tracing(data_dir: &Path) -> anyhow::Result<()> {
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    let appender = tracing_appender::rolling::daily(&log_dir, "aisafeguard.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    std::mem::forget(guard); // 程序生命周期与进程一致

    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false);

    tracing_subscriber::registry()
        .with(filter())
        .with(file_layer)
        .init();
    Ok(())
}
