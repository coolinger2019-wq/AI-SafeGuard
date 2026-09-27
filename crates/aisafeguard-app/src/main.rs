mod api;
mod console;
mod fed;
mod engine;
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

    pub fn install_systemd() -> anyhow::Result<()> {
        super::install_systemd_unit()
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
        println!("⚠ systemd 未运行：启用后执行 sudo systemctl daemon-reload && sudo systemctl enable --now aisafeguard");
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
use aisafeguard_core::secrets;
use aisafeguard_store::Store;
use console::Console;
use engine::EngineHandle;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> anyhow::Result<()> {
    let mut headless = false;
    let mut service_mode = false;
    let mut print_token = false;
    let mut cfg_path: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut command: Option<(String, Option<String>)> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--headless" => headless = true,
            "--service" => service_mode = true,
            "--print-token" => print_token = true,
            "--version" => {
                println!("aisafeguard {VERSION}");
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
            "service" => {
                i += 1;
                match args.get(i).map(|s| s.as_str()) {
                    Some(w @ ("install" | "uninstall" | "start" | "stop" | "install-systemd")) => {
                        command = Some((format!("service-{w}"), None))
                    }
                    _ => {
                        eprintln!("用法: aisafeguard service install|uninstall|start|stop (Windows)");
                        eprintln!("      aisafeguard service install-systemd        (Linux，需 root)");
                        std::process::exit(2);
                    }
                }
            }
            other => {
                eprintln!("未知参数: {other}");
                eprintln!("用法: aisafeguard [--headless] [--config <path>] [--data-dir <path>]");
                eprintln!("      aisafeguard verify-log | export-events <out.jsonl> | --print-token | --version");
                eprintln!("      aisafeguard service install|uninstall|start|stop   (需管理员)");
                eprintln!("      aisafeguard --service                              (由服务管理器调用)");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    // 子命令
    if let Some((cmd, arg)) = command {
        match cmd.as_str() {
            "verify-log" => return cmd_verify_log(resolve_cfg(cfg_path, data_dir)?.1),
            "export-events" => return cmd_export_events(resolve_cfg(cfg_path, data_dir)?, arg),
            "service-install" | "service-uninstall" | "service-start" | "service-stop"
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
        println!("  API:      http://127.0.0.1:{}  (Bearer token: 凭据管理器 AISafeGuard/api-token，或 --print-token)", bundle.cfg.api.port);
        println!("  数据目录: {:?}", bundle.cfg.data_dir());
        println!("  Ctrl+C 退出");
        rt_wait_ctrl_c(&bundle)?;
        println!("正在停止…");
        bundle.engine.honeypot.stop();
        Ok(())
    } else {
        // GUI：已提权 → 内嵌引擎；未提权 → 优先连接提权服务；无服务 → 内嵌回退（防火墙功能受限）
        let elevated = aisafeguard_firewall::create_backend().is_elevated();
        let console: Arc<dyn Console> = if elevated {
            let (cfg, cfg_path) = resolve_cfg(cfg_path, data_dir)?;
            let bundle = assemble_engine(cfg, cfg_path)?;
            println!("内嵌引擎模式（管理员）");
            Arc::new(engine::EmbeddedConsole(bundle.engine))
        } else if let Some(rc) = remote::probe_service() {
            println!("远程控制台模式：已连接 AI-SafeGuard 服务");
            Arc::new(rc)
        } else {
            println!("未检测到提权服务，回退内嵌模式（防火墙功能需管理员）");
            let (cfg, cfg_path) = resolve_cfg(cfg_path, data_dir)?;
            let bundle = assemble_engine(cfg, cfg_path)?;
            Arc::new(engine::EmbeddedConsole(bundle.engine))
        };
        gui::run(console)
    }
}

fn resolve_cfg(cfg_path: Option<PathBuf>, data_dir: Option<PathBuf>) -> anyhow::Result<(AppConfig, PathBuf)> {
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

fn cmd_verify_log(cfg_path: PathBuf) -> anyhow::Result<()> {
    let (cfg, _) = AppConfig::load(&cfg_path)?;
    let store = Store::open(&cfg.db_path())?;
    let report = store.verify_chain()?;
    if report.ok {
        println!("✓ 哈希链完整：{}/{} 条事件校验通过", report.rows, report.rows);
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
    let data_dir = service::service_data_dir().ok_or_else(|| anyhow::anyhow!("PROGRAMDATA 环境变量不可用"))?;
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
    let firewall = aisafeguard_firewall::create_backend();
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

    let honeypot = rt.block_on(async { aisafeguard_honeypot::start(&cfg.honeypot, bus.clone()) });
    if !cfg.honeypot.enabled {
        bus.publish(SecurityEvent::engine("info", "蜜罐功能已禁用"));
    }

    let engine = Arc::new(EngineHandle {
        cfg: RwLock::new(cfg.clone()),
        cfg_path: cfg_path.clone(),
        store,
        bus: bus.clone(),
        firewall: firewall.clone(),
        detect: Arc::new(aisafeguard_detect::FreqEngine::new()),
        rt: rt.handle().clone(),
        started: Instant::now(),
        ai_running: Arc::new(AtomicBool::new(false)),
        honeypot,
        token,
        version: VERSION,
    });

    // 快路径频次检测 + TTL 自动解封
    engine::spawn_detect_task(&engine);
    engine::spawn_expiry_janitor(&engine);

    // 威胁情报（默认关闭，[intel].enabled 开启）
    if cfg.intel.enabled {
        engine::spawn_intel_task(&engine);
    } else {
        bus.publish(SecurityEvent::engine("info", "威胁情报未启用（[intel].enabled）"));
    }

    // 启动时把 DB 中已启用的来源 IP 封禁同步回防火墙
    // （nftables 的 set 是易失的；Windows COM 规则持久，resync 为空实现）
    if let Ok(rules) = engine.store.list_rules() {
        let entries: Vec<(aisafeguard_firewall::Direction, std::net::IpAddr)> = rules
            .iter()
            .filter(|r| r.enabled && !r.remote_ip.is_empty())
            .filter_map(|r| {
                let direction = if r.direction == "in" {
                    aisafeguard_firewall::Direction::In
                } else {
                    aisafeguard_firewall::Direction::Out
                };
                r.remote_ip
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .map(|ip| (direction, ip))
            })
            .collect();
        if let Err(e) = engine.firewall.resync(&entries) {
            tracing::warn!("防火墙规则同步失败: {e}");
        }
    }

    if cfg.api.enabled {
        let engine = engine.clone();
        rt.spawn(async move { api::serve(engine).await });
    }

    // 组织协同（0.3 骨架）：coordinator 挂 /fed 路由，agent 起上报任务
    if cfg.fed.enabled {
        if !cfg.fed.valid_role() || cfg.fed.node.is_empty() {
            bus.publish(SecurityEvent::engine(
                "error",
                format!("组织协同配置无效：role={} node={:?}", cfg.fed.role, cfg.fed.node),
            ));
        } else {
            match cfg.fed.role.as_str() {
                "coordinator" => {
                    bus.publish(SecurityEvent::engine(
                        "info",
                        format!("组织协同：本节点为协调者（{}）", cfg.fed.node),
                    ));
                    // 路由在 api::serve 内按配置挂载
                }
                "agent" => {
                    if cfg.fed.coordinator.is_empty() || cfg.fed.effective_token().is_empty() {
                        bus.publish(SecurityEvent::engine(
                            "error",
                            "组织协同：agent 需要 coordinator 地址与组织令牌",
                        ));
                    } else {
                        bus.publish(SecurityEvent::engine(
                            "info",
                            format!("组织协同：agent {} → {}", cfg.fed.node, cfg.fed.coordinator),
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
            engine.honeypot.listeners.len(),
            if cfg.detect.enabled { "开启" } else { "关闭" },
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
        tracing::info!("API token 写入 {p:?}（Linux 0.2 无凭据管理器后端，请确保目录仅本用户/管理员可读）");
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

    tracing_subscriber::registry().with(filter()).with(file_layer).init();
    Ok(())
}
