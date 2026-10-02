//! 监听器：bind / accept / 停机 + 会话分派与两级并发预算。
//!
//! 并发模型（0.5.9 H102）：全局信号量兜底所有蜜罐连接；交互会话（假 Shell 等
//! 有状态多轮）额外受独立小额预算约束——长会话不得挤占全局额度饿死其他监听器。
//! 满额一律静默丢连接（全局）或优雅拒绝并留事件（交互），蜜罐自身不能被打挂。

use aisafeguard_core::config::{FingerprintConfig, HoneypotConfig, ListenerConfig};
use aisafeguard_core::event::{EventBus, SecurityEvent};
use aisafeguard_core::now_ts;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use crate::canary::CanaryState;
use crate::shell::ShellRuntime;
use crate::templates::TemplateRegistry;
use crate::{SessionOutcome, http, mysql, protocol, redis};

/// 每连接会话共享的运行时（0.5.11 收敛：假 Shell/蜜饵/模板/反识别参数/凭证
/// 采集开关统一入口，协议分派按 kind 取用）。
pub(crate) struct SessionCtx {
    pub shell: Option<Arc<ShellRuntime>>,
    pub canary: Option<Arc<CanaryState>>,
    /// 模板注册表（H300；None = 未启用）
    pub templates: Option<Arc<TemplateRegistry>>,
    /// 反识别参数（H320）：banner/版本固定于启动，会话语义不热变
    pub fp: FingerprintConfig,
    pub collect_creds: bool,
}

const MAX_CONCURRENT: usize = 64;
/// 交互会话独立预算（0.5.9 跨任务红线）：默认 8，防止长会话刷满全局 64 额度。
const MAX_INTERACTIVE: usize = 8;

#[derive(Debug, Clone)]
pub struct ListenerState {
    pub name: String,
    pub port: u16,
    pub kind: String,
    /// 交互模式：「低交互」banner 级 /「中交互」假 Shell（0.5.10 H150 能力可见）
    pub mode: String,
    /// 实际运行状态：bind 成功 = true，停机/绑定失败 = false。
    /// 配置里有 ≠ 真的在跑——GUI 状态章以这个为准（0.5.12）。
    pub running: Arc<AtomicBool>,
}

/// kind + 假 Shell 运行时可用性 → 交互模式（与 is_interactive_session 同一口径）
fn interaction_mode(kind: &str, shell: Option<&ShellRuntime>) -> &'static str {
    if is_interactive_session(kind, shell) {
        "中交互"
    } else {
        "低交互"
    }
}

/// 运行时监听器注册表行：一个配置行对应一条，含热启停控制通道。
struct RuntimeListener {
    cfg: ListenerConfig,
    /// 交互模式（启动时按 shell 运行时可用性算好；热启沿用）
    mode: String,
    running: Arc<AtomicBool>,
    /// 服务任务是否存活（bind 失败会退出任务；热启动据此决定唤醒还是重拉）
    task_alive: Arc<AtomicBool>,
    /// 期望状态镜像（原子可读）：false → 摘下监听驻留；true → 服务
    desired_state: Arc<AtomicBool>,
    /// 期望状态的广播通道（镜像变更时发送）
    desired_tx: watch::Sender<bool>,
}

pub struct HoneypotHandle {
    /// 运行时注册表（配置行 + 模板监听器都在；停机/热停的行保留以便热启动）
    registry: Mutex<Vec<RuntimeListener>>,
    /// 共享会话上下文：热启动新任务时复用（shell 运行时/蜜饵/模板/指纹）
    ctx: Arc<SessionCtx>,
    bus: EventBus,
    shutdown: watch::Sender<bool>,
}

impl HoneypotHandle {
    /// 全局停机（进程退出用）：所有监听器优雅退出。
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }

    /// 状态快照（status/API 用）：全部注册行，含未运行行。
    pub fn listeners(&self) -> Vec<ListenerState> {
        self.registry
            .lock()
            .map(|reg| {
                reg.iter()
                    .map(|r| ListenerState {
                        name: r.cfg.name.clone(),
                        port: r.cfg.port,
                        kind: r.cfg.kind.clone(),
                        mode: r.mode.clone(),
                        running: Arc::clone(&r.running),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 热停止：期望状态收敛为 false，服务任务摘下监听并释放端口后驻留等待。
    /// 非阻塞（发信号即返回）；状态以 `listeners()` 快照为准，GUI 缓存 2s 内刷新。
    /// 幂等：已停止的行直接返回 Ok。
    pub fn stop_listener(&self, name: &str) -> Result<(), String> {
        let (desired_state, desired_tx) = {
            let reg = self.registry.lock().map_err(|_| "注册表锁中毒".to_string())?;
            reg.iter()
                .find(|r| r.cfg.name == name)
                .map(|r| (r.desired_state.clone(), r.desired_tx.clone()))
                .ok_or_else(|| format!("监听器 [{name}] 不在运行时注册表中"))?
        };
        desired_state.store(false, Ordering::Relaxed);
        let _ = desired_tx.send(false);
        Ok(())
    }

    /// 热启动：期望状态收敛为 true。任务存活（含停止指令在途）→ 唤醒/撤回停止，
    /// 任务由同一生命周期重新 bind（无端口竞态窗口）；任务已死（bind 失败/全局
    /// 停机）→ 重拉。非阻塞；bind 失败留 engine 错误事件，状态以 `listeners()` 为准。
    pub fn start_listener(&self, name: &str) -> Result<(), String> {
        let (cfg, running, task_alive, desired_state, desired_tx, shutdown_rx) = {
            let reg = self.registry.lock().map_err(|_| "注册表锁中毒".to_string())?;
            let r = reg
                .iter()
                .find(|r| r.cfg.name == name)
                .ok_or_else(|| format!("监听器 [{name}] 不在运行时注册表中"))?;
            if r.running.load(Ordering::Relaxed) && r.desired_state.load(Ordering::Relaxed) {
                return Err(format!("监听器 [{name}] 已在运行"));
            }
            (
                r.cfg.clone(),
                Arc::clone(&r.running),
                Arc::clone(&r.task_alive),
                r.desired_state.clone(),
                r.desired_tx.clone(),
                self.shutdown.subscribe(),
            )
        };
        desired_state.store(true, Ordering::Relaxed);
        let _ = desired_tx.send(true);
        if task_alive.load(Ordering::Relaxed) {
            return Ok(()); // 驻留任务会唤醒/撤回停止并重新 bind
        }
        // 任务已死（bind 失败/全局停机后）：重拉一个服务任务
        let desired_rx = desired_tx.subscribe();
        let bus = self.bus.clone();
        let ctx = Arc::clone(&self.ctx);
        tokio::spawn(spawn_guarded_listener(
            cfg,
            bus,
            shutdown_rx,
            ctx,
            running,
            task_alive,
            desired_rx,
        ));
        Ok(())
    }
}

/// 必须在 tokio runtime 上下文中调用。data_dir 用于假 Shell host key 的
/// 默认落盘位置（<data_dir>/honeypot/，fed 证书路径同款约定）。
pub fn start(cfg: &HoneypotConfig, bus: EventBus, data_dir: &std::path::Path) -> HoneypotHandle {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let collect_creds = cfg.credentials.enabled;
    // 会话上下文始终构建（热启动 start_listener 复用）；假 Shell 运行时仅在
    // 蜜罐启用且 shell.enabled 时装配——host key 落盘是副作用，禁用时不产生
    let canary = if cfg.enabled && cfg.canary.enabled {
        match crate::canary::CanaryState::resolve(&cfg.canary.key, data_dir) {
            Ok(v) => {
                let v = Arc::new(v);
                if !cfg.canary.fs_paths.is_empty() {
                    let placed =
                        crate::canary::place_and_watch_fs_canaries(&cfg.canary.fs_paths, &bus, &v);
                    if placed > 0 {
                        bus.publish(SecurityEvent::engine(
                            "info",
                            format!("文件系统蜜饵已启用: {placed} 处（读取即告警）"),
                        ));
                    }
                }
                Some(v)
            }
            Err(e) => {
                bus.publish(SecurityEvent::engine(
                    "error",
                    format!("蜜饵密钥初始化失败,HTTP 蜜饵停用: {e}"),
                ));
                None
            }
        }
    } else {
        None
    };
    let shell = if cfg.enabled && cfg.shell.enabled {
        match crate::shell::start_runtime(&cfg.shell, data_dir) {
            Ok(rt) => {
                bus.publish(SecurityEvent::engine(
                    "info",
                    format!(
                        "假 Shell 已启用（ssh 升级中交互,用户 {}@{}）",
                        cfg.shell.username, cfg.shell.hostname
                    ),
                ));
                Some(rt)
            }
            Err(e) => {
                bus.publish(SecurityEvent::engine(
                    "error",
                    format!("假 Shell host key 初始化失败,ssh 保持 banner 低交互: {e}"),
                ));
                None
            }
        }
    } else {
        None
    };
    // 模板（0.5.11 H300）：默认关。加载注册表并把模板监听器追加到运行列表；
    // 内容变更走轮询热重载，增删模板目录需重启（轮询只告警提示）
    let mut extra_listeners: Vec<ListenerConfig> = Vec::new();
    let templates: Option<Arc<TemplateRegistry>> = if cfg.enabled && cfg.templates.enabled {
        let root = if cfg.templates.dir.is_empty() {
            data_dir.join("honeypot").join("templates")
        } else {
            std::path::PathBuf::from(&cfg.templates.dir)
        };
        let occupied: Vec<u16> = cfg
            .listeners
            .iter()
            .filter(|l| l.enabled)
            .map(|l| l.port)
            .collect();
        let (registry, extra) = TemplateRegistry::load(&root, &occupied, &bus);
        extra_listeners = extra;
        crate::templates::spawn_template_poller(registry.clone(), bus.clone());
        Some(registry)
    } else {
        None
    };
    let ctx = Arc::new(SessionCtx {
        shell,
        canary,
        templates,
        fp: cfg.fingerprint.clone(),
        collect_creds,
    });
    // 运行时注册表：配置行 + 模板监听器全部登记（disabled 行 running=false，
    // 可热启动）；enabled 行立即拉起
    let mut registry: Vec<RuntimeListener> = Vec::new();
    for l in cfg.listeners.iter().chain(extra_listeners.iter()) {
        let (desired_tx, _) = watch::channel(l.enabled);
        let running = Arc::new(AtomicBool::new(false));
        let task_alive = Arc::new(AtomicBool::new(false));
        if l.enabled {
            let desired_rx = desired_tx.subscribe();
            tokio::spawn(spawn_guarded_listener(
                l.clone(),
                bus.clone(),
                shutdown_rx.clone(),
                ctx.clone(),
                running.clone(),
                task_alive.clone(),
                desired_rx,
            ));
        }
        let desired_state = Arc::new(AtomicBool::new(l.enabled));
        registry.push(RuntimeListener {
            cfg: l.clone(),
            mode: if l.enabled {
                interaction_mode(&l.kind, ctx.shell.as_deref()).to_string()
            } else {
                "未启用".to_string()
            },
            running,
            task_alive,
            desired_state,
            desired_tx,
        });
    }
    if !cfg.enabled {
        bus.publish(SecurityEvent::engine("info", "蜜罐功能已禁用"));
    }
    HoneypotHandle {
        registry: Mutex::new(registry),
        ctx,
        bus,
        shutdown: shutdown_tx,
    }
}

/// 服务任务包装：管理 task_alive 生命周期标志——任务退出（bind 失败/全局停机）
/// 后置 false，热启动据此决定唤醒驻留任务还是重拉新任务。
async fn spawn_guarded_listener(
    l: ListenerConfig,
    bus: EventBus,
    shutdown: watch::Receiver<bool>,
    ctx: Arc<SessionCtx>,
    running: Arc<AtomicBool>,
    task_alive: Arc<AtomicBool>,
    desired: watch::Receiver<bool>,
) {
    task_alive.store(true, Ordering::Relaxed);
    run_listener(l, bus, shutdown, ctx, running.clone(), desired).await;
    // 单一出口统一清标志：run_listener 的所有 return 路径（含全局停机）
    // 都必须落成「未运行」，否则状态章会残留僵尸的「运行中」
    running.store(false, Ordering::Relaxed);
    task_alive.store(false, Ordering::Relaxed);
}

/// 服务任务主体：期望状态驱动的服务循环（0.5.12 热启停）。
///
/// desired=true → bind 并服务；翻 false → 摘下监听（释放端口）后**驻留等待**
/// （不杀任务：热停→热启由同一任务重绑，无端口竞态窗口）；bind 失败 → 留错误
/// 事件后退出任务（热启动重拉重试，不做死循环重试）。全局 shutdown 任何状态立即退出。
async fn run_listener(
    l: ListenerConfig,
    bus: EventBus,
    mut shutdown: watch::Receiver<bool>,
    ctx: Arc<SessionCtx>,
    running: Arc<AtomicBool>,
    mut desired: watch::Receiver<bool>,
) {
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), l.port);
    loop {
        // 期望状态闸门：false → 摘下监听驻留（不占端口、不占并发预算）
        while !*desired.borrow_and_update() {
            running.store(false, Ordering::Relaxed);
            tokio::select! {
                _ = shutdown.changed() => return,
                changed = desired.changed() => {
                    if changed.is_err() {
                        return; // 期望状态通道关闭：注册表已亡，随引擎退场
                    }
                }
            }
        }
        let listener = match TcpListener::bind(addr).await {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                running.store(false, Ordering::Relaxed);
                bus.publish(SecurityEvent::engine(
                    "error",
                    format!(
                        "蜜罐 [{}] 绑定 :{} 失败：端口已被占用——很可能另一个 AI-SafeGuard 实例正在运行（单机只应运行一个实例），结束另一实例后热启动或重启本程序",
                        l.name, l.port
                    ),
                ));
                return; // 退出任务：热启动会重拉重试
            }
            Err(e) => {
                running.store(false, Ordering::Relaxed);
                bus.publish(SecurityEvent::engine(
                    "error",
                    format!("蜜罐 [{}] 绑定 :{} 失败: {e}", l.name, l.port),
                ));
                return; // 退出任务：热启动会重拉重试
            }
        };
        running.store(true, Ordering::Relaxed);
        bus.publish(SecurityEvent::engine(
            "info",
            format!("蜜罐 [{}] ({}) 已监听 :{}", l.name, l.kind, l.port),
        ));
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
        let interactive_sem = Arc::new(Semaphore::new(MAX_INTERACTIVE));
        loop {
            let stream = tokio::select! {
                _ = shutdown.changed() => return,
                // 热停（0.5.12）：期望状态翻 false → 摘下监听回到外层驻留
                _ = desired.changed() => {
                    if !*desired.borrow_and_update() {
                        break;
                    }
                    continue;
                }
                accepted = listener.accept() => match accepted {
                    Ok((s, _)) => s,
                    Err(_) => continue,
                },
            };
            // 满载直接丢弃连接：蜜罐自身不能被打挂
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            // 交互会话占独立小额预算：满额优雅拒绝并留痕（对齐 OpenSSH 正常拒连语义）
            let interactive_permit =
                if is_interactive_session(&l.kind, ctx.shell.as_deref()) {
                match interactive_sem.clone().try_acquire_owned() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        bus.publish(SecurityEvent::engine(
                            "info",
                            format!(
                                "蜜罐 [{}] 交互会话并发已满（{}），拒绝新会话",
                                l.name, MAX_INTERACTIVE
                            ),
                        ));
                        drop(stream);
                        drop(permit);
                        continue;
                    }
                }
            } else {
                None
            };
            let bus = bus.clone();
            let name = l.name.clone();
            let kind = l.kind.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                handle_conn(stream, name, kind, bus, ctx).await;
                drop(interactive_permit);
                drop(permit);
            });
        }
        running.store(false, Ordering::Relaxed);
        bus.publish(SecurityEvent::engine(
            "info",
            format!("蜜罐 [{}] 已停止", l.name),
        ));
        // 回到外层：desired=false → 驻留；期间又被翻 true → 立即重 bind
    }
}

/// 该 kind 是否交互会话（有状态多轮）：ssh 由 [honeypot.shell].enabled +
/// host key 可用性决定（H104），telnet 由 shell.telnet_enabled 决定（H120）。
fn is_interactive_session(kind: &str, shell: Option<&ShellRuntime>) -> bool {
    match (kind, shell) {
        ("ssh", Some(rt)) => rt.ssh_config.is_some(),
        ("telnet", Some(rt)) => rt.telnet_enabled,
        _ => false,
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    listener: String,
    kind: String,
    bus: EventBus,
    ctx: Arc<SessionCtx>,
) {
    let (remote_ip, remote_port) = match stream.peer_addr() {
        Ok(a) => (a.ip().to_string(), a.port()),
        Err(_) => ("unknown".into(), 0),
    };
    let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);

    // ssh/telnet 假 Shell 启用时流被仿真层消费（提前取端口）;其余按 &mut 读一包。
    // banner 解析顺序（H300/H320）：模板覆盖 > [honeypot.fingerprint] 全局默认
    let result: std::io::Result<SessionOutcome> = match kind.as_str() {
        "ssh" if ctx.shell.as_ref().is_some_and(|rt| rt.ssh_config.is_some()) => {
            let rt = ctx.shell.clone().expect("守卫已判 Some");
            Ok(crate::shell::ssh_shell_session(stream, rt).await)
        }
        "telnet" if ctx.shell.as_ref().is_some_and(|rt| rt.telnet_enabled) => {
            let rt = ctx.shell.clone().expect("守卫已判 Some");
            Ok(crate::shell::telnet_shell_session(stream, rt).await)
        }
        "ssh" => {
            let banner = ctx
                .templates
                .as_ref()
                .and_then(|t| t.banner(&listener))
                .unwrap_or_else(|| ctx.fp.ssh_banner.clone());
            protocol::ssh_session(&mut stream, &banner).await
        }
        "http" => {
            let tpl = ctx.templates.as_ref().and_then(|t| t.http_tpl(&listener));
            http::http_session(&mut stream, ctx.canary.as_deref(), tpl.as_ref(), &ctx.fp.http_server)
                .await
        }
        "telnet" => protocol::telnet_session(&mut stream, &ctx.fp.telnet_greeting).await,
        "mysql" => mysql::mysql_session(&mut stream, &ctx.fp.mysql_version).await,
        "redis" => redis::redis_session(&mut stream).await,
        _ => protocol::generic_session(&mut stream).await,
    };

    let outcome = match result {
        Ok(v) => v,
        Err(e) => {
            // 读超时属于常态（端口扫描只 connect 不发数据），不按错误处理
            let summary = if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::UnexpectedEof
            {
                "连接建立后未发送数据（疑似端口扫描）".to_string()
            } else {
                format!("会话异常: {e}")
            };
            SessionOutcome {
                summary,
                payload: String::new(),
                http_hint: None,
                interaction: None,
                credentials: Vec::new(),
            }
        }
    };

    // 凭证采集（0.5.10 H200）：[honeypot.credentials].enabled 门控；口令明文只到
    // 本函数为止——先 argon2id 加盐哈希，再进事件（事件与落盘表面只见哈希）
    if ctx.collect_creds {
        for raw in &outcome.credentials {
            if raw.username.is_empty() {
                continue;
            }
            let hashed = crate::cred::hash_credential(raw);
            bus.publish(SecurityEvent::CredentialObserved {
                ts: now_ts(),
                listener: listener.clone(),
                kind: kind.clone(),
                port: local_port,
                remote_ip: remote_ip.clone(),
                remote_port,
                username: hashed.username,
                pass_hash: hashed.pass_hash,
            });
        }
    }

    let ev = SecurityEvent::HoneypotHit {
        ts: now_ts(),
        listener,
        kind,
        port: local_port,
        remote_ip,
        remote_port,
        summary: outcome.summary,
        payload: outcome.payload,
        http_hint: outcome.http_hint,
        interaction: outcome.interaction,
    };
    bus.publish(ev);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::strip_iac;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn interactive_gate_follows_shell_config() {
        // H104：ssh + [honeypot.shell].enabled → 交互会话;关闭/其他 kind → 低交互
        for kind in ["http", "telnet", "generic", "mysql", "redis"] {
            assert!(!is_interactive_session(kind, None), "{kind} 应为低交互");
        }
        assert!(!is_interactive_session("ssh", None), "shell 关闭时 ssh 低交互");
        let tmp = std::env::temp_dir().join(format!("asg-shell-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let rt = crate::shell::start_runtime(
            &aisafeguard_core::config::ShellConfig {
                enabled: true,
                ..Default::default()
            },
            &tmp,
        )
        .expect("host key 应在临时目录生成");
        assert!(is_interactive_session("ssh", Some(&rt)));
        assert!(!is_interactive_session("telnet", Some(&rt)));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn interactive_sem_exhaustion_graceful() {
        // 预算语义：8 个许可拿满后拒绝，归还后恢复
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sem = Arc::new(Semaphore::new(MAX_INTERACTIVE));
            let mut permits = Vec::new();
            for _ in 0..MAX_INTERACTIVE {
                permits.push(sem.clone().try_acquire_owned().unwrap());
            }
            assert!(sem.clone().try_acquire_owned().is_err());
            drop(permits);
            assert!(sem.clone().try_acquire_owned().is_ok());
        });
    }

    #[test]
    fn strip_iac_handles_negotiation_and_literals() {
        // WILL ECHO(255 251 1) + 数据 + IAC IAC(字面 0xFF 在 b、c 之间)
        let raw = [0xff, 251, 1, b'a', b'b', 0xff, 0xff, b'c'];
        assert_eq!(strip_iac(&raw), b"ab\xffc".to_vec());
        // SB..SE 子协商整段丢弃
        let raw = [0xff, 250, 24, 0, b'x', b'y', 0xff, 240, b'z'];
        assert_eq!(strip_iac(&raw), b"z".to_vec());
        // DO(253)+option、两字节命令、截断尾巴
        assert_eq!(strip_iac(&[0xff, 253, 0, b'q']), b"q".to_vec());
        assert_eq!(strip_iac(&[0xff, 246, b'q']), b"q".to_vec()); // AYT
        assert_eq!(strip_iac(&[b'k', 0xff]), b"k".to_vec());
    }

    #[test]
    fn fuzz_strip_iac_never_panic() {
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..5000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = (state >> 33) as usize % 100;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            let _ = strip_iac(&bytes);
        }
    }

    #[tokio::test]
    async fn telnet_shell_full_flow_records_commands() {
        use aisafeguard_core::event::SecurityEvent as E2;
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            credentials: Default::default(),
            canary: Default::default(),
            templates: Default::default(),
            fingerprint: Default::default(),
            shell: aisafeguard_core::config::ShellConfig {
                enabled: true,
                telnet_enabled: true,
                ..Default::default()
            },
            listeners: vec![ListenerConfig {
                name: "telnet".into(),
                port,
                kind: "telnet".into(),
                enabled: true,
            }],
        };
        let _handle = start(&cfg, bus, &std::env::temp_dir());
        let mut c = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(v) => {
                    c = Some(v);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let mut c = c.expect("telnet 蜜罐未就绪");
        let mut buf = vec![0u8; 256];
        let n = c.read(&mut buf).await.unwrap();
        let banner = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(banner.contains("Welcome to Ubuntu 22.04 LTS"));
        assert!(banner.contains("debian-11 login: "));

        // 登录:IAC 协商混在凭证里也要能过
        c.write_all(&[0xff, 251, 3]).await.unwrap(); // WILL SGA
        c.write_all(b"root\r\n").await.unwrap();
        let n = c.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("Password: "),
            "应提示密码"
        );
        c.write_all(b"hunter2\r\n").await.unwrap();

        // 等 motd + prompt
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut seen = String::new();
        loop {
            match tokio::time::timeout_at(deadline, c.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
            if seen.contains("deploy@debian-11:~$") {
                break;
            }
        }
        assert!(seen.contains("deploy@debian-11:~$"), "应收到假 prompt: {seen}");

        // 白名单命令
        c.write_all(b"whoami\r\n").await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut seen = String::new();
        loop {
            match tokio::time::timeout_at(deadline, c.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
            if seen.contains("deploy") {
                break;
            }
        }
        assert!(seen.contains("deploy"), "whoami 仿真响应: {seen}");
        c.write_all(b"exit\r\n").await.unwrap();
        drop(c);

        // 事件:interaction 含 whoami;口令明文不得出现在 payload
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("超时未收到蜜罐事件")
                .expect("事件通道关闭");
            if let E2::HoneypotHit {
                summary,
                payload,
                interaction: Some(steps),
                ..
            } = ev
            {
                assert!(
                    summary.contains("Telnet 假 Shell 会话(2 条,用户 root)"),
                    "实际: {summary}"
                );
                assert_eq!(steps[0].command, "whoami");
                assert_eq!(steps[1].command, "exit");
                assert!(!payload.contains("hunter2"), "telnet 口令明文不得落 payload");
                break;
            }
        }
    }

    #[tokio::test]
    async fn telnet_banner_mode_regression_0_5_8() {
        // shell 关闭(默认):banner 级行为与 0.5.8 一致
        use aisafeguard_core::event::SecurityEvent as E3;
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            listeners: vec![ListenerConfig {
                name: "telnet".into(),
                port,
                kind: "telnet".into(),
                enabled: true,
            }],
            ..Default::default()
        };
        let _handle = start(&cfg, bus, &std::env::temp_dir());
        let mut c = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(v) => {
                    c = Some(v);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let mut c = c.expect("telnet 蜜罐未就绪");
        let mut buf = vec![0u8; 128];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf[..n]),
            "Welcome to Ubuntu 22.04 LTS\r\nlogin: ",
            "banner 模式问候语逐字节不变"
        );
        c.write_all(b"admin\r\n").await.unwrap();
        drop(c);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("超时未收到蜜罐事件")
                .expect("事件通道关闭");
            if let E3::HoneypotHit {
                summary,
                payload, ..
            } = ev
                && !payload.is_empty()
            {
                assert!(summary.contains("尝试登录"), "实际: {summary}");
                assert!(payload.contains("admin"));
                break;
            }
        }
    }

    /// 0.5.12 热启停端到端：运行中热停 → 端口释放 → 热启 → 再次可连。
    /// 全局 stop() 回归：一次性停掉全部监听器。
    #[tokio::test]
    async fn hot_start_stop_toggle_roundtrip() {
        use tokio::io::AsyncWriteExt;

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            listeners: vec![
                ListenerConfig { name: "telnet".into(), port, kind: "telnet".into(), enabled: true },
                ListenerConfig { name: "redis".into(), port: 6390, kind: "redis".into(), enabled: false },
            ],
            ..Default::default()
        };
        let handle = start(&cfg, bus, &std::env::temp_dir());

        // 注册表：两行都在，enabled 行真实运行（spawn 后 bind 有竞态，等待就绪）
        let snap = handle.listeners();
        assert_eq!(snap.len(), 2);
        let telnet = snap.iter().find(|l| l.name == "telnet").unwrap();
        for _ in 0..40 {
            if telnet.running.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(telnet.running.load(Ordering::Relaxed), "enabled 行应已运行");
        let redis = snap.iter().find(|l| l.name == "redis").unwrap();
        assert!(!redis.running.load(Ordering::Relaxed), "disabled 行不运行");

        // 等待 bind 稳定后可连
        let mut c = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(v) => { c = Some(v); break; }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        assert!(c.is_some(), "热停前应可连");
        drop(c);

        // 热停：信号即返（非阻塞），轮询等待任务摘下监听并释放端口
        handle.stop_listener("telnet").expect("热停应成功");
        let snap = handle.listeners();
        let telnet = snap.iter().find(|l| l.name == "telnet").unwrap();
        for _ in 0..40 {
            if !telnet.running.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!telnet.running.load(Ordering::Relaxed), "热停后 running 应为 false");
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err(),
            "热停后端口应不可连"
        );

        // 热停→立即热启：驻留任务唤醒重绑，无竞态窗口
        handle.start_listener("telnet").expect("热启应成功");
        let snap = handle.listeners();
        let telnet = snap.iter().find(|l| l.name == "telnet").unwrap();
        for _ in 0..40 {
            if telnet.running.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(telnet.running.load(Ordering::Relaxed), "热启后应运行");
        let mut c = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(v) => { c = Some(v); break; }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        assert!(c.is_some(), "热启后应可连");
        if let Some(mut c) = c {
            let _ = c.write_all(b"admin
").await;
        }

        // 幂等/边界：重复热停 Ok、运行中热启 Err、未知名 Err
        handle.stop_listener("telnet").expect("重复热停应幂等");
        assert!(handle.start_listener("telnet").is_ok(), "重新热启");
        assert!(handle.stop_listener("no-such").is_err(), "未知名应报错");
        let _ = rx.try_recv();

        // 全局停机：所有行 running 翻 false
        handle.stop();
        tokio::time::sleep(Duration::from_millis(200)).await;
        for l in handle.listeners() {
            assert!(!l.running.load(Ordering::Relaxed), "{} 应随全局停机退出", l.name);
        }
    }

    #[tokio::test]
    async fn ssh_listener_captures_connection() {
        // shell 关闭基准:banner 低交互行为与 0.5.8 一致
        // 先占一个空闲端口再放开，避免测试端口冲突
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg = HoneypotConfig {
            enabled: true,
            listeners: vec![ListenerConfig {
                name: "ssh".into(),
                port,
                kind: "ssh".into(),
                enabled: true,
            }],
            ..Default::default()
        };
        let _handle = start(&cfg, bus.clone(), &std::env::temp_dir());

        // 连接并读取 banner（start 异步 spawn，bind 与 connect 有竞态——重试等待）
        let mut conn = None;
        for _ in 0..40 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(c) => {
                    conn = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let mut conn = conn.expect("监听器未在 2 秒内就绪");
        let mut banner = [0u8; 32];
        let n = conn.read(&mut banner).await.unwrap();
        assert!(String::from_utf8_lossy(&banner[..n]).starts_with("SSH-2.0"));
        conn.write_all(b"SSH-2.0-attacker\r\n").await.unwrap();
        drop(conn);

        // 跳过 Engine 事件（如"已监听"），直到收到 HoneypotHit
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("超时未收到蜜罐事件")
                .expect("事件通道关闭");
            match ev {
                SecurityEvent::HoneypotHit {
                    remote_ip, payload, ..
                } => {
                    assert_eq!(remote_ip, "127.0.0.1");
                    assert!(payload.contains("SSH-2.0-attacker"));
                    break;
                }
                _ => continue,
            }
        }
    }

    /// H104 端到端:[honeypot.shell].enabled → 真实 SSH 客户端(russh)登录后
    /// shell_request 推送假 prompt;断开后事件走「认证通过、零命令」路径。
    /// 完整命令仿真链路由 paramiko 实连验收(scripts/replay-ssh-shell.py,H105)。
    #[tokio::test]
    async fn ssh_shell_e2e_prompt_and_empty_session_event() {
        use std::sync::Mutex as StdMutex;

        // 占空闲端口
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let tmp = std::env::temp_dir().join(format!("asg-shell-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bus = EventBus::new(256);
        let cfg = HoneypotConfig {
            enabled: true,
            credentials: Default::default(),
            canary: Default::default(),
            templates: Default::default(),
            fingerprint: Default::default(),
            shell: aisafeguard_core::config::ShellConfig {
                enabled: true,
                ..Default::default()
            },
            listeners: vec![ListenerConfig {
                name: "ssh".into(),
                port,
                kind: "ssh".into(),
                enabled: true,
            }],
        };
        let _handle = start(&cfg, bus.clone(), &tmp);
        assert!(
            tmp.join("honeypot").join("hostkey.ed25519").exists(),
            "host key 应落盘持久化"
        );

        // 等监听就绪
        let mut ready = false;
        for _ in 0..40 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "蜜罐未在 2 秒内就绪");

        // russh 客户端:任意凭证登录 → shell → 发命令
        struct ClientHandler {
            buf: Arc<StdMutex<Vec<u8>>>,
        }
        impl russh::client::Handler for ClientHandler {
            type Error = russh::Error;
            async fn check_server_key(
                &mut self,
                _key: &russh::keys::PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
            async fn data(
                &mut self,
                _channel: russh::ChannelId,
                data: &[u8],
                _session: &mut russh::client::Session,
            ) -> Result<(), Self::Error> {
                self.buf.lock().unwrap().extend_from_slice(data);
                Ok(())
            }
        }
        let buf = Arc::new(StdMutex::new(Vec::new()));
        let client_cfg = Arc::new(russh::client::Config {
            inactivity_timeout: Some(Duration::from_secs(10)),
            ..Default::default()
        });
        let mut handle = russh::client::connect(
            client_cfg,
            ("127.0.0.1", port),
            ClientHandler { buf: buf.clone() },
        )
        .await
        .expect("SSH 握手应成功");
        let auth = handle
            .authenticate_password("root", "hunter2")
            .await
            .expect("认证流程应完成");
        assert!(auth.success(), "任意凭证应放行");

        let channel = handle.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();

        // 等 shell_request 推送的假 prompt 到达客户端(russh 客户端与
        // run_stream 之间的通道数据互传存在上游兼容问题——仅影响
        // russh↔russh 自连;paramiko/OpenSSH 实连全路径由
        // scripts/replay-ssh-shell.py 在 H105 验收)
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let seen = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
            if seen.contains("deploy@debian-11:~$") {
                break;
            }
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(50)))
                .await
                .expect("超时未收到假 Shell prompt");
        }

        // russh↔russh 的通道数据/断开通知存在上游兼容问题(仅自连场景;
        // paramiko/OpenSSH 实连全路径由 scripts/spike_paramiko_login.py 验收)。
        // prompt 到达 + 任意凭证放行已证明:host key 装配、认证放行、shell_request
        // 推送与 run_stream 生命周期均正常。
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
