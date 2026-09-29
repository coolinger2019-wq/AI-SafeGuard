//! 主机暴露面盘点（0.2 P1："自动分析功能接口"第一步）。
//!
//! 枚举本机监听中的 TCP/UDP 端口与归属进程，产出结构化清单供：
//! 1. 存储快照与界面展示；2. AI 分析提示词（评估对外暴露风险）。
//!
//! 解析逻辑全部是平台无关的纯函数（样本驱动的单测跑在所有平台），
//! 只有 `collect()` 的进程/文件访问按平台门控。

use std::collections::HashMap;
use std::path::Path;

use aisafeguard_core::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// tcp | udp
    pub proto: String,
    /// 监听地址，如 "0.0.0.0:135"、"[::]:22"
    pub addr: String,
    pub pid: u32,
    pub process: String,
}

// ---------- Windows: netstat -ano ----------

/// 解析 `netstat -ano` 输出。列头随系统语言变化，但数据行结构稳定：
/// TCP 行以 PID 结尾且 State 列为 LISTENING（各语言版 Windows 均为英文），
/// UDP 行没有 State 列。返回 (proto, local_addr, pid)。
pub fn parse_netstat_windows(text: &str) -> Vec<(String, String, u32)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied() {
            Some(p) if p.eq_ignore_ascii_case("tcp") => {
                if parts.len() >= 5
                    && parts[3].eq_ignore_ascii_case("LISTENING")
                    && let Ok(pid) = parts[4].parse::<u32>()
                {
                    out.push(("tcp".into(), parts[1].to_string(), pid));
                }
            }
            Some(p) if p.eq_ignore_ascii_case("udp") => {
                if let Some(pid) = parts.get(3).and_then(|s| s.parse::<u32>().ok()) {
                    out.push(("udp".into(), parts[1].to_string(), pid));
                }
            }
            _ => {}
        }
    }
    out
}

/// 解析 `tasklist /fo csv /nh`：每行 `"映像名","PID","会话名",...`。
/// 手写带引号感知的 CSV 切分（进程名可能含逗号）；第二列非数字的行（表头）跳过。
pub fn parse_tasklist_csv(text: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let fields = split_csv_line(line);
        if fields.len() < 2 {
            continue;
        }
        if let Ok(pid) = fields[1].trim().parse::<u32>() {
            map.insert(pid, fields[0].trim().to_string());
        }
    }
    map
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

// ---------- Linux: /proc/net/{tcp,tcp6,udp,udp6} ----------

/// 解析 /proc/net/tcp(6)/udp(6) 的监听条目。
/// TCP 过滤 state == 0A (LISTEN)；UDP 无法区分监听，取未连接（远端全零）条目。
/// 返回 (proto, local_addr, inode)。
pub fn parse_proc_net_listeners(text: &str, proto: &str, v6: bool) -> Vec<(String, String, u64)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local = parts[1];
        let remote = parts[2];
        let state = parts[3];
        let is_listen = if proto == "tcp" {
            state == "0A"
        } else {
            remote == "00000000:0000" || remote == "00000000000000000000000000000000:0000"
        };
        if !is_listen {
            continue;
        }
        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let Ok(inode) = parts[9].parse::<u64>() else {
            continue;
        };
        // v6 地址加方括号，与 netstat 的 [::]:22 记法一致
        let addr_text = hex_addr_to_string(addr_hex, v6);
        let addr = if v6 {
            format!("[{addr_text}]:{port}")
        } else {
            format!("{addr_text}:{port}")
        };
        out.push((proto.to_string(), addr, inode));
    }
    out
}

/// /proc/net 的地址是小端 u32 序列（v4）或 4 组小端 u32（v6）的十六进制
pub fn hex_addr_to_string(hex: &str, v6: bool) -> String {
    if v6 {
        let mut bytes = Vec::with_capacity(16);
        for group in (0..hex.len()).step_by(8) {
            let chunk = &hex[group..group + 8];
            let v = u32::from_str_radix(chunk, 16).unwrap_or(0);
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        std::net::Ipv6Addr::from(bytes.try_into().unwrap_or([0u8; 16])).to_string()
    } else {
        let v = u32::from_str_radix(hex, 16).unwrap_or(0);
        std::net::Ipv4Addr::from(v.to_le_bytes()).to_string()
    }
}

/// 从 read_link 的目标 "socket:[123]" 提取 inode
pub fn inode_from_target(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
}

/// 扫描 /proc/*/fd 的 socket:[inode] 链接，建立 inode → pid 映射
pub fn socket_inode_pid_map(proc_root: &Path) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            if let Some(inode) = inode_from_target(&target.to_string_lossy()) {
                map.insert(inode, pid);
            }
        }
    }
    map
}

pub fn comm_of(proc_root: &Path, pid: u32) -> String {
    std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| format!("pid:{pid}"))
}

/// 汇编条目（Linux）：把 inode 映射为 pid/进程名
pub fn assemble_linux(
    raw: Vec<(String, String, u64)>,
    inode_pid: &HashMap<u64, u32>,
    proc_root: &Path,
) -> Vec<Entry> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (proto, addr, inode) in raw {
        if !seen.insert((proto.clone(), addr.clone())) {
            continue;
        }
        let pid = inode_pid.get(&inode).copied().unwrap_or(0);
        let process = if pid == 0 {
            "未知(无权限)".into()
        } else {
            comm_of(proc_root, pid)
        };
        out.push(Entry {
            proto,
            addr,
            pid,
            process,
        });
    }
    out.sort_by(|a, b| a.addr.cmp(&b.addr));
    out
}

/// Windows：汇编条目（netstat + tasklist）
pub fn assemble_windows(
    raw: Vec<(String, String, u32)>,
    pid_names: &HashMap<u32, String>,
) -> Vec<Entry> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (proto, addr, pid) in raw {
        if !seen.insert((proto.clone(), addr.clone())) {
            continue;
        }
        let process = pid_names
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| format!("pid:{pid}"));
        out.push(Entry {
            proto,
            addr,
            pid,
            process,
        });
    }
    out.sort_by(|a, b| a.addr.cmp(&b.addr));
    out
}

// ---------- 采集入口 ----------

#[cfg(windows)]
pub fn collect() -> Result<Vec<Entry>> {
    use std::process::Command;
    let netstat = Command::new("netstat")
        .args(["-ano"])
        .output()
        .map_err(|e| Error::Honeypot(format!("执行 netstat 失败: {e}")))?;
    let tasklist = Command::new("tasklist")
        .args(["/fo", "csv", "/nh"])
        .output()
        .map_err(|e| Error::Honeypot(format!("执行 tasklist 失败: {e}")))?;
    let raw = parse_netstat_windows(&String::from_utf8_lossy(&netstat.stdout));
    let names = parse_tasklist_csv(&String::from_utf8_lossy(&tasklist.stdout));
    Ok(assemble_windows(raw, &names))
}

#[cfg(target_os = "linux")]
pub fn collect() -> Result<Vec<Entry>> {
    let proc_root = Path::new("/proc");
    let mut raw = Vec::new();
    for (file, proto, v6) in [
        ("tcp", "tcp", false),
        ("tcp6", "tcp", true),
        ("udp", "udp", false),
        ("udp6", "udp", true),
    ] {
        let text = std::fs::read_to_string(proc_root.join("net").join(file))
            .map_err(|e| Error::Honeypot(format!("读取 /proc/net/{file} 失败: {e}")))?;
        raw.extend(parse_proc_net_listeners(&text, proto, v6));
    }
    let map = socket_inode_pid_map(proc_root);
    Ok(assemble_linux(raw, &map, proc_root))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn collect() -> Result<Vec<Entry>> {
    Err(Error::Honeypot("当前平台暂无暴露面采集器".into()))
}
