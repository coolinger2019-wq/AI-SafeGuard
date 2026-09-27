#![forbid(unsafe_code)]

//! 防火墙抽象。0.1 只实现 Windows（`windows_firewall`，COM 封装），
//! 其他平台返回明确错误，等 nftables/pf 后端（见 ROADMAP 0.2）。
//!
//! 安全约束：只做 block 类规则的添加/删除；规则名统一 `aisafeguard-` 前缀，
//! 只动自己创建的规则，绝不触碰系统既有规则。

use std::net::IpAddr;

use aisafeguard_core::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub const RULE_PREFIX: &str = "aisafeguard-";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Any => "any",
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// 一条封禁规则的结构化描述。应用层只消费这个结构，不接触任何字符串命令。
#[derive(Debug, Clone, Deserialize)]
pub struct BlockSpec {
    pub direction: Direction,
    pub protocol: Protocol,
    pub remote_ip: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub note: String,
}

impl BlockSpec {
    pub fn describe(&self) -> String {
        let dir = match self.direction {
            Direction::In => "入站",
            Direction::Out => "出站",
        };
        let proto = self.protocol.as_str().to_uppercase();
        let ip = self
            .remote_ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| "任意".into());
        let port = self
            .local_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "任意".into());
        format!("封禁 {dir} {proto} 源 {ip} 目标端口 {port}")
    }
}

pub trait Firewall: Send + Sync {
    fn backend(&self) -> &'static str;
    fn is_elevated(&self) -> bool;
    fn add_block(&self, name: &str, spec: &BlockSpec) -> Result<()>;
    /// Windows 按名字删；nftables 按 (方向, IP) 删集合元素，二者都从参数里拿。
    fn remove(&self, name: &str, remote_ip: Option<IpAddr>, direction: Direction) -> Result<()>;
    /// 启动时把已启用的来源 IP 封禁同步进防火墙（幂等）。
    /// Windows COM 规则跨重启持久，默认空实现；nftables 的 set 是易失的，
    /// 需要每次启动重灌。
    fn resync(&self, _entries: &[(Direction, IpAddr)]) -> Result<()> {
        Ok(())
    }
}

/// 创建当前平台的后端。
pub fn create_backend() -> std::sync::Arc<dyn Firewall> {
    #[cfg(windows)]
    {
        std::sync::Arc::new(WindowsFirewall::new())
    }
    #[cfg(target_os = "linux")]
    {
        std::sync::Arc::new(NftablesBackend::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        std::sync::Arc::new(UnsupportedFirewall)
    }
}

/// nftables 命令构造与 Linux 提权检测——纯函数，平台无关，便于单测。
pub mod nft {
    pub const TABLE: &str = "aisafeguard";
    /// CAP_NET_ADMIN 在 CapEff 位图中的位置
    pub const CAP_NET_ADMIN: u64 = 1 << 12;

    pub const SET_IN4: &str = "blk4_in";
    pub const SET_IN6: &str = "blk6_in";
    pub const SET_OUT4: &str = "blk4_out";
    pub const SET_OUT6: &str = "blk6_out";
    pub const CHAIN_IN: &str = "blk_in";
    pub const CHAIN_OUT: &str = "blk_out";

    pub fn add_table() -> Vec<&'static str> {
        vec!["add", "table", "inet", TABLE]
    }

    pub fn add_set(name: &str, v6: bool) -> Vec<String> {
        vec![
            "add".into(),
            "set".into(),
            "inet".into(),
            TABLE.into(),
            name.into(),
            if v6 {
                "{ type ipv6_addr ; flags interval ; }".into()
            } else {
                "{ type ipv4_addr ; flags interval ; }".into()
            },
        ]
    }

    pub fn add_chain(chain: &str, hook: &str) -> Vec<String> {
        vec![
            "add".into(),
            "chain".into(),
            "inet".into(),
            TABLE.into(),
            chain.into(),
            "{ type filter hook <hook> priority mangle ; policy accept ; }"
                .replace("<hook>", hook),
        ]
    }

    /// 集合名 → 是否 IPv6。**不要用 ends_with("6") 判断**——"blk6_in" 以 "_in" 结尾
    /// （0.2 WSL 实测踩坑：v6 集合走了 v4 选择器，datatype mismatch）。
    pub fn set_is_v6(set: &str) -> bool {
        set.starts_with("blk6")
    }

    /// 按集合 family 生成正确的 drop 规则参数（v4 集合用 `ip`，v6 集合用 `ip6`）
    pub fn drop_rule_for(chain: &str, set: &str, out: bool) -> Vec<String> {
        let selector = match (set_is_v6(set), out) {
            (false, false) => "ip saddr",
            (false, true) => "ip daddr",
            (true, false) => "ip6 saddr",
            (true, true) => "ip6 daddr",
        };
        vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            TABLE.into(),
            chain.into(),
            selector.into(),
            format!("@{set}"),
            "drop".into(),
        ]
    }

    pub fn add_element(set: &str, ip: &str) -> Vec<String> {
        vec![
            "add".into(),
            "element".into(),
            "inet".into(),
            TABLE.into(),
            set.into(),
            format!("{{ {ip} }}"),
        ]
    }

    pub fn delete_element(set: &str, ip: &str) -> Vec<String> {
        vec![
            "delete".into(),
            "element".into(),
            "inet".into(),
            TABLE.into(),
            set.into(),
            format!("{{ {ip} }}"),
        ]
    }

    pub fn flush_set(set: &str) -> Vec<String> {
        vec!["flush".into(), "set".into(), "inet".into(), TABLE.into(), set.into()]
    }

    pub fn list_chain(chain: &str) -> Vec<String> {
        vec![
            "list".into(),
            "chain".into(),
            "inet".into(),
            TABLE.into(),
            chain.into(),
        ]
    }

    /// nft 的"已存在"报错按幂等成功处理
    pub fn is_exists_error(stderr: &str) -> bool {
        stderr.contains("exists")
    }

    /// 解析 /proc/self/status 的 CapEff 行，判断是否持有 CAP_NET_ADMIN
    pub fn cap_eff_grants_net_admin(status_text: &str) -> bool {
        for line in status_text.lines() {
            if let Some(hex) = line.trim().strip_prefix("CapEff:") {
                return u64::from_str_radix(hex.trim(), 16)
                    .map(|v| v & CAP_NET_ADMIN != 0)
                    .unwrap_or(false);
            }
        }
        false
    }

    /// 把 (方向, IP) 映射到对应的 nft set 名
    pub fn set_for(direction: crate::Direction, ip: std::net::IpAddr) -> &'static str {
        use crate::Direction;
        match (direction, ip) {
            (Direction::In, std::net::IpAddr::V6(_)) => SET_IN6,
            (Direction::In, _) => SET_IN4,
            (Direction::Out, std::net::IpAddr::V6(_)) => SET_OUT6,
            (Direction::Out, _) => SET_OUT4,
        }
    }
}

/// 提权检测：解析完整性级别 SID（不随系统语言变化）。
/// High = S-1-16-12288，System = S-1-16-16384。
fn detect_elevated() -> bool {
    let Ok(out) = std::process::Command::new("whoami")
        .args(["/groups", "/fo", "list"])
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.contains("S-1-16-12288") || text.contains("S-1-16-16384")
}

#[cfg(windows)]
pub struct WindowsFirewall {
    elevated: bool,
}

#[cfg(windows)]
impl WindowsFirewall {
    pub fn new() -> Self {
        Self {
            elevated: detect_elevated(),
        }
    }
}

#[cfg(windows)]
impl Default for WindowsFirewall {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl Firewall for WindowsFirewall {
    fn backend(&self) -> &'static str {
        "windows-firewall(COM)"
    }

    fn is_elevated(&self) -> bool {
        self.elevated
    }

    fn add_block(&self, name: &str, spec: &BlockSpec) -> Result<()> {
        use std::collections::HashSet;
        use windows_firewall::{Action, Address, Direction as WfDirection, FirewallRule, Port, Protocol as WfProtocol};

        // typed-builder 的条件字段无法链式续写，必填项走 builder，可选项走 setter
        let mut rule = FirewallRule::builder()
            .name(name)
            .description(format!("AI-SafeGuard: {}", spec.note))
            .action(Action::Block)
            .enabled(true)
            .direction(match spec.direction {
                Direction::In => WfDirection::In,
                Direction::Out => WfDirection::Out,
            })
            .build();
        rule.set_protocol(Some(match spec.protocol {
            Protocol::Any => WfProtocol::Any,
            Protocol::Tcp => WfProtocol::Tcp,
            Protocol::Udp => WfProtocol::Udp,
        }));
        if let Some(ip) = spec.remote_ip {
            rule.set_remote_addresses(Some(HashSet::from([Address::Ip(ip)])));
        }
        if let Some(port) = spec.local_port {
            rule.set_local_ports(Some(HashSet::from([Port::from(port)])));
        }
        windows_firewall::add_rule(&rule)
            .map_err(|e| Error::Firewall(format!("添加规则 {name} 失败: {e}（需要管理员权限）")))
    }

    fn remove(&self, name: &str, _remote_ip: Option<IpAddr>, _direction: Direction) -> Result<()> {
        if !name.starts_with(RULE_PREFIX) {
            return Err(Error::Firewall(format!("拒绝删除非 AI-SafeGuard 规则: {name}")));
        }
        match windows_firewall::rule_exists(name) {
            Ok(false) => Ok(()),
            Ok(true) => windows_firewall::remove_rule(name)
                .map_err(|e| Error::Firewall(format!("删除规则 {name} 失败: {e}"))),
            Err(e) => Err(Error::Firewall(format!("查询规则 {name} 失败: {e}"))),
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub struct UnsupportedFirewall;

#[cfg(not(any(windows, target_os = "linux")))]
impl Firewall for UnsupportedFirewall {
    fn backend(&self) -> &'static str {
        "unsupported"
    }

    fn is_elevated(&self) -> bool {
        false
    }

    fn add_block(&self, _name: &str, _spec: &BlockSpec) -> Result<()> {
        Err(Error::Firewall(
            "当前平台暂无防火墙后端（Windows COM / Linux nftables 已支持）".into(),
        ))
    }

    fn remove(&self, _name: &str, _remote_ip: Option<IpAddr>, _direction: Direction) -> Result<()> {
        Err(Error::Firewall("当前平台暂无防火墙后端".into()))
    }
}

// ---------- Linux: nftables（set 元素模型） ----------

/// nftables 后端：表 `inet aisafeguard` + 四个地址集（入/出 × v4/v6）。
/// 添加/删除 = 集合元素的增删（幂等、原子、不触碰系统既有规则）。
/// MVP 限制：仅支持按来源 IP 封禁；仅端口的封禁返回明确错误。
#[cfg(target_os = "linux")]
pub struct NftablesBackend {
    elevated: bool,
    setup: std::sync::OnceLock<()>,
}

#[cfg(target_os = "linux")]
impl NftablesBackend {
    pub fn new() -> Self {
        // 提权检测优先读 CapEff（CAP_NET_ADMIN），回退完整性 SID（容器里 SID 不变）
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let elevated = if status.contains("CapEff:") {
            nft::cap_eff_grants_net_admin(&status)
        } else {
            detect_elevated()
        };
        Self {
            elevated,
            setup: std::sync::OnceLock::new(),
        }
    }

    fn run(&self, args: &[String]) -> Result<String> {
        use std::process::Command;
        let out = Command::new("nft")
            .args(args)
            .output()
            .map_err(|e| Error::Firewall(format!("执行 nft 失败（未安装或不在 PATH）: {e}")))?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !nft::is_exists_error(&stderr) {
            return Err(Error::Firewall(format!(
                "nft {} 失败: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// 幂等建表/集/链/规则（进程内只做一次；"exists" 视为成功）
    fn ensure_setup(&self) -> Result<()> {
        if self.setup.get().is_some() {
            return Ok(());
        }
        self.run(&nft::add_table().iter().map(|s| s.to_string()).collect::<Vec<_>>())?;
        for (set, v6) in [
            (nft::SET_IN4, false),
            (nft::SET_IN6, true),
            (nft::SET_OUT4, false),
            (nft::SET_OUT6, true),
        ] {
            self.run(&nft::add_set(set, v6))?;
        }
        for (chain, hook) in [(nft::CHAIN_IN, "input"), (nft::CHAIN_OUT, "output")] {
            self.run(&nft::add_chain(chain, hook))?;
        }
        // 单条失败不短路：记下所有失败，最后统一报错——否则一条规则失败
        // 会让剩余规则全部不执行（0.2 WSL 实测踩坑）
        let mut failures = Vec::new();
        for (chain, set, out) in [
            (nft::CHAIN_IN, nft::SET_IN4, false),
            (nft::CHAIN_IN, nft::SET_IN6, false),
            (nft::CHAIN_OUT, nft::SET_OUT4, true),
            (nft::CHAIN_OUT, nft::SET_OUT6, true),
        ] {
            let listing = self.run(&nft::list_chain(chain).iter().map(|s| s.to_string()).collect::<Vec<_>>())?;
            if listing.contains(&format!("@{set}")) {
                continue;
            }
            if let Err(e) = self.run(&nft::drop_rule_for(chain, set, out)) {
                failures.push(e.to_string());
            }
        }
        if !failures.is_empty() {
            return Err(Error::Firewall(format!(
                "nftables 规则初始化部分失败: {}",
                failures.join("；")
            )));
        }
        let _ = self.setup.set(());
        Ok(())
    }

    fn element_op(&self, op: fn(&str, &str) -> Vec<String>, set: &str, ip: &IpAddr) -> Result<()> {
        self.ensure_setup()?;
        self.run(&op(set, &ip.to_string()))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl Firewall for NftablesBackend {
    fn backend(&self) -> &'static str {
        "nftables"
    }

    fn is_elevated(&self) -> bool {
        self.elevated
    }

    fn add_block(&self, _name: &str, spec: &BlockSpec) -> Result<()> {
        let Some(ip) = spec.remote_ip else {
            return Err(Error::Firewall(
                "nftables 后端 0.2 仅支持按来源 IP 封禁（仅端口封禁待后续版本）".into(),
            ));
        };
        let set = nft::set_for(spec.direction, ip);
        self.element_op(nft::add_element, set, &ip)
    }

    fn remove(&self, _name: &str, remote_ip: Option<IpAddr>, direction: Direction) -> Result<()> {
        let Some(ip) = remote_ip else {
            return Err(Error::Firewall(
                "nftables 后端删除需要来源 IP（仅端口封禁待后续版本）".into(),
            ));
        };
        let set = nft::set_for(direction, ip);
        self.element_op(nft::delete_element, set, &ip)
    }

    fn resync(&self, entries: &[(Direction, IpAddr)]) -> Result<()> {
        self.ensure_setup()?;
        for set in [nft::SET_IN4, nft::SET_IN6, nft::SET_OUT4, nft::SET_OUT6] {
            self.run(&nft::flush_set(set))?;
        }
        for (dir, ip) in entries {
            let set = nft::set_for(*dir, *ip);
            self.run(&nft::add_element(set, &ip.to_string()))?;
        }
        Ok(())
    }
}
