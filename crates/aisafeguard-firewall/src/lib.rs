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
impl std::str::FromStr for Protocol {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            _ => Self::Any,
        })
    }
}

impl std::str::FromStr for Direction {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "out" => Self::Out,
            _ => Self::In,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockSpec {
    pub direction: Direction,
    pub protocol: Protocol,
    pub remote_ip: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub note: String,
    /// 可选标签（0.4.0 B1）：来源/用途分组（如「蜜罐」「情报」），审计与展示用，
    /// 不参与防火墙匹配语义。
    pub tag: String,
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
    /// 删除规则。spec 携带完整执行语义（方向/协议/IP/端口）——
    /// nftables 按此分派到 IP 级集合或端口级集合；Windows 按名字删。
    fn remove(&self, name: &str, spec: &BlockSpec) -> Result<()>;
    /// 启动时把已启用的封禁规则同步进防火墙（幂等）。
    /// Windows COM 规则跨重启持久，默认空实现；nftables 的 set 是易失的，
    /// 需要每次启动重灌（0.4.0 B1 起携带完整 spec——含端口级规则）。
    fn resync(&self, _specs: &[BlockSpec]) -> Result<()> {
        Ok(())
    }

    /// 元素共享语义（F793）：本后端的封禁是否落在按 IP/粒度键控的共享元素上
    /// （nftables 集合元素 / XDP map 表项）。同元素多条规则共存时，解封任务
    /// 若按「先到期先删」执行，会连带拆掉后到期规则的封禁——引擎据此决定
    /// 跳过防火墙删除、只清记账。按规则名删除的后端（Windows COM）互不
    /// 影响，恒 false。
    fn removes_shared_element(&self) -> bool {
        false
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
    // 自包含导入：本模块的纯函数刻意不依赖外部作用域
    use std::net::IpAddr;

    pub const TABLE: &str = "aisafeguard";
    /// CAP_NET_ADMIN 在 CapEff 位图中的位置
    pub const CAP_NET_ADMIN: u64 = 1 << 12;

    pub const SET_IN4: &str = "blk4_in";
    pub const SET_IN6: &str = "blk6_in";
    pub const SET_OUT4: &str = "blk4_out";
    pub const SET_OUT6: &str = "blk6_out";
    /// 端口级封禁（0.4.0 B1）：拼接类型集合 `ipv4_addr . inet_service`，
    /// 元素形如 `{ 203.0.113.7 . 2222 }`——IP 级封禁之外的第二种粒度。
    /// v6 端口级暂不支持（add_block 明确报错）。
    pub const SET_PORT_TCP_IN: &str = "blk4_tcp_in";
    pub const SET_PORT_UDP_IN: &str = "blk4_udp_in";
    pub const SET_PORT_TCP_OUT: &str = "blk4_tcp_out";
    pub const SET_PORT_UDP_OUT: &str = "blk4_udp_out";
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
            "{ type filter hook <hook> priority mangle ; policy accept ; }".replace("<hook>", hook),
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

    /// 端口级拼接集合（`type ipv4_addr . inet_service`）
    pub fn add_port_set(set: &str) -> Vec<String> {
        vec![
            "add".into(),
            "set".into(),
            "inet".into(),
            TABLE.into(),
            set.into(),
            "{".into(),
            "type".into(),
            "ipv4_addr".into(),
            ".".into(),
            "inet_service".into(),
            ";".into(),
            "}".into(),
        ]
    }

    /// 端口级集合元素：`{ 203.0.113.7 . 2222 }`
    pub fn port_element_args(set: &str, ip: &str, port: u16) -> Vec<String> {
        vec![
            "add".into(),
            "element".into(),
            "inet".into(),
            TABLE.into(),
            set.into(),
            format!("{{ {ip} . {port} }}"),
        ]
    }

    /// 端口级集合元素删除（动词 delete）
    pub fn port_element_args_delete(set: &str, ip: &str, port: u16) -> Vec<String> {
        vec![
            "delete".into(),
            "element".into(),
            "inet".into(),
            TABLE.into(),
            set.into(),
            format!("{{ {ip} . {port} }}"),
        ]
    }

    /// 端口级链规则：`ip saddr . tcp dport @blk4_tcp_in drop`（出站为 daddr）
    pub fn drop_rule_port_for(chain: &str, set: &str, proto: &str, out: bool) -> Vec<String> {
        let (addr_kw, port_kw) = match out {
            false => ("ip saddr", "dport"),
            true => ("ip daddr", "sport"),
        };
        vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            TABLE.into(),
            chain.into(),
            addr_kw.into(),
            ".".into(),
            proto.into(),
            port_kw.to_string(),
            format!("@{set}"),
            "drop".into(),
        ]
    }

    pub fn flush_set(set: &str) -> Vec<String> {
        vec![
            "flush".into(),
            "set".into(),
            "inet".into(),
            TABLE.into(),
            set.into(),
        ]
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

    pub fn list_set(set: &str) -> Vec<String> {
        vec![
            "list".into(),
            "set".into(),
            "inet".into(),
            TABLE.into(),
            set.into(),
        ]
    }

    /// ---------- F798 m1：入站 IP 选项异常观察（观察型，不参与封禁） ----------

    /// 集合带元素 1h 超时：伪造源刷集合会自动退场（有界），持续源每小时
    /// 重新进城 = 天然的再告警节奏。双端 spike 已验证（WSL 内核 6.6 + 节点
    /// nft 1.0.9），`flags dynamic, timeout` 是并列枚举（漏 timeout 标志会
    /// 报 "unexpected number"——已踩过的语法坑）。
    pub const SET_IPOPT: &str = "ipopt_srcs";

    pub fn add_ipopt_set() -> Vec<String> {
        vec![
            "add".into(),
            "set".into(),
            "inet".into(),
            TABLE.into(),
            SET_IPOPT.into(),
            "{ type ipv4_addr; flags dynamic, timeout; timeout 1h; }".into(),
        ]
    }

    /// 观察规则挂在入站链：IHL>5（带 IP 选项）计数 + 按源登记。
    /// 真实互联网里 IP 选项近乎绝迹——命中即特异信号（pwn.ai PwnEscape 类
    /// 宿主逃逸攻击的唯一可见特征就在此）。nft 规则无身份去重，重放会加倍
    /// ——添加方必须先 list 链检查（Monitor 的 ensure 已处理）。
    pub fn add_ipopt_rule() -> Vec<String> {
        vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            TABLE.into(),
            CHAIN_IN.into(),
            "ip".into(),
            "hdrlength".into(),
            ">".into(),
            "5".into(),
            "counter".into(),
            "update".into(),
            format!("@{SET_IPOPT}"),
            "{ ip saddr }".into(),
        ]
    }

    /// `nft list set` 文本 → 元素 IP 列表。带超时的元素形如
    /// `1.2.3.4 timeout 1h expires 59m...`，取每个逗号分隔 token 的首词。
    /// 元素多时 nft 可能折行——括号深度扫描拿到完整内区，跨行不丢。
    pub fn parse_set_ips(listing: &str) -> Vec<IpAddr> {
        let Some(start) = listing.find("elements = {") else {
            return Vec::new();
        };
        let bytes = listing.as_bytes();
        let mut depth = 0usize;
        let mut inner = String::new();
        for &b in &bytes[start..] {
            match b {
                b'{' => {
                    depth += 1;
                    if depth == 1 {
                        continue; // 开花括号本身不进内区
                    }
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {
                    if depth >= 1 {
                        inner.push(b as char);
                    }
                }
            }
        }
        inner
            .split(',')
            .filter_map(|tok| tok.split_whitespace().next())
            .filter_map(|addr| addr.parse::<IpAddr>().ok())
            .collect()
    }

    /// `nft list chain` 文本 → hdrlength 观察规则的 counter packets 数。
    pub fn parse_ipopt_counter(listing: &str) -> Option<u64> {
        for line in listing.lines() {
            if !line.contains("hdrlength") {
                continue;
            }
            let mut it = line.split_whitespace();
            while let Some(t) = it.next() {
                if t == "counter"
                    && it.next() == Some("packets")
                    && let Some(n) = it.next()
                {
                    return n.parse().ok();
                }
            }
        }
        None
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

    /// 端口级规则的 (协议, 方向) → set 名列表；protocol=Any → tcp+udp 两个集合
    pub fn port_sets_for(
        direction: crate::Direction,
        protocol: crate::Protocol,
    ) -> Vec<&'static str> {
        use crate::{Direction, Protocol};
        // 出站必须落 OUT 集合（旧实现把 Out+Tcp/Udp 并进 In 臂——出站端口级
        // 封禁实际写在入站链上，add/remove 对称但功能失效）
        let (tcp, udp) = match (direction, protocol) {
            (Direction::In, Protocol::Tcp) => (Some(SET_PORT_TCP_IN), None),
            (Direction::In, Protocol::Udp) => (None, Some(SET_PORT_UDP_IN)),
            (Direction::Out, Protocol::Tcp) => (Some(SET_PORT_TCP_OUT), None),
            (Direction::Out, Protocol::Udp) => (None, Some(SET_PORT_UDP_OUT)),
            (Direction::In, _) => (Some(SET_PORT_TCP_IN), Some(SET_PORT_UDP_IN)),
            (Direction::Out, _) => (Some(SET_PORT_TCP_OUT), Some(SET_PORT_UDP_OUT)),
        };
        [tcp, udp].into_iter().flatten().collect()
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
        use windows_firewall::{
            Action, Address, Direction as WfDirection, FirewallRule, Port, Protocol as WfProtocol,
        };

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

    fn remove(&self, name: &str, _spec: &BlockSpec) -> Result<()> {
        if !name.starts_with(RULE_PREFIX) {
            return Err(Error::Firewall(format!(
                "拒绝删除非 AI-SafeGuard 规则: {name}"
            )));
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

    fn remove(&self, _name: &str, _spec: &BlockSpec) -> Result<()> {
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
        self.run(
            &nft::add_table()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )?;
        for (set, v6) in [
            (nft::SET_IN4, false),
            (nft::SET_IN6, true),
            (nft::SET_OUT4, false),
            (nft::SET_OUT6, true),
        ] {
            self.run(&nft::add_set(set, v6))?;
        }
        for set in [
            nft::SET_PORT_TCP_IN,
            nft::SET_PORT_UDP_IN,
            nft::SET_PORT_TCP_OUT,
            nft::SET_PORT_UDP_OUT,
        ] {
            self.run(&nft::add_port_set(set))?;
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
            let listing = self.run(
                &nft::list_chain(chain)
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
            )?;
            if listing.contains(&format!("@{set}")) {
                continue;
            }
            if let Err(e) = self.run(&nft::drop_rule_for(chain, set, out)) {
                failures.push(e.to_string());
            }
        }
        // 端口级链规则（0.4.0 B1）：in 链两条（tcp/udp dport）、out 链两条（sport）
        for (chain, set, proto, out) in [
            (nft::CHAIN_IN, nft::SET_PORT_TCP_IN, "tcp", false),
            (nft::CHAIN_IN, nft::SET_PORT_UDP_IN, "udp", false),
            (nft::CHAIN_OUT, nft::SET_PORT_TCP_OUT, "tcp", true),
            (nft::CHAIN_OUT, nft::SET_PORT_UDP_OUT, "udp", true),
        ] {
            let listing = self.run(
                &nft::list_chain(chain)
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
            )?;
            if listing.contains(&format!("@{set}")) {
                continue;
            }
            if let Err(e) = self.run(&nft::drop_rule_port_for(chain, set, proto, out)) {
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

/// F798 m1：入站 IP 选项异常观察器（观察型）。独立于 [`Firewall`] trait——
/// 不做封禁、Windows 后端无此资产；janitor 每 60s 轮询一次并做源级差分。
/// 轮询失败只返回 Err（调用方限流记日志），观察资产损坏绝不波及封禁链。
#[cfg(target_os = "linux")]
pub mod ipopts {
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::process::Command;
    use std::sync::OnceLock;

    use super::nft;
    use aisafeguard_core::error::{Error, Result};

    /// 一次轮询的结果：规则聚合计数 + 当前在册源 + 本轮新进源。
    /// `new_sources` 语义 = 与上一轮相比**出现的变化量**：首轮快照全算新进；
    /// 持续稳定的源不重复告警；元素 1h 超时退场后再次进城的源会再告警。
    #[derive(Debug, Clone)]
    pub struct IpOptsSnapshot {
        pub total_packets: u64,
        pub sources: Vec<IpAddr>,
        pub new_sources: Vec<IpAddr>,
    }

    pub struct IpOptsMonitor {
        setup: OnceLock<()>,
        last_sources: HashSet<IpAddr>,
    }

    impl IpOptsMonitor {
        pub fn new() -> Self {
            Self {
                setup: OnceLock::new(),
                last_sources: HashSet::new(),
            }
        }

        fn run(&self, args: &[String]) -> Result<String> {
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

        /// 幂等建集合与规则。规则没有身份去重，重放会加倍——先查链再补。
        pub fn ensure(&self) -> Result<()> {
            if self.setup.get().is_some() {
                return Ok(());
            }
            self.run(&nft::add_ipopt_set())?;
            let chain = self.run(&nft::list_chain(nft::CHAIN_IN))?;
            if !chain.contains("hdrlength") {
                self.run(&nft::add_ipopt_rule())?;
            }
            let _ = self.setup.set(());
            Ok(())
        }

        /// 每轮 60s 调用一次。内部自 ensure（与主防火墙同表，进程启动时主
        /// 后端已建表；外部删表也能在下轮自愈）。
        pub fn poll(&mut self) -> Result<IpOptsSnapshot> {
            self.ensure()?;
            let set_list = self.run(&nft::list_set(nft::SET_IPOPT))?;
            let chain = self.run(&nft::list_chain(nft::CHAIN_IN))?;
            let sources = nft::parse_set_ips(&set_list);
            let current: HashSet<IpAddr> = sources.iter().copied().collect();
            let new_sources: Vec<IpAddr> =
                current.difference(&self.last_sources).copied().collect();
            self.last_sources = current;
            let total_packets = nft::parse_ipopt_counter(&chain).unwrap_or(0);
            Ok(IpOptsSnapshot {
                total_packets,
                sources,
                new_sources,
            })
        }
    }
}

#[cfg(target_os = "linux")]
impl Firewall for NftablesBackend {
    fn backend(&self) -> &'static str {
        "nftables"
    }

    fn removes_shared_element(&self) -> bool {
        true
    }

    fn is_elevated(&self) -> bool {
        self.elevated
    }

    fn add_block(&self, _name: &str, spec: &BlockSpec) -> Result<()> {
        let Some(ip) = spec.remote_ip else {
            return Err(Error::Firewall(
                "nftables 后端仅支持按来源 IP（可选端口）封禁".into(),
            ));
        };
        match spec.local_port {
            // 端口级：v4 拼接集合；any 协议 = tcp+udp 两个集合都写
            Some(port) => {
                let sets = nft::port_sets_for(spec.direction, spec.protocol);
                self.ensure_setup()?;
                for set in sets {
                    self.run(&nft::port_element_args(set, &ip.to_string(), port))?;
                }
                Ok(())
            }
            None => {
                let set = nft::set_for(spec.direction, ip);
                self.element_op(nft::add_element, set, &ip)
            }
        }
    }

    fn remove(&self, _name: &str, spec: &BlockSpec) -> Result<()> {
        let Some(ip) = spec.remote_ip else {
            return Err(Error::Firewall("nftables 后端删除需要来源 IP".into()));
        };
        match spec.local_port {
            Some(port) => {
                let sets = nft::port_sets_for(spec.direction, spec.protocol);
                self.ensure_setup()?;
                for set in sets {
                    self.run(&nft::port_element_args_delete(set, &ip.to_string(), port))?;
                }
                Ok(())
            }
            None => {
                let set = nft::set_for(spec.direction, ip);
                self.element_op(nft::delete_element, set, &ip)
            }
        }
    }

    fn resync(&self, specs: &[BlockSpec]) -> Result<()> {
        self.ensure_setup()?;
        for set in [
            nft::SET_IN4,
            nft::SET_IN6,
            nft::SET_OUT4,
            nft::SET_OUT6,
            nft::SET_PORT_TCP_IN,
            nft::SET_PORT_UDP_IN,
            nft::SET_PORT_TCP_OUT,
            nft::SET_PORT_UDP_OUT,
        ] {
            self.run(&nft::flush_set(set))?;
        }
        for spec in specs {
            let Some(ip) = spec.remote_ip else { continue };
            match spec.local_port {
                Some(port) => {
                    for set in nft::port_sets_for(spec.direction, spec.protocol) {
                        self.run(&nft::port_element_args(set, &ip.to_string(), port))?;
                    }
                }
                None => {
                    self.run(&nft::add_element(
                        nft::set_for(spec.direction, ip),
                        &ip.to_string(),
                    ))?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::nft;

    #[test]
    fn ipopt_args_shape() {
        let s = nft::add_ipopt_set();
        assert_eq!(s[4], nft::SET_IPOPT);
        assert!(s[5].contains("flags dynamic, timeout") && s[5].contains("timeout 1h"));
        let r = nft::add_ipopt_rule();
        assert_eq!(r[3], nft::TABLE);
        assert_eq!(r[4], nft::CHAIN_IN);
        assert!(r.contains(&"hdrlength".to_string()));
        assert!(r.contains(&"@ipopt_srcs".to_string()));
        assert!(r.contains(&"{ ip saddr }".to_string()));
    }

    #[test]
    fn parse_set_ips_timeout_multi_line() {
        // 带超时元的典型输出（单行）
        let one = "\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 1h\n\t\telements = { 127.0.0.1 timeout 1h expires 59m59s996ms }\n}";
        assert_eq!(
            nft::parse_set_ips(one),
            vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        // 多元 + 折行（nft 元素多时的新行渲染）
        let multi = "\t\telements = { 1.1.1.1 timeout 1h,\n\t\t\t2.2.2.2,\n\t\t\t3.3.3.3 timeout 1h expires 10m }\n}";
        let got = nft::parse_set_ips(multi);
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(got.iter().any(|ip| ip.to_string() == "2.2.2.2"));
        // 无元素/无该字段
        assert!(nft::parse_set_ips("\tno elements here").is_empty());
        assert!(nft::parse_set_ips("elements = { }").is_empty());
    }

    #[test]
    fn parse_ipopt_counter_variants() {
        let hit = "\t\tip hdrlength > 5 counter packets 2 bytes 89 update @ipopt_srcs { ip saddr }";
        assert_eq!(nft::parse_ipopt_counter(hit), Some(2));
        assert_eq!(nft::parse_ipopt_counter("\t\tip daddr @blk4_in drop"), None);
        // 折行规则（counter 与 hdrlength 分行）取第一处同行匹配：nft 单行渲染为宜，
        // 本解析不跨行——与 spike 实测输出一致
        assert_eq!(nft::parse_ipopt_counter("nothing"), None);
    }
}
