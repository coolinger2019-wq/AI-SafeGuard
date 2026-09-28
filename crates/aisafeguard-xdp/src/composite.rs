//! 组合防火墙：nftables 兜底 + XDP map 镜像加速。
//!
//! 执行语义：
//! - 所有规则无条件走底层后端（nftables：完整方向/端口/协议语义 + 持久 + resync）；
//! - 满足「In 方向 + Any 协议 + 无端口限定 + IPv4」的规则**额外**镜像进 XDP map
//!   （XDP 是 IP 级全端口入站丢弃，只能承载这个子集；TCP/UDP 细粒度规则不镜像，
//!   避免"封 TCP 却把 UDP 也丢了"的语义放大）；
//! - XDP 附加失败（无 CAP_BPF、网卡不支持）只降级：组合层退化为纯 nftables，
//!   错误原因由装配方留痕；
//! - remove/resync 双写同步：XDP map 内容从 nftables 侧看是纯加速缓存，
//!   任何一侧不一致都能被 resync 重建。

#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use aisafeguard_core::error::Result;
use aisafeguard_firewall::{BlockSpec, Direction, Firewall, Protocol};

/// XDP 附加模式：skb（generic XDP，所有网卡可用）| native（驱动级，微秒级）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpMode {
    Skb,
    Native,
}

impl XdpMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "skb" => Some(Self::Skb),
            "native" => Some(Self::Native),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Skb => "skb",
            Self::Native => "native",
        }
    }
}

/// 镜像资格：规则是否能由 XDP 承载（IP 级全端口入站 IPv4）。
pub fn mirrorable(spec: &BlockSpec) -> Option<Ipv4Addr> {
    if spec.direction != Direction::In
        || spec.protocol != Protocol::Any
        || spec.local_port.is_some()
    {
        return None;
    }
    match spec.remote_ip {
        Some(IpAddr::V4(v4)) => Some(v4),
        _ => None,
    }
}

/// Linux 侧：附加 XDP 程序 + map 句柄。
#[cfg(target_os = "linux")]
pub struct XdpFastPath {
    /// 保活：aya 对象（程序/链接/map）同生命周期
    _ebpf: aya::Ebpf,
    blocklist: aya::maps::HashMap<aya::maps::MapData, u32, u32>,
    /// 本侧已镜像的 IPv4（镜像集，resync 用它对账）
    mirror: std::collections::HashSet<Ipv4Addr>,
    pub iface: String,
    pub mode: XdpMode,
}

#[cfg(target_os = "linux")]
impl XdpFastPath {
    /// 附加 XDP 程序到指定网卡并取回 BLOCKLIST map。
    pub fn attach(iface: &str, mode: XdpMode) -> std::result::Result<Self, String> {
        // to_vec()：include_bytes 数据按 1 字节对齐，堆拷贝获得分配器对齐（见 lib.rs 注）
        let obj = crate::XDP_OBJECT.to_vec();
        let mut ebpf = aya::Ebpf::load(obj.as_slice()).map_err(|e| {
            tracing::error!("eBPF load 失败详情: {e:?}");
            format!("eBPF 对象加载失败: {e}")
        })?;
        let prog: &mut aya::programs::Xdp = ebpf
            .program_mut("aisafeguard_xdp")
            .ok_or("eBPF 对象里找不到程序 aisafeguard_xdp")?
            .try_into()
            .map_err(|e| format!("程序类型不匹配: {e}"))?;
        prog.load().map_err(|e| format!("eBPF 程序加载失败: {e}"))?;
        let flags = match mode {
            XdpMode::Native => aya::programs::XdpFlags::default(),
            XdpMode::Skb => aya::programs::XdpFlags::SKB_MODE,
        };
        prog.attach(iface, flags)
            .map_err(|e| format!("XDP 附加到 {iface} 失败（{mode:?} 模式）: {e}"))?;
        let blocklist: aya::maps::HashMap<aya::maps::MapData, u32, u32> = ebpf
            .take_map("BLOCKLIST")
            .ok_or("eBPF 对象里找不到 map BLOCKLIST")?
            .try_into()
            .map_err(|e| format!("map 类型不匹配: {e}"))?;
        Ok(Self {
            _ebpf: ebpf,
            blocklist,
            mirror: HashSet::new(),
            iface: iface.to_string(),
            mode,
        })
    }

    pub fn block(&mut self, ip: Ipv4Addr) -> std::result::Result<(), String> {
        self.blocklist
            .insert(u32::from(ip), 1, 0)
            .map_err(|e| format!("XDP map 写入 {ip} 失败: {e}"))?;
        self.mirror.insert(ip);
        Ok(())
    }

    pub fn unblock(&mut self, ip: Ipv4Addr) -> std::result::Result<(), String> {
        // 不在镜像集里的 key 直接判成功（幂等，与底层 remove 语义一致）
        self.blocklist.remove(&u32::from(ip)).map_err(|e| {
            // map 里本来就没有该 key 视为已解封
            if self.mirror.contains(&ip) {
                format!("XDP map 删除 {ip} 失败: {e}")
            } else {
                String::new()
            }
        })?;
        self.mirror.remove(&ip);
        Ok(())
    }

    /// 对账：以 desired 为准增删 map 条目（resync 用）。
    pub fn reconcile(&mut self, desired: &[Ipv4Addr]) -> std::result::Result<(), String> {
        let want: HashSet<Ipv4Addr> = desired.iter().copied().collect();
        let stale: Vec<Ipv4Addr> = self.mirror.difference(&want).copied().collect();
        let missing: Vec<Ipv4Addr> = want.difference(&self.mirror).copied().collect();
        for ip in stale {
            self.unblock(ip)?;
        }
        for ip in missing {
            self.block(ip)?;
        }
        Ok(())
    }

    pub fn mirrored_count(&self) -> usize {
        self.mirror.len()
    }
}

/// 组合执行器：base（nftables）兜底 + XDP 镜像加速。
pub struct CompositeFirewall {
    base: Arc<dyn Firewall>,
    #[cfg(target_os = "linux")]
    fast: std::sync::Mutex<Option<XdpFastPath>>,
}

impl CompositeFirewall {
    pub fn new(base: Arc<dyn Firewall>) -> Self {
        Self {
            base,
            #[cfg(target_os = "linux")]
            fast: std::sync::Mutex::new(None),
        }
    }

    /// 附加 XDP 快速层（Linux；成功返回 Some，失败原因原样返回给调用方留痕）。
    #[cfg(target_os = "linux")]
    pub fn attach_fast(&self, iface: &str, mode: XdpMode) -> std::result::Result<(), String> {
        let fast = XdpFastPath::attach(iface, mode)?;
        let mut guard = self.fast.lock().expect("XDP 状态锁中毒");
        *guard = Some(fast);
        Ok(())
    }

    /// 快速层是否已附加。
    pub fn fast_active(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.fast.lock().expect("XDP 状态锁中毒").is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl Firewall for CompositeFirewall {
    fn backend(&self) -> &'static str {
        if self.fast_active() {
            "nftables+xdp"
        } else {
            self.base.backend()
        }
    }

    fn is_elevated(&self) -> bool {
        self.base.is_elevated()
    }

    fn add_block(&self, name: &str, spec: &BlockSpec) -> Result<()> {
        // 兜底层先执行（权威）：失败即整体失败，不写加速层
        self.base.add_block(name, spec)?;
        #[cfg(target_os = "linux")]
        if let Some(ip) = mirrorable(spec) {
            if let Some(fast) = self.fast.lock().expect("XDP 状态锁中毒").as_mut() {
                // 加速层失败只留 warn：兜底层已封住，语义不缩水
                if let Err(e) = fast.block(ip) {
                    tracing::warn!("XDP 镜像 {ip} 失败（nftables 已兜底）: {e}");
                }
            }
        }
        Ok(())
    }

    fn remove(&self, name: &str, remote_ip: Option<IpAddr>, direction: Direction) -> Result<()> {
        // 两层都清：base 失败（如元素/表已不存在）不阻断加速层清理，
        // 否则 XDP map 会残留"nft 看不见的封禁"；原样返回 base 的结果保持 API 诚实
        let base_result = self.base.remove(name, remote_ip, direction);
        #[cfg(target_os = "linux")]
        if direction == Direction::In {
            if let Some(IpAddr::V4(ip)) = remote_ip {
                if let Some(fast) = self.fast.lock().expect("XDP 状态锁中毒").as_mut() {
                    if let Err(e) = fast.unblock(ip) {
                        tracing::warn!("XDP 解封 {ip} 失败: {e}");
                    }
                }
            }
        }
        base_result
    }

    fn resync(&self, entries: &[(Direction, IpAddr)]) -> Result<()> {
        self.base.resync(entries)?;
        #[cfg(target_os = "linux")]
        {
            let desired: Vec<Ipv4Addr> = entries
                .iter()
                .filter(|(d, _)| *d == Direction::In)
                .filter_map(|(_, ip)| match ip {
                    IpAddr::V4(v4) => Some(*v4),
                    _ => None,
                })
                .collect();
            if let Some(fast) = self.fast.lock().expect("XDP 状态锁中毒").as_mut() {
                fast.reconcile(&desired)
                    .map_err(aisafeguard_core::error::Error::Firewall)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(direction: Direction, protocol: Protocol, ip: Option<IpAddr>, port: Option<u16>) -> BlockSpec {
        BlockSpec {
            direction,
            protocol,
            remote_ip: ip,
            local_port: port,
            note: "test".into(),
        }
    }

    #[test]
    fn mirrorable_matches_ip_level_inbound_only() {
        // 完全符合：In + Any + 无端口 + IPv4
        assert_eq!(
            mirrorable(&spec(Direction::In, Protocol::Any, Some("203.0.113.7".parse().unwrap()), None)),
            Some("203.0.113.7".parse().unwrap())
        );
        // 出站不镜像
        assert_eq!(
            mirrorable(&spec(Direction::Out, Protocol::Any, Some("203.0.113.7".parse().unwrap()), None)),
            None
        );
        // 带端口不镜像（XDP 无端口粒度）
        assert_eq!(
            mirrorable(&spec(Direction::In, Protocol::Any, Some("203.0.113.7".parse().unwrap()), Some(2222))),
            None
        );
        // 细粒度协议不镜像（避免封 TCP 丢 UDP 的语义放大）
        assert_eq!(
            mirrorable(&spec(Direction::In, Protocol::Tcp, Some("203.0.113.7".parse().unwrap()), None)),
            None
        );
        // IPv6 暂不镜像
        assert_eq!(
            mirrorable(&spec(Direction::In, Protocol::Any, Some("2001:db8::1".parse().unwrap()), None)),
            None
        );
    }
}
