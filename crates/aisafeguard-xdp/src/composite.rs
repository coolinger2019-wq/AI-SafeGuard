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
/// **内网/回环/链路本地/多播地址永不镜像**（0.5.1 G2：内网前缀永不写入
/// 高速丢弃表——误配置不能经内核直丢路径放大成全内网断网；nftables 兜底层
/// 语义不变，内网侧处置仍完整）。负路径测试见 mirrorable_never_takes_protected_ips。
pub fn mirrorable(spec: &BlockSpec) -> Option<Ipv4Addr> {
    if spec.direction != Direction::In
        || spec.protocol != Protocol::Any
        || spec.local_port.is_some()
    {
        return None;
    }
    match spec.remote_ip {
        Some(IpAddr::V4(v4)) => {
            if aisafeguard_core::is_protected_ip(IpAddr::V4(v4)) {
                None
            } else {
                Some(v4)
            }
        }
        _ => None,
    }
}

/// XDP 快速层运行统计（0.5.1 G1/G3，status 只读展示；全部元数据与计数）。
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStats {
    /// 已镜像的封禁源数（= BLOCKLIST 条目数）
    pub mirrored: usize,
    /// XDP 累计丢弃包数（内核 DROP_TOTAL 计数器，重启清零）
    pub drops_total: u64,
    /// 内核流表条目数（LRU 有界 65536，只存源三元组 + 包计数）
    pub flows: usize,
}

/// Linux 侧：附加 XDP 程序 + map 句柄。
#[cfg(target_os = "linux")]
pub struct XdpFastPath {
    /// 保活：aya 对象（程序/链接/map）同生命周期
    _ebpf: aya::Ebpf,
    blocklist: aya::maps::HashMap<aya::maps::MapData, u32, u32>,
    /// 内核流表（G1：源三元组 → 包计数，LRU 有界）
    flows: aya::maps::HashMap<aya::maps::MapData, XdpFlowKey, u32>,
    /// 全局丢弃计数（G3：内核单槽 u64）
    drop_total: aya::maps::Array<aya::maps::MapData, u64>,
    /// 本侧已镜像的 IPv4（镜像集，resync 用它对账）
    mirror: std::collections::HashSet<Ipv4Addr>,
    pub iface: String,
    pub mode: XdpMode,
}

/// 内核流表 key（与 eBPF 侧 `repr(C) FlowKey` 逐字段对齐）。
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpFlowKey {
    pub src: u32,
    pub sport: u16,
    pub dport: u16,
}

// aya map key/value 约束：纯 Copy 数据按字节转译（无 unsafe 语句体，仅为声明）
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe impl aya::Pod for XdpFlowKey {}

#[cfg(target_os = "linux")]
impl XdpFastPath {
    /// 附加 XDP 程序到指定网卡并取回 BLOCKLIST map。
    /// 启动事务（G4）：load → 程序加载 → 附加 → 取 map 串行，任一步失败
    /// 即整体失败返回——半挂状态的 XDP 程序随对象一起卸载，无残留 hook。
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
        let flows: aya::maps::HashMap<aya::maps::MapData, XdpFlowKey, u32> = ebpf
            .take_map("FLOWS")
            .ok_or("eBPF 对象里找不到 map FLOWS")?
            .try_into()
            .map_err(|e| format!("map FLOWS 类型不匹配: {e}"))?;
        let drop_total: aya::maps::Array<aya::maps::MapData, u64> = ebpf
            .take_map("DROP_TOTAL")
            .ok_or("eBPF 对象里找不到 map DROP_TOTAL")?
            .try_into()
            .map_err(|e| format!("map DROP_TOTAL 类型不匹配: {e}"))?;
        Ok(Self {
            _ebpf: ebpf,
            blocklist,
            flows,
            drop_total,
            mirror: HashSet::new(),
            iface: iface.to_string(),
            mode,
        })
    }

    pub fn block(&mut self, ip: Ipv4Addr) -> std::result::Result<(), String> {
        // value 语义 = 该源被 XDP 丢弃的包计数（内核侧递增），初始 0
        self.blocklist
            .insert(u32::from(ip), 0, 0)
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

    /// 运行统计（G1/G3）：镜像数 / drop 总数 / 内核流表条目数。
    /// 流表计数需遍历 key（BPF syscall），容量上限 65536，status 按需调用。
    pub fn stats(&mut self) -> std::result::Result<XdpStats, String> {
        let mut stats = XdpStats {
            mirrored: self.mirror.len(),
            drops_total: self
                .drop_total
                .get(&0u32, 0)
                .map_err(|e| format!("读 DROP_TOTAL 失败: {e}"))?,
            flows: 0,
        };
        let mut keys = self.flows.keys();
        while let Some(k) = keys.next() {
            k.map_err(|e| format!("遍历 FLOWS 失败: {e}"))?;
            stats.flows += 1;
        }
        Ok(stats)
    }

    /// 一键清空（G3）：封禁 map 全清 + 流表全清（镜像集归零）。
    /// 兜底层 nftables 不受影响——清空后语义回落到 nftables 侧。
    pub fn clear(&mut self) -> std::result::Result<(), String> {
        self.reconcile(&[])?;
        // 先收集 key 再逐个删除（aya 迭代器借用与 remove 的可变借用冲突）
        let keys: Vec<XdpFlowKey> = self.flows.keys().filter_map(|k| k.ok()).collect();
        for k in keys {
            self.flows
                .remove(&k)
                .map_err(|e| format!("清空 FLOWS 失败: {e}"))?;
        }
        Ok(())
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

    /// 运行统计（G1/G3，status 只读）。未附加返回 None。
    pub fn fast_stats(&self) -> Option<XdpStats> {
        #[cfg(target_os = "linux")]
        {
            let mut guard = self.fast.lock().expect("XDP 状态锁中毒");
            guard.as_mut().and_then(|f| f.stats().ok())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// 一键清空 map（G3）：封禁镜像 + 流表全清；nftables 兜底不受影响。
    pub fn fast_clear(&self) -> std::result::Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let mut guard = self.fast.lock().expect("XDP 状态锁中毒");
            match guard.as_mut() {
                Some(f) => f.clear(),
                None => Ok(()),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
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

    fn remove(&self, name: &str, spec: &BlockSpec) -> Result<()> {
        // 两层都清：base 失败（如元素/表已不存在）不阻断加速层清理，
        // 否则 XDP map 会残留"nft 看不见的封禁"；原样返回 base 的结果保持 API 诚实
        let base_result = self.base.remove(name, spec);
        #[cfg(target_os = "linux")]
        if spec.direction == Direction::In && spec.local_port.is_none() {
            // 端口级规则不进 XDP map（只镜像 IP 级），无需清理
            if let Some(IpAddr::V4(ip)) = spec.remote_ip {
                if let Some(fast) = self.fast.lock().expect("XDP 状态锁中毒").as_mut() {
                    if let Err(e) = fast.unblock(ip) {
                        tracing::warn!("XDP 解封 {ip} 失败: {e}");
                    }
                }
            }
        }
        base_result
    }

    fn resync(&self, specs: &[BlockSpec]) -> Result<()> {
        self.base.resync(specs)?;
        #[cfg(target_os = "linux")]
        {
            let desired: Vec<Ipv4Addr> = specs
                .iter()
                .filter(|s| s.direction == Direction::In && s.local_port.is_none())
                .filter_map(|s| match s.remote_ip {
                    Some(IpAddr::V4(v4)) => Some(v4),
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

    fn spec(
        direction: Direction,
        protocol: Protocol,
        ip: Option<IpAddr>,
        port: Option<u16>,
    ) -> BlockSpec {
        BlockSpec {
            direction,
            protocol,
            remote_ip: ip,
            local_port: port,
            note: "test".into(),
            tag: String::new(),
        }
    }

    #[test]
    fn mirrorable_matches_ip_level_inbound_only() {
        // 完全符合：In + Any + 无端口 + IPv4
        assert_eq!(
            mirrorable(&spec(
                Direction::In,
                Protocol::Any,
                Some("203.0.113.7".parse().unwrap()),
                None
            )),
            Some("203.0.113.7".parse().unwrap())
        );
        // 出站不镜像
        assert_eq!(
            mirrorable(&spec(
                Direction::Out,
                Protocol::Any,
                Some("203.0.113.7".parse().unwrap()),
                None
            )),
            None
        );
        // 带端口不镜像（XDP 无端口粒度）
        assert_eq!(
            mirrorable(&spec(
                Direction::In,
                Protocol::Any,
                Some("203.0.113.7".parse().unwrap()),
                Some(2222)
            )),
            None
        );
        // 细粒度协议不镜像（避免封 TCP 丢 UDP 的语义放大）
        assert_eq!(
            mirrorable(&spec(
                Direction::In,
                Protocol::Tcp,
                Some("203.0.113.7".parse().unwrap()),
                None
            )),
            None
        );
        // IPv6 暂不镜像
        assert_eq!(
            mirrorable(&spec(
                Direction::In,
                Protocol::Any,
                Some("2001:db8::1".parse().unwrap()),
                None
            )),
            None
        );
    }

    #[test]
    fn mirrorable_never_takes_protected_ips() {
        // G2 硬过滤：内网/回环/链路本地/未指定地址永不写入高速丢弃表——
        // 误配置不能经内核直丢路径放大成全内网断网（nftables 兜底层语义不变）
        for ip in [
            "127.0.0.1",
            "192.168.1.50",
            "10.0.0.9",
            "172.16.4.4",
            "169.254.1.2",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
        ] {
            assert_eq!(
                mirrorable(&spec(
                    Direction::In,
                    Protocol::Any,
                    Some(ip.parse().unwrap()),
                    None
                )),
                None,
                "{ip} 不得镜像进 XDP map"
            );
        }
        // 公网地址不受影响
        assert!(
            mirrorable(&spec(
                Direction::In,
                Protocol::Any,
                Some("203.0.113.7".parse().unwrap()),
                None
            ))
            .is_some()
        );
    }
}
