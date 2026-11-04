//! 采样捕获层（检测平台 MVP，设计见 docs/NGFW_EVOLUTION.md §2.2 capture 层）。
//!
//! 职责单一：打开平台数据面（Windows = WinDivert，Linux = AF_PACKET），
//! 把观测帧递给上层管线。两条铁律：
//! 1. **被动观测不动网络**——WinDivert 以 SNIFF 模式打开：驱动**不吸收**匹配包
//!    （内核照常转发），只把副本投递到句柄；AF_PACKET 同样只读不注回。
//!    因此不需要任何注回动作，捕获线程死亡/退出也不影响主机网络。
//!    帧先拷贝进有界通道（满即丢观测）。
//! 2. **优雅降级**——驱动缺失、无提权（WinDivert 管理员 / AF_PACKET CAP_NET_RAW）、
//!    被杀软拦截都返回明确的失败原因，由 engine 转成事件与状态展示，
//!    检测功能缺席不拖垮其余功能。
//!
//! 帧语义全平台对齐：`CapturedFrame.data` = IP 包（L3），control 模式只投递
//! TCP 纯 SYN、full 模式只投递 TCP 段（Linux 侧在捕获线程内预过滤，与
//! Windows 的内核过滤器同语义，见 [`passes_mode_filter`])。
//! 隐私红线：不开混杂模式（AF_PACKET 默认只收本机相关帧）。

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub ts: i64,
    pub data: Vec<u8>,
}

/// 帧通道容量：满即丢观测（快路径宁可少看，不可堆积内存）。
pub const CHANNEL_CAP: usize = 4096;

/// 当前平台的捕获后端名（状态展示用）。
pub fn backend_name() -> &'static str {
    if cfg!(windows) {
        "windivert"
    } else if cfg!(target_os = "linux") {
        "afpacket"
    } else {
        "none"
    }
}

/// 打开当前平台的采样捕获并启动分发线程，返回帧接收端。
/// 平台差异（打开方式、过滤位置、L2/L3）在本层内部抹平。
#[cfg(windows)]
pub fn spawn(mode: &str) -> Result<std::sync::mpsc::Receiver<CapturedFrame>, String> {
    spawn_windivert(mode)
}

/// 打开当前平台的采样捕获并启动分发线程，返回帧接收端。
#[cfg(target_os = "linux")]
pub fn spawn(mode: &str) -> Result<std::sync::mpsc::Receiver<CapturedFrame>, String> {
    spawn_afpacket(mode)
}

/// 其余平台：暂无捕获后端，明确失败。
#[cfg(not(any(windows, target_os = "linux")))]
pub fn spawn(_mode: &str) -> Result<std::sync::mpsc::Receiver<CapturedFrame>, String> {
    Err("当前平台暂无流量捕获后端".to_string())
}

/// WinDivert 抓包过滤器。control 模式只要纯 SYN（元数据，最省）；full 模式要完整 TCP 段。
#[cfg(windows)]
pub fn win_filter(mode: &str) -> &'static str {
    if mode == "full" {
        "tcp"
    } else {
        "tcp.Syn == 1 and tcp.Ack == 0"
    }
}

/// 打开 WinDivert 嗅探捕获并启动分发线程，返回帧接收端。
/// WinDivert 错误原样映射成可读原因（驱动缺失/无提权/被拦截）。
///
/// SNIFF 的语义（读 vendored 驱动源码确认，见 docs/LESSONS.md）：驱动不设
/// BLOCK/ABSORB，匹配包**同时**走正常协议栈与用户态句柄——只观察、不注回。
#[cfg(windows)]
fn spawn_windivert(mode: &str) -> Result<std::sync::mpsc::Receiver<CapturedFrame>, String> {
    use windivert::prelude::*;

    let filter = win_filter(mode);
    let divert = WinDivert::<NetworkLayer>::network(filter, 0, WinDivertFlags::new().set_sniff())
        .map_err(open_error_reason)?;
    let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAP);
    std::thread::Builder::new()
        .name("capture-windivert".into())
        .spawn(move || {
            let mut buf = [0u8; 65535];
            loop {
                match divert.recv(&mut buf) {
                    Ok(packet) => {
                        let frame = CapturedFrame {
                            ts: aisafeguard_core::now_ts(),
                            data: packet.data.to_vec(),
                        };
                        // 满则丢本次观测：传感器绝不阻塞、不堆积
                        let _ = tx.try_send(frame);
                    }
                    Err(e) => {
                        tracing::warn!("WinDivert recv 退出（句柄关闭或驱动停止）: {e}");
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("启动捕获线程失败: {e}"))?;
    Ok(rx)
}

/// WinDivert 打开失败 → 可读原因（含处置指引）。
#[cfg(windows)]
fn open_error_reason(e: windivert::error::WinDivertError) -> String {
    use windivert::error::{WinDivertError, WinDivertOpenError};
    match e {
        WinDivertError::Open(o) => match o {
            WinDivertOpenError::MissingSYS => {
                "缺少 WinDivert64.sys 驱动文件（需与程序同目录，见 docs/NGFW_EVOLUTION.md）"
                    .to_string()
            }
            WinDivertOpenError::AccessDenied => {
                "需要管理员权限（引擎以服务模式运行时才可捕获）".to_string()
            }
            WinDivertOpenError::InvalidImageHash => {
                "WinDivert64.sys 数字签名无效（请使用官方发行版文件）".to_string()
            }
            WinDivertOpenError::DriverBlocked => {
                "WinDivert 驱动被安全软件拦截或环境不支持驱动加载".to_string()
            }
            WinDivertOpenError::IncompatibleVersion => {
                "已加载的 WinDivert 驱动版本不兼容（重启系统或统一版本）".to_string()
            }
            WinDivertOpenError::BaseFilteringEngineDisabled => {
                "系统 Base Filtering Engine 服务被禁用，无法捕获".to_string()
            }
            other => format!("WinDivert 打开失败: {other}"),
        },
        other => format!("WinDivert 打开失败: {other}"),
    }
}

/// Linux = AF_PACKET 原始套接字（L2 以太网帧）。协议 ETH_P_ALL 且不 bind →
/// 观测所有接口的本机相关帧；不开混杂模式（只看与本机相关的流量，隐私红线 §3）。
/// 需要 CAP_NET_RAW（root / systemd 服务天然具备）；无权限时映射为可读错误。
#[cfg(target_os = "linux")]
fn spawn_afpacket(mode: &str) -> Result<std::sync::mpsc::Receiver<CapturedFrame>, String> {
    use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType, eth, recv, socket_with};

    let full = mode == "full";
    let sock = socket_with(
        AddressFamily::PACKET,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(eth::ALL),
    )
    .map_err(afpacket_error_reason)?;
    let (tx, rx) = std::sync::mpsc::sync_channel(CHANNEL_CAP);
    std::thread::Builder::new()
        .name("capture-afpacket".into())
        .spawn(move || {
            let mut buf = [0u8; 65535];
            loop {
                match recv(&sock, &mut buf, RecvFlags::empty()) {
                    Ok((_, n)) => {
                        // L2 → L3 剥离（与 WinDivert 的 IP 包语义对齐），
                        // 再按模式预过滤（与 Windows 内核过滤器同语义）
                        let Some(ip) = l3_payload(&buf[..n]) else {
                            continue;
                        };
                        if !passes_mode_filter(ip, full) {
                            continue;
                        }
                        let frame = CapturedFrame {
                            ts: aisafeguard_core::now_ts(),
                            data: ip.to_vec(),
                        };
                        // 满则丢本次观测：传感器绝不阻塞、不堆积
                        let _ = tx.try_send(frame);
                    }
                    Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::AGAIN) => continue,
                    Err(e) => {
                        tracing::warn!("AF_PACKET recv 退出（接口停止或套接字关闭）: {e}");
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("启动捕获线程失败: {e}"))?;
    Ok(rx)
}

/// AF_PACKET 打开失败 → 可读原因（含处置指引）。
#[cfg(target_os = "linux")]
fn afpacket_error_reason(e: rustix::io::Errno) -> String {
    match e {
        rustix::io::Errno::PERM | rustix::io::Errno::ACCESS => {
            "需要 CAP_NET_RAW 权限（root 运行或以服务模式安装后开启捕获）".to_string()
        }
        rustix::io::Errno::NOPROTOOPT | rustix::io::Errno::PROTONOSUPPORT => {
            "内核不支持 AF_PACKET 数据面".to_string()
        }
        other => format!("AF_PACKET 套接字打开失败: {other}"),
    }
}

/// 以太网帧 → IP 包切片（L2 剥离）。Linux AF_PACKET 给 L2 帧，剥离后与
/// WinDivert 的 L3 语义对齐。IPv4/IPv6 直通；单层 VLAN(802.1Q) 解包；
/// ARP/其他协议/超短帧返回 None。
pub fn l3_payload(frame: &[u8]) -> Option<&[u8]> {
    const ETHERTYPE_IPV4: u16 = 0x0800;
    const ETHERTYPE_IPV6: u16 = 0x86DD;
    const ETHERTYPE_VLAN: u16 = 0x8100;
    if frame.len() < 14 {
        return None;
    }
    let etype = u16::from_be_bytes([frame[12], frame[13]]);
    match etype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => Some(&frame[14..]),
        ETHERTYPE_VLAN if frame.len() >= 18 => {
            let inner = u16::from_be_bytes([frame[16], frame[17]]);
            match inner {
                ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => Some(&frame[18..]),
                _ => None,
            }
        }
        _ => None,
    }
}

/// 模式过滤（Linux 捕获线程内做，与 Windows 内核过滤器同语义）：
/// control 模式只放 TCP 纯 SYN；full 模式放全部 TCP 段 + SCTP（F808：
/// CVE-2026-98548 块级特征检测需要看到 SCTP PDU）；非 TCP/UDP 且非 SCTP 一律不放。
/// 解析失败的畸形帧不放（宁缺毋滥）。Windows 侧 win_filter 不放行 SCTP——
/// SCTP 检测为 Linux-only（WinDivert 过滤语言的协议关键字所限）。
pub fn passes_mode_filter(ip: &[u8], full: bool) -> bool {
    let Ok(sp) = etherparse::SlicedPacket::from_ip(ip) else {
        return false;
    };
    // F808：full 模式放行 SCTP over IPv4（协议 132）
    if let Some(etherparse::NetSlice::Ipv4(v4)) = &sp.net
        && v4.header().protocol() == etherparse::IpNumber::SCTP
    {
        return full;
    }
    match sp.transport {
        Some(etherparse::TransportSlice::Tcp(t)) => full || (t.syn() && !t.ack()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn filter_matches_mode() {
        assert_eq!(win_filter("control"), "tcp.Syn == 1 and tcp.Ack == 0");
        assert_eq!(win_filter("full"), "tcp");
        assert_eq!(win_filter("任意非法值"), "tcp.Syn == 1 and tcp.Ack == 0");
    }

    /// 构造以太网帧（可选单层 VLAN）。
    fn eth_frame(etype: u16, with_vlan: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; if with_vlan { 18 } else { 14 }];
        out[12..14].copy_from_slice(&if with_vlan {
            0x8100u16.to_be_bytes()
        } else {
            etype.to_be_bytes()
        });
        if with_vlan {
            out[16..18].copy_from_slice(&etype.to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn l3_payload_strips_ethernet() {
        let ip = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let f = eth_frame(0x0800, false, &ip);
        assert_eq!(l3_payload(&f), Some(&ip[..]));

        let f6 = eth_frame(0x86DD, false, &ip);
        assert_eq!(l3_payload(&f6), Some(&ip[..]));

        // ARP 不是 IP
        assert_eq!(l3_payload(&eth_frame(0x0806, false, &ip)), None);
        // VLAN 单层解包后取内层 ethertype
        let fv = eth_frame(0x0800, true, &ip);
        assert_eq!(l3_payload(&fv), Some(&ip[..]));
        // VLAN 内层不是 IP
        assert_eq!(l3_payload(&eth_frame(0x0806, true, &ip)), None);
        // 超短帧
        assert_eq!(l3_payload(&f[..10]), None);
        // VLAN 帧被截断（不足 18 字节）
        assert_eq!(l3_payload(&eth_frame(0x0800, true, &ip)[..16]), None);
    }

    #[test]
    fn mode_filter_matches_platform_semantics() {
        use crate::inspect::testkit::{TcpFrame, data_frame, frame, syn_frame};
        let syn = syn_frame("203.0.113.7", 80, 40000);
        // 纯 SYN：control / full 都放
        assert!(passes_mode_filter(&syn, false));
        assert!(passes_mode_filter(&syn, true));
        // 数据段（ACK + 载荷）：只 full 放
        let data = data_frame("203.0.113.7", 40000, 80, 1001, b"GET / HTTP/1.1");
        assert!(!passes_mode_filter(&data, false));
        assert!(passes_mode_filter(&data, true));
        // SYN-ACK（回包方向）：只 full 放，control 不放（对齐 WinDivert Ack==0 过滤）
        let syn_ack = frame(TcpFrame {
            src: "10.0.0.1",
            dst: "203.0.113.7",
            sport: 80,
            dport: 40000,
            seq: 2000,
            syn: true,
            ack: true,
            payload: &[],
        });
        assert!(!passes_mode_filter(&syn_ack, false));
        assert!(passes_mode_filter(&syn_ack, true));
        // 非 IP / 畸形帧：一律不放
        assert!(!passes_mode_filter(&[0u8; 20], false));
        assert!(!passes_mode_filter(&[0u8; 20], true));
    }

    #[test]
    fn backend_name_matches_platform() {
        let name = backend_name();
        if cfg!(windows) {
            assert_eq!(name, "windivert");
        } else if cfg!(target_os = "linux") {
            assert_eq!(name, "afpacket");
        } else {
            assert_eq!(name, "none");
        }
    }
}
