//! 采样捕获层（检测平台 MVP，设计见 docs/NGFW_EVOLUTION.md §2.2 capture 层）。
//!
//! 职责单一：打开平台数据面（Windows = WinDivert），把观测帧递给上层管线。
//! 两条铁律：
//! 1. **被动观测不动网络**——WinDivert 以 SNIFF 模式打开：驱动**不吸收**匹配包
//!    （内核照常转发），只把副本投递到句柄；因此不需要任何注回动作，
//!    捕获线程死亡/退出也不影响主机网络。帧先拷贝进有界通道（满即丢观测）。
//! 2. **优雅降级**——驱动缺失、无提权、被杀软拦截都返回明确的失败原因，
//!    由 engine 转成事件与状态展示，检测功能缺席不拖垮其余功能。

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub ts: i64,
    pub data: Vec<u8>,
}

/// 帧通道容量：满即丢观测（快路径宁可少看，不可堆积内存）。
pub const CHANNEL_CAP: usize = 4096;

/// WinDivert 抓包过滤器。control 模式只要纯 SYN（元数据，最省）；full 模式要完整 TCP 段。
pub fn win_filter(mode: &str) -> &'static str {
    if mode == "full" {
        "tcp"
    } else {
        "tcp.Syn == 1 and tcp.Ack == 0"
    }
}

/// 当前平台的捕获后端名（状态展示用）。
pub fn backend_name() -> &'static str {
    if cfg!(windows) {
        "windivert"
    } else {
        "none"
    }
}

/// 打开 WinDivert 嗅探捕获并启动分发线程，返回帧接收端。
/// WinDivert 错误原样映射成可读原因（驱动缺失/无提权/被拦截）。
///
/// SNIFF 的语义（读 vendored 驱动源码确认，见 docs/LESSONS.md）：驱动不设
/// BLOCK/ABSORB，匹配包**同时**走正常协议栈与用户态句柄——只观察、不注回。
#[cfg(windows)]
pub fn spawn_windivert(mode: &str) -> Result<std::sync::mpsc::Receiver<CapturedFrame>, String> {
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
                "缺少 WinDivert64.sys 驱动文件（需与程序同目录，见 docs/NGFW_EVOLUTION.md）".to_string()
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

/// 非 Windows 平台：暂无捕获后端（Linux nflog 为 0.3 后续项），明确失败。
#[cfg(not(windows))]
pub fn spawn_windivert(_mode: &str) -> Result<std::sync::mpsc::Receiver<CapturedFrame>, String> {
    Err("当前平台暂无流量捕获后端（Linux nflog 为 0.3 后续项）".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_mode() {
        assert_eq!(win_filter("control"), "tcp.Syn == 1 and tcp.Ack == 0");
        assert_eq!(win_filter("full"), "tcp");
        assert_eq!(win_filter("任意非法值"), "tcp.Syn == 1 and tcp.Ack == 0");
    }
}
