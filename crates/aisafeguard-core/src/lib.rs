#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod event;
pub mod l7;
pub mod secrets;

use std::net::IpAddr;

pub fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 受保护地址：回环/内网/链路本地/广播/组播/未指定。
/// AI 建议与自动封禁一律不得作用于这些地址——误封网关或自己的设备
/// 比漏掉一个攻击者代价大（AGENTS 决策记录 docs/LESSONS.md）。
pub fn is_protected_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}
