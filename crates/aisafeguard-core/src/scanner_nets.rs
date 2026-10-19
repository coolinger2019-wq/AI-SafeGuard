//! 已知互联网测绘/安全扫描服务网段（F760 首片）。
//!
//! 背景：测绘服务（Palo Alto Xpanse、Censys、Shodan 等）的扫描是互联网的
//! 无害背景声——它们规规矩矩敲门、不做任何利用动作。第一段实验的口径④
//! 抽样里，AI 把 Xpanse 的协议指纹采集体当成「漏洞利用尝试」灰度封禁
//! （40 条抽样的 3 条错误全部此类，whois 双日核实）——这类「类级误报」
//! 的修法就是维护名单，在自动应用门控直接拒绝，建议照常产出由人工处置。
//!
//! 名单纪律：只收 whois 核实（PAN）或官方公布（Censys/Shodan 文档页）的段；
//! 拿不准归属就别加——宁可漏收（多一条人工确认），不可错收（真攻击者洗白）。

use std::net::IpAddr;

pub const NETS: &[&str] = &[
    // Palo Alto Networks Xpanse（原 Expanse）互联网测绘——whois PAN-22 核实
    "205.210.31.0/24",
    "198.235.24.0/24",
    // Censys 官方公布的扫描源段
    "162.142.125.0/24",
    "167.248.133.0/24",
    "74.120.14.0/24",
    // Shodan 官方文档公布的扫描器单机
    "66.240.236.119/32",
    "209.126.110.38/32",
    "192.241.199.165/32",
];

/// 判断来源是否属于已知测绘/扫描服务网段。仅 IPv4 名单；IPv6 一律 false
/// （出现 v6 测绘源时按名单纪律核实后加）。
pub fn is_known_scanner(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(_) => return false,
    };
    NETS.iter().any(|entry| {
        let (base, plen) = match entry.split_once('/') {
            Some((b, p)) => (b, p),
            None => (*entry, "32"),
        };
        let (Ok(base_ip), Ok(plen)) = (base.parse::<IpAddr>(), plen.parse::<u8>()) else {
            return false;
        };
        let base_v4 = match base_ip {
            IpAddr::V4(v4) => u32::from(v4),
            IpAddr::V6(_) => return false,
        };
        if plen > 32 {
            return false;
        }
        let mask = if plen == 0 {
            0
        } else {
            u32::MAX << (32 - plen)
        };
        v4 & mask == base_v4 & mask
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_nets_match_by_prefix() {
        assert!(is_known_scanner("205.210.31.7".parse().unwrap()));
        assert!(is_known_scanner("198.235.24.249".parse().unwrap()));
        assert!(is_known_scanner("162.142.125.12".parse().unwrap()));
        assert!(is_known_scanner("66.240.236.119".parse().unwrap()));
        // 同网段外一个字节不算（/24 边界）
        assert!(!is_known_scanner("205.210.30.7".parse().unwrap()));
        assert!(!is_known_scanner("205.210.32.7".parse().unwrap()));
        // 无关来源
        assert!(!is_known_scanner("8.8.8.8".parse().unwrap()));
        assert!(!is_known_scanner("203.0.113.7".parse().unwrap()));
        // v6 名单外
        assert!(!is_known_scanner("::1".parse().unwrap()));
    }
}
