#![forbid(unsafe_code)]

//! nftables 命令构造与 CapEff 提权检测的纯函数单测（全平台跑）。

use aisafeguard_firewall::nft;
use aisafeguard_firewall::{BlockSpec, Direction, Protocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn element_args_carry_table_set_and_ip() {
    let args = nft::add_element(nft::SET_IN4, "203.0.113.7");
    assert_eq!(
        args,
        vec![
            "add",
            "element",
            "inet",
            "aisafeguard",
            "blk4_in",
            "{ 203.0.113.7 }"
        ]
    );
    let args = nft::delete_element(nft::SET_OUT6, "2001:db8::1");
    assert_eq!(
        args,
        vec![
            "delete",
            "element",
            "inet",
            "aisafeguard",
            "blk6_out",
            "{ 2001:db8::1 }"
        ]
    );
}

#[test]
fn set_selection_by_direction_and_family() {
    let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(nft::set_for(Direction::In, v4), nft::SET_IN4);
    assert_eq!(nft::set_for(Direction::In, v6), nft::SET_IN6);
    assert_eq!(nft::set_for(Direction::Out, v4), nft::SET_OUT4);
    assert_eq!(nft::set_for(Direction::Out, v6), nft::SET_OUT6);
}

#[test]
fn rules_use_correct_hook_direction() {
    let r = nft::drop_rule_for(nft::CHAIN_IN, nft::SET_IN4, false);
    assert!(r.contains(&"ip saddr".to_string()));
    let r = nft::drop_rule_for(nft::CHAIN_OUT, nft::SET_OUT4, true);
    assert!(r.contains(&"ip daddr".to_string()));
    let r = nft::drop_rule_for(nft::CHAIN_IN, nft::SET_IN6, false);
    assert!(r.contains(&"ip6 saddr".to_string()));
    let r = nft::drop_rule_for(nft::CHAIN_OUT, nft::SET_OUT6, true);
    assert!(r.contains(&"ip6 daddr".to_string()));
}

/// 回归测试（0.2 WSL 实测踩坑）：v6 集合绝不能用 v4 选择器。
/// 旧代码用 ends_with("6") 判 family——"blk6_in" 以 "_in" 结尾，判断永远为 false。
#[test]
fn set_family_detection_and_selector_consistency() {
    for (set, v6) in [
        (nft::SET_IN4, false),
        (nft::SET_OUT4, false),
        (nft::SET_IN6, true),
        (nft::SET_OUT6, true),
    ] {
        assert_eq!(nft::set_is_v6(set), v6, "{set} 的 family 判定错误");
        for out in [false, true] {
            let r = nft::drop_rule_for(nft::CHAIN_IN, set, out);
            let selector = &r[5];
            let selector_is_v6 = selector.starts_with("ip6");
            assert_eq!(
                selector_is_v6, v6,
                "set {set} 的选择器 {selector} 与集合 family 不匹配"
            );
        }
    }
}

#[test]
fn cap_eff_parsing() {
    // 有 CAP_NET_ADMIN（bit 12）
    assert!(nft::cap_eff_grants_net_admin(
        "CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff"
    ));
    // 无 CAP_NET_ADMIN（空能力集）
    assert!(!nft::cap_eff_grants_net_admin("CapEff:\t0000000000000000\n"));
    // 无 CapEff 行 → false
    assert!(!nft::cap_eff_grants_net_admin("Name:\tbash\n"));
    // 非法 hex → false 不 panic
    assert!(!nft::cap_eff_grants_net_admin("CapEff:\tzxck\n"));
}

#[test]
fn exists_error_is_idempotent() {
    assert!(nft::is_exists_error("Error: Could not process rule: File exists"));
    assert!(!nft::is_exists_error("Error: syntax error"));
}

#[test]
fn block_spec_still_validates() {
    let spec = BlockSpec {
        direction: Direction::In,
        protocol: Protocol::Any,
        remote_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        local_port: None,
        note: "nft".into(),
    };
    assert!(spec.describe().contains("203.0.113.7"));
}
