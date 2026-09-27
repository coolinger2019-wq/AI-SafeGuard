#![forbid(unsafe_code)]

//! 暴露面解析的样本驱动测试（平台无关，Windows/Linux 样本全平台跑）。

use aisafeguard_detect::exposure::*;
use std::collections::HashMap;
use std::path::Path;

#[test]
fn parse_netstat_windows_listening_only() {
    // 中文版 Windows 的表头（本地化），数据行结构不变
    let sample = "\n活动连接\n\n  协议  本地地址          外部地址        状态           PID\n  \
TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234\n  \
TCP    127.0.0.1:7420         0.0.0.0:0              LISTENING       5678\n  \
TCP    [::]:445               [::]:0                 LISTENING       1234\n  \
TCP    1.2.3.4:139            1.2.3.4:56789          ESTABLISHED     999\n  \
TCP    1.2.3.4:5555           5.6.7.8:80             SYN_SENT        999\n  \
UDP    0.0.0.0:5353           *:*                                    777\n  \
UDP    [::]:1900              *:*                                    777\n";
    let rows = parse_netstat_windows(sample);
    // 3 个 LISTENING + 2 个 UDP；ESTABLISHED/SYN_SENT 不算暴露
    assert_eq!(rows.len(), 5, "{rows:?}");
    assert!(rows.contains(&("tcp".to_string(), "0.0.0.0:135".to_string(), 1234)));
    assert!(rows.contains(&("tcp".to_string(), "[::]:445".to_string(), 1234)));
    assert!(rows.contains(&("udp".to_string(), "0.0.0.0:5353".to_string(), 777)));
    assert!(rows.contains(&("udp".to_string(), "[::]:1900".to_string(), 777)));
    assert!(!rows.iter().any(|(_, a, _)| a.contains("139")));
}

#[test]
fn parse_tasklist_csv_with_quoted_comma() {
    let sample = "\"映像名称\",\"PID\",\"会话名\",\"会话#\",\"内存使用\"\n\
\"System\",\"4\",\"Services\",\"0\",\"144 K\"\n\
\"svc,.exe\",\"1234\",\"Services\",\"0\",\"1,024 K\"\n";
    let map = parse_tasklist_csv(sample);
    assert_eq!(map.get(&4).unwrap(), "System");
    // 名字里带逗号：引号感知切分不能断错
    assert_eq!(map.get(&1234).unwrap(), "svc,.exe");
    assert_eq!(map.len(), 2);
}

#[test]
fn parse_proc_net_tcp_listeners() {
    // 真实 /proc/net/tcp 片段：0A = LISTEN
    let sample = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345\n   \
1: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346\n   \
2: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12347\n";
    let rows = parse_proc_net_listeners(sample, "tcp", false);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].1, "127.0.0.1:8080"); // 1F90 = 8080
    assert_eq!(rows[0].2, 12345);
    assert_eq!(rows[1].1, "0.0.0.0:2222"); // 08AE = 2222
}

#[test]
fn parse_proc_net_udp_and_v6() {
    // UDP 未连接（远端全零）算暴露；tcp6 的 ::1 用小端 u32 组编码。
    // 样本按真实 /proc 列数（sl local rem st tx:rx tr:tm retrnsmt uid timeout inode）
    let tcp6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777\n";
    let rows = parse_proc_net_listeners(tcp6, "tcp", true);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "[::1]:22");

    let udp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
0: 00000000:14EB 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 888\n";
    let rows = parse_proc_net_listeners(udp, "udp", false);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "0.0.0.0:5355");
}

#[test]
fn hex_addr_v4_little_endian() {
    // 0100007F = 小端 → 127.0.0.1
    assert_eq!(hex_addr_to_string("0100007F", false), "127.0.0.1");
}

#[test]
fn inode_target_extraction() {
    assert_eq!(inode_from_target("socket:[12345]"), Some(12345));
    assert_eq!(inode_from_target("socket:[0]"), Some(0));
    assert_eq!(inode_from_target("pipe:[777]"), None);
    assert_eq!(inode_from_target("garbage"), None);
}

#[test]
fn assemble_linux_maps_inode_to_process() {
    let proc_root = Path::new("/proc"); // assemble 只读 comm（对无归属条目也不会 panic）
    let mut map = HashMap::new();
    map.insert(12345u64, 42u32);
    map.insert(12346u64, 99u32);
    let raw = vec![
        ("tcp".to_string(), "0.0.0.0:22".to_string(), 12345),
        ("tcp".to_string(), "0.0.0.0:80".to_string(), 12346),
        ("tcp".to_string(), "0.0.0.0:443".to_string(), 99999), // 无归属
    ];
    let entries = assemble_linux(raw, &map, proc_root);
    // 按地址排序后：:22(42) → :443(无归属) → :80(99)
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].pid, 42);
    assert_eq!(entries[1].pid, 0);
    assert_eq!(entries[2].pid, 99);
    assert_eq!(entries[1].process, "未知(无权限)");
}
