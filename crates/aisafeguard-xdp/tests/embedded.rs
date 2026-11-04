//! 嵌入对象的运行时解析测试（仅 Linux）。
#[cfg(target_os = "linux")]
#[test]
fn embedded_object_parses() {
    let bytes = aisafeguard_xdp::XDP_OBJECT;
    println!("object len = {}", bytes.len());
    println!("head hex = {:02x?}", &bytes[..16.min(bytes.len())]);
    // 与产品路径一致：include_bytes 数据 1 字节对齐，必须堆拷贝再 load
    // （见 lib.rs 注与 docs/LESSONS.md——直接 load 报 ELF 对齐错误）
    let res = aya::Ebpf::load(bytes.to_vec().as_slice());
    match &res {
        Ok(_) => println!("LOAD OK"),
        // 非特权环境（CI runner / 普通用户）创建 map 必然 EPERM。
        // 本测试只验证嵌入对象可解析：权限不足时跳过，不判失败。
        Err(aya::EbpfError::MapError(aya::maps::MapError::CreateError { io_error, .. }))
            if io_error.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            println!("LOAD SKIP: 无 CAP_BPF/root 权限，跳过 map 创建");
            return;
        }
        Err(e) => println!("LOAD ERR: {e:#?}"),
    }
    assert!(res.is_ok(), "嵌入的 eBPF 对象必须可解析");
}

/// G4 实机冒烟（需 root；默认忽略）：附加 → 读统计 → 清空 → 卸载，
/// 验证新 FLOWS/DROP_TOTAL map 与用户态句柄类型匹配。实机清单见 docs/LINUX-TESTING.md。
/// 运行：sudo cargo test -p aisafeguard-xdp --test embedded -- --ignored
#[cfg(target_os = "linux")]
#[test]
#[ignore = "需要 root 与真实网卡（WSL2 实机验证用）"]
fn xdp_attach_smoke() {
    let iface = std::env::var("AISAFE_XDP_SMOKE_IFACE").unwrap_or_else(|_| "eth0".into());
    let mut fast = match aisafeguard_xdp::composite::XdpFastPath::attach(
        &iface,
        aisafeguard_xdp::composite::XdpMode::Skb,
    ) {
        Ok(f) => f,
        Err(e) => {
            println!("attach 失败（该环境不支持 XDP 时属预期）: {e}");
            return;
        }
    };
    // 镜像一个公网测试地址（TEST-NET-3，不产生真实流量影响）
    let test_ip = std::net::Ipv4Addr::new(203, 0, 113, 250);
    fast.block(std::net::IpAddr::V4(test_ip))
        .expect("写入 BLOCKLIST");
    let stats = fast.stats().expect("读统计");
    assert_eq!(stats.mirrored, 1);
    fast.clear().expect("清空 map");
    let after = fast.stats().expect("再读统计");
    assert_eq!(after.mirrored, 0, "清空后镜像集应为零");
    println!(
        "smoke ok: drops={} flows={}",
        after.drops_total, after.flows
    );
}
