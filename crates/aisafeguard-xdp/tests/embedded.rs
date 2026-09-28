//! 嵌入对象的运行时解析测试（仅 Linux）。
#[cfg(target_os = "linux")]
#[test]
fn embedded_object_parses() {
    let bytes = aisafeguard_xdp::XDP_OBJECT;
    println!("object len = {}", bytes.len());
    println!("head hex = {:02x?}", &bytes[..16.min(bytes.len())]);
    let res = aya::Ebpf::load(bytes);
    match res {
        Ok(_) => println!("LOAD OK"),
        Err(e) => println!("LOAD ERR: {e:#?}"),
    }
    assert!(res.is_ok(), "嵌入的 eBPF 对象必须可解析");
}
