#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LruHashMap},
    programs::XdpContext,
};

/// 封禁名单：key = 源 IPv4（主机字节序的内存表示），value = 该源被 XDP 丢弃的
/// 包计数（0.5.1 G3 可观测：用户态遍历求和得 drop 总数，逐项得按源计数）。
/// 由组合防火墙（nftables 兜底 + XDP 镜像）双写：入站 + 任意协议 + 无端口 +
/// IPv4 且**非内网/回环**的规则（内网地址永不进快速丢弃路径）。
#[map]
static BLOCKLIST: LruHashMap<u32, u32> = LruHashMap::with_max_entries(65536, 0);

/// F807 封禁名单 v6：key = 源 IPv6 的 16 字节大端整（u128::from_be_bytes(octets)，
/// 与用户态写入侧同构）。用原语键而非自定义结构键——bpf-linker 0.9.15 会把
/// 自定义结构键的 map 静态常量折叠进 .rodata（符号从 maps 段消失，加载端找不到）。
#[map]
static BLOCKLIST_V6: LruHashMap<u128, u32> = LruHashMap::with_max_entries(65536, 0);

/// 流表（0.5.1 G1）：入站五元组元数据（目标固定本机，故 key 只含源三元组），
/// value = 观测包计数。LRU 有界：表满按最旧驱逐，不拖垮收包路径。
/// 红线对齐：只存元数据与计数，无载荷。
#[repr(C)]
struct FlowKey {
    src: u32,
    sport: u16,
    dport: u16,
}

#[map]
static FLOWS: LruHashMap<FlowKey, u32> = LruHashMap::with_max_entries(65536, 0);

/// 全局丢弃计数（0.5.1 G3）：单槽 u64，用户态一次读得 drop 总数——
/// status 轮询免遍历 BLOCKLIST。
#[map]
static DROP_TOTAL: Array<u64> = Array::with_max_entries(1, 0);

/// 程序名 aisafeguard_xdp（加载端 program_mut 按此查找）。
/// 纪律：解析失败一律放行（XDP_PASS）——快速层绝不能拖垮正常转发；
/// 真正的封禁语义由 nftables 兜底层保证。
#[xdp]
pub fn aisafeguard_xdp(ctx: XdpContext) -> u32 {
    match try_drop(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn observe_flow(src: u32, sport: u16, dport: u16) {
    // 仅 TCP(6)/UDP(17)；key 只有 8 字节，栈上拷贝避免引用越界语义
    if sport == 0 && dport == 0 {
        return;
    }
    let key = FlowKey { src, sport, dport };
    unsafe {
        if let Some(c) = FLOWS.get_ptr_mut(&key) {
            *c = (*c).wrapping_add(1);
        } else {
            let _ = FLOWS.insert(&key, &1, 0);
        }
    }
}

#[inline(always)]
fn try_drop(ctx: XdpContext) -> Result<u32, ()> {
    // 以太网帧：偏移 12..14 = ethertype。v4（0x0800）与 v6（0x86DD）双栈；
    // 其他 ethertype 一律放行（快速层绝不能拖垮正常转发）。
    let etype = u16::from_be(unsafe { *ptr_at::<u16>(&ctx, 12)? });
    match etype {
        0x0800 => try_drop_v4(ctx),
        0x86DD => try_drop_v6(ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// 封禁命中处理：逐源 +1（BLOCKLIST value），全局 +1（DROP_TOTAL），丢包。
#[inline(always)]
fn hit_and_drop<K: Copy>(map: &LruHashMap<K, u32>, key: &K) -> u32 {
    unsafe {
        if let Some(c) = map.get_ptr_mut(key) {
            *c = (*c).wrapping_add(1);
        }
        if let Some(c) = DROP_TOTAL.get_ptr_mut(0) {
            *c = (*c).wrapping_add(1);
        }
    }
    xdp_action::XDP_DROP
}

#[inline(always)]
fn try_drop_v4(ctx: XdpContext) -> Result<u32, ()> {
    // IPv4 头：23 = 协议号；源地址 26..30；四层端口 34..36/36..38（无 options 时；
    // 带 options 的包这两个偏移读到的是别的字段——计数仅是元数据信号，不影响
    // 放行/丢弃判定）
    let proto = unsafe { *ptr_at::<u8>(&ctx, 23)? };
    let raw = unsafe { *ptr_at::<u32>(&ctx, 26)? };
    let src = u32::from_be(raw);
    if proto == 6 || proto == 17 {
        let sport = u16::from_be(unsafe { *ptr_at::<u16>(&ctx, 34)? });
        let dport = u16::from_be(unsafe { *ptr_at::<u16>(&ctx, 36)? });
        observe_flow(src, sport, dport);
    }
    if unsafe { BLOCKLIST.get(&src) }.is_some() {
        Ok(hit_and_drop(&BLOCKLIST, &src))
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[inline(always)]
fn try_drop_v6(ctx: XdpContext) -> Result<u32, ()> {
    // IPv6 头（固定 40 字节）：源地址 14+8=22..38。逐字节读取（BPF 对非对齐
    // 宽加载会拒绝）；扩展头不影响源地址偏移。组装为大端 u128 作 map 键。
    let mut b = [0u8; 16];
    let mut i = 0usize;
    while i < 16 {
        b[i] = unsafe { *ptr_at::<u8>(&ctx, 22 + i)? };
        i += 1;
    }
    let key = u128::from_be_bytes(b);
    if unsafe { BLOCKLIST_V6.get(&key) }.is_some() {
        Ok(hit_and_drop(&BLOCKLIST_V6, &key))
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
