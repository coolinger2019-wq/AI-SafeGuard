#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::LruHashMap,
    programs::XdpContext,
};

/// 封禁名单：key = 源 IPv4（主机字节序的内存表示），value = 预留计数（恒 1）。
/// 由组合防火墙（nftables 兜底 + XDP 镜像）双写：入站 + 任意协议 + 无端口 + IPv4 的规则。
#[map]
static BLOCKLIST: LruHashMap<u32, u32> = LruHashMap::with_max_entries(65536, 0);

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
fn try_drop(ctx: XdpContext) -> Result<u32, ()> {
    // 以太网帧：偏移 12..14 = ethertype；IPv4 源地址在偏移 26..30
    let etype = u16::from_be(unsafe { *ptr_at::<u16>(&ctx, 12)? });
    if etype != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }
    let raw = unsafe { *ptr_at::<u32>(&ctx, 26)? };
    let src = u32::from_be(raw);
    if unsafe { BLOCKLIST.get(&src) }.is_some() {
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
