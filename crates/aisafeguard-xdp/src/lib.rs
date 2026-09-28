//! XDP 快速执行层（0.3.7，设计见 docs/NGFW_EVOLUTION.md §2.4 / ROADMAP 数据面 Linux）。
//!
//! 职责：把「入站 + 任意协议 + 无端口 + IPv4」的封禁规则镜像进 eBPF map，
//! XDP 程序在内核收包路径上按源地址直接 XDP_DROP——微秒级生效，无需用户态参与。
//!
//! 落点（AGENTS：传感器/执行器分离）：本 crate 不替代 nftables，而是组合执行层——
//! 全部规则仍由 nftables 兜底（语义完整、跨重启持久、resync 可重灌），满足镜像条件的
//! 规则**额外**写入 XDP map。卸载/降级时 nftables 独立工作，语义不缩水。
//!
//! eBPF 程序：`ebpf/`（nightly + bpf-linker 单独构建，产物 `objects/aisafeguard_xdp.o`
//! 随仓库分发，运行时 include_bytes 嵌入——单二进制发布不依赖目标机工具链）。
//! 修改 ebpf 源码后必须执行 `ebpf/build.sh` 重新生成产物并一并提交。

pub mod composite;

/// 仓库内预编译的 eBPF 对象（`ebpf/build.sh` 产出）。
/// 注意：传给 aya 前必须拷贝到对齐的缓冲（`to_vec()`）——include_bytes 数据按 1 字节
/// 对齐，object crate 的零拷贝 ELF 解析报 "Invalid ELF header size or alignment"
/// （实测 WSL2 release；同一字节 load_file 成功）。见 docs/LESSONS.md。
pub const XDP_OBJECT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/objects/aisafeguard_xdp.o"
));
