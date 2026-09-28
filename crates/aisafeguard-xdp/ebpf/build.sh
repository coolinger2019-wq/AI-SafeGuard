#!/usr/bin/env bash
# eBPF 程序构建（需要 nightly + rust-src + bpf-linker 0.9.x + 系统 LLVM 19 dev）。
# 产物提交入库：crates/aisafeguard-xdp/objects/aisafeguard_xdp.o（+ .sha256）。
# 修改 ebpf/src/main.rs 后必须重跑本脚本并一并提交新产物。
set -euo pipefail
cd "$(dirname "$0")"

export LLVM_SYS_191_PREFIX="${LLVM_SYS_191_PREFIX:-/usr/lib/llvm-19}"

cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core --target-dir ../target-ebpf

OUT=../objects
mkdir -p "$OUT"
cp ../target-ebpf/bpfel-unknown-none/release/aisafeguard-xdp-ebpf "$OUT/aisafeguard_xdp.o"
sha256sum "$OUT/aisafeguard_xdp.o" > "$OUT/aisafeguard_xdp.o.sha256"
ls -la "$OUT"
