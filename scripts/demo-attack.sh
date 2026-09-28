#!/usr/bin/env bash
# AI-SafeGuard 5 分钟演示（无 AI、仅快路径）——Linux/WSL。
# 演示：蜜罐诱捕 → 频次判定 → 自动封禁 → TTL 自动解封 → 哈希链校验。
# 用法：bash scripts/demo-attack.sh [二进制路径]   （默认 target/release/aisafeguard）
set -euo pipefail

BIN="${1:-$(dirname "$0")/../target/release/aisafeguard}"
[ -x "$BIN" ] || { echo "未找到 $BIN —— 先 cargo build --release"; exit 1; }
command -v nft >/dev/null || { echo "需要 nftables（sudo apt install nftables）"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "请用 root/sudo 运行（封禁需要 CAP_NET_ADMIN）"; exit 1; }

DEMO_DIR=$(mktemp -d /tmp/aisafeguard-demo.XXXXXX)
trap 'pkill -x aisafeguard >/dev/null 2>&1 || true; nft delete table inet aisafeguard >/dev/null 2>&1 || true; rm -rf "$DEMO_DIR"' EXIT

cat > "$DEMO_DIR/cfg.toml" <<'EOF'
[api]
enabled = true
port = 7420

[ai]
enabled = false          # 演示模式：无 AI、无外网依赖

[detect]
enabled = true
auto_block = true
scan_distinct_ports = 3   # 演示阈值：3 个不同蜜罐端口即判定扫描
ttl_secs = 120            # 封禁 2 分钟自动解封
EOF

echo "═══ 1) 启动引擎（无 AI，蜜罐 4 端口）═══"
"$BIN" --headless --config "$DEMO_DIR/cfg.toml" --data-dir "$DEMO_DIR" &
sleep 2
TOKEN=$(cat "$DEMO_DIR/api-token")

echo "═══ 2) 攻击者视角：连接 3 个蜜罐端口（触发扫描判定）═══"
for p in 2222 8081 2323; do timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$p" 2>/dev/null || true; done
sleep 2

echo "═══ 3) 防守视角：事件流水（detection + 自动封禁）═══"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:7420/api/events?limit=6" \
  | python3 -c "
import json,sys
for e in json.load(sys.stdin)[:6]:
    k = e.get('kind'); s = (e.get('summary') or '')[:90]
    print('  [' + k + '] ' + s)"

echo "═══ 4) 封禁效果：nftables 集合（内网保护会跳过 127.0.0.1 的自动封禁——"
echo "    换公网来源即真实封禁；此处展示判定链路）═══"
nft list set inet aisafeguard blk4_in | head -5 || true

echo "═══ 5) 完整性：哈希链离线校验 ═══"
"$BIN" --data-dir "$DEMO_DIR" verify-log

echo "═══ 演示完成。事件与数据在 $DEMO_DIR（退出自动清理）═══"
