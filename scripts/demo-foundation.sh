#!/usr/bin/env bash
# AI-SafeGuard 地基版 5 分钟单机演示（0.5.6，无 AI、无多机、无外网依赖）——Linux/WSL。
# 演示闭环：HTTP 诱饵与假登录 → 可读事件（method/path/标签）→ 可解释封禁（谁/为啥/多久）
#          → 一键误报（抑制 + 自动解封 + 恢复资格）。
# 配套 GUI 演示见文末提示；端口级攻击演示见 scripts/demo-attack.sh。
# 用法：bash scripts/demo-foundation.sh [二进制路径]   （默认 target/release/aisafeguard）
set -euo pipefail

BIN="${1:-$(dirname "$0")/../target/release/aisafeguard}"
[ -x "$BIN" ] || { echo "未找到 $BIN —— 先 cargo build --release"; exit 1; }
command -v nft >/dev/null || { echo "需要 nftables（sudo apt install nftables）"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "请用 root/sudo 运行（封禁需要 CAP_NET_ADMIN）"; exit 1; }
command -v python3 >/dev/null || { echo "需要 python3（解析 API 输出）"; exit 1; }
command -v curl >/dev/null || { echo "需要 curl"; exit 1; }

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
ttl_secs = 120
EOF

echo "═══ 1) 启动引擎（无 AI，默认蜜罐含 http:8081）═══"
"$BIN" --headless --config "$DEMO_DIR/cfg.toml" --data-dir "$DEMO_DIR" &
sleep 2
TOKEN=$(cat "$DEMO_DIR/api-token")
API="http://127.0.0.1:7420"
AUTH="Authorization: Bearer $TOKEN"

echo
echo "═══ 2) 攻击者视角：假登录页（GET 下发表单）═══"
curl -s "http://127.0.0.1:8081/login" | head -c 220; echo " …"

echo
echo "═══ 3) 攻击者视角：登录提交（密码字段将被脱敏，只记「出现过」）═══"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -d "username=root&password=Tr0ub4dor&3" "http://127.0.0.1:8081/login"

echo
echo "═══ 4) 攻击者视角：敏感路径诱饵扫描 ═══"
for p in /.env /admin /wp-login.php /index.html; do
  curl -s -o /dev/null -w "  %{http_code}  $p\n" "http://127.0.0.1:8081$p"
done
sleep 2

echo
echo "═══ 5) 防守视角：事件流水可读（method/path/标签一目了然）═══"
curl -s -H "$AUTH" "$API/api/events?limit=8" | python3 -c "
import json,sys
for e in json.load(sys.stdin)[:8]:
    print('  [' + e.get('kind','') + '] ' + (e.get('summary') or '')[:110])"

echo
echo "═══ 6) 可解释封禁：手动添加一条，看「谁 / 为啥 / 多久」═══"
curl -s -o /dev/null -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"direction":"in","protocol":"any","remote_ip":"203.0.113.7","note":"演示： leaked 凭据来源"}' \
  "$API/api/rules"
curl -s -H "$AUTH" "$API/api/rules" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    print('  源 {} · {}\n    规则 {} → {}\n    TTL: {}'.format(
        r.get('source'), r.get('remote_ip'),
        (r.get('name') or '')[:28], (r.get('reason_summary') or '')[:60],
        r.get('ttl_text')))"

echo
echo "═══ 7) 一键误报闭环：抑制 + 自动解封 + 可取消 ═══"
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"remote_ip":"203.0.113.7"}' "$API/api/feedback" | python3 -c "
import json,sys
v=json.load(sys.stdin)
print('  已收弃建议 {} 条 · 已解封规则 {} 条'.format(v.get('dismissed_proposals'), v.get('removed_rules')))"
curl -s -H "$AUTH" "$API/api/feedback" | python3 -c "
import json,sys
rows=json.load(sys.stdin)
print('  抑制列表: ' + (', '.join(r['value'] for r in rows) if rows else '(空)'))"
echo "  解封后规则数: $(curl -s -H "$AUTH" "$API/api/rules" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')"

echo
echo "═══ GUI 演示提示（aisafeguard 打开界面）═══"
echo "  · 防火墙页：每条规则可见 来源 / 原因 / TTL 文案，规则行有「查看事件」「误报」"
echo "  · 事件页：点「详情」看 method/path/UA/标签 与截断载荷；「误报」一键三联动"
echo "  · AI 助手页：「误报 / 白名单抑制」小节可查、可取消抑制"
echo "  · 演示数据目录：$DEMO_DIR（退出自动清理）"
