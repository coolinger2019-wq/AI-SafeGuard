#!/usr/bin/env bash
# AI-SafeGuard 蜜罐深化一键演示(0.5.9 H400)——Linux/WSL。
# 演示:SSH 假 Shell(paramiko 实连)+ MySQL 蜜罐 + Redis 蜜罐 → 事件流水。
# 不需要 root(不涉封禁);需要 python3-paramiko(mysql/redis 演示用内置协议客户端)。
# 用法:bash scripts/demo-honeypot-deep.sh [二进制路径]  (默认 target/release/aisafeguard)
set -euo pipefail

BIN="${1:-$(dirname "$0")/../target/release/aisafeguard}"
[ -x "$BIN" ] || { echo "未找到 $BIN —— 先 cargo build --release"; exit 1; }
command -v python3 >/dev/null || { echo "需要 python3"; exit 1; }
python3 -c "import paramiko" 2>/dev/null || { echo "需要 paramiko(pip3 install paramiko 或 apt install python3-paramiko)"; exit 1; }

DEMO_DIR=$(mktemp -d /tmp/aisafeguard-deep.XXXXXX)
trap 'pkill -x aisafeguard >/dev/null 2>&1 || true; rm -rf "$DEMO_DIR"' EXIT

cat > "$DEMO_DIR/cfg.toml" <<'EOF'
[api]
enabled = true
port = 7420

[ai]
enabled = false

[honeypot.shell]
enabled = true             # SSH 假 Shell(中交互)
telnet_enabled = false
username = "deploy"
hostname = "debian-11"

# 新协议蜜罐:显式配置监听即开启(默认监听表不含它们)
[[honeypot.listeners]]
name = "mysql"
port = 3307
kind = "mysql"

[[honeypot.listeners]]
name = "redis"
port = 6380
kind = "redis"
EOF

echo "═══ 1) 启动引擎(假 Shell + MySQL 3307 + Redis 6380)═══"
"$BIN" --headless --config "$DEMO_DIR/cfg.toml" --data-dir "$DEMO_DIR" &
sleep 2
TOKEN=$(cat "$DEMO_DIR/api-token")

echo "═══ 2) SSH 假 Shell:paramiko 实连回放 ═══"
python3 "$(dirname "$0")/replay-ssh-shell.py" 127.0.0.1 2222

echo "═══ 3) MySQL 蜜罐:握手 → 语句假响应 ═══"
python3 - <<'PYEOF'
import socket, struct

def pkt(seq, payload):
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload

s = socket.create_connection(("127.0.0.1", 3307), timeout=5)
hdr = s.recv(4)
greeting = s.recv(hdr[0] | (hdr[1] << 8))
assert greeting[0] == 0x0a, "协议版本应为 10"
print(f"  greeting: {greeting[1:greeting.index(b'\\0')].decode()} (protocol 10)")

# HandshakeResponse41:用户名 root
resp = struct.pack("<IIB", 0x0001 | 0x0200 | 0x8000 | 0x0800_00, 0x1000000, 0x21) + b"\x00" * 23
resp += b"root\x00" + b"\x00" + b"mysql_native_password\x00"
s.sendall(pkt(1, resp))
hdr = s.recv(4)
ok = s.recv(hdr[0] | (hdr[1] << 8))
assert ok[0] == 0x00, "任意凭证应放行"
print("  认证:root 任意口令放行(OK)")

for sql in [b"SELECT 1", b"SHOW DATABASES"]:
    s.sendall(pkt(0, b"\x03" + sql))
    frames = 0
    while frames < 12:
        h = s.recv(4)
        if len(h) < 4: break
        n = h[0] | (h[1] << 8)
        if n == 0: break
        data = s.recv(n)
        frames += 1
        if data[:1] in (b"\xfe",) or n == 0: break
    print(f"  COM_QUERY {sql.decode()} → 假响应({frames} 包)")
s.sendall(pkt(0, b"\x01"))  # COM_QUIT
s.close()
print("  MYSQL PASS")
PYEOF

echo "═══ 4) Redis 蜜罐:RESP 命令假响应 + AUTH 口令脱敏 ═══"
python3 - <<'PYEOF'
import socket

def resp(*args):
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        a = a.encode()
        out += f"${len(a)}\r\n".encode() + a + b"\r\n"
    return out

s = socket.create_connection(("127.0.0.1", 6380), timeout=5)
def cmd(*args):
    s.sendall(resp(*args))
    return s.recv(512)

r = cmd("PING");  assert r == b"+PONG\r\n", r
print(f"  PING → {r!r}")
r = cmd("SET", "stage", "payload")
assert r == b"+OK\r\n", r
print(f"  SET stage payload → {r!r}")
r = cmd("SLAVEOF", "1.2.3.4", "6379")
assert r == b"+OK\r\n", r
print("  SLAVEOF 1.2.3.4 6379 → +OK(复制类行为留痕)")
r = cmd("AUTH", "hunter2")
assert r == b"+OK\r\n", r
print("  AUTH → +OK(口令脱敏落库)")
r = cmd("NOSUCHCMD")
assert r.startswith(b"-ERR unknown command"), r
print(f"  NOSUCHCMD → {r!r}")
s.sendall(resp("QUIT"))
s.close()
print("  REDIS PASS")
PYEOF

echo "═══ 5) 防守视角:事件流水(假 Shell 逐命令 interaction)═══"
sleep 1
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:7420/api/events?limit=10" \
  | python3 -c "
import json,sys
for e in json.load(sys.stdin)[:10]:
    k = e.get('kind'); s = (e.get('summary') or '')[:80]
    if k == 'honeypot_hit':
        print('  [' + k + '] ' + s)"

echo "═══ 6) 完整性:哈希链离线校验 ═══"
"$BIN" --data-dir "$DEMO_DIR" verify-log

echo "═══ 演示完成。事件与数据在 $DEMO_DIR(退出自动清理)═══"
