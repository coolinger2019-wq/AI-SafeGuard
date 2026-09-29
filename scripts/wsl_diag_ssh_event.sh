#!/usr/bin/env bash
# 诊断(临时,不入库):paramiko 会话结束后服务端 TCP 与事件状态
set -uo pipefail
cd ~/aisafeguard
pgrep -x aisafeguard >/dev/null || {
  setsid nohup ./target/release/aisafeguard --headless --config /tmp/asg-manual/cfg.toml --data-dir /tmp/asg-manual > /tmp/asg-manual/engine.log 2>&1 &
  sleep 4
}
python3 scripts/replay-ssh-shell.py 127.0.0.1 2222 2>&1 | tail -1
echo "=== 回放后 TCP(2222):"
ss -tn 2>/dev/null | grep 2222 | head -5
sleep 5
echo "=== 5 秒后 TCP:"
ss -tn 2>/dev/null | grep 2222 | head -5
echo "=== honeypot_hit 事件:"
cat > /tmp/asg-manual/dump.py <<'EOF'
import sqlite3
conn = sqlite3.connect("/tmp/asg-manual/aisafeguard.db")
n = 0
for r in conn.execute("SELECT id, summary, length(interaction) FROM events WHERE kind='honeypot_hit' ORDER BY id"):
    print(r)
    n += 1
print("total honeypot_hit:", n)
EOF
python3 /tmp/asg-manual/dump.py
echo "=== 引擎日志尾部:"
tail -5 /tmp/asg-manual/engine.log
