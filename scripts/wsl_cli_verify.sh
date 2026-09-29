#!/usr/bin/env bash
# 实机 CLI 验收(临时):mysql/redis-cli 原生客户端连蜜罐
set -uo pipefail
cd ~/aisafeguard
pkill -x aisafeguard 2>/dev/null
rm -rf /tmp/asg-cli && mkdir -p /tmp/asg-cli
cat > /tmp/asg-cli/cfg.toml <<'EOF'
[api]
enabled = false
[ai]
enabled = false
[honeypot.listeners]
EOF
cat >> /tmp/asg-cli/cfg.toml <<'EOF'
EOF
# listeners 整表语义:写全默认四协议 + mysql/redis
python3 - <<'PY'
cfg = open("/tmp/asg-cli/cfg.toml").read()
cfg = cfg.replace("[honeypot.listeners]\n", """[[honeypot.listeners]]
name = "ssh"
port = 2222
kind = "ssh"
[[honeypot.listeners]]
name = "mysql"
port = 3307
kind = "mysql"
[[honeypot.listeners]]
name = "redis"
port = 6380
kind = "redis"
""")
open("/tmp/asg-cli/cfg.toml", "w").write(cfg)
PY
setsid nohup ./target/release/aisafeguard --headless --config /tmp/asg-cli/cfg.toml --data-dir /tmp/asg-cli > /tmp/asg-cli/engine.log 2>&1 &
for i in $(seq 1 30); do (timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/6380") 2>/dev/null && break; sleep 0.5; done

echo "=== redis-cli 实连:"
redis-cli -h 127.0.0.1 -p 6380 PING
redis-cli -h 127.0.0.1 -p 6380 SET stage payload
redis-cli -h 127.0.0.1 -p 6380 INFO server | head -3
redis-cli -h 127.0.0.1 -p 6380 SLAVEOF 1.2.3.4 6379
redis-cli -h 127.0.0.1 -p 6380 DBSIZE

echo "=== mysql CLI 实连(任意口令):"
mysql -h 127.0.0.1 -P 3307 -u root -pwrongpass -e "SELECT 1; SHOW DATABASES;" 2>&1 | head -10

echo "=== 事件核对:"
sleep 2
pkill -x aisafeguard
sleep 1
python3 - <<'PY'
import sqlite3
conn = sqlite3.connect("/tmp/asg-cli/aisafeguard.db")
for r in conn.execute("SELECT id, kind, summary FROM events WHERE kind='honeypot_hit' ORDER BY id"):
    print(r)
PY
rm -rf /tmp/asg-cli
