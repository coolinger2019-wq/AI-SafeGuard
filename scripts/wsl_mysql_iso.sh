#!/usr/bin/env bash
# mysql CLI 逐语句二分(临时)
set -uo pipefail
cd ~/aisafeguard
pkill -x aisafeguard 2>/dev/null
rm -rf /tmp/asg-m3 && mkdir -p /tmp/asg-m3
cat > /tmp/asg-m3/cfg.toml <<'EOF'
[api]
enabled = false
[ai]
enabled = false
[[honeypot.listeners]]
name = "mysql"
port = 3307
kind = "mysql"
EOF
setsid nohup ./target/release/aisafeguard --headless --config /tmp/asg-m3/cfg.toml --data-dir /tmp/asg-m3 > /tmp/asg-m3/engine.log 2>&1 &
for i in $(seq 1 30); do (timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/3307") 2>/dev/null && break; sleep 0.5; done

M="mysql -h 127.0.0.1 -P 3307 -u root -px --connect-timeout=5 --ssl-mode=DISABLED"
echo "=== 1) OK-only 语句(SET NAMES):"
$M -e "SET NAMES utf8mb4" 2>&1 | grep -v Warning | head -2 && echo "  → exit=$?"
echo "=== 2) 空结果集(SELECT 1):"
$M -e "SELECT 1" 2>&1 | grep -v Warning | head -3
echo "=== 3) 多行结果集(SHOW DATABASES):"
$M -e "SHOW DATABASES" 2>&1 | grep -v Warning | head -8
echo "=== 4) mysql 版本:"
$M --version
pkill -x aisafeguard
rm -rf /tmp/asg-m3
