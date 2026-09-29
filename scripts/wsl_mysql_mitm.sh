#!/usr/bin/env bash
# mysql CLI MITM 抓包(临时):3306 代理 → 3307 蜜罐,打印双向帧
set -uo pipefail
cd ~/aisafeguard
pkill -x aisafeguard 2>/dev/null
rm -rf /tmp/asg-m4 && mkdir -p /tmp/asg-m4
cat > /tmp/asg-m4/cfg.toml <<'EOF'
[api]
enabled = false
[ai]
enabled = false
[[honeypot.listeners]]
name = "mysql"
port = 3307
kind = "mysql"
EOF
setsid nohup ./target/release/aisafeguard --headless --config /tmp/asg-m4/cfg.toml --data-dir /tmp/asg-m4 > /tmp/asg-m4/engine.log 2>&1 &
for i in $(seq 1 30); do (timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/3307") 2>/dev/null && break; sleep 0.5; done

cat > /tmp/asg-m4/proxy.py <<'PY'
import socket, threading

def pump(src, dst, tag):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            # 按帧切打印(len 3LE + seq + payload)
            off = 0
            while off + 4 <= len(data):
                ln = data[off] | (data[off+1] << 8) | (data[off+2] << 16)
                seq = data[off+3]
                end = min(off + 4 + ln, len(data))
                print(f"[{tag}] seq={seq} len={ln} {data[off+4:end][:60].hex()}", flush=True)
                off = end
                if ln == 0xffffff:
                    continue
            dst.sendall(data)
    except Exception as e:
        print(f"[{tag}] closed: {e}", flush=True)
    try:
        dst.shutdown(socket.SHUT_WR)
    except Exception:
        pass

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 3306))
srv.listen(1)
print("proxy on 3306", flush=True)
c, _ = srv.accept()
u = socket.create_connection(("127.0.0.1", 3307))
t1 = threading.Thread(target=pump, args=(u, c, "S->C"))
t2 = threading.Thread(target=pump, args=(c, u, "C->S"))
t1.start(); t2.start()
t1.join(30); t2.join(1)
PY
python3 /tmp/asg-m4/proxy.py &
PROXY_PID=$!
sleep 1
mysql -h 127.0.0.1 -P 3306 -u root -px --connect-timeout=5 --ssl-mode=DISABLED -e "SELECT 1" 2>&1 | grep -v Warning | head -3
sleep 2
kill $PROXY_PID 2>/dev/null
pkill -x aisafeguard
rm -rf /tmp/asg-m4
