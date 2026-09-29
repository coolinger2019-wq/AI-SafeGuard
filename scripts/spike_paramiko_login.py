#!/usr/bin/env python3
"""paramiko 实连假 Shell 验收(H104/H105):对启用 [honeypot.shell] 的真实监听器
回放登录 → shell → 白名单命令 → 未知命令 → 退出。

用法:python scripts/spike_paramiko_login.py [host] [port]
默认 127.0.0.1:2222(默认蜜罐 ssh 监听端口)。
"""

import socket
import sys
import time

import paramiko

PROMPT = "deploy@debian-11:~$ "


def read_until(chan: "paramiko.Channel", marker: bytes, deadline_s: float = 5.0) -> bytes:
    buf = b""
    end = time.time() + deadline_s
    while marker not in buf:
        if time.time() > end:
            raise TimeoutError(f"等待 {marker!r} 超时,已收 {buf!r}")
        if chan.recv_ready():
            buf += chan.recv(4096)
        else:
            time.sleep(0.05)
    return buf


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2222
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username="root", password="hunter2",
        look_for_keys=False, allow_agent=False, timeout=10,
    )
    print("[1] login ok:任意凭证放行")

    chan = client.invoke_shell()
    read_until(chan, PROMPT.encode())
    print(f"[2] shell prompt received: {PROMPT!r}")

    # 白名单命令:whoami 命中仿真层
    chan.send("whoami\n")
    resp = read_until(chan, PROMPT.encode()).decode("utf-8", "replace")
    print(f"[3] whoami response: {resp!r}")
    if "deploy" not in resp:
        print("FAIL:whoami 仿真响应不符预期")
        return 1

    # 未知命令:bash 文案对齐(不泄漏蜜罐特征)
    chan.send("mimikatz\n")
    resp = read_until(chan, PROMPT.encode()).decode("utf-8", "replace")
    print(f"[4] unknown command response: {resp!r}")
    if "bash: mimikatz: command not found" not in resp:
        print("FAIL:未知命令响应不符预期")
        return 1

    chan.send("exit\n")
    client.close()
    print("SPIKE PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (paramiko.SSHException, socket.error, TimeoutError) as e:
        print(f"SPIKE FAIL: {e}")
        sys.exit(1)
