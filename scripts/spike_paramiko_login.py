#!/usr/bin/env python3
"""H101 spike 验收:paramiko 实连 russh 假 Shell。

前置:cargo run -p aisafeguard-honeypot --example ssh_shell_spike
退出标准:任意凭证登录成功 + shell channel 收到 prompt + 命令有响应 + 优雅退出。
"""

import socket
import sys
import time

import paramiko

HOST, PORT = "127.0.0.1", 2223
PROMPT = "spike@aisafeguard:~$ "


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
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST, port=PORT, username="root", password="hunter2",
        look_for_keys=False, allow_agent=False, timeout=10,
    )
    print("[1] login ok:任意凭证放行")

    chan = client.invoke_shell()
    read_until(chan, PROMPT.encode())
    print(f"[2] shell prompt received: {PROMPT!r}")

    chan.send("id\n")
    resp = read_until(chan, PROMPT.encode())
    print(f"[3] command response: {resp!r}")
    if b"command not found" not in resp:
        print("FAIL:命令响应不符预期")
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
