#!/usr/bin/env python3
"""SSH 假 Shell 回放验收(0.5.9 H105):对启用 [honeypot.shell] 的真实监听器
paramiko 实连,回放完整攻击剧本并断言每一步响应。

剧本:任意凭证登录 → 白名单命令(whoami/uname -a/ls/cat /etc/passwd)→
组合命令注入(只仿真首个)→ 未知命令(bash 文案)→ 超长输入(4KB)→ 退出。

用法:python scripts/replay-ssh-shell.py [host] [port]
默认 127.0.0.1:2222(默认蜜罐 ssh 监听端口)。
前置:配置文件 [honeypot.shell] enabled = true 后重启引擎。
"""

import socket
import sys
import time

import paramiko

PROMPT = "deploy@debian-11:~$ "


def read_until(chan: "paramiko.Channel", marker: bytes, deadline_s: float = 5.0) -> str:
    buf = b""
    end = time.time() + deadline_s
    while marker not in buf:
        if time.time() > end:
            raise TimeoutError(f"等待 {marker!r} 超时,已收 {buf[-200:]!r}")
        if chan.recv_ready():
            buf += chan.recv(4096)
        else:
            time.sleep(0.05)
    return buf.decode("utf-8", "replace")


def expect(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL:{msg}")
        sys.exit(1)
    print(f"  ok:{msg}")


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2222
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username="root", password="hunter2",
        look_for_keys=False, allow_agent=False, timeout=10,
    )
    print("[1] 登录:任意凭证放行")

    chan = client.invoke_shell()
    resp = read_until(chan, PROMPT.encode())
    expect(PROMPT in resp, f"假 prompt 到达({PROMPT!r})")

    # 白名单命令
    chan.send("whoami\n")
    resp = read_until(chan, PROMPT.encode())
    expect("deploy" in resp, "whoami → deploy")
    chan.send("uname -a\n")
    resp = read_until(chan, PROMPT.encode())
    expect("Linux debian-11" in resp, "uname -a → 合成内核串")
    chan.send("ls\n")
    resp = read_until(chan, PROMPT.encode())
    expect(".bash_history" in resp, "ls → 假家目录视图")
    chan.send("cat /etc/passwd\n")
    resp = read_until(chan, PROMPT.encode())
    expect("deploy:x:1000" in resp, "cat /etc/passwd → 内置诱饵内容")

    # 组合命令注入:只仿真首个命令,其余原样留痕
    chan.send("whoami; cat /etc/shadow\n")
    resp = read_until(chan, PROMPT.encode())
    expect("deploy" in resp, "组合命令只仿真首个(whoami)")
    expect("Access denied" not in resp and "PLACEHOLDER" not in resp, "未执行第二段")

    # 未知命令:bash 文案对齐,不泄漏蜜罐特征
    chan.send("mimikatz\n")
    resp = read_until(chan, PROMPT.encode())
    expect("bash: mimikatz: command not found" in resp, "未知命令文案对齐真实 bash")

    # 负路径:4KB 超长输入不炸会话
    chan.send("A" * 4096 + "\n")
    resp = read_until(chan, PROMPT.encode())
    expect(PROMPT in resp, "4KB 超长输入后会话存活")

    # 退出
    chan.send("exit\n")
    client.close()
    print("REPLAY PASS:全链路(登录/白名单/组合注入/未知命令/超长输入/退出)全过")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (paramiko.SSHException, socket.error, TimeoutError) as e:
        print(f"REPLAY FAIL: {e}")
        sys.exit(1)
