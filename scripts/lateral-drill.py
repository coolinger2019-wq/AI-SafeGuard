#!/usr/bin/env python3
"""内网横向移动红队演练脚本（0.7 F740/F745 第二段）。

⚠️ 仅限在**自有内网**对**自有资产**执行授权演练——在他人网络上运行是违法行为。
原理：从 A 机（本脚本运行处）对 B/C 两台节点的蜜罐端口依次发起连接，使 B/C 各自
观测到同一个内网源（A 的 LAN IP）→ 触发各自频次检测（scan 判定需要窗口内 ≥N 个
不同端口命中）→ 协调者产出组织印证 → 成员复验命中。全链路验证 docs/EXPERIMENT.md §5。

用法（在 A 机上，对 B/C 的蜜罐端口）：
  python lateral-drill.py --targets 192.168.1.50,192.168.1.51 \
      --ports 2222,8081,2323,5555,13306,16379 --speak

  --speak  对 HTTP 端口附带发送一个无害 GET（增加 L7 事件丰富度）
"""

import argparse
import socket
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def probe(host, port, timeout=3.0, speak=False):
    """单次连接。返回 (是否连上, 备注)。"""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return False, str(e)
    note = "open"
    try:
        if speak:
            try:
                s.sendall(b"GET /admin HTTP/1.0\r\nHost: lateral-drill\r\n\r\n")
            except OSError:
                pass
            try:
                s.settimeout(2.0)
                data = s.recv(256)
                if data:
                    note = f"open+banner({len(data)}B)"
            except OSError:
                pass
    finally:
        s.close()
    return True, note


def main():
    ap = argparse.ArgumentParser(description="内网横向演练（仅限自有网络授权使用）")
    ap.add_argument("--targets", required=True, help="逗号分隔的目标节点 IP（B/C...）")
    ap.add_argument("--ports", required=True, help="逗号分隔的蜜罐端口（open 的才产生命中）")
    ap.add_argument("--rounds", type=int, default=1, help="轮数（默认 1；一轮即满足频次判定窗口）")
    ap.add_argument("--speak", action="store_true", help="HTTP 端口附带无害 GET")
    args = ap.parse_args()

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    if not targets or not ports:
        print("targets/ports 不能为空")
        return 2

    print(f"横向演练：源 = 本机，目标 = {targets}，端口 = {ports}，{args.rounds} 轮\n")
    summary = {}
    for rnd in range(1, args.rounds + 1):
        for host in targets:
            opened = 0
            for port in ports:
                ok, note = probe(host, port, speak=args.speak)
                mark = "✓" if ok else "·"
                if ok:
                    opened += 1
                print(f"  [r{rnd}] {host}:{port} {mark} {note}")
            key = f"{host} 第 {rnd} 轮"
            summary[key] = opened
        if rnd < args.rounds:
            time.sleep(5)

    print("\n── 摘要 ──")
    ok_nodes = 0
    for key, opened in summary.items():
        print(f"{key}: open {opened}/{len(ports)}")
        if opened >= 3:
            ok_nodes += 1
    print(f"\n预期：≥3 个端口 open 的节点会产生蜜罐命中 + 频次 scan 判定；")
    print("被 ≥2 台节点观测到同一源（本机 IP）即应触发协调者印证（docs/EXPERIMENT.md §5）。")
    print("下一步：到协调者 GUI/事件流看「组织印证」，再到成员 org_events 账本看复验结果。")
    return 0 if ok_nodes >= 1 else 1


if __name__ == "__main__":
    sys.exit(main())
