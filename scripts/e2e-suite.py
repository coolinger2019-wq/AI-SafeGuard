#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI-SafeGuard 整体功能集成测试套件（0.5.12）。

对一个真实运行的引擎（headless）做全链路功能验证，覆盖：
  1) 引擎与 API 基线（版本/监听器/token 鉴权）
  2) 蜜罐六协议抓捕（SSH/Telnet/HTTP/MySQL/Redis/Generic 实连 + 事件落库）
  3) 蜜饵与水印（backup.zip 下载 + canary-decode 溯源 + 篡改拒绝）
  4) 凭证采集与本地喷洒检测（credential_observed + credential_spray）
  5) 频次检测与内网保护（scan 判定 + 回环永不自动封禁的负路径）
  6) 防火墙规则 CRUD
  7) 误报反馈闭环（记录/列表/清除）
  8) 监听器热启停（停止→端口不可连→启动→可连）
  9) SSH 假 Shell 逐命令（可选：装有 paramiko 才跑）
 10) 暴露面扫描
 11) 事件导出与哈希链完整性（export-events + verify-log）

用法：
  python scripts/e2e-suite.py                       # 默认 target/release/aisafeguard[.exe]
  python scripts/e2e-suite.py --binary PATH --keep  # 保留工作目录供排查
  python scripts/e2e-suite.py --api-port 17420      # 避开本机已占用的 7420

退出码：0 = 全部通过；1 = 存在失败。全程只用 Python 标准库（不依赖 paramiko，
SSH 假 Shell 阶段在缺 paramiko 时自动 SKIP）。
"""

import argparse
import getpass
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PASS, FAIL, SKIP = "[PASS]", "[FAIL]", "[SKIP]"

# 各协议监听端口（与套件自写配置一致）
PORTS = {"ssh": 2222, "http": 8081, "telnet": 2323, "generic": 1337, "mysql": 3307, "redis": 6380}


class SuiteError(Exception):
    """阶段内失败：消息会进结果表。"""


class Suite:
    def __init__(self, binary: str, api_port: int, keep: bool, port_base: int = 0):
        self.binary = binary
        self.api_port = api_port
        self.keep = keep
        # 端口基座：与本机已在跑的实例共存时用 --port-base 整体错开蜜罐端口
        self.port_base = port_base
        self.__init_state()

    def port(self, kind: str) -> int:
        return PORTS[kind] + self.port_base

    def __init_state(self):
        self.workdir = None
        self.cfg_path = None
        self.proc = None
        self.log_path = None
        self.token = ""
        self.results = []  # (phase_title, status, detail)

    # ---------- 引擎生命周期 ----------

    def write_config(self):
        data = self.workdir
        cfg = f"""[general]
data_dir = '{data}'

[api]
enabled = true
port = {self.api_port}

[ai]
enabled = false

[honeypot.shell]
enabled = true
telnet_enabled = false
username = "deploy"
hostname = "debian-11"

[[honeypot.listeners]]
name = "ssh"
port = {self.port('ssh')}
kind = "ssh"

[[honeypot.listeners]]
name = "http"
port = {self.port('http')}
kind = "http"

[[honeypot.listeners]]
name = "telnet"
port = {self.port('telnet')}
kind = "telnet"

[[honeypot.listeners]]
name = "generic"
port = {self.port('generic')}
kind = "generic"

[[honeypot.listeners]]
name = "mysql"
port = {self.port('mysql')}
kind = "mysql"

[[honeypot.listeners]]
name = "redis"
port = {self.port('redis')}
kind = "redis"

[honeypot.canary]
enabled = true
"""
        self.cfg_path = os.path.join(data, "cfg.toml")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            f.write(cfg)

    def start_engine(self):
        self.write_config()
        self.log_path = os.path.join(self.workdir, "engine.log")
        log = open(self.log_path, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            [self.binary, "--headless", "--config", self.cfg_path,
             "--data-dir", self.workdir],
            stdout=log, stderr=subprocess.STDOUT,
        )
        # 等 token 与 API 就绪（冷启动可能 >2s）
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SuiteError(f"引擎进程提前退出，日志尾部:\n{self.log_tail()}")
            tok = self.fetch_token()
            if tok:
                self.token = tok
                try:
                    st = self.api("/api/status")
                    if all(l["running"] for l in st["listeners"]) and len(st["listeners"]) == 6:
                        return
                except Exception:
                    pass
            time.sleep(0.5)
        raise SuiteError(f"引擎 60 秒内未就绪，日志尾部:\n{self.log_tail()}")

    def fetch_token(self):
        try:
            r = subprocess.run(
                [self.binary, "--print-token", "--config", self.cfg_path,
                 "--data-dir", self.workdir],
                capture_output=True, text=True, timeout=15,
            )
            lines = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
            return lines[-1] if lines else ""
        except Exception:
            return ""

    def stop_engine(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def log_tail(self, n=15):
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                return "".join(f.readlines()[-n:])
        except OSError:
            return "(无日志)"

    def cleanup(self):
        self.stop_engine()
        if self.workdir and not self.keep:
            shutil.rmtree(self.workdir, ignore_errors=True)

    # ---------- 工具 ----------

    def api(self, path, method="GET", body=None, with_token=True):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.api_port}{path}",
            method=method,
            headers={"Authorization": f"Bearer {self.token}"} if with_token else {},
        )
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, data=data, timeout=10) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:200]
            raise SuiteError(f"{method} {path} → HTTP {e.code}: {detail}")

    def try_api(self, path, method="GET"):
        """期望失败的调用：返回 (status_code, body_text)。"""
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.api_port}{path}", method=method,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")

    def events(self, limit=300):
        return self.api(f"/api/events?limit={limit}")

    def cli(self, *args):
        return subprocess.run(
            [self.binary, *args, "--config", self.cfg_path, "--data-dir", self.workdir],
            capture_output=True, text=True, timeout=60,
        )

    def wait_events(self, pred, timeout=8, poll=0.5):
        """轮询事件流水直到 pred(rows) 为真；超时返回最后一批。"""
        deadline = time.time() + timeout
        rows = []
        while time.time() < deadline:
            rows = self.events()
            if pred(rows):
                return rows, True
            time.sleep(poll)
        return rows, False


# ---------- 协议探针 ----------

def recv_some(s: socket.socket, size=512, timeout=3) -> bytes:
    s.settimeout(timeout)
    try:
        return s.recv(size)
    except socket.timeout:
        return b""


def mysql_probe(port):
    """deep-demo 同款握手：greeting → root 认证 → SELECT 1 假响应。"""
    def pkt(seq, payload):
        return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload

    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    hdr = s.recv(4)
    greeting = s.recv(hdr[0] | (hdr[1] << 8))
    assert greeting[0] == 0x0A, f"MySQL 协议版本应为 10: {greeting[:8]!r}"
    version = greeting[1:greeting.index(b"\x00")].decode()
    resp = struct.pack("<IIB", 0x0001 | 0x0200 | 0x8000 | 0x080000, 0x1000000, 0x21) + b"\x00" * 23
    resp += b"root\x00" + b"\x00" + b"mysql_native_password\x00"
    s.sendall(pkt(1, resp))
    hdr = s.recv(4)
    ok = s.recv(hdr[0] | (hdr[1] << 8))
    assert ok[0] == 0x00, f"MySQL 任意凭证应放行: {ok[:8]!r}"
    for sql in (b"SELECT 1", b"SHOW DATABASES"):
        s.sendall(pkt(0, b"\x03" + sql))
        frames = 0
        while frames < 12:
            h = s.recv(4)
            if len(h) < 4:
                break
            n = h[0] | (h[1] << 8)
            if n == 0:
                break
            data = s.recv(n)
            frames += 1
            if data[:1] in (b"\xfe",):
                break
    s.sendall(pkt(0, b"\x01"))
    s.close()
    return version


def redis_probe(port):
    def resp(*args):
        out = f"*{len(args)}\r\n".encode()
        for a in args:
            a = a.encode()
            out += f"${len(a)}\r\n".encode() + a + b"\r\n"
        return out

    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    def cmd(*args):
        s.sendall(resp(*args))
        return s.recv(512)

    assert cmd("PING") == b"+PONG\r\n"
    assert cmd("SET", "stage", "payload") == b"+OK\r\n"
    assert cmd("SLAVEOF", "1.2.3.4", "6379") == b"+OK\r\n"
    assert cmd("AUTH", "hunter2") == b"+OK\r\n"
    assert cmd("NOSUCHCMD").startswith(b"-ERR unknown command")
    s.sendall(resp("QUIT"))
    s.close()


def http_probe(port, path, method="GET", body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    data = None
    if body is not None:
        data = body.encode()
        req.add_header("Content-Length", str(len(data)))
    try:
        with urllib.request.urlopen(req, data=data, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


# ---------- 测试阶段 ----------

def phase_1_baseline(s: Suite):
    st = s.api("/api/status")
    if not st["version"].startswith("0.5."):
        raise SuiteError(f"版本异常: {st['version']}")
    if not st["honeypot_enabled"]:
        raise SuiteError("蜜罐应默认启用")
    if len(st["listeners"]) != 6 or not all(l["running"] for l in st["listeners"]):
        raise SuiteError(f"应有 6 个监听器全部运行: {[(l['name'], l['running']) for l in st['listeners']]}")
    print(f"  · status: v{st['version']}，6 监听器全部运行")
    cfg = s.api("/api/config")
    if len(cfg["honeypot"]["listeners"]) != 6:
        raise SuiteError("/api/config 监听表应含 6 行（配置 roundtrip 解析）")
    print("  · /api/config 监听表 6 行（配置解析 roundtrip）")
    # 无 token 请求必须 401
    req = urllib.request.Request(f"http://127.0.0.1:{s.api_port}/api/status")
    try:
        urllib.request.urlopen(req, timeout=5)
        raise SuiteError("无 token 请求应被拒绝")
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise SuiteError(f"无 token 应 401，得到 {e.code}")
    print("  · 无 token 访问 → 401（Bearer 鉴权）")


def phase_2_protocols(s: Suite):
    # SSH banner
    c = socket.create_connection(("127.0.0.1", s.port("ssh")), timeout=5)
    banner = recv_some(c)
    c.close()
    if not banner.startswith(b"SSH-2.0"):
        raise SuiteError(f"SSH banner 异常: {banner[:40]!r}")
    print(f"  · SSH banner: {banner.strip().decode()!r}")
    # Telnet banner + 登录
    c = socket.create_connection(("127.0.0.1", s.port("telnet")), timeout=5)
    banner = recv_some(c)
    if b"login:" not in banner:
        raise SuiteError(f"Telnet 问候语异常: {banner[:60]!r}")
    c.sendall(b"admin\r\n")
    c.close()
    print("  · Telnet 问候语 + 登录投递 admin")
    # HTTP：登录页 / 表单提交 / 诱饵 403
    code, body = http_probe(s.port("http"), "/login")
    if code != 200 or 'type="password"' not in body:
        raise SuiteError(f"GET /login 应 200 假登录页: {code}")
    code, body = http_probe(s.port("http"), "/login", "POST", "username=bob&password=s3cret")
    if code != 200 or "用户名或密码错误" not in body:
        raise SuiteError(f"POST /login 应 200 失败页: {code} {body[:80]}")
    code, _ = http_probe(s.port("http"), "/.env")
    if code != 403:
        raise SuiteError(f"GET /.env 诱饵应 403: {code}")
    print("  · HTTP 假登录页 / 表单提交 / .env 诱饵 403")
    # MySQL / Redis / Generic
    version = mysql_probe(s.port("mysql"))
    print(f"  · MySQL greeting {version}，root 认证放行 + COM_QUERY 假响应")
    redis_probe(s.port("redis"))
    print("  · Redis PING/SET/SLAVEOF/AUTH/未知命令 全部假响应")
    c = socket.create_connection(("127.0.0.1", s.port("generic")), timeout=5)
    c.sendall(b"hello\r\n")
    c.close()
    print("  · Generic 端口投递原始字节")

    # 事件落库断言
    rows, ok = s.wait_events(
        lambda rows: {e["listener"] for e in rows if e["kind"] == "honeypot_hit"}
        >= {"ssh", "http", "telnet", "mysql", "redis", "generic"},
        timeout=10,
    )
    if not ok:
        got = {e["listener"] for e in rows if e["kind"] == "honeypot_hit"}
        raise SuiteError(f"六协议事件未齐: {got}")
    print("  · 事件落库：六协议 honeypot_hit 全齐")
    http_hit = next(e for e in rows if e["kind"] == "honeypot_hit" and e["listener"] == "http"
                    and "login:post" in (e.get("summary") or ""))
    if "password=***" not in http_hit["payload"] or "s3cret" in http_hit["payload"]:
        raise SuiteError("HTTP 表单口令应脱敏 *** 且不留明文")
    print("  · HTTP 表单口令脱敏（payload 有 *** 无明文）")
    redis_hit = next(e for e in rows if e["kind"] == "honeypot_hit" and e["listener"] == "redis")
    if "AUTH ***" not in redis_hit["payload"] or "hunter2" in redis_hit["payload"]:
        raise SuiteError("Redis AUTH 口令应脱敏 *** 且不留明文")
    print("  · Redis AUTH 口令脱敏")


def phase_3_canary(s: Suite):
    code, body = http_probe(s.port("http"), "/backup.zip")
    if code != 200 or "AC1." not in body:
        raise SuiteError(f"/backup.zip 应 200 且含水印 token: {code}")
    m = re.search(r"AC1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", body)
    if not m:
        raise SuiteError("未能在蜜饵内容中提取 token")
    token = m.group(0)
    print(f"  · /backup.zip 下载含水印 token（{token[:24]}…）")
    r = s.cli("canary-decode", token)
    if r.returncode != 0 or "蜜饵水印解码成功" not in r.stdout or "backup.zip" not in r.stdout:
        raise SuiteError(f"canary-decode 溯源失败: rc={r.returncode} {r.stdout} {r.stderr}")
    node_line = next((l for l in r.stdout.splitlines() if "来源节点" in l), "").strip()
    print(f"  · canary-decode 溯源: {node_line}（含 backup.zip）")
    r = s.cli("canary-decode", token[:-2] + "xx")
    if r.returncode == 0:
        raise SuiteError("被篡改的 token 应解码失败")
    print("  · 篡改 token → 解码拒绝（非零退出）")


def phase_4_spray(s: Suite):
    user = getpass.getuser()
    c = socket.create_connection(("127.0.0.1", s.port("telnet")), timeout=5)
    recv_some(c)
    c.sendall(user.encode() + b"\r\n")
    c.close()
    print(f"  · Telnet 投递本机账号同名用户名: {user}")

    rows, ok = s.wait_events(
        lambda rows: any(
            e["kind"] == "credential_observed" and e["payload"].strip().lower() == user.lower()
            for e in rows
        ),
        timeout=8,
    )
    if not ok:
        raise SuiteError("未见 credential_observed 事件（凭证采集未生效）")
    print("  · credential_observed 事件（payload 只有用户名）")
    if any(e["kind"] == "credential_observed" and "password" in (e.get("payload") or "").lower()
           for e in rows):
        raise SuiteError("凭证事件 payload 不应携带口令字段")
    _, ok = s.wait_events(
        lambda rows: any(
            e["kind"] == "detection" and "credential_spray" in (e.get("summary") or "")
            for e in rows
        ),
        timeout=8,
    )
    if not ok:
        raise SuiteError("与本机账号同名的登录应触发 credential_spray 检测")
    print("  · credential_spray 高严重度检测（用户名 ∩ 本机账号）")


def phase_5_detect_and_protection(s: Suite):
    rows = s.events(300)
    dets = [e for e in rows if e["kind"] == "detection"
            and (e.get("summary") or "").startswith(("[scan]", "[bruteforce]"))]
    if not dets:
        raise SuiteError("六端口探测应触发 scan/bruteforce 频次检测")
    print(f"  · 频次检测事件: {dets[0]['summary'][:60]}")
    engines = [e for e in rows if e["kind"] == "engine" and "内网保护" in (e.get("summary") or "")]
    if not engines:
        raise SuiteError("回环来源自动封禁应被内网保护拦下（应有 engine 事件留痕）")
    print(f"  · 内网保护: {engines[-1]['summary'][:70]}")
    rules = s.api("/api/rules")
    if any((r.get("remote_ip") or "") == "127.0.0.1" for r in rules):
        raise SuiteError("回环地址永不自动封禁——规则表不应出现 127.0.0.1")
    print("  · /api/rules 无 127.0.0.1（回环永不自动封禁）")


def phase_6_rules_crud(s: Suite):
    if not s.api("/api/status")["elevated"]:
        print("  · 引擎未提权（Windows 防火墙写需要管理员/root）——跳过本阶段")
        return "skip"
    row = s.api("/api/rules", "POST", {
        "direction": "in", "remote_ip": "198.51.100.7",
        "note": "e2e-suite 手动规则", "tag": "e2e",
    })
    rid = row["id"]
    print(f"  · 添加手动规则 #{rid}（198.51.100.7）")
    rules = s.api("/api/rules")
    if not any(r["id"] == rid for r in rules):
        raise SuiteError("添加后规则列表应包含新规则")
    s.api(f"/api/rules/{rid}", "DELETE")
    rules = s.api("/api/rules")
    if any(r["id"] == rid for r in rules):
        raise SuiteError("删除后规则仍存在")
    print("  · 列表确认 → 删除 → 列表确认消失")


def phase_7_feedback(s: Suite):
    resp = s.api("/api/feedback", "POST", {
        "remote_ip": "198.51.100.7", "note": "e2e 误报闭环",
    })
    if not resp.get("ok"):
        raise SuiteError(f"误报反馈应成功: {resp}")
    print(f"  · 误报标记 198.51.100.7（收弃建议 {resp.get('dismissed_proposals', 0)} 条）")
    fb = s.api("/api/feedback")
    if not any((f.get("value") or "") == "198.51.100.7" for f in fb):
        raise SuiteError(f"误报列表应含刚标记的来源: {str(fb)[:150]}")
    print("  · /api/feedback 列表可见")
    s.api("/api/feedback/198.51.100.7", "DELETE")
    fb = s.api("/api/feedback")
    if any((f.get("value") or "") == "198.51.100.7" for f in fb):
        raise SuiteError("清除误报抑制后列表不应再有该来源")
    print("  · 清除抑制 → 列表消失（闭环完整）")


def phase_8_hot_swap(s: Suite):
    name = "telnet"
    port = s.port("telnet")
    s.api(f"/api/honeypot/listeners/{name}/stop", "POST")
    time.sleep(1)
    st = s.api("/api/status")
    tel = next(l for l in st["listeners"] if l["name"] == name)
    if tel["running"]:
        raise SuiteError("热停后 running 应为 false")
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        raise SuiteError("热停后端口应不可连")
    except SuiteError:
        raise
    except OSError:
        pass
    print("  · 热停 telnet → 状态翻「已停止」+ 端口不可连")
    s.api(f"/api/honeypot/listeners/{name}/start", "POST")
    time.sleep(1)
    tel = next(l for l in s.api("/api/status")["listeners"] if l["name"] == name)
    if not tel["running"]:
        raise SuiteError("热启后 running 应为 true")
    try:
        socket.create_connection(("127.0.0.1", port), timeout=3).close()
    except OSError as e:
        raise SuiteError(f"热启后端口应可连: {e}")
    print("  · 热启 telnet → 重新可连（即时生效）")
    code, body = s.try_api(f"/api/honeypot/listeners/{name}/start")
    if code < 400:
        raise SuiteError(f"对运行中的监听器重复启动应报错，得到 {code}")
    print(f"  · 重复启动 → {code} 拒绝（已在运行）")
    code, _ = s.try_api("/api/honeypot/listeners/no-such/stop")
    if code < 400:
        raise SuiteError("未知监听器热停应报错")
    print("  · 未知名热停 → 拒绝")
    with open(s.cfg_path, encoding="utf-8") as f:
        cfg_text = f.read()
    m = re.search(r'name = "telnet"[^[]*?enabled = (\w+)', cfg_text, re.S)
    if not m or m.group(1) != "true":
        raise SuiteError("热启停往返后 config.toml 的 telnet.enabled 应保持 true（持久化一致）")
    print("  · config.toml enabled 持久化一致（往返无损）")


def phase_9_ssh_shell(s: Suite):
    try:
        import paramiko  # noqa: F401
    except ImportError:
        print("  · 未安装 paramiko，跳过（可 pip install paramiko 后重跑）")
        return "skip"
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay-ssh-shell.py")
    r = subprocess.run(
        [sys.executable, script, "127.0.0.1", str(s.port("ssh"))],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        raise SuiteError(f"SSH 假 Shell 回放失败:\n{r.stdout[-600:]}\n{r.stderr[-300:]}")
    print("  · paramiko 回放：登录→白名单命令→组合注入→未知命令→exit 全过")
    rows, ok = s.wait_events(
        lambda rows: any(
            e["kind"] == "honeypot_hit" and e["listener"] == "ssh"
            and (e.get("interaction") or "").strip() not in ("", "[]", "null")
            for e in rows
        ),
        timeout=8,
    )
    if not ok:
        raise SuiteError("假 Shell 会话应有逐命令 interaction 留痕")
    hit = next(e for e in rows if e["listener"] == "ssh" and (e.get("interaction") or "").strip() not in ("", "[]", "null"))
    if "whoami" not in hit["interaction"]:
        raise SuiteError("interaction 应含回放的 whoami 命令")
    print("  · interaction 逐命令留痕进事件（whoami 可见）")


def phase_10_exposure(s: Suite):
    snap = s.api("/api/exposure/scan", "POST")
    if "ts" not in snap or "entries" not in snap:
        raise SuiteError(f"暴露面扫描响应异常: {str(snap)[:120]}")
    print(f"  · 扫描完成：{len(snap['entries'])} 条监听入口")
    latest = s.api("/api/exposure")
    if not latest.get("ts"):
        raise SuiteError("暴露面快照应已入库")
    print("  · 快照入库（/api/exposure 可查）")


def phase_11_integrity(s: Suite):
    rows = s.events(300)
    kinds = {e["kind"] for e in rows}
    need = {"honeypot_hit", "detection", "engine"}
    if not need <= kinds:
        raise SuiteError(f"事件流应含 {need}，实际 {kinds}")
    print(f"  · 事件种类齐全: {sorted(kinds)}")
    out = os.path.join(s.workdir, "export.jsonl")
    r = s.cli("export-events", out)
    if r.returncode != 0 or not os.path.exists(out):
        raise SuiteError(f"export-events 失败: {r.stderr[:200]}")
    with open(out, encoding="utf-8") as f:
        n = sum(1 for _ in f)
    if n < len(rows):
        raise SuiteError(f"导出行数 {n} 少于事件查询 {len(rows)}")
    print(f"  · export-events 导出 {n} 行")
    r = s.cli("verify-log")
    if r.returncode != 0 or "✓" not in (r.stdout or ""):
        raise SuiteError(f"哈希链校验失败: rc={r.returncode} {r.stdout} {r.stderr}")
    print("  · verify-log 哈希链完整")


PHASES = [
    ("引擎与 API 基线", phase_1_baseline),
    ("蜜罐六协议抓捕", phase_2_protocols),
    ("蜜饵与水印溯源", phase_3_canary),
    ("凭证采集与喷洒检测", phase_4_spray),
    ("频次检测与内网保护", phase_5_detect_and_protection),
    ("防火墙规则 CRUD", phase_6_rules_crud),
    ("误报反馈闭环", phase_7_feedback),
    ("监听器热启停", phase_8_hot_swap),
    ("SSH 假 Shell（可选）", phase_9_ssh_shell),
    ("暴露面扫描", phase_10_exposure),
    ("事件导出与哈希链完整性", phase_11_integrity),
]


def main():
    ap = argparse.ArgumentParser(description="AI-SafeGuard 整体功能集成测试套件")
    ap.add_argument("--binary", default=None, help="被测二进制路径（默认 target/release/aisafeguard[.exe]）")
    ap.add_argument("--api-port", type=int, default=17420, help="引擎 API 端口（默认 17420，避开开发实例）")
    ap.add_argument("--port-base", type=int, default=0, help="蜜罐端口基座偏移（与本机已运行的实例共存时整体错开）")
    ap.add_argument("--keep", action="store_true", help="保留工作目录（事件库/日志）供排查")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    exe = args.binary
    if not exe:
        cand = ["target/release/aisafeguard.exe", "target/release/aisafeguard"]
        exe = next((c for c in cand if os.path.exists(c)), None)
        if not exe:
            print("未找到被测二进制——先 cargo build --release，或用 --binary 指定")
            return 2
    exe = os.path.abspath(exe)

    # 端口预检：被占用会让阶段结果失真
    honeypot_ports = [p + args.port_base for p in PORTS.values()]
    busy = [p for p in honeypot_ports + [args.api_port] if _port_in_use(p)]
    if busy:
        print(f"端口已被占用: {busy} —— 先释放，或用 --port-base 整体错开蜜罐端口")
        return 2

    suite = Suite(exe, args.api_port, args.keep, args.port_base)
    suite.workdir = tempfile.mkdtemp(prefix="aisafeguard-e2e-")
    print(f"被测二进制: {exe}")
    print(f"工作目录:   {suite.workdir}\n")

    failed = []
    skipped = []
    try:
        suite.start_engine()
        for i, (title, fn) in enumerate(PHASES, 1):
            header = f"── {i}) {title} "
            print(header + "─" * max(4, 62 - len(header)))
            try:
                ret = fn(suite)
                if ret == "skip":
                    skipped.append(title)
                    print(f"{SKIP} {title}")
                else:
                    suite.results.append((title, PASS, ""))
                    print(f"{PASS} {title}\n")
            except SuiteError as e:
                suite.results.append((title, FAIL, str(e)))
                failed.append(title)
                print(f"{FAIL} {title}: {e}\n")
            except Exception as e:  # 意外异常也算失败，但不中断后续阶段
                suite.results.append((title, FAIL, f"意外异常: {e!r}"))
                failed.append(title)
                print(f"{FAIL} {title}: 意外异常 {e!r}\n")
    finally:
        suite.cleanup()

    print("═" * 64)
    for title, status, detail in suite.results:
        line = f"{status} {title}"
        if detail and status == FAIL:
            line += f" — {detail[:100]}"
        print(line)
    for t in skipped:
        print(f"{SKIP} {t}")
    total = len(suite.results)
    ok = sum(1 for _, s2, _ in suite.results if s2 == PASS)
    print(f"═" * 64)
    print(f"结果: {ok}/{total} 通过" + (f"，{len(skipped)} 跳过" if skipped else "")
          + (f"，失败 {len(failed)}: {failed}" if failed else ""))
    return 1 if failed else 0


def _port_in_use(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


if __name__ == "__main__":
    sys.exit(main())
