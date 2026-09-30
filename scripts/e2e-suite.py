#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI-SafeGuard 整体功能集成测试套件（0.5.12）。双模式：

**spawn 模式（默认）**：拉起一个本地 headless 引擎做全链路验证——
  python scripts/e2e-suite.py                       # 默认 target/release/aisafeguard[.exe]
  python scripts/e2e-suite.py --port-base 20000     # 与本机运行中的实例共存（整体错开蜜罐端口）

**attach 模式（远程/真实部署）**：不启引擎，直接测一个已在运行的实例——
  本机服务/GUI 内嵌引擎：
    python scripts/e2e-suite.py --attach http://127.0.0.1:7420 --token <TOKEN>
  远程机器（API 只听 127.0.0.1，先建 SSH 隧道把远端 API 映射到本地）：
    ssh -L 17420:127.0.0.1:7420 user@remote
    python scripts/e2e-suite.py --attach http://127.0.0.1:17420 --token <TOKEN> --host <远端IP>
  可选：--data-dir <远端数据目录>（本机附加场景）启用 canary-decode/export/verify-log 三个
  需要数据目录的阶段；--spray-user <远端真实账号> 强断言喷洒检测；--config-path 供 CLI 阶段。

11 个阶段：API 基线（版本/监听器/token 鉴权）→ 蜜罐协议抓捕（按实例实际配置的协议探针：
SSH/Telnet/HTTP/MySQL/Redis/Generic，事件落库 + 口令脱敏）→ 蜜饵水印（下载 + canary-decode 溯源 +
篡改拒绝）→ 凭证采集与喷洒 → 频次检测与内网保护 → 防火墙规则 CRUD → 误报反馈闭环 → 监听器
热启停（停→不可连→启→可连，结束恢复初始状态）→ SSH 假 Shell（可选）→ 暴露面扫描 → 导出与哈希链。

退出码：0 = 全部通过；1 = 存在失败；2 = 环境/参数问题。纯 Python 标准库。
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

# 各协议默认端口（spawn 模式 + port_base 偏移；attach 模式以实例 status 为准）
PORTS = {"ssh": 2222, "http": 8081, "telnet": 2323, "generic": 1337, "mysql": 3307, "redis": 6380}


class SuiteError(Exception):
    """阶段内失败：消息会进结果表。"""


class Suite:
    def __init__(self, binary, api_port, keep, port_base=0,
                 attach=None, token=None, host="127.0.0.1",
                 data_dir=None, config_path=None, spray_user=None):
        self.binary = binary
        self.api_port = api_port
        self.keep = keep
        self.port_base = port_base
        self.mode = "attach" if attach else "spawn"
        self.base_url = (attach or f"http://127.0.0.1:{api_port}").rstrip("/")
        self.token = token or ""
        self.host = host
        self.data_dir = data_dir
        self.config_path = config_path
        self.spray_user = spray_user
        self.workdir = None
        self.cfg_path = None
        self.proc = None
        self.log_path = None
        self.results = []  # (phase_title, status, detail)

    def port(self, kind: str) -> int:
        return PORTS[kind] + self.port_base

    # ---------- 引擎生命周期 / attach 就绪 ----------

    def write_config(self):
        data = self.workdir
        # TOML 字面量字符串：Windows 反斜杠路径不需要转义
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
        self.data_dir = self.workdir  # spawn 模式：数据目录即工作目录（CLI 阶段用）
        self.log_path = os.path.join(self.workdir, "engine.log")
        log = open(self.log_path, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            [self.binary, "--headless", "--config", self.cfg_path,
             "--data-dir", self.workdir],
            stdout=log, stderr=subprocess.STDOUT,
        )
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

    def attach_verify(self):
        """attach 模式：不启引擎，验证目标实例可达 + token 有效，拉取监听器清单。"""
        try:
            st = self.api("/api/status")
        except SuiteError as e:
            raise SuiteError(
                f"目标实例不可达或 token 无效: {e}\n"
                "提示：API 只监听目标机 127.0.0.1——跨机测试先建 SSH 隧道"
                "（ssh -L 17420:127.0.0.1:7420 user@host），token 用目标机 --print-token 获取"
            )
        self.listeners = st["listeners"]
        if not self.listeners:
            raise SuiteError("目标实例没有已配置的监听器（蜜罐未启用或监听表为空）")
        print(f"  · 已附加 {self.base_url}（v{st['version']}，{len(self.listeners)} 个监听器，"
              f"提权: {'是' if st['elevated'] else '否'}）")

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
        if self.mode == "spawn":
            self.stop_engine()
        if self.workdir and not self.keep:
            shutil.rmtree(self.workdir, ignore_errors=True)

    # ---------- 工具 ----------

    def api(self, path, method="GET", body=None, with_token=True):
        req = urllib.request.Request(
            f"{self.base_url}{path}",
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
        except urllib.error.URLError as e:
            raise SuiteError(
                f"{method} {path} → 目标不可达: {e.reason}。"
                "提示：API 只监听目标机 127.0.0.1——跨机测试先建 SSH 隧道，"
                "或确认目标实例仍在运行"
            )

    def try_api(self, path, method="GET"):
        """期望失败的调用：返回 (status_code, body_text)。"""
        req = urllib.request.Request(
            f"{self.base_url}{path}", method=method,
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
        cmd = [self.binary, *args]
        if self.config_path:
            cmd += ["--config", self.config_path]
        if self.data_dir:
            cmd += ["--data-dir", self.data_dir]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    def wait_events(self, pred, timeout=8, poll=0.5):
        deadline = time.time() + timeout
        rows = []
        while time.time() < deadline:
            rows = self.events()
            if pred(rows):
                return rows, True
            time.sleep(poll)
        return rows, False

    def listener_by_kind(self, kind):
        return next((l for l in self.listeners if l["kind"] == kind), None)

    def can_connect(self, port, timeout=3):
        try:
            socket.create_connection((self.host, port), timeout=timeout).close()
            return True
        except OSError:
            return False


# ---------- 协议探针（host + 端口由调用方给） ----------

def recv_some(s: socket.socket, size=512, timeout=3) -> bytes:
    s.settimeout(timeout)
    try:
        return s.recv(size)
    except socket.timeout:
        return b""


def mysql_probe(host, port):
    """deep-demo 同款握手：greeting → root 认证 → COM_QUERY 假响应。"""
    def pkt(seq, payload):
        return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload

    s = socket.create_connection((host, port), timeout=5)
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


def redis_probe(host, port):
    def resp(*args):
        out = f"*{len(args)}\r\n".encode()
        for a in args:
            a = a.encode()
            out += f"${len(a)}\r\n".encode() + a + b"\r\n"
        return out

    s = socket.create_connection((host, port), timeout=5)
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


def http_probe(host, port, path, method="GET", body=None):
    req = urllib.request.Request(f"http://{host}:{port}{path}", method=method)
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
        raise SuiteError("蜜罐应启用（attach 到已停用蜜罐的实例无法测蜜罐面）")
    s.listeners = st["listeners"]
    kinds = {l["kind"] for l in s.listeners}
    if not all(l["running"] for l in s.listeners):
        raise SuiteError(f"存在未运行的已配置监听器: {[(l['name'], l['running']) for l in s.listeners]}")
    print(f"  · status: v{st['version']}，{len(s.listeners)} 监听器全部运行（协议 {sorted(kinds)}）")
    cfg = s.api("/api/config")
    if len(cfg["honeypot"]["listeners"]) != len(s.listeners):
        raise SuiteError("/api/config 监听表行数与 status 不一致")
    print("  · /api/config 与 status 一致（配置 roundtrip 解析）")
    req = urllib.request.Request(f"{s.base_url}/api/status")
    try:
        urllib.request.urlopen(req, timeout=5)
        raise SuiteError("无 token 请求应被拒绝")
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise SuiteError(f"无 token 应 401，得到 {e.code}")
    print("  · 无 token 访问 → 401（Bearer 鉴权）")


def phase_2_protocols(s: Suite):
    probed = []
    for kind, port_of in [
        ("ssh", lambda l: l["port"]),
        ("telnet", lambda l: l["port"]),
        ("http", lambda l: l["port"]),
        ("mysql", lambda l: l["port"]),
        ("redis", lambda l: l["port"]),
        ("generic", lambda l: l["port"]),
    ]:
        l = s.listener_by_kind(kind)
        if not l:
            print(f"  · {kind}: 实例未配置，跳过探针")
            continue
        port = port_of(l)
        if kind == "ssh":
            c = socket.create_connection((s.host, port), timeout=5)
            banner = recv_some(c)
            c.close()
            if not banner.startswith(b"SSH-2.0"):
                raise SuiteError(f"SSH banner 异常: {banner[:40]!r}")
            print(f"  · SSH :{port} banner {banner.strip().decode()!r}")
        elif kind == "telnet":
            c = socket.create_connection((s.host, port), timeout=5)
            banner = recv_some(c)
            if b"login:" not in banner:
                raise SuiteError(f"Telnet 问候语异常: {banner[:60]!r}")
            c.sendall(b"admin\r\n")
            c.close()
            print(f"  · Telnet :{port} 问候语 + 登录投递 admin")
        elif kind == "http":
            code, body = http_probe(s.host, port, "/login")
            if code != 200 or 'type="password"' not in body:
                raise SuiteError(f"GET /login 应 200 假登录页: {code}")
            code, body = http_probe(s.host, port, "/login", "POST", "username=bob&password=s3cret")
            if code != 200 or "用户名或密码错误" not in body:
                raise SuiteError(f"POST /login 应 200 失败页: {code} {body[:80]}")
            code, _ = http_probe(s.host, port, "/.env")
            if code != 403:
                raise SuiteError(f"GET /.env 诱饵应 403: {code}")
            print(f"  · HTTP :{port} 假登录页 / 表单提交 / .env 诱饵 403")
        elif kind == "mysql":
            version = mysql_probe(s.host, port)
            print(f"  · MySQL :{port} greeting {version}，root 放行 + COM_QUERY 假响应")
        elif kind == "redis":
            redis_probe(s.host, port)
            print(f"  · Redis :{port} PING/SET/SLAVEOF/AUTH/未知命令 全部假响应")
        elif kind == "generic":
            c = socket.create_connection((s.host, port), timeout=5)
            c.sendall(b"hello\r\n")
            c.close()
            print(f"  · Generic :{port} 投递原始字节")
        probed.append((kind, l["name"]))

    names = {n for _, n in probed}
    probed_http = any(k == "http" for k, _ in probed)
    rows, ok = s.wait_events(
        lambda rows: {e["listener"] for e in rows if e["kind"] == "honeypot_hit"} >= names,
        timeout=10,
    )
    if not ok:
        got = {e["listener"] for e in rows if e["kind"] == "honeypot_hit"}
        raise SuiteError(f"探针过的协议事件未齐: 需 {names}，得 {got}")
    print(f"  · 事件落库：{len(probed)} 个协议 honeypot_hit 全齐")
    http_hit = next((e for e in rows if e["kind"] == "honeypot_hit"
                     and e["listener"] in [n for k, n in probed if k == "http"]
                     and "login:post" in (e.get("summary") or "")), None)
    if http_hit:
        # 表单体是否随首包进 payload 取决于 TCP 分段——确定性的保证是：
        # 明文口令绝不出现（进了 payload 也必须是 ***），且凭证采集已入库
        if "s3cret" in http_hit["payload"]:
            raise SuiteError("HTTP 表单口令明文不得出现在 payload")
        if "password=" in http_hit["payload"] and "password=***" not in http_hit["payload"]:
            raise SuiteError("HTTP 表单口令进 payload 时必须已脱敏为 ***")
        print("  · HTTP 表单口令不落明文（payload 分段无关）")
    cred_bob = any(e["kind"] == "credential_observed"
                   and e["payload"].strip().lower() == "bob" for e in rows)
    if probed_http and not cred_bob:
        raise SuiteError("HTTP 表单提交应有 credential_observed(bob) 事件（采集+哈希链路）")
    if probed_http:
        print("  · HTTP 表单凭证采集入库（credential_observed: bob）")
    redis_hit = next((e for e in rows if e["kind"] == "honeypot_hit"
                      and e["listener"] in [n for k, n in probed if k == "redis"]), None)
    if redis_hit:
        if "AUTH ***" not in redis_hit["payload"] or "hunter2" in redis_hit["payload"]:
            raise SuiteError("Redis AUTH 口令应脱敏 *** 且不留明文")
        print("  · Redis AUTH 口令脱敏")


def phase_3_canary(s: Suite):
    http_l = s.listener_by_kind("http")
    if not http_l:
        print("  · 实例无 http 监听器，跳过蜜饵下载验证")
        return "skip"
    canary_on = s.api("/api/config")["honeypot"]["canary"]["enabled"]
    if not canary_on:
        print("  · 目标实例 canary 未启用（默认关）——跳过（spawn 模式或开启 canary 后覆盖）")
        return "skip"
    code, body = http_probe(s.host, http_l["port"], "/backup.zip")
    if code != 200 or "AC1." not in body:
        raise SuiteError(f"/backup.zip 应 200 且含水印 token: {code}")
    m = re.search(r"AC1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", body)
    if not m:
        raise SuiteError("未能在蜜饵内容中提取 token")
    token = m.group(0)
    print(f"  · /backup.zip 下载含水印 token（{token[:24]}…）")
    if not s.data_dir:
        print("  · 未提供 --data-dir，跳过 canary-decode 溯源与篡改拒绝（本机附加时提供即可覆盖）")
        return None
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
    forced = s.spray_user is not None
    user = s.spray_user or getpass.getuser()
    telnet_l = s.listener_by_kind("telnet")
    if telnet_l:
        c = socket.create_connection((s.host, telnet_l["port"]), timeout=5)
        recv_some(c)
        c.sendall(user.encode() + b"\r\n")
        c.close()
        print(f"  · Telnet 投递用户名: {user}")
    else:
        http_l = s.listener_by_kind("http")
        if not http_l:
            print("  · 无 telnet/http 监听器，跳过凭证采集验证")
            return "skip"
        http_probe(s.host, http_l["port"], "/login", "POST",
                   f"username={user}&password=gUESS-it-1")
        print(f"  · HTTP 表单投递用户名: {user}")

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
    if any("password" in (e.get("payload") or "").lower()
           for e in rows if e["kind"] == "credential_observed"):
        raise SuiteError("凭证事件 payload 不应携带口令字段")
    _, ok = s.wait_events(
        lambda rows: any(
            e["kind"] == "detection" and "credential_spray" in (e.get("summary") or "")
            and user.lower() in (e.get("summary") or "").lower()
            for e in rows
        ),
        timeout=8,
    )
    if ok:
        print("  · credential_spray 高严重度检测（用户名 ∩ 本机账号）")
    elif forced or s.mode == "spawn":
        raise SuiteError("与本地账号同名的登录应触发 credential_spray 检测")
    else:
        print("  · 未触发喷洒判定（attach 模式：目标机账号集与本机不同；"
              "用 --spray-user 指定目标机真实账号可强断言）")


def phase_5_detect_and_protection(s: Suite):
    rows = s.events(300)
    dets = [e for e in rows if e["kind"] == "detection"
            and (e.get("summary") or "").startswith(("[scan]", "[bruteforce]"))]
    if dets:
        print(f"  · 频次检测事件: {dets[-1]['summary'][:60]}")
    elif s.mode == "spawn":
        raise SuiteError("六端口探测应触发 scan/bruteforce 频次检测")
    else:
        print("  · 附加模式未压测端口，无 scan/bruteforce（spawn 模式覆盖）——按已有 detection 检查")
        if not [e for e in rows if e["kind"] == "detection"]:
            raise SuiteError("事件流中无任何 detection（检测管道未工作）")
    import ipaddress
    try:
        protected = (ipaddress.ip_address(s.host).is_loopback
                     or ipaddress.ip_address(s.host).is_private)
    except ValueError:
        protected = True  # 主机名按内网对待
    engines = [e for e in rows if e["kind"] == "engine" and "内网保护" in (e.get("summary") or "")]
    if protected:
        if not engines:
            raise SuiteError("内网来源的自动封禁应被内网保护拦下（应有 engine 事件留痕）")
        print(f"  · 内网保护: {engines[-1]['summary'][:70]}")
        rules = s.api("/api/rules")
        if any((r.get("remote_ip") or "") == s.host for r in rules):
            raise SuiteError(f"内网地址 {s.host} 永不自动封禁——规则表不应出现它")
        print(f"  · /api/rules 无 {s.host}（内网永不自动封禁）")
    else:
        print("  · 来源为公网地址：跳过内网保护断言（注意：自动封禁可能已作用于本机出口 IP，"
              "可在目标机误报反馈解除）")


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
    # 选一个监听器做热切换：优先 telnet（纯诱饵面），否则按协议序取第一个
    target = (s.listener_by_kind("telnet") or next(
        (l for l in s.listeners if l["kind"] in ("http", "ssh", "redis", "mysql", "generic")),
        None))
    if not target:
        print("  · 无可切换的监听器")
        return "skip"
    name, port, initial = target["name"], target["port"], target["running"]
    action = "停止" if initial else "启动"
    s.api(f"/api/honeypot/listeners/{name}/{'stop' if initial else 'start'}", "POST")
    time.sleep(1)
    tel = next(l for l in s.api("/api/status")["listeners"] if l["name"] == name)
    if tel["running"] == initial:
        raise SuiteError(f"热{action}后 running 应翻转为 {not initial}")
    if initial and s.can_connect(port):
        raise SuiteError("热停后端口应不可连")
    print(f"  · 热{action} {name} → 状态即时翻转" + ("，端口不可连" if initial else "，端口可连"))
    # 恢复初始状态（测试不改目标实例的长期行为）
    s.api(f"/api/honeypot/listeners/{name}/{'start' if initial else 'stop'}", "POST")
    time.sleep(1)
    tel = next(l for l in s.api("/api/status")["listeners"] if l["name"] == name)
    if tel["running"] != initial:
        raise SuiteError("恢复初始状态失败")
    print(f"  · 已恢复初始状态（{ '运行中' if initial else '已停止' }）")
    code, _ = s.try_api(f"/api/honeypot/listeners/{name}/start")
    if initial and code < 400:
        raise SuiteError(f"对运行中的监听器重复启动应报错，得到 {code}")
    if initial:
        print(f"  · 重复启动 → {code} 拒绝（已在运行）")
    code, _ = s.try_api("/api/honeypot/listeners/no-such/stop")
    if code < 400:
        raise SuiteError("未知监听器热停应报错")
    print("  · 未知名热停 → 拒绝")
    if s.mode == "spawn":
        with open(s.cfg_path, encoding="utf-8") as f:
            cfg_text = f.read()
        m = re.search(rf'name = "{name}"[^[]*?enabled = (\w+)', cfg_text, re.S)
        if not m or m.group(1) != "true":
            raise SuiteError(f"热启停往返后 config.toml 的 {name}.enabled 应保持 true")
        print("  · config.toml enabled 持久化一致（往返无损）")


def phase_9_ssh_shell(s: Suite):
    ssh_l = s.listener_by_kind("ssh")
    if not ssh_l:
        print("  · 实例无 ssh 监听器，跳过")
        return "skip"
    if not s.api("/api/config")["honeypot"]["shell"]["enabled"]:
        print("  · 目标实例未开假 Shell（ssh 为 banner 低交互）——跳过（spawn 模式覆盖）")
        return "skip"
    try:
        import paramiko  # noqa: F401
    except ImportError:
        print("  · 未安装 paramiko，跳过（可 pip install paramiko 后重跑）")
        return "skip"
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay-ssh-shell.py")
    r = subprocess.run(
        [sys.executable, script, s.host, str(ssh_l["port"])],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        raise SuiteError(f"SSH 假 Shell 回放失败:\n{r.stdout[-600:]}\n{r.stderr[-300:]}")
    print("  · paramiko 回放：登录→白名单命令→组合注入→未知命令→exit 全过")
    rows, ok = s.wait_events(
        lambda rows: any(
            e["kind"] == "honeypot_hit" and e["listener"] == ssh_l["name"]
            and (e.get("interaction") or "").strip() not in ("", "[]", "null")
            for e in rows
        ),
        timeout=8,
    )
    if not ok:
        raise SuiteError("假 Shell 会话应有逐命令 interaction 留痕")
    hit = next(e for e in rows if e["listener"] == ssh_l["name"]
               and (e.get("interaction") or "").strip() not in ("", "[]", "null"))
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
    if not {"honeypot_hit", "engine"} <= kinds:
        raise SuiteError(f"事件流应含 honeypot_hit/engine，实际 {kinds}")
    print(f"  · 事件种类: {sorted(kinds)}")
    if not s.data_dir:
        print("  · 未提供 --data-dir，跳过 export-events/verify-log（它们要读目标机数据目录）")
        return "skip"
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
    ("蜜罐协议抓捕", phase_2_protocols),
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
    ap = argparse.ArgumentParser(description="AI-SafeGuard 整体功能集成测试套件（spawn/attach 双模式）")
    ap.add_argument("--binary", default=None, help="被测二进制路径（默认 target/release/aisafeguard[.exe]；spawn 模式必得，attach 模式供 CLI 阶段用）")
    ap.add_argument("--api-port", type=int, default=17420, help="spawn 模式引擎 API 端口（默认 17420）")
    ap.add_argument("--port-base", type=int, default=0, help="spawn 模式蜜罐端口基座偏移（与本机运行实例共存）")
    ap.add_argument("--keep", action="store_true", help="保留工作目录（事件库/日志）供排查")
    ap.add_argument("--attach", default=None, metavar="BASE_URL",
                    help="attach 模式：不启引擎，测已在运行的实例（如 http://127.0.0.1:7420；跨机先建 SSH 隧道）")
    ap.add_argument("--token", default=None, help="attach 模式目标实例的 API token（目标机 --print-token 获取）")
    ap.add_argument("--host", default="127.0.0.1", help="蜜罐协议探针目标主机（attach 跨机时给远端 IP）")
    ap.add_argument("--data-dir", default=None, help="目标实例数据目录（本机附加时提供，启用 canary-decode/export/verify-log 阶段）")
    ap.add_argument("--config-path", default=None, help="目标实例 config.toml 路径（CLI 阶段用，可选）")
    ap.add_argument("--spray-user", default=None, help="喷洒检测强断言用的目标机真实账号名（默认取本机用户名）")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    exe = args.binary
    if not exe:
        cand = ["target/release/aisafeguard.exe", "target/release/aisafeguard"]
        exe = next((c for c in cand if os.path.exists(c)), None)
        if not exe and not args.attach:
            print("未找到被测二进制——先 cargo build --release，或用 --binary/--attach 指定")
            return 2
    if exe:
        exe = os.path.abspath(exe)

    if args.attach and not args.token:
        print("attach 模式需要 --token（在目标机上执行 aisafeguard --print-token 获取）")
        return 2

    suite = Suite(exe, args.api_port, args.keep, args.port_base,
                  attach=args.attach, token=args.token, host=args.host,
                  data_dir=args.data_dir, config_path=args.config_path,
                  spray_user=args.spray_user)

    if suite.mode == "spawn":
        honeypot_ports = [p + args.port_base for p in PORTS.values()]
        busy = [p for p in honeypot_ports + [args.api_port] if _port_in_use(p)]
        if busy:
            print(f"端口已被占用: {busy} —— 先释放，或用 --port-base 整体错开蜜罐端口")
            return 2
        suite.workdir = tempfile.mkdtemp(prefix="aisafeguard-e2e-")
    else:
        suite.workdir = tempfile.mkdtemp(prefix="aisafeguard-e2e-attach-")

    print(f"模式: {suite.mode}  目标: {suite.base_url}  探针主机: {suite.host}")
    if exe:
        print(f"被测二进制: {exe}")
    print(f"工作目录:   {suite.workdir}\n")

    failed = []
    skipped = []
    try:
        if suite.mode == "spawn":
            suite.start_engine()
        else:
            suite.attach_verify()
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
            except Exception as e:
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
    print("═" * 64)
    total = len(suite.results)
    ok = sum(1 for _, s2, _ in suite.results if s2 == PASS)
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
