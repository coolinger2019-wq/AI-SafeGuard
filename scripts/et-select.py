#!/usr/bin/env python3
"""F750 ET Open 精选子集——选包管线（初筛阶段）。

红线（预注册，docs/ROADMAP-0.7.md F750）：
- 误报是唯一硬淘汰项（回放校准阶段处理，本脚本只做语法/相关性初筛）
- 零命中不是淘汰项（保险单保留）
- 协议不可达才是淘汰项（我们蜜罐面看不到的协议规则 = 死重）

许可注意：ET Open 规则有再分发限制的不确定性——**生成的规则包不进 git**，
本仓库只携带本脚本与终选清单（sid/msg 事实性元数据）。月度刷新 = 重跑本脚本。

用法：
  python et-select.py --raw emerging-all.rules --out-dir out/ [--limit 200]
产出：
  out/candidate.rules      初筛规则包（可被 load_package 直接校验）
  out/manifest.tsv         sid \\t classtype \\t dst-port \\t msg
  out/stats.txt            过滤漏斗计数
"""

import argparse
import hashlib
import re
import sys
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# 规则子集 v1 白名单（docs/RULESET_SUBSET.md 冻结版）——逐字镜像
ALLOWED_KEYWORDS = {
    "msg", "sid", "rev", "classtype", "content", "nocase", "offset", "depth",
    "distance", "within", "pcre", "flow", "threshold", "metadata",
}
ALLOWED_CLASSTYPE = {
    "attempted-admin", "web-application-attack", "attempted-user",
    "malware-cnc", "trojan-activity", "policy-violation",
    "scan", "attempted-dos", "bad-unknown", "attempted-recon",
}
ALLOWED_ADDR = {"any", "$HOME_NET", "$EXTERNAL_NET"}

# 我方蜜罐暴露面（节点实测端口；generic 双端口 1337/5555 都算）
HONEYPOT_PORTS = {2222, 2323, 1337, 5555, 445, 3389, 8000, 8081, 9200, 13306, 16379, 2375}

# classtype → 选包优先级（严重类优先；与 severity 映射对齐）
CT_PRIORITY = {
    "attempted-admin": 5, "web-application-attack": 5, "malware-cnc": 5,
    "trojan-activity": 4, "attempted-user": 4,
    "attempted-recon": 3, "scan": 3,
    "policy-violation": 2, "attempted-dos": 2, "bad-unknown": 2,
}

RULE_RE = re.compile(r"^(?P<act>\w+)\s+(?P<proto>\w+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+(?P<dir>\S+)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s+\((?P<opts>.*)\)\s*$")


def top_level_options(opt_text):
    """按引号感知的 ';' 切顶层选项。"""
    parts, cur, in_q = [], [], False
    for ch in opt_text:
        if ch == '"':
            in_q = not in_q
            cur.append(ch)
        elif ch == ";" and not in_q:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def split_kw(opt):
    """选项关键字按**冒号**切（msg 值含空格：msg:"ET MALWARE x y"——按空白切会碎）。"""
    if ":" in opt:
        k, _, v = opt.partition(":")
        return k.strip(), v.strip()
    return opt.strip(), None


def fix_escapes(val):
    """content/msg 转义归一到引擎白名单（\" \ \; |hex|）：ET 习惯的 `\:` 语义就是
    冒号，剥掉多余反斜杠即等价可加载；其余未知转义拒绝。返回 (新值, 是否支持)。"""
    out, i, n = [], 0, len(val)
    while i < n:
        ch = val[i]
        if ch == "|":
            j = val.find("|", i + 1)
            if j < 0:
                return val, False
            out.append(val[i : j + 1])
            i = j + 1
            continue
        if ch == "\\" and i + 1 < n:
            nxt = val[i + 1]
            if nxt in '"\;':
                out.append(ch + nxt)
                i += 2
                continue
            if nxt == ":":
                out.append(":")  # 等价归一：\: -> :
                i += 2
                continue
            return val, False
        out.append(ch)
        i += 1
    return "".join(out), True


def norm_addr(tok):
    """地址侧归一：$*_SERVERS（HTTP/SQL/SMTP…）语义上都是「我方服务器」= $HOME_NET；
    列表组归一到两内置变量或 any；字面量仅单 IP/CIDR 保留。返回 (新token, 是否支持)。"""
    t = tok.strip()
    if t in ALLOWED_ADDR:
        return t, True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", t):
        return t, True
    if t.endswith("_SERVERS"):
        return "$HOME_NET", True
    if t.startswith("["):
        parts = [p.strip() for p in t.strip("[]").split(",")]
        mapped = set()
        for p in parts:
            if p == "$EXTERNAL_NET":
                mapped.add("E")
            elif p == "$HOME_NET":
                mapped.add("H")
            elif p.endswith("_SERVERS"):
                mapped.add("H")
            elif p == "any":
                return "any", True
            else:
                return tok, False  # 字面量列表/未知变量组：子集不支持
        if mapped == {"E"}:
            return "$EXTERNAL_NET", True
        if mapped == {"H"}:
            return "$HOME_NET", True
        if mapped == {"E", "H"}:
            return "any", True
        return tok, False
    return tok, False


def port_tokens(tok):
    """端口字段里的数字集合（含列表/范围/取反；取反算 0 = 不作端口相关性判断）。"""
    if tok == "any" or tok.startswith("!"):
        return set()
    out = set()
    for part in tok.strip("[]").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            a, _, b = part.partition(":")
            try:
                lo = int(a) if a else 0
                hi = int(b) if b else 65535
            except ValueError:
                return set()
            out.update(range(lo, hi + 1))
        else:
            try:
                out.add(int(part))
            except ValueError:
                return set()
    return out


PORT_VARS = {
    "$HTTP_PORTS": "[8081,8000]",
    "$FILE_DATA_PORTS": "[8081,8000]",
    "$SSH_PORTS": "[2222]",
    "$MYSQL_PORTS": "[13306]",
    "$MS_SQL_PORTS": "[13306]",
}


def norm_port(tok):
    """端口字段：any/列表/范围/取反保留（引擎 IR 支持）；ET 端口变量映射到我方
    蜜罐对应端口（收敛适配非放大）；取反变量与未知变量拒绝。"""
    t = tok.strip()
    if t in PORT_VARS:
        return PORT_VARS[t], True
    if t == "any":
        return t, True
    if t.startswith("!"):
        return t, True
    for part in t.strip("[]").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            a, _, b = part.partition(":")
            if a and not a.isdigit():
                return tok, False
            if b and not b.isdigit():
                return tok, False
        elif not part.isdigit():
            return tok, False
    return t, True


_NOTE_HOOK = None


def funnel_note(msg):
    if _NOTE_HOOK:
        _NOTE_HOOK[msg] += 1


def classify(line, funnel=None):
    """返回 (状态, 规则dict, 淘汰原因)。状态: ok / skip / reject。"""
    global _NOTE_HOOK
    _NOTE_HOOK = funnel
    s = line.strip()
    if not s or s.startswith("#"):
        return ("skip", None, None)
    m = RULE_RE.match(s)
    if not m:
        return ("reject", None, "语法不匹配头结构")
    if m.group("act") != "alert":
        return ("reject", None, f"动作 {m.group('act')}")
    if m.group("proto") not in ("tcp", "udp"):
        return ("reject", None, f"协议 {m.group('proto')}")
    if m.group("dir") not in ("->", "<>"):
        return ("reject", None, f"方向 {m.group('dir')}")
    # 地址侧归一（$*_SERVERS → $HOME_NET 等），重建规则头
    nsrc, ok1 = norm_addr(m.group("src"))
    ndst, ok2 = norm_addr(m.group("dst"))
    if not (ok1 and ok2):
        return ("reject", None, "地址组不归一")
    nsport, ok3 = norm_port(m.group("sport"))
    ndport, ok4 = norm_port(m.group("dport"))
    if not (ok3 and ok4):
        return ("reject", None, "端口组不归一")
    header = " ".join([m.group("act"), m.group("proto"), nsrc, nsport, m.group("dir"), ndst, ndport])
    opts = top_level_options(m.group("opts"))
    kw_counter = Counter()
    kept = []
    rule = {"dstport": ndport, "sid": None, "msg": None, "classtype": None}
    for opt in opts:
        if not opt:
            continue
        kw, val = split_kw(opt)
        if kw in ("content", "msg") and val is not None:
            val2, ok = fix_escapes(val)
            if not ok:
                return ("reject", None, f"{kw} 含不支持转义")
            opt = f"{kw}:{val2}"
            val = val2
        if kw == "reference":
            funnel_note("reference 剥离")  # 纯元数据无匹配语义，安全剥离
            continue
        if kw == "fast_pattern":
            funnel_note("fast_pattern 剥离")  # 引擎性能提示，无匹配语义，安全剥离
            continue
        if kw not in ALLOWED_KEYWORDS:
            return ("reject", None, f"越界关键字 {kw}")
        kw_counter[kw] += 1
        if kw == "sid":
            rule["sid"] = val
        elif kw == "classtype":
            if val not in ALLOWED_CLASSTYPE:
                return ("reject", None, f"白名单外 classtype {val}")
            rule["classtype"] = val
        elif kw == "msg":
            rule["msg"] = (val or "").strip('"')
        kept.append(opt)
    rule["raw"] = header + " (" + "; ".join(kept) + ";)"
    if kw_counter["msg"] != 1 or kw_counter["sid"] != 1:
        return ("reject", None, "msg/sid 缺失或重复")
    if not rule["classtype"]:
        return ("reject", None, "缺 classtype")
    return ("ok", rule, None)


def relevance(rule):
    """(相关性, 优先级)：端口相交=2，to_server 泛端口=1，其余=0。"""
    ports = port_tokens(rule["dstport"])
    if ports & HONEYPOT_PORTS:
        return 2
    if ports == set():  # any/取反——泛端口载荷规则
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--limit", type=int, default=200)
    a = ap.parse_args()

    funnel = Counter()
    picked = []
    seen_sids = set()
    with open(a.raw, encoding="utf-8", errors="replace") as f:
        for line in f:
            funnel["总行"] += 1
            st, rule, why = classify(line, funnel)
            if st == "skip":
                continue
            if st == "reject":
                funnel[f"淘汰:{why}"] += 1
                continue
            funnel["语法白名单通过"] += 1
            sid = int(rule["sid"])
            if sid in seen_sids:
                funnel["重复 sid 丢弃"] += 1
                continue
            seen_sids.add(sid)
            picked.append(rule)

    picked.sort(key=lambda r: (-relevance(r), -CT_PRIORITY[r["classtype"]], int(r["sid"])))
    final = picked[: a.limit]

    import os
    os.makedirs(a.out_dir, exist_ok=True)
    pack_path = os.path.join(a.out_dir, "candidate.rules")
    with open(pack_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# F750 初筛候选包（由 scripts/et-select.py 生成；勿手改；不进 git）\n")
        f.write(f"# 来源: {a.raw}；初筛 {len(final)} 条；终选 ≤50 由回放校准定版\n")
        for r in final:
            f.write(r["raw"] + "\n")
    raw_bytes = open(pack_path, "rb").read()
    sha = hashlib.sha256(raw_bytes).hexdigest()

    man = os.path.join(a.out_dir, "manifest.tsv")
    with open(man, "w", encoding="utf-8", newline="\n") as f:
        f.write("sid\tclasstype\trelevance\tdstport\tmsg\n")
        for r in final:
            f.write(f"{r['sid']}\t{r['classtype']}\t{relevance(r)}\t{r['dstport']}\t{r['msg']}\n")

    with open(os.path.join(a.out_dir, "stats.txt"), "w", encoding="utf-8") as f:
        for k, v in funnel.most_common():
            f.write(f"{k}: {v}\n")
        f.write(f"入选: {len(final)}\nSHA-256: {sha}\n")

    print(f"初筛完成：候选 {len(final)} 条 → {pack_path}")
    print(f"SHA-256: {sha}")
    for k, v in funnel.most_common(12):
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
