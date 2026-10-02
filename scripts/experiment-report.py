#!/usr/bin/env python3
"""实战实验数据报告生成器（0.7 F740，纯 stdlib）。

从产品数据库（export-events 的富数据在库里，本脚本直读 SQLite）确定性生成
docs/EXPERIMENT.md 预注册的四组口径。人工只做判读，不做计算。

用法：
  python experiment-report.py --db coord=C:/path/aisafeguard.db --db member1=... [--days 14] [--out report.md]

约定：
  - 每个 --db 一个节点，格式 标签=路径；第一个节点视为协调者（多节点时）。
  - 只读打开（mode=ro）；若库在运行中，连 WAL 三件套一起拷贝后再分析。
  - 取数前先在被测节点跑 aisafeguard verify-log（哈希链校验），失败的数据不进分析——本脚本不重复校验。
"""

import argparse
import sqlite3
import sys
from datetime import datetime, timedelta

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def q(conn, sql, args=()):
    cur = conn.execute(sql, args)
    return cur.fetchall()


def open_ro(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def fmt_day(ts):
    return datetime.fromtimestamp(ts).strftime("%m-%d")


def node_section(label, path, days):
    conn = open_ro(path)
    cutoff = int((datetime.now() - timedelta(days=days)).timestamp())
    out = [f"\n## 节点 [{label}]\n"]

    # —— ① 噪声基线 ——
    total = q(conn, "SELECT COUNT(*) FROM events WHERE ts >= ?", (cutoff,))[0][0]
    out.append(f"### ① 噪声基线（近 {days} 天）\n")
    out.append(f"- 事件总量：**{total}**")
    kinds = q(
        conn,
        "SELECT kind, COUNT(*) FROM events WHERE ts >= ? GROUP BY kind ORDER BY 2 DESC",
        (cutoff,),
    )
    out.append("- 按 kind：" + "、".join(f"{k}={n}" for k, n in kinds))
    attackers = q(
        conn,
        "SELECT COUNT(DISTINCT remote_ip) FROM events WHERE ts >= ? "
        "AND kind IN ('honeypot_hit','detection') AND remote_ip != ''",
        (cutoff,),
    )[0][0]
    out.append(f"- 独立攻击者数：**{attackers}**")
    byday = q(
        conn,
        "SELECT ts FROM events WHERE ts >= ? ORDER BY ts",
        (cutoff,),
    )
    per_day = {}
    for (ts,) in byday:
        d = fmt_day(ts)
        per_day[d] = per_day.get(d, 0) + 1
    if per_day:
        out.append("- 按日：" + "、".join(f"{d}:{n}" for d, n in sorted(per_day.items())))
    top = q(
        conn,
        "SELECT remote_ip, COUNT(*) FROM events WHERE ts >= ? "
        "AND kind IN ('honeypot_hit','detection') AND remote_ip != '' "
        "GROUP BY remote_ip ORDER BY 2 DESC LIMIT 20",
        (cutoff,),
    )
    out.append("- Top 20 源：")
    for ip, n in top:
        out.append(f"  - {ip} × {n}")

    # —— 按规则命中（F740 rule_id 落库后才有；老 schema 优雅降级） ——
    out.append("\n### 检测命中按规则\n")
    cols = {row[1] for row in q(conn, "PRAGMA table_info(events)")}
    if "rule_id" in cols:
        per_rule = q(
            conn,
            "SELECT rule_id, COUNT(*) FROM events WHERE ts >= ? AND kind='detection' "
            "AND rule_id != '' GROUP BY rule_id ORDER BY 2 DESC LIMIT 20",
            (cutoff,),
        )
        empty_rule = q(
            conn,
            "SELECT COUNT(*) FROM events WHERE ts >= ? AND kind='detection' AND rule_id = ''",
            (cutoff,),
        )[0][0]
        if per_rule:
            out.append("".join(f"\n- {rid} × {n}" for rid, n in per_rule))
        else:
            out.append("\n- （无带 rule_id 的检测——确认起跑时间晚于 0.7 升级）")
        out.append(f"\n- 无 rule_id 的 detection：{empty_rule}（频次检测本就无规则 ID——签名检测才携带）")
    else:
        out.append("- **库 schema 早于 0.7（缺 rule_id 列）**：升级节点后此节才有数据，"
                   "正式实验必须在升级后的库上采集")

    # —— ③ 误报候选 ——
    out.append("\n### ③ 误报候选与建议\n")
    fp_rows, fp_total = q(
        conn, "SELECT COUNT(*), COALESCE(SUM(count),0) FROM fp_feedback"
    )[0]
    out.append(f"- 误报标记：{fp_rows} 条（累计触发 {fp_total}）")
    if total:
        out.append(f"- 误报候选率：{fp_rows * 1000 / total:.1f} / 千事件")
    props = q(
        conn,
        "SELECT model, status, COUNT(*) FROM proposals WHERE created_ts >= ? "
        "GROUP BY model, status ORDER BY model",
        (cutoff,),
    )
    if props:
        out.append("- 建议分布：")
        for model, status, n in props:
            out.append(f"  - {model} → {status} × {n}")
    else:
        out.append("- 建议分布：（无）")

    # —— 规则与情报现状 ——
    rules = q(
        conn,
        "SELECT origin, enabled, COUNT(*) FROM rules GROUP BY origin, enabled ORDER BY origin",
    )
    rules_txt = "、".join(
        f"{o}({'启用' if e else '停用'})×{n}" for o, e, n in rules
    )
    out.append(f"- 防火墙规则：{rules_txt or '（无）'}")
    intel = q(
        conn,
        "SELECT source, COUNT(*) FROM intel WHERE expires_ts > ? GROUP BY source",
        (int(datetime.now().timestamp()),),
    )
    out.append("- 在库情报：" + ("、".join(f"{s}={n}" for s, n in intel) or "（空）"))

    # —— 组织事件账本（第二段印证分析的主数据源） ——
    out.append("\n### 组织事件账本（F200/F300）\n")
    org = q(
        conn,
        "SELECT kind, detail, COUNT(*) FROM org_events WHERE ts >= ? "
        "GROUP BY kind, detail ORDER BY kind",
        (cutoff,),
    )
    if org:
        for kind, detail, n in org:
            suffix = f"（{detail}）" if detail else ""
            out.append(f"- {kind}{suffix} × {n}")
    else:
        out.append("- （无——多节点部署后此处应有 corroboration/suggestion/fp-flag）")

    # —— 协调者专属：印证产出事件流 ——
    corr = q(
        conn,
        "SELECT COUNT(*) FROM events WHERE ts >= ? AND summary LIKE '%组织印证%'",
        (cutoff,),
    )[0][0]
    if corr:
        out.append(f"\n- 协调者印证产出事件：{corr} 条")
    conn.close()
    return out, attackers, total


def main():
    ap = argparse.ArgumentParser(description="实战实验数据报告（F740，口径见 docs/EXPERIMENT.md）")
    ap.add_argument("--db", action="append", required=True, metavar="标签=路径",
                    help="节点库（只读），可多次；第一个节点视为协调者")
    ap.add_argument("--days", type=int, default=14, help="统计窗口（天）")
    ap.add_argument("--out", default=None, help="输出 markdown 文件（缺省打 stdout）")
    args = ap.parse_args()

    nodes = []
    for spec in args.db:
        if "=" not in spec:
            print(f"--db 格式须为 标签=路径：{spec}", file=sys.stderr)
            return 2
        label, path = spec.split("=", 1)
        nodes.append((label, path))

    lines = [f"# 实战实验数据报告（窗口 {args.days} 天，生成于 {datetime.now():%Y-%m-%d %H:%M}）\n"]
    lines.append("> 前置自检：各节点 verify-log 哈希链校验是否已通过？未通过的数据不得进本报告。\n")

    all_attackers = set()
    grand_total = 0
    for i, (label, path) in enumerate(nodes):
        try:
            section, attackers, total = node_section(label, path, args.days)
        except sqlite3.Error as e:
            lines.append(f"\n## 节点 [{label}]\n\n- **读取失败**：{e}")
            continue
        lines.extend(section)
        # 跨节点攻击者并集（单节点 unique 是节点内口径；并集只在多节点时有意义）
        conn = open_ro(path)
        ips = q(
            conn,
            "SELECT DISTINCT remote_ip FROM events WHERE ts >= ? "
            "AND kind IN ('honeypot_hit','detection') AND remote_ip != ''",
            (int((datetime.now() - timedelta(days=args.days)).timestamp()),),
        )
        conn.close()
        all_attackers.update(ip for (ip,) in ips)
        grand_total += total

    if len(nodes) > 1:
        lines.append(f"\n## 跨节点汇总\n")
        lines.append(f"- 合计事件量：{grand_total}")
        lines.append(f"- **跨节点独立攻击者（并集）：{len(all_attackers)}**")
        lines.append("- 提示：印证命中率（第二段）以演练口径判读（docs/EXPERIMENT.md §5），"
                     "第一段公网多节点扩展才用扫描器重叠率口径。")

    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"报告已写入 {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
