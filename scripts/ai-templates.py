#!/usr/bin/env python3
"""AI 预生成蜜罐模板（F794b④，galah 思路的离线改造）。

蜜罐数据面不依赖外部 LLM（延迟/可用性/成本），改由本脚本**离线批量**调用
OpenAI 兼容端点生成逼真 Web 假站模板（template.toml + page.html），落盘到
模板目录后由既有 H300 模板机制热加载——"AI 生成一次，蜜罐离线服务"。

用法：
  export AISAFEGUARD_AI_KEY=<你的 key>          # OpenAI 兼容端点
  export AI_BASE_URL=https://open.bigmodel.cn/api/paas/v4   # 可选
  export AI_MODEL=glm-4.7                                    # 可选
  python3 scripts/ai-templates.py --out /var/lib/aisafeguard/honeypot/templates \
      --profile devops --profile camera

约定：
  - 生成的模板带 token 水印（模板 page.html 尾部注释，与 H210 canary 联动）。
  - 每个模板独立目录，加载失败只拒绝该模板不拖垮注册表（H300 语义）。
  - 内容全部合成；脚本不写任何真实主机名/IP/密钥。
"""

import argparse
import json
import os
import sys
import time
import urllib.request

PROFILES = {
    "devops": "Jenkins/CI 部署后台（构建队列、部署按钮、版本号）",
    "router": "家用路由器管理页（WAN 状态、无线设置、固件版本）",
    "camera": "网络摄像头 Web 控制台（实时画面占位、通道列表、录像设置）",
    "nas": "NAS 管理后台（存储池、共享目录、备份任务）",
    "firewall": "企业防火墙管理页（会话表、策略列表、接口状态）",
}


def call_llm(base_url: str, model: str, key: str, prompt: str) -> str:
    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": "你是安全研究人员，为蜜罐生成完全虚构的网页。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.7,
        }
    ).encode()
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


PROMPT = """为一个蜜罐生成一个高度逼真的{desc}登录后首页（HTML 单文件，内联 CSS）。
要求：
1. 页面标题与侧栏导航符合该系统的真实形态，含版本号等可信细节；
2. 所有数据是明显的占位/合成值（IP 用 192.0.2.x、10.x，主机名 generic，统计数字随意）；
3. 只输出 HTML，不要 markdown 代码块标记；中文界面。
页面尾部 HTML 注释需包含：<!-- decoy-template generated {ts} -->

template.toml 需要的字段（TOML）：
name = "{name}"        # 模板目录名
port = 0               # 0 = 由部署者填一个未占用端口
title = "<页面标题>"
"""

TOML_TMPL = """name = "{name}"
port = 0
title = "{title}"
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="模板根目录（<data_dir>/honeypot/templates 或配置路径）")
    ap.add_argument("--profile", action="append", required=True, choices=sorted(PROFILES))
    args = ap.parse_args()

    key = os.environ.get("AISAFEGUARD_AI_KEY", "")
    if not key:
        print("AISAFEGUARD_AI_KEY 未设置", file=sys.stderr)
        return 1
    base_url = os.environ.get("AI_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
    model = os.environ.get("AI_MODEL", "glm-4.7")

    ok = 0
    for profile in args.profile:
        name = f"ai-{profile}"
        desc = PROFILES[profile]
        try:
            html = call_llm(
                base_url,
                model,
                key,
                PROMPT.format(desc=desc, name=name, ts=time.strftime("%Y-%m-%d")),
            )
            html = html.strip()
            if html.startswith("```"):
                # 容错剥掉代码块围栏（LLM 偶发不守指令）
                html = html.split("```")[1]
                if html.startswith("html"):
                    html = html[4:]
            dest = os.path.join(args.out, name)
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "page.html"), "w", encoding="utf-8") as f:
                f.write(html + "\n")
            with open(os.path.join(dest, "template.toml"), "w", encoding="utf-8") as f:
                f.write(TOML_TMPL.format(name=name, title=desc.split("（")[0]))
            print(f"[ok] {name} -> {dest}")
            ok += 1
        except Exception as exc:  # 单模板失败不拖垮整批
            print(f"[fail] {profile}: {exc}", file=sys.stderr)
    print(f"生成完成：{ok}/{len(args.profile)} 个模板。部署者需编辑 template.toml 填 port 后重启程序加载。")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
