#!/usr/bin/env bash
# AI-SafeGuard 一键升级（已有节点）：下载 latest → 校验 → 备份 → 换装 → 启动（失败自动回滚）。
# 用法（仓库根目录）：bash scripts/deploy.sh
# v0.8.3 事故教训：首次启动可能在 DB 迁移/依赖缺失时失败，换装必须带
# 「备份旧二进制 + 等待 active + 失败自动回滚」，否则安全防护直接下线。
set -euo pipefail

VPS=${VPS:-asg-vps}
GH="https://github.com/coolinger2019-wq/AI-SafeGuard/releases/latest/download"

echo "[1/6] 下载最新 CI 预构建二进制（VPS 侧直连 GitHub，不过 GFW）..."
ssh "$VPS" "curl -fsSL --max-time 120 -o /tmp/aisafeguard.new '$GH/aisafeguard' && curl -fsSL --max-time 30 -o /tmp/aisafeguard.sha256 '$GH/aisafeguard.sha256'"

echo "[2/6] sha256 校验..."
ssh "$VPS" "cd /tmp && printf '%s  %s\n' \"\$(cut -d' ' -f1 aisafeguard.sha256)\" aisafeguard.new | sha256sum -c -"

echo "[3/6] 备份当前二进制..."
ssh "$VPS" "cp -f /usr/local/bin/aisafeguard /tmp/aisafeguard.prev && echo 备份: /tmp/aisafeguard.prev"

echo "[4/6] 换装 + 重启（等待 active，最多 60s；失败自动回滚）..."
ssh "$VPS" bash -s <<'REMOTE'
set -euo pipefail
install -m755 /tmp/aisafeguard.new /usr/local/bin/aisafeguard
systemctl restart aisafeguard
ok=0
for i in $(seq 1 30); do
    s=$(systemctl is-active aisafeguard || true)
    if [ "$s" = "active" ]; then ok=1; break; fi
    if [ "$s" = "failed" ]; then break; fi
    sleep 2
done
if [ "$ok" != "1" ]; then
    echo "✗ 新版本启动失败，自动回滚到上一版本" >&2
    install -m755 /tmp/aisafeguard.prev /usr/local/bin/aisafeguard
    systemctl restart aisafeguard
    sleep 5
    systemctl is-active aisafeguard
    echo "已回滚。新版本二进制保留在 /tmp/aisafeguard.new 供排查（先看: /usr/local/bin/aisafeguard --version）" >&2
    exit 1
fi
rm -f /tmp/aisafeguard.prev
systemctl is-active aisafeguard
REMOTE

echo "[5/6] 健康检查（版本 + 哈希链 + 监听口）..."
ssh "$VPS" "/usr/local/bin/aisafeguard --version | head -1 && /usr/local/bin/aisafeguard verify-log --data-dir /var/lib/aisafeguard 2>&1 | tail -1 && ss -tlnp | grep -c aisafeguard"

echo "[6/6] 部署完成 ✅"
