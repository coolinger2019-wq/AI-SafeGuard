#!/usr/bin/env bash
# AI-SafeGuard 一键部署（升级现有节点）：
#   在 VPS 上下载 CI 预构建二进制（VPS 在美国，GitHub 直连极快，不过 GFW）
#   → sha256 校验 → 换装 → 重启 → 健康检查
# 用法（本机仓库根目录）：bash scripts/deploy.sh
set -euo pipefail

VPS=${VPS:-asg-vps}
GH="https://github.com/coolinger2019-wq/AI-SafeGuard/releases/latest/download"

echo "[1/5] 下载最新 CI 预构建二进制（VPS 侧直连 GitHub，不过 GFW）..."
ssh "$VPS" "curl -fsSL --max-time 120 -o /tmp/aisafeguard.new '$GH/aisafeguard' && curl -fsSL --max-time 30 -o /tmp/aisafeguard.sha256 '$GH/aisafeguard.sha256'"

echo "[2/5] sha256 校验..."
ssh "$VPS" "cd /tmp && echo '\$(cat aisafeguard.sha256)' | sha256sum -c - >/dev/null && grep aisafeguard\$ aisafeguard.sha256"

echo "[3/5] 换装 + 重启..."
ssh "$VPS" "systemctl stop aisafeguard && install -m755 /tmp/aisafeguard.new /usr/local/bin/aisafeguard && rm -f /tmp/aisafeguard.new /tmp/aisafeguard.sha256 && systemctl start aisafeguard && sleep 5 && systemctl is-active aisafeguard"

echo "[4/5] 健康检查（哈希链 + 监听口）..."
ssh "$VPS" "/usr/local/bin/aisafeguard verify-log --data-dir /var/lib/aisafeguard 2>&1 | tail -1 && ss -tlnp | grep -c aisafeguard"

echo "[5/5] 部署完成 ✅"
