#!/usr/bin/env bash
# AI-SafeGuard 一键安装（新 VPS 从零到运行）：
#   下载 CI 预构建二进制 → sha256 校验 → 安装 → systemd 单元 → 启动
# 用法（在目标 VPS 上，root）：
#   bash <(curl -fsSL https://gitee.com/coolinger2019-wq/AI-SafeGuard/raw/main/scripts/install.sh)
# 双源下载：Gitee 附件优先（国内稳），GitHub Releases 兜底。
# 前提：Ubuntu 22.04+/x86_64；需要创建数据目录与配置（脚本末尾提示初始化步骤）。
set -euo pipefail

GITEE="https://gitee.com/coolinger2019-wq/AI-SafeGuard/releases/latest/download"
GITHUB="https://github.com/coolinger2019-wq/AI-SafeGuard/releases/latest/download"

fetch() { # fetch <路径> <输出>：Gitee 优先，GitHub 兜底
    curl -fsSL --max-time 180 -o "$2" "$GITEE/$1" 2>/dev/null \
        || curl -fsSL --max-time 180 -o "$2" "$GITHUB/$1"
}

echo "[1/5] 下载预构建二进制..."
fetch "aisafeguard" /tmp/aisafeguard.new
fetch "aisafeguard.sha256" /tmp/aisafeguard.sha256

echo "[2/5] sha256 校验..."
cd /tmp
sha256sum -c aisafeguard.sha256

echo "[3/5] 安装..."
install -m755 /tmp/aisafeguard.new /usr/local/bin/aisafeguard
rm -f /tmp/aisafeguard.new /tmp/aisafeguard.sha256

echo "[4/5] systemd 单元..."
cat > /etc/systemd/system/aisafeguard.service <<'EOF'
[Unit]
Description=AI-SafeGuard Engine
After=network.target

[Service]
ExecStart=/usr/local/bin/aisafeguard --headless
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now aisafeguard
sleep 4
systemctl is-active aisafeguard

echo "[5/5] 安装完成 ✅"
echo "  数据目录: /var/lib/aisafeguard（首次启动自动创建）"
echo "  API:      http://127.0.0.1:7420（Bearer token：aisafeguard --print-token）"
echo "  下一步:   编辑 /root/.config/aisafeguard/config.toml 配置蜜罐监听器与 AI 端点，"
echo "            或运行 aisafeguard --headless 首启后按事件日志初始化。"
