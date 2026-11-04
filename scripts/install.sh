#!/usr/bin/env bash
# AI-SafeGuard 一键安装（新 VPS 从零到运行）：
#   下载 CI 预构建二进制 → sha256 校验 → 安装 → systemd 单元 → 启动
# 用法（在目标 VPS 上，root）：
#   bash <(curl -fsSL https://gitee.com/coolinger/ai-safe-guard/raw/main/scripts/install.sh)
# 双源下载：Gitee Release 优先（国内直连稳），GitHub Releases 兜底。
# 注意：Gitee 不支持 /releases/latest/download/ 别名，需先经 API 解析最新 tag；
#       二进制与 sha256 必须同源下载（混源会出现"哈希对不上"的假失败）。
# 前提：Ubuntu 22.04+/x86_64；需要创建数据目录与配置（脚本末尾提示初始化步骤）。
set -euo pipefail

GITEE_OWNER="coolinger"
GITEE_REPO="ai-safe-guard"
GITEE_API="https://gitee.com/api/v5/repos/$GITEE_OWNER/$GITEE_REPO/releases/latest"
GITEE_DL="https://gitee.com/$GITEE_OWNER/$GITEE_REPO/releases/download"
GITHUB_DL="https://github.com/coolinger2019-wq/AI-SafeGuard/releases/latest/download"
DL=/tmp/aisafeguard.new
SHASUM=/tmp/aisafeguard.sha256

gitee_latest_tag() {
    curl -fsSL --max-time 20 "$GITEE_API" 2>/dev/null \
        | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | head -1 | sed 's/.*"\([^"]*\)"$/\1/'
}

pick_source() { # 输出选定源的 base URL；二进制已下到 $DL
    local tag
    tag=$(gitee_latest_tag || true)
    if [ -n "$tag" ] \
        && curl -fsSL --max-time 120 -o "$DL" "$GITEE_DL/$tag/aisafeguard" 2>/dev/null; then
        printf '%s\n' "$GITEE_DL/$tag"
        return 0
    fi
    curl -fsSL --max-time 180 -o "$DL" "$GITHUB_DL/aisafeguard" || return 1
    printf '%s\n' "$GITHUB_DL"
}

echo "[1/5] 下载预构建二进制..."
BASE=$(pick_source) || { echo "下载失败：Gitee 与 GitHub 均不可用" >&2; exit 1; }
echo "      源: $BASE"
curl -fsSL --max-time 60 -o "$SHASUM" "$BASE/aisafeguard.sha256"

echo "[2/5] sha256 校验..."
cd /tmp
# 下载件名是 aisafeguard.new，校验行引用 aisafeguard——按哈希值重拼校验行
printf '%s  %s\n' "$(cut -d' ' -f1 "$SHASUM")" "$(basename "$DL")" | sha256sum -c -

echo "[3/5] 安装..."
install -m755 "$DL" /usr/local/bin/aisafeguard
rm -f "$DL" "$SHASUM"

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
