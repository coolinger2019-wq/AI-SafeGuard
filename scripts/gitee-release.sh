#!/usr/bin/env bash
# 把 GitHub Release 的产物镜像到 Gitee Release（一键安装的 Gitee 主源）。
#
# 背景：Gitee 与 GitHub 的 Release 完全独立，tag 推送只同步 git 对象，
# 不会带附件；Gitee 也不支持 /releases/latest/download/ 别名。
# 本脚本按 tag 下载 GitHub 产物 → 校验和 → 创建/复用 Gitee Release → 上传附件。
#
# 前提：export GITEE_TOKEN=<Gitee 私人令牌，需 projects 权限>
# 用法：bash scripts/gitee-release.sh v0.8.0
# 幂等：Release 已存在则复用；同名附件先删后传，保证与 GitHub 一致。
set -euo pipefail

TAG=${1:?用法: bash scripts/gitee-release.sh <tag>（例如 v0.8.0）}
OWNER="coolinger"
REPO="ai-safe-guard"
API="https://gitee.com/api/v5/repos/$OWNER/$REPO"
GH="https://github.com/coolinger2019-wq/AI-SafeGuard/releases/download/$TAG"
FILES=(
    aisafeguard
    aisafeguard.sha256
    aisafeguard_xdp.o
    aisafeguard_xdp.o.sha256
    aisafeguard-windows-x64.zip
    aisafeguard-windows-x64.zip.sha256
)

: "${GITEE_TOKEN:?请先 export GITEE_TOKEN=<Gitee 私人令牌（projects 权限）>}"
TOKEN_Q="access_token=$GITEE_TOKEN"

pick_python() { # Windows 的 python3 可能只是商店占位符，逐个试跑
    local cand
    for cand in python3 python; do
        if "$cand" -c 'import json' >/dev/null 2>&1; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    return 1
}
PY=$(pick_python) || { echo "需要可用的 python3（解析 API JSON）" >&2; exit 1; }

# 缓存目录：慢链路下断点续传（53MB 产物在 100KB/s 线路上要 ~10 分钟）
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/aisafeguard-gitee/$TAG"
mkdir -p "$CACHE"

fetch_cached() { # fetch_cached <文件名>：本地校验通过则复用；否则 -C - 续传
    local dst="$CACHE/$1" sha="$CACHE/$1.sha256" url="$GH/$1" want got
    # 同目录有 .sha256 且校验通过 → 直接用（离线/慢链路友好；sha 文件自身跳过）
    if [ -s "$dst" ] && [ -s "$sha" ] \
        && (cd "$CACHE" && sha256sum -c "$1.sha256" >/dev/null 2>&1); then
        return 0
    fi
    if [ -s "$dst" ]; then
        want=$(curl -fsSIL --max-time 30 "$url" \
            | awk 'tolower($1)=="content-length:"{print $2}' | tr -d '\r')
        got=$(wc -c < "$dst")
        if [ -n "$want" ] && [ "$want" = "$got" ]; then
            return 0
        fi
    fi
    curl -fsSL --max-time 1800 -C - -o "$dst" "$url" \
        || { rm -f "$dst"; curl -fsSL --max-time 1800 -o "$dst" "$url"; }
}

echo "[1/4] 从 GitHub 下载 $TAG 产物..."
for f in "${FILES[@]}"; do
    fetch_cached "$f"
    echo "  ✓ $f"
done
(cd "$CACHE" \
    && sha256sum -c aisafeguard.sha256 aisafeguard_xdp.o.sha256 aisafeguard-windows-x64.zip.sha256 >/dev/null \
    && echo "  校验和 OK")

echo "[2/4] 查询 Gitee Release $TAG..."
release_json=$(curl -fsSL --max-time 30 "$API/releases/tags/$TAG?$TOKEN_Q" || true)
rel_id=$(printf '%s' "$release_json" | "$PY" -c '
import json, sys
raw = sys.stdin.read().strip()
if raw and raw != "null":
    d = json.loads(raw)
    print(d.get("id", ""))
' 2>/dev/null || true)

if [ -n "$rel_id" ]; then
    echo "  已存在（id=$rel_id），复用"
else
    echo "  不存在，创建..."
    body=$("$PY" - "$TAG" <<'PY'
import json, sys
tag = sys.argv[1]
print(json.dumps({
    "tag_name": tag,
    "name": tag,
    "target_commitish": "main",
    "body": "与 GitHub Release 同步（scripts/gitee-release.sh）",
    "prerelease": False,
}))
PY
)
    created=$(curl -fsSL --max-time 60 -X POST "$API/releases?$TOKEN_Q" \
        -H 'Content-Type: application/json' -d "$body")
    rel_id=$(printf '%s' "$created" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    echo "  已创建（id=$rel_id）"
fi

echo "[3/4] 同步附件（同名先删后传）..."
while read -r aid aname; do
    # Windows 的 python 会把 \n 翻成 \r\n，read 后要去掉行尾 \r
    aid=${aid%$'\r'}
    aname=${aname%$'\r'}
    [ -n "$aid" ] || continue
    for f in "${FILES[@]}"; do
        if [ "$aname" = "$f" ]; then
            curl -fsSL -X DELETE "$API/releases/$rel_id/attach_files/$aid?$TOKEN_Q" >/dev/null
            echo "  - 删除旧附件 $aname"
        fi
    done
done < <(curl -fsSL "$API/releases/$rel_id/attach_files?$TOKEN_Q" | "$PY" -c '
import json, sys
# 注意：release 详情里的 assets 只有 name/url，没有 id；附件 id 只能从
# /releases/{id}/attach_files 取（Gitee API 与 GitHub 的差异）
for a in json.load(sys.stdin):
    print(a["id"], a["name"])
')

for f in "${FILES[@]}"; do
    curl -fsSL --max-time 1800 -X POST "$API/releases/$rel_id/attach_files?$TOKEN_Q" \
        -F "file=@$CACHE/$f" >/dev/null
    echo "  ✓ $f"
done

echo "[4/4] Gitee Release 现状："
curl -fsSL "$API/releases/$rel_id/attach_files?$TOKEN_Q" | "$PY" -c '
import json, sys
for a in json.load(sys.stdin):
    print("  -", a.get("name"), a.get("size"), "bytes")
'
echo "完成: https://gitee.com/$OWNER/$REPO/releases/tag/$TAG"
echo "install.sh 的 Gitee 源将解析到该 tag（API: $API/releases/latest）"
