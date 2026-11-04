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

verified() { # <文件名>：本地缓存是否已可用（payload 由其 .sha256 校验）
    local f="$1" p
    case "$f" in
        *.sha256)
            # sha 文件自身：它校验的 payload 通过即说明 sha 文件可信
            p="${f%.sha256}"
            [ -s "$CACHE/$f" ] && [ -s "$CACHE/$p" ] \
                && (cd "$CACHE" && sha256sum -c "$f" >/dev/null 2>&1)
            ;;
        *)
            [ -s "$CACHE/$f" ] && [ -s "$CACHE/$f.sha256" ] \
                && (cd "$CACHE" && sha256sum -c "$f.sha256" >/dev/null 2>&1)
            ;;
    esac
}

fetch_cached() { # 本地校验通过则复用；否则续传到 .part，校验完整后才替换，绝不动已有文件
    local dst="$CACHE/$1" part="$CACHE/$1.part" url="$GH/$1" want got
    if verified "$1"; then
        return 0
    fi
    # 远端大小：代理 TLS 抖动时不能中断脚本（set -e + pipefail），失败置空继续
    want=$(curl -fsSIL --max-time 30 "$url" 2>/dev/null \
        | awk 'tolower($1)=="content-length:"{print $2}' | tr -d '\r' || true)
    # 无 sha 伴随的文件（sha 文件自身）只能按大小判断完整性
    if [ -s "$dst" ] && [ ! -e "$CACHE/$1.sha256" ] && [ -n "$want" ] \
        && [ "$want" = "$(wc -c < "$dst")" ]; then
        return 0
    fi
    curl -fsSL --max-time 1800 -C - -o "$part" "$url" 2>/dev/null || true
    got=$(wc -c < "$part" 2>/dev/null || echo 0)
    if [ -n "$want" ] && [ "$want" != "$got" ]; then
        echo "  下载未完成: $1 ($got/$want bytes)，缓存保留，可重跑续传" >&2
        return 1
    fi
    [ -s "$part" ] || { echo "  下载失败: $1" >&2; return 1; }
    mv -f "$part" "$dst"
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
