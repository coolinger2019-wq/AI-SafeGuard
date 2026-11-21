#!/usr/bin/env bash
# AI-SafeGuard 一键升级（已有节点）：下载 latest → 校验 → 新二进制预检 → 备份二进制 →
# 数据快照（主库 + honeypot/credentials.db + config.toml）→ 换装 → 启动（失败自动
# 回滚二进制 + 主库 + 蜜罐凭据）→ 健康检查（verify-log 非零即中止，不打 ✅）。
# 用法（仓库根目录）：bash scripts/deploy.sh
# v0.8.3 事故教训：新二进制可能在目标机起不来（glibc 前向不兼容），且新版会对 DB
# 全量重链（回滚旧 exe 会新旧口径混写 verify-log）。换装必须带「--version 预检 +
# 备份旧二进制 + 数据快照 + 等待 active + 失败自动回滚（二进制 + DB）」，
# 否则安全防护直接下线。
set -euo pipefail

VPS=${VPS:-asg-vps}
GH="https://github.com/coolinger2019-wq/AI-SafeGuard/releases/latest/download"
STAMP=$(date +%Y%m%d-%H%M%S)
SSH=(ssh -o ServerAliveInterval=10 -o ServerAliveCountMax=6)

echo "[1/8] 下载最新 CI 预构建二进制（VPS 侧直连 GitHub，不过 GFW）..."
"${SSH[@]}" "$VPS" "curl -fsSL --max-time 120 -o /tmp/aisafeguard.new '$GH/aisafeguard' && curl -fsSL --max-time 30 -o /tmp/aisafeguard.sha256 '$GH/aisafeguard.sha256'"

echo "[2/8] sha256 校验..."
"${SSH[@]}" "$VPS" "cd /tmp && printf '%s  %s\n' \"\$(cut -d' ' -f1 aisafeguard.sha256)\" aisafeguard.new | sha256sum -c -"

echo "[3/8] 新二进制预检（目标机冷启动 --version；glibc 不兼容在此拦截，未动服务无需回滚）..."
"${SSH[@]}" "$VPS" 'chmod +x /tmp/aisafeguard.new && /tmp/aisafeguard.new --version || { echo "✗ 新二进制在目标机 --version 失败（典型: 构建机 glibc 比目标机新）。服务未动，无需回滚。" >&2; exit 1; }'

echo "[4/8] 备份当前二进制..."
"${SSH[@]}" "$VPS" "cp -f /usr/local/bin/aisafeguard /tmp/aisafeguard.prev && echo 备份: /tmp/aisafeguard.prev"

echo "[5/8] 升级前数据快照（python3 sqlite3 backup API 在线备份，保留最近 5 份）..."
"${SSH[@]}" "$VPS" python3 - "$STAMP" <<'PY'
import os, shutil, sqlite3, sys

stamp = sys.argv[1]
data_dir = "/var/lib/aisafeguard"
backup_root = os.path.join(data_dir, "backups")
bdir = os.path.join(backup_root, "pre-" + stamp)
db = os.path.join(data_dir, "aisafeguard.db")
if not os.path.exists(db):
    sys.exit("✗ 未找到主数据库 %s，中止升级（快照失败不换装）" % db)
os.makedirs(bdir, exist_ok=True)

# 在线安全快照：sqlite3 backup API，含 WAL 中未 checkpoint 的内容（VPS 无 sqlite3 CLI）
src = sqlite3.connect(db)
dst = sqlite3.connect(os.path.join(bdir, "aisafeguard.db"))
src.backup(dst)
dst.close()
src.close()

# credentials.db 在 <data_dir>/honeypot/ 下（main.rs:923 CredentialStore::open）。
# 存在即必须拷贝成功：copy2 失败直接抛错 → ssh 非零 → 外层 set -e 在换装前中止
copied = []
creds_src = os.path.join(data_dir, "honeypot", "credentials.db")
creds_dst = os.path.join(bdir, "honeypot", "credentials.db")
if os.path.exists(creds_src):
    os.makedirs(os.path.dirname(creds_dst), exist_ok=True)
    shutil.copy2(creds_src, creds_dst)
    copied.append("honeypot/credentials.db")
else:
    print("⚠ 未找到 %s，本次快照不含蜜罐凭据库" % creds_src, file=sys.stderr)

# config.toml 存在才拷贝
toml_src = "/root/.config/aisafeguard/config.toml"
if os.path.exists(toml_src):
    shutil.copy2(toml_src, os.path.join(bdir, "config.toml"))
    copied.append("config.toml")

if not copied:
    print("⚠ 快照清单为空（credentials.db 与 config.toml 均未找到），仅有主库快照", file=sys.stderr)

# 只保留最近 5 份 pre-*，超出删最旧
pres = sorted(d for d in os.listdir(backup_root) if d.startswith("pre-"))
for old in pres[:-5]:
    shutil.rmtree(os.path.join(backup_root, old), ignore_errors=True)

manifest = []
for root, _dirs, files in os.walk(bdir):
    for f in files:
        manifest.append(os.path.relpath(os.path.join(root, f), bdir))
print("快照完成: " + bdir)
print("快照内容: " + ", ".join(sorted(manifest)))
PY

echo "[6/8] 换装 + 重启（等待 active，最多 60s；失败自动回滚二进制 + 主库 + 蜜罐凭据）..."
"${SSH[@]}" "$VPS" bash -s "/var/lib/aisafeguard/backups/pre-$STAMP" <<'REMOTE'
set -euo pipefail
BKDIR=$1
install -m755 /tmp/aisafeguard.new /usr/local/bin/aisafeguard
# restart 失败（如 crash-loop 触发 systemd 启动频率限制）不能绕过回滚逻辑：
# 交给下方轮询循环判 failed 驱动回滚
systemctl restart aisafeguard || true
ok=0
for i in $(seq 1 30); do
    s=$(systemctl is-active aisafeguard || true)
    if [ "$s" = "active" ]; then ok=1; break; fi
    if [ "$s" = "failed" ]; then break; fi
    sleep 2
done
if [ "$ok" != "1" ]; then
    echo "✗ 新版本启动失败，自动回滚（二进制 + 主库 + 蜜罐凭据）。快照目录: $BKDIR" >&2
    install -m755 /tmp/aisafeguard.prev /usr/local/bin/aisafeguard
    systemctl stop aisafeguard || true
    # 主库恢复：先拷到同盘临时文件并确认成功，再删 WAL/SHM、原子 mv 到位
    # （cp 失败时原库与 WAL 保持不动，状态不会比告警更糟）
    if cp -f "$BKDIR/aisafeguard.db" /var/lib/aisafeguard/aisafeguard.db.restore.tmp; then
        rm -f /var/lib/aisafeguard/aisafeguard.db-wal /var/lib/aisafeguard/aisafeguard.db-shm
        mv -f /var/lib/aisafeguard/aisafeguard.db.restore.tmp /var/lib/aisafeguard/aisafeguard.db
        echo "主库已恢复自快照" >&2
    else
        echo "⚠ 主库恢复失败（快照缺失/写盘失败），原库（含 WAL）保持不动，仅回滚二进制；请人工核查 $BKDIR" >&2
    fi
    # 蜜罐凭据恢复：快照里有才恢复（服务已 stop，顺序安全；同样先 tmp 后到位）
    if [ -f "$BKDIR/honeypot/credentials.db" ]; then
        if cp -f "$BKDIR/honeypot/credentials.db" /var/lib/aisafeguard/honeypot/credentials.db.restore.tmp; then
            rm -f /var/lib/aisafeguard/honeypot/credentials.db-wal /var/lib/aisafeguard/honeypot/credentials.db-shm
            mv -f /var/lib/aisafeguard/honeypot/credentials.db.restore.tmp /var/lib/aisafeguard/honeypot/credentials.db
            echo "honeypot/credentials.db 已恢复自快照" >&2
        else
            echo "⚠ 蜜罐凭据恢复失败，保留原文件；请人工核查 $BKDIR/honeypot/credentials.db" >&2
        fi
    fi
    # 若 restart 曾触发 systemd 启动频率限制，先清 failed 状态与计数再 start
    systemctl reset-failed aisafeguard || true
    systemctl start aisafeguard || true
    rok=0
    for i in $(seq 1 30); do
        s=$(systemctl is-active aisafeguard || true)
        if [ "$s" = "active" ]; then rok=1; break; fi
        if [ "$s" = "failed" ]; then break; fi
        sleep 2
    done
    if [ "$rok" != "1" ]; then
        echo "✗ 回滚后服务仍未 active，需人工介入。DB 快照: $BKDIR/aisafeguard.db" >&2
        exit 1
    fi
    systemctl is-active aisafeguard
    echo "已回滚（二进制 + 主库 + 蜜罐凭据恢复自快照）。新版本二进制保留在 /tmp/aisafeguard.new 供排查（先看: /usr/local/bin/aisafeguard --version）" >&2
    exit 1
fi
rm -f /tmp/aisafeguard.prev
systemctl is-active aisafeguard
REMOTE

echo "[7/8] 健康检查（版本 + 哈希链 + 监听口；verify-log 退出码必须为 0）..."
"${SSH[@]}" "$VPS" bash -s <<'HEALTH'
set -euo pipefail
v=$(/usr/local/bin/aisafeguard --version) || { echo "✗ 新版本 --version 失败" >&2; exit 1; }
echo "$v" | head -1
out=$(/usr/local/bin/aisafeguard verify-log --data-dir /var/lib/aisafeguard 2>&1) || { echo "$out" | tail -1; echo "✗ 哈希链校验失败（verify-log 非零退出），中止" >&2; exit 1; }
echo "$out" | tail -1
n=$(ss -tlnp | grep -c aisafeguard) || { echo "✗ 未发现 aisafeguard 监听口" >&2; exit 1; }
echo "监听口: $n"
HEALTH

echo "[8/8] 部署完成 ✅"
