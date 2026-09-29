# Linux/WSL 测试指南（0.2）

> **实测状态（2026-09-28，Ubuntu 24.04 / WSL2 内核 6.6）**：第 1-11 节全部验证通过，
> 清单已回填。验证过程发现并修复 3 个问题：测试监听竞态（bind/connect 时间差）、
> Linux token 落点（keyring v3 无平台特性时是进程内 mock，token 必须落文件）、
> nftables v6 集合误用 v4 选择器（ensure_setup 两处，见 docs/LESSONS.md）。
>
> 目标：在 WSL2（Ubuntu 22.04+）里完成 AI-SafeGuard Linux 后端的实机验证。
> 0.2 Linux 支持范围：headless 引擎 / 蜜罐 / 本地 API / 频次检测 / **nftables 封禁** /
> 哈希链校验 / 事件导出。GUI 可选（WSLg）；凭据管理器后端 0.3 才接入（本文用环境变量与文件替代）。
>
> 每一步都给了命令与期望输出，按顺序执行即可。验证结果请回填到文末的清单。

## 0. 前置条件

```bash
# WSL2 + Ubuntu 22.04+（wsl --update 保证内核较新，nf_tables 模块可用）
nft --version          # nftables 须已安装：sudo apt install nftables
rustc --version        # ≥ 1.95（rustup update stable）
```

代码获取二选一：

```bash
# 方案 A：直接用 Windows 侧代码（能跑，但 /mnt/c 的 IO 慢，编译会明显变久）
cd /mnt/c/code/AI-safe
# 方案 B（推荐）：复制进 WSL 文件系统
cp -r /mnt/c/code/AI-safe ~/aisafeguard && cd ~/aisafeguard
```

## 1. 构建与单元测试

```bash
cargo test --workspace
```

期望：全部 `test result: ok`（当前 28 个用例，含模糊测试与 nftables 命令构造的单测——
这些纯函数测试不依赖 Linux 特权，在 WSL 里跑就是对 Windows 侧开发的双重确认）。

```bash
cargo build --release
```

## 2. 启动 headless 引擎

```bash
# nftables 需要 CAP_NET_ADMIN，验证防火墙功能请用 sudo；
# 不用 sudo 也能跑（蜜罐/API 可用，防火墙操作会报权限错误——这也是一种验证）
sudo env AISAFEGUARD_AI_KEY="你的GLM-Key或留空" ./target/release/aisafeguard --headless
```

期望输出：

```
AI-SafeGuard 0.2.0 headless 运行中
  API:      http://127.0.0.1:7420  (Bearer token: 凭据管理器 AISafeGuard/api-token，或 --print-token)
  数据目录: "/home/<你>/.local/share/aisafeguard"
```

> **Linux 0.2 的 token 存放**：无凭据管理器后端，token 落在数据目录的
> `api-token` 文件（`sudo cat ~/.local/share/aisafeguard/api-token`）。目录默认仅本用户可读；
> 多用户机器请自行收紧（`chmod 600`）。AI Key 一律走环境变量 `AISAFEGUARD_AI_KEY`。

另开一个终端做后续验证：

```bash
export TOKEN=$(sudo cat ~/.local/share/aisafeguard/api-token)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7420/api/status | python3 -m json.tool
```

期望：`"backend": "nftables"`、`"elevated": true`（sudo 时）、`listeners` 4 个。

## 3. 蜜罐冒烟

```bash
printf 'SSH-2.0-probe\r\n' | timeout 3 nc 127.0.0.1 2222
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:7420/api/events?limit=3"
```

期望：`honeypot_hit` 事件，payload 含 `SSH-2.0-probe`。

## 4. nftables 后端实机验证（本轮重点）

### 4.1 表结构

```bash
sudo nft list table inet aisafeguard
```

期望看到（AI-SafeGuard 只动这张表，绝不碰系统既有规则）：

- 4 个 set：`blk4_in` / `blk6_in` / `blk4_out` / `blk6_out`（type ipv4_addr / ipv6_addr）
- 2 条链：`blk_in`（hook input，priority mangle，policy accept）、`blk_out`（hook output）
- 每条链 2 条规则：`ip saddr @blk4_in drop`、`ip6 saddr @blk6_in drop`（output 链为 daddr）

### 4.2 经 API 加规则 → 集合元素出现

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"direction":"in","protocol":"any","remote_ip":"203.0.113.7","note":"wsl-test"}' \
  http://127.0.0.1:7420/api/rules
sudo nft list set inet aisafeguard blk4_in
```

期望：set elements 含 `203.0.113.7`。

### 4.3 真实封禁效果（跨 WSL/Windows 边界）

WSL2 有独立 IP，从 Windows 侧连接 WSL 的蜜罐端口，来源是 Windows vEthernet 地址：

```powershell
# Windows PowerShell：先拿 WSL IP
wsl hostname -I
Test-NetConnection <WSL_IP> -Port 2222    # 此时应 TcpTestSucceeded: True
```

封掉这个来源（把 `<WIN_VETH_IP>` 换成上一步 Test-NetConnection 的 SourceAddress）：

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"direction":"in","protocol":"any","remote_ip":"<WIN_VETH_IP>","note":"wsl-block-test"}' \
  http://127.0.0.1:7420/api/rules
sudo nft list set inet aisafeguard blk4_in   # 应包含 <WIN_VETH_IP>
```

再回 Windows `Test-NetConnection <WSL_IP> -Port 2222` → 期望 **TcpTestSucceeded: False**（被 drop）。
解封后恢复：

```bash
# 查规则 id
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7420/api/rules
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7420/api/rules/<id>
```

> 注意：手动 API 封禁**允许**内网地址（管理员有权封内网设备）；
> **自动**封禁（频次引擎/AI 建议）才强制内网保护。这是有意的行为差异。

### 4.4 重启重灌（resync）

```bash
sudo nft delete table inet aisafeguard    # 清场，模拟重启后 set 丢失
# 重启引擎（Ctrl+C 后再 sudo ... --headless）
sudo nft list set inet aisafeguard blk4_in
```

期望：刚封的 IP 自动回来（启动时从 DB 重灌）。这是 nftables 集成最关键的正确性验证。

## 5. 频次检测（如实说明 WSL 场景的边界）

```bash
# 4 个蜜罐端口各连一次（默认阈值 5 个不同端口 → 改配置再触发）
sudo systemctl stop ... # 不适用；直接 Ctrl+C 后用临时配置重启：
```

```bash
cat > /tmp/detect-test.toml <<'TOML'
[detect]
enabled = true
auto_block = true
scan_distinct_ports = 4
TOML
sudo env AISAFEGUARD_AI_KEY="$AISAFEGUARD_AI_KEY" ./target/release/aisafeguard --headless \
  --config /tmp/detect-test.toml
# 然后连满 4 个端口
for p in 2222 8081 2323 1337; do timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$p"; done
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:7420/api/events?limit=5" | grep detection
```

期望：`detection | [scan] 127.0.0.1: 60 秒内触达 4 个不同蜜罐端口…`，以及一条
`内网保护：跳过对 127.0.0.1 的自动封禁`（**WSL 单机只能测到"判定 + 保护跳过"，
自动封禁 + TTL 解封需要非私网来源**——把 4.3 的封禁测试或频次触发换成外部来源即可，
或等部署到有公网流量的机器上观察）。

## 6. 完整性与导出

```bash
./target/release/aisafeguard verify-log                      # 期望 ✓ 哈希链完整：N/N
./target/release/aisafeguard export-events /tmp/events.jsonl # JSONL 含 hash 字段
# 篡改实验：sqlite3 直接改一行 summary 再 verify-log → 应报 ✗ 并定位行号
```

## 7. GUI（可选，WSLg）

```bash
./target/release/aisafeguard        # 普通用户跑：内嵌模式，能看数据
sudo ./target/release/aisafeguard   # WSLg 下 root 跑 GUI 可能有 X11 授权问题，不推荐
```

Linux 服务化（systemd）0.3 接入；当前 Linux 形态就是 headless。

## 8. 可选：systemd 常驻（WSL2 开启 systemd 后可用）

```ini
# /etc/systemd/system/aisafeguard.service
[Unit]
Description=AI-SafeGuard Engine
After=network.target

[Service]
ExecStart=/home/<你>/aisafeguard/target/release/aisafeguard --headless
Environment=AISAFEGUARD_AI_KEY=<可选>
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now aisafeguard
systemctl status aisafeguard    # 期望 active (running)
```

## 9. 清场

```bash
sudo nft delete table inet aisafeguard
rm -rf ~/.local/share/aisafeguard
```

## 10. 排障表

| 现象 | 原因与处理 |
|---|---|
| `nft` 命令不存在 | `sudo apt install nftables` |
| `nft list ruleset` 报 Operation not permitted | 没用 sudo；或 WSL 内核太老，`wsl --update` 后重试 |
| `/api/rules` 返回 "执行 nft 失败" | 引擎非 root 启动；用 sudo 重跑 |
| `elevated: false` 但用了 sudo | CapEff 解析不到 CAP_NET_ADMIN，多为容器/受限内核，记录环境反馈 |
| 蜜罐绑定失败 :2222 | 端口被占（ssh 等占了标准口不在默认列表内），改 config.toml 端口 |
| GUI 打不开 | WSLg 未启用（`wsl --version` ≥ 1.0）；headless 不受影响 |
| `verify-log` 报链损坏 | 先确认是不是 prune 断点（新链头 prev_hash 为空属正常）；否则查篡改 |

## 11. 验证结果回填（2026-09-28 已由开发侧执行，供复验）

- [x] `cargo test --workspace` 全绿（WSL 原生，24 用例）
- [x] headless 启动，status 返回 backend=nftables / elevated=true
- [x] 蜜罐命中事件含 payload
- [x] `nft list table inet aisafeguard` 结构正确（4 set + 2 chain + 4 rule）
- [x] API 加规则 → set 元素出现
- [x] 跨边界封禁生效（Windows → WSL 连接被 drop：Test-NetConnection False）
- [x] 解封恢复连通（True）
- [x] 清场后重启 → resync 自动重灌（4.4，最关键）
- [x] 频次检测判定 + 内网保护跳过事件（阈值改 4 触发）
- [x] verify-log ✓（36/36）/ export-events 含 hash

## 12. 采样捕获实机验证（0.3.3 新增，2026-09-28 WSL2 实测回填）

> 状态（2026-09-28，Ubuntu 24.04 / WSL2 内核 6.6 / rustc 1.98.1）：**全部实机项已执行通过**。
> `cargo test --workspace` 73 用例全绿（含 capture 层 l3_payload / mode_filter / fuzz）。
> 实测方法升级：单机"够不着"的非私网封禁分支用 IP_HDRINCL 原始套接字伪造源地址覆盖
> （内核按 martian 丢弃不影响网络，捕获层在 L2 tap 先于 ip_rcv 可见），见 docs/LESSONS.md。
> 执行中发现的行为边界记在文末「实测备注」，运维坑记在 docs/LESSONS.md 第五批。

```bash
cargo test --workspace   # 实测：73 用例全绿（Windows 侧开发的双重确认）
```

- [x] **降级路径**：非 root 启动 + `[detect.capture].enabled=true` → 引擎正常运行，
  `/api/status` 返回 `capture: {enabled: true, active: false, backend: "afpacket", note: "需要 CAP_NET_RAW 权限…"}`，
  事件留痕 `流量采样不可用：需要 CAP_NET_RAW 权限…`；蜜罐 4 监听与 API 不受影响
- [x] **启动路径**：root 启动 → `/api/status` 返回
  `"capture": {"active": true, "backend": "afpacket", "mode": "control"}`，
  事件 `流量采样已启动（afpacket / control 模式）`
- [x] **检测链路（control 模式）**：连 4 个蜜罐端口 → 采样判定
  `[scan] 60 秒内对 4 个不同目标端口发送 SYN（采样捕获，[2222, 2323, 7420, 8081]）`，
  与频次引擎判定（`触达 4 个不同蜜罐端口`）双传感器同时出现，各带一条
  `内网保护：跳过对 127.0.0.1 的自动封禁（scan）`
- [x] **语义对齐抽查**：API 请求 + 蜜罐带载荷连接等正常业务流量零误报；control 模式
  证据只含端口元数据。附带观察：正常业务连接的 SYN 也进扫描计数（7420 出现在端口列表）——
  传感器视角正确，阈值内不会误判
- [x] **full 模式**：洪水判定证据含载荷摘要段——
  `[flood] … 发送 4 个纯 SYN（采样捕获）；载荷摘要: FORENSIC-PAYLOAD-2026-09-28  AAAA…`，
  控制字符（\x01\x02\x03）已清洗、摘要精确 120 字符截断。**扫描（tcp_scan）判定的载荷摘要
  结构性为空**（判定在第 N 个不同端口的首个 SYN 时刻触发，该流载荷按 TCP 语义必在其后），
  取证摘要目前只有 flood 判定可达——设计取舍见 LESSONS 第五批
- [x] **AF_PACKET 特有**：`/proc/net/packet` 只有一个套接字（SOCK_RAW / ETH_P_ALL /
  Iface=0 未绑单接口），lo 与 eth0 均无 PROMISC 标志——未开混杂，隐私红线成立
- [x] **自动封禁出口**：伪造源 203.0.113.7（TEST-NET-3）SYN 突发 → flood 判定 →
  真实自动封禁（`nft set blk4_in` 出现该元素，规则 `origin=engine` 带 TTL）→
  TTL（90s）到期 janitor 自动解封（set 清空 + `TTL 到期，自动解封` + `firewall_remove` 事件）；
  `nft delete table` 后重启 → 规则从 DB 重灌（resync）且 capture 仍 active；
  私网/回环源 → 内网保护跳过留痕（对照组）

### 0.3.4 附加闭环（同轮实测）

- [x] **误报反馈三联动**：engine 自动封禁 198.51.100.5 后 `POST /api/feedback` →
  `{"ok":true,"removed_rules":1}`（联动解封）+ 30 天抑制入库；同源换端口再洪水 →
  判定照常产生但事件为 `误报反馈抑制：跳过对 … 的自动封禁`，无新规则；列表接口返回
  count/first/last/note 聚合
- [x] **转正正/负路径**：engine TTL 规则 promote → `expires` 延长 30.0 天（promote_ttl_secs）；
  手动永久规则 promote → 明确拒绝 `已是永久封禁，无需转正`
- [x] **鉴权与 AI 端点冒烟**：无 token 401；`/api/ai/key` present=false（未配 key）、
  `/api/ai/runs`、`/api/proposals` 空列表
- [x] **完整性/导出**：`verify-log` 哈希链校验通过；`export-events` 全量 JSONL 含
  prev_hash/hash 字段

### 实测备注（行为边界，非缺陷）

1. **tcp_scan 判定的载荷摘要恒空**（full 模式）：判定触发表=第 N 个**不同**端口的首个
   SYN，而该流的载荷必在 SYN 之后到达；同源 60s 冷却又挡住后续补发。若要扫描判定也带
   取证，需设计调整（判定时取该源任一已缓存流摘要 / 载荷到达后补发取证事件），当前按
   "flood 可取证、scan 只看元数据"理解。
2. **loopback 上 AF_PACKET 每帧双投递**（xmit tap + rx tap）：实验环境洪水计数翻倍
   （阈值 4 实际 2 个 SYN 即触发）；扫描判定按去重端口计数不受影响。生产 eth0 单向观测
   无此现象。
3. **事件存储不携带 rule_id**：`builtin.*` 规则标识只在事件总线（GUI 实时流）可见，
   落库/API 历史里靠证据文案辨识规则。追溯需求若强，可考虑给 EventRow 加列。
4. **低阈值实验配置下，对同一端口的高频轮询**（本测试的 curl）会触发 syn_flood 判定
   （同端口窗口内 ≥4 连接）——默认阈值 100 下正常监控频率不会触发。

## 13. XDP 快速层实机冒烟（0.5.1 Batch G 回填，2026-09-29 WSL2 实测）

```bash
sudo cargo test -p aisafeguard-xdp --test embedded -- --include-ignored --nocapture
```

- `embedded_object_parses`：嵌入对象（含新 FLOWS/DROP_TOTAL map）可解析
- `xdp_attach_smoke`：eth0 skb 模式附加 → BLOCKLIST 写入 TEST-NET-3 地址 →
  统计（mirrored=1）→ 清空（mirrored=0）→ 卸载，全链路通过
- 失败预期：无 root / lockdown=integrity / 内核不支持 → 附加失败返回 Err
  （产品路径 = 自动降级纯 nftables 并留事件，进程不退出）
