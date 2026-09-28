# AI-SafeGuard

**主机入侵检测与处置工具**——蜜罐诱捕 → 事件流水线 → 快路径频次检测 / AI 慢路径分析 → 防火墙处置，单二进制，Windows + Linux。

> **这不是 LLM 内容审核/Guardrail 产品**。AI 在这里只做一件事：把蜜罐与真实流量观测到的攻击证据读给 LLM，产出**严格校验的封禁建议**（默认人工确认）。检测与处置不依赖 AI——关掉 AI，快路径全功能照常。
>
> 当前版本 **0.4.0**。架构与设计：[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · 路线图：[docs/ROADMAP.md](docs/ROADMAP.md) + [ROADMAP-0.4.md](docs/ROADMAP-0.4.md) · 威胁模型：[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · ISO 27001 对照：[docs/COMPLIANCE.md](docs/COMPLIANCE.md) · NGFW/协同演进：[docs/NGFW_EVOLUTION.md](docs/NGFW_EVOLUTION.md)

```
 蜜罐(诱捕) ────────┐
 真实流量采样 ──────┤▶ 事件总线 ─▶ 快路径(频次/扫描/洪水/情报, 自动+TTL)
 威胁情报 ──────────┘      │            └▶ 慢路径(AI 分析, 默认人工)
                          ▼
              防火墙执行器(COM/WFP · nftables+XDP) ─▶ 全链路审计(哈希链)
```

## 适合谁 / 不适合谁

**适合**：有公网或内网暴露面的 Linux/Windows 服务器与工作站；想要"蜜罐诱捕 + 自动处置 + 可审计"而不想装全家桶的运维；研究蜜罐与 AI 处置联动的个人。
**不适合**：期望企业多租户管控、完整 NGFW/IPS、EDR 级内存/进程防护的团队（见[威胁模型](docs/THREAT_MODEL.md)的非目标清单）。

## 当前能力

- **蜜罐**：SSH/HTTP/Telnet/通用 四种低交互监听，假响应逼真，HTTP 带 L7 标签（method/path 前缀/可疑 UA）
- **快路径检测**：频次引擎（扫描/暴破）+ 采样捕获检测器（端口扫描/SYN flood），触发即自动封禁——TTL 到期自动解封，内网/回环永不自动封
- **流量采样捕获**（默认关闭）：WinDivert（Windows）/ AF_PACKET（Linux）被动采样只取副本，control 只看 SYN 元数据、full 带流重组取证（载荷仅可疑时截断留存）；可选驱动哈希校验；[Windows 实机验证](docs/WINDOWS-CAPTURE-TESTING.md) / [Linux](docs/LINUX-TESTING.md)
- **XDP 快速执行层**（Linux，默认关闭）：IP 级入站封禁镜像进 eBPF map，内核直丢微秒级生效；nftables 永远兜底，附加失败自动降级；eBPF 程序内嵌主程序
- **防火墙**：Windows COM/WFP 规则；Linux nftables 集合（IP 级 + 端口级拼接集合）；只管理自己创建的 `aisafeguard-blk-*` 规则
- **AI 助手**（慢路径）：OpenAI 兼容端点（默认 GLM，内网可指向本地推理），严格 schema 校验的封禁建议；灰度 TTL → 人工转正；误报反馈闭环（抑制时长可配 + 端口粒度 + 一键清除）
- **价值指标**：24h/7d 建议数、采纳率、误报率、自动封禁数（GUI + `/api/status`）
- **完整性**：事件哈希链 + `verify-log` 离线校验 + 结构化模糊测试护栏
- **事件外发**：syslog（RFC 5424 UDP/TCP）+ webhook 告警（severity 口径统一），best-effort 不阻塞引擎
- **组织协同**：mTLS 每节点证书 + 指纹绑定/预登记/吊销；事件上报、情报同步、建议推送（本地复验、仅慢路径）；quorum 可选；`fed audit` 审计导出
- **暴露面盘点**：监听端口/进程枚举 → 快照入库 → AI 评估
- **GUI**（egui）：仪表盘/事件/防火墙/蜜罐/AI/设置；主题与字号可调；热更项与需重启项明确标注

## 5 分钟上手

**Linux/WSL**（root）：

```bash
cargo build --release
sudo env AISAFEGUARD_AI_KEY=<可选> ./target/release/aisafeguard --headless
# 另开终端：连 3 个蜜罐端口 → detection 事件 + 自动封禁
for p in 2222 8081 2323; do timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$p"; done
curl -s -H "Authorization: Bearer $(sudo cat /root/.local/share/aisafeguard/api-token)" \
  "http://127.0.0.1:7420/api/events?limit=5"
sudo bash scripts/demo-attack.sh   # 或一键演示（含自动封禁与哈希链校验）
```

**Windows**（管理员）：`target\release\aisafeguard.exe`；服务化 `service install`（非管理员 GUI 自动经本地 API 读数据；服务/交互模式凭据路径差异见下文）。采样捕获需 [WinDivert64.sys](docs/WINDOWS-CAPTURE-TESTING.md)（官方渠道获取，支持哈希校验）。

## 架构一句话

**传感器与执行器分离**：`Firewall` trait 永远窄口（封禁/解封），所有检测能力落 `aisafeguard-detect` 等传感器 crate 经事件总线接入；**跨节点同步建议而非命令**；全仓库 `forbid(unsafe_code)`。

## 最小配置

```toml
[ai]
enabled = false            # 无 AI 也能跑完整快路径；开启后填 Key 或环境变量

[detect.capture]
enabled = false            # 采样捕获（需提权；默认关闭）

[syslog]
enabled = false            # 事件外发 syslog/webhook（默认关闭）
```

全部配置见首次运行生成的 `config.toml`（每项带注释）；**热更项保存即生效，需重启项保存时会明确列出**（分界契约 `AppConfig::restart_required`）。

## 服务模式（Windows）与凭据路径

Windows 服务（`service install`，LocalSystem）与普通 GUI 进程的**凭据存放位置不同**（凭据管理器按用户隔离）：

| 凭据 | 服务模式 | 交互（内嵌/远程 GUI）模式 |
|------|----------|--------------------------|
| API token | `%PROGRAMDATA%\aisafeguard\api-token`（本机用户可读） | 凭据管理器 `AISafeGuard/api-token` |
| AI Key | **环境变量 `AISAFEGUARD_AI_KEY`**（服务账户读不到用户存的 Key） | 凭据管理器 `AISafeGuard/ai-key`，或环境变量 |

**服务模式下请用系统环境变量配置 AI Key**。Linux 服务同理（unit `Environment=`）。

### 组织协同运维（协调者侧）

```bash
aisafeguard fed init-ca                            # 组织 CA（一次性）
aisafeguard fed issue-cert coord1 --san 10.0.0.1   # 协调者证书（SAN = 对外地址）
aisafeguard fed issue-cert agent1                  # 成员证书（分发到节点）
aisafeguard fed expect agent1 <指纹>                # 预登记（关闭抢注窗口）
aisafeguard fed revoke <节点名|指纹> [原因]           # 吊销（立即拒连）
aisafeguard fed audit <out.json>                   # 审计导出
```

推荐加入流程：签发 → 预登记 → 分发 → 上线（指纹不符即拒）。换证 = 吊销旧证 → 签发新证 → 更新预登记 → 删 `fed_members` 旧指纹 → 分发。协同面建议绑内网地址（绑公网会启动告警）。

## 已知限制（重要的放这里，不藏文末）

- 封禁规则为 IP 粒度（可选端口已支持）；L7 仅有轻量标签，无签名库（0.5）
- AI 是概率性的：默认人工确认；自动应用 = 可选开关 + 严重度阈值 + 灰度 TTL（到期自动解封）
- 内网/回环地址永不自动封（手动封不禁）；误报抑制期内自动封禁跳过
- nftables 集合/规则易失，依赖启动 resync 重灌；Windows COM 规则跨重启持久
- 事件外发是副本不是审计源（完整性以本地哈希链为准）；webhook 无重试与签名
- ISO 27001 对照是自查表不是认证
- 发布物暂未代码签名（发布页公布 SHA-256；见 [SECURITY.md](SECURITY.md)）
- 采样捕获 Windows 需管理员/服务模式 + WinDivert64.sys，Linux 需 CAP_NET_RAW；缺权限只降级不报错

## 路线图

0.3 全部完成（检测平台 + AI 深度介入 + 事件外发 + 组织协同 mTLS + XDP）；**0.4 = 工程与安全收口（进行中）**，见 [ROADMAP-0.4.md](docs/ROADMAP-0.4.md)；0.5 NGFW 数据面与规则；0.6 协同完全体。总览：[docs/ROADMAP.md](docs/ROADMAP.md)。

## 安全披露

[SECURITY.md](SECURITY.md)：披露渠道、响应时限、支持版本、发布完整性说明。MIT License，© 2026 coolinger · vibe coding。
