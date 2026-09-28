# AI-SafeGuard

用 Rust 编写的模块化终端安全软件。**蜜罐诱捕 → 事件流水线 → 快路径频次检测 / AI 慢路径分析 → 防火墙处置** 的端到端闭环，带本地图形界面。

> 当前版本 **0.3.7**（检测平台 MVP + AI 深度介入 v1 + 事件外发 + 组织协同 mTLS + XDP 快速执行层，Windows + Linux）。设计文档见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，路线图见 [docs/ROADMAP.md](docs/ROADMAP.md)，ISO 27001 对照见 [docs/COMPLIANCE.md](docs/COMPLIANCE.md)，NGFW/分布式演进见 [docs/NGFW_EVOLUTION.md](docs/NGFW_EVOLUTION.md)。

## 当前功能

- **蜜罐**：SSH / HTTP / Telnet / 通用 四种低交互 TCP 监听器，记录来源与首包，假响应逼真，自身有并发/超时/截断三重防护
- **快路径检测**：频次引擎自动判定端口扫描 / 暴力探测，触发即产出 Detection 事件；自动封禁带 TTL 到期自动解封，内网/回环地址永不自动封禁
- **流量采样捕获**（Windows + Linux，默认关闭）：被动观测真实流量（Windows = WinDivert 嗅探模式，Linux = AF_PACKET；均只取副本、不吸收不注回，AF_PACKET 不开混杂模式），内置端口扫描 / SYN flood 检测器走同一自动封禁出口；control 模式只看 SYN 元数据，full 模式带 TCP 流重组取证；缺驱动/无提权只降级不报错（[Windows 实机验证清单](docs/WINDOWS-CAPTURE-TESTING.md)）
- **防火墙**：Windows = COM API 管理 `aisafeguard-blk-*` 规则；Linux = nftables（`inet aisafeguard` 表 + 集合元素，启动自动重灌）。两端都只管理自己创建的内容
- **XDP 快速执行层**（Linux，默认关闭）：nftables 之上的加速层——IP 级入站封禁规则镜像进 eBPF map，内核收包路径直接丢弃（微秒级生效）；nftables 永远兜底，附加失败自动降级；eBPF 程序内嵌于主程序，无需目标机工具链
- **主机暴露面盘点**：枚举监听端口与归属进程，AI 评估对外暴露风险（"自动分析功能接口"第一步）
- **AI 助手**（慢路径）：OpenAI 兼容端点（默认智谱 GLM，内网可指向本地推理），把 24h 攻击统计、暴露面快照喂给 LLM，产出**严格校验**的封禁建议；默认人工确认，可选自动应用（带严重度阈值）
- **完整性**：事件表链式 SHA-256 哈希，`aisafeguard verify-log` 离线校验篡改；解析路径有结构化模糊测试护栏
- **凭据管理**：AI Key 与 API token 存 Windows 凭据管理器，配置文件不承载任何秘密
- **图形界面**（egui）：仪表盘 / 事件流水 / 防火墙 / 蜜罐 / AI 助手 / 设置
- **界面主题**：4 套配色自由切换（深邃蓝 / 浅色办公 / 暖色护眼 / 高对比无障碍）+ 全局字号缩放（默认“舒适”档），设置页即时预览、保存后保持；规范见 [ui.md](ui.md)
- **威胁情报**：Feodo C2 源 + 本地蜜罐源，高置信度自动封禁，命中随 AI 分析送评
- **日志远程转发**（默认关闭）：事件总线 → RFC 5424 syslog 收集器（UDP/TCP），severity 统一口径（detection/封禁=warning、蜜罐命中=notice），best-effort 不阻塞引擎，完整性以本地哈希链为准
- **告警通知**（默认关闭）：达到阈值的事件 POST JSON 到 webhook 接收端（企业微信/钉钉/Slack 兼容网关或自建），最低严重度四档可配
- **组织协同**（骨架）：协调者/agent 双角色，事件上报、情报同步、AI 建议推送（本地复验、仅慢路径）；mTLS 每节点证书（`fed init-ca` / `fed issue-cert`，node↔证书指纹绑定，协调者独立 mTLS 监听面）
- **本地 API**：`127.0.0.1` + Bearer token，供脚本与未来的远程控制台使用

## 构建与运行

需要 Rust 1.95+（`rustup update stable`）。

```bash
cargo build --release
```

**以管理员身份运行**（防火墙功能需要；不提权则只能看数据）：

```
target\release\aisafeguard.exe
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--headless` | 无界面运行（服务器/服务形态），Ctrl+C 退出 |
| `--data-dir <path>` | 自定义数据目录（默认 `%LOCALAPPDATA%\aisafeguard`） |
| `--config <path>` | 自定义配置文件（默认 `%APPDATA%\aisafeguard\config.toml`） |
| `verify-log` | 离线校验事件哈希链是否被篡改（退出码 0=完整 / 1=损坏） |
| `service install\|uninstall\|start\|stop` | Windows 服务管理（需管理员，详见下文） |
| `export-events <out.jsonl>` | 导出全部事件（含哈希字段）为 JSONL 留档 |

数据（SQLite、日志）在数据目录下，日志按天滚动在 `logs\aisafeguard.log`。

## 配置

首次运行自动生成默认配置。关键项：

```toml
[ai]
enabled = true
base_url = "https://open.bigmodel.cn/api/paas/v4"   # 任何 OpenAI 兼容端点；封闭内网可指向本地推理
model = "glm-4.7"
auto_apply = false          # true = 高危建议自动封禁（默认关闭）
analyze_interval_secs = 900
# API Key 不在配置文件里：设置界面存入凭据管理器，或环境变量 AISAFEGUARD_AI_KEY（优先级更高）

[detect]
enabled = true              # 快路径频次检测
auto_block = true           # 触发后自动封禁（TTL + 内网保护）
scan_distinct_ports = 5     # 60 秒内触达 ≥5 个不同蜜罐端口 = 端口扫描
bruteforce_hits = 10        # 同一蜜罐 60 秒内命中 ≥10 次 = 暴力探测
ttl_secs = 1800             # 自动封禁 30 分钟后自动解封

[detect.capture]
enabled = false             # 真实流量采样捕获（Windows 需管理员/服务模式；Linux 需 CAP_NET_RAW；重启生效）
mode = "control"            # control = 仅 TCP SYN 元数据；full = 全 TCP 段 + 流重组取证
scan_distinct_ports = 15    # 窗口内对不同目标端口发 SYN 的判定阈值
syn_flood_rate = 100        # 同一 (来源, 目标:端口) 窗口内 SYN 数判定阈值
window_secs = 60
flow_idle_secs = 120
flow_table_cap = 65536

[honeypot]
enabled = true
# 默认监听 2222(ssh) 8081(http) 2323(telnet) 1337(generic)
# 要监听 22/80/23 等标准端口改这里（需管理员，重启生效）

[ui]
theme = "deep_blue"   # deep_blue | light | warm | contrast（高对比）
font_scale = 1.15     # 全局字号缩放 0.85–1.6，默认 1.15（舒适档）
```

## 本地 API

Token 在 **Windows 凭据管理器**（`AISafeGuard` / `api-token`），PowerShell 读取示例：

```powershell
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSS(
  (Get-SavedCredential AISafeGuard/api-token ...)))
```

或临时用 `AISAFEGUARD_TOKEN` 类脚本自行从凭据管理器取出。示例（`$TOKEN` 为取出的 token）：

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7420/api/status
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:7420/api/events?limit=20&ip=203.0.113"
# 手动封禁
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"direction":"in","protocol":"tcp","remote_ip":"203.0.113.7","note":"扫描来源"}' \
  http://127.0.0.1:7420/api/rules
# 触发 AI 分析
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7420/api/ai/analyze
```

全部端点：`GET /api/status`、`GET /api/events`、`GET|POST /api/rules`、`DELETE /api/rules/{id}`、`GET /api/proposals`、`POST /api/proposals/{id}/apply|dismiss`、`POST /api/ai/analyze`。

## 自身安全设计（要点）

- 自有代码全部 `#![forbid(unsafe_code)]`（全仓库零 unsafe）
- 无 shell 拼接；防火墙走结构化 COM 封装；提权检测用完整性 SID（不受系统语言影响）
- AI 输入输出双向设防：蜜罐数据标记为不可信输入；LLM 建议按 allowlist 逐字段校验，**字段存在但非法 → 整条作废**（绝不静默放宽为更宽的规则）；拒绝封禁内网/回环地址
- 事件哈希链防篡改 + 离线校验；每次分析/规则变更全链路审计入库
- 凭据管理器存密；CI 供应链门禁（cargo-audit / cargo-deny）+ SBOM（cargo-auditable）；漏洞披露见 [SECURITY.md](SECURITY.md)

## 目录结构

```
crates/
  aisafeguard-core       配置 / 事件总线 / 凭据 / 统一错误
  aisafeguard-store      SQLite 持久层（事件哈希链/规则 TTL/建议/AI 审计）
  aisafeguard-firewall   防火墙 trait + Windows COM 实现
  aisafeguard-honeypot   TCP 蜜罐监听器
  aisafeguard-ai         LLM 客户端 + 建议 schema 校验
  aisafeguard-detect     快路径检测（频次引擎 / 情报管道 / 暴露面盘点 / 采样捕获）
  aisafeguard-app        引擎装配 / REST API / egui 界面 / 入口
docs/               架构 / 路线图 / 合规对照 / NGFW 演进 / Windows 捕获验证 / Linux 测试指南 / 弯路记录
```

## 已知限制（0.3.2）

配置分两类：**热更**（`[detect]` 阈值、`[syslog]`、`[notify]`、`[ai]`、`[exposure]`、`[intel]` 等，保存即生效）与**需重启**（蜜罐监听、API 端口、捕获开关/模式、XDP、fed 角色——GUI 保存时会明确列出需重启项）；服务模式与内嵌模式并存，服务 token 文件依赖 ProgramData 默认 ACL（后续收紧为命名管道）；采样捕获 Windows 用 WinDivert（WinDivert64.sys 需自行从官方渠道获取放入程序目录）、Linux 用 AF_PACKET（需 CAP_NET_RAW，实机验证清单 docs/LINUX-TESTING.md §12）；Linux 无凭据管理器后端（Key 请用环境变量）；防火墙封禁规则为 IP 粒度，L7/应用层识别在路线图 0.5。详见架构文档。

## 服务模式（Windows）与凭据路径

Windows 服务（`service install`，LocalSystem）与普通 GUI 进程的**凭据存放位置不同**，这是 Windows 凭据管理器按用户隔离的必然结果：

| 凭据 | 服务模式 | 交互（内嵌/远程 GUI）模式 |
|------|----------|--------------------------|
| API token | 发布为 `%PROGRAMDATA%isafeguardpi-token`（本机用户可读，GUI 远程连接用） | 凭据管理器 `AISafeGuard/api-token` |
| AI Key | 服务进程读**环境变量 `AISAFEGUARD_AI_KEY`**（服务账户的凭据管理器与你的用户账户隔离，服务读不到你存进去的 Key） | 凭据管理器 `AISafeGuard/ai-key`，或环境变量 |

**服务模式下请用系统环境变量（或 schtasks/systemd 的 Environment=）配置 AI Key**；Linux 服务同理（unit 的 `Environment=` 或 EnvironmentFile）。API Key 与事件数据完整性不受此影响。

---

© 2026 **coolinger** · vibe coding · MIT License · UI 规范见 [ui.md](ui.md)
