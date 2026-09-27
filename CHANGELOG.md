# 更新日志

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.3.0] - 2026-09-28

按 ROADMAP 0.3 推进（检测平台 MVP 因 WinDivert 驱动分发/许可审查单独立项，见 0.3 第二批）。

### 新增

- **威胁情报管道 v1** [A.5.23]：Feodo C2 源拉取（6h 定时，`feed_url` 可换自托管源）+ 本地蜜罐源合并；
  高置信度 C2 自动封禁（TTL 3 天 + 内网保护 + 幂等跳过），本地/fed 源仅标注进 AI 提示词（`<intel>` 段）；
  `GET /api/intel`、`POST /api/intel/refresh`；TTL 过期清理
- **组织协同骨架**（docs/NGFW_EVOLUTION.md §6）：协调者/agent 双角色；
  事件上报（时钟窗 ±1h 校验、100 条/批上限）、情报双向同步（fed 来源仅标注、
  内网地址上报前置拒收防投毒）、AI 建议推送（接收方本地复验、仅慢路径、10 条/批）；
  鉴权 v1 = 组织令牌（环境变量 AISAFEGUARD_FED_TOKEN，配置文件不承载）；
  协调者失联各节点独立运行
- **Linux systemd 服务化**：`service install-systemd` 写 unit + enable --now
  （数据目录 /var/lib/aisafeguard），WSL 实测 active
- AI 分析输入扩展：暴露面快照（30 分钟内有效）与情报命中随统计一并送评

### 实测（WSL2 Ubuntu 24.04 + Windows 11 双平台）

- 情报：本地假源确定性闭环（拉取→入库→nft set 自动封禁→幂等跳过）；
  Windows 真实 Feodo 拉取 5 条 C2 入库
- 协同：双实例（协调者+agent）事件上报（fed:node 前缀可区分）、成员表、
  情报上报内网拒收、建议复验（合法入库/内网拒绝）、无令牌 401
- systemd：`service install-systemd` 后 systemctl is-active = active

## [0.2.0] - 2026-09-28

ISO 27001 合规加固版（对照矩阵见 docs/COMPLIANCE.md）+ 快路径检测 + Linux 后端。

### 新增

- **快路径频次检测**（新 crate `aisafeguard-detect`）：端口扫描 / 暴力探测自动判定，
  触发产出 `SecurityEvent::Detection`；自动封禁带 TTL 到期自动解封（60s 清扫任务）；
  内网/回环地址对自动封禁全局保护
- **Linux nftables 后端**：`inet aisafeguard` 表 + 集合元素模型（入/出 × v4/v6），
  封禁 = 元素增删（幂等），启动从 DB 自动重灌；CapEff 提权检测。
  实机验证指南见 docs/LINUX-TESTING.md（WSL）
- **事件完整性** [A.8.15]：事件表链式 SHA-256 哈希；`verify-log` 离线校验（退出码 0/1）、
  `export-events` JSONL 留档；30 天修剪改为整段修剪 + 断链头标记
- **凭据管理** [A.8.24]：AI Key 与 API token 迁入 Windows 凭据管理器，
  config.toml 不再承载任何秘密（0.1 明文自动迁移）；Linux 无 keyring 时 token 回退数据目录文件
- **Windows 服务化** [A.8.2/A.5.15]：`service install/uninstall/start/stop` + `--service` 工作模式，
  引擎以 LocalSystem 服务运行（数据目录 %PROGRAMDATA%\aisafeguard），
  GUI 普通权限三态自动选择（提权→内嵌 / 服务→远程 / 都不→内嵌回退）
- **GUI 控制台抽象**：`Console` trait 内嵌/远程双实现，为 0.3 多主机控制台奠基
- **本地 API 扩充**：`GET/POST /api/config`、`GET/POST/DELETE /api/ai/key`、
  `GET /api/stats`、`GET /api/ai/runs`；`--print-token` 供脚本取回 token
- **模糊测试** [A.8.29]：蜜罐解析路径与频次引擎的结构化模糊测试（6 万+随机输入/不变量断言），
  首轮即修复 C1 控制字符泄漏
- **主机暴露面盘点**：枚举本机监听端口与归属进程（Windows netstat+tasklist / Linux /proc/net+fd 纯函数解析），快照入库并入 AI 提示词做暴露风险评估；`POST /api/exposure/scan`、`GET /api/exposure`，GUI AI 页一键扫描
- **供应链与流程** [A.5.21/5.24-26]：CI 门禁（双平台测试 + clippy + cargo-audit + cargo-deny +
  cargo-auditable SBOM）、dependabot、SECURITY.md 漏洞披露流程

### 变更

- reqwest 切换 rustls（跨平台 TLS 一致）
- 事件/规则/建议等 DTO 补 Deserialize（跨进程 JSON 契约）
- 版本号 0.1.0 → 0.2.0

### 修复

- 频次窗口的"压线"语义（恰好在窗口边界的样本仍在窗内）
- 蜜罐 sanitize 漏 C1 控制字符（U+0080-9F）——模糊测试发现
- 服务漏报 Running 状态（SCM 永远显示"正在启动"）——真实服务 E2E 发现
- 服务数据目录落到 LocalSystem 私有 systemprofile——钉死到 %PROGRAMDATA%
- 改名 sed 二阶污染的环境变量名（AI-SafeGuardGUARD_AI_KEY → AISAFEGUARD_AI_KEY）

### 已知限制

- 服务 token 文件依赖 ProgramData 继承 ACL（本机用户可读）；0.3 换命名管道 + 调用方模拟
- Linux 无凭据管理器后端（AI Key 用环境变量；token 回退文件）；systemd unit 为可选配置
- nftables 实机验证待 Linux 环境（逻辑单测与交叉类型检查已完成）
- 服务模式下蜜罐/API 配置改动仍需重启服务

## [0.1.0] - 2026-09-27

最小端到端闭环。

- 模块化 Rust workspace（core / store / firewall / honeypot / ai / app）
- TCP 蜜罐：SSH / HTTP / Telnet / 通用，事件入库 + 实时上屏
- Windows 防火墙封禁（COM API），规则生命周期管理
- AI 分析：OpenAI 兼容端点（默认 GLM）→ 严格 schema 封禁建议 → 人工确认/阈值自动应用
- 本地 REST API（127.0.0.1 + Bearer token）与 egui 图形界面
- 自身加固：全仓库 forbid(unsafe_code)、schema 校验、提示注入防护、事件清洗
