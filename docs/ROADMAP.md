# AI-SafeGuard 路线图

## 0.1（当前版本）——最小端到端闭环 ✅

- [x] 模块化 Rust workspace（core / store / firewall / honeypot / ai / app）
- [x] TCP 蜜罐：ssh / http / telnet / generic 四种监听行为，事件入库 + 实时上屏
- [x] Windows 防火墙封禁（COM API），规则生命周期管理（添加 / 删除 / 启停）
- [x] AI 分析：OpenAI 兼容端点（默认 GLM），24h 统计 + 最近记录 → 严格 schema 封禁建议
- [x] 建议 → 人工确认 → 应用（可选自动应用 + 严重度阈值），全链路审计
- [x] 本地 REST API（127.0.0.1 + Bearer token），为远程控制台预留
- [x] egui 图形界面：仪表盘 / 事件 / 防火墙 / 蜜罐 / AI 助手 / 设置
- [x] 自身加固：零 unsafe、schema 校验、提示注入防护、事件清洗

## 0.2 —— 合规加固与服务化（ISO 27001 对齐，详见 docs/COMPLIANCE.md）

### P0 · 合规硬伤（审计最先点名的六项，全部对应 Annex A 控制项）

- [x] **服务化拆分** [A.8.2/A.5.15]：提权引擎注册为 Windows 服务（`service install`，LocalSystem），GUI 以普通权限进程经本地 API 连接（自动探测：提权→内嵌 / 有服务→远程 / 无服务→内嵌回退），界面不再以管理员运行
- [x] **密钥进凭据管理器** [A.8.24]：AI Key 与 API token 迁移 keyring（Windows Credential Manager），config.toml 停止承载任何秘密
- [x] **日志完整性** [A.8.15]：事件哈希链（逐条链式 SHA-256）+ 导出与离线校验工具
- [x] **CI 门禁** [A.8.25/8.28]：cargo audit / cargo deny / clippy / test 作为合并门禁
- [x] **SBOM** [A.5.21]：cargo auditable 把依赖清单嵌入二进制，随时可出 CycloneDX
- [x] **安全响应流程** [A.5.24-5.26]：SECURITY.md（披露渠道、响应时限、支持版本策略）

### P0.5 · 模糊测试 [A.8.29]

- [x] 结构化模糊测试覆盖蜜罐解析路径（sanitize / request_summary / HTTP 头完整性扫描 + 频次引擎随机序列不变量，确定性 PRNG 双平台 CI 可跑；coverage-guided cargo-fuzz 待 Linux CI 专项）——首轮即抓到 C1 控制字符泄漏真 bug

### P1 · 功能演进

- [x] Linux nftables 后端：`inet aisafeguard` 表 + 四个地址集（入/出 × v4/v6），封禁=集合元素增删，启动 resync 重灌；macOS pf 后端待后续。逻辑单测 + Linux 交叉类型检查已过；实机验证指南 docs/LINUX-TESTING.md（用户将在 WSL 执行）
- [x] 频次规则引擎：不依赖 AI 的本地自动处置（同源 IP 阈值封禁、封禁 TTL 自动解封）——**快路径第一块**，`SecurityEvent::Detection` 变体已落地（设计见 docs/NGFW_EVOLUTION.md）
- [x] 主机暴露面盘点：枚举本机监听端口与归属进程（Windows netstat+tasklist / Linux /proc/net+fd），快照入库 → AI 提示词评估暴露风险（"自动分析功能接口"第一步）；`POST /api/exposure/scan`、`GET /api/exposure`，GUI AI 页可扫

### P2

- [ ] HTTP 蜜罐增强：路径诱饵、请求头指纹、爬虫行为记录
- [ ] 配置与数据备份导出/恢复 [A.8.13]

## 0.3 —— 检测与处置深化（NGFW 能力演进，设计依据 docs/NGFW_EVOLUTION.md）

> 按"传感器/执行器分离 + 快/慢双路径"演进：防火墙 trait 只做执行器，检测能力全部落在新 crate `aisafeguard-detect`，经事件总线接入。

- [x] **检测平台 MVP（Windows，0.3 第二批）**：`aisafeguard-detect` 新增 capture / reasm / flow / inspect 分层——WinDivert 被动采样捕获（静态编入；SNIFF 嗅探：内核照常转发、句柄只取副本；缺驱动/无提权优雅降级）、TCP 流重组（乱序/重传/环绕，含结构化模糊测试）、流统计表（元数据与计数，红线不存载荷）、内置端口扫描 / SYN flood 检测器；实机验证指南 docs/WINDOWS-CAPTURE-TESTING.md（WinDivert64.sys 需从官方渠道获取后置于程序目录）
- [x] **检测平台（Linux，0.3 第三批）**：AF_PACKET 采样捕获（`capture::spawn` 平台分发，ETH_P_ALL 不 bind 观测所有接口、不开混杂模式；无 CAP_NET_RAW 优雅降级；L2 剥离 + 模式预过滤与 Windows 内核过滤器同语义）。L2→L3 剥离与过滤逻辑为纯函数，全平台单测 + 模糊测试；Linux 目标交叉类型检查已过，**实机 E2E 清单见 docs/LINUX-TESTING.md §12（待 Linux 环境）**。nflog 方案弃用：无 iptables 集成需求，AF_PACKET 更简单直接
- [x] **快路径引擎扩展**：端口扫描 / SYN flood / 暴破速率内置检测器（暴破延续 0.2 频次引擎；扫描与 SYN flood 由采样捕获驱动），全部带 TTL 自动解封与内网保护，触发器映射表有容量上限防伪造源耗尽
- [x] **威胁情报管道 v1** [A.5.23]：Feodo C2 源（`feed_url` 可换自托管/镜像源）+ 本地蜜罐源；高置信度自动封禁（TTL 3 天+内网保护），本地/fed 源仅标注进 AI 上下文；`GET /api/intel`、`POST /api/intel/refresh`；6h 定时拉取，源不可达优雅跳过
- [x] **数据面（Windows，0.3.7 决策收口）**：主路径 = **WFP**——执行侧维持既有 COM/`aisafeguard-blk-*` 用户态管理面（规则由系统 BFE 在内核 WFP 层执行，与 Linux nftables→netfilter 同构，内核级生效能力已在手）；感知侧短期维持 WinDivert 采样（0.3.1），WFP callout（仅感知、处置仍走事件总线与 Firewall trait）为中期确有需要时的评估项；**eBPF for Windows 定为实验轨**，非 0.3/0.4 阻塞项。跨平台原则 = 能力对齐（采样/流元数据/情报驱动封禁），不做程序同源。详见 docs/NGFW_EVOLUTION.md「Windows 数据面决策」
- [x] **数据面（Linux）**：XDP + Aya 快速执行层（0.3.7）——组合防火墙：nftables 永远兜底，「入站 + Any 协议 + 无端口 + IPv4」规则镜像进 eBPF map，内核收包路径 XDP_DROP 微秒级生效；eBPF 程序随仓库分发（`objects/*.o` 嵌入主程序，单二进制）；附加失败降级纯 nftables；WSL2 实测含"删 nft 表后 XDP 独立丢包"证明。蜜罐 XDP_REDIRECT 诱导模式待后续（map 基础已具备）
- [x] **AI 深度介入 v1（0.3 第四批）**：处置灰度执行——AI 建议应用即短 TTL 试运行（AI 给 `ttl_secs` 60-604800s 用它的、否则 `[ai].trial_ttl_secs` 默认 900s；到期既有 TTL 清扫自动解封；人工"转正"延长到 `[ai].promote_ttl_secs` 默认 30 天，防火墙页一键转正）；误报反馈闭环——`fp_feedback` 表（IP 聚合 count/first/last/note）+ `mark_false_positive` 三联动（记录 30 天抑制 + 解除该来源 engine/ai 自动封禁 + 收弃 pending 建议），自动封禁/自动应用跳过抑制来源，`<feedback>` 段进提示词；AI 输入扩展——`<flows>`（流表快照 + top_syn_sources top5）+ `<self_endpoints>`（自身 API 攻击面自检：端点清单/回环绑定/Bearer/fed 现状）；API 三端点（promote/feedback×2）+ GUI 三页联动（AI 灰度应用+误报 / 事件误报 / 防火墙转正）+ Console 双实现（内嵌/远程）
- [x] **多主机控制台（组织协同骨架，完全体见 §6 / 0.4）**：协调者 + agent——事件上报（时钟窗校验+100 条/批）、情报双向同步（fed 来源仅标注不自动封禁、内网地址上报前置拒收防投毒）、AI 建议推送（接收方本地复验、仅慢路径）；协调者失联各节点独立运行。**mTLS 每节点证书加固已完成（0.3.6）[A.5.15]**：`fed init-ca`/`issue-cert` PKI 工具链、协调者独立 mTLS 监听面（强制客户端证书链到组织 CA）、node↔证书指纹 TOFU 绑定、组织令牌移除
- [x] 发布物签名 [A.8.24]（0.3.7 决策收口为过渡方案）：callout 推迟后驱动签名不再是 0.3 阻塞；当前以**分发渠道声明 + 发布页公布 SHA-256**（Batch A 的 A3 一并落地）为发布完整性过渡方案，EV 代码签名证书（发布物 + 未来 WFP callout 驱动共用）挂 0.4 收口批次，视采购情况执行- [x] Linux systemd 服务化：`service install-systemd`（unit 写入 + daemon-reload + enable --now，数据目录 /var/lib/aisafeguard；systemd 未运行时照写 unit 并提示）——WSL 实测 active
- [x] 日志远程转发（syslog/SIEM）[A.8.15]：`forward::spawn_syslog_task` 事件总线 → RFC 5424（UDP/TCP 可选），severity 统一口径（detection/封禁=warning、蜜罐命中=notice），best-effort 不阻塞引擎，完整性以本地哈希链为准——WSL 实测 UDP/TCP 收包（0.3.5）
- [x] 告警通知（webhook）：`forward::spawn_notify_task` POST JSON + `min_severity` 四档过滤 + 超时丢弃限频留痕——WSL 实测 severity 过滤与全量 body（0.3.5）
- [x] 报表导出与邮件通知（2026-09-29 按用户 Won't 清单关闭：webhook + syslog 已覆盖外发需求；"复杂报表中心"与邮件明确不做——见 docs/ROADMAP-0.4.md §5）
## 版本分层说明（2026-09 修订）

0.3.x 已完成：**检测平台 MVP + AI 深度介入 v1 + 事件外发 + 组织协同 mTLS**。  
原「0.4 完整 NGFW + 组织协同完全体」跨度过大，与当前「可安装、可运维、可度量」缺口不在同一层级。

自本修订起拆为三层，**原 checkbox 全部保留，仅调整归属与前置条件**：

| 版本 | 主题 | 一句话 |
|------|------|--------|
| **0.4** | 工程与安全收口 | 装得上、跑得稳、少重启、封禁可解释、协同可吊销、价值可度量 |
| **0.5** | NGFW 数据面与规则 | L7 指纹、ET/Suricata 子集、eBPF/XDP/AF_XDP（详见 NGFW_EVOLUTION.md §4） |
| **0.6** | 协同完全体 + 情报生态 | quorum 升格情报、选举、建议闭环打磨、STIX/MISP（详见 §6） |

约束不变：传感器与执行器分离；跨节点同步**建议**而非命令；`forbid(unsafe_code)`；内网/回环永不自动封；外发只读总线。

更细的 0.4 任务表、坑项与验收清单见 [`docs/ROADMAP-0.4.md`](ROADMAP-0.4.md)（若已加入仓库）。

---

## 0.4 —— 工程与安全收口（生产化）

> 目标：把 0.3.x 闭环做成可部署、可运维、可审计的主机侧产品；为 0.5 数据面留下干净接口。  
> **本版本不做**完整 NGFW、不引入 eBPF/XDP、不上协调者选举与 STIX。

### 安装与运行

- [x] Windows 服务安装体验收口（0.4.0 A1：服务/交互模式凭据路径差异表已入 README；服务 E2E 于 0.2 实机完成）
- [x] Linux systemd unit + 最小权限（0.4.0）：unit 白名单式授权 `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` + `CapabilityBoundingSet` + `NoNewPrivileges=yes`，注释写明降级路径（不开捕获/XDP 可整行删除）
- [x] WinDivert 官方获取说明与可选文件哈希校验（0.4.0）：`[detect.capture].driver_sha256` 配置期望哈希（空=不校验），不符降级并留事件不静默；缺失驱动原有明确提示
- [x] 配置热更新（第一批，0.4.0）：`[detect]` 阈值、`[syslog]`、`[notify]`、`[ai].enabled` / `auto_apply`、暴露面扫描间隔无需重启；**接线 `analyze_interval_secs` 定时分析任务**（此前只有配置无消费者，分析全靠手动）；热更/重启分界固化为 `AppConfig::restart_required` 契约 + 单测
- [x] 需重启项（蜜罐端口、API 端口、捕获开关/模式、XDP、fed 角色、数据目录）在 GUI 标注（0.4.0）：设置页各小节「需重启」徽标 + 新增 XDP 小节 + 保存 toast 按 `restart_required` 列出需重启项；「生效配置 vs 文件配置」完整 diff 视图留 P1

### 封禁语义与误报

- [x] 规则模型扩展：`ip` → `ip + optional port + optional tag`；旧 IP 规则兼容（0.4.0 B1：nftables 端口级拼接集合，修复端口被放大为封全端口）
- [x] 轻量 L7 **标签**（非完整指纹）（0.4.0 B2：method/path 前缀/可疑 UA，蜜罐与捕获共用 core::l7）：HTTP method / path 前缀 / 可疑 UA 等进入事件与 AI 上下文（为 0.5 抽取解析器铺路）
- [x] 误报抑制时长可配置；API/GUI 可查可清；可选高严重度忽略抑制（0.4.0 B3）
- [x] 误报可选 port 粒度（0.4.0 B4；默认仍按 IP）
- [x] 价值指标：近 24h/7d 建议数、采纳率、误报率、自动封禁数（GUI + `/api/status`，0.4.0 B5，口径写死+测试）

### 组织协同（安全补全，非完全体）

- [x] 证书吊销（文件式 CRL，0.4.0 C1：fed revoke，连接级检查立即生效 + 审计事件）
- [x] 换证流程文档化 + TOFU 缓解（0.4.0 C2：fed expect 预登记，README 组织协同运维节）
- [x] 可选 quorum 约束 **auto_apply**（0.4.0 C3：[fed].min_peers，单节点/无上报自动降级本地策略）
- [x] 协同审计导出（0.4.0 C4：fed audit 导出成员/吊销/近期协同事件；拒绝原因走事件总线）
- [x] fed 监听引导内网绑定（0.4.0 C5：公网/全地址启动 warn 事件 + README 建议）

### 分发与叙事

- [x] GitHub 发布 CI（0.4.0 D1：workflow 就绪；mirror 推送待 GitHub 可达时执行）
- [x] README 重写（0.4.0 D2：定位/数据流图/适合谁/已知限制中置/5 分钟上手）
- [x] 5 分钟演示脚本（0.4.0 D3：scripts/demo-attack.sh，无 AI 仅快路径）
- [x] 威胁模型一页纸（0.4.0 D4：docs/THREAT_MODEL.md）

### 0.4 明确 Won't

- 完整 DPI / IPS 特征库、Suricata 全量语义
- eBPF 流表、XDP map、AF_XDP
- 协调者选举、STIX 2.1 / MISP
- 邮件中心、多租户 SaaS 控制面、自动更新、macOS

### 0.4 发布前验收（摘要）

- [ ] Win 服务 + Linux systemd 可按文档独立完成
- [ ] 热更新项连续变更无任务泄漏；需重启项可见
- [ ] 旧规则兼容；内网永不自动封；AI 非法建议整条作废
- [ ] 吊销/指纹不一致负路径实测；外发失败无自反馈风暴
- [ ] 指标定义与文档一致

---

> **Windows 数据面（已拍板，0.3 已收口）：** 主路径 = **WFP**（用户态规则维持现状；采样短期 WinDivert，中期可选 WFP callout 只做感知）。**eBPF for Windows** = 实验轨，非 0.3/0.4 阻塞项；与 Linux eBPF/XDP 仅做能力对齐，不做程序同源。结论已并入 0.3「数据面（Windows）」条目，详见 `docs/NGFW_EVOLUTION.md`「Windows 数据面决策」。

## 0.5 —— NGFW 数据面与规则（详见 docs/NGFW_EVOLUTION.md §4）

> 前置：0.4 收口完成（尤其服务化、热更新边界、规则模型扩展、轻量 HTTP 标签）。  
> 目标：在**不破坏**「防火墙 trait 窄口」的前提下，增强感知与高速联动；Linux 优先，Windows 对等能力单独写清上限。  
> **状态（2026-09-29）：0.5.0 完成 L7 复用 + 规则子集引擎 + Windows 对等（下列前两组全勾，明细见 docs/ROADMAP-0.5.md）；内核数据面组归 0.5.1。**

### L7 与解析复用

- [x] L7 应用层指纹：JA3/JA4 + HTTP 解析器从蜜罐 crate 抽取复用（0.5.0：aisafeguard-l7，JA4 对齐 FoxIO 官方实现）
- [x] 与 0.4 轻量标签对齐：同一解析管线，指纹/标签都只产事件与上下文，不直接扩防火墙 API（0.5.0 E3/E6）

### 规则引擎

- [x] Suricata/ET 开放规则集**子集**兼容引擎（Rust 匹配实现，不自造规则格式；0.5.0 aisafeguard-rules，范围冻结见 docs/RULESET_SUBSET.md）
- [x] 规则命中 → 事件总线 → 既有快路径封禁 / 慢路径 AI；禁止规则引擎直接调系统防火墙绕过 trait（0.5.0：crate 依赖图禁止链 firewall，默认只告警）

### 内核数据面（Linux 主路径）

- [ ] eBPF 流表（LRU 5 元组状态）与情报 → XDP map 全联动（**0.5.1 Batch G**）
- [ ] 隐私可控的真实流量采样深检（AF_XDP）
- [ ] 文档：无 CAP/无内核支持时的降级路径；与现有 AF_PACKET / WinDivert 采样的关系

### 跨平台与风险

- [x] Windows 侧对等策略说明（能做 / 不做 / 用户态近似；0.5.0：纯用户态同一引擎，NGFW_EVOLUTION §7）
- [x] 性能护栏：默认不启用深检；流表 cap、drop 计数进入 status（drop 计数随 0.5.1 Batch G）
- [x] 隐私红线复查：载荷截断、默认非混杂、配置明示（default_config_security_baseline 测试钉住）

### 0.5 建议 Won't（可再拆 0.5.x）

- 协调者选举、STIX（归 0.6）
- 自研全量规则语言
- 把防火墙 trait 膨胀成通用 NGFW 配置 API

---

## 0.6 —— 组织协同完全体与情报生态（详见 docs/NGFW_EVOLUTION.md §6）

> 前置：0.4 吊销/绑定/审计；0.5 至少具备稳定的检测事件与情报入口（规则或指纹命中可汇总）。  
> 目标：**防投毒**的协同完全体 + 可选对接外部情报生态。

### 组织协同完全体 [防投毒]

- [ ] 多节点印证 quorum（**N-of-M 升格情报**，与 0.4「约束自动封禁」的 quorum 配置可共用参数但语义分列文档）
- [ ] 跨节点 AI 建议同步闭环（仅慢路径 + 本地复验；接收端可拒绝/灰度）
- [ ] 协调者选举
- [ ] 节点时钟窗校验（告警 + 拒绝过期消息；与吊销立即生效策略兼容）

### 情报生态

- [ ] STIX 2.1 导入导出**评估**（对接 MISP 生态；先评估再承诺写入主路径）
- [ ] 导入情报与本地蜜罐/规则命中的置信度、TTL、内网保护策略一致化

### 0.6 验收关注点

- [ ] 单点投毒无法驱动全网自动封禁（quorum + 本地复验 + 内网硬拒绝）
- [ ] 选举切换期间不丢审计、不重复执行冲突规则
- [ ] STIX 路径默认关闭或只读评估，避免未审查 IoC 直达 auto_block

---

## 与历史表述的对应关系

| 原「0.4 —— 完整 NGFW…」条目 | 现归属 |
|------------------------------|--------|
| L7：JA3/JA4 + HTTP 解析抽取复用 | **0.5**（0.4 仅轻量标签铺路） |
| Suricata/ET 子集兼容引擎 | **0.5** |
| eBPF 流表 + 情报 → XDP map | **0.5** |
| AF_XDP 隐私可控深检 | **0.5** |
| 组织协同完全体（quorum 升格情报、AI 建议闭环、选举、时钟窗） | **0.6**（0.4 仅吊销/绑定/可选封禁 quorum） |
| STIX 2.1 / MISP 评估 | **0.6** |
| （原 0.4 未单列）服务化、热更、指标、README、吊销 | **0.4** 新增主路径 |

---

## 修订记录

| 日期 | 说明 |
|------|------|
| 2026-09-28 | 将原单一「0.4 完整 NGFW+协同」拆为 0.4 收口 / 0.5 NGFW / 0.6 协同+STIX；保留原 checkbox 并标注归属 |


## 远期

## 0.x —— 完整 NGFW 能力与组织协同（详见 docs/NGFW_EVOLUTION.md §4/§6）

- [ ] L7 应用层指纹：JA3/JA4 + HTTP 解析器从蜜罐 crate 抽取复用
- [ ] Suricata/ET 开放规则集子集兼容引擎（Rust 匹配实现，不自造规则格式）
- [ ] eBPF 流表（LRU 5 元组状态）与情报 → XDP map 全联动（**0.5.1 Batch G**）
- [ ] 隐私可控的真实流量采样深检（AF_XDP）
- [ ] **组织协同完全体** [防投毒]：多节点印证 quorum（N-of-M 升格情报）、跨节点 AI 建议同步闭环（仅慢路径 + 本地复验）、协调者选举、节点时钟窗校验
- [ ] STIX 2.1 导入导出评估（对接 MISP 生态）

- 分布式 agent 编排与配置下发
- 跨组织情报联邦（MISP 对接，行业 ISAC 共享）
- 检测特征库与 YARA 类文件层检测
- AI 驱动的接口模糊测试（对蜜罐与真实服务）
- WFP callout 自研内核检测（驱动签名成本可接受时）、ML 异常评分
