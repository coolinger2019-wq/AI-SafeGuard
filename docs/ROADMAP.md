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
- [ ] **数据面（Windows）**：WFP callout 驱动或 WinDivert；ebpf-for-windows 成熟后试点评估（Aya 用户态加载器绑定 Linux bpf() 系统调用，不能直接用于 Windows）
- [ ] **数据面（Linux）**：XDP + Aya 实现 `XdpBackend`——AI 封禁决策写入 eBPF map，内核微秒级生效（`Firewall` trait 已预留该扩展位）；蜜罐升级为 XDP_REDIRECT 诱导模式：对已标记的扫描源，把发往真实服务端口的流量重定向到蜜罐端口
- [x] **AI 深度介入 v1（0.3 第四批）**：处置灰度执行——AI 建议应用即短 TTL 试运行（AI 给 `ttl_secs` 60-604800s 用它的、否则 `[ai].trial_ttl_secs` 默认 900s；到期既有 TTL 清扫自动解封；人工"转正"延长到 `[ai].promote_ttl_secs` 默认 30 天，防火墙页一键转正）；误报反馈闭环——`fp_feedback` 表（IP 聚合 count/first/last/note）+ `mark_false_positive` 三联动（记录 30 天抑制 + 解除该来源 engine/ai 自动封禁 + 收弃 pending 建议），自动封禁/自动应用跳过抑制来源，`<feedback>` 段进提示词；AI 输入扩展——`<flows>`（流表快照 + top_syn_sources top5）+ `<self_endpoints>`（自身 API 攻击面自检：端点清单/回环绑定/Bearer/fed 现状）；API 三端点（promote/feedback×2）+ GUI 三页联动（AI 灰度应用+误报 / 事件误报 / 防火墙转正）+ Console 双实现（内嵌/远程）
- [x] **多主机控制台（组织协同骨架，完全体见 §6 / 0.4）**：协调者 + agent——事件上报（时钟窗校验+100 条/批）、情报双向同步（fed 来源仅标注不自动封禁、内网地址上报前置拒收防投毒）、AI 建议推送（接收方本地复验、仅慢路径）；协调者失联各节点独立运行。鉴权 v1=组织令牌（环境变量），mTLS 每节点证书为 0.3 后续加固 [A.5.15]
- [ ] 发布物代码签名 + 更新清单签名 [A.8.24]
- [x] Linux systemd 服务化：`service install-systemd`（unit 写入 + daemon-reload + enable --now，数据目录 /var/lib/aisafeguard；systemd 未运行时照写 unit 并提示）——WSL 实测 active
- [x] 日志远程转发（syslog/SIEM）[A.8.15]：`forward::spawn_syslog_task` 事件总线 → RFC 5424（UDP/TCP 可选），severity 统一口径（detection/封禁=warning、蜜罐命中=notice），best-effort 不阻塞引擎，完整性以本地哈希链为准——WSL 实测 UDP/TCP 收包（0.3.5）
- [x] 告警通知（webhook）：`forward::spawn_notify_task` POST JSON + `min_severity` 四档过滤 + 超时丢弃限频留痕——WSL 实测 severity 过滤与全量 body（0.3.5）
- [ ] 报表导出与邮件通知

## 0.4 —— 完整 NGFW 能力与组织协同（详见 docs/NGFW_EVOLUTION.md §4/§6）

- [ ] L7 应用层指纹：JA3/JA4 + HTTP 解析器从蜜罐 crate 抽取复用
- [ ] Suricata/ET 开放规则集子集兼容引擎（Rust 匹配实现，不自造规则格式）
- [ ] eBPF 流表（LRU 5 元组状态）与情报 → XDP map 全联动
- [ ] 隐私可控的真实流量采样深检（AF_XDP）
- [ ] **组织协同完全体** [防投毒]：多节点印证 quorum（N-of-M 升格情报）、跨节点 AI 建议同步闭环（仅慢路径 + 本地复验）、协调者选举、节点时钟窗校验
- [ ] STIX 2.1 导入导出评估（对接 MISP 生态）

## 远期

- 分布式 agent 编排与配置下发
- 跨组织情报联邦（MISP 对接，行业 ISAC 共享）
- 检测特征库与 YARA 类文件层检测
- AI 驱动的接口模糊测试（对蜜罐与真实服务）
- WFP callout 自研内核检测（驱动签名成本可接受时）、ML 异常评分
