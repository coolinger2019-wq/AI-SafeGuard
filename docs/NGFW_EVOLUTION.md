# NGFW 能力演进设计（DPI / 状态跟踪 / 应用层识别 / IPS / 威胁情报）

> 目的：回答"AI-SafeGuard 的防火墙如何长成下一代防火墙（NGFW/IPS）"。
> 基调：**加传感器，不动执行器**。`Firewall` trait 保持窄口，所有检测能力落在新 crate、经事件总线接入，0.1 闭环零重写。
> 本文档是 ROADMAP 0.2/0.3/0.4 检测类条目的设计依据；§6 为内网组织协同（分布式威胁共享）设计。

## 0. 现状基线（0.1 有什么 / 没什么）

**已有：**
- 执行器：`Firewall` trait = `add_block(BlockSpec)` / `remove`，结构化、`aisafeguard-` 前缀保护、内网保护（`is_protected_ip`）
- 传感器：蜜罐（被动诱捕，攻击者应用层完整会话视角）
- 慢路径决策：AI 分析 → 严格 schema 建议 → 人工/阈值自动 → 全链路审计
- 隐含免费能力：Windows 防火墙本身有状态（WFP ALE 层跟踪连接），现有规则天然状态化

**没有（本文档要补的）：** 真实流量观测、连接状态统计、DPI/L7 识别、签名与异常检测、外部威胁情报。

## 1. 总架构：传感器 / 执行器分离

```
 蜜罐(已有) ────────┐
 真实流量观测(新) ──┤▶ EventBus（SecurityEvent 统一流）
 威胁情报(新) ──────┘        │
                 ┌───────────┴───────────┐
                 ▼                       ▼
        [快路径·本地规则引擎]      [慢路径·AI 分析(已有)]
         签名/阈值/状态异常/情报    行为分析、模糊场景
         可解释 → 可自动执行       建议 → schema 校验 → 默认人工
                 └───────────┬───────────┘
                             ▼
              [执行器: Firewall trait / eBPF map]
                             ▼
                        全链路审计(已有)
```

### 快/慢双路径准入规则（此后所有检测功能必须遵守）

| | 快路径 | 慢路径 |
|---|---|---|
| 输入 | 确定性证据：签名命中、频次阈值、状态机异常、高置信度情报 | 模糊/行为类证据，AI 分析 |
| 自动执行 | 允许，但必须：理由可读、TTL 自动解封、内网/白名单保护 | 默认人工确认；自动应用仅限显式开关 + 严重度阈值（0.1 已有） |
| 审计 | 强制 | 强制 |

不设第三条执行通道——任何新检测器必须归入其中一条。

### 四条立即生效的架构决策

1. **`Firewall` trait 保持窄**：永不往 `BlockSpec` 加 DPI/状态字段，不进化成 NGFW API。检测能力落在新 crate `aisafeguard-detect`，与防火墙只通过 `BlockSpec` 和事件总线对话。
2. **`SecurityEvent` 预留演进**：新增 `Detection` 变体（§5）；Rust enum 加变体对既有消费者零破坏，现在就占位。
3. **快/慢双路径**是准入规则（上表），新检测器先选边再动手。
4. **隐私红线与 DPI 同步立项**（§3），不做事后补丁。

## 2. 五个能力的实现设计

### 2.1 状态连接跟踪

- **Windows**：基础状态化 0.1 已免费获得（WFP ALE 层）。自定义流统计走 WinDivert 用户态流表（0.3，用户态、免自研驱动签名）；WFP callout（需驱动签名）为最后手段。
- **Linux**：nftables `ct` 状态匹配（0.2 后端即带 established/related/new/invalid 规则模板）；更深的自定义流表用 eBPF LRU hash map（5 元组 → {syn_ts, pkt_count, byte_count, last_seen}），建在 XdpBackend 之上。
- **落点**：流表统计（新建速率、半开连接数、每流字节分布）周期产出 `Detection` 事件入总线入库。
- **AI 角色**：流统计是提示词的高价值特征——"60 秒内 800 个半开连接"比"连接数 800"对 LLM 有用一个量级。
- **红线**：流表只存元数据与计数，不存载荷。

### 2.2 深度包检测（DPI）

- **分工原则：内核做粗分类，用户态做深检。**
  - 内核（eBPF/XDP 或 WinDivert 过滤表达式）：头解析、端口+协议粗分、名单匹配、可疑流标记。
  - 用户态：可疑流采样捕获（Linux: XDP_REDIRECT→AF_XDP 或 tc；Windows: WinDivert），TCP 重组、正则、协议解码。
- **全量深检不做**：性能与复杂度深坑，且与隐私红线冲突。默认 = 蜜罐全量深检（数据本来就是攻击者发给假服务的）+ 真实流量可疑流采样，采样率可配置。
- **落点**：`aisafeguard-detect` 内部分层：`capture`（平台数据面适配）→ `reasm`（TCP 流重组，RFC793 简化集）→ `inspect`（解码 + 规则匹配）。
- **AI 角色**：可疑会话的"元数据 + 截断载荷"喂 LLM——0.1 蜜罐的不可信输入管线原样复用（`<events>` 包裹、声明非指令、schema 校验输出）。

### 2.3 应用层识别（L7 Awareness）

- **指纹库**：JA3/JA4（TLS 客户端指纹）、HTTP（方法/路径模式/UA/头序）、协议握手特征。用现成开源指纹数据，不自造格式。
- **复用红利**：0.1 蜜罐已实现 HTTP 请求解析与 SSH/Telnet banner 交互——把解析器从 `aisafeguard-honeypot` 抽到 `aisafeguard-detect::l7`，蜜罐与真实流量共用，蜜罐顺势升级为"全量深检消费者"。
- **产出**：`Detection { kind: l7, flow_id, proto, fingerprint, confidence }`，用于：(a) 策略匹配（如"RDP 暴露告警"）；(b) AI 特征；(c) 诱导决策（对可疑源把流量重定向到对应假服务）。

### 2.4 入侵预防（IPS）

- **快路径引擎**（0.2 频次引擎起步，0.3 扩展为完整引擎）：
  - 规则格式：兼容 Suricata/ET 开放规则集**子集**（header + content/itype 简单匹配），我们只写 Rust 匹配引擎，复用社区维护的规则库（AGENTS：不自造生态）。
  - 内置检测器（零签名依赖）：端口扫描（固定窗口 n 端口/s）、SYN flood、暴力破解速率、蜜罐命中即信（蜜罐被碰 = 恶意，0.1 已隐含，正式化为规则）。
  - 执行：产出 `BlockSpec` 走现有 trait；rules 表加 `expires_ts` 列，TTL 到期自动解封。
- **慢路径**：现有 AI 管线不变，输入源从"蜜罐统计"扩展为"蜜罐 + 流统计（`<flows>`：快照计数 + 纯 SYN top 来源，0.3.4 接入）+ DPI 元数据 + 情报标注（`<intel>`）+ 自身攻击面（`<self_endpoints>`，0.3.4）+ 误报反馈（`<feedback>`，0.3.4）。处置灰度：AI 应用即短 TTL（AI `ttl_secs` 或 `trial_ttl_secs`），人工转正延长（`promote_ttl_secs`）。
- **误杀治理**：内网/回环保护对自动封禁全局生效；所有自动执行带 TTL 与一键撤销；快路径每条执行都是可解释的（规则 ID + 证据摘要）。

### 2.5 威胁情报集成

- **数据源（全公开免费）**：abuse.ch Feodo Tracker（C2 IP）、URLhaus、Spamhaus DROP（恶意网段）、Greynoise 免费层。**本地情报优先**：蜜罐捕获的源 IP 就是最可信的情报（events 表已有）。
- **管道**：定时拉取 → 解析归一化（value/kind/来源/置信度/TTL）→ store 新表 `intel` → 两个消费口：
  1. 高置信度（C2/恶意软件分发、来源信誉好）→ 快路径自动下发（防火墙/eBPF map，XdpBackend 场景微秒级生效）；
  2. 其余 → 仅作 AI 特征与界面标注（"该 IP 被 Feodo 标记为 botnet C2"），不自动封。
- **治理**（对应 A.5.23）：每源登记评估记录（维护方/更新频率/许可证/误报史）；条目 TTL 过期自动失效；整源一键禁用。
- **红线**：情报封禁同样过 `is_protected_ip` 与前缀校验；DROP 类网段列表不自动封（范围过大），只标注 + 进 AI 上下文。

## 3. 隐私与合规红线（与 DPI 同步立项，对应 A.8.11）

1. **元数据优先**：默认只采集/留存流元数据与计数。
2. **采样深检**：真实流量内容检测仅限被快路径标记的可疑流，采样率可配置。
3. **明文内容检测默认关闭**，可配置开启（蜜罐除外——蜜罐数据本来就是攻击者发给假服务的）。
4. **留存期限**：DPI 产物沿用 events 的 30 天清理策略。
5. **文档化采集**：config 中每个采集开关附一行说明"采什么、为什么"。

## 4. 分阶段落地与验收

| 阶段 | 内容 | 验收标准 |
|---|---|---|
| 0.2（随 P1） | `SecurityEvent::Detection` 变体占位；频次引擎 v1（端口扫描/暴破速率）；nftables 后端带 `ct` 模板 | 单测：扫描器连 5 端口 → Detection 事件 + 自动封禁 + TTL 解封 |
| 0.3 | `aisafeguard-detect` MVP：WinDivert/nflog 采样捕获 + TCP 重组 + 端口扫描/SYN flood/暴破检测器；情报管道 v1（Feodo + 本地蜜罐源）；TTL 自动解封<br>**状态（0.3.3）**：Windows 侧（capture/flow/reasm/inspect 分层 + WinDivert 静态集成 + 降级路径，实机核对见 docs/WINDOWS-CAPTURE-TESTING.md）与 Linux 侧（AF_PACKET 采样捕获，交叉类型检查已过、实机 E2E 清单见 docs/LINUX-TESTING.md §12）均已完成；nflog 方案弃用（无 iptables 集成需求）<br>**数据面 Linux（0.3.7）**：XDP + Aya 组合执行层已落地——nftables 兜底 + IP 级入站规则镜像进 eBPF map 内核直丢，实机验证含"删 nft 表后 XDP 独立丢包" | E2E：nmap 扫描 → 秒级自动封 → TTL 后恢复；Feodo 列表 IP 连接 → 命中事件 + 自动封；XDP 封禁在 nftables 缺席时独立生效 |
| 0.4 | L7 指纹（JA3/JA4 + HTTP 解析复用）；Suricata 规则子集引擎；eBPF 流表；情报 → XDP map 联动；AI 输入接入流统计 | E2E：特定 TLS 指纹命中规则 → 处置留痕；AI 报告引用流统计与情报标注 |
| 远期 | AF_XDP 全流量深检、文件/载荷还原、ML 异常评分、WFP callout（驱动签名成本可接受时） | — |

## 5. 新增构件清单

- **crate**：`aisafeguard-detect`，内部分 `capture / reasm / flow / inspect`（0.3.1 已落地）与 `l7 / rules`（0.4）等模块；对外只发事件，不直接碰防火墙（执行只经 `BlockSpec`）。
- **事件**：`SecurityEvent::Detection { ts, kind: scan|flood|bruteforce|signature|intel_hit, src_ip, confidence, evidence: String(截断), rule_id: Option<String> }`（0.3.1 起 rule_id 标识内置规则，如 builtin.tcp_scan / builtin.syn_flood）
- **store**：新表 `intel`（source, kind, value, confidence, first_seen, expires_ts）；`rules` 表加 `expires_ts` 列；流统计**不落盘**（内存流表 + 空闲回收，只随 Detection 证据留痕）
- **config**：`[detect]`（频次引擎开关与阈值）、`[detect.capture]`（0.3.1：enabled/mode/扫描与 flood 阈值/窗口/流表容量）与 `[intel]`（feed_url、拉取间隔、自动下发开关）
- **新 trait**：`CaptureSource`（win: WinDivert【0.3.1 已实现】 / linux: AF_PACKET【0.3.3 已实现；nflog 弃用——无 iptables 集成需求】）与流表（做在 detect crate 内的用户态实现，容量上限 + 超时回收）；实现落为 `capture::spawn` 平台分发函数而非 trait（当前每平台只有一个后端，AGENTS：不做预防性抽象）；`Firewall` 与 `EventBus` 不动

## 6. 内网组织协同（分布式威胁共享）

> 定位：0.3"多主机控制台"的完全体——每个节点独立探测威胁，向组织共享检测到的威胁信息与应对建议，其他节点同步后按本地策略处置。
> 现实可行性已验证：Wazuh（中心+代理+active response 下发）、CrowdSec（多节点 signal 共享与印证）、MISP/STIX（标准化情报共享）。
> 参照这些实现沉淀的教训，形成以下设计约束。

### 6.1 三条设计约束（来自现实实现）

1. **中心+代理为主，对等只是故障形态。** 节点加入组织时注册身份（mTLS + 每节点证书 + 组织 ID），指定或选举一台为协调者（coordinator）。协调者在协议里只是"第一个对等点的特例"——同步协议按对等可扩展设计，但日常拓扑不搞纯 P2P mesh（信任、新鲜度、撤销在无中心 P2P 里做不好，现实产品无一例外）。
2. **防投毒是第一设计约束。** 被攻陷节点注入的情报不能让全网自锁（例如"封掉网关"）。机制：多节点印证（quorum N-of-M）、置信度评分、TTL 自动过期、单源一键禁用；`is_protected_ip` 内网保护对一切共享内容全局生效。
3. **跨节点共享"结构化建议"，不共享命令。** 同步的是 AI Proposal（0.1 的严格 schema 就是现成的共享格式）与印证过的情报条目；接收节点用**本地同一套 allowlist 校验管线**复验后，走本节点的慢路径（人工确认/本地阈值）。标准界有 OpenC2/CACAO（机器可读处置动作/剧本），互操作时再评估，0.x 不引入。

### 6.2 拓扑与协议

- **角色**：协调者（coordinator，可重选）/ 成员节点（member）。协调者挂掉 → 存活节点重选（0.4），期间各节点退化为独立运行（永远可用）。
- **加入流程（组织注册）**：新节点生成密钥对 → 管理员在协调者处审批 → 颁发节点证书 + 组织 ID → 节点以 mTLS 接入。
- **同步协议 v1 = 现有 axum API 扩展三个端点**：
  - `POST /fed/events` —— 节点上报检测/蜜罐事件摘要（供协调者聚合与印证）
  - `GET /fed/intel` —— 拉取已印证的情报列表（带置信度/TTL/来源节点列表）
  - `POST /fed/proposals` —— 推送 AI 建议（接收方本地复验，仅进慢路径）
- **传输与消息**：mTLS（0.3.6 已实现：`fed init-ca`/`issue-cert` 签发组织 CA 与节点证书，协调者独立 mTLS 监听面强制客户端证书，node↔证书指纹 TOFU 绑定）；每条消息带节点 ID + 时间戳，接收方校验时间窗防重放。
- **互操作**：0.4 评估 STIX 2.1 导入导出（对接 MISP 生态）；跨组织联邦放远期。

### 6.3 印证与执行规则（防投毒核心）

| 层级 | 规则 |
|---|---|
| 事件级 | 单节点观测 → 只进本节点事件流与上报，**仅标注**，不产生任何自动处置 |
| 情报级 | ≥N 个节点（默认 N=2，可配）独立观测同一来源 → 升格为 `intel` 条目（置信度 + 来源节点列表 + TTL）→ 达到自动下发阈值才进快路径（防火墙/eBPF map） |
| 建议级 | 跨节点 Proposal 永远只进慢路径，永不自动执行 |
| 全局 | `is_protected_ip`、规则前缀校验、TTL、单源一键禁用，对共享内容同样生效 |

### 6.4 离线内网适配

- **AI 分析**：`base_url` 指向本地推理端点（Ollama/vLLM 等 OpenAI 兼容服务）——封闭内网无云端 LLM 也能跑完整分析闭环。
- **情报**：无外网时退化为组织内共享（蜜罐源 + 多节点印证），不依赖外部 feed。
- **时钟**：节点间要求 NTP 同步；消息时间戳校验容忍度可配（默认 ±120s），超窗拒收。

### 6.5 落点与新增构件

- **0.3（骨架）**：协调者 + agent——节点注册审批、事件上报、情报下发、Proposal 推送四条链路打通，mTLS 全程。
- **0.4（完全体）**：多节点印证 quorum、跨节点 Proposal 本地复验闭环、协调者选举、STIX 互操作评估。
- **构件**：`fed` 模块（先放 `aisafeguard-app`，独立成 `aisafeguard-fed` crate 待接口稳定）；config 新增 `[fed]`（enabled / role / org_id / coordinator / quorum_n / 时间窗）；store 新表 `fed_members`（node_id, cert_fp, last_seen, trust），`intel` 表扩展 `sources` 列表列。
