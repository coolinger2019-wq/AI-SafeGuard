# 更新日志

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.4.0] - 2026-09-29

按 ROADMAP-0.4 Batch A（装得上、跑得稳）完成第一批：配置热更新契约、
服务化权限收口、交付完整性校验、AI 定时分析接线。

### 新增

- **误报端口粒度（B4）**：`fp_feedback` 加 `local_port` 列（ALTER 兼容）——
  反馈可带端口（缺省 = 按 IP 整体抑制）；`active_fp` 匹配规则：IP 级记录
  抑制任何处置，端口级记录仅抑制同端口处置（来源级检测不被端口级记录抑制）；
  最后一次标记决定粒度；FpRow/API/测试同步
- **规则模型扩展（B1）**：防火墙 trait 支持可选端口全链路——nftables 端口级
  拼接集合（`ipv4_addr . inet_service`，4 个新集合 + 4 条链规则），`add_block`
  按 `local_port` 分派 IP 级/端口级（**此前端口被静默放大为封全端口**），
  `any` 协议 = tcp+udp 双集合；trait `remove` 改收完整 `BlockSpec`（janitor/
  删规则处由规则行构造，语义不再丢失），`resync` 携带完整 spec（端口级规则
  重启后可重灌）；Windows COM 按名字删除不受影响；规则表加 `tag` 可选标签
  （API/GUI 表单可填，列表展示，审计可解释性）；旧「仅 IP」规则完全兼容
- **价值指标仪表（B5）**：`store::metrics_since` 三个单查询取数（口径写死：
  proposed=窗口内建议数、applied=采纳数、fp=窗口内误报来源数、
  auto_blocks=快路径自动封禁次数，以 handle_detection 固定文案「已自动封禁」
  识别）；`/api/status` 返回 `metrics_24h` / `metrics_7d`；AI 页顶部展示
  双窗口数字与派生比率（采纳率 = 采纳/建议、误报率 = 误报/采纳，分母为零显示"—"）；
  store 窗口内外断言测试
- **误报抑制时长可配置 + 清除抑制（B3）**：`[ai].fp_suppress_secs`（默认 30 天）
  替代硬编码常量——快路径自动封禁 / auto_apply / 抑制列表三处统一读取；
  `DELETE /api/feedback/{ip}` + AI 页"生效中的误报抑制"小节（行内"清除抑制"
  按钮，清除后恢复自动封禁资格并留事件）；`[ai].fp_ignore_min_severity`
  可选高严重度忽略抑制（仅作用 auto_apply，快路径始终尊重抑制）
- **AI 定时分析接线（A4）**：`[ai].analyze_interval_secs` 此前只有配置没有
  消费者（分析全靠 GUI/API 手动触发）；新增引擎定时任务，每轮读最新配置——
  `enabled` / `interval` / `auto_apply` 全部热更；`ai_running` 防重入闸门
  手动与定时共用；首跑延迟 30s（与情报/暴露面任务先例一致）
- **热更/重启分界契约（A4/A5）**：`AppConfig::restart_required(old, new)`
  纯函数 + 契约单测——蜜罐监听、API 服务、捕获开关/模式、XDP、fed 角色、
  数据目录 = **需重启**；detect 阈值 / syslog / notify / ai / exposure /
  intel / fed 运行期参数 = **热更**。保存配置时据此留事件、设置页 toast
  明确列出需重启项，杜绝"以为改了其实没生效"
- **驱动完整性校验（A3）**：`[detect.capture].driver_sha256`（空 = 不校验，
  默认）——Windows 启动捕获前校验 exe 同目录 `WinDivert64.sys` 的 SHA-256，
  不符则捕获降级并留事件（供应链防护，不静默继续）；官方获取说明见
  docs/WINDOWS-CAPTURE-TESTING.md
- **systemd 最小权限（A2）**：unit 增加 `AmbientCapabilities=CAP_NET_ADMIN
  CAP_NET_RAW` + `CapabilityBoundingSet` + `NoNewPrivileges=yes`（白名单式
  授权而非裸 root 全能力），注释写明"仅蜜罐+API"场景的降级路径与专用用户收权示例
- **A1 文档化**：README 新增"服务模式与凭据路径"——Windows 凭据管理器按用户
  隔离导致服务读不到用户存的 AI Key，服务模式一律走环境变量（表格式说明）
- **XDP 设置小节（A5）**：设置页新增启用/网卡/模式（标注仅 Linux、需重启）

### 变更

- 配置保存事件与 GUI toast 按 `restart_required` 生成（"全部热更生效"或
  "需重启项列表"），替代原先一刀切的"重启后生效"表述
- README 已知限制同步热更/重启两类表述

### 已知限制

- 「生效配置 vs 文件配置」完整 diff 视图留 P1
- 热更边界以 `restart_required` 契约为准——新增需重启项时必须同步该函数
  （契约单测钉住各分支）

### 验证（WSL2 Ubuntu 24.04，2026-09-29）

- AI 定时任务：`interval_secs=30` + `enabled=true` + 无 Key → 每 30s 一条
  `ai_run`（未配置 API Key）；`POST /api/config` 关闭 enabled → 不再产生（热更）
- `restart_required` 契约单测全分支（含"热更项不计入"反向断言）
- systemd unit 重装后含 AmbientCapabilities / NoNewPrivileges，服务 active
- 0.3.7 XDP 回归：附加/双写/解封正常

## [0.3.7] - 2026-09-28

按 ROADMAP 0.3 推进第七批：数据面 Linux——XDP + Aya 快速执行层
（`Firewall` trait 预留的扩展位落地，设计见 docs/NGFW_EVOLUTION.md §2.4）。

### 新增

- **新 crate `aisafeguard-xdp`**：组合防火墙（`CompositeFirewall`）——nftables
  永远兜底，满足「入站 + Any 协议 + 无端口限定 + IPv4」的规则**额外**镜像进
  eBPF map（`BLOCKLIST`，LruHashMap 65536），XDP 程序在内核收包路径按源地址
  直接 `XDP_DROP`——微秒级生效，无需用户态参与。细粒度协议/端口/出站/IPv6
  规则不镜像（XDP 是 IP 级全端口入站丢弃，镜像会放大语义）
- **eBPF 程序**（`aisafeguard-xdp/ebpf/`）：`#[xdp]` 入口解析失败一律放行
  （快速层绝不拖垮正常转发，封禁语义由 nftables 兜底保证）；nightly +
  bpf-linker 0.9.13（LLVM 19）独立构建（脱离主 workspace，`ebpf/build.sh`），
  产物 `objects/aisafeguard_xdp.o`（1400 字节）**提交入库**，运行时
  `include_bytes!` 嵌入——单二进制分发不依赖目标机工具链
- **降级语义**：附加失败（无 CAP_BPF、网卡不支持）只留 error 事件，组合层
  退化为纯 nftables；`remove` 双层都清（base 失败不阻断加速层清理，
  防止 map 残留"nft 看不见的封禁"）；`resync` 以期望集对账增删 map
- 配置 `[xdp]`（enabled/iface/mode=skb|native，默认关闭；仅 Linux 编译）
- 单测：镜像资格判定（方向/协议/端口/IPv6 各分支）、嵌入对象可解析（Linux）
- 可行性专项先行：WSL2 内核 6.6（CONFIG_BPF_SYSCALL/JIT/XDP_SOCKETS 全 y）+
  nightly + rust-src + bpf-linker 0.9.13（对应 llvm-sys 191；最新版要 LLVM 23）
  + LLVM 19 dev 包（apt）——spike 先验证 lo 上 XDP_DROP/解封全链路再进实现

### 变更

- 无接口变化：`Firewall` trait 不动，XDP 是 create_backend 之上的组合层
- main.rs 装配点：Linux + `[xdp].enabled` 时用组合层替换裸 nftables 后端

### 已知限制

- SKB 模式（generic XDP）在收包路径软中断点生效；native 模式需网卡驱动支持
  （virtio_net/内核 6.6 支持），微秒级路径需实测生产网卡
- eBPF 程序/地图 pinned 到进程生命周期：引擎退出即卸载（nftables 集合同理易失，
  启动 resync 重灌）
- XDP map 无直接观测口（bpftool 可查，产品内暂未暴露计数）

### 实测（WSL2 Ubuntu 24.04，2026-09-28）

- 附加验证：`ip -d link show lo` 出现 xdpgeneric 标记
- 双写封禁 127.0.0.2：nft set 与 XDP map 同时生效（ping 全丢）；API 解封 →
  map 同步删除（ping 恢复）；伪造源 SYN 突发 → engine 自动封禁（同一组合出口），
  TTL 到期 janitor 自动解封
- **XDP 独立丢包证明**：封禁生效后手动删除整个 nftables 表 → ping 仍被丢
  （内核 eBPF 在丢包，与用户态无关）；API 解封仍能清 map 恢复连通
- 调试过程中发现并修复 `include_bytes!` 对齐坑（见 LESSONS 第七批）

## [0.3.6] - 2026-09-28

按 ROADMAP 0.3 推进第六批：组织协同 mTLS 每节点证书加固 [A.5.15]——
组织共享令牌整体移除（无兼容层），节点身份改由 X.509 证书承载。

### 新增

- **PKI 工具链**：`aisafeguard fed init-ca`（生成组织 CA，自签 10 年，
  `<数据目录>/fed/ca.pem` + `ca-key.pem`；已存在时明确拒绝——覆盖 CA = 全网信任
  重置，绝不能静默发生）；`aisafeguard fed issue-cert <node> [--san <dns|ip> ...]`
  （签发节点证书，默认 SAN = 节点名，协调者需追加对外地址的 SAN；
  clientAuth + serverAuth 双 EKU 一证两用；输出 SHA-256 指纹供核对）。
  rcgen 0.13 签发（ring 后端，与 reqwest 的 rustls-tls 同一加密栈）
- **协调者独立 mTLS 监听面**：`[fed].listen_addr`（默认 0.0.0.0:7421），
  rustls WebPkiClientVerifier **强制**客户端证书链到组织 CA；手写 accept 循环
  （tokio-rustls + TowerToHyperService）——不走 axum-server 的 tls-rustls 特性，
  避免 feature 合并悄悄引入 aws-lc-rs provider（Windows 构建需 CMake/NASM）。
  /fed 路由整体从本地 API（127.0.0.1:7420）迁出
- **node ↔ 证书指纹 TOFU 绑定**：首次接触登记 `cert_fp`（fed_members 表新列），
  之后每次请求校验指纹一致——一张失窃证书冒用其他节点名在此被拦（403）；
  换证需管理员删除成员记录重新登记
- **agent mTLS 客户端**：reqwest 携带本节点证书身份 + 组织 CA 验证协调者；
  证书材料（默认 `<数据目录>/fed/{ca,cert,key}.pem` 或 `certs/<node>.pem`）
  惰性加载——缺失只降级留痕（60s 限频），补齐文件后下一轮自动恢复
- 配置 `[fed]` 新增 `listen_addr` / `ca_path` / `cert_path` / `key_path`
  （空 = 数据目录 fed/ 默认位置；节点证书对另回退 `certs/<node>.pem`）；
  移除 `AISAFEGUARD_FED_TOKEN` 环境变量与 `effective_token()`
- 单测：cert_fp SHA-256 已知向量、节点名校验、PKI 全流程（init-ca → issue-cert
  → 读回证书/私钥 → 指纹一致；重复 init-ca 拒绝）、store 指纹绑定（首登/心跳/
  异指纹拒绝/多成员）

### 变更

- fed_members 表加 `cert_fp` 列（ALTER 兼容存量库）；`GET /fed/members` 返回指纹
- AI `<self_endpoints>` 段的 fed 鉴权描述同步为 mTLS 现状

### 已知限制

- node↔指纹为 TOFU：攻击者若在真实节点之前用合法证书抢注节点名可完成绑定
  （需先持有组织 CA 签发的证书，风险窗口限于首个上报周期）；证书吊销列表
  （CRL/OCSP）与 quorum 印证属 0.4
- 协调者 mTLS 面按配置对外监听（默认 0.0.0.0:7421）——这是组织同步的必要暴露，
  暴露面盘点会将其计入
- 时钟窗校验（±1h）沿用 0.3.0；节点间 NTP 同步仍是部署前提

### 实测（WSL2 Ubuntu 24.04，2026-09-28）

- 双实例（coord1 + agent1）真 TLS 握手：agent 15s 一轮上报，协调者事件流出现
  `fed:agent1` 蜜罐命中；成员表指纹与签发输出一致
- 负路径：无客户端证书 → TLS 握手被拒；agent2 合法证书冒用 node=agent1 → 403

## [0.3.5] - 2026-09-28

按 ROADMAP 0.3 推进第五批：事件外发与自动化——日志远程转发（syslog/SIEM）+
告警通知（webhook）+ 暴露面定时自动扫描。三条通道都是事件总线的只读消费者，
"加传感器不动执行器"基调不变，零新依赖。

### 新增

- **日志远程转发 [A.8.15]**：`forward::spawn_syslog_task` 常驻订阅事件总线，
  转发 RFC 5424 行到收集器——UDP（RFC 5426）或 TCP（换行分帧），`[syslog].protocol`
  可选；PRI = facility daemon(3)×8 + 事件严重度，MSG = 事件摘要（控制字符逐个归空格，
  保证 TCP 分帧下单条报文永不拆行）；HOSTNAME 取自系统（防御性收敛为可见 ASCII）。
  配置改动下一条事件即生效；协议非法按 UDP 处理并留痕；目标不可达只丢该条
  （best-effort），绝不阻塞引擎
- **告警通知（Webhook）**：`forward::spawn_notify_task` 把达到阈值的事件 POST JSON
  （host / severity / summary / event 全量）到接收端；`SecurityEvent::severity()`
  统一严重度口径（RFC 5424 数值越小越严重：detection/封禁执行=warning，
  蜜罐命中/AI 建议=notice，例行流水=info，engine 按 level），`[notify].min_severity`
  四档过滤（error/warning/notice/info）；超时可配（1-120s），失败丢弃本条且 60s
  限频留 tracing，防目标宕机刷日志
- **暴露面定时自动扫描**：`[exposure].auto_scan_secs`（0=关闭，300-86400）；启动后
  30 秒先扫一轮（与情报任务"启动首轮"先例一致），之后按间隔复用既有 `scan_exposure`
  （快照入库 + 事件留痕 + AI `<exposure>` 上下文）
- **severity 纯函数**：`severity()` / `severity_name()` / `severity_threshold()`，
  syslog 与 webhook 共用同一"多严重"口径
- GUI 设置页三组控件：远程日志（开关/收集器地址/协议）、告警通知（开关/URL/最低严重度）、
  暴露面自动扫描（间隔），保存时校验
- 单测 4 个：RFC 5424 行快照（PRI/时间戳/字段序）、MSG 换行剥离（TCP 分帧不变量）、
  severity 映射与阈值过滤（含非法配置回退）、hostname 回退

### 变更

- 事件总线新增两个常驻消费者；转发器**只读总线不产事件**（失败只走 tracing，
  杜绝"外发失败→engine 事件→再外发"的自反馈风暴）

### 已知限制

- 外发是副本不是审计源：转发报文不携带哈希链 id/hash，完整性校验仍以
  `verify-log` / `export-events` 为准
- webhook 无重试与 HMAC 签名，按需后补
- 邮件通知与报表导出未包含（ROADMAP 已拆分为独立条目）

### 实测（WSL2 Ubuntu 24.04，2026-09-28）

- UDP/TCP 双通道 RFC 5424 收包核对（PRI=30/29/28 对应 info/notice/warning，
  HOSTNAME/PROCID/MSGID 字段正确，中文 MSG 完整）
- webhook severity 过滤：notice 阈值下蜜罐命中全量到达、手动加规则（warning）到达、
  全部事件（info 级）按预期被过滤
- 暴露面首扫 30 秒内出现（17 个监听端点），事件留痕正常

## [0.3.4] - 2026-09-28

按 ROADMAP 0.3 推进第四批：AI 深度介入 v1——处置灰度执行 + 误报反馈闭环 + 输入面扩展。

### 新增

- **处置灰度执行（playbook 语义落地）**：AI 建议应用即短 TTL 试运行——AI 明确给 `ttl_secs`（60-604800s，schema 严格校验、非法整条作废）用它的，否则配置 `[ai].trial_ttl_secs`（默认 900s）；到期由既有 TTL 清扫任务自动解封；人工"转正"延长到 `[ai].promote_ttl_secs`（默认 30 天），防火墙页灰度规则一键转正。语义分层：AI=暂时（灰度），人工转正=长期，管理员手动=随自己意；0.3.3 前的永久 AI 规则转正明确拒绝
- **误报反馈闭环**：store 新表 `fp_feedback`（value=来源 IP 聚合，count/first_ts/last_ts/note，ON CONFLICT 累加）；`mark_false_positive` 一键三联动——记录反馈（30 天抑制 `active_fp`）+ 解除该来源全部 engine/ai 自动封禁（人工手动规则不动）+ 收弃该来源 pending 建议；自动封禁（快路径 handle_detection）与自动应用（AI auto_apply）跳过抑制期来源并留痕，人工封禁不受影响；`<feedback>` 段进提示词（"用户已判定正常，无新确凿证据不要再建议封禁"）
- **AI 输入面扩展**：`<flows>` 段（采样捕获活跃时送评：流表快照 flow_count + 按纯 SYN 计数 top 5 来源——`FlowTable::top_syn_sources` 聚合、同分按 IP 字典序稳定排序；元数据与计数，无载荷）；`<self_endpoints>` 段（本产品自身 API 攻击面：端点清单 + 仅回环绑定 + Bearer token + fed 开关与鉴权现状，提示词要求评估自身暴露异常）
- **API**：`POST /api/rules/{id}/promote`（转正）、`POST /api/feedback`（误报反馈，返回解封/收弃计数）、`GET /api/feedback`（抑制期列表）
- **GUI 三页联动**：AI 页建议行"灰度应用"（toast 显示解封时间）+ "误报"；事件页 detection 行"误报"；防火墙页灰度 AI 规则"转正"按钮 + 来源列区分 AI/检测器/情报/手动
- **Console 契约扩展**：trait 新增 `promote_rule`/`mark_false_positive`，内嵌（EngineHandle 委托）与远程（HTTP → 新端点）双实现，GUI 双形态行为一致
- system prompt 更新：灰度语义（不确定→短 TTL 灰度、确凿→长 TTL）+ `<feedback>`/`<flows>`/`<self_endpoints>` 段说明；`PromptInputs` 结构化（7 段可选输入，无数据段不出现）
- 单测：ai（ttl_secs 边界校验 60-604800、非法整条作废、提示词全段包含/缺省不出现）；store（fp_feedback 聚合 upsert/active 边界/收弃计数/update_rule_expires）；detect（top_syn_sources 聚合排序截断）；engine 集成（误报抑制跳过自动封禁、转正延长 TTL）

### 变更

- `apply_proposal` 从永久规则改为灰度 TTL（0.3.3 前应用的 AI 规则保持永久，转正对其明确拒绝）
- 捕获管线 sweep 时刷新 `FlowSnapshot` 进 CaptureState（AI 分析随取随用）
- fed 共享建议复验入库带 ttl_secs（远端建议同样走灰度语义）

### 已知限制

- 误报抑制 30 天为常量（`FP_SUPPRESS_TTL_SECS`），暂不可配
- 转正 TTL 固定 `promote_ttl_secs`（默认 30 天），不支持"永久转正"（永久封禁走管理员手动添加）
- 误报反馈按来源 IP 聚合，无 per-端口/per-协议粒度

## [0.3.3] - 2026-09-28

按 ROADMAP 0.3 推进第三批：检测平台补齐 Linux 侧——AF_PACKET 采样捕获后端，
Windows/Linux 帧语义全平台对齐。

### 新增

- **Linux 采样捕获（AF_PACKET）**：`aisafeguard-detect::capture` 平台分发重构为
  `spawn(mode)` 单入口（Windows=WinDivert / Linux=AF_PACKET / 其余平台明确报暂无）——
  AF_PACKET 原始套接字（ETH_P_ALL、不 bind = 观测所有接口；**不开混杂模式**，
  只看与本机相关的流量，隐私红线 §3）；无 CAP_NET_RAW 时映射为可读错误并优雅降级
  （root / systemd 服务天然具备权限，`service install-systemd` 以 root 运行直接可用）
- **帧语义全平台对齐**：Linux 捕获线程内完成 L2→L3 剥离（`l3_payload` 纯函数，
  IPv4/IPv6 直通 + 单层 VLAN 解包）与模式预过滤（`passes_mode_filter`：control 只放
  TCP 纯 SYN、full 放全部 TCP 段——与 WinDivert 内核过滤器同语义），管线与流表
  在两个平台看到完全相同的输入
- 纯函数单测（全平台可跑）+ 5 万轮模糊测试（不变量：`l3_payload` 产出恒为输入的
  偏移 14/18 后缀切片、过滤器对任意输入不 panic）
- Linux 目标交叉类型检查通过（rustix 依赖面 + 捕获代码路径，方法见 docs/LESSONS.md）

### 变更

- engine 捕获任务改调 `capture::spawn`；GUI 设置页采集说明改为平台无关措辞，
  并修正 0.3.1 遗留的错误描述（SNIFF 模式是"仅取副本"而非"包原样注回"）
- 新依赖：`rustix 1.1`（仅 Linux 目标，`net`+`time` 特性；已在依赖树内，安全 API）

### 已知限制

- Linux 实机 E2E 未执行（本开发环境 WSL/Docker 均不可用）：清单已备好
  docs/LINUX-TESTING.md §12，待环境后执行
- rustix 1.1.5 的 `net` 特性单独启用时 linux_raw 后端缺 `timespec`（sockopt 引用），
  需同时启用 `time`——已在 workspace 依赖注释中说明

## [0.3.2] - 2026-09-28

界面外观批次：多套配色方案 + 全局字号缩放（按 ui.md 规范落地），并补齐版权信息。

### 新增

- **界面主题系统**（`gui/theme.rs`，按 ui.md §2/§3 落地，映射说明见 ui.md §8）：
  四套配色自由切换——深邃蓝（默认深色）/ 浅色办公 / 暖色护眼（低蓝光）/ 高对比（无障碍）；
  全部控件改走语义取色（Primary/Success/Warning/Error + 中性色），不再有散落的硬编码色值
- **全局字号缩放**：配置 `[ui].font_scale`（0.85–1.6），默认 **1.15 舒适档**
  （正文约 16.7px，原默认偏小）；设置页滑杆 + 紧凑/舒适/大/特大预设，即时预览
- **设置 → 界面外观**：主题卡片（含色卡预览与说明）+ 字号控制；主题/字号保存后持久化，
  重启保持；主题名非法时回退默认方案不打不开界面
- 单测：主题标识往返与非法回退、字号归一化（NaN/越界）、四套方案对比度护栏
  （正文/辅助/主色文字三组亮度差，防"看不见的字"）

### 变更

- `[ui]` 新增配置节：`theme`（deep_blue | light | warm | contrast）、`font_scale`
- GUI 配色常量（ACCENT/TEXT_DIM/BG_* 等 11 个）全部移除，改为主题语义取色函数

### 版权

- LICENSE / README / Cargo.toml authors / `--version` 输出 / GUI 设置页"关于"
  统一标注 **coolinger · vibe coding**（MIT License）

## [0.3.1] - 2026-09-28

按 ROADMAP 0.3 推进第二批：检测平台 MVP（Windows）——真实流量采样捕获 + 流重组 + 内置检测器。

### 新增

- **检测平台 MVP（Windows）**：`aisafeguard-detect` 新增四层结构——
  `capture`（WinDivert 被动采样捕获；control 模式仅抓 TCP 纯 SYN 元数据，full 模式抓全 TCP 段启用流重组取证；
  包只拷贝进有界队列、不吸收不注回（SNIFF 嗅探：内核照常转发，句柄只拿副本），捕获线程异常不影响主机网络；缺驱动/无提权/被杀软拦截都降级为可读状态与事件）、
  `flow`（5 元组流统计表：计数与元数据，容量上限 + 空闲回收，红线不存载荷）、
  `reasm`（TCP 流重组：乱序缓存、重传去重、32 位环绕感知、上限截断）、
  `inspect`（采样管线：etherparse 解析 + 端口扫描 / SYN flood 内置检测器 + full 模式载荷摘要取证）
- **快路径引擎扩展**：端口扫描 / SYN flood 检测器接入与蜜罐频次引擎同一自动封禁出口
  （Detection 事件含 rule_id：builtin.tcp_scan / builtin.syn_flood；TTL 自动解封 + 内网保护 + 全链路审计）；
  检测器映射表设容量上限，伪造源 IP 洪泛下内存有界
- **配置** `[detect.capture]`：enabled（默认关闭）/ mode（control | full）/ 扫描与 flood 阈值 / 窗口 / 流表容量；
  GUI 设置页新增采样捕获开关、模式选择与运行状态展示；`GET /api/status` 返回 capture 状态（enabled/active/backend/mode/note）
- **WinDivert 静态编入**：windivert 0.7.0-beta（`static` feature，MSVC 从 vendored 源码编译）——
  进程加载不依赖任何 DLL，仅开启捕获时才需要在 exe 旁放置官方签名 WinDivert64.sys；LGPL 合规说明见 deny.toml 与 docs/COMPLIANCE.md
- 文档：docs/WINDOWS-CAPTURE-TESTING.md（驱动获取与实机验证清单）

### 实测（Windows 11）

- 捕获降级：headless 引擎开启捕获（无 WinDivert64.sys）→ 进程正常运行，状态与事件输出
  "缺少 WinDivert64.sys 驱动文件（需与程序同目录）"，其余功能不受影响
- 检测链路：本机连接 3 个蜜罐端口 → Detection 事件（scan，含证据摘要）+
  内网保护跳过自动封禁留痕
- 封禁落地：API 添加 TEST-NET-3 地址规则 → Windows 防火墙真实生成入站阻止规则（netsh 核验）→
  API 删除 → 防火墙规则同步移除
- 单元/集成：reasm 乱序/重传/环绕/上限单测 + 2 万轮结构化模糊测试（断言重组结果恒为源序列前缀）；
  检测器窗口与冷却语义单测；engine 封禁链路 4 项集成测试（mock 防火墙：封禁+TTL 记账、内网保护零封禁、
  auto_block 关闭、空规则拒绝）
- CI 门禁：cargo test --workspace（17 个测试目标）、clippy -D warnings 全绿

### 已知限制

- WinDivert64.sys（官方签名驱动）需用户自行从官方渠道获取放入程序目录；本开发环境网络不可达官方源，
  真实驱动 E2E 按 docs/WINDOWS-CAPTURE-TESTING.md 的清单在联网环境执行
- Linux 采样捕获（nflog/afpacket）未实现：`CaptureSource` trait 已预留扩展位，Linux 上开启捕获会明确报"暂无后端"
- 捕获开关/模式修改需重启生效（与蜜罐/API 端口同一约定）

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
