# 更新日志

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [未发布]

### 新增

- **webhook 请求签名**：`[notify].sign`（默认关）开启后，事件外发附带
  `X-AISafeGuard-Timestamp` + `X-AISafeGuard-Signature: v1=<hex>`
  （HMAC-SHA256 覆盖 `"{timestamp}.{原始字节}"`，Stripe/GitHub webhook 同款语义，
  接收方同密钥重算比对 + 时间窗防重放）。密钥不入配置文件：环境变量
  `AISAFEGUARD_WEBHOOK_SECRET`（最高优先）或凭据管理器（webhook-secret）；
  开而不设密钥 = 丢弃不发送（不做静默降级）。能力边界明示：HMAC 只证明传输
  完整性，不构成可审计证据（THREAT_MODEL「证据语义」）。已知向量测试由
  python hashlib 独立预计算。净增依赖无（ring::hmac 既有栈）。

### 新增（续）

- **webhook 发送重试**：首发失败进入内存重试队列（退避 10s/30s/60s，最多 3 次重试，
  总窗 ~100s 覆盖接收端重启）；队列有界 100 条、满 = 丢新留旧（与 fed 出站队列同哲学）；
  放弃累计计数 + 周期性日志播报（「本地哈希链为真源」）；通道关闭队列作废，重启清空
  （不落盘——外发是副本）。重试发送时重打新鲜时间戳（不吃旧签名时间戳，避免被接收方
  重放窗拒收）。syslog 通道不重试（UDP 语义）。

### 新增（续二）

- **GUI 远程控制台模式**：`aisafeguard --remote <url> --token <值|文件>` ——连接任意
  节点的 API 呈现完整界面（配合 SSH 端口转发：`ssh -N -L 17420:127.0.0.1:7420 节点`，
  节点 API 永远只听本机回环、公网不可达）。仪表盘/事件/防火墙/组织面板（F500）全功能
  可用于远程节点；`RemoteConsole::with_base` 泛化（原 probe_service 本机路径复用）。
  用途：多节点运维与实验取数的图形化视图（docs/EXPERIMENT.md §3.5）。

### 新增（续三）

- **GUI 入伙向导**：组织化加入的文件传递式流程（F740）——成员「生成入伙申请」（标准
  PKCS#10 CSR，私钥本机生成永不外传）→ 协调者「处理入伙申请」（CA 签发 + 自动预登记
  指纹 + 批准包）→ 成员「导入批准包」（证书与 [fed] 配置自动写入，热生效入伙无需重启）。
  任何文件均可经任意渠道传递（不含秘密）；导入校验证书与本机申请私钥配对。API：
  `/api/fed/join/request|approve|import`。净增依赖：rfd（egui 生态标准原生文件对话框）。

### 新增（续四）

- **Web 控制台（F790）**：引擎 API 同端口直出的单文件浏览器控制台（`http://127.0.0.1:<api.port>/`，
  SSH 隧道场景即 `http://127.0.0.1:17420/`）——仪表盘（24h 命中/攻击者/引擎状态/蜜罐监听/
  Top 来源）、事件实时表（3s 轮询、点行展开载荷、类型筛选下拉）、**AI 建议页**（查看全部
  建议 + 状态筛选 + 应用/驳回，应用走既有灰度封禁语义、AI 分析理由点行展开）、
  **配置文件管理**（`GET/PUT /api/config/raw`
  读写 config.toml 原文；服务端先解析校验后写盘+热更，返回需重启项列表）。
  安全边界不变：静态壳无数据免 token，`/api/*` 仍
  Bearer；API 仍只听本机回环，跨机只能走 SSH 隧道。纯 vanilla JS 单文件内嵌（include_str!），
  零前端构建链、零外部依赖（无 CDN）。**面板可操作**（v1.1，用户反馈驱动）：蜜罐监听
  热启停按钮、AI 立即分析、情报立即刷新、暴露面立即扫描、`POST /api/service/restart`
  面板重启服务（Linux systemd `--no-block`，延迟 1s 让响应先走、审计事件留痕；Windows
  明确报错引导服务管理器）、新增防火墙页（规则来源/TTL 状态/剩余时间/原因）、Top 来源
  IP 归属查询（第三方 ip-api.com 备用 ipwho.is，仅查询攻击者 IP，结果缓存本机）。
  **磁盘覆盖优先**：`<data_dir>/web/index.html` 存在
  则覆盖内嵌版（开发/定制热改——改文件刷新浏览器即生效，无需重编译；删除即回归内嵌，
  发布仍是单二进制）。egui `--remote` 模式保留为全功能备选（规则/
  组织面板操作）。

## [0.6.0] - 2026-09-30

0.6「多机协同完全体」：回答「多台机器看到同一个攻击者时，组织比我单个人更确信」。
跨节点只同步**建议与证据**，永不直接下发处置命令——节点自治红线不变。批次 F100-F600
（docs/ROADMAP-0.6.md），集群级验收 `scripts/e2e-suite.py --cluster 3` 5/5。

### 新增

- **fed 协议 v1（F100）**：统一信封（版本/节点/序列号/时间/类型/载荷/签名）；版本协商
  （major 不同拒连 + 双方版本号 GUI 告警，minor 未知字段忽略）；消息级 ECDSA P-256 签名
  （节点证书钥，可离线验签防抵赖）；node+seq 幂等（24h seen 集合 + 持久化高水位，
  序列号回退 = 备份恢复/伪造重放 → 拒收告警）；hello 心跳兼 last_seen 与时钟对表；
  补传窗 ±1h 放宽为 24h；`fed init-ca [组织名]`
- **多机印证引擎（F200）**：四维度滑动窗（源 IP / JA3/JA4 指纹 / 凭证用户名 / 蜜饵水印
  =critical 横向线索）+ K 独立节点 + 一窗一报冷却 + 时钟降权（偏移 >5s 剔除）；
  协调者不再持久化节点事件（内存窗口 + 有界审计日志 audit.jsonl，可离线验签）；
  org-feed 广播环 + 各节点本地复验（命中提示/未命中留痕）；min_peers 门控切换数据源
- **组织建议闭环（F300）**：org-suggestion 生命周期（印证驱动/节点建议重广播 → 四关
  本地复验 → 慢路径灰度 TTL → 采纳/收弃回流，(节点,引用) 去重）；组织推荐升级
  （采纳率 ≥60% 可配 + 零误报 + ≥2 节点，一次性广播，后续建议默认严重度提高——仍是建议）；
  「组织」来源位（origin=org 可解释文案 + 规则行组织误报计数）；误报广播（share_fp 默认关）；
  AI 慢路径 `<org>` 上下文段；`/api/status` 组织指标
- **韧性（F400）**：协调者入站限频（每节点 240/分钟可配，超限降级仅心跳 5 分钟）；
  软隔离（`fed quarantine`：保留心跳与审计、断事件/建议通道；解除需指纹前缀确认；
  状态变更全组织广播）与吊销互补；出站有界队列（丢新留旧 10k + 计数告警，最旧优先取数）
- **STIX 2.1 导入导出（F310）**：四类对象冻结（identity/indicator/observed-data/sighting）+
  包信封节点证书签名；`fed audit --format stix` / `stix-import`（验签失败/缺签名/超限
  五路拒收；valid_until 到期自动失效）；**python-stix2 3.0.2 实测解析通过**；凭证永不导出、
  内网地址脱敏（自动化断言 + 集群 e2e 实测）；导入 IOC 默认只告警（事件打 ioc-hit 标签）
- **GUI 组织面板（F500）**：侧栏「⇄ 组织」页——角色头、成员表（在线/隔离/指纹）、协议
  异常计数（篡改/回退/限频/重复）、组织事件流；软隔离面板入口与 CLI 同一 DB 通路

### 变更

- `fed_members` 表新增 max_seq/status 列；org_events 新表（组织消息账本）；新增配置
  `[fed] share_fp`（默认关）/`org_adoption_percent`（默认 60）/`inbound_rate_per_min`
  （默认 240，均可热更）；内部 crate 依赖改纯 path 引用（钉版漂移根治）
- 版本协商拒绝、签名失败、隔离/限频均走事件流 GUI 可见；hello 响应携带协议计数

### 实测

- **集群 e2e 5/5**（`--cluster 3`：1 协调者 + 2 成员，证书/预登记/配置全自动编排）：
  C1 成员入伙与预登记 · C2 多机印证触发 + 内网地址建议被成员复验拒绝 · C3 软隔离
  （事件停摆且本地照常、错误指纹拒、正确指纹解除）· C4 杀协调者分区（成员本地不停摆）
  + 恢复重连续传 · C5 STIX 导出签名 → 他节点验签导入 → 回环地址脱敏实测 → 篡改包拒收
- 单机 e2e 10/10 回归；workspace 测试全绿（app 53/store 17）；clippy -D warnings 零警告；
  全仓库 `forbid(unsafe_code)` 不变；净增依赖 ring/x509-parser（均在既有树内）

### 已知限制（诚实声明）

- 备用协调者为冷备（管理员手动交接 CA，无自动主备——拍板决议，避免信任根双份暴露）；
  时钟健全性靠 hello 对表（无 NTP 查询）；证据链跨节点跳转视图与节点详情代理未做
  （需要协调者无状态代理通路）；TAXII 明确不做；建议发起方自身的本地采纳不回流
  （采纳统计只计他节点，口径保守）

## [0.5.12] - 2026-09-30

0.5.12 可用性专项与测试基建：UAC 自动提权 + 蜜罐页全量状态与就地设置 + 蜜罐热启停 + 整体功能 e2e 套件（见专项立项提交）。

### 新增

- **UAC 自动提权**：Windows GUI 未提权且未装服务时自动弹 UAC 请求管理员权限（PowerShell `Start-Process -Verb RunAs`，CREATE_NO_WINDOW 安全 API，不破 `forbid(unsafe_code)`）；同意后提权实例接管、拒绝则未提权继续（`--uac-child` 标记防循环）；已装服务场景不变（GUI 普通权限连服务，不弹）
- **蜜罐热启停**：监听器运行时启动/停止——`HoneypotHandle` 改注册表 + 每行期望状态驱动（watch + 原子镜像），热停摘下监听释放端口、热启同任务重绑（无端口竞态窗口）；`POST /api/honeypot/listeners/{name}/start|stop` + GUI 开关真·热切换（按真实 bind 态显示），端口/协议等改动仍如实标注「重启后生效」；修复全局停机路径残留僵尸「运行中」标志
- **整体功能集成测试套件 `scripts/e2e-suite.py`**：spawn 模式（临时配置拉起 `--headless` 实例）覆盖 API 基线/六协议蜜罐探测与反识别断言/蜜饵水印/凭证采集与喷洒检测/扫描爆破与内网保护/规则 CRUD/误报闭环/监听器热启停/导出与哈希链校验等阶段，退出码可接 CI；**attach 模式**直接测运行中/远程部署的实例（127.0.0.1 Bearer API，可经 SSH 隧道跨机）

### 变更

- 蜜罐页改 Grid 两列等宽卡片，未配置协议出占位卡；监听器状态以真实 bind 成功为准（配置里有 ≠ 真的在跑）；监听表/假 Shell/凭证采集/蜜饵设置进蜜罐页就地修改，与「设置→蜜罐」共用同一份草稿与保存流程
- 版本三处对齐：Cargo.toml 内部 crate 依赖改纯 path 引用（去掉漂移的 version 钉版），README 版本行更新，CHANGELOG 建档补齐

### 实测（Windows 11 本机）

- 热启停端到端（注册表状态/热停端口释放/热启重绑/幂等/未知名）+ 真机 API E2E（热停端口不可连、热启恢复、config.toml enabled 往返无损）
- e2e-suite spawn 全阶段与 attach 模式跑通；UAC 弹窗/拒绝/服务场景手工验证

## [0.5.11] - 2026-09-30

0.5.11 第三批(产品化与反识别):蜜罐模板机制 + AI 慢路径上下文增强 + 反识别加固,任务号 H300/H310/H320/H400(见 docs/ROADMAP-0.5.9.md 第三批)。

### 新增

- **蜜罐页面/协议模板(H300)**:`[honeypot.templates]` 默认关。目录约定 `<root>/<模板名>/{template.toml,page.html}`——协议/端口/页面/表单字段名/敏感路径全模板可配,有效 http 模板自动生成监听器,ssh/telnet 模板可覆盖 banner;**单模板解析失败只拒绝该模板并告警**(不影响其他模板与内置默认,整包加载哲学的单模板化),端口与已有监听器冲突拒绝;模板内容变更(mtime+长度轮询,规则引擎同款先例)约 5 秒热重载,增删模板目录需重启(轮询只告警提示);无模板目录行为与上一发布版逐字节一致(回归)。「不改一行代码,放 html + toml 即新增假 Grafana 登录页(重启生效)」;新增依赖 honeypot crate:serde/toml(已在依赖树)
- **AI 慢路径蜜罐上下文增强(H310)**:分析请求新增四个可选段(有则附带无则不阻塞)——<interactions> 中交互会话逐命令序列、<credentials> 凭证尝试(口令只以掩码出现,spray=true=与本机账号同名,pass_hash 刻意不出参)、<canary> 蜜饵水印命中、<fingerprints> JA3/JA4(l7 开启才有);建议 schema 扩展 `credential_spray` 动作(remote_ip 必填/无端口/内网来源拒绝,严格校验同 block)——登记为已确认喷洒战役进入观察,**不走防火墙、不自动应用**(AI 不自动处置红线不变),GUI「确认战役」按钮 + `/api/proposals/{id}/confirm`
- **反识别加固(H320)**:`[honeypot.fingerprint]` banner 全协议可配——SSH 版本串/Telnet 问候语/MySQL greeting 版本/HTTP Server 头,默认值与内置值逐字节一致(升级零行为变化);banner 解析顺序:模板覆盖 > 全局配置 > 内置默认;`docs/deployment.md` 新建「部署与反识别」章节(banner 选择建议/端口混布建议/演示端口不得用于生产的明示/残余风险)

### 变更

- 蜜罐会话运行时收敛为 `SessionCtx`(shell/canary/templates/指纹/凭证采集开关统一入口);`greeting_payload`/`ssh_session`/`telnet_session`/`http_session` 按指纹参数化;`proposals` 表新增 `action` 列(迁移默认 'block');净新增依赖:无(serde/toml 均已在依赖树)

### 实测(Windows 11 本机)

- 模板端到端(自动化):模板监听器对外服务自定义页面、模板敏感路径 403、模板表单字段(account/secret)进凭证采集并哈希落库、事件带 template 标签;损坏模板/端口冲突模板隔离告警
- H310 schema:credential_spray 合法解析、缺 IP/内网来源/未知动作拒绝(自动化);凭证库 recent 查询只出掩码形态(结构上无哈希出参)
- 门禁:cargo test --workspace / clippy -D warnings 全绿

### 已知限制(诚实声明):不承诺对抗主动交互式指纹探测(协议行为差异不可能归零,deployment.md 明示);模板内容热重载不覆盖监听器增删(需重启);credential_spray 的确认效果是进入 AI 观察名单而非任何网络动作;nmap -sV 验收为手工步骤(待发布验证)

## [0.5.10] - 2026-09-30

0.5.10 第二批(情报价值):凭证采集与本地喷洒检测 + Canary 蜜饵 + 可用性专项(设置页蜜罐域全量 GUI 化/示例配置/内置手册),任务号 H130/H140/H150/H200/H210(见 docs/ROADMAP-0.5.9.md 第二批)。

### 新增

- **蜜罐凭证采集与本地喷洒检测(H200)**:`[honeypot.credentials]` 默认开。SSH/Telnet/HTTP 表单/MySQL/Redis 五协议的 用户名/口令 对统一采集——口令在会话内即完成 argon2id 加盐哈希(RustCrypto 纯 Rust,参数刻意调低:被哈希的是攻击者自选口令,8MiB/2 轮防高频撞库烧 CPU),明文永不落盘、事件与 API 输出只有哈希入独立凭证库(`<数据目录>/honeypot/credentials.db`,文件 0600,不进事件表)。MySQL 握手口令为不可逆 scramble,只记用户名。本机账号快照(sysinfo 安全封装,只取用户名,forbid(unsafe_code) 不破例)与蜜罐用户名做同名比对 → **credential_spray 高严重度事件直推快路径**(自动封禁仍受内网保护与误报抑制约束);同一来源跨协议提交同一口令 → credential_reuse 聚合告警;同键 24h 节流防刷屏。
- **Canary 蜜饵(H210)**:`[honeypot.canary]` 默认关。HTTP 蜜罐内置 `/backup.zip`、`/.git/config`、`/id_rsa`、`/db.sql` 诱饵资源(合成内容,结构对齐真实文件、数据零值),内容带水印 token(`AC1.<payload>.<mac>`),下载行为本身即事件(事件带 canary 标签);`aisafeguard canary-decode <token>` 离线还原 来源节点/投放时间/资源,支撑外传溯源(密钥来源与引擎一致:配置显式 key 或自动生成的 `<数据目录>/honeypot/canary.key`);关闭状态 HTTP 响应与 0.5.8 逐字节一致(回归测试钉住)。文件系统蜜饵 v1 **仅 Linux**(notify/inotify 只读监听「文件被读取」):配置路径缺失则写入合成诱饵并监控,已存在则拒绝该条并告警(绝不覆盖真实文件);Windows 降级告警明示(用户态无「文件被读取」对等 API)。
- **蜜罐 GUI 全量可操作(H130)**:设置页蜜罐域新增假 Shell 开关(SSH/Telnet)+用户名/主机名/命令上限输入、监听表编辑器(启停/名称/协议/端口/增删行,端口范围与去重校验,mysql/redis 由此进入可见范围);`ListenerConfig` 新增 `enabled` 字段(缺省 true,旧配置零影响,roundtrip 测试钉住)。
- **示例配置 + 内置手册(H140)**:`docs/config.example.toml` 全量注释示例(每字段:人话说明+默认值+改了会怎样;默认关的段落以注释态给出,抄一行即用),CI 测试 `config_example_stays_in_sync` 防漂移(新增字段不进示例即红);`docs/MANUAL.md` 人话版集成操作手册,GUI 新增「帮助」页内嵌渲染(离线内置,零新增依赖的受控子集渲染器)。
- **GUI/配置对齐审计(H150)**:`docs/CONFIG-COVERAGE.md` 全量对账表(AppConfig 每字段 → GUI/示例/手册三态处置);蜜罐 Tab 监听卡片显示交互模式(低交互/中交互/未启用)与单监听器运行状态。
- **蜜罐界面修正**:监听卡片改 2 个一行换行布局——窄窗口下横排挤压变形的问题(用户实测反馈),极窄窗口退化为单列。

### 实测(Windows 11 本轮自动化)

- 凭证采集:五协议采集接点单测/集成测试全绿;`credential_event_row_carries_no_secret` 钉住「事件 API 无哈希无明文」;凭证库 0600 权限断言(Unix)+ 独立文件设计(Windows 权限沿用目录继承,发布包随目录 ACL)
- canary:token roundtrip/篡改拒绝/异密钥拒绝;HTTP 蜜饵下发与关闭回归;蜜饵路径冲突拒绝覆盖;Linux inotify 读取告警与 60s 去重为编译门控路径,**WSL2 实机读取告警待发布验证**
- 门禁:cargo test --workspace / clippy -D warnings / cargo audit / cargo deny check 全绿

### 变更

- `SecurityEvent` 新增 `CredentialObserved` 变体(kind=credential_observed,GUI 事件页单独配色);`HoneypotConfig` derive PartialEq;`restart_required` 契约纳入 credentials/canary 段(蜜罐监听)
- 净新增依赖:argon2 0.6(凭证哈希)、sysinfo 0.37(仅 user 特性,账号快照;Windows 内部走 NetUserEnum)、notify 8(仅 Linux 目标,文件蜜饵);audit+deny 全绿

### 已知限制(诚实声明):凭证库不做外部泄露库比对(归 0.6 情报通道);文件系统蜜饵仅 Linux,Windows 用户态无读取通知;水印 MAC 为 SHA-256 前缀构造(溯源完整性场景,非对抗性密码学);GUI 验收项(纯 GUI 开假 Shell→重启→replay)待实机操作确认

## [0.5.9] - 2026-09-30

蜜罐深化专项(0.5.9 第一批:仿真深度):SSH/Telnet 假 Shell 中交互 + MySQL/Redis 蜜罐,统一逐命令留痕,全部默认关、显式开启。任务号 H101-H120(见 docs/ROADMAP-0.5.9.md 切分决议);0.5.10(凭证采集/canary)与 0.5.11(模板/反识别)顺延。

### 新增

- **SSH 假 Shell(中交互,H103/H104)**:`[honeypot.shell]` 默认关。启用后 ssh 监听器升级:russh(ring 后端)完成真实 KEX/加密传输 → 任意凭证放行 → 白名单命令仿真(whoami/uname -a/id/pwd/ls/cat/ps/ifconfig/ip addr/netstat/wget/curl/chmod/history/exit)→ 静态假文件系统(/etc/passwd、/etc/shadow 等内置诱饵内容)→ 逐命令 `interaction` 数组进事件;组合命令(`;`/`|`/`&&`)只仿真首个、整行原样留痕;未知命令文案对齐真实 bash;命令数上限(默认 50)+ 120s 空闲超时;支持 exec(非交互单命令);host key 惰性生成持久化 `<data_dir>/honeypot/`(unix 0600),失败降级 banner 模式留事件;SSH 口令不落任何留痕(0.5.10 凭证库接管)
- **Telnet 假 Shell(H120)**:`telnet_enabled` 独立开关默认关;login/password 后复用同一命令仿真层;IAC 转义剥离(协商/子协商/字面转义);关闭时 banner 模式与 0.5.8 逐字节一致(回归测试钉住)
- **MySQL 蜜罐(H110)**:显式配置 `kind = "mysql"` 监听即开启。握手 v10 greeting(版本 8.0.36 全合成)、任意凭证放行、COM_QUERY 假响应(SELECT 空结果集/SHOW DATABASES 内置假库/其他 OK)、畸形握手回对齐真实 mysqld 的 Access denied 文案;语句逐条留痕
- **Redis 蜜罐(H110)**:`kind = "redis"` 同上。RESP 增量解析(数组式+内联式)+ PING/AUTH/INFO/CONFIG/SLAVEOF/SET/GET/KEYS/EVAL 等假响应;AUTH 口令脱敏 `***` 不落明文;复制类命令(SLAVEOF/REPLCONF/PSYNC)高价值行为逐条留痕
- **逐命令事件字段**:HoneypotHit 增 `interaction`(ShellStep 数组,serde 可选字段,不进哈希链 canonical——存量事件与链校验兼容,store 加列 + GUI 事件详情可展开交互序列)
- **交互会话独立并发上限**:交互会话独立预算(默认 8)与全局 64 分离,防长会话刷满全局额度饿死其他监听器(跨任务红线)
- **演示与验收脚本**:`scripts/demo-honeypot-deep.sh`(假 Shell + MySQL + Redis 一键演示,含事件流水与哈希链校验)、`scripts/replay-ssh-shell.py`(paramiko 回放:白名单/组合注入/未知命令/4KB 超长输入逐步断言)

### 修复(WSL 实测抓出)

- **假 Shell 会话事件丢失**:`run_stream().await` 只等到会话任务 spawn,需再 await `RunningSession` 等会话真正结束——否则事件落在空状态(0 条命令)
- **verify-log `--data-dir` 不生效**:`cmd_verify_log` 收 cfg_path 后重读配置文件,丢弃 CLI 覆盖;改收 resolved AppConfig(与 export-events 同款模式)
- **MySQL 列定义编码**:ColumnDefinition41 字符串为 lenenc 长度前缀而非 NUL 结尾——真实 mysql 8 客户端把 'd'(0x64) 当长度读爆报 2008 out of memory(MITM 抓包定位;python 协议客户端不解析列定义故自动化未暴露)
- **Linux 构建**:unix cfg 分支 OpenOptionsExt 导入缺失(Windows 编译期不可见)

### 变更

- 蜜罐 crate 模块化(H102):761 行单文件拆 facade/listener/protocol/http/redis/mysql/shell,会话出口收敛 `SessionOutcome`;安全基线断言新增「假 Shell 默认关」「telnet_enabled 默认关」「默认监听表不含 mysql/redis」;`restart_required` 契约补假 Shell 配置(需重启)
- 供应链:russh 0.63(ring 后端,显式关默认特性防 aws-lc-rs 引入 CMake/NASM 构建依赖)+ rand 0.10;cargo-deny 校准(epaint_default_fonts 字体许可 OFL-1.1/Ubuntu-font-1.0、RUSTSEC-2026-0192 ttf-parser unmaintained ignore、workspace 路径依赖显式版本)

### 实测(WSL2 Ubuntu 24.04)

- paramiko 全剧本回放 PASS(登录/白名单/组合注入/未知命令/4KB);mysql 8.0.46 CLI 实连(SHOW DATABASES 假库);redis-cli 实连(PING/SET/INFO/SLAVEOF);demo 全流程事件流水 + 哈希链 14/14
### 已知限制(诚实声明):russh 客户端自连本蜜罐存在上游通道数据兼容问题(paramiko/OpenSSH 不受影响),NEGATIVE-PATH-TESTING §6 明示

### Artifact SHA-256(与发布页同清单;构建源 = 提交 710395d,即 tag v0.5.9 所指树;仓库不存二进制,本地暂存 dist/ 已 gitignore)

- Windows x86_64(MSVC)`aisafeguard-v0.5.9-windows-x86_64.exe`(`--version` = 0.5.9,30,609,408 字节):
  `e246128501eaf30f9c5337ccfe3b93cd551dd1e2a4be3c2c79d1445b515ffca7`
- Linux x86_64(WSL2 Ubuntu 24.04 `cargo build --release`)`aisafeguard-v0.5.9-linux-x86_64`(`--version` = 0.5.9,36,186,600 字节):
  `d68c4ca2d236a446ec2787594f7cf6b6f88c63046be18c75a78fe3222cc07599`

## [0.5.8] - 2026-09-29

GUI 重设计（frontend-ui-engineering 规范落地）：排版比例体系统一、设置页分页、版本标识常驻。规范文档 ui.md 升 v1.1（§8 桌面端落地约定）。

### 变更

- **排版比例体系**：新增 `type_scale` 七级 token（DISPLAY 26 / TITLE 20 /
  SECTION 15.5 / BODY 14.5 / CAPTION 12.5 / MICRO 11.5 / MONO 13）与 8pt 间距
  系统（`space`：4/8/12/16）；此前散落各页的 `.size(10~24)` 硬编码全部
  收敛到 token（约 80 处），表格行高/表头统一 `ROW_H/HEADER_H`——字号缩放
  与层级比例全界面一致
- **设置页分页**：单页长滚动（13 个小节）改为六个功能域子页（分段导航）——
  外观 / AI 分析（含 API Key） / 检测与感知（快路径/采样/L7/规则引擎） /
  蜜罐与执行（蜜罐/XDP） / 通道与告警（API/syslog/webhook/暴露面） / 关于；
  保存栏每页一致，草稿跨子页保持，主题与字号切换即时预览不变
- **版本标识**：侧栏常驻版本徽章（主色底 `v{版本}`，一眼区分版本）；设置 →
  关于页以 DISPLAY 级版本号作主视觉，附后端 / 权限 / 运行时长 / 配置与数据
  路径 / 许可

### 验证

- `cargo test --workspace` 全绿；实机截图核验设置页（外观子页）与 AI 助手页
  的层级、间距与控件比例

### Artifact SHA-256(与发布页同清单;构建源 = 提交 1430b92,即 tag v0.5.8 所指树;仓库不存二进制,本地暂存 dist/ 已 gitignore)

- Windows x86_64(MSVC)`aisafeguard.exe`(`--version` = 0.5.8,28,136,448 字节):
  `9de10be2db94b023d0da7437b696e99864d362c67f23d89942bde632dd486795`
- Linux x86_64(WSL2 Ubuntu 24.04 `cargo build --release`)`aisafeguard.linux-x86_64`(`--version` = 0.5.8,33,748,072 字节):
  `c3105451d0f9ef8a215796169ec3ec756acdd6c8c7f27e95b897f620acb4dbb1`

## [0.5.7] - 2026-09-29

修复内嵌 GUI 模式引擎静默失效（0.2 服务化引入 EngineBundle 起的存量 bug）。

### 修复

- **内嵌 GUI 的 runtime 生命周期**：所有引擎后台任务（蜜罐监听/API 服务/事件
  入库/TTL 清扫/AI 定时分析）都跑在 `EngineBundle.rt` 上，而 GUI 组装路径在
  `assemble_engine` 返回后立即 drop 了 bundle——runtime 被中止，蜜罐端口绑定
  成功也随即消失（事件库只剩启动记录，无绑定成败留痕；GUI「监听中」来自
  配置快照，是假象）。修复：`embedded_console()` 组装时
  `std::mem::forget(bundle.rt)`（进程生命周期 = runtime 生命周期），提权内嵌
  与回退内嵌两条路径统一收敛到该函数
- **影响范围**：0.2-0.5.6 的内嵌 GUI 模式（管理员/回退）均受影响；0.5.6
  Windows exe 仅 `--headless` 可用；服务模式（引擎在服务进程）与远程控制台
  不受影响；Linux headless/WSL 演示不受影响
- **可见症状**：浏览器访问蜜罐端口无应答且无事件；GUI 蜜罐页显示监听但
  计数恒零；实时事件流停止滚动

### 验证

- GUI 启动 → netstat 8081/7420 LISTENING → 浏览器 `http://localhost:8081/admin`
  返回假登录页 → 事件库记录 honeypot_hit（含 HttpHint v2 标签）→ 「误报」
  一键闭环可用
- `cargo test --workspace` 全绿

### Artifact SHA-256(与发布页同清单;构建源 = 提交 c45d87e,即 tag v0.5.7 所指树;仓库不存二进制,本地暂存 dist/ 已 gitignore)

- Windows x86_64(MSVC)`aisafeguard.exe`(`--version` = 0.5.7,28,158,464 字节):
  `1aae4019d0b2cc478e44e809afdcc3923b4a6f2a677955f80c891dd002bf735d`
- Linux x86_64(WSL2 Ubuntu 24.04 `cargo build --release`)`aisafeguard.linux-x86_64`(`--version` = 0.5.7,33,717,864 字节):
  `0b23da3202f20b7059c89ba718cb504ee2b5434147444c3f4de8c1970b1ea9ce`

## [0.5.6] - 2026-09-29

地基版 Batch 3 + 文档收官（任务拆分见 docs/ROADMAP-0.5.3.md）：HTTP 蜜罐明显比「空端口监听」好用；仍不进行中交互。

### 新增

- **HTTP 路径诱饵（F11）**：内置一批敏感路径诱饵（`/admin`、`/.env`、
  `/wp-login.php`、`/api/login`、`/login`、`/phpmyadmin` 等，精确 + 子路径
  匹配），未命中走通用假页；SSH/Telnet 维持横幅级低交互不变
- **假登录页（F12）**：GET 登录路径下发短表单；POST 记提交（`login:post`
  标签）并返回「用户名或密码错误」页——无真实成功会话；**密码字段只记
  「出现过」**：`redact_secrets` 对 form `k=v` 与 JSON `"k":"v"` 两种形态做
  值脱敏（词边界匹配，`user_password` 命中、`bypass` 不误伤），明文不落库
- **事件结构化字段（F13）**：`HttpHint` schema v2——标签并入提示对象
  （`tags` 单一来源，`http_tags()` 委托解析结果），蜜罐与采样共用同一字段；
  HoneypotHit 事件携带 `http_hint` 入库（`GET /api/events` 可查）
- **事件 GUI 详情（F14）**：事件页「详情」按钮展开结构化卡片——
  method/path/Host/UA/标签/JA3/JA4 与截断载荷（等宽展示，2000 字符上限），
  再点收起
- **与检测/AI 衔接（F15）**：撞登录路径的蜜罐命中照走既有频次引擎与
  `recent_honeypot_hits` → AI 上下文（摘要含 `login:post` 等标签），
  未新增执行通道
- **模糊/单测（F16）**：2000 轮伪随机字节过脱敏/路由/解析零 panic（保持
  `forbid(unsafe_code)`）；HTTP 蜜罐端到端测试（假登录 GET 表单、POST 脱敏
  落库、诱饵 403、通用假页）

### 文档

- **单机 5 分钟演示（F17）**：`scripts/demo-foundation.sh`——假登录 → 诱饵
  扫描 → 可读事件 → 可解释封禁 → 一键误报闭环，无 AI 无外网
- **README「单机地基能力」小节（F18）**：可解释封禁 / 误报一键 / HTTP 诱饵
  三项收口 + 与 0.6 多机关系；蜜罐与防火墙能力描述对账到实际实现
- **已知限制（F19）**：低交互加强 ≠ 中交互蜜罐（无假 Shell/命令执行），
  非 0.6 多机

### 验证

- `cargo test --workspace` 全绿；l7 HttpHint v2 标签单测、honeypot 诱饵路由 /
  脱敏 / Content-Length / 端到端共 8 项新增
- release 双平台构建通过(Windows MSVC / WSL2 Ubuntu 24.04),产物
  `--version` = 0.5.6

### Artifact SHA-256(与发布页同清单;构建源 = 提交 98ef5d2,即 tag v0.5.6 所指树;仓库不存二进制,本地暂存 dist/ 已 gitignore)

- Windows x86_64(MSVC)`aisafeguard.exe`(`--version` = 0.5.6,28,157,952 字节):
  `f3f4b9e8e2243b8f8c43cdfa9be27cb1bae2c7eff11c7bf564c6a1204c643733`
- Linux x86_64(WSL2 Ubuntu 24.04 `cargo build --release`)`aisafeguard.linux-x86_64`(`--version` = 0.5.6,33,718,120 字节):
  `a284424a6c290a9a5c43eda012eac97a8ca42a937a650a4c069459484382e6a4`

## [0.5.5] - 2026-09-29

地基版 Batch 2（误报一键，任务拆分见 docs/ROADMAP-0.5.3.md）：用户只理解一个按钮——「这是误报」。

### 新增

- **误报一键三处入口（F7）**：事件行（检测判定 + 蜜罐命中）、防火墙规则行、
  AI 建议行均可触发同一引擎逻辑（GUI 内 `mark_fp` 统一入口，内嵌 / 远程
  控制台行为一致）；一键完成抑制 + 解除该来源 engine/ai 自动封禁 + 收弃
  pending 建议，手动规则默认不动（F6 复查通过，本批补齐入口与文案）
- **抑制时长可配（F8）**：GUI 设置页新增「误报抑制时长（天）」（1-90 天，
  建议 7～14 天）→ `[ai].fp_suppress_secs` 热更生效；默认值从 30 天调整为
  14 天（存量配置文件保持原值不受影响）；事件留痕与 toast 文案按实际配置
  生成，不再写死「30 天」
- **抑制列表增强（F9）**：AI 助手页「误报 / 白名单抑制」小节每行显示
  「抑制至 {时间}」，按钮更名「取消抑制」；`GET /api/feedback` 与
  `DELETE /api/feedback/{ip}` 原有能力不变
- **操作反馈统一（F10）**：标记误报 toast 固定为「解封 N 条自动规则、收弃
  M 条建议、至 {时间} 前不再自动封禁该来源」；失败原因原样可读

### 验证

- `cargo test --workspace` 全绿；新增 DoD 单测：抑制期内快路径跳过自动封禁，
  抑制期外恢复自动封禁资格

## [0.5.4] - 2026-09-29

地基版 Batch 1（封禁可解释，任务拆分见 docs/ROADMAP-0.5.3.md）：打开防火墙页不再像「无名 IP 黑名单」——每条规则可见谁封的、为啥封、多久解。

### 新增

- **规则展示模型统一（F1）**：GUI 防火墙页与 `GET /api/rules` 共用新投影
  `RuleExplain`（app 层 explain.rs）——`source`（来源可读文案）、
  `ttl_state`（trial/promoted/engine/manual）、`ttl_text`（固定文案 + 剩余时间）、
  `reason_summary`（一句话原因）。GUI 与远程控制台（服务模式）行为一致
- **原因摘要生成（F2）**：按来源模板产出——检测判定取引擎证据段、AI 建议取
  reason、情报取来源说明、手动取备注；控制字符清洗 + 80 字符截断（单测钉住
  「不塞原始 payload 进标题」）
- **TTL 文案固定（F3）**：试封中 / 已转正 / 自动封禁 / 手动添加四类固定文案，
  带剩余时间与「到期自动解封」标注；旧数据无来源时显示「未知 / 来源未知 / 长期」
- **「查看相关事件」（F4）**：防火墙规则行一键跳转事件页并按来源 IP 过滤；
  过滤无匹配时事件页提示「暂无关联事件」
- **rules 表新增 `promoted` 列**：转正 = TTL 延长 + 落标记（沿用一次性
  ALTER TABLE 先例，无兼容层）；「转正」按钮条件从「AI 来源且带 TTL」收紧为
  `ttl_state == trial`

### 验证

- `cargo test --workspace` 全绿（含 explain 单测：TTL 状态机 / 文案 / 摘要清洗 /
  store promoted 往返）
- 已知限制：复杂策略编辑器不在本批（规则编辑仍走 config.toml / 规则包外置）

## [0.5.3] - 2026-09-29

文档与发布收口版:无功能性代码变更(版本号除外)。先核对后写文档——0.4/0.5 全部对外声称能力与代码逐一对账。

### 新增(文档)

- **README 按 ROADMAP-0.4 D2 结构重写**:一句话定位(主机侧诱捕 + 检测 + 处置,不是 LLM 内容 Guardrail)→ 数据流图(补感知层支路)→ 适合谁 / 不适合谁 → 5 分钟上手 → **已知限制中置**。限制口径与代码对账后的新表述:深检默认全关、规则引擎默认只告警、蜜罐仅端口诱捕(文件诱捕未实现)、eBPF 流表/XDP 仅 Linux(Windows 纯用户态对等)、HTTPS 识别经 JA3/JA4 的 SNI 扩展体现(无独立 SNI 域名字段)
- **配置示例与实际配置节对齐**:`[detect.capture]` / `[detect.l7]`(enabled/ja3/ja4)/ `[detect.rules]`(enabled/path/auto_block/max_rules)/ `[xdp]`(enabled/iface/mode)——仓库**没有** `[detect.ebpf]` 节,eBPF 能力统一挂在 `[xdp]` 下,文档按实际写
- **docs/NEGATIVE-PATH-TESTING.md(可复现负路径记录)**:吊销(文件式 CRL 立即拒连)、指纹不一致(预登记不匹配 403)、内网永不自动封(五处生效点,硬编码无开关)、外发失败无自反馈风暴(转发器只读总线不产事件 + 失败丢弃 + 日志 60s 限频)、规则默认只告警——每条含机制位置 + 自动化测试证据 + 实机复现步骤
- ROADMAP-0.4 验收清单三条收口勾选(fed 负路径 / README / 回归)
- 发布完整性:tag `v0.5.3` + 发布页附 artifact SHA-256(「渠道声明 + 哈希」过渡方案,代码签名后移除)

### 验证

- `cargo test --workspace` 全绿 0 failed(Windows 11,150 个测试;Linux 侧含 XDP 实机冒烟 `xdp_attach_smoke` 的 `#[ignore]` 测试需 root 另行执行)
- 能力核对结论(9 项):detect.l7 / detect.rules / XDP 流表 / 内网硬过滤 / 吊销与指纹 TOFU / 通知失败限频 / 端口蜜罐 / 首运行生成配置 均为真实实现且有测试;文件诱捕未实现(文档已如实标注)

### Artifact SHA-256(与发布页同清单)

- Windows x86_64(MSVC)`aisafeguard.exe`(`--version` = 0.5.3):
  `99a2c619c0c61575d834eaba596d81507c5abf6186e801f4cfefb62425edf31a`
- Linux x86_64:发布页构建后附上(WSL2 `cargo build --release` 即得,哈希以发布页为准;仓库不存二进制)

## [0.5.2] - 2026-09-29

0.5 规划收官：stretch 四件套按 ROADMAP-0.5 原文的交付形态完成（设计/计划/差异表，无生产代码，不进默认安装/构建链/CI）。

### 新增（文档）

- **G5 AF_XDP 深检设计 + 生产化清单**（NGFW_EVOLUTION §9.1）：采集源扩展为
  windivert/af_packet/af_xdp 三后端（帧语义对齐、上层零改动）、与执行层 XDP 程序
  共用 attach 位（redirect 样本即镜像）、旁路纪律与隐私红线不变；zero-copy 驱动
  依赖/ring 丢帧计数/内核门槛等风险 + 五项生产化清单
- **H3 WFP callout 感知 POC 计划**（§9.2）：ALE_FLOW_ESTABLISHED classify 上送
  五元组（只元数据不带载荷），用户态喂流表照走事件总线；EWDK/测试签名/HVCI/WHQL
  清单；验收标准 = 流表计数与 WinDivert control 一致 + 退出反注册零泄漏
- **H4 eBPF-for-windows 实验轨文档包**（§9.3）：大字警告不进默认安装；维持实验轨
  三理由（hook 窄/部署成本/等价能力已在手）+ 三条重评估触发条件
- **JA4 差异表**（§9.4，E5 验收的"差异表"项）：实现 vs FoxIO 官方逐维度对照——
  分片 ClientHello → None（漏报不误报）、恒 "t"（无 QUIC/DTLS）、
  未做官方二进制对拍（列为后续动作）

## [0.5.1] - 2026-09-29

按 ROADMAP-0.5 Batch G 完成 Linux 高速路径（G5 AF_XDP 维持 stretch）。

### 新增

- **eBPF 内核流表（G1）**：XDP 程序新增 `FLOWS` LRU map（65536 上限）——
  入站源三元组 → 包计数，只存元数据无载荷（隐私红线同用户态流表）；
  `DROP_TOTAL` 单槽计数器一次读得丢弃总数；BLOCKLIST value 语义升级为
  按源丢弃计数（内核侧递增）
- **drop 计数 / via=xdp 标签 / 一键清空（G3）**：`/api/status` 与 GUI 设置页
  暴露 `xdp { active, iface, mode, mirrored, drops_total, flows }`；自动封禁命中
  可镜像规则时事件留痕 `via=xdp`；`POST /api/xdp/clear` 与 GUI 按钮一键清空
  map（封禁镜像 + 流表），清空后语义回落 nftables
- **内网硬过滤（G2）**：`mirrorable` 拒绝回环/内网/链路本地/多播/未指定地址
  进入 XDP 快速丢弃表（负路径测试钉住）——误配置不能经内核直丢放大成全内网
  断网；nftables 兜底层语义不变；TTL 一致性由 janitor remove→map 同步保证
- **发行版/安全启动矩阵文档（G6）**：NGFW_EVOLUTION §8——WSL2 Ubuntu 24.04
  实测、Ubuntu 22.04+ 预期、Secure Boot lockdown 失败模式（全部失败路径 =
  纯 nftables 继续工作）

### 修复

- `tests/embedded.rs` 借用错误（0.3.7 起从未在 Linux 编译通过）：include_bytes
  1 字节对齐需堆拷贝再 load（产品路径一致）；WSL2 实机冒烟
  `xdp_attach_smoke`（root，附加→统计→清空→卸载）首次真正运行并通过

## [0.5.0] - 2026-09-29

按 ROADMAP-0.5 完成 Batch E（解析与 L7 复用）+ Batch F（规则子集引擎）+
Batch H（Windows 对等与产品化收口）P0 全部与 P1（E5 JA4 / F7 示范包 / H7 GUI）。
Batch G（Linux eBPF 流表 + XDP map 联动）按发版建议归 0.5.1。

### 修复

- **Windows release 构建爆栈（0.3.1 引入，用户实测暴露）**：`service install`
  等多数命令报 `thread 'main' has overflowed its stack`。根因 = windivert.c
  静态编入时其全局 `memcpy`/`memset` 定义（`#pragma function`）劫持了整个
  进程的 CRT intrinsic，堆初始化被污染。修法 = `[patch.crates-io]` 指向
  仓库内 fork（third_party/windivert-sys）去掉该段劫持；static 特性保留
  （分发语义不变：仅需 WinDivert64.sys 放 exe 目录）。git 二分 + stub
  实验定位，详见 docs/LESSONS.md 第八批
- 同步修复：dirs 调用点曾疑似崩溃点（误），恢复原实现；未上线的 env-var
  实验代码移除

### 新增

- **统一事件字段（E6）**：`SecurityEvent::Detection` 新增 `http_hint`
  （HttpHint JSON）与 `tls_fingerprint`（JA3 md5）可选字段——capture full
  模式命中时从重组流前缀解析填充；events 表加 `http_hint`/`tls_fp` 列
  （ALTER 兼容），EventRow 与 `/api/events`、导出 JSONL、AI 提示词 events
  段自动携带；蜜罐入口的 hint 继续以 [L7] 后缀在 summary 中
- **JA3 客户端指纹（E4）**：`aisafeguard_l7::parse_ja3`——TLS record →
  ClientHello 解析（版本/密码套件/扩展列表/supported_groups/ec_point_formats），
  产出标准 JA3 raw 与 md5（md-5 crate）；非 TLS/截断/ServerHello 返回 None
  不阻断；已知向量测试（手工构造 ClientHello → raw `771,47,10-11,29,0` +
  md5 精确断言）；模糊语义同 parse_http_hint
- **规则子集规范一页纸（F1）**：`docs/RULESET_SUBSET.md` v1 冻结——白名单
  关键字（alert/content/nocase/有限 pcre/flow/threshold/sid/msg/classtype）、
  classtype→severity 映射表、加载治理（整包拒绝/max_rules/文件哈希）、匹配
  语义与 v1 边界重申；超集关键字加载失败不半生效
- **新 crate `aisafeguard-l7`（E1）**：HTTP 解析从蜜罐 crate 抽取为独立基座——
  蜜罐与采样 full 模式共用同一解析；`HttpHint` 版本化 schema（E2，
  schema_version=1：method/path 前缀/host/UA/可疑 UA）；`sanitize` /
  `request_summary` / `http_request_complete` 迁入；不依赖 firewall（依赖图
  禁止规则/解析侧触达执行器）；蜜罐与 capture evidence 的 [L7] 标签改走新
  crate（E3：0.4 标签格式原样保留）；确定性模糊测试（2 万轮不 panic +
  path 上限断言）+ 原有测试迁移
- **新 crate `aisafeguard-rules`（F2/F5/F3）**：Suricata/ET 风格规则子集
  解析 → IR → 匹配，规范依据 F1 冻结版——头部（tcp/udp、`$HOME_NET`/
  `$EXTERNAL_NET`/CIDR/端口列表/`<>`）、content（`|hex|`、nocase、
  offset/depth/distance/within，顺序 AND 允许间隔）、pcre（标志白名单 i/R，
  rust regex 线性时间编译免疫灾难回溯 + 4KB 大小上限）、flow/threshold
  （limit|both, by_src）；头部随载荷方向对齐（`->` 规则 from_server 包源
  是 server）。加载治理：**任何一条越界/语法错/重复 sid → 整包拒绝不半生效**，
  文件 ≤5MB、max_rules、单 content ≤512B、SHA-256 留痕；crate 禁止依赖
  firewall（只产判定）
- **规则引擎接线与处置解耦（F4/F6）**：`[detect.rules]`（enabled/path/
  auto_block/max_rules，默认全关，热更）；`spawn_rules_task` 启动加载 +
  文件签名变化整包热重载、原子替换，失败保持旧包生效并留事件；蜜罐路径
  payload 全窗 + 采样 full 模式重组流前缀两条命中路径，命中 →
  `Detection(kind=signature, rule_id=sid:n, severity=classtype 映射)`
  （Detection 事件新增 `severity` 字段，内置检测器归 medium）；是否自动封禁
  由调用方决定——规则默认只告警，显式 `auto_block` 才走封禁出口（内网保护/
  误报抑制照常）；threshold 判定器 + 采样流级去重（同流 10 分钟只报一次）
- **示范规则包（F7）**：`crates/aisafeguard-rules/demo.rules` 16 条自写
  （扫描器 UA/路径探测/Shellshock/Log4Shell/SQLi/SSH-Telnet 交互/from_server
  泄露外传，sid 示范段 1000001-1999999），全部落在 v1 白名单内；集成测试
  覆盖整包加载、典型命中、锚定、限频、方向门控与误报负路径
- **JA4 客户端指纹（E5）**：`aisafeguard_l7::parse_ja4` 对齐 FoxIO 官方
  python 实现——版本映射（TLS1.2→12/1.3→13）、GREASE 剔除、SNI/ALPN 不进
  扩展哈希、签名算法原序缀尾、sha256 截断 12 字符、ALPN 首尾字符
  （http/1.1→h1）；已知向量 ×2 + 模糊测试；`[detect.l7].ja4` 开启时事件携带
  `tls_ja4`（events 表加列，幂等 ALTER）
- **配置与可观测（H5/H6）**：`[detect.l7]`（enabled/ja3/ja4，E6 结构化字段
  按开关门控，深检默认 off）；`/api/status` 与 GUI 暴露 rules（enabled/
  loaded/条数/SHA-256 前 16 位/加载说明/命中数）与 fingerprint_24h
  （Detection 携带 JA3 占比统计）
- **GUI 设置页最小暴露（H7）**：L7 与规则引擎开关 + 规则包路径 + 命中计数
  只读——0.5 不做规则编辑器，规则文件外置维护
- **文档收口（H1/H2）**：NGFW_EVOLUTION §7「0.5.0 感知层落地对账」——
  Windows 与 Linux 跑同一规则 IR/L7 解析（纯用户态 crate，行为一致是构造性
  的），Windows 演示零 eBPF 步骤；采样策略维持 0.4 决策（WinDivert 默认 +
  降级留痕），WFP callout 维持 0.5.2 stretch

## [0.4.0] - 2026-09-29

按 ROADMAP-0.4 Batch A（装得上、跑得稳）完成第一批：配置热更新契约、
服务化权限收口、交付完整性校验、AI 定时分析接线。

### 新增

- **协同审计导出（C4）**：`aisafeguard fed audit <out.json>`——成员表
  （节点/指纹/last_seen）、吊销表、近期协同事件样例（fed: 前缀），JSON 落盘；
  拒绝事件（指纹不符/吊销）在 0.4.0 起全部走事件总线留痕，可经 export-events 全量导出
- **quorum 约束自动应用（C3）**：`[fed].min_peers`（默认 0 = 不启用）——>0 时，
  某来源若有协同节点上报但**独立节点数 < min_peers**，其 AI 建议不自动应用
  （降级为慢路径人工确认）；该来源无任何协同上报时按本地策略照常（单节点
  部署不假死）；store 按事件 listener 前缀 `fed:` 去重节点数
- **证书吊销 + 预登记（C1/C2）+ 绑定建议（C5）**：`fed revoke <节点名|指纹>`（文件式
  CRL `fed/revoked.json`，协调者每次连接检查、命中拒连并留审计事件，立即生效不依赖
  证书有效期）；`fed expect <node> <指纹>` 预登记（关闭 TOFU 抢注窗口，预登记后
  非匹配指纹的首次绑定也拒）；监听公网/所有地址时启动告警（协同面建议绑内网）；
  README 新增组织协同运维（加入流程/换证流程/监听建议）
- **轻量 L7 标签（B2）**：`aisafeguard_core::l7::http_tags`——HTTP 请求行方法
  （白名单）、path 前 2 段前缀（去查询串）、可疑 UA（sqlmap/nikto/nmap 等
  克制名单）三类标签，解析失败返回空绝不 panic（2 万轮确定性模糊测试钉住）；
  蜜罐 HTTP 会话 summary 追加 ` [L7 …]` 后缀（进事件与 AI 提示词 events 段）；
  捕获 full 模式检测证据同步追加。定位是标签不是完整指纹/语义解析（0.5）
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
