# AI-SafeGuard

**主机侧诱捕 + 检测 + 处置工具**——蜜罐诱捕 → 事件流水线 → 快路径频次检测 / 规则与指纹感知 / AI 慢路径分析 → 防火墙处置,单二进制,Windows + Linux。

> **这不是 LLM 内容审核/Guardrail 产品**。AI 在这里只做一件事:把蜜罐与真实流量观测到的攻击证据读给 LLM,产出**严格校验的封禁建议**(默认人工确认)。检测与处置不依赖 AI——关掉 AI,快路径全功能照常。
>
> 当前版本 **0.8.1**。架构与设计:[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · 路线图:[docs/ROADMAP.md](docs/ROADMAP.md) + [ROADMAP-0.5.md](docs/ROADMAP-0.5.md) + [ROADMAP-0.5.3.md](docs/ROADMAP-0.5.3.md) + [ROADMAP-0.6.md](docs/ROADMAP-0.6.md) + [ROADMAP-0.7.md](docs/ROADMAP-0.7.md) · 威胁模型:[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · ISO 27001 对照:[docs/COMPLIANCE.md](docs/COMPLIANCE.md) · NGFW/协同演进:[docs/NGFW_EVOLUTION.md](docs/NGFW_EVOLUTION.md)

```
 蜜罐(诱捕) ────────┐
 真实流量采样 ──────┤▶ 事件总线 ─▶ 快路径(频次/扫描/洪水/情报, 自动+TTL)
 威胁情报 ──────────┘      │        ├▶ 感知层(full 模式: HttpHint / JA3 / JA4 / 规则子集)
                          │        └▶ 慢路径(AI 分析, 默认人工)
                          ▼
              防火墙执行器(COM/WFP · nftables+XDP) ─▶ 全链路审计(哈希链)
```

## 适合谁 / 不适合谁

**适合**:有公网或内网暴露面的 Linux/Windows 服务器与工作站;想要"蜜罐诱捕 + 自动处置 + 可审计"而不想装全家桶的运维;研究蜜罐与 AI 处置联动的个人。
**不适合**:期望企业多租户管控、完整 NGFW/IPS、EDR 级内存/进程防护的团队(见[威胁模型](docs/THREAT_MODEL.md)的非目标清单)。

## 0.8 亮点(0.7-0.8 周期,全量见 [CHANGELOG](CHANGELOG.md) 与 [ROADMAP-0.7](docs/ROADMAP-0.7.md))

- **IPv6 攻击面全覆盖**:蜜罐监听器双栈(v6+v4-mapped 归一化)、XDP 增 v6 封禁镜像
  (BLOCKLIST_V6,保护段 v6 照旧硬过滤)、`builtin.sctp_uaf` 检测器(单包捆绑
  [ERROR(Stale Cookie)]+[DATA] = CVE-2026-98548 同类内核 UAF 的利用特征,自动进累进阶梯)
- **检测漏斗收口**:检测/建议/镜像计数按 kind 与来源全量入库可查;防火墙封禁累进
  升级阶梯(1h→24h→7d→31d→6month→1year,误报反馈清零计数);AI 自动封禁口径拆分
  (快路径/AI 分列计数)
- **全链安全审计加固**:六阶段深度审计 + 45 评委启发式交叉验证,18+ 项真实发现修复
  (事件哈希链补齐 5 列证据、建议入库列失配修复、SNI 默认值换冷门真实站、
  面板仅回环强化、访问日志与 limitIp=3、后量子签名 ML-DSA-65 可选启用、
  口令证据口径裁定等)
- **三通道部署架构**(实战检验):ws-CDN 隧道线(源站 IP 对 DNS 隐形)/ hy2 UDP 快线 /
  reality 直连观察位——任一通道被封,切换成本趋近于零

## 一键部署(0.8 新增)

**新机从零到运行**(Ubuntu 22.04+/x86_64,root;下载 CI 预构建二进制,目标机零编译):

```bash
bash <(curl -fsSL https://gitee.com/coolinger/ai-safe-guard/raw/main/scripts/install.sh)
```

下载双源:Gitee Release 优先(国内直连稳),GitHub Releases 兜底;两源由
`scripts/gitee-release.sh` 保持同步(需 `GITEE_TOKEN`,见脚本头注释)。

**Windows**:从 [Releases](https://github.com/coolinger2019-wq/AI-SafeGuard/releases/latest) 下载
`aisafeguard-windows-x64.zip`,用同名 `.sha256` 校验后解压,管理员运行 `aisafeguard.exe`(或 `service install` 注册服务;采样捕获需 [WinDivert64.sys](docs/WINDOWS-CAPTURE-TESTING.md))。

**已有节点升级**(仓库根目录;VPS 侧直连 GitHub Releases 下载+校验+换装+健康检查):

```bash
bash scripts/deploy.sh
```

二进制由 CI(Actions)在 tag 推送时构建并附 SHA-256;eBPF 对象从源码可复现构建
(llvm-19 + nightly + bpf-linker),产物入库带哈希伴生。

## 5 分钟上手

**Linux/WSL**(root):

```bash
cargo build --release
sudo env AISAFEGUARD_AI_KEY=<可选> ./target/release/aisafeguard --headless
# 另开终端:连 3 个蜜罐端口 → detection 事件 + 自动封禁
for p in 2222 8081 2323; do timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$p"; done
curl -s -H "Authorization: Bearer $(sudo cat /root/.local/share/aisafeguard/api-token)" \
  "http://127.0.0.1:7420/api/events?limit=5"
sudo bash scripts/demo-attack.sh   # 或一键演示(含自动封禁与哈希链校验)
```

**Windows**(管理员):`target\release\aisafeguard.exe`;服务化 `service install`(非管理员 GUI 自动经本地 API 读数据;服务/交互模式凭据路径差异见下文)。采样捕获需 [WinDivert64.sys](docs/WINDOWS-CAPTURE-TESTING.md)(官方渠道获取,支持哈希校验)。

**整体功能集成测试**:`python scripts/e2e-suite.py`——对真实运行的引擎做 11 阶段全链路验证(API 基线/六协议抓捕/蜜饵水印/凭证喷洒/频次检测与内网保护/规则 CRUD/误报闭环/监听器热启停/SSH 假 Shell/暴露面/导出与哈希链),纯标准库、双平台、退出码可接 CI;未提权环境自动跳过防火墙写阶段,`--port-base` 可与本机运行中实例共存。 attach 模式测真实部署:`python scripts/e2e-suite.py --attach http://127.0.0.1:7420 --token <TOKEN>`(不启引擎,按实例实际配置自适应;跨机先 SSH 隧道映射 API 再加 `--host <远端IP>`)。

配置参考 [docs/config.example.toml](docs/config.example.toml)(每项带注释,CI 测试防漂移);首次运行自动生成默认 `config.toml`。人话版集成操作手册:[docs/MANUAL.md](docs/MANUAL.md)(GUI「帮助」页内嵌,离线可看)。负路径行为(吊销、指纹不一致、内网保护、外发失败)的可复现实测记录:[docs/NEGATIVE-PATH-TESTING.md](docs/NEGATIVE-PATH-TESTING.md)。

## 已知限制(重要的放这里,不藏文末)

- **检测范围是主机侧**:封禁规则为 IP 粒度(可选端口);不是网关型 IPS,看不到不经本机的流量
- **Suricata/ET 规则为受限子集**(content/pcre/flow/threshold,范围冻结见 [RULESET_SUBSET.md](docs/RULESET_SUBSET.md)),非完整 Suricata 兼容
- **深检默认全关**:`[detect.capture]`、`[detect.l7]`、`[detect.rules]`、`[xdp]` 默认 enabled=false,需显式开启
- **规则引擎默认只告警**:命中只产事件,自动封禁需显式 `auto_block = true`(仍受内网保护约束)
- **蜜罐中交互默认关**:`[honeypot.shell]`(SSH 假 Shell)与 `telnet_enabled`(Telnet 假 Shell)默认 enabled=false,显式开启;MySQL/Redis 蜜罐默认不在监听表,显式配置 kind 即开启(GUI 监听表可加);蜜饵 canary 默认关(`[honeypot.canary]`:HTTP 内置诱饵资源 + Linux 文件蜜饵,Windows 文件蜜饵降级不启用)
- **假 Shell 是仿真不是真机**:白名单命令 + 静态假文件系统,永不 fork 真实进程;反识别只做成本可接受的混淆(banner/版本可配 + 模板,见 [deployment.md](docs/deployment.md)),不承诺对抗主动交互式指纹探测;russh 客户端自连存在上游兼容问题(paramiko/OpenSSH 不受影响,[NEGATIVE-PATH §6](docs/NEGATIVE-PATH-TESTING.md))
- **eBPF 流表/XDP 仅 Linux**;Windows 无 eBPF 依赖,能力对等由用户态实现(纯用户态,行为构造性一致)
- AI 是概率性的:默认人工确认;自动应用 = 可选开关 + 严重度阈值 + 灰度 TTL(到期自动解封)
- 内网/回环地址永不自动封(硬编码,手动封不禁);误报抑制期内自动封禁跳过
- nftables 集合/规则易失,依赖启动 resync 重灌;Windows COM 规则跨重启持久
- 事件外发是副本不是审计源(完整性以本地哈希链为准);webhook 无重试与签名,失败丢弃本条 + 日志 60s 限频(不积压不重发)
- ISO 27001 对照是自查表不是认证;发布物暂未代码签名(发布页公布 SHA-256,见 [SECURITY.md](SECURITY.md))
- 采样捕获 Windows 需管理员/服务模式 + WinDivert64.sys,Linux 需 CAP_NET_RAW;缺权限只降级不报错

## 当前能力

- **蜜罐**:六种协议——SSH/HTTP/Telnet/通用 低交互(HTTP 假登录页 + 敏感路径诱饵,POST 密码字段脱敏)+ **SSH 假 Shell 中交互**(`[honeypot.shell]` 默认关:任意凭证放行 → 白名单命令仿真(whoami/uname/ls/cat/ps/netstat/wget 等)→ 静态假文件系统 → 逐命令 interaction 留痕)+ **Telnet 假 Shell**(独立开关)+ **MySQL/Redis 蜜罐**(显式配置监听即开启:握手采集、SELECT 空结果集/SHOW 假数据、RESP 假响应、AUTH 口令脱敏);交互会话独立并发上限(8)防资源耗尽;GUI 事件详情可展开交互序列;**凭证采集与喷洒检测**(`[honeypot.credentials]` 默认开:五协议用户名/口令对 argon2id 加盐哈希入独立凭证库(0600),口令明文永不落盘;与本机账号同名比对 → credential_spray 高严重度事件,跨协议同口令 → credential_reuse 聚合告警);**蜜饵 canary**(`[honeypot.canary]` 默认关:HTTP 诱饵资源带水印 token,`aisafeguard canary-decode <token>` 离线溯源;Linux 文件蜜饵读取即告警);**GUI 监听表编辑器 + 假 Shell 开关**(设置页直接操作,监听器卡片显示交互模式);**蜜罐模板**(`[honeypot.templates]` 默认关:模板目录放 html+toml 即新增假业务监听器,单模板损坏只拒绝该模板,内容热重载);**反识别参数**(`[honeypot.fingerprint]`:SSH 版本串/Telnet 问候语/MySQL 版本/HTTP Server 头全协议可配,默认值=内置值零行为变化);**AI 慢路径蜜罐上下文**(假 Shell 逐命令/掩码凭证+喷洒命中/蜜饵命中/JA3-JA4 指纹进 AI 请求;建议 schema 新增 credential_spray 观察类动作,仅人工确认,不自动处置)
- **快路径检测**:频次引擎(扫描/暴破)+ 采样捕获检测器(端口扫描/SYN flood),触发即自动封禁——TTL 到期自动解封,内网/回环永不自动封
- **流量采样捕获**(默认关闭):WinDivert(Windows)/ AF_PACKET(Linux)被动采样只取副本,control 只看 SYN 元数据、full 带流重组取证(载荷仅可疑时截断留存);可选驱动哈希校验;[Windows 实机验证](docs/WINDOWS-CAPTURE-TESTING.md) / [Linux](docs/LINUX-TESTING.md)
- **L7 解析与指纹**(`[detect.l7]`,默认关闭):HttpHint(method/path/UA,蜜罐与采样共用同一解析)+ JA3/JA4 客户端指纹(JA4 对齐 FoxIO 官方算法),full 模式重组流前缀解析,字段随 Detection 事件入库;HTTPS 站点经由 JA3/JA4 的 SNI 扩展体现,无独立 SNI 域名字段
- **规则子集引擎**(`[detect.rules]`,默认关闭):Suricata/ET 书写风格受限子集,整包加载治理(越界即整包拒绝),双平台同一用户态引擎;含 16 条自写示范包(`crates/aisafeguard-rules/demo.rules`)
- **XDP 快速执行层**(`[xdp]`,Linux,默认关闭):IP 级入站封禁镜像进 eBPF map,内核直丢微秒级生效;eBPF 内核流表(FLOWS LRU map + DROP_TOTAL 丢弃计数);nftables 永远兜底,附加失败自动降级;eBPF 程序内嵌主程序;内网地址永进不了快速丢弃表
- **防火墙**:Windows COM/WFP 规则;Linux nftables 集合(IP 级 + 端口级拼接集合);只管理自己创建的 `aisafeguard-blk-*` 规则;规则可解释——GUI 与 `GET /api/rules` 暴露来源(手动/检测引擎/AI/情报)、一句话原因、TTL 固定文案(试封中/已转正/自动封禁/手动),规则行可跳转相关事件
- **AI 助手**(慢路径):OpenAI 兼容端点(默认 GLM,内网可指向本地推理),严格 schema 校验的封禁建议;灰度 TTL → 人工转正;误报一键闭环——事件行/规则行/建议行三处入口,一键完成抑制 + 解除自动封禁 + 收弃建议,抑制列表可查可取消(时长可配,默认 14 天)
- **价值指标**:24h/7d 建议数、采纳率、误报率、自动封禁数(GUI + `/api/status`)
- **完整性**:事件哈希链 + `verify-log` 离线校验 + 结构化模糊测试护栏
- **事件外发**:syslog(RFC 5424 UDP/TCP)+ webhook 告警(severity 口径统一),best-effort 不阻塞引擎
- **组织协同**:mTLS 每节点证书 + 指纹绑定/预登记/吊销;事件上报、情报同步、建议推送(本地复验、仅慢路径);quorum 可选;`fed audit` 审计导出
- **暴露面盘点**:监听端口/进程枚举 → 快照入库 → AI 评估
- **GUI**(egui):仪表盘/事件/防火墙/蜜罐/AI/设置;主题与字号可调;热更项与需重启项明确标注

## 单机地基能力(0.5.4-0.5.6,多机前收口)

单机先够用——能抓、能看懂、误报不折腾(任务书:[docs/ROADMAP-0.5.3.md](docs/ROADMAP-0.5.3.md)):

1. **看得懂「谁、碰了啥」**:扫一下/打开假登录页 → 事件含 method/path/UA/标签,GUI 事件详情给结构化字段与截断载荷
2. **看得懂「谁、为啥封、多久解」**:防火墙页每条规则可见来源、原因摘要、TTL 文案;从规则一键跳转相关事件
3. **误报不折腾**:三处「误报」按钮同一逻辑——写入抑制(默认 14 天,可配 1-90 天)+ 解除该来源自动封禁(手动规则不动)+ 收弃 pending 建议;抑制列表可查、可取消

与 0.6 的关系:本批是**单机体验收口**,为多台打底——干净事件与可解释封禁是跨节点印证的输入;多机印证/选举/STIX 与「组织」来源位留给 0.6,不在本批实现。一键演示:`sudo bash scripts/demo-foundation.sh`。

## 最小配置

```toml
[ai]
enabled = false            # 无 AI 也能跑完整快路径;开启后填 Key 或环境变量

[detect.capture]
enabled = false            # 采样捕获(需提权;默认关闭)

[syslog]
enabled = false            # 事件外发 syslog/webhook(默认关闭)
```

开启 0.5 感知层(按需,全部默认关):

```toml
[detect.l7]                # HttpHint + JA3/JA4 指纹(需 capture full 模式)
enabled = true
ja3 = true
ja4 = true                 # JA4 默认关

[detect.rules]             # 规则子集引擎:默认只告警
enabled = true
path = "rules/demo.rules"  # 本地规则包(单文件)
auto_block = false         # 显式开启才自动封禁(内网保护仍然生效)

[xdp]                      # Linux 快速执行层(需重启;Windows 上自动不可用)
enabled = true
iface = "eth0"
mode = "native"            # skb | native
```

全部配置见首次运行生成的 `config.toml`(每项带注释);**热更项保存即生效,需重启项保存时会明确列出**(分界契约 `AppConfig::restart_required`)。

## 架构一句话

**传感器与执行器分离**:`Firewall` trait 永远窄口(封禁/解封),所有检测能力落 `aisafeguard-detect` 等传感器 crate 经事件总线接入;**跨节点同步建议而非命令**;全仓库 `forbid(unsafe_code)`。

## 服务模式(Windows)与凭据路径

Windows 服务(`service install`,LocalSystem)与普通 GUI 进程的**凭据存放位置不同**(凭据管理器按用户隔离):

| 凭据 | 服务模式 | 交互(内嵌/远程 GUI)模式 |
|------|----------|--------------------------|
| API token | `%PROGRAMDATA%\aisafeguard\api-token`(本机用户可读) | 凭据管理器 `AISafeGuard/api-token` |
| AI Key | **环境变量 `AISAFEGUARD_AI_KEY`**(服务账户读不到用户存的 Key) | 凭据管理器 `AISafeGuard/ai-key`,或环境变量 |

**服务模式下请用系统环境变量配置 AI Key**。Linux 服务同理(unit `Environment=`)。

### 升级(Windows 服务)

GUI 是普通权限进程:检测到已安装的 `aisafeguard` 服务时会自动进入**远程控制台模式**连接它
(控制台窗口里的"远程控制台模式:已连接 AI-SafeGuard 服务")。因此只替换 exe 不够——服务
进程还跑着旧二进制。升级步骤(管理员):

```bat
aisafeguard service stop
:: 用新版 aisafeguard.exe 覆盖原路径；若换目录则先 service uninstall 再在新目录 service install
aisafeguard service start
```

客户端与服务端版本不一致时,侧栏会显示「版本不一致」并提示此流程。

### 组织协同运维(协调者侧)

```bash
aisafeguard fed init-ca                            # 组织 CA(一次性)
aisafeguard fed issue-cert coord1 --san 10.0.0.1   # 协调者证书(SAN = 对外地址)
aisafeguard fed issue-cert agent1                  # 成员证书(分发到节点)
aisafeguard fed expect agent1 <指纹>                # 预登记(关闭抢注窗口)
aisafeguard fed revoke <节点名|指纹> [原因]           # 吊销(立即拒连)
aisafeguard fed audit <out.json>                   # 审计导出
```

推荐加入流程:签发 → 预登记 → 分发 → 上线(指纹不符即拒)。换证 = 吊销旧证 → 签发新证 → 更新预登记 → 删 `fed_members` 旧指纹 → 分发。协同面建议绑内网地址(绑公网会启动告警)。

## 路线图

0.3 / 0.4 全部完成(检测平台 + AI 深度介入 + 事件外发 + 组织协同 mTLS + XDP;工程与安全收口)。**0.5 = NGFW 感知层(已完成)**:0.5.0 L7 复用(HttpHint/JA3/JA4)+ Suricata/ET 风格规则子集引擎 + Windows 能力对等(纯用户态,零 eBPF 依赖);0.5.1 Linux eBPF 流表 + XDP map 联动(Batch G);0.5.2 stretch 收官(AF_XDP 设计 / WFP callout POC 计划 / eBPF-for-windows 实验轨 / JA4 差异表)。**0.5.4-0.5.6 = 单机地基版(已完成,见上文「单机地基能力」)**;0.6 = 多机协同完全体。**0.7-0.8 = 攻击面深捕与自审闭环(已完成)**:粘性缓冲区规则语义、MCP 蜜罐深化、AI 协议模板、检测漏斗收口、累进阶梯、全链安全审计加固、IPv6 三连(F806/F807/F808)、三通道部署架构。总览:[docs/ROADMAP.md](docs/ROADMAP.md)。

## 安全披露

[SECURITY.md](SECURITY.md):披露渠道、响应时限、支持版本、发布完整性说明(SHA-256 清单见发布页)。MIT License,© 2026 coolinger · vibe coding。

## 组织协同运维（0.6）

多台机器组成一个防御组织：**多机印证**（同一攻击者被 ≥2 节点独立观测 → 组织级确信度）、
组织建议闭环（全组织复验、采纳率升级「组织推荐」）、STIX 2.1 情报交换、软隔离与吊销。
跨节点只同步**建议与证据**，永不直接下发处置命令——节点自治是架构红线。

```bash
# 协调者：创建组织（组织身份 = CA 证书，不是组织名）
aisafeguard fed init-ca [组织名]
# 给成员机器发证（拷贝到目标机 <数据目录>/fed/），预登记指纹后成员改 [fed] 配置入伙
aisafeguard fed issue-cert <节点名>
aisafeguard fed expect <节点名> <指纹>
# 运维：软隔离（保留心跳审计）/吊销（驱离）/审计导出/STIX 导出导入
aisafeguard fed quarantine <节点> [原因]      # 解除: --lift <指纹前缀>
aisafeguard fed audit <out.json> [--format stix]
aisafeguard stix-import <签名包.json>
```

GUI 侧栏「⇄ 组织」页：成员表（在线/隔离/指纹）、协议异常计数、组织事件流。
手册：[docs/FEDERATION.md](docs/FEDERATION.md)（加入流程、协议 v1、升级顺序：先协调者后成员、
威胁模型与降级预案）。
