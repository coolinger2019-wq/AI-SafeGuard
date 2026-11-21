# AI-SafeGuard 改进计划（plan.md）

> 生成于 2026-11-19，基于 software-architect 架构评估（全量 10 crates / 约 4.1 万行 Rust /
> docs 与 CI 全量通读）+ 会话遗留事项。当前版本 v0.8.3（生产 VPS 单节点运行中）。
> 完成一项就把对应条目打 ✅ 并在 CHANGELOG 留痕；本文件不替代 ROADMAP（能力向），
> 只承载「接下来要做的改进」。

## 结论先行

架构质量高于同规模独立项目平均水准：依赖图无环、Firewall trait 刻意收窄、
快/慢双路径准入有文档钉住、事件哈希链版本化、THREAT_MODEL 对残余风险诚实。
主要债务集中在三处：

1. **运维成熟度**——备份/恢复缺失（COMPLIANCE A.8.13 从 0.2 拖到现在）、
   无 metrics 端点、升级回滚只保二进制不保数据库
2. **两个上帝文件**——store/lib.rs 3,377 行（11 张表全生命期）、
   app/engine.rs 4,117 行 / fed.rs 2,941 行开始侵蚀模块化红利
3. **更新信任链未闭环**——发布物只有同源 sha256 无签名，Windows 自更新是
   产品内建路径，信任链断点最大的一处

v0.8.3 发布事故（runner glibc 前向不兼容 → 防护静默下线）实证了：
**0.9 的边际收益最高处不是新检测能力，而是"防自己下线"的运维收口。**

## 改进点 Top 10

### P0（安全 / 稳定性）

- [x] **P0-1 deploy.sh 升级流程补数据库快照 + 新二进制预检** ✅ 2026-11-21（subagent 实现 + 独立审查两轮 PASS：credentials 路径/回滚顺序/systemctl 容错/verify-log 守门 7 项修复，VPS _selftest 实测）
  - 现状：deploy.sh 只备份二进制；DB 被 v0.8.3 的全量重链改写后回滚旧 exe
    会出现新旧口径混写 verify-log 的风险（store/lib.rs:563-579 rechain_all）
  - 方案：换装前 `sqlite3 .backup` 到带版本号目录；回滚分支同时恢复 DB；
    换装前先跑 `/tmp/aisafeguard.new --version` 冷启动验证
  - 工作量 0.5-1 天，风险低

- [x] **P0-2 事件总线 lag 从"日志"升级为"信号"** ✅ 2026-11-21（第一步落地：bus_lag_total + handle_bus_lag + persist/detect/creds 三消费者统一 + StatusReport 暴露 + 订阅点前移；mpsc 迁移为后续步骤）
  - 现状：持久化与检测消费者 lag 只打 tracing warn（main.rs:924-926、
    engine.rs:1651-1653）——对哈希链审计产品意味着**证据空窗无告警**
  - 方案（两步）：先做 lag 计数器进 StatusReport + 超阈值发 Engine error 事件
    （走既有 webhook 外发）；后续把持久化消费者迁专用 mpsc（broadcast 留给
    GUI/API 这类可容忍丢失的消费者）
  - 工作量 1-2 天（专用队列含回归 2-3 天），风险中

- [ ] **P0-3 发布物与自更新签名**
  - 现状：update.rs 双源下载 + 同源 sha256，sha 可被同源替换；
    ROADMAP.md:52 的签名条目悬置 4 个月
  - 方案：ECDSA P-256 签名发布 manifest（ring 已在依赖树，复用 F100 fed
    签名基建）；update.rs 应用前验签；公钥指纹进 README/发布页
  - 工作量 2-4 天，风险低；需一并写清签名密钥保管流程

### P1（架构健康）

- [ ] **P1-4 store/lib.rs 按表域拆分 + 迁移容错收窄**
  - 现状：单文件 3,377 行；lib.rs:538 对迁移错误**无差别忽略**——磁盘满/
    锁死/损坏同样被吞，只留半迁移状态
  - 方案：按表域拆五模块（events含链/rules/proposals/fed_members+org/intel）；
    迁移处区分"列已存在"（可忽略）与其他错误（fail-fast）。
    **不引入迁移框架**（AGENTS 第 2 条，枚举式幂等迁移是当前正确选择）
  - 工作量 2-3 天，风险低

- [ ] **P1-5 fed 域抽 aisafeguard-fed crate**
  - 现状：app/src/fed.rs 2,941 行 = 协议 + mTLS 服务端 + agent 客户端 + PKI CLI
  - 方案：收编 fed.rs + fedproto.rs + corroboration.rs + stix.rs；app 只留装配。
    时机：**下次动 fed 协议时顺手做**（Rule of Three 已满足）
  - 工作量 3-5 天，风险中（Console trait 与 FedPanel 类型归属需重新切线）

- [ ] **P1-6 /api/metrics + 防护存活外显**
  - 现状：无 metrics；v0.8.3 事故形态正是"防护下线无人知"
  - 方案：text/plain 输出 events_total/detections_total/auto_block_total/
    bus_lag/listener_up(11)/db_size/xdp_attached；deploy.sh 健康检查改消费它；
    文档给 cron+curl 心跳外发配方（配合既有 webhook）
  - 工作量 2-3 天，风险低

- [ ] **P1-7 `aisafeguard backup` / `restore` 子命令（A.8.13 收口）**
  - 现状：COMPLIANCE.md:36 唯一从 0.2 拖到现在的 P0 合规项
  - 方案：一条命令打包 config.toml + DB 快照 + credentials.db + fed 证书目录；
    restore 反向；不做加密不做云上传（输出 manifest + sha256，保管是运营者的事）
  - 工作量 2-3 天，风险低

- [ ] **P1-8 快路径容量预留（只记录，不动手）**
  - 现状：handle_detection 热路径同步 3 次 SQLite 查询（engine.rs:1415-1443）；
    FreqEngine 全局单锁（detect/lib.rs:63）
  - 方案：写两条适应度函数进 NGFW_EVOLUTION.md §2.4 附注——蜜罐命中 > 20 万/日
    或检测判定 p99 > 100ms 时再做（a) fp/阶梯查询出热路径 (b) 按 listener 分片。
    现在做 = 过早抽象（AGENTS 第 2 条）
  - 工作量：记录 0.5 天；真做 3-5 天

### P2（体验与效率）

- [ ] **P2-9 Web 控制台加固收尾**
  - index.html:1011 三处字段未 esc()；index.html:492-510 默认向第三方
    `http://ip-api.com` 明文查询攻击者 IP（顺带外泄运营者查询行为）
  - 方案：补 esc；geo 查询加显式开关（默认关或走 https）；esc 强制约定写进 LESSONS
  - 工作量 0.5-1 天，风险低

- [ ] **P2-10 构建面钉版本与 GUI 隔离评估**
  - build.yml:68 Windows 产物仍在 `windows-latest`（漂移 runner）——
    LESSONS 的教训只钉了 Linux 侧
  - 方案：Windows 钉 `windows-2022`；feature gate `gui` 做评估 spike
    （headless 瘦身 + 审计面收窄 vs CI 矩阵翻倍），先出数据再决定
  - 工作量 0.5 天 + spike 1-2 天，风险低

## 0.9 立项（建议 A + B 打包，C 并行 / D 挂起）

| 主题 | 内容 | 规模 |
|---|---|---|
| **A. 运维收口（必选）** | P0-1 + P0-2 + P1-6 + P1-7 打包 | M（1.5-2 周） |
| **B. 发布信任链（必选）** | P0-3 + P2-10 Windows 钉版本 + musl 静态链接 spike（LESSONS"需要时再做"已到"需要时"） | M-L（3-7 天） |
| **C. fed 抽取 + store 拆分（并行）** | P1-4 + P1-5——为 0.6 协同完全体（quorum/选举）铺依赖边界 | M |
| **D. eBPF 流表联动（挂起）** | 0.5.1 Batch G 遗留；单节点无横向流量，收益存疑，等多节点场景 | L |

## 会话遗留事项（与上述计划并行跟进）

- [ ] **AI 403**：VPS `[ai]` 指向 opencode Go（订阅失效）→ 等用户指定可用供应商
      后改配置验证（影响 funnel proposed/applied=0）
- [ ] **PR #8 rustix 1.1.6**：CI 绿但 AF_PACKET 路径 CI 测不到——待 WSL 本地
      验证 sockopt 行为后合并（已留言暂缓）
- [ ] **PR #6 softprops v3**：release job 只在 tag 时跑——下次发版前验证 v3 兼容
      （已留言暂缓）
- [ ] **musl 静态链接 spike**：v0.8.3 glibc 前向不兼容事故的终极解（已进 0.9-B）
- [ ] **IP 决策**：观察期已过（11-20），IPv4 渐解封 + 工单已暂缓——是否行使 $3
      换 IP 由用户决定；决定后更新本条
- [ ] **#42 后观察**：slow_scan 上线后 RDP 面转化率变化（下轮桥报看数据）

## 验收口径

- P0/P1 各项：实现 + 单测 + 双平台门禁绿 + CHANGELOG 留痕 = 完成
- 0.9 主题 A/B：可独立发版（0.9.0 起，theme 版本化）
- 所有"记录型"条目（P1-8）：写进对应 docs 后即完成，不写代码
