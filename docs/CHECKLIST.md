# 问题模式检查清单（F795）

> 来源：docs/LESSONS.md 历史批次 + 2026-10-03 全面检视的真实 bug。每条都是**踩过至少一次**
> 的模式，不是预防性想象。新代码生成/审查时按阶段对照；新踩的坑往里加（带日期）。
>
> 用法：①生成代码前把本文件相关段粘进 prompt；②审查（agent 或人工）按清单逐项过；
> ③新坑按「模式 → 触发条件 → 钉死手段」格式收录。

## 一、设计/架构期

- [ ] **trait 加方法不写默认 Err 实现**（踩 4 次，根治定式）：默认实现 = 编译器不再强制覆盖，
      内嵌/远程必漏一个。宁可强制全覆盖编译错。例外仅限「多数实现合法不支持」。
- [ ] **新功能必须同时出现在 GUI/API/手册三面**（H150 定式；再犯：LISTENER_KINDS 漏 mcp
      与 F794 四协议）：界面上看不见的功能 = 不存在。新增 kind/开关/端点时同步
      `gui/mod.rs` 常量表、MANUAL、CONFIG-COVERAGE。
- [ ] **对外输入永远不可信**：AI 输出（建议/阈值）不经证据门控不得直接驱动防火墙；
      攻击者载荷先 sanitize/redact 再落库；探针/验证脚本自己也可能错——用服务端事件当真值。
- [ ] **共享资源语义先想清楚**：nftables/XDP 元素按（方向,IP,粒度）键控是共享的——
      多条规则叠加的删除/过期要定义「取叠加最大值」还是「先到先删」（F793 教训）。

## 二、编码期

- [ ] **转义纪律**（用户约定，2026-10-03）：协议常量用十六进制/字节数组；不在 heredoc 里写
      含 `\0`/`\x`/`\\` 的补丁（Bash 工具会剥层）；Edit 直写源码；涉及转义必加字节级断言
      （如 `assert_eq!(&blob[..8], b"NTLMSSP\0")`）。
- [ ] **配置字段三连**：新字段 = 结构体 + 全部测试构造器 + `restart_required` 判定；
      deny_unknown_fields 会拦旧配置——同步 `docs/config.example.toml`（防漂移测试）。
- [ ] **events 表列序**：insert_event 的九元组字段序必须与 EVENT_COLUMNS 一致
      （HoneypotHit rule_id 曾落错列）。
- [ ] **Rust 版本 API 断层**：rand 0.10 `gen`→`random`；russh `run_stream` 后必须再 await
      `RunningSession`；ring 验签只吃裸点不吃 SPKI；TLS provider 钉 ring 防 aws-lc-rs 混入。
      升依赖后先查这几个。
- [ ] **平台分支**：Linux-only 代码 Windows 编译期不检查——交叉 `cargo check` 必跑；
      `#[cfg(test)]` 不进 `cargo check`，改测试构造器后要跑 `cargo test`。
- [ ] **handler 三实现**：EngineHandle/Console 加方法时内嵌/远程/默认三处同步（见一-1）。
- [ ] **特权端口**：绑定 <1024 需要 `CAP_NET_BIND_SERVICE`——unit 模板与节点实配要同步核对
      （漂移已发生一次：BPF/PERFMON、NET_BIND_SERVICE）。

## 三、测试期

- [ ] **测试必须单 crate 跑**：workspace 全量并行时蜜罐 ssh/canary 测试偶发红
      （bind :0 探测-让渡竞态）——单独跑即绿。流水线按 crate 循环就是这个原因。
- [ ] **新协议蜜罐的验收 = 真客户端实连**：mysql 用 8.x CLI、redis-cli、paramiko；
      python 手写客户端测不出协议实现 bug（MySQL lenenc 教训）。
- [ ] **验证探针纯数值字节数组构造**：探针自身转义/长度/padding 错会伪装成服务端 bug
      （本会话三连）。字段偏移先在探针侧声明；以服务端事件为真值判定。
- [ ] **多标签页/多实例陷阱**：浏览器测试按 URL 选标签（VPS 数据当本地测试数据看过半天）；
      单机只跑一个实例（端口战争 + DB 共写）。
- [ ] **事件 summary 分布 review**：新蜜罐/新路径上线第一天看非预期 summary 占比
      （SMB「非 NBSS 数据」31/37 = 解析门槛错 + 标签错）。写进部署验证步骤。

## 四、部署/运维期

- [ ] **改二进制先 `systemctl stop`**（Text file busy）；daemon-reload 后再 restart。
- [ ] **VPS 构建**：tar over ssh 同步（排除 target/.git/dist）；增量 ~8 分钟；swapfile 用后撤。
- [ ] **配置编辑在节点上**：python3 heredoc + 精确锚点 + tomllib 回读校验（sed 多行会塌成一行）；
      改前备份；`--data-dir` 不决定配置路径（本地测试必须显式 `--config`）。
- [ ] **控制台上线双通道**：内嵌版要编译（本地验证 include_str!），磁盘覆盖版 scp 即生效——
      两个版本要一致，否则下次部署回退。
- [ ] **webhook/通知线**：密钥永不进 config/对话；验证路径设计为不需要读 key 本身。

## 五、运行时验证（每轮发布后 / 定期）

- [ ] `aisafeguard verify-log`（哈希链 100%）先行，失败数据不进分析。
- [ ] 事件 kind/summary 分布查询：非预期 summary（兜底分支命中率高）= 新 bug 信号。
- [ ] 资源基线：内存（42MB 级）、CPU、磁盘增速；重启计数（journalctl Stopped/Started 对）。
- [ ] 处置闭环抽查：detection → firewall_add → TTL 到期 remove 的完整事件对；
      AI 建议 → applied → 规则存在。
- [ ] 压测口径（需要时）：并发连接打满 MAX_CONCURRENT=64 的优雅拒绝、交互会话 8 上限。

## 六、审查 agent 的固定动作（每次代码审查必做）

1. 按本清单逐项对照（设计期四条 + 编码期七条优先）。
2. 找「两个真相来源」：同一状态在 DB / 内存 / nftables / 面板是否一致（F793 状态谎言）。
3. 找「静默失败」：unwrap_or(false)/unwrap_or(true)/let _ = 的错误吞没点，逐个问是否该留痕。
4. 找「边界继承」：新字段/新枚举值/新 kind 是否漏进：GUI 常量表、防漂移示例、restart_required、
   explain 文案、AI prompt 上下文、STIX 导出排除单。
5. 找「时序假设」：TTL 到期/热更/并发信号量/重启窗口下的竞态。
