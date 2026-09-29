# 负路径实测记录(可复现)

回应 ROADMAP-0.4 验收清单中遗留的三条负路径项:**吊销 / 指纹不一致**、**内网永不自动封**、**外发失败无自反馈风暴**。每条给出:机制位置 → 自动化测试证据 → 实机复现步骤。

- 记录日期:2026-09-29(版本 0.5.3)
- 自动化环境:Windows 11 x64,`cargo test --workspace` 全绿(0 failed)
- 历史实机环境:WSL2 Ubuntu 24.04 / Windows 11(对应实测记录见 CHANGELOG 0.3.5 / 0.3.6 / 0.4.0)

## 1. 证书吊销 → 立即拒连

**机制**:`crates/aisafeguard-app/src/fed.rs` `check_not_revoked`——文件式 CRL(`fed/revoked.json`),协调者**每次** mTLS 连接检查,命中即拒连并留审计事件;`fed revoke` CLI 即时生效,不依赖证书有效期。

**自动化证据**(2026-09-29,本机通过):

```
test fed::tests::revocations_and_expected_registration ... ok
```

覆盖:空表不吊销 → 按指纹吊销立即生效 → 重复吊销拒绝 → 按节点名吊销(算证书指纹)→ 预登记指纹匹配/不匹配 → 未预登记节点走 TOFU。

**实机复现**(双实例,WSL2,根目录 = 数据目录):

```bash
# 协调者侧
aisafeguard fed revoke agent1 "演练:吊销负路径"   # 立即生效
# agent1 侧下一轮上报(≤15s)即被拒;协调者事件流出现 fed 拒绝审计事件
aisafeguard fed audit audit.json                  # 导出核对:吊销表 + 拒绝事件
```

**历史实测**:0.3.6(2026-09-28,CHANGELOG)双实例真 TLS 握手——合法证书冒用他人节点名 → 403;本条吊销路径同一连接检查点。

## 2. 指纹不一致(冒用/换证)→ 403

**机制**:node ↔ 证书 SHA-256 指纹 TOFU 绑定(`fed.rs` 首次接触登记 `cert_fp`)+ `fed expect` 预登记;之后每次请求校验指纹,不符返回 403「指纹与预登记不符(可能的冒用/换证)」。同证书冒用其他节点名在同一点被拦。

**自动化证据**:同上 `revocations_and_expected_registration` 中 `expected_ok` 断言——预登记后指纹不符必须拒(`!expected_ok(&expected, "agent1", &"f".repeat(64))`);持久化绑定见 `crates/aisafeguard-store`(`cert_fp` 列)。

**实机复现**:

```bash
aisafeguard fed expect agent1 <预登记指纹>
# 用另一张合法证书(指纹不同)冒充 agent1 上报 → 协调者 403,审计事件留痕
```

**历史实测**:0.3.6 CHANGELOG「agent2 合法证书冒用 node=agent1 → 403」。

## 3. 内网/回环地址永不自动封

**机制**:`aisafeguard_core::is_protected_ip`(`crates/aisafeguard-core/src/lib.rs`)硬编码——回环/未指定/组播/链路本地/RFC1918 私网/IPv6 ULA 全部保护,**无配置开关**(误配置也不能关闭)。生效点五处:

1. 快路径自动封禁前置拒绝(`engine.rs` handle_detection,留痕「内网保护」)
2. AI 建议应用(`aisafeguard-ai`)
3. 情报源自动封禁(`engine.rs` intel 路径)
4. 协同上报前置拒收(`fed.rs`,防投毒)
5. XDP 镜像资格 + eBPF 内核路径(`aisafeguard-xdp` `mirrorable`)

**自动化证据**(2026-09-29,本机通过):

```
test engine::tests::detection_never_blocks_protected_ip ... ok
   # mock 防火墙断言:内网/回环触发检测 → 零封禁、规则表为空、判定事件与"内网保护"留痕照常
test composite::tests::mirrorable_never_takes_protected_ips ... ok
   # XDP 镜像资格:受保护地址永不进快速丢弃表
test config::tests::default_config_security_baseline ... ok
```

**实机复现**(Linux,root):

```bash
for p in 2222 8081 2323; do timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$p"; done
curl -s -H "Authorization: Bearer $(cat /root/.local/share/aisafeguard/api-token)" \
  "http://127.0.0.1:7420/api/events?limit=5"   # 有 detection 事件 + "内网保护"留痕,无封禁规则
curl -s "http://127.0.0.1:7420/api/rules"      # 防火墙规则表为空(蜜罐触达不产生封禁)
```

注:手动 `POST /api/rules` 封内网地址不受此保护(管理员明确意图),自动路径全部受保护。

**历史实测**:0.3.1 CHANGELOG「内网保护跳过自动封禁留痕」(Windows 实机)。

## 4. 外发失败无自反馈风暴

**机制**(`crates/aisafeguard-app/src/forward.rs`):

1. syslog/webhook 转发器**只读事件总线、不产事件**——失败只走 tracing 日志,构不成「外发失败 → engine 事件 → 再外发」的自反馈环
2. webhook 失败/非 2xx **丢弃本条**,不积压不重试;失败日志 60s 限频(`last_fail`),防目标宕机刷日志
3. 事件流 backlog 超限时按 broadcast lag 丢弃,慢消费者不拖垮引擎

**自动化证据**(2026-09-29,本机通过):

```
test forward::tests::hostname_falls_back_without_panic ... ok
test forward::tests::severity_mapping_and_thresholds ... ok
test forward::tests::syslog_line_matches_rfc5424_shape ... ok
test forward::tests::syslog_msg_strips_newlines_for_tcp_framing ... ok
```

限频逻辑(`forward.rs` spawn_notify_task)为纯路径断言之外的代码约束(注释钉住语义),复现按下方实机步骤。

**实机复现**(指向不可达目标,观察 5 分钟):

```bash
# config.toml: [notify] enabled=true, url="http://127.0.0.1:9/unreachable"(端口 9 必然拒绝)
# 触发一批蜜罐事件后:
#   1) 引擎持续正常出事件、GUI/API 不受影响(失败不回灌事件总线)
#   2) 日志中 webhook 失败告警每 60s 至多一条(限频),不随事件量增长
#   3) systemctl / 进程无内存或队列增长(失败即弃)
```

**历史实测**:0.3.5 CHANGELOG 实测段——UDP/TCP 双通道 + severity 过滤正常;失败语义「best-effort 不阻塞引擎」。

## 5. 规则引擎默认只告警(附)

**机制**:`[detect.rules].auto_block` 独立于快路径 `auto_block`(默认 false);命中只产 `Detection(kind=signature)` 事件,是否封禁由调用方决定,封禁出口仍过内网保护 + 误报抑制。

**自动化证据**(2026-09-29,本机通过):

```
test engine::tests::rule_hit_default_alert_only_never_blocks ... ok
test engine::tests::detection_respects_auto_block_off ... ok
test engine::tests::rule_scan_hits_and_dedups_per_flow ... ok
```

## 复现自动化证据

```bash
cargo test --workspace          # 全绿(2026-09-29,Windows 11;Linux 侧 WSL2 同套测试)
cargo test -p aisafeguard-app   # 本文档引用的 fed/engine/forward 测试所在
```
