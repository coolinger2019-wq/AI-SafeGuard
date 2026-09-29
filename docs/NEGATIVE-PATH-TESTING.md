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

## 6. SSH 假 Shell 负路径(0.5.9 H105)

**机制**:`crates/aisafeguard-honeypot/src/shell.rs`——攻击者输入永远当「数据」:`ShellSession::handle_line` 先 `sanitize`(lossy UTF-8 + 控制字符替换 + 4096 截断)再解析;组合命令(`;` `|` `&`)只仿真首个、整行原样留痕;未知命令回对齐真实 bash 的 `command not found`;命令数达 `max_commands`(默认 50)即优雅退出。任何输入不 fork 真实进程、不拼接系统调用。

**自动化证据**(2026-09-29,`cargo test -p aisafeguard-honeypot` 全绿):

```
test shell::tests::combinator_only_first_segment_simulated ... ok
test shell::tests::long_and_binary_input_bounded_never_panic ... ok   # ≥4KB 与二进制乱码
test shell::tests::fuzz_random_lines_never_panic ... ok               # 2000 轮随机输入
test shell::tests::exit_and_command_limit_close_session ... ok        # 会话上限
test shell::tests::unknown_command_matches_bash_text ... ok
```

**实机复现**(配置 `[honeypot.shell] enabled = true` 后):

```bash
python3 scripts/replay-ssh-shell.py 127.0.0.1 2222
# 剧本含:白名单命令 → 组合注入 "whoami; cat /etc/shadow"(只仿真 whoami)→
# mimikatz(未知命令)→ 4096 个 A(超长)→ 每步断言,末尾打印 REPLAY PASS
# 会话超时:连上后静置 120 秒,服务端 inactivity_timeout 断开,事件留痕
```

**已知限制(诚实声明)**:russh 0.63 客户端对 russh 服务端自连时通道数据互传存在上游兼容问题——仅影响「russh 客户端连本蜜罐」这一自连场景;paramiko/OpenSSH 实连全路径已验证。自动化测试因此只断言到 auth+prompt,全命令链路由上述 paramiko 脚本承担。

## 7. MySQL/Redis 蜜罐畸形输入(0.5.9 H110)

**机制**:`mysql.rs`/`redis.rs` 协议解析为纯函数,畸形包一律「回对齐真实服务的错误文案后断开」或「静默结束」,不 panic;MySQL 包长 >2048 视为畸形;RESP 数组上限 64 元素、bulk 长度上限 2048。Redis AUTH 口令在留痕层脱敏为 `***`(明文不落库,COMPLIANCE 纪律;H200 上线后加盐哈希入库)。

**自动化证据**(2026-09-29,`cargo test -p aisafeguard-honeypot` 全绿):

```
test redis::tests::fuzz_parse_resp_never_panic ... ok          # 5000 轮随机字节
test redis::tests::parse_inline_and_malformed ... ok           # 负长度/超大长度/坏计数
test mysql::tests::fuzz_username_and_classify_never_panic ... ok  # 5000 轮
test mysql::tests::mysql_listener_roundtrip ... ok             # 真实 TCP 全流程
test redis::tests::redis_listener_roundtrip ... ok             # 真实 TCP + 口令脱敏断言
test listener::tests::interactive_gate_follows_shell_config ... ok  # 交互并发预算语义
```

**实机复现**(WSL,见 CHANGELOG 0.5.9 实测段):

```bash
# 随机字节打两个蜜罐端口:服务不崩、会话被优雅关闭
head -c 4096 /dev/urandom | timeout 2 nc 127.0.0.1 3307 || true
head -c 4096 /dev/urandom | timeout 2 nc 127.0.0.1 6380 || true
redis-cli -h 127.0.0.1 -p 6380 PING          # → PONG
mysql -h 127.0.0.1 -P 3307 -u root -p        # 任意口令进入,SELECT 1 → 空结果集
```

## 复现自动化证据

```bash
cargo test --workspace          # 全绿(2026-09-29,Windows 11;Linux 侧 WSL2 同套测试)
cargo test -p aisafeguard-app   # 本文档引用的 fed/engine/forward 测试所在
cargo test -p aisafeguard-honeypot   # 本文档第 6/7 节假 Shell 与 MySQL/Redis 负路径
```

## 8. 凭证库与蜜饵的负路径（0.5.10 H200/H210）

- 记录日期:2026-09-30(版本 0.5.10)
- 自动化环境:Windows 11 x64,`cargo test --workspace` 全绿;标注 (Linux) 的条目为编译门控路径,WSL2 实机口径同 §6/§7

### 8.1 凭证哈希/明文永不进事件与 API

机制:`SecurityEvent::CredentialObserved` 的 pass_hash 在 store `insert_event` 显式丢弃(事件行只落用户名);口令明文在蜜罐会话内即 argon2id 哈希后丢弃。
证据:`store::tests::credential_event_row_carries_no_secret`——插入带 `pass_hash` 的事件,回读 EventRow 序列化 JSON,断言不含 `argon2id`/哈希值,且 payload 只含用户名。
实机:`cargo test -p aisafeguard-store credential_event_row_carries_no_secret`。

### 8.2 凭证库文件权限与隔离

机制:凭证库是独立 SQLite 文件(`<数据目录>/honeypot/credentials.db`),Unix 上 open 即 chmod 0600;不进主事件库、不进任何 API/Console 方法(结构上不可达)。
证据:`credentials::tests::insert_query_and_prune_roundtrip` 含 0600 断言(Unix);Windows 权限沿用父目录 ACL(发布建议随 `%PROGRAMDATA%` 目录 ACL 管理)。

### 8.3 蜜罐凭证入口的注入面

机制:用户名/口令在采集点统一 `sanitize`(去控制字符/截断:用户名 128、表单值 128、Redis 参数 512);凭证对只产生三类查询(按 IP 用户名集合/按哈希协议数),SQL 全部参数绑定。
证据:honeypot crate fuzz 护栏(`fuzz_parse_resp_never_panic` 等 5 条)覆盖 AUTH/表单解析路径;store 查询测试使用含大写与特殊字符用户名(ROOT)验证 lower 归一不注入。

### 8.4 蜜饵关闭状态行为回归(0.5.8 逐字节)

机制:`canary_response` 在 canary 未启用时恒返回 None,HTTP 路由不进入蜜饵分支。
证据:`http::tests::http_decoy_and_generic_pages`——canary 关闭时 `/backup.zip` 走通用假页且事件无 canary 标签;`/.git/config` 维持 403 诱饵。

### 8.5 蜜饵路径冲突拒绝覆盖

机制:`validate_fs_path`——配置的 fs 蜜饵路径已存在(可能是真实文件)→ 拒绝该条 + engine warn 事件,绝不写入;父目录缺失同样拒绝。
证据:`canary::tests::fs_path_validation_rejects_existing_and_missing_parent`。

### 8.6 诱饵误读抑制(可配窗口)

机制:fs 蜜饵读取事件按路径 60s 去重(`FS_DEDUP_SECS`),正常业务进程批量扫描目录不会高频刷屏;更长的抑制沿用现有误报闭环(fp_feedback 表 + 自动封禁跳过)。
证据:去重逻辑在 Linux 监听线程内(编译门控),逻辑与 §8.5 同文件;实机验证口径:Linux 上 `cat` 蜜饵文件两次,1 分钟内只产 1 条事件(随发布验证)。

### 8.7 水印 token 防篡改

机制:`AC1.<b64url(payload)>.<b64url(mac)>`,MAC=SHA-256(key‖payload);密钥不匹配/内容被改/格式不对一律 Err。
证据:`canary::tests::tamper_and_wrong_key_rejected`(payload 改一位/异节点密钥/非 token 输入/空密钥全拒绝)。
