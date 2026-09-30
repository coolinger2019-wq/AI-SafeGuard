# CONFIG-COVERAGE：配置字段与界面/示例/手册对齐审计（0.5.10 H150）

> 目的：消灭「界面上完全看不出存在」的功能。0.5.9 复盘发现假 Shell 只能改
> config.toml 开启，GUI 用户无从发现——本审计保证每个能力在三个表面
> （GUI / 示例配置 / 手册）上至少可见，简单开关必须 GUI 可操作。
>
> 三态处置纪律（H400 收口清单同步）：
> - **简单开关** → 补 GUI（设置页勾选/输入框）；
> - **进阶参数** → 示例文件带注释 + 手册提及；
> - **危险/运维项** → 明示「仅配置文件」的理由，不塞进 GUI。
>
> 以后新增配置字段 = 三处同步（结构体 / GUI 或示例 / 手册），CI 防漂移测试
> `config_example_stays_in_sync` 拦截「字段未进示例」。

处置图例：✅ GUI 可操作 · 📄 示例文件带注释 · 📖 手册有提及 · 🔒 仅配置文件（附理由）

| 字段 | 默认 | GUI | 示例 | 手册 | 处置说明 |
|---|---|---|---|---|---|
| general.data_dir | 空 | 🔒 关于页只读展示 | 📄 | — | 运维项：改目录不迁移数据，只给明事理的人改 |
| api.enabled | true | ✅ 通道页 | 📄 | 📖 快速上手 | |
| api.port | 7420 | ✅ 通道页 | 📄 | 📖 | |
| honeypot.enabled | true | ✅ 蜜罐页 | 📄 | 📖 界面导览 | |
| honeypot.listeners[].{name,port,kind,enabled} | 4 行 | ✅ 蜜罐页监听表编辑器 | 📄 | 📖 增加监听器 | H130 补 GUI；mysql/redis 由此进入可见范围 |
| honeypot.shell.enabled | false | ✅ 蜜罐页 | 📄 | 📖 开启假 Shell | H130 补 GUI |
| honeypot.shell.telnet_enabled | false | ✅ 蜜罐页 | 📄 | 📖 | |
| honeypot.shell.username / hostname | deploy / debian-11 | ✅ 蜜罐页 | 📄 | 📖 | |
| honeypot.shell.max_commands | 50 | ✅ 蜜罐页 | 📄 | 📖 | |
| honeypot.shell.host_key_path | 空 | 🔒 | 📄 | — | 运维项：默认自动生成持久化，只有证书目录特殊约定才需要改 |
| honeypot.credentials.enabled | true | ✅ 蜜罐页 | 📄 | 📖（事件/出事看哪里） | H200；被动分析，明文不落盘 |
| honeypot.credentials.snapshot_interval_secs | 3600 | 🔒 | 📄 | — | 进阶参数：默认一小时刷新足够 |
| honeypot.canary.enabled | false | ✅ 蜜罐页 | 📄 | 📖 放置蜜饵 | H210 |
| honeypot.canary.key | 空 | 🔒 | 📄 | 📖 | 运维项：默认自动生成密钥文件，跨节点场景才需要显式配置 |
| honeypot.canary.fs_paths | 空 | 🔒 | 📄 | 📖 | 平台差异项（仅 Linux），路径是运维决策，不进 GUI |
| honeypot.templates.enabled / dir | false / 空 | 🔒 | 📄 | 📖（部署指南 §2） | 运维项（0.5.11 H300）：模板是资产文件（html+toml），编辑器解决不了内容生产，目录约定见 deployment.md |
| honeypot.fingerprint.ssh_banner / telnet_greeting / mysql_version / http_server | 内置默认 | 🔒 | 📄 | 📖（部署指南 §1） | 进阶参数（0.5.11 H320）：与真实环境服务版本强相关，逐环境不同，默认值=内置值零行为变化 |
| ai.enabled | false | ✅ AI 页 | 📄 | 📖 开启 AI 分析 | |
| ai.base_url / model | GLM | ✅ AI 页 | 📄 | 📖 | |
| ai.auto_apply / auto_apply_min_severity | false / high | ✅ AI 页 | 📄 | 📖 | |
| ai.analyze_interval_secs | 900 | ✅ AI 页 | 📄 | — | |
| ai.max_snippet_chars | 200 | ✅ AI 页 | 📄 | — | |
| ai.fp_suppress_secs | 14 天 | ✅ AI 页（天） | 📄 | 📖 封错了 | |
| ai.fp_ignore_min_severity | 空 | 🔒 | 📄 | — | 进阶参数：与误报抑制语义耦合，误用会削弱闭环 |
| ai.trial_ttl_secs / promote_ttl_secs | 900 / 30 天 | 🔒 | 📄 | 📖（灰度语义） | 进阶参数：灰度闭环的默认值经评审，不鼓励随手改 |
| detect.enabled / auto_block | true / true | ✅ 检测页 | 📄 | 📖 | |
| detect.scan_distinct_ports / bruteforce_hits / window_secs / ttl_secs | 5 / 10 / 60 / 1800 | 🔒 | 📄 | — | 进阶参数：默认阈值贴合真实攻击节奏，GUI 只给开关 |
| detect.capture.enabled / mode | false / control | ✅ 检测页 | 📄 | — | |
| detect.capture.scan_distinct_ports / syn_flood_rate / window_secs / flow_idle_secs / flow_table_cap | 15 / 100 / 60 / 120 / 65536 | 🔒 | 📄 | — | 进阶参数：检测调优面 |
| detect.capture.driver_sha256 | 空 | 🔒 | 📄 | — | 运维项：供应链校验钉扎值，只能来自官方渠道文档 |
| detect.l7.enabled / ja3 / ja4 | false / true / false | ✅ 检测页 | 📄 | — | |
| detect.rules.enabled / path / auto_block | false / 空 / false | ✅ 检测页 | 📄 | 📖 开启规则包 | |
| detect.rules.max_rules | 5000 | 🔒 | 📄 | — | 进阶参数：整包校验上限 |
| xdp.enabled / iface / mode | false / eth0 / skb | ✅ 蜜罐页（XDP 段） | 📄 | — | Linux-only，GUI 有开关与状态 chip |
| intel.enabled / interval_secs | false / 6h | ✅ 检测页 | 📄 | 手动拉取按钮 | 联网项：默认关；fed/stix/local 源永不自动封禁 |
| intel.sources[]（name/url/confidence/kind/auto_block/ttl_secs） | feodo_c2 | 🔒 检测页只读展示 | 📄 | — | F710 多源分级：自动封禁 = auto_block && confidence=high 双条件；换源不再同等信任 |
| fed.enabled / role / node / coordinator / min_peers / interval_secs / listen_addr | false / off / … | 🔒 | 📄 | — | 运维项：多节点部署与证书签发是一套流程，GUI 化反而危险 |
| fed.ca_path / cert_path / key_path | 空 | 🔒 | 📄 | — | 运维项：证书材料路径 |
| syslog.enabled / target / protocol | false / … / udp | ✅ 通道页 | 📄 | — | |
| notify.enabled / url / min_severity | false / 空 / warning | ✅ 通道页 | 📄 | — | |
| notify.timeout_secs | 10 | 🔒 | 📄 | — | 进阶参数 |
| notify.sign | false | 🔒 | 📄 | — | HMAC 签名开关；密钥走环境变量 AISAFEGUARD_WEBHOOK_SECRET / 凭据管理器（不入配置） |
| exposure.auto_scan_secs | 0 | ✅ 通道页 | 📄 | — | |
| ui.theme / font_scale | deep_blue / 1.15 | ✅ 外观页 | 📄 | — | |

## 走查结论（0.5.10）

- 此前「GUI 完全不可见」的功能：假 Shell（0.5.9 新增）、监听表编辑、mysql/redis 协议、凭证喷洒检测、蜜饵 canary——本轮已全部补进设置页蜜罐域；「帮助」页内嵌手册让能力可被发现。
- 蜜罐 Tab 每个监听器显示交互模式（低交互/中交互/未启用）与运行状态。
- 明确不塞进 GUI 的：证书材料、数据目录迁移、驱动哈希钉扎、灰度 TTL 默认值——理由见上表，均为「改错比不改危险」的运维/进阶项。
