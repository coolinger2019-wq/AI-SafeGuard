# 弯路与决策记录

按 AGENTS.md 第 9 条：走过的弯路记在这里，避免重复踩。

## 2026-09-27（0.1 立项）

- **Windows 防火墙不要用 netsh 输出解析**：netsh 文本随系统语言变化，规则列表解析必然脆。选了 `windows_firewall` crate（封装 INetFwPolicy2 COM，20 个版本、约 10 万下载、2026-08 仍在发版）。只有在不引 COM 依赖的小工具里才考虑 netsh 参数数组（`std::process::Command` 不经 shell）。
- **提权检测用完整性级别 SID**，不要解析本地化的组名（"Administrators" 在中文系统叫别的名字）。`whoami /groups /fo list` 里的 SID（S-1-16-12288 High / S-1-16-16384 System）不随语言变。避免了引 `windows` 大依赖 + unsafe FFI。
- **GUI 选 egui 而不是 Tauri**：安全软件要压缩自身攻击面，webview 栈（JS、IPC、npm 供应链）是纯负担；egui 单二进制纯 Rust。代价是图表弱、界面"工具感"，对本产品可接受；真要富报表时再评估加独立 web 控制台（API 已预留）。
- **eframe 默认字体不含 CJK**，中文直接变豆腐块。启动时按 `msyh.ttc → simhei.ttf` 顺序加载系统字体，不往仓库提交字体文件。
- **LLM 输出永远当不可信输入**：严格 allowlist 校验（schema 之外的丢弃）、结构化字段直通 COM、绝不给 LLM 输出任何进 shell/命令的机会；蜜罐回显数据在提示词里包标签声明不可信。
- **不要自动封内网/回环 IP**：哪怕 AI 建议也拦下——误封网关/自己的设备比漏掉一个攻击者代价大。
- **事件时间戳存 epoch 整数**，展示层再转本地时间。SQLite 里拿 RFC3339 字符串做时间比较会因为时区偏移翻车。
- 仓库根 `C:\Users\coolinger\.cargo\config` 文件名已废弃（应叫 `config.toml`），cargo 每次构建告警——与本项目无关，属于本机配置，顺手记下。

## 0.1 实现过程

- **egui 0.36.2 要求 rustc 1.95**：本机 1.93 直接被 cargo 拒绝解析依赖。`rustup update stable` 解决（1.98.1）。新项目锁 GUI 框架版本前先看它的 MSRV。
- **eframe 0.36 是个大版本 API 断层**：`App::update` 拆成 `logic`（无 UI）+ `ui(&mut self, ui: &mut Ui, frame)`（给的是根 Ui，不是 ctx）；`SidePanel/TopPanel` 合并为 `Panel::left/right/top/bottom` + `exact_size()`；所有 Panel/CentralPanel 的 `show()` 改收 `ui` 而非 `ctx`；`egui_extras::Size` 改名 `Column`；`Context::style_mut` 改为 `style_mut_of(Theme::Dark, …)`。下次升级 egui 先读 CHANGELOG，别按记忆写。
- **typed-builder 条件字段不能续写**：`let b = ...; if x { b = b.field(v); }` 会因类型状态参数变化而编译失败。解法：必填项走 builder 链，可选项 build 之后用 getset 生成的 `set_xxx()` 方法。
- **egui 中文显示**：默认字体不含 CJK；`msyh.ttc` 能被 ab_glyph 解析（ttc 取第一个面）。但雅黑缺装饰符号字形（⌂ ◉ ✦ 显示为方块），把 `seguisym.ttf`（Segoe UI Symbol，Windows 自带）和 CJK 字体按顺序追加到 family **末尾**做回退（追加在末尾=拉丁用默认字体，缺的才回退）。
- **LLM 建议校验的教训（单测抓出来的）**：初版把"非法 IP / 越界端口"静默降级（丢掉该字段继续用另一字段），结果"封 99999 端口"会变成"封该 IP 全端口"——规则被放宽了。正确姿势：字段存在但非法 → 整条建议作废。放宽永远不该是解析器的决定。

## 0.2 合规加固（2026-09-27）

- **链式 sed 重命名会"二阶污染"**：把 `AISAFE_AI_KEY → AISAFEGUARD_AI_KEY` 后，第二轮 `AISAFE → AI-SafeGuard` 又把新串的前缀替换成 `AI-SafeGuardGUARD_AI_KEY`。事后残留检查用的是"旧串不再出现"，挡不住这种新串被再次改坏的情况。教训：多条重叠模式的批量替换要么一次替换完成，要么检查**最终语义正确性**（编译 + 全文搜无意义 token），不要只查旧串是否清零。本次靠编译错误（env::var_os 收不收这个值不报错）侥幸没漏——真正暴露是 clippy/人肉复查。
- **SQLite 加列用 ALTER + 忽略"列已存在"错误**即可，不用引迁移框架；一次性数据搬迁（0.1 明文 key → 凭据管理器）放在解析前的 pre-pass，搬完把字段从文件里物理删除——是"搬数据"不是"兼容层"。
- `std::env::var()` 是 Result 不是 Option，没有 `.filter()`——先 `.ok()` 再 filter；clippy 的 collapsible_if 催出来的。
- **滑动窗口检测器的"压线"语义**：窗口 [ts-60, ts] 左闭右开时，恰好 60 秒前的样本仍在窗内。测试断言窗口边界时容易差一，写测试先把"触达序列 + 滑出条件"在纸上排一遍。
- **检测器触发语义**：`observe()` 返回的判定在"达到阈值的那一次调用"就触发，不是下一次调用——测试和文档都要按这个语义写。
- 凭据管理器 keyring v3：Windows 后端在 `default-features=false, features=["windows-native"]` 下零额外系统依赖；Linux 后端另选（0.3），期间 Linux 上 `Entry::new` 返回错误要优雅降级到环境变量。

## 0.2 服务化拆分（2026-09-28）

- **GUI/引擎分离的正确切面是"控制台契约"**：先抽 `Console` trait（内嵌/远程两实现），GUI 全部改走 trait，再上服务——比"先写服务再改 GUI"返工少一半。StatusReport/EventRow 等所有跨进程 DTO 要同时派生 Serialize+Deserialize，一开始只派生 Serialize 是伏笔。
- **windows-service 0.8 的 API 与旧版文档差异大**：没有 ServiceControlHandlerBuilder，用 `service_control_handler::register(name, FnMut(ServiceControl) -> Result)`；ServiceInfo 无 description 字段（create 后 `service.set_description()`）；ServiceStatus 多了 `process_id` 字段。抄旧示例必挂，先看本地 registry 源码。
- **服务模式的凭据分发是独立设计题**：Keyring 是每用户隔离的，LocalSystem 服务存的凭据 GUI 用户读不到。0.2 的取舍 = 服务把 API token 发布为 ProgramData 文件（本机用户可读，ProgramData 继承 ACL）；代价是本机其他用户能读 token——可接受（API 只能封禁/解封，不能执行代码），0.3 换命名管道 + 调用方模拟后收紧。
- **提权检测的一个 Windows 坑**：非提权管理员进程的 token 里 Administrators SID 是 deny-only，把文件 ACL 授给 Administrators 组**并不能**让非提权 GUI 读它——所以 token 文件靠 ProgramData 继承 ACL 给 Users 而不是显式 ACL 给管理员组。
- GUI 探测顺序（提权→内嵌 / 服务→远程 / 都不→内嵌回退）保证了"任何时候都能打开界面"，服务只是增强项不是硬依赖——分布式/服务化改造都该遵守这条。

## 0.2 fuzz 与 nftables（2026-09-28）

- **模糊测试第一轮就抓到真 bug**：sanitize 手写的 `(c as u32) < 0x20 || c == 0x7f` 漏掉 C1 控制区（U+0080-9F）——多字节 UTF-8 序列会产生这类字符进入 GUI。正确姿势是 `char::is_control()`（覆盖 C0+C1+DEL）。"自己列举范围"几乎必然漏，用标准判定。
- **Windows 服务两个必踩坑**：① 只报 StartPending/Stopped 而不报 Running → SCM 永远显示"正在启动"；② LocalSystem 的 LOCALAPPDATA 是 `systemprofile` 私有目录——服务必须显式钉死数据目录到 ProgramData，否则 DB/日志落进用户无法 inspect 的地方。真实服务 E2E 一跑就暴露，早该在服务化第一天用真实服务而不是"假装服务"的 headless 验证。
- **交叉类型检查物有所值**：`cargo check -p aisafeguard-firewall --target x86_64-unknown-linux-gnu` 在 Windows 上就揪出 trait 默认实现与平台实现的返回类型不一致（`resync`）。注意全 workspace 交叉检查会被 ring（需要 C 工具链）卡住，按 crate 单独 check 可行。
- nftables 集成选了"命令行 + 集合元素"而非 netlink 库：幂等（exists 视为成功）、原子、实现薄；命令构造与 CapEff 解析做成纯函数放平台无关模块，全平台单测。实机验证欠账已标注。

## Linux/WSL 实测（2026-09-28）

- **真实环境一跑，三个"理论正确"的环节各掉一个坑**：① nftables 后端 `set.ends_with("6")` 判 family——"blk6_in" 以 "_in" 结尾，判断恒 false，v6 集合全走了 v4 选择器（datatype mismatch），且 ensure_setup 的 `?` 短路让一条失败吞掉剩余三条（blk_out 整个空了）；② keyring v3 无平台特性时静默用进程内 mock 存储——set"成功"但 token 跨进程不可见，Linux 必须显式走文件；③ 测试里 start() 异步 spawn 后立即 connect，Windows 上 bind 总是赢、WSL 上输——竞态测试要重试等待。
- **教训的共同点**：单测只测了纯函数（命令构造、解析），没测"组装后的命令序列"；Windows 上永远测不到的路径（keyring 缺失、nft 真执行、bind 时序）必须在真实环境跑一遍。跨平台项目把"真机验收清单"当作发版门槛而不是可选项。
- **WSL 驱动技巧**：`wsl -u root` 免密提权（nft 需要 CAP_NET_ADMIN）；Windows `curl 127.0.0.1:<port>` 经 localhost 转发直达 WSL 引擎；`pkill -f` 的模式会匹配到承载它的 bash 命令行自身——用 `pkill -x` 精确匹配进程名。
- **删除正在运行的 exe 在 Windows 上是可能的**（本例 MSYS rm 成功删除了服务镜像），服务继续跑旧镜像但文件路径空出——重建写不进去是因为 SCM/杀软锁的是 deps 下的中间产物。绕法：换 `--target-dir` 构建，再把产物拷回注册路径。

## 暴露面盘点（2026-09-28）

- **/proc/net 的地址是小端字节序**：v4 是 4 字节反序（"0100007F" → 127.0.0.1），v6 是 4 组小端 u32。用 `u32::from_str_radix` 后必须 `to_le_bytes()` 再转 `IpAddr`——直接 `Ipv4Addr::from(u32)` 是大端，出来就是 "1.0.0.127"。样本驱动单测把这坑钉死了。
- **采集器路径手误**（/proc/tcp vs /proc/net/tcp）单测测不到（解析函数拿的是文本）——平台 I/O 层薄薄一层，靠真机 E2E 兜底。这类"拼路径"代码放最小化的一行里。
- 伪造 /proc 树的测试在 Windows 上不可行（read_link 语义不同），把 inode 提取抽成纯函数单独测、map 测试用手工构造——平台差异的 I/O 与纯逻辑分离，是跨平台测试的核心手法。

## 0.3 第二批 · 检测平台 MVP（2026-09-28）

- **受限网络下的依赖获取路径**：本机只有部分国内镜像可达（crates.io / static.crates.io / github / rust-lang 全不通）。cargo 用 `~/.cargo/config.toml` 的 sparse 源替换指向阿里云镜像（`sparse+https://mirrors.aliyun.com/crates.io-index/`，已验证可下载）；rustup 用 `RUSTUP_DIST_SERVER=https://mirrors.aliyun.com/rustup` 升级工具链（egui 0.36 要 rustc ≥1.95，本机原 1.94）。下次换机器先测这三条通路再动工。
- **WinDivert 集成方式：static 而不是 vendored DLL**。windivert-sys 的 `vendored` 特性只编译出 DLL 并按 import lib 链接——WinDivert.dll 缺失是**进程加载失败**（STATUS_DLL_NOT_FOUND），一个可选功能把整个程序拖死；`static` 把用户态库静态编入 exe，只有真正开启捕获才需要旁边放 `.sys`，缺文件时 WinDivertOpen 返回可映射的错误。教训：可选能力的运行期依赖绝不能放在**加载期**。
- **vendored 源码不含驱动二进制**：WinDivert 2.x 的官方 DLL 里嵌的是驱动，但 crate vendored 的是纯 C 源码，编译产物不嵌入 `WinDivert64.sys`（内核态编译需 WDK）——所以运行期必须放官方签名 `.sys`，且版本要与静态编入的源码一致（2.2.2）。
- **流重组的锚点必须是 SYN 的 ISN+1，不是"第一段数据"**。单测里先发数据段再发更早的数据段时暴露：锚在乱序先到的段上，后来补齐的"前缀"会被当旧段丢弃，重组出中段子串。修法是 full 模式观测到 SYN 时 `seed(ISN+1)`。这也是"生产语义定锚点"的通用教训。
- **模糊测试的输入构造必须先对齐生产语义**（第二轮又栽在这）：随机把重复段插到分片数组**头部**，锚点就成了中段，断言"重组结果=源序列前缀"必挂——fuzz 挂了先怀疑 harness 而不是被测代码。
- **检测器映射表要有容量上限**：伪造源 IP 的 SYN 洪泛能无限制造新键（`HashMap<源IP, …>`），10 秒一次的 sweep 也兜不住。到达上限后只更新已跟踪来源、拒收新键——内存有界，且攻击者换源等于放弃被跟踪，降级方向正确。
- **WinDivert 的 SNIFF 标志语义要读驱动源码确认：它是"不吸收、只给副本"，不是"发送时不改校验和"**。初版按"recv→注回"写，读 vendored 驱动源码才发现 SNIFF 模式下驱动不设 BLOCK/ABSORB（`windivert.c` 网络层 classify 末尾 `if (!sniff_mode)`），匹配包**同时**走协议栈与用户态句柄——再 `send()` 就是重复注入（SYN 发两遍、full 模式全量重复）。正确姿势：嗅探模式只收不发，天然"捕获线程死了也不影响网络"，比注回模式少一类故障面。教训：第三方 C 库的标志语义别按记忆写，`vendor/` 里有源码就直接读。
- **单机 E2E 够不着的分支要用可注入依赖补测试**：本机所有流量源必是回环/私网（内网保护会拦下封禁分支），真实自动封禁无法在单机触发。把封禁出口抽成 `apply_block(fw, store, bus, …)` + `DetectionSink`，用 mock 防火墙断言"公网 IP 封禁+TTL 记账 / 内网零封禁 / 开关关闭 / 空规则拒绝"，再用真实 Windows 防火墙跑一遍 API 加删规则验证后端本身。
- WinDivert 的过滤表达式大小写不敏感（`tcp.Syn == 1 and tcp.Ack == 0`）；纯 SYN 判定要在过滤器里排掉 SYN-ACK（`Ack == 0`），否则回包方向也会被当成扫描样本。

## 0.3 第三批 · Linux AF_PACKET 捕获（2026-09-28）

- **全 crate 交叉类型检查被 ring 卡死时，用"只含目标平台依赖的临时 crate"检查平台代码**：detect crate 因 reqwest→ring（需 Linux C 工具链）无法在 Windows 交叉 check，但新写的平台代码路径可以抽出来放进 `target/` 下的临时 crate（桩掉 `CapturedFrame`/`now_ts`，带上 rustix/etherparse），`cargo check --target x86_64-unknown-linux-gnu` 秒级完成——这一步抓到了 `Errno::ACCES` 拼错（rustix 1.1 里叫 `ACCESS`，`ACCES` 只是 doc alias）。临时 crate 不进仓库，用完即删。
- **rustix 1.1.5 的 `net` 特性单独启用在 Linux 上编译不过**：linux_raw 后端的 `net/sockopt.rs` 引用 `crate::timespec`，而 `mod timespec` 的 cfg 门控需要 fs/event/process/runtime/thread/time 之一——net 不在名单里。解法：同时启用 `time`（`features = ["net", "time"]`）。这是上游特性声明漏洞，升级 rustix 后可试着去掉 time。
- **rustix 的 Errno 变体名去掉 E 前缀但不是机械截断**：`EACCES → ACCESS`（不是 `ACCES`）。写 match 前先 grep 源码确认（`src/backend/linux_raw/io/errno.rs`），doc alias 里的老名字不能用于匹配。
- **AF_PACKET 的语义对齐点**：①它给的是 L2 以太网帧（WinDivert NetworkLayer 给 L3），必须剥离后才能进同一管线——剥头偏移只有 14（以太网）/18（单层 802.1Q），做成纯函数全平台可测；②它没有内核过滤表达式，WinDivert 在内核做的事（control 只放纯 SYN、full 放 TCP）要在捕获线程用用户态预过滤补上，否则 flow 表语义漂移 + 高流量主机会把 4096 容量的帧通道灌满；③默认不开混杂模式，只收本机相关帧——正好符合隐私红线，别去加 PACKET_ADD_MEMBERSHIP。
- **文案是行为的一部分**：GUI 设置页 0.3.1 留了一句"采样为被动观测（包原样注回）"——SNIFF 模式恰恰**不注回**（LESSONS 上一批刚记录），代码改对了但说明文字没跟着改。改行为时全仓库搜一遍旧描述（"注回"），说明文字与行为漂移比代码 bug 更误导。

## 0.3 第四批 · AI 深度介入（2026-09-28）

- **GUI 的 `self.eng` 是 `Arc<dyn Console>` 不是 EngineHandle**：给引擎加新能力（promote_rule/mark_false_positive）必须三处一起动——Console trait + EmbeddedConsole（`self.0.xxx().map_err(anyhow::Error::msg)`）+ RemoteConsole（HTTP → 新端点）。只改 EngineHandle 时 GUI 编译报 E0599 "method not found in `Arc<dyn Console>`"——trait 是 GUI/API 双通道契约，0.2 服务化时就该记住的纪律。
- **AI 应用即灰度是语义对齐，不是新功能**：AI 判断是概率性的，"应用"不该等于"永久封禁"。AI 规则默认短 TTL（AI 给 `ttl_secs` 用它的、否则 `[ai].trial_ttl_secs` 默认 900s），人工"转正"才延长（`promote_ttl_secs` 默认 30 天）——复用既有 TTL 清扫任务与 rules.expires_ts 记账，零新执行器。永久 AI 规则（0.3.3 前）转正要明确拒绝（否则"转正"反而把永久降成 30 天）。
- **误报"学习" = 本地抑制 + 提示词反馈，不训模型**：`fp_feedback` 表按 IP 聚合（count/first_ts/last_ts/note，ON CONFLICT 累加）+ `active_fp` 查询（handle_detection/auto_apply 跳过抑制来源）+ `<feedback>` 段进提示词。零推理成本、每次跳过留痕可审计、TTL 到期自然失效。
- **reqwest blocking 的 `post_json` 返回 Response 不是 Value**：忘接 `.json()?` 就是 E0308 "expected `Value`, found `Response`"。远程 Console 的响应解析与内嵌不同形——内嵌直返结构体，远程要 JSON 反序列化，两套返回形状分别对。
- **`cargo check` 不编译 `#[cfg(test)]` 代码**：改方法签名（insert_proposal 加 ttl_secs 参数）后 `cargo check` 全绿、`cargo clippy --all-targets` 才炸 E0061——测试调用点漏改。CI 门禁必须用 `--all-targets`。
- **长会话里"我做过什么"的记忆会自己长出内容**：本轮多次出现编辑结果与记忆互相矛盾（"成功"与"失败"并存、同文件两个路径拼写、工具输出与 grep 不一致）。机械协议：每步编辑后立即 `cargo check`，以编译器输出为唯一事实源；状态彻底可疑时 `git stash push`（可逆兜底）→ `git status`/`git diff --stat HEAD` 机械核对 → `git stash pop` 恢复——stash 往返零丢失，比在矛盾记忆里继续编辑安全得多。
- **Edit 被拒"File has not been read yet"是防线在工作**：只 grep/sed 过的文件（Bash 读）不算"已读"，Edit 工具要求 Read 工具读过才放行——被拒就老老实实 Read 再改，绝不凭记忆写 old_string。被拒的编辑不落盘，这本身就是保护。
