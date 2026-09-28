# Windows 采样捕获实机验证清单（0.3 检测平台 MVP）

> 对应 docs/LINUX-TESTING.md 的 Windows 版：WinDivert 需要官方签名驱动
> `WinDivert64.sys`，本仓库不分发该文件（LGPL/GPL 上游许可，见 docs/COMPLIANCE.md）。
> 本清单在一次联网环境执行即可全部打完勾。

## 1. 准备驱动文件

1. 从官方渠道下载 WinDivert 2.2.2（<https://reqrypt.org/windivert.html> 的
   `WinDivert-2.2.2-A.zip`）。
2. 解压后取出 **`WinDivert64.sys`**（64 位程序用；32 位用 `WinDivert32.sys`），
   放到 `aisafeguard.exe` 同目录（`target\release\` 或服务安装目录）。
   - 用户态库无需 DLL：WinDivert 用户态部分已静态编入 exe；
   - `.sys` 由 WinDivert 在首次打开句柄时自动安装/启动服务（需要管理员/服务权限）。
3. 校验版本匹配：本仓库静态编入的 WinDivert 源码版本为 **2.2.2**
   （`windivert-sys` vendored 源码 VERSION 文件）；混用其他版本的 `.sys`
   会在状态里报 "驱动版本不兼容"。

## 2. 开启捕获

编辑 `config.toml`（GUI 设置页也可改开关与模式）：

```toml
[detect.capture]
enabled = true
mode = "control"          # control=仅 SYN 元数据；full=全 TCP 段+流重组取证
scan_distinct_ports = 15  # 窗口内不同目标端口数
syn_flood_rate = 100      # 同一 (来源, 目标:端口) 窗口内 SYN 数
window_secs = 60
```

以管理员运行（或装成服务 `service install` 后由服务捕获）：

```powershell
.\aisafeguard.exe --headless
```

期望：事件流水出现 `流量采样已启动（windivert / control 模式）`；
`GET /api/status` 的 `capture.active = true`。

## 3. 验证清单

| # | 操作 | 期望 |
|---|---|---|
| 1 | 扫描本机 20 个高位端口（`nmap -p 30000-30019 <本机IP>` 或 PowerShell 循环连接） | `detection` 事件（`[scan] … 秒内对 N 个不同目标端口发送 SYN`，rule_id=builtin.tcp_scan）；来源为内网/回环时同时出现"内网保护：跳过自动封禁" |
| 2 | 从另一主机对同一目标端口快速发起大量 SYN（如 `hping3 -S -p 445 --flood`） | `detection` 事件（`[flood] … 发送 N 个纯 SYN`，rule_id=builtin.syn_flood）；公网来源会被自动封禁并在规则表可见（TTL 到期自动解封） |
| 3 | 捕获开启状态下正常浏览/下载 | 网络无中断、无丢包异常（SNIFF 嗅探：包同时在协议栈正常流转，句柄只拿副本，无重复注入、无吸收） |
| 4 | full 模式重复 #1（用浏览器访问一个 HTTP 端口触发扫描判定后立即发请求） | 判定证据追加 `载荷摘要: …`（截断 120 字符、控制字符已清洗） |
| 5 | 结束进程/停服务 | 主机网络立即可用，无残留 WinDivert 句柄影响 |
| 6 | 删除 `WinDivert64.sys` 后启动 | 引擎正常运行，状态 `capture.note` = "缺少 WinDivert64.sys 驱动文件…"；蜜罐/AI/API 不受影响 |

## 4. 故障排查

| 状态/事件里的提示 | 含义与处置 |
|---|---|
| 缺少 WinDivert64.sys 驱动文件 | 按 §1 放置官方 `.sys` 到 exe 同目录 |
| 需要管理员权限 | 以管理员运行，或用 `service install` 装为服务（LocalSystem） |
| WinDivert64.sys 数字签名无效 | 使用官方发行版文件（第三方重打包可能被改写） |
| WinDivert 驱动被安全软件拦截 | 在 EDR/杀软中放行官方驱动；这是 WinDivert 的常见误报，发布物代码签名后缓解 |
| Base Filtering Engine 服务被禁用 | `sc config BFE start= auto && net start BFE`（Windows 防火墙依赖它） |
| 已加载的 WinDivert 驱动版本不兼容 | 重启系统，或统一 `.sys` 与程序版本（均 2.2.2） |

## 5. 隐私红线核对（NGFW_EVOLUTION §3）

- control（默认）：只采集 TCP 纯 SYN 包头，不接触载荷；证据仅含端口/计数。
- full：载荷进入内存重组缓存（每流 ≤8KB、缓存表 ≤1024 流），
  且**只有被判定可疑的来源**其流前缀会作为证据截断留存（≤120 字符、控制字符清洗）。
- 流表只存元数据与计数；重启即清空（不落盘）。
