# Suricata/ET 风格规则子集规范（v2）

> 对应 ROADMAP-0.5.md Batch F1（P0）。**本文件冻结规则子集范围**：
> 超出本规范的关键字/动作/修饰符 → 规则加载失败（整包拒绝，不半生效）。
> 变更本文件 = 显式版本 bump。**v2（2026-10-20，F780）**：新增五个粘性缓冲区关键字
> （http_method/http_uri/http_header/http_user_agent/http_client_body，sticky 前置与
> modifier 后置两形态等价）+ pcre 快捷标志映射（/U /I /P /H，/Hm 系容忍）；
> 其余 http_*/tls.*/file_data 仍拒绝；pcre 白名单/线性时间/4KB 上限红线不放松。
> 原注：变更本文件 = 显式版本 bump（v1 → v2），并同步匹配引擎实现与测试。

## 设计立场

- **只做 Rust 匹配引擎，不自造规则格式**：语法对齐 Suricata 规则书写习惯，
  复用社区维护的规则集（ET 开放规则集）的**书写子集**。
- **不是 Suricata 兼容引擎**：不承诺字节级行为一致、不支持运行时全语义。
- **命中只产事件**：规则引擎 crate 禁止依赖 `aisafeguard-firewall`（依赖图强制）；
  是否自动封禁由 0.4 的 `handle_detection` 出口与 `[detect.rules].auto_block` 决定（默认 false）。

## 支持的语法（v1 白名单）

### 规则头（header）

| 字段 | 支持 | 说明 |
|------|------|------|
| 动作 | `alert` | 仅 alert；`pass`/`drop`/`reject` 不支持（处置归执行器） |
| 协议 | `tcp` `udp` | 其余（icmp/ip/http 等）不支持 |
| 源地址 | 任意单 IP 或 `$HOME_NET`/`$EXTERNAL_NET`/`any` | CIDR 支持；地址组仅上述两个内置变量 |
| 源端口 | `any` 或单端口/端口列表（如 `!80, [1:1024]` 的范围形式） | 有限集 |
| 方向 | `->` `<>` | |
| 目标地址/端口 | 同源 | |

### 规则选项（options）

| 关键字 | 支持 | 说明 |
|--------|------|------|
| `msg` | ✅ | 必填（无 msg 的规则拒绝） |
| `sid` | ✅ | 必填，全局唯一（重复 sid 整包拒绝） |
| `rev` | ✅ | 记录，不参与匹配 |
| `classtype` | ✅ | 映射到 Detection severity（白名单：attempted-admin/web-application-attack/malware-cnc 等 10 类，见映射表） |
| `content` | ✅ | 多 content 顺序 AND；支持 `|hex|` 转义与 `offset`/`depth`/`distance`/`within` 修饰符（有限数值） |
| `nocase` | ✅ | 仅作用于紧邻的 content |
| `pcre` | ✅ | 有限正则：编译大小 ≤ 4KB、执行预算超时拒绝（防灾难回溯）；`/.../i` 与 `/.../R` 标志子集 |
| `flow` | ✅ | `established` `to_server` `from_server`（组合用逗号） |
| `threshold` | ✅ | `type both/limit, track by_src, count N, seconds S` 子集 |
| `metadata` | ✅ | 透传为标签（不参与匹配） |

### 明确不支持（加载失败）

`byte_test`/`byte_jump`、`isdataat`、`datasets`、`xbits`、`flowbits`、`ipbits`、
`lua`、`base64_*`、`filestore`/`file.*`、`http_*` sticky buffer（0.5 用 content 近似）、
`tls.*` sticky buffer、`decode`、`replace`、`drop`/`sdrop` 动作、
地址组自定义变量定义（`var`）、`include`。

## 映射表（classtype → severity）

| classtype | severity |
|-----------|----------|
| attempted-admin, web-application-attack, attempted-user | critical |
| malware-cnc, trojan-activity, policy-violation | high |
| scan, attempted-dos, bad-unknown | medium |
| 其余白名单内 classtype | low |

## 加载治理（F5）

- 规则包 = 本地文件（`[detect.rules].path`），**默认不内置任何规则包**。
- 加载失败（任何一条越界/语法错/sid 重复）→ **整包拒绝**，事件留痕，不半生效。
- `max_rules = 5000` 上限；单条 content 长度 ≤ 512 字节；单文件 ≤ 5MB。
- 规则文件 SHA-256 记录进加载事件（可选钉扎比对）。

## 匹配语义（F3）

- 匹配窗口：蜜罐 payload（完整）、采样 full 模式重组流前缀（≤8KB）、control 模式不匹配。
- 多 content：按出现顺序在窗口内 AND（支持 offset/depth 锚定）。
- 命中产出：`SecurityEvent::Detection { kind: "signature", rule_id: "sid:<n>",
  evidence: "<msg>（规则 <sid> v<rev>）", confidence: "high", … }`（0.4 口径）。

## v1 边界重申（Won't）

文件还原、TLS 解密、LUA、app-layer 状态机、自动规则更新、
与 Suricata 引擎字节级兼容——全部不在 0.5（见 ROADMAP-0.5 §7）。
