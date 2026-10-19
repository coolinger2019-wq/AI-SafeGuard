# F750 ET Open 精选子集——终选记录（2026-10-18）

> 生成管线：`scripts/et-select.py`（初筛）→ `crates/aisafeguard-rules/examples/et_replay.rs`（回放校准+修复循环）。
> **规则文本不进 git**（ET Open 再分发许可不确定性）——本页只留选包漏斗、终选清单与 SHA-256 留痕；
> 月度刷新 = 重跑管线（ET 上游每日更新），成本一次脚本运行。

## 选包漏斗（ET Open 2026-10-19 快照，51022 条 alert）

| 阶段 | 数量 |
|---|---|
| 语法白名单通过（v1 子集） | 20643 |
| 剥离 reference（纯元数据） | 24012 处 |
| 剥离 fast_pattern（性能提示） | 20500 处 |
| 越界关键字淘汰（http_* 缓冲区/byte_*/flowbits/file_data 等） | ~22000 |
| 白名单外 classtype（misc-activity 等） | 2989 |
| 初筛候选（相关性+严重度排序） | 200 |
| 整包修复剔除（pcre 超体积 / /H /U /R 等不支持标志） | 42 |
| 方向终选淘汰（出站 CnC 类：蜜罐路径结构性不可达） | 59 |
| 可见性终选淘汰（入站二进制 content：脱敏窗口不可达，capture 开启后的扩展面） | 48 |
| **终选** | **49** |

## 终选包

- 文件：本地生成 `et-open-subset.rules`（49 条，全部入站、纯文本 content）
- SHA-256（规则文件字节）：`41a41b2994e4043810b8151ec9eab16b59b3578f193e1e6e3dc71b12663851f9`
- SHA-256（加载器 join 后字节）：`0c3ff15380cf5335…`——差异仅为尾部空行，留痕以文件哈希为准
- 回放校准：26882 事件（14 天窗口全部非空蜜罐载荷）/ 3910579 字节窗口 → **0 命中 = 0 误报**
  —— 零命中按预注册红线保留（保险单），不是淘汰项
- 匹配基准：49 条规则 @ 3922 ns/事件（158 条时 6137 ns/事件）——26.8k 事件全扫 105ms，性能无虞
- 对照组：demo.rules（自写 16 条）同库命中 6/16——自写规则对本产品暴露面的命中率高于 ET 子集（预期内：demo 按我们实际 TTP 定制）

## 启用方法

```toml
[detect.rules]
enabled = true
path = "/etc/aisafeguard/et-open-subset.rules"   # 由 et-select.py 管线生成
auto_block = false                                # 观察期不自动封禁
```

## 终选清单（49 条）

| sid | classtype | dport | msg |
|-----|-----------|-------|-----|
| 2006443 | web-application-attack | [8081,8000] | ET WEB_SERVER Possible SQL Injection Attempt DELETE FROM in HTTP URI |
| 2006444 | web-application-attack | [8081,8000] | ET WEB_SERVER Possible SQL Injection Attempt INSERT INTO in HTTP URI |
| 2006446 | web-application-attack | [8081,8000] | ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT in HTTP URI |
| 2008175 | attempted-admin | [8081,8000] | ET WEB_SERVER Possible SQL Injection (varchar) in HTTP URI |
| 2008176 | attempted-admin | [8081,8000] | ET WEB_SERVER Possible SQL Injection (exec) in HTTP URI |
| 2008467 | attempted-admin | [8081,8000] | ET WEB_SERVER Possible SQL Injection Attempt Danmec related (declare) in HTTP URI |
| 2009043 | attempted-admin | [8081,8000] | ET SCAN SQLNinja Attempt To Recreate xp_cmdshell Using sp_configure |
| 2009044 | attempted-admin | [8081,8000] | ET SCAN SQLNinja Attempt To Create xp_cmdshell Session |
| 2010037 | web-application-attack | [8081,8000] | ET WEB_SERVER Possible SQL Injection INTO OUTFILE Arbitrary File Write Attempt in HTTP URI |
| 2011042 | web-application-attack | [8081,8000] | ET WEB_SERVER Possible SQL Injection SELECT CONCAT in HTTP URI |
| 2011122 | web-application-attack | [8081,8000] | ET WEB_SERVER Possible SQL injection obfuscated via REVERSE function in HTTP URI |
| 2011424 | web-application-attack | [8081,8000] | ET WEB_SERVER Possible SQL Injection Using MSSQL sp_configure Command in HTTP URI |
| 2016596 | attempted-admin | [8081,8000] | ET WEB_SERVER Possible SQL Injection (varchar2) in HTTP URI |
| 2016936 | web-application-attack | [8081,8000] | ET WEB_SERVER SQL Injection Local File Access Attempt Using LOAD_FILE |
| 2018107 | web-application-attack | [8081,8000] | ET WEB_SPECIFIC_APPS JoomSocial AvatarUpload RCE |
| 2018495 | attempted-admin | [9200,9292] | ET WEB_SERVER Possible CVE-2014-3120 Elastic Search Remote Code Execution Attempt |
| 2020648 | attempted-admin | [9200,9292] | ET WEB_SERVER Possible CVE-2015-1427 Elastic Search Sandbox Escape Remote Code Execution Attempt |
| 2024980 | attempted-admin | [23,2323] | ET EXPLOIT Actiontec C1000A backdoor account M2 |
| 2025080 | attempted-admin | [23,2323] | ET EXPLOIT Actiontec C1000A backdoor account M1 |
| 2025929 | attempted-admin | [8081,8000] | ET WEB_SPECIFIC_APPS Oracle WebLogic Deserialization (CVE-2018-2893) |
| 2050095 | attempted-admin | [8081,8000] | ET WEB_SPECIFIC_APPS Ivanti Pulse Secure Authentication Bypass and Command Injection Attempt (CVE-2023-46805, CVE-2024-21887) M1 |
| 2053467 | attempted-admin | [8081,8000] | ET WEB_SERVER Possible SQL Injection SELECT CAST in HTTP URI |
| 2053479 | attempted-admin | [8081,8000] | ET WEB_SERVER Possible SQL Injection WAITFOR DELAY in HTTP URI |
| 2056733 | attempted-admin | [8081,8000] | ET WEB_SPECIFIC_APPS D-LINK DIR-845L Information Disclosure Attempt (CVE-2024-33113) |
| 2069653 | web-application-attack | [8081,8000] | ET WEB_SPECIFIC_APPS Gitea Container Registry Unauthorized Private Image Access (CVE-2026-27771) |
| 2100981 | web-application-attack | [8081,8000] | GPL EXPLOIT unicode directory traversal attempt |
| 2100982 | web-application-attack | [8081,8000] | GPL EXPLOIT unicode directory traversal attempt |
| 2100983 | web-application-attack | [8081,8000] | GPL EXPLOIT unicode directory traversal attempt |
| 2101008 | web-application-attack | [8081,8000] | GPL ATTACK_RESPONSE del attempt |
| 2101059 | web-application-attack | [8081,8000] | GPL EXPLOIT xp_filelist attempt |
| 2101071 | web-application-attack | [8081,8000] | GPL WEB_SERVER .htpasswd access |
| 2101334 | web-application-attack | [8081,8000] | GPL EXPLOIT echo command attempt |
| 2101661 | web-application-attack | [8081,8000] | GPL EXPLOIT cmd32.exe access |
| 2000105 | attempted-user | [8081,8000] | ET WEB_SERVER SQL sp_password attempt |
| 2000106 | attempted-user | [8081,8000] | ET WEB_SERVER SQL sp_delete_alert attempt |
| 2008518 | attempted-user | [8081,8000] | ET EXPLOIT SQL sp_configure attempt |
| 2010004 | attempted-user | [8081,8000] | ET WEB_SERVER SQL sp_start_job attempt |
| 2015552 | trojan-activity | [8081,8000] | ET SCAN HTExploit Method |
| 2021179 | trojan-activity | [139,445] | ET TROJAN Possible BlackEnergy Accessing SMB/SMB2 Named Pipe (ASCII) |
| 2021230 | trojan-activity | [139,445] | ET TROJAN Possible Duqu 2.0 Accessing SMB/SMB2 Named Pipe (ASCII) 1 |
| 2021231 | trojan-activity | [139,445] | ET TROJAN Possible Duqu 2.0 Accessing SMB/SMB2 Named Pipe (ASCII) 2 |
| 2021232 | trojan-activity | [139,445] | ET TROJAN Possible Duqu 2.0 Accessing SMB/SMB2 Named Pipe (ASCII) 3 |
| 2021233 | trojan-activity | [139,445] | ET TROJAN Possible Duqu 2.0 Accessing SMB/SMB2 Named Pipe (ASCII) 4 |
| 2021234 | trojan-activity | [139,445] | ET TROJAN Possible Duqu 2.0 Accessing SMB/SMB2 Named Pipe (ASCII) 5 |
| 2021235 | trojan-activity | [139,445] | ET TROJAN Possible Duqu 2.0 Accessing SMB/SMB2 Named Pipe (ASCII) 6 |
| 2023549 | trojan-activity | [5555,7547] | ET EXPLOIT Eir D1000 Modem CWMP Exploit Retrieving Wifi Key |
| 2025788 | attempted-user | 1024: | ET EXPLOIT Oracle Weblogic Server Deserialization Remote Command Execution |
| 2027181 | trojan-activity | [139,445] | ET POLICY WMIC WMI Request Over SMB - Likely Lateral Movement |
| 2027182 | trojan-activity | [139,445] | ET POLICY WMIC WMI Request Over SMB - Likely Lateral Movement |

— 生成于 2026-10-19 17:33
