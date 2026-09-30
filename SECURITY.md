# 安全策略与漏洞披露

AI-SafeGuard 自身是一门"安全软件"，它自己的漏洞按最高标准对待。

## 支持版本

| 版本 | 状态 | 安全修复 |
|---|---|---|
| 0.2.x | ✅ 支持 | 接收修复 |
| 0.1.x | ⛔ 已停止 | 请升级到 0.2.x |
| < 0.1 | ⛔ 已停止 | 不适用 |

## 如何报告漏洞

**请不要在公开 Issue 中报告安全漏洞。**

- 首选：GitHub Security Advisories（仓库 Security 标签页 → Report a vulnerability，私有通道）
- 备选：security@aisafeguard.example（占位邮箱，正式发布前替换为受监控邮箱并公布 PGP 公钥）

报告请包含：影响版本与平台、复现步骤或 PoC、影响评估（能做什么/不能做什么）、可能的修复思路（如有）。

## 响应承诺

| 阶段 | 时限 |
|---|---|
| 确认收到 | 48 小时内 |
| 初步评估（定级 + 影响范围） | 7 天内 |
| 高危（可远程利用/提权/绕过防护）修复 | 30 天内 |
| 中低危修复 | 下一个功能版本 |

全程与报告者保持沟通；发布修复时在 Release Notes 中致谢（除非报告者要求匿名）。

## 报告范围

**属于**：本仓库全部自有代码（`crates/` 下六个 crate）——内存安全、提示注入绕过（AI 建议 schema 校验、不可信数据隔离）、本地 API 鉴权、防火墙操作边界、蜜罐进程逃逸/资源耗尽、哈希链完整性。

**不属于**：第三方依赖自身的漏洞（请按其披露流程报告，我们会跟进升级）；需要已获得管理员权限的本地攻击场景（除非构成提权路径）；对蜜罐的"成功欺骗"（那本来就是设计目标）。

## 安全设计基线（审核提示）

- 自有代码全部 `#![forbid(unsafe_code)]`
- LLM 输出视为不可信输入：allowlist 校验、非法即作废、永不进入命令执行层
- 密钥与 API token 存 Windows 凭据管理器，配置文件不承载秘密
- 事件哈希链防篡改（`aisafeguard verify-log` 可离线校验）——注意：外发通道的验签
  （如 webhook HMAC）只证明传输完整性，**不构成可审计证据**（可审计 = 本地哈希链 +
  fed 消息级证书签名，见 docs/THREAT_MODEL.md「证据语义」）
- 供应链：cargo-deny + cargo-audit 进 CI 门禁，SBOM 经 cargo-auditable 嵌入二进制

详见 [docs/COMPLIANCE.md](docs/COMPLIANCE.md) 与 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
