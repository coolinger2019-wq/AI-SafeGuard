# 发布签发流程（P0-3）

发布完整性 = SHA-256 清单 + ECDSA P-256 签名。CI 对每个发布物附带的 `.sha256`
逐文件签出 `.sha256.sig`；客户端自更新下载 zip → 校验 `.sha256` → 对其验签：
签名缺失（存量 release）跳过并告警；**签名不符硬失败**，中止升级——sha 清单
与二进制同源被替换时，没有私钥伪造不出有效签名。

## 密钥体系

- 算法：ECDSA P-256（ring）。签名 = fixed-width 64 字节 R||S（ring 原生格式，
  非 openssl DER——CI 用 aisafeguard 自家二进制自签自验，无 DER 转换歧义）。
- 私钥：PKCS#8 DER hex（`gen-signing-key` 产出）。只存 GitHub Secret
  `AISAFEGUARD_SIGNING_KEY`，不入库、不入日志、不进 chat。私钥丢失 = 无法再签出
  可被当前客户端验签的发布物，只能换 keypair 并重走一次性配置。
- 公钥：非压缩点 hex（65 字节，`04||X||Y`），嵌入
  `crates/aisafeguard-app/src/update.rs` 的 `SIGNING_PUBKEY_HEX`，随二进制分发。
- 公钥指纹：公钥点字节的 SHA-256（`gen-signing-key` 会打印），发布页公示，
  供人工核对公钥未被调包。
- 已知限制：私钥 hex 以 `String` 存在于 `sign-manifest`/`gen-signing-key` 进程
  内存直至退出，无法 zeroize（ring 不提供擦除接口，hex 载入即成堆上明文）。
  两个命令都是离线维护者工具、进程秒级退出，不常驻内存、不落盘，可接受；
  若未来做成常驻服务需重新评估。

## 一次性配置

1. 本机生成密钥对（离线操作）：

   ```
   aisafeguard gen-signing-key
   ```

   记下输出的私钥 hex、公钥 hex、公钥指纹。
2. GitHub 仓库 → Settings → Secrets and variables → Actions → New repository
   secret：Name 填 `AISAFEGUARD_SIGNING_KEY`，Secret 值 = 私钥 hex。
3. 把公钥 hex 填入 `update.rs` 的 `SIGNING_PUBKEY_HEX`（当前是 64 个 `'0'` 占位，
   占位期间自更新跳过验签并告警）并发布一个带新公钥的版本。自该版本起的客户端
   才能自动验签后续 release；更早的客户端嵌的是占位公钥，对 `.sig` 会跳过验签
   并告警（不影响其升级）。

## 日常发布（CI 自动签名）

```
git tag v0.8.4 && git push origin v0.8.4
```

build.yml 的 release job：双平台构建 → 下载产物 → 用 build-linux 产物里的
aisafeguard 对三个 `.sha256` 逐文件签出 `.sha256.sig` → 一并上传 Release。
secret 未配置时 CI 打 warning 跳过签名（Release 照常发布，客户端对缺 `.sig`
的 release 也跳过验签，不会失败）。

**Gitee 镜像（国内主源，验签同样生效）**：CI 签名完成后跑
`bash scripts/gitee-release.sh <tag>`，脚本从 GitHub Release 下载产物
（含 `.sha256.sig`）镜像到 Gitee Release。镜像顺序必须先 GitHub 后 Gitee：
签名只发生在 GitHub CI，先镜像后签名会漏掉 `.sig` 资产。self-update 的
Gitee 源与 GitHub 源走同一条验签路径，`.sig` 缺失同样只告警不阻断
（存量 release 兼容），验签失败同样硬退。

## 手动验签（下载后核对，可选）

```
# 1) 常规校验和（zip 本体）
sha256sum -c aisafeguard-windows-x64.zip.sha256

# 2) 对 .sha256 清单本身验签（清单与签名配对，防同源调包）
aisafeguard verify-manifest aisafeguard-windows-x64.zip.sha256 \
  --sig "$(cat aisafeguard-windows-x64.zip.sha256.sig)" \
  --pubkey <发布页公示的公钥 hex>
```

`verify-manifest` 退出码 0 = 通过；非 0 = 清单或签名被替换，请勿使用该发布物。
