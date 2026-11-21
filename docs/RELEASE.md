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

## musl 静态链接 spike（2026-11-21，只出数据不实施）

plan 0.9-B 项。v0.8.3 glibc 前向不兼容事故（LESSONS 2026-11-15：runner 漂到
glibc 2.43、24.04 部署机 2.39，二进制启动即崩防护下线）的终极解验证——
当前解法是钉 `runs-on: ubuntu-24.04`，musl 若可行则连这个对 runner 漂移的
信任都可以去掉。spike 在生产 VPS（Ubuntu 24.04.5，1 核）/tmp 内完成，
未触碰生产服务与二进制；musl-tools 与 rustup target 留存无害。

### 构建结果：一次通过，零代码改动，零 CC 配置

环境：rustc 1.99.0 / musl-gcc（gcc 13.3.0 wrapper）。仓库原样浅克隆，
`cargo build --release --target x86_64-unknown-linux-musl --bin aisafeguard`
直接成功（23m08s，1 核 VPS；CI runner 会显著更快），未设任何 `CC*` 环境变量，
cc crate 自动找到 musl 工具链。预判的坑点全部没踩：

| 风险点 | 结果 |
|---|---|
| ring 0.17（rustls/rcgen/签名同栈） | musl 编译通过 |
| aya 0.13（XDP/eBPF，Linux 目标必编） | 编译通过 |
| rusqlite bundled（libsqlite3-sys C 编译） | 编译通过，运行正常 |
| eframe/egui/winit/accesskit（无 gui gate，无条件编入） | 全栈编译通过 |
| rfd / russh(ring) / rustls / reqwest(rustls) / notify / sysinfo | 编译通过 |

### 体积与静态性

- musl 产物 40,484,512 字节（40.48 MB）vs 生产 gnu 0.8.3 二进制 40,500,880
  字节（40.5 MB）——几乎持平（strip + thin LTO 两者同开）。
- `file`：static-pie linked；`ldd`：statically linked；`readelf -d`：
  无任何 NEEDED 条目。全静态 + PIE，ASLR 保留。
- 构建中间产物 target/ 约 1.6G（CI 缓存口径参考）。

### 运行验证（VPS 实测）

- `aisafeguard --version`：正常输出 0.8.3，exit 0。
- `aisafeguard verify-log --data-dir <空目录>`：exit 0，「哈希链完整：
  0/0 条事件校验通过」，并自动建库——bundled SQLite 链接与运行时行为正常。

### 注意点

- **DNS 解析**：musl 用内置 resolver，直读 `/etc/resolv.conf` 与 `/etc/hosts`，
  不走 nsswitch——静态链接二进制本来也不能 dlopen glibc NSS 模块，所以这不是
  musl 新增的限制。本项目只做普通 A/AAAA 查询（AI 端点、GitHub/Gitee、fed 节点
  域名），行为无差异；若未来遇到 systemd-resolved 通配域、LDAP/mDNS 类企业
  解析需求才需要重新评估。
- **与 gui gate（P2-10）的关系**：本 spike 未依赖 gui gate，egui 树在 musl 下
  完整编译通过——两件事正交。若日后实施 gui gate（headless 314 包 vs 全量
  417 包），musl 产物还能再瘦一圈。
- 静态二进制对 systemd 部署、deploy.sh 回滚逻辑、CI 签名流程均无影响。

### 结论：建议正式 Release 构建切 musl

零代码改动、体积持平、全静态彻底消除「构建机 glibc ≥ 部署机」这一整类供应链
漂移事故，运行验证通过。CI 落地步骤（不是零配置）：build.yml Linux job 需加
`apt install musl-tools` + `rustup target add x86_64-unknown-linux-musl` +
`--target` 参数（runner 镜像默认没有 musl-tools——spike 第一步就是装它）。
切换后 ubuntu-24.04 的 runs-on 钉版从"必要守门"降级为"可松绑的偏好"。
落地属于 0.9-B 实施（build.yml 双平台矩阵 + 验证一轮发布产物），本 spike 不实施。
