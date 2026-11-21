//! P1-7 备份/恢复（COMPLIANCE.md A.8.13 收口）。
//!
//! backup：aisafeguard.db / honeypot/credentials.db 用 `VACUUM INTO`（SQLite
//! 3.27+，bundled rusqlite）做在线一致性快照——只读连接 + 读事务，WAL 模式下
//! 引擎运行中安全，快照含未 checkpoint 的内容；config.toml 与 fed/ 证书目录
//! 逐文件拷入；manifest.json 记录文件清单 + sha256 + 源数据目录 + 时间戳。
//! restore：反向恢复，现有同名文件改名 *.restore-bak-<时间戳> 留痕，恢复完
//! 自动跑 verify-log 校验哈希链。不做加密不做云上传（备份保管是运营者的事）。

use std::path::{Component, Path, PathBuf};

use aisafeguard_store::Store;
use chrono::Local;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct ManifestFile {
    /// 相对备份目录的路径，统一用 `/` 分隔（跨平台稳定，restore 按此分发）
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    app_version: String,
    created: String,
    source_data_dir: String,
    source_config_path: String,
    files: Vec<ManifestFile>,
}

/// `aisafeguard backup <输出目录>`
pub fn cmd_backup(data_dir: &Path, config_path: &Path, out_dir: &Path) -> anyhow::Result<()> {
    let db = data_dir.join("aisafeguard.db");
    if !db.exists() {
        anyhow::bail!("数据目录中没有 aisafeguard.db：{}", data_dir.display());
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| anyhow::anyhow!("创建输出目录 {} 失败: {e}", out_dir.display()))?;

    // 快照清单：按备份步骤逐项登记（相对路径，/ 分隔）
    snapshot_db(&db, &out_dir.join("aisafeguard.db"))?;
    let mut rels: Vec<String> = vec!["aisafeguard.db".into()];
    let cred = data_dir.join("honeypot").join("credentials.db");
    if cred.exists() {
        snapshot_db(&cred, &out_dir.join("honeypot").join("credentials.db"))?;
        rels.push("honeypot/credentials.db".into());
    }
    // 蜜饵水印密钥（H210）：跨机恢复后 canary-decode 还能用的前提。
    // credentials.db 不存在时 out/honeypot 还没建——copy 前先建父目录
    let canary = data_dir.join("honeypot").join("canary.key");
    if canary.exists() {
        let dst = out_dir.join("honeypot").join("canary.key");
        std::fs::create_dir_all(dst.parent().expect("honeypot 相对路径必有父目录"))?;
        std::fs::copy(&canary, &dst)?;
        rels.push("honeypot/canary.key".into());
    }
    if config_path.exists() {
        std::fs::copy(config_path, out_dir.join("config.toml"))?;
        rels.push("config.toml".into());
    } else {
        println!("⚠ 配置文件不存在，跳过: {}", config_path.display());
    }
    let fed = data_dir.join("fed");
    if fed.is_dir() {
        copy_tree(&fed, &out_dir.join("fed"))?;
        let mut fed_files = Vec::new();
        collect_files(&out_dir.join("fed"), "fed", &mut fed_files)?;
        rels.extend(fed_files.into_iter().map(|(rel, _)| rel));
    } else {
        println!("ℹ 无 fed/ 证书目录，跳过");
    }

    // manifest（清单文件自身不在清单里，写完后统一打印）
    let mut files = Vec::with_capacity(rels.len());
    for rel in &rels {
        let abs = out_dir.join(rel);
        files.push(ManifestFile {
            path: rel.clone(),
            bytes: std::fs::metadata(&abs)?.len(),
            sha256: sha256_file(&abs)?,
        });
    }
    let manifest = Manifest {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        created: Local::now().to_rfc3339(),
        source_data_dir: data_dir.to_string_lossy().into_owned(),
        source_config_path: config_path.to_string_lossy().into_owned(),
        files,
    };
    std::fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    println!("✓ 备份完成 → {}", out_dir.display());
    println!("  源数据目录: {}", data_dir.display());
    println!("  时间戳: {}", manifest.created);
    println!("  sha256（整个输出目录逐文件）:");
    let mut printed = Vec::new();
    collect_files(out_dir, "", &mut printed)?;
    printed.sort();
    for (rel, abs) in &printed {
        println!("  {}  {}", sha256_file(abs)?, rel);
    }
    Ok(())
}

/// `aisafeguard restore <备份目录>`
pub fn cmd_restore(backup_dir: &Path, data_dir: &Path, config_path: &Path) -> anyhow::Result<()> {
    warn_stop_service();

    let manifest_path = backup_dir.join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path).map_err(|e| {
        anyhow::anyhow!(
            "读取备份清单失败 {}: {e}（restore 只接受 backup 生成的目录）",
            manifest_path.display()
        )
    })?;
    let manifest: Manifest =
        serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("manifest.json 解析失败: {e}"))?;

    // zip-slip 防线（在任何文件 IO 之前）：备份保管是运营者的事——manifest 与
    // 文件可一起伪造，sha256 不是路径安全屏障。只收相对且无父级/根/盘符分量的
    // 路径；正常 backup 产物（collect_files 只产 `a/b.ext` 形式）全部通过。
    for f in &manifest.files {
        validate_rel_path(&f.path)?;
    }

    // 恢复前整体校验备份完整性：任一文件 sha256 不符立即中止，不做半恢复
    for f in &manifest.files {
        let sha = sha256_file(&backup_dir.join(&f.path))
            .map_err(|e| anyhow::anyhow!("备份文件缺失 {}: {e}", f.path))?;
        if sha != f.sha256 {
            anyhow::bail!("备份文件校验失败 {}: sha256 不符（备份已损坏）", f.path);
        }
    }

    let ts = Local::now().format("%Y%m%d-%H%M%S%.3f").to_string();
    let mut restored = 0usize;
    for f in &manifest.files {
        let src = backup_dir.join(&f.path);
        let dst = match f.path.as_str() {
            // 配置还原到本机配置路径（经 resolve_cfg：GUI 默认在 config_dir，
            // 服务模式在数据目录）——不是照抄备份时来源，跨机器恢复才成立
            "config.toml" => config_path.to_path_buf(),
            "aisafeguard.db" => data_dir.join("aisafeguard.db"),
            "honeypot/credentials.db" => data_dir.join("honeypot").join("credentials.db"),
            "honeypot/canary.key" => data_dir.join("honeypot").join("canary.key"),
            other if other.starts_with("fed/") => data_dir.join(other),
            other => {
                println!("ℹ 跳过清单外未知文件: {other}");
                continue;
            }
        };
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // DB 的 -wal/-shm 残留属于旧库：换新库前必须一并留痕清走，否则会被
        // SQLite 当成新库的未 checkpoint 内容合并，直接损坏恢复结果
        let mut moved: Vec<PathBuf> = Vec::new();
        if f.path.ends_with(".db") {
            for suffix in ["-wal", "-shm"] {
                let side = PathBuf::from(format!("{}{suffix}", dst.display()));
                if let Some(b) = move_aside(&side, &ts)? {
                    moved.push(b);
                }
            }
        }
        if let Some(b) = move_aside(&dst, &ts)? {
            moved.push(b);
        }
        std::fs::copy(&src, &dst)?;
        restored += 1;
        println!("✓ {} → {}", f.path, dst.display());
        for b in &moved {
            println!("  旧文件留痕 → {}", b.display());
        }
    }
    if restored == 0 {
        anyhow::bail!("备份目录里没有可恢复的文件");
    }

    // 恢复完自动校验哈希链（与 verify-log 同一实现）
    println!("已恢复 {restored} 个文件，校验哈希链…");
    let store = Store::open(&data_dir.join("aisafeguard.db"))?;
    let report = store.verify_chain()?;
    if report.ok {
        println!("✓ 恢复完成，哈希链完整：{} 条事件校验通过", report.rows);
        // 跨机恢复告警：路径相关字段不会自动适配，必须人工过目
        if manifest.source_data_dir != data_dir.to_string_lossy() {
            println!();
            println!("⚠ 备份来自其他数据目录: {}", manifest.source_data_dir);
            println!(
                "  ≠ 本次恢复目标: {}——请人工检查 config.toml 中与路径/身份相关的字段：",
                data_dir.display()
            );
            println!("    [general].data_dir（应为本机数据目录，或用 --data-dir 覆盖）");
            println!("    [fed] 证书路径与节点身份（fed/ 材料已随备份恢复）");
        }
        Ok(())
    } else {
        eprintln!(
            "✗ 恢复完成但哈希链损坏：第 {} 条事件校验失败（共 {} 条）——备份可能已损坏",
            report.broken_at.unwrap_or_default(),
            report.rows
        );
        std::process::exit(1);
    }
}

/// 恢复前强提示（尽力而为检测，不强制阻断）。
fn warn_stop_service() {
    println!("⚠ 恢复将覆盖数据目录中的现有文件——必须先停止 AI-SafeGuard 服务/引擎！");
    println!("  （引擎运行中恢复：打开中的旧句柄与残留 WAL 会污染新库）");
    println!("  Windows: aisafeguard service stop（sc query AISafeGuard 确认状态）");
    println!("  Linux:   sudo systemctl stop aisafeguard（systemctl is-active 确认）");
    match service_running() {
        Some(true) => println!("✗ 自动检测：服务仍在运行——按要求不强制阻断，请自行确认风险"),
        Some(false) => println!("自动检测：服务未在运行"),
        None => println!("自动检测：无法确认服务状态，请人工确认已停止"),
    }
}

/// 服务是否在运行（尽力而为）：Windows `sc query AISafeGuard` 看 RUNNING，
/// Linux `systemctl is-active aisafeguard`；命令缺失/失败 → None。
fn service_running() -> Option<bool> {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("sc")
            .args(["query", "AISafeGuard"])
            .output()
            .ok()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Some(text.contains("RUNNING"))
    }
    #[cfg(not(windows))]
    {
        let out = std::process::Command::new("systemctl")
            .args(["is-active", "aisafeguard"])
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim() == "active")
    }
}

/// SQLite 在线一致性快照：`VACUUM INTO`（目标不能已存在 → 先写 *.vacuum-tmp
/// 再改名落位；改名前清掉旧快照，允许重复 backup 到同一目录。失败不留半成品）。
fn snapshot_db(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = PathBuf::from(format!("{}.vacuum-tmp", dst.display()));
    let _ = std::fs::remove_file(&tmp);
    // 只读打开：VACUUM INTO 只读源库（WAL 模式引擎在线安全），不碰源文件。
    // 崩溃残留的 -wal 会让只读连接无法完成 WAL 恢复——报错必须可操作
    let conn = Connection::open_with_flags(src, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| {
        let wal = PathBuf::from(format!("{}-wal", src.display()));
        if wal.exists() {
            anyhow::anyhow!(
                "只读打开 {} 失败: {e}——可能存在崩溃残留的 -wal，请先启动一次引擎让其恢复后再备份",
                src.display()
            )
        } else {
            anyhow::anyhow!("只读打开 {} 失败: {e}（请检查文件权限）", src.display())
        }
    })?;
    let sql = format!(
        "VACUUM INTO '{}'",
        tmp.to_string_lossy().replace('\'', "''")
    );
    if let Err(e) = conn.execute(&sql, []) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "快照 {} 失败（VACUUM INTO）: {e}",
            src.display()
        ));
    }
    drop(conn);
    if dst.exists() {
        std::fs::remove_file(dst)?;
    }
    std::fs::rename(&tmp, dst)?;
    Ok(())
}

/// 递归拷贝目录（fed/ 证书树）。
fn copy_tree(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let target = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_tree(&e.path(), &target)?;
        } else {
            std::fs::copy(e.path(), &target)?;
        }
    }
    Ok(())
}

/// 递归收集文件为 (相对路径 [`/` 分隔], 绝对路径)，目录内按文件名排序（确定性输出）。
fn collect_files(dir: &Path, prefix: &str, out: &mut Vec<(String, PathBuf)>) -> anyhow::Result<()> {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let rel = if prefix.is_empty() {
            e.file_name().to_string_lossy().into_owned()
        } else {
            format!("{prefix}/{}", e.file_name().to_string_lossy())
        };
        let p = e.path();
        if p.is_dir() {
            collect_files(&p, &rel, out)?;
        } else {
            out.push((rel, p));
        }
    }
    Ok(())
}

/// manifest 路径校验（zip-slip 防线）：空路径、绝对路径、根分量（`/etc/...`，
/// Windows 上 join 会整体换盘）、盘符/UNC 前缀、父级分量（`..`，含 `\` 分隔的
/// Windows 变体——components() 在 Windows 上把 / 和 \ 都当分隔符）一律拒绝。
fn validate_rel_path(p: &str) -> anyhow::Result<()> {
    if p.is_empty() {
        anyhow::bail!("manifest 路径非法: （空路径）");
    }
    let escapes = Path::new(p).components().any(|c| {
        matches!(
            c,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    });
    if escapes {
        anyhow::bail!("manifest 路径非法: {p}");
    }
    Ok(())
}

/// 恢复留痕：现有文件改名 *.restore-bak-<时间戳>（同毫秒重名顺延 -n）。
fn move_aside(p: &Path, ts: &str) -> anyhow::Result<Option<PathBuf>> {
    if !p.exists() {
        return Ok(None);
    }
    let base = format!("{}.restore-bak-{ts}", p.display());
    let mut bak = base.clone();
    let mut n = 2;
    while Path::new(&bak).exists() {
        bak = format!("{base}-{n}");
        n += 1;
    }
    std::fs::rename(p, &bak)?;
    Ok(Some(PathBuf::from(bak)))
}

fn sha256_file(p: &Path) -> anyhow::Result<String> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("asg-backup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 假数据目录：主库两张表塞几行 + credentials 库 + config.toml + fed/ 证书树
    fn fake_data_dir(dir: &Path) -> PathBuf {
        let data = dir.join("data");
        std::fs::create_dir_all(data.join("honeypot")).unwrap();
        let conn = Connection::open(data.join("aisafeguard.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT);
             INSERT INTO t1 (name) VALUES ('alpha'), ('beta');
             CREATE TABLE t2 (k TEXT, v INTEGER);
             INSERT INTO t2 VALUES ('x', 1), ('y', 2);",
        )
        .unwrap();
        drop(conn);
        let cred = Connection::open(data.join("honeypot").join("credentials.db")).unwrap();
        cred.execute_batch(
            "CREATE TABLE cred (u TEXT);
             INSERT INTO cred VALUES ('root');",
        )
        .unwrap();
        drop(cred);
        std::fs::write(dir.join("config.toml"), "[general]\ndata_dir = \"x\"\n").unwrap();
        std::fs::write(data.join("honeypot").join("canary.key"), "CANARY-SECRET").unwrap();
        std::fs::create_dir_all(data.join("fed").join("certs")).unwrap();
        std::fs::write(data.join("fed").join("ca.pem"), "CERT-CA").unwrap();
        std::fs::write(data.join("fed").join("certs").join("node.pem"), "CERT-NODE").unwrap();
        data
    }

    fn rows(db: &Path, sql: &str) -> Vec<String> {
        let conn = Connection::open(db).unwrap();
        let mut stmt = conn.prepare(sql).unwrap();
        let got: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(stmt);
        conn.close().unwrap();
        got
    }

    #[test]
    fn backup_then_restore_roundtrip() {
        let dir = tmpdir("roundtrip");
        let data = fake_data_dir(&dir);
        let cfg = dir.join("config.toml");
        let out = dir.join("backup");
        cmd_backup(&data, &cfg, &out).unwrap();

        // manifest：清单齐全、sha256/bytes 与落盘文件一致
        let m: Manifest =
            serde_json::from_str(&std::fs::read_to_string(out.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(m.source_data_dir, data.to_string_lossy());
        let paths: Vec<&str> = m.files.iter().map(|f| f.path.as_str()).collect();
        for rel in [
            "aisafeguard.db",
            "honeypot/credentials.db",
            "honeypot/canary.key",
            "config.toml",
            "fed/ca.pem",
            "fed/certs/node.pem",
        ] {
            assert!(paths.contains(&rel), "manifest 缺 {rel}");
        }
        for f in &m.files {
            assert_eq!(
                sha256_file(&out.join(&f.path)).unwrap(),
                f.sha256,
                "{}",
                f.path
            );
            assert_eq!(std::fs::metadata(out.join(&f.path)).unwrap().len(), f.bytes);
        }

        // restore 到另一数据目录 + 另一配置路径
        let rdata = dir.join("restored");
        std::fs::create_dir_all(&rdata).unwrap();
        let rcfg = dir.join("restored-config.toml");
        cmd_restore(&out, &rdata, &rcfg).unwrap();

        // DB 表内容逐行一致
        assert_eq!(
            rows(
                &data.join("aisafeguard.db"),
                "SELECT name FROM t1 ORDER BY id"
            ),
            rows(
                &rdata.join("aisafeguard.db"),
                "SELECT name FROM t1 ORDER BY id"
            )
        );
        assert_eq!(
            rows(&data.join("aisafeguard.db"), "SELECT k FROM t2 ORDER BY v"),
            rows(&rdata.join("aisafeguard.db"), "SELECT k FROM t2 ORDER BY v")
        );
        assert_eq!(
            rows(
                &data.join("honeypot").join("credentials.db"),
                "SELECT u FROM cred"
            ),
            rows(
                &rdata.join("honeypot").join("credentials.db"),
                "SELECT u FROM cred"
            )
        );
        // config 与 fed/canary 字节一致
        assert_eq!(std::fs::read(&cfg).unwrap(), std::fs::read(&rcfg).unwrap());
        for rel in ["fed/ca.pem", "fed/certs/node.pem", "honeypot/canary.key"] {
            assert_eq!(
                std::fs::read(data.join(rel)).unwrap(),
                std::fs::read(rdata.join(rel)).unwrap(),
                "{rel}"
            );
        }

        // 清理
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_twice_into_same_dir_refreshes_snapshot() {
        let dir = tmpdir("twice");
        let data = fake_data_dir(&dir);
        let cfg = dir.join("config.toml");
        let out = dir.join("backup");
        cmd_backup(&data, &cfg, &out).unwrap();

        // 第一次备份后引擎继续写入：快照必须反映新内容（VACUUM INTO 目标已
        // 存在的清理路径 + 非陈旧副本）
        let conn = Connection::open(data.join("aisafeguard.db")).unwrap();
        conn.execute("INSERT INTO t1 (name) VALUES ('gamma')", [])
            .unwrap();
        conn.close().unwrap();
        cmd_backup(&data, &cfg, &out).unwrap();

        let names = rows(
            &out.join("aisafeguard.db"),
            "SELECT name FROM t1 ORDER BY id",
        );
        assert_eq!(names, ["alpha", "beta", "gamma"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_works_while_engine_holds_wal_open() {
        // 模拟引擎运行中：持有 WAL 模式连接、写入且不 checkpoint
        let dir = tmpdir("online");
        let data = dir.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let conn = Connection::open(data.join("aisafeguard.db")).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch("CREATE TABLE t1 (name TEXT);").unwrap();
        conn.execute("INSERT INTO t1 VALUES ('checkpointed')", [])
            .unwrap();
        conn.execute("INSERT INTO t1 VALUES ('in-wal')", [])
            .unwrap();

        let out = dir.join("backup");
        cmd_backup(&data, &dir.join("config.toml"), &out).unwrap();
        drop(conn);

        // 快照含 WAL 中未 checkpoint 的行 = 读到了最新一致状态
        let names = rows(
            &out.join("aisafeguard.db"),
            "SELECT name FROM t1 ORDER BY rowid",
        );
        assert_eq!(names, ["checkpointed", "in-wal"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_over_existing_leaves_timestamped_bak() {
        let dir = tmpdir("over");
        let data = fake_data_dir(&dir);
        let cfg = dir.join("config.toml");
        let out = dir.join("backup");
        cmd_backup(&data, &cfg, &out).unwrap();

        // 目标目录已有同名旧文件（含 WAL 残留）
        let rdata = dir.join("restored");
        std::fs::create_dir_all(rdata.join("honeypot")).unwrap();
        std::fs::write(rdata.join("aisafeguard.db"), "stale").unwrap();
        std::fs::write(rdata.join("aisafeguard.db-wal"), "stale-wal").unwrap();
        std::fs::write(rdata.join("config.toml"), "stale").unwrap();

        let rcfg = dir.join("restored-config.toml");
        cmd_restore(&out, &rdata, &rcfg).unwrap();

        // 恢复结果可用 + 旧文件全部留痕（DB 本体、-wal、config）
        assert_eq!(
            rows(&rdata.join("aisafeguard.db"), "SELECT name FROM t1").len(),
            2
        );
        let names: Vec<String> = std::fs::read_dir(&rdata)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("aisafeguard.db.restore-bak-")),
            "DB 旧文件未留痕: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("aisafeguard.db-wal.restore-bak-")),
            "WAL 残留未留痕: {names:?}"
        );
        assert!(
            std::fs::read_to_string(&rcfg)
                .unwrap()
                .contains("[general]"),
            "config 未恢复"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_rejects_path_traversal_manifest() {
        let dir = tmpdir("zipslip");
        let data = fake_data_dir(&dir);
        let cfg = dir.join("config.toml");
        let out = dir.join("backup");
        cmd_backup(&data, &cfg, &out).unwrap();

        // 合法备份中篡改 manifest 塞入恶意路径（manifest 与文件可一起伪造，
        // sha256 拦不住）——必须在任何文件落盘前拒绝
        let manifest_path = out.join("manifest.json");
        for evil in ["fed/../../outside.db", "/etc/passwd"] {
            let mut v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
            v["files"][0]["path"] = evil.into();
            std::fs::write(&manifest_path, serde_json::to_string(&v).unwrap()).unwrap();
            let rdata = dir.join(format!("restored-{}", evil.replace(['/', '\\'], "_")));
            std::fs::create_dir_all(&rdata).unwrap();
            let err = cmd_restore(&out, &rdata, &dir.join("evil-cfg.toml")).unwrap_err();
            assert!(
                err.to_string().contains("manifest 路径非法"),
                "{evil}: {err}"
            );
            // 拒绝发生在任何文件 IO 之前：目标目录仍是空的
            assert!(
                std::fs::read_dir(&rdata).unwrap().next().is_none(),
                "{evil} 有文件落盘"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_fails_without_db() {
        let dir = tmpdir("nodb");
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let out = dir.join("backup");
        let err = cmd_backup(&empty, &dir.join("config.toml"), &out).unwrap_err();
        assert!(err.to_string().contains("aisafeguard.db"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
