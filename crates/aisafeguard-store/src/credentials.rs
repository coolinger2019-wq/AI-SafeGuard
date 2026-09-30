//! 蜜罐凭证库（0.5.10 H200）：独立 SQLite 文件（`<data_dir>/honeypot/credentials.db`）。
//!
//! 与主事件库分离的红线依据：凭证库文件权限单独压 0600（Unix），不随主库走；
//! 口令只存 argon2id PHC 哈希（含随机盐，不可逆），明文在蜜罐会话内即丢弃。
//! 本库不进 API、不进 GUI 事件流——展示层需要的凭证信息走 events 表的
//! credential_observed 行（只有用户名，无哈希）。
//!
//! 查询口径：喷洒比对按 `lower(username)`（Windows 用户名不区分大小写）；
//! 跨协议撞库按同一 (remote_ip, pass_hash) 的去重协议数。

use std::path::Path;
use std::sync::Mutex;

use aisafeguard_core::error::{Error, Result};
use rusqlite::{Connection, params};

/// 一条凭证观察的展示形态（H310 AI 上下文用）：刻意不含哈希。
pub struct CredObservation {
    pub ts: i64,
    pub remote_ip: String,
    pub username: String,
    pub has_password: bool,
}

/// 一条待入库的凭证记录（字段并列比逐位传参直白，也避开 8 参上限）。
pub struct CredentialRecord<'a> {
    pub ts: i64,
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub listener: &'a str,
    /// 协议 kind（ssh | telnet | http | mysql | redis）
    pub protocol: &'a str,
    pub username: &'a str,
    /// argon2id PHC 串；空串 = 协议拿不到口令（如 MySQL）
    pub pass_hash: &'a str,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL DEFAULT 0,
    listener TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL,
    pass_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_credentials_ip_ts ON credentials(remote_ip, ts);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(username);
";

pub struct CredentialStore {
    conn: Mutex<Connection>,
}

impl CredentialStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("创建凭证库目录失败: {e}")))?;
        }
        let conn = Connection::open(path).map_err(|e| Error::Store(e.to_string()))?;
        // 红线：凭证库文件权限 0600（Unix）。不用 WAL——WAL 伴生文件让权限
        // 面变大；本库只有单写者且写入频率低，回滚日志模式足够。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.execute_batch(SCHEMA)
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| Error::Store("凭证库锁中毒".into()))
    }

    /// 追加一条凭证记录。
    pub fn insert(&self, r: CredentialRecord<'_>) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO credentials (ts, remote_ip, remote_port, listener, protocol, username, pass_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![r.ts, r.remote_ip, r.remote_port as i64, r.listener, r.protocol, r.username, r.pass_hash],
        )
        .map_err(|e| Error::Store(e.to_string()))?;
        Ok(())
    }

    /// 某来源在窗口内试过的去重用户名集合（小写归一，供本地账号交集比对）。
    pub fn usernames_by_ip(&self, ip: &str, since: i64) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT DISTINCT lower(username) FROM credentials WHERE remote_ip = ?1 AND ts >= ?2")
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![ip, since], |r| r.get::<_, String>(0))
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(rows)
    }

    /// 同一 (ip, 哈希) 在窗口内出现的去重协议数（跨协议撞库聚合依据）。
    pub fn hash_protocol_count(&self, ip: &str, pass_hash: &str, since: i64) -> Result<i64> {
        let conn = self.lock()?;
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT protocol) FROM credentials
                 WHERE remote_ip = ?1 AND pass_hash = ?2 AND ts >= ?3",
                params![ip, pass_hash, since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n)
    }

    /// 窗口内已保存的哈希串（跨协议比对时避免进程重启后哈希集合丢失）。
    pub fn hashes_by_ip(&self, ip: &str, since: i64) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT DISTINCT pass_hash FROM credentials WHERE remote_ip = ?1 AND ts >= ?2 AND pass_hash != ''")
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![ip, since], |r| r.get::<_, String>(0))
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(rows)
    }

    /// 窗口内最近的凭证观察（H310：供 AI 慢路径上下文）。只返回用户名与
    /// 「是否有口令」布尔——pass_hash 刻意不出参（不进 API/提示词/日志）。
    /// F200 凭证维度本地复验：本节点近期是否观测过某用户名的凭证投递。
    pub fn username_seen(&self, username: &str, since: i64) -> Result<bool> {
        let conn = self.lock()?;
        let hit: i64 = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE username = ?1 AND ts >= ?2)",
                rusqlite::params![username, since],
                |r| r.get(0),
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(hit != 0)
    }

    pub fn recent(&self, since: i64, limit: u32) -> Result<Vec<CredObservation>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT ts, remote_ip, username, pass_hash != '' FROM credentials
                 WHERE ts >= ?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(|e| Error::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![since, limit], |r| {
                Ok(CredObservation {
                    ts: r.get(0)?,
                    remote_ip: r.get(1)?,
                    username: r.get(2)?,
                    has_password: r.get::<_, i64>(3)? != 0,
                })
            })
            .map_err(|e| Error::Store(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(rows)
    }

    /// 按保留期清理（与 events 同一 keep_days 口径）。
    pub fn prune(&self, keep_days: u32) -> Result<usize> {
        let cutoff = aisafeguard_core::now_ts() - (keep_days as i64) * 86400;
        let conn = self.lock()?;
        conn.execute("DELETE FROM credentials WHERE ts < ?1", params![cutoff])
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(conn.changes() as usize)
    }

    pub fn count(&self) -> Result<i64> {
        let conn = self.lock()?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))
            .map_err(|e| Error::Store(e.to_string()))?;
        Ok(n)
    }
}

use std::sync::MutexGuard;

#[cfg(test)]
mod tests {
    use super::*;

    fn open_tmp(tag: &str) -> (std::path::PathBuf, CredentialStore) {
        let dir = std::env::temp_dir().join(format!("asg-credstore-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("credentials.db");
        let store = CredentialStore::open(&path).unwrap();
        (path, store)
    }

    #[test]
    fn insert_query_and_prune_roundtrip() {
        let (path, store) = open_tmp("roundtrip");
        let now = aisafeguard_core::now_ts();
        fn rec<'a>(
            ts: i64,
            ip: &'a str,
            port: u16,
            lst: &'a str,
            proto: &'a str,
            user: &'a str,
            hash: &'a str,
        ) -> CredentialRecord<'a> {
            CredentialRecord {
                ts,
                remote_ip: ip,
                remote_port: port,
                listener: lst,
                protocol: proto,
                username: user,
                pass_hash: hash,
            }
        }
        store.insert(rec(now, "9.9.9.9", 4444, "ssh", "ssh", "root", "$argon2id$AAA")).unwrap();
        store.insert(rec(now, "9.9.9.9", 4444, "mysql", "mysql", "ROOT", "")).unwrap();
        store.insert(rec(now - 40 * 86400, "8.8.8.8", 1, "ssh", "ssh", "admin", "$argon2id$BBB")).unwrap();

        // 用户名按 lower 归一去重
        let names = store.usernames_by_ip("9.9.9.9", now - 60).unwrap();
        assert_eq!(names, vec!["root"]);
        // 跨协议同哈希
        store.insert(rec(now, "9.9.9.9", 5555, "mysql", "mysql", "deploy", "$argon2id$AAA")).unwrap();
        assert_eq!(store.hash_protocol_count("9.9.9.9", "$argon2id$AAA", now - 60).unwrap(), 2);
        assert_eq!(store.hash_protocol_count("9.9.9.9", "$argon2id$CCC", now - 60).unwrap(), 0);
        // 保留期清理
        let pruned = store.prune(30).unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(store.count().unwrap(), 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "凭证库文件权限必须 0600");
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
