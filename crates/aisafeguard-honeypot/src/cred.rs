//! 凭证采集（0.5.10 H200）：蜜罐会话内采集的 用户名/口令 对统一出口。
//!
//! 口令明文只存在于采集瞬间（本 crate 内存），离开前必须完成 argon2id 加盐
//! 哈希——事件总线与任何落盘表面只见哈希（红线：事件与 API 永不包含口令明文
//! 与可逆信息；COMPLIANCE 凭证哈希存储条目）。

use argon2::password_hash::PasswordHasher;
use argon2::{Algorithm, Argon2, Params, Version};

/// 会话内采集到的一对凭证。password 为采集瞬间的明文，仅在本 crate 内存存在；
/// 协议拿不到口令（MySQL 握手只有用户名，口令是不可逆的 scramble）时为 None。
#[derive(Debug, Clone)]
pub(crate) struct RawCredential {
    pub username: String,
    pub password: Option<String>,
}

/// 哈希后可进事件的形态。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HashedCredential {
    pub username: String,
    /// argon2id PHC 串（含随机盐）；None = 无口令可采
    pub pass_hash: Option<String>,
}

/// 参数刻意低于 OWASP 推荐：被哈希的是攻击者自选的口令（低熵是常态），
/// 哈希的用途是比对与频次统计，不保护任何真实秘密——8 MiB / 2 轮足以防
/// 「扫一眼数据库记口令」，又在蜜罐被高频撞库时不烧 CPU。
fn argon2_ctx() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(8192, 2, 1, Some(32)).expect("常量参数合法"),
    )
}

/// 哈希一对凭证：argon2id 自动生成随机盐（password-hash 0.6 语义），永不还原。
/// 空口令/缺口令 → pass_hash None（只留用户名）。
pub(crate) fn hash_credential(raw: &RawCredential) -> HashedCredential {
    let pass_hash = raw.password.as_ref().and_then(|pw| {
        if pw.is_empty() {
            return None;
        }
        argon2_ctx()
            .hash_password(pw.as_bytes())
            .ok()
            .map(|h| h.to_string())
    });
    HashedCredential {
        username: raw.username.clone(),
        pass_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_argon2id_phc_with_random_salt() {
        let raw = RawCredential {
            username: "root".into(),
            password: Some("hunter2".into()),
        };
        let a = hash_credential(&raw);
        let b = hash_credential(&raw);
        let ha = a.pass_hash.expect("有口令必有哈希");
        let hb = b.pass_hash.expect("有口令必有哈希");
        assert!(ha.starts_with("$argon2id$"), "实际: {ha}");
        assert_ne!(ha, hb, "随机盐：同一口令两次哈希必不相同");
        // PHC 串不携带明文
        assert!(!ha.contains("hunter2"));
    }

    #[test]
    fn missing_or_empty_password_yields_none() {
        let no_pw = hash_credential(&RawCredential {
            username: "mysqluser".into(),
            password: None,
        });
        assert!(no_pw.pass_hash.is_none());
        let empty_pw = hash_credential(&RawCredential {
            username: "u".into(),
            password: Some(String::new()),
        });
        assert!(empty_pw.pass_hash.is_none());
    }
}
