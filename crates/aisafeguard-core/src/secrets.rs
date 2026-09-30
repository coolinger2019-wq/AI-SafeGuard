//! 凭据管理：API Key 与本地 API token 一律进 Windows 凭据管理器，
//! 配置文件不承载任何秘密（[A.8.24]）。
//!
//! 环境变量 `AISAFEGUARD_AI_KEY` 仍是最高优先级覆盖（CI/无头场景）。
//! 非 Windows 平台 0.2 未接 keyring 后端，`get` 返回 None、`set` 返回错误——
//! 由调用方给出明确提示，Linux 后端随 0.3 nftables 一起落地。

use crate::error::{Error, Result};

const SERVICE: &str = "AISafeGuard";
const AI_KEY_USER: &str = "ai-key";
const API_TOKEN_USER: &str = "api-token";
const WEBHOOK_SECRET_USER: &str = "webhook-secret";

fn entry(user: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, user).map_err(|e| Error::Config(format!("凭据管理器不可用: {e}")))
}

fn get(user: &str) -> Option<String> {
    let entry = entry(user).ok()?;
    match entry.get_password() {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn set(user: &str, value: &str) -> Result<()> {
    let entry = entry(user)?;
    entry
        .set_password(value)
        .map_err(|e| Error::Config(format!("写入凭据管理器失败: {e}")))
}

fn delete(user: &str) -> Result<()> {
    let entry = entry(user)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::Config(format!("清除凭据失败: {e}"))),
    }
}

// ---------- AI Key ----------

pub fn ai_key() -> Option<String> {
    get(AI_KEY_USER)
}

pub fn ai_key_present() -> bool {
    ai_key().is_some()
}

pub fn set_ai_key(value: &str) -> Result<()> {
    set(AI_KEY_USER, value)
}

pub fn delete_ai_key() -> Result<()> {
    delete(AI_KEY_USER)
}

// ---------- webhook HMAC 密钥（F-webhook） ----------

pub fn webhook_secret() -> Option<String> {
    get(WEBHOOK_SECRET_USER)
}

pub fn set_webhook_secret(value: &str) -> Result<()> {
    set(WEBHOOK_SECRET_USER, value)
}

pub fn delete_webhook_secret() -> Result<()> {
    delete(WEBHOOK_SECRET_USER)
}

// ---------- 本地 API token ----------

pub fn api_token() -> Option<String> {
    get(API_TOKEN_USER)
}

pub fn set_api_token(value: &str) -> Result<()> {
    set(API_TOKEN_USER, value)
}
