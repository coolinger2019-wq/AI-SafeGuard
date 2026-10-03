//! 蜜饵水印（0.5.10 H210）：`AC1.<b64url(payload)>.<b64url(mac)>` 形态的
//! 自校验 token，内嵌于 HTTP 蜜饵与文件系统蜜饵内容中，被外传后可用
//! `aisafeguard canary-decode <token>` 还原 来源节点 / 投放时间 / 蜜饵资源。
//!
//! MAC 用 SHA-256(key‖payload)（非 HMAC）——威胁模型是「溯源信息不被随手
//! 伪造/篡改」，不是对抗有密钥的密码学攻击者；刻意不引入 hmac 依赖。

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// token 版本前缀（未来格式演进用）
pub const TOKEN_PREFIX: &str = "AC1";

/// 水印载荷。node = 来源节点标识（主机名）；ts = 投放时间（epoch 秒）；
/// res = 蜜饵资源标识（如 backup.zip / 蜜饵文件路径）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryPayload {
    pub node: String,
    pub ts: i64,
    pub res: String,
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn unb64url(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
}

/// SHA-256(key ‖ payload) 摘要
fn mac(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.update(payload);
    h.finalize().into()
}

/// 节点标识：Windows 读 COMPUTERNAME，Unix 读 /etc/hostname；拿不到用 "unknown"。
/// （不用 sysinfo：canary 只需要主机名，不值得拉起 system 特性）
pub fn node_id() -> String {
    #[cfg(windows)]
    if let Ok(name) = std::env::var("COMPUTERNAME")
        && !name.is_empty()
    {
        return name;
    }
    #[cfg(unix)]
    if let Ok(name) = std::fs::read_to_string("/etc/hostname") {
        let name = name.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    "unknown".into()
}

/// 生成水印 token。key 为空视为非法（调用方须先解决密钥来源）。
pub fn make_token(key: &[u8], payload: &CanaryPayload) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let payload_bytes = serde_json::to_vec(payload).ok()?;
    let digest = mac(key, &payload_bytes);
    Some(format!(
        "{TOKEN_PREFIX}.{}.{}",
        b64url(&payload_bytes),
        b64url(&digest)
    ))
}

/// 解码并校验水印 token：前缀/MAC 任一不符 → Err（篡改或异节点密钥）。
pub fn decode_token(key: &[u8], token: &str) -> Result<CanaryPayload, String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 || parts[0] != TOKEN_PREFIX {
        return Err("不是 AC1 蜜饵水印 token".into());
    }
    if key.is_empty() {
        return Err("水印密钥为空".into());
    }
    let payload_bytes = unb64url(parts[1]).ok_or("payload 不是合法 base64url")?;
    let expect = unb64url(parts[2]).ok_or("MAC 不是合法 base64url")?;
    if mac(key, &payload_bytes).to_vec() != expect {
        return Err("MAC 校验失败（密钥不匹配或内容被篡改）".into());
    }
    serde_json::from_slice(&payload_bytes).map_err(|e| format!("payload 解析失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> CanaryPayload {
        CanaryPayload {
            node: "web-01".into(),
            ts: 1_760_000_000,
            res: "backup.zip".into(),
        }
    }

    #[test]
    fn token_roundtrip() {
        let token = make_token(b"k", &payload()).unwrap();
        let back = decode_token(b"k", &token).unwrap();
        assert_eq!(back, payload());
        assert!(token.starts_with("AC1."));
    }

    #[test]
    fn tamper_and_wrong_key_rejected() {
        let token = make_token(b"k", &payload()).unwrap();
        // 改一位 payload
        let mut tampered = token.clone();
        tampered.replace_range(6..7, "Z");
        assert!(decode_token(b"k", &tampered).is_err());
        // 异节点密钥
        assert!(decode_token(b"other", &token).is_err());
        // 完全不是 token 的输入
        assert!(decode_token(b"k", "hello world").is_err());
        // 空密钥生成/解码都拒绝
        assert!(make_token(b"", &payload()).is_none());
        assert!(decode_token(b"", &token).is_err());
    }

    #[test]
    fn node_id_nonempty_and_no_newlines() {
        let n = node_id();
        assert!(!n.is_empty());
        assert!(!n.contains('\n'));
    }
}
