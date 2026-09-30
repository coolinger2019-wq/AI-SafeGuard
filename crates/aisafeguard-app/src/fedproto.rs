//! fed 线上协议 v1（0.6 F100，设计见 docs/ROADMAP-0.6.md）。
//!
//! 所有 `/fed` 请求共用一个信封：`{proto, node, seq, ts, type, payload, sig}`。
//! - 版本协商：`proto` 为 `major.minor`，major 不同拒连（426 + 双方版本号）；
//!   minor 差异靠「未知字段忽略」（serde 默认行为），规则写死不静默降级。
//! - 幂等：消息 ID = `node:seq`，seq 为节点本地单调计数（重连不清零，间隙允许）。
//!   接收方 24h 窗内 seen 集合去重；seq 不大于已见最大值且不在 seen 集合 = 回退
//!   （备份恢复/伪造）拒收。
//! - 防抵赖：sig = 节点证书私钥对 canonical_json(去 sig 信封) 的 ECDSA P-256 签名，
//!   验签公钥取自 mTLS 对端证书（SPKI）——消息可以离开 TLS 连接独立取证。
//! - 规范化：自写 canonical_json（键排序、无空白），与 serde_json 的 Map 顺序
//!   实现细节解耦，双方对同一 Value 必得同一字节串。payload 不使用浮点数。

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTO_MAJOR: u32 = 1;
pub const PROTO: &str = "1.0";

/// 信封时间窗：信封 ts 偏离接收方当前时钟超过此值按重放拒收。
/// 同时是补传窗口（0.6 拍板：±1h 收紧改 24h，超窗只归档不进印证）。
pub const REPLAY_WINDOW_SECS: i64 = 24 * 3600;

/// 消息类型。hello 兼职心跳与版本协商；其余 payload schema 见 fed.rs 各 handler。
/// intel 上行暂不存在（情报是协调者→agent 的无信封 GET 拉取），F310 落地时补。
pub mod types {
    pub const HELLO: &str = "hello";
    pub const EVENTS: &str = "events";
    pub const PROPOSALS: &str = "proposals";
    /// F300 组织建议生命周期回流（采纳/收弃/误报标记）
    pub const REPORTS: &str = "reports";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub proto: String,
    pub node: String,
    pub seq: u64,
    pub ts: i64,
    #[serde(rename = "type")]
    pub ty: String,
    pub payload: Value,
    pub sig: String,
}

/// 版本协商：major 必须一致；解析失败按畸形消息拒绝。
/// minor 不比较——未知字段忽略是双向写死的向前兼容规则。
pub fn version_compatible(proto: &str) -> Result<(), String> {
    let (maj, min) = proto
        .split_once('.')
        .ok_or_else(|| format!("proto 字段非法（须 major.minor）: {proto:?}"))?;
    let maj: u32 = maj
        .parse()
        .map_err(|_| format!("proto 主版本非法: {proto:?}"))?;
    min.parse::<u32>()
        .map_err(|_| format!("proto 次版本非法: {proto:?}"))?;
    if maj == PROTO_MAJOR {
        Ok(())
    } else {
        Err(format!(
            "fed 协议主版本不兼容：本端 {PROTO}，对端 {proto}（major 不同拒绝连接，请升级节点）"
        ))
    }
}

/// 自写规范化 JSON：对象键按字节序排序、无空白。双方对同一 Value 得同一字符串，
/// 不依赖 serde_json Map 的内部顺序。协议内不使用浮点数（Number 按其文本输出）。
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&o[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// 签名覆盖范围：去 sig 信封的 canonical 字节串（含 payload 全部内容）。
pub fn signing_bytes(env: &Envelope) -> Vec<u8> {
    let obj = serde_json::json!({
        "proto": env.proto,
        "node": env.node,
        "seq": env.seq,
        "ts": env.ts,
        "type": env.ty,
        "payload": env.payload,
    });
    canonical_json(&obj).into_bytes()
}

// ---------- 签名 / 验签（ring ECDSA P-256，与节点证书同一密钥对） ----------

/// 从节点证书 DER 提取公钥（非压缩 EC 点，ring UnparsedPublicKey 的输入格式——
/// 实测 ring 的 ECDSA 验签不吃 SPKI DER，吃 `04||X||Y` 裸点）。
pub fn public_point_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("对端证书 DER 解析失败: {e}"))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

/// 用已加载的签名钥对字节串签名，返回 hex。
pub fn sign_with_key(key: &ring::signature::EcdsaKeyPair, bytes: &[u8]) -> Result<String, String> {
    let sig = key
        .sign(&ring::rand::SystemRandom::new(), bytes)
        .map_err(|e| format!("fed 消息签名失败: {e:?}"))?;
    Ok(sig
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>())
}

/// 加载 PKCS#8 私钥为 ring 签名钥（issue-cert 生成即 P-256 PKCS#8）。
pub fn load_signing_key(key_pem: &str) -> Result<ring::signature::EcdsaKeyPair, String> {
    let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let der = pem_private_key_der(key_pem)?;
    ring::signature::EcdsaKeyPair::from_pkcs8(alg, &der, &ring::rand::SystemRandom::new())
        .map_err(|e| format!("fed 签名钥加载失败（须为 issue-cert 产出的 P-256 PKCS#8）: {e:?}"))
}

/// 验签：证书公钥点 + 签名字节串 + hex 签名。任何失败 = false（调用方计数留痕）。
pub fn verify_signature(public_point: &[u8], bytes: &[u8], sig_hex: &str) -> bool {
    let Ok(sig) = hex_decode(sig_hex) else {
        return false;
    };
    let pk = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        public_point,
    );
    pk.verify(bytes, &sig).is_ok()
}

fn pem_private_key_der(key_pem: &str) -> Result<Vec<u8>, String> {
    let begin = "-----BEGIN PRIVATE KEY-----";
    let end = "-----END PRIVATE KEY-----";
    let i = key_pem
        .find(begin)
        .ok_or("私钥 PEM 中没有 PRIVATE KEY 块")?;
    let j = key_pem[i..].find(end).ok_or("私钥 PEM 块未闭合")?;
    let body: String = key_pem[i + begin.len()..i + j]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("私钥 base64 解码失败: {e}"))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

// ---------- 接收侧去重：24h 窗内 (node, seq) seen 集合 ----------

/// 有界 seen 集合：窗口过期剔除 + 容量上限丢最旧。协调者进程内存态——
/// 重启后 seen 丢失由「seq 单调 + ts 窗」两层兜底，不破坏幂等语义。
pub struct DedupSet {
    seen: HashMap<(String, u64), i64>,
    order: VecDeque<(String, u64)>,
    cap: usize,
}

impl DedupSet {
    pub fn new(cap: usize) -> Self {
        Self {
            seen: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// true = 窗口内首次见到（应处理）；false = 重复（幂等跳过）。
    pub fn first_time(&mut self, node: &str, seq: u64, now: i64, window_secs: i64) -> bool {
        let key = (node.to_string(), seq);
        if let Some(&ts) = self.seen.get(&key)
            && now - ts <= window_secs
        {
            return false;
        }
        if self.seen.insert(key.clone(), now).is_none() {
            self.order.push_back(key.clone());
        }
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_is_key_order_independent() {
        // 键插入顺序不同，规范化结果必须逐字节一致
        let a = json!({"ts": 1, "node": "a", "payload": {"z": 1, "a": [2, {"y": null, "b": true}]}});
        let b = json!({"node": "a", "payload": {"a": [2, {"b": true, "y": null}], "z": 1}, "ts": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(canonical_json(&a), r#"{"node":"a","payload":{"a":[2,{"b":true,"y":null}],"z":1},"ts":1}"#);
    }

    #[test]
    fn canonical_json_escapes_and_unicode() {
        let v = json!({"s": "引号\"与\n换行", "n": -3});
        assert_eq!(canonical_json(&v), "{\"n\":-3,\"s\":\"引号\\\"与\\n换行\"}");
    }

    #[test]
    fn version_matrix() {
        assert!(version_compatible("1.0").is_ok());
        assert!(version_compatible("1.7").is_ok(), "minor 差异兼容");
        assert!(version_compatible("2.0").is_err(), "major 不同必须拒");
        assert!(version_compatible("abc").is_err());
        assert!(version_compatible("").is_err());
        assert!(version_compatible("1").is_err());
        assert!(version_compatible("1.x").is_err());
    }

    /// 关键链路实测：rcgen 签发的证书 + 私钥 → ring 签名 → 证书公钥点验签通过；
    /// 篡改任一字节、换钥签名、改签名均拒绝。
    #[test]
    fn sign_verify_roundtrip_with_issued_cert() {
        let dir = std::env::temp_dir().join(format!("asg-fedproto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::fed::cmd_init_ca(&dir, "").unwrap();
        crate::fed::cmd_issue_cert(&dir, "node-a", &[]).unwrap();
        let key_pem =
            std::fs::read_to_string(dir.join("fed").join("certs").join("node-a-key.pem")).unwrap();
        let cert_der = std::fs::read(dir.join("fed").join("certs").join("node-a.pem")).unwrap();
        // 证书文件是 PEM，需提取 DER
        let cert_pem = String::from_utf8(cert_der).unwrap();
        let begin = "-----BEGIN CERTIFICATE-----";
        let end = "-----END CERTIFICATE-----";
        let i = cert_pem.find(begin).unwrap();
        let j = cert_pem[i..].find(end).unwrap();
        let body: String = cert_pem[i + begin.len()..i + j]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();

        let point = public_point_from_cert_der(&der).unwrap();
        let env = Envelope {
            proto: PROTO.to_string(),
            node: "node-a".into(),
            seq: 7,
            ts: 1_700_000_000,
            ty: types::HELLO.into(),
            payload: json!({"members": 3}),
            sig: String::new(),
        };
        let bytes = signing_bytes(&env);
        let key = load_signing_key(&key_pem).unwrap();
        let sig = sign_with_key(&key, &bytes).unwrap();
        assert_eq!(sig.len(), 128, "P-256 fixed 签名为 64 字节 hex");
        assert!(verify_signature(&point, &bytes, &sig));

        // 篡改 payload 一位 → 拒
        let mut tampered = env.clone();
        tampered.payload = json!({"members": 4});
        assert!(!verify_signature(&point, &signing_bytes(&tampered), &sig));
        // 篡改 seq → 拒
        let mut tampered = env.clone();
        tampered.seq = 8;
        assert!(!verify_signature(&point, &signing_bytes(&tampered), &sig));
        // 错误公钥 → 拒
        crate::fed::cmd_issue_cert(&dir, "node-b", &[]).unwrap();
        let other_pem = std::fs::read_to_string(dir.join("fed").join("certs").join("node-b.pem")).unwrap();
        let (i, j) = (
            other_pem.find(begin).unwrap(),
            other_pem.find(end).unwrap(),
        );
        let body2: String = other_pem[i + begin.len()..i + j]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der2 = base64::engine::general_purpose::STANDARD.decode(body2).unwrap();
        let point2 = public_point_from_cert_der(&der2).unwrap();
        assert!(!verify_signature(&point2, &bytes, &sig));
        // 非法签名 hex → 拒（不 panic）
        assert!(!verify_signature(&point, &bytes, "zz"));
        assert!(!verify_signature(&point, &bytes, ""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_window_and_cap() {
        let mut s = DedupSet::new(3);
        assert!(s.first_time("a", 1, 100, 3600));
        assert!(!s.first_time("a", 1, 200, 3600), "窗口内重复");
        assert!(s.first_time("a", 2, 200, 3600));
        assert!(s.first_time("a", 1, 100 + 3601, 3600), "过窗后允许再次进入");
        // 容量：超限丢最旧（容量 2，第三条进来后第一条必被逐出）
        let mut s = DedupSet::new(2);
        assert!(s.first_time("a", 1, 100, 3600));
        assert!(s.first_time("a", 2, 100, 3600));
        assert!(s.first_time("a", 3, 100, 3600));
        assert!(s.first_time("a", 1, 100, 3600), "最旧被逐出后视为首次");
    }

    /// F100 验收：fuzz 随机/畸形字节与信封变体打解析层——只返回错误，绝不 panic。
    #[test]
    fn fuzz_envelope_parsing_no_panic() {
        // 固定种子的可复现伪随机（与蜜罐 fuzz 同哲学：确定性可回归）
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let n = (next() % 256) as usize;
            let bytes: Vec<u8> = (0..n).map(|_| (next() & 0xff) as u8).collect();
            let _ = serde_json::from_slice::<Envelope>(&bytes);
            // 规范化对任意 Value 也不能 panic
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                let _ = canonical_json(&v);
            }
        }
        // 合法 JSON 但字段类型错误：必须 Err 而非 panic
        let bad = [
            json!({"proto": 1, "node": [], "seq": "x", "ts": {}, "type": null, "payload": 1, "sig": 2}),
            json!({"proto": "1.0"}),
            json!({"proto": "1.0", "node": "a", "seq": -1, "ts": 0, "type": "hello", "payload": {}, "sig": ""}),
            json!([1, 2, 3]),
            json!("hello"),
            json!(null),
        ];
        for v in bad {
            let r = serde_json::from_value::<Envelope>(v);
            if let Ok(env) = r {
                // 解析成功的（如缺字段失败不会到这）也必须能过签名检查而不 panic
                let _ = verify_signature(&[1, 2, 3], &signing_bytes(&env), &env.sig);
            }
        }
    }
}
