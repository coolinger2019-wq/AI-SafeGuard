//! 多机印证引擎（0.6 F200，设计见 docs/ROADMAP-0.6.md）。0.6 核心：把 N 台机器
//! 各自的干净观测变成组织级确信度——「三台机器在 10 分钟内各自看到同一个 IP 在扫」
//! 比一台机器说三次更可信。
//!
//! 纪律（全批次红线，任何改动不得违反）：
//! 1. **印证只加置信，不加处置**——产出的是组织事件与建议，节点本地复验后自行
//!    决定（升级严重度/推慢路径），永不直接触发全网封禁；
//! 2. **独立性**：K 节点 = K 个不同节点名的各自观测；单节点重复上报永不触发；
//! 3. **协调者无状态**：窗口全内存（重启丢窗 = 降级本地模式），不持久化节点事件，
//!    只留有界审计日志（拍板决议②）；
//! 4. **时钟降权**：节点上报的时钟偏移超阈值 → 其观测不参与印证（宁少勿错）；
//! 5. 凭证维度 v1 按**用户名**跨节点比对——argon2id 随机盐使哈希跨节点天然不可比
//!    （对 ROADMAP 原文「口令哈希对」的显式修正，盐可比化需组织级 pepper，风险大于
//!    收益，不做）；凭证观测出参只有 username/remote_ip/ts，无可逆材料。

use std::collections::{HashMap, VecDeque};

use serde::Serialize;
use serde_json::json;

/// 印证维度。key 语义：Ip=源 IP；Fingerprint=JA3 md5 或 JA4；
/// Credential=用户名（v1，见模块头注释）；Canary=蜜饵水印触发（key=源 IP）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dim {
    Ip,
    Fingerprint,
    Credential,
    Canary,
}

impl Dim {
    pub fn as_str(&self) -> &'static str {
        match self {
            Dim::Ip => "ip",
            Dim::Fingerprint => "fingerprint",
            Dim::Credential => "credential",
            Dim::Canary => "canary",
        }
    }
    pub fn severity(&self) -> &'static str {
        match self {
            // 横向移动线索 = 最高严重度（拍板：蜜饵联动维度）
            Dim::Canary => "critical",
            _ => "high",
        }
    }
}

/// 一条进入印证窗口的原始观测（节点本地事件投影，不含任何 payload 细节）。
#[derive(Debug, Clone)]
pub struct Observation {
    pub node: String,
    pub ts: i64,
    pub dim: Dim,
    pub key: String,
}

/// 组织印证事件（协调者聚合产出，进 org-feed 广播环）。
#[derive(Debug, Clone, Serialize)]
pub struct OrgCorroboration {
    pub id: u64,
    pub ts: i64,
    pub dim: Dim,
    pub key: String,
    pub nodes: Vec<String>,
    pub first_ts: i64,
    pub last_ts: i64,
    pub severity: String,
}

impl OrgCorroboration {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}

#[derive(Debug, Clone)]
pub struct CorroborationConfig {
    /// 时间窗：窗口内被 ≥K 节点独立观测才印证
    pub window_secs: i64,
    /// 独立节点数阈值 K
    pub min_nodes: u32,
    /// 时钟偏移降权阈值（秒）：超限节点的观测不参与
    pub clock_demote_secs: i64,
    /// 有界：最多跟踪的攻击者键数（超限逐最旧）
    pub max_keys: usize,
    /// 同一攻击者键的印证事件冷却（= 窗口：一窗一报）
    pub emit_cooldown_secs: i64,
    /// 观测保留上限（对齐 F320 重放窗）
    pub retain_secs: i64,
}

impl Default for CorroborationConfig {
    fn default() -> Self {
        Self {
            window_secs: 600,
            min_nodes: 2,
            clock_demote_secs: 5,
            max_keys: 10_000,
            emit_cooldown_secs: 600,
            retain_secs: 24 * 3600,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct NodeObs {
    first_ts: i64,
    last_ts: i64,
}

#[derive(Debug, Default)]
struct KeyState {
    nodes: HashMap<String, NodeObs>,
    last_emitted: Option<i64>,
    last_active: i64,
}

/// 印证引擎（协调者侧内存态）。并发由调用方 Mutex 保护；重启清零 = 降级本地模式。
#[derive(Debug)]
pub struct CorroborationEngine {
    pub cfg: CorroborationConfig,
    keys: HashMap<(Dim, String), KeyState>,
    order: VecDeque<(Dim, String)>,
    next_id: u64,
    /// 节点时钟偏移（秒，来自 hello 上报）：|offset| 超阈值 → 观测剔除
    offsets: HashMap<String, i64>,
}

impl Default for CorroborationEngine {
    fn default() -> Self {
        Self::new(CorroborationConfig::default())
    }
}

impl CorroborationEngine {
    pub fn new(cfg: CorroborationConfig) -> Self {
        Self {
            cfg,
            keys: HashMap::new(),
            order: VecDeque::new(),
            next_id: 1,
            offsets: HashMap::new(),
        }
    }

    /// hello 上报的节点时钟偏移。
    pub fn set_offset(&mut self, node: &str, offset_secs: i64) {
        self.offsets.insert(node.to_string(), offset_secs);
    }

    /// 该节点当前是否被时钟降权。
    pub fn is_demoted(&self, node: &str) -> bool {
        self.offsets
            .get(node)
            .is_some_and(|o| o.abs() > self.cfg.clock_demote_secs)
    }

    /// 记录一条观测并评估该键是否达成印证。返回新产出的组织印证事件（冷却期内
    /// 或节点数不足返回 None）。单节点重复上报只刷新时间戳，永不满足独立性。
    pub fn record(&mut self, obs: &Observation, now: i64) -> Option<OrgCorroboration> {
        self.prune(now);
        if self.is_demoted(&obs.node) {
            return None;
        }
        let id = (obs.dim, obs.key.clone());
        // 有界：先逐最旧再落新观测（当前键随后会重新排到队尾）
        while self.order.len() >= self.cfg.max_keys {
            if let Some(old) = self.order.pop_front() {
                self.keys.remove(&old);
            }
        }
        let state = self.keys.entry(id.clone()).or_default();
        let e = state
            .nodes
            .entry(obs.node.clone())
            .or_insert_with(|| NodeObs {
                first_ts: obs.ts,
                last_ts: obs.ts,
            });
        e.first_ts = e.first_ts.min(obs.ts);
        e.last_ts = e.last_ts.max(obs.ts);
        state.last_active = state.last_active.max(obs.ts);
        self.order.retain(|k| k != &id);
        self.order.push_back(id.clone());

        // 独立节点数：窗口内有观测的去重节点名数
        let window_start = now - self.cfg.window_secs;
        let active: Vec<&String> = state
            .nodes
            .iter()
            .filter(|(_, o)| o.last_ts >= window_start)
            .map(|(n, _)| n)
            .collect();
        if (active.len() as u32) < self.cfg.min_nodes {
            return None;
        }
        // 冷却：同一攻击者键一窗一报
        if let Some(last) = state.last_emitted
            && now - last < self.cfg.emit_cooldown_secs
        {
            return None;
        }
        state.last_emitted = Some(now);
        let mut nodes: Vec<String> = active.into_iter().cloned().collect();
        nodes.sort();
        let (first_ts, last_ts) = state
            .nodes
            .values()
            .fold((obs.ts, obs.ts), |(f, l), o| (f.min(o.first_ts), l.max(o.last_ts)));
        let oc = OrgCorroboration {
            id: self.next_id,
            ts: now,
            dim: obs.dim,
            key: obs.key.clone(),
            nodes,
            first_ts,
            last_ts,
            severity: obs.dim.severity().to_string(),
        };
        self.next_id += 1;
        Some(oc)
    }

    /// quorum（min_peers 自动应用门控）用：某源 IP 在 since 以来被几个独立节点观测过。
    /// 0.4 的 fed_reporter_count（查协调者本地 events 表）随「协调者不持久化节点事件」
    /// 一并切换到这里（内存窗口，重启清零 = 降级本地策略，与单节点部署同语义）。
    pub fn reporter_count(&self, ip: &str, since: i64) -> u32 {
        self.keys
            .get(&(Dim::Ip, ip.to_string()))
            .map(|s| {
                s.nodes
                    .values()
                    .filter(|o| o.last_ts >= since)
                    .count() as u32
            })
            .unwrap_or(0)
    }

    /// 清扫：超保留窗的观测/键全部丢弃（对齐重放窗哲学：老观测只在外部审计日志里）。
    fn prune(&mut self, now: i64) {
        let cutoff = now - self.cfg.retain_secs;
        self.keys.retain(|_, s| {
            s.nodes.retain(|_, o| o.last_ts >= cutoff);
            s.last_active >= cutoff
        });
        self.order.retain(|k| self.keys.contains_key(k));
        self.offsets.retain(|_, _| true); // 偏移表随节点生命周期，体积小不扫
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(node: &str, ts: i64, dim: Dim, key: &str) -> Observation {
        Observation {
            node: node.to_string(),
            ts,
            dim,
            key: key.to_string(),
        }
    }

    #[test]
    fn two_nodes_trigger_one_node_does_not() {
        let mut e = CorroborationEngine::default();
        let now = 10_000;
        // 单节点三次观测：独立性不满足
        assert!(e.record(&obs("a", now, Dim::Ip, "203.0.113.7"), now).is_none());
        assert!(e.record(&obs("a", now + 10, Dim::Ip, "203.0.113.7"), now + 10).is_none());
        assert!(e.record(&obs("a", now + 20, Dim::Ip, "203.0.113.7"), now + 20).is_none());
        // 第二个节点 → 印证产出
        let oc = e
            .record(&obs("b", now + 30, Dim::Ip, "203.0.113.7"), now + 30)
            .expect("双节点应触发");
        assert_eq!(oc.nodes, vec!["a", "b"]);
        assert_eq!(oc.dim, Dim::Ip);
        assert_eq!(oc.severity, "high");
        assert_eq!(oc.id, 1);
    }

    #[test]
    fn window_expiry_and_cooldown() {
        let mut e = CorroborationEngine::default();
        let now = 10_000;
        e.record(&obs("a", now, Dim::Ip, "9.9.9.9"), now);
        // 窗口外（默认 600s）第二节点 → 不触发
        assert!(e
            .record(&obs("b", now + 700, Dim::Ip, "9.9.9.9"), now + 700)
            .is_none());
        // 窗口内第二节点 → 触发；冷却期内第三节点加入 → 不再产
        let oc = e
            .record(&obs("b", now + 100, Dim::Ip, "9.9.9.9"), now + 100)
            .expect("应触发");
        assert_eq!(oc.id, 1);
        assert!(e
            .record(&obs("c", now + 110, Dim::Ip, "9.9.9.9"), now + 110)
            .is_none(), "冷却期内不重复产出");
        // 冷却期过后再触发 → 新 id
        let oc2 = e
            .record(&obs("d", now + 100 + 601, Dim::Ip, "9.9.9.9"), now + 100 + 601)
            .expect("冷却后应再产出");
        assert_eq!(oc2.id, 2);
    }

    #[test]
    fn clock_demotion_excludes_node() {
        let mut e = CorroborationEngine::default();
        let now = 10_000;
        e.set_offset("bad", 30); // 偏移 30s > 5s 阈值
        e.record(&obs("bad", now, Dim::Ip, "8.8.8.8"), now);
        assert!(e
            .record(&obs("good", now, Dim::Ip, "8.8.8.8"), now)
            .is_none(), "被降权节点的观测不参与独立性计数");
        assert!(e.is_demoted("bad"));
        // 偏移恢复（NTP 校正）后自动解除
        e.set_offset("bad", 1);
        let oc = e
            .record(&obs("bad", now + 5, Dim::Ip, "8.8.8.8"), now + 5)
            .expect("降权解除后应参与");
        assert_eq!(oc.nodes, vec!["bad", "good"]);
    }

    #[test]
    fn dimensions_and_lateral_severity() {
        let mut e = CorroborationEngine::default();
        let now = 10_000;
        // 指纹维度
        e.record(&obs("a", now, Dim::Fingerprint, "a67dc37c..."), now);
        let oc = e
            .record(&obs("b", now, Dim::Fingerprint, "a67dc37c..."), now)
            .expect("指纹维度应触发");
        assert_eq!(oc.dim, Dim::Fingerprint);
        // 凭证维度（v1 用户名）
        e.record(&obs("a", now, Dim::Credential, "admin"), now);
        assert!(e
            .record(&obs("b", now, Dim::Credential, "admin"), now)
            .is_some());
        // 蜜饵维度 = critical
        e.record(&obs("a", now, Dim::Canary, "10.1.2.3"), now);
        let oc = e
            .record(&obs("b", now, Dim::Canary, "10.1.2.3"), now)
            .expect("蜜饵维度应触发");
        assert_eq!(oc.severity, "critical");
    }

    #[test]
    fn reporter_count_distinct_nodes() {
        let mut e = CorroborationEngine::default();
        let now = 10_000;
        e.record(&obs("a", now, Dim::Ip, "203.0.113.7"), now);
        e.record(&obs("a", now + 1, Dim::Ip, "203.0.113.7"), now + 1);
        e.record(&obs("b", now + 2, Dim::Ip, "203.0.113.7"), now + 2);
        e.record(&obs("a", now, Dim::Ip, "1.2.3.4"), now); // 别的 IP 不计
        assert_eq!(e.reporter_count("203.0.113.7", now - 10), 2);
        assert_eq!(e.reporter_count("203.0.113.7", now + 5), 0, "since 之后无观测");
        assert_eq!(e.reporter_count("无此IP", now - 10), 0);
    }

    #[test]
    fn bounded_keys_evict_oldest() {
        let mut e = CorroborationEngine::new(CorroborationConfig {
            max_keys: 3,
            ..Default::default()
        });
        let now = 10_000;
        for i in 0..5 {
            e.record(&obs("a", now, Dim::Ip, &format!("10.0.0.{i}")), now + i);
        }
        assert_eq!(e.reporter_count("10.0.0.0", 0), 0, "最旧的已被逐出");
        assert_eq!(e.reporter_count("10.0.0.4", 0), 1);
    }

    #[test]
    fn prune_drops_stale_within_retain_window() {
        let mut e = CorroborationEngine::default();
        let now = 10_000;
        e.record(&obs("a", now, Dim::Ip, "10.0.0.1"), now);
        e.record(&obs("b", now, Dim::Ip, "10.0.0.1"), now);
        // 25h 后全部过期（保留窗 24h）
        e.record(&obs("a", now + 25 * 3600, Dim::Ip, "10.0.0.2"), now + 25 * 3600);
        assert_eq!(e.reporter_count("10.0.0.1", 0), 0, "超保留窗的观测被清扫");
    }

    /// 红线自动化断言：组织印证消息不含任何凭证材料/口令字段。
    #[test]
    fn org_message_has_no_credential_material() {
        let mut e = CorroborationEngine::default();
        let now = 10_000;
        e.record(&obs("a", now, Dim::Credential, "admin"), now);
        let oc = e
            .record(&obs("b", now, Dim::Credential, "admin"), now)
            .expect("应触发");
        let j = oc.to_json().to_string();
        assert!(
            !j.contains("pass_hash") && !j.contains("password") && !j.contains("argon"),
            "组织印证消息不得携带凭证材料: {j}"
        );
        // 序列化只含白名单键
        let obj = oc.to_json();
        for k in obj.as_object().unwrap().keys() {
            assert!(
                ["id", "ts", "dim", "key", "nodes", "first_ts", "last_ts", "severity"]
                    .contains(&k.as_str()),
                "非白名单字段: {k}"
            );
        }
    }
}
