//! 事件外发通道（0.3.5，对应 ROADMAP「日志远程转发 / 报表导出与告警通知」）。
//!
//! 职责单一：把事件总线的流转发给外部系统（syslog 收集器 / Webhook 接收端），
//! 并周期执行暴露面快照。三条纪律：
//! 1. **只读总线，不产事件**——转发器绝不 publish 事件（失败只走 tracing），
//!    避免自反馈风暴（外发失败 → engine 事件 → 再外发 → …）。
//! 2. **best-effort 不阻塞**——目标不可达丢弃本条并留痕，绝不让外发拖住引擎；
//!    完整性以本地哈希链（verify-log / export-events）为准，外发是副本不是审计源。
//! 3. **severity 单一口径**——两通道共用 [`SecurityEvent::severity`]（RFC 5424 数值，
//!    越小越严重），保证"多严重才告警"在 syslog 与 webhook 一致。

use std::sync::Arc;
use std::time::Duration;

use aisafeguard_core::event::SecurityEvent;

use crate::engine::EngineHandle;

/// RFC 5424 Facility：daemon（安全软件的惯例归属）。
const FACILITY_DAEMON: u8 = 3;
const APP_NAME: &str = "aisafeguard";

/// 本机主机名（syslog HOSTNAME 字段 / webhook payload）。
pub fn hostname() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".into())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "localhost".into())
    }
}

/// 单条事件 → RFC 5424 行（不含帧尾换行）。
/// `<PRI>1 ISO8601 HOST APP PROCID MSGID - MSG`；MSG 内控制字符归空格（含换行，
/// 保证 TCP 换行分帧下一条报文不会拆成多条）。
pub fn syslog_line(facility: u8, hostname: &str, pid: u32, ev: &SecurityEvent) -> String {
    let pri = facility * 8 + ev.severity();
    let ts = chrono::DateTime::from_timestamp(ev.ts(), 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ");
    let msg: String = ev
        .summary()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!(
        "<{pri}>1 {ts} {host} {app} {pid} {msgid} - {msg}",
        host = sanitize_token(hostname),
        app = APP_NAME,
        msgid = ev.kind(),
        msg = msg,
    )
}

/// HOSTNAME 等字段只允许可见 ASCII 图形字符（RFC 5424 值域），防御性收敛。
fn sanitize_token(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic())
        .take(255)
        .collect()
}

/// 解析 syslog 收集器地址：`ip:port` 字面量 / `host:port` 域名 / 无端口（补 514）。
async fn resolve_target(target: &str) -> Option<std::net::SocketAddr> {
    if let Ok(a) = target.parse::<std::net::SocketAddr>() {
        return Some(a);
    }
    if let Some(a) = tokio::net::lookup_host(target.to_string())
        .await
        .ok()
        .and_then(|mut it| it.next())
    {
        return Some(a);
    }
    tokio::net::lookup_host(format!("{target}:514"))
        .await
        .ok()?
        .next()
}

/// syslog 转发任务：常驻订阅事件总线，按配置转发到 UDP/TCP 收集器。
/// 配置改动（GUI/API 保存）下一条事件即生效；协议非法按 UDP 处理并留痕。
pub fn spawn_syslog_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut rx = eng.bus.subscribe();
        let host = hostname();
        let pid = std::process::id();
        let mut udp: Option<tokio::net::UdpSocket> = None;
        let mut tcp: Option<tokio::net::TcpStream> = None;
        let mut warned_protocol = false;
        let mut warned_target = false;
        loop {
            let ev = match rx.recv().await {
                Ok(ev) => ev,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // 慢消费被丢弃的事件数：记录即可，绝不追补（best-effort）
                    tracing::warn!("syslog 转发跟不上事件流，丢弃 {n} 条");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let cfg = eng.config().syslog;
            if !cfg.enabled || cfg.target.is_empty() {
                continue;
            }
            let use_tcp = match cfg.protocol.as_str() {
                "tcp" => true,
                "udp" => false,
                other => {
                    if !warned_protocol {
                        tracing::warn!("syslog.protocol 非法（{other}），按 UDP 处理");
                        warned_protocol = true;
                    }
                    false
                }
            };
            let peer = match resolve_target(&cfg.target).await {
                Some(a) => a,
                None => {
                    if !warned_target {
                        tracing::warn!("syslog.target 无法解析: {}", cfg.target);
                        warned_target = true;
                    }
                    continue;
                }
            };
            let line = syslog_line(FACILITY_DAEMON, &host, pid, &ev);
            if use_tcp {
                if tcp.is_none() {
                    match tokio::time::timeout(
                        Duration::from_secs(3),
                        tokio::net::TcpStream::connect(peer),
                    )
                    .await
                    {
                        Ok(Ok(s)) => tcp = Some(s),
                        _ => {
                            tcp = None;
                            tracing::debug!("syslog TCP 连接失败: {peer}");
                            continue;
                        }
                    }
                }
                use tokio::io::AsyncWriteExt;
                let stream = tcp.as_mut().expect("TCP 流已建立");
                if let Err(e) = stream.write_all(line.as_bytes()).await {
                    tcp = None;
                    tracing::debug!("syslog TCP 发送失败重连: {e}");
                    continue;
                }
                let _ = stream.write_all(b"\n").await;
            } else {
                if udp.is_none() {
                    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => udp = Some(s),
                        Err(e) => {
                            tracing::warn!("syslog UDP 套接字创建失败: {e}");
                            continue;
                        }
                    }
                }
                let _ = udp
                    .as_ref()
                    .expect("UDP 套接字已建立")
                    .send_to(line.as_bytes(), peer)
                    .await;
            }
        }
    });
}

/// Webhook 告警任务：severity 达到 min_severity 的事件 POST JSON 到接收端。
/// 请求超时（配置）与失败都只丢本条；失败留 tracing 且 60 秒限频，防目标宕机刷日志。
/// F-webhook：HMAC-SHA256 请求签名（Stripe/GitHub webhook 同款语义）。
/// 覆盖 "{timestamp}.{原始字节}"——接收方以同密钥同序重算比对 + 时间窗防重放。
/// 能力边界：HMAC 只证明「传输未被第三方篡改」，不构成可审计证据
/// （THREAT_MODEL「证据语义」：可审计 = 本地哈希链 + fed 证书签名）。
pub fn webhook_sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let mut msg = Vec::with_capacity(body.len() + 21);
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(body);
    let tag = ring::hmac::sign(&key, &msg);
    let mut out = String::with_capacity(64);
    for b in tag.as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 签名密钥：环境变量 `AISAFEGUARD_WEBHOOK_SECRET` 最高优先（CI/无头/服务注入），
/// 其次凭据管理器（webhook-secret）——与 AI Key 同款双通道。
fn webhook_secret() -> Option<String> {
    if let Ok(v) = std::env::var("AISAFEGUARD_WEBHOOK_SECRET")
        && !v.is_empty()
    {
        return Some(v);
    }
    aisafeguard_core::secrets::webhook_secret()
}

/// F-webhook 重试（拍板三件套：指数退避 + 硬上限 + 丢弃留计数）。
/// 内存队列不落盘——外发是副本，本地哈希链才是真源，重启清空可接受。
/// 纪律不破：队列有界（满 = 丢新留旧）、重试搭车不堵主线（500ms tick）、
/// 退避给接收端喘息（10s/30s/60s，覆盖接收端重启窗口，总窗 ~100s < 2 分钟）。
struct WebhookRetryItem {
    body: Vec<u8>,
    signed: bool,
    attempts: u32,
    next_try: std::time::Instant,
}

struct WebhookRetryQueue {
    q: std::collections::VecDeque<WebhookRetryItem>,
    dropped: u64,
}

impl WebhookRetryQueue {
    const CAP: usize = 100;
    /// 原始 1 发 + 最多 3 次重试
    const MAX_ATTEMPTS: u32 = 3;

    fn new() -> Self {
        Self {
            q: std::collections::VecDeque::new(),
            dropped: 0,
        }
    }

    /// 重试退避表：第 1/2/3 次重试分别等 10s/30s/60s。
    fn delay(attempts: u32) -> Duration {
        Duration::from_secs(match attempts {
            0 => 10,
            1 => 30,
            _ => 60,
        })
    }

    /// 首发失败入队。满 = 丢新留旧（返回 false，dropped 已计数）。
    fn push(&mut self, body: Vec<u8>, signed: bool, now: std::time::Instant) -> bool {
        if self.q.len() >= Self::CAP {
            self.dropped += 1;
            return false;
        }
        self.q.push_back(WebhookRetryItem {
            body,
            signed,
            attempts: 0,
            next_try: now + Self::delay(0),
        });
        true
    }

    /// 取出到期的重试项（发送失败由调用方 requeue 或放弃）。
    fn take_due(&mut self, now: std::time::Instant) -> Vec<WebhookRetryItem> {
        let mut out = Vec::new();
        let mut keep = std::collections::VecDeque::new();
        while let Some(it) = self.q.pop_front() {
            if it.next_try <= now {
                out.push(it);
            } else {
                keep.push_back(it);
            }
        }
        self.q = keep;
        out
    }

    /// 重发失败再入队；重试次数用尽或队满 = 放弃（dropped 计数）。返回 false = 已放弃。
    fn requeue(&mut self, mut item: WebhookRetryItem, now: std::time::Instant) -> bool {
        item.attempts += 1;
        if item.attempts > Self::MAX_ATTEMPTS || self.q.len() >= Self::CAP {
            self.dropped += 1;
            return false;
        }
        item.next_try = now + Self::delay(item.attempts);
        self.q.push_back(item);
        true
    }

    /// 通道关闭 = 队列作废（副本语义）。
    fn clear(&mut self) {
        self.q.clear();
    }

    fn dropped(&self) -> u64 {
        self.dropped
    }
}

enum WebhookFail {
    /// sign 开而未配密钥（不入重试——丢弃 + 限频告警）
    NoSecret,
    Status(u16),
    Transport(String),
}

/// 发送一条已序列化的 webhook 请求（签名在发送时打新鲜时间戳——重试不吃旧时间戳，
/// 避免被接收方重放窗拒收）。
async fn send_webhook(
    http: &reqwest::Client,
    url: &str,
    sign: bool,
    body: &[u8],
) -> Result<(), WebhookFail> {
    let mut req = http.post(url).header("content-type", "application/json");
    if sign {
        let Some(secret) = webhook_secret() else {
            return Err(WebhookFail::NoSecret);
        };
        let ts = aisafeguard_core::now_ts();
        req = req
            .header("X-AISafeGuard-Timestamp", ts.to_string())
            .header(
                "X-AISafeGuard-Signature",
                format!("v1={}", webhook_sign(&secret, ts, body)),
            );
    }
    match req.body(body.to_vec()).send().await {
        Ok(resp) if !resp.status().is_success() => Err(WebhookFail::Status(resp.status().as_u16())),
        Ok(_) => Ok(()),
        Err(e) => Err(WebhookFail::Transport(e.to_string())),
    }
}

pub fn spawn_notify_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut rx = eng.bus.subscribe();
        let host = hostname();
        let mut client: Option<(u64, reqwest::Client)> = None;
        let mut last_fail: Option<std::time::Instant> = None;
        let mut retry = WebhookRetryQueue::new();
        let mut drops_logged: u64 = 0;
        let mut last_drop_log: Option<std::time::Instant> = None;
        loop {
            // 500ms tick：到期重试不依赖新事件到来（重试搭车，不堵主线）
            let ev = match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                Ok(Ok(ev)) => Some(ev),
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    tracing::warn!("webhook 转发跟不上事件流，丢弃 {n} 条");
                    None
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                Err(_) => None,
            };
            let cfg = eng.config().notify;
            if !cfg.enabled || cfg.url.is_empty() {
                retry.clear(); // 通道关闭 = 队列作废（副本语义）
                continue;
            }
            // 超时配置变更时重建 client（廉价，仅在值变化时发生）
            if !matches!(&client, Some((t, _)) if *t == cfg.timeout_secs) {
                match reqwest::Client::builder()
                    .timeout(Duration::from_secs(cfg.timeout_secs.clamp(1, 120)))
                    .build()
                {
                    Ok(c) => client = Some((cfg.timeout_secs, c)),
                    Err(e) => {
                        tracing::warn!("webhook HTTP client 构建失败: {e}");
                        continue;
                    }
                }
            }
            let http = client.as_ref().expect("client 已构建").1.clone();

            // 1) 到期重试先于新事件（旧事优先）
            for item in retry.take_due(std::time::Instant::now()) {
                if send_webhook(&http, &cfg.url, item.signed, &item.body)
                    .await
                    .is_err()
                    && !retry.requeue(item, std::time::Instant::now())
                {
                    // 放弃已计数；周期日志统一播报
                }
            }
            let drops = retry.dropped();
            if drops > drops_logged
                && last_drop_log
                    .map(|t| t.elapsed() >= Duration::from_secs(60))
                    .unwrap_or(true)
            {
                tracing::warn!(
                    "webhook 重试放弃，累计丢弃 {drops} 条事件（本地哈希链为真源）"
                );
                drops_logged = drops;
                last_drop_log = Some(std::time::Instant::now());
            }

            // 2) 新事件
            let Some(ev) = ev else { continue };
            let sev = ev.severity();
            let threshold = SecurityEvent::severity_threshold(&cfg.min_severity);
            if sev > threshold {
                continue;
            }
            let body = serde_json::json!({
                "host": host,
                "severity": SecurityEvent::severity_name(sev),
                "summary": ev.summary(),
                "event": serde_json::to_value(&ev).unwrap_or_default(),
            });
            // 签名覆盖「将发送的原始字节」（序列化一次，签发同字节——接收方逐字节重算）
            let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
            match send_webhook(&http, &cfg.url, cfg.sign, &body_bytes).await {
                Ok(()) => {
                    last_fail = None;
                }
                Err(WebhookFail::NoSecret) => {
                    // 开而不设密钥 = 丢弃不发送（不做静默降级，不入重试）
                    if last_fail
                        .map(|t| t.elapsed() >= Duration::from_secs(60))
                        .unwrap_or(true)
                    {
                        tracing::warn!(
                            "[notify].sign 已开启但未配置密钥（AISAFEGUARD_WEBHOOK_SECRET 或凭据管理器 webhook-secret）：事件丢弃不发送"
                        );
                        last_fail = Some(std::time::Instant::now());
                    }
                }
                Err(WebhookFail::Status(code)) => {
                    if last_fail
                        .map(|t| t.elapsed() >= Duration::from_secs(60))
                        .unwrap_or(true)
                    {
                        tracing::warn!("webhook 返回 {code}（本条进入重试队列）");
                        last_fail = Some(std::time::Instant::now());
                    }
                    retry.push(body_bytes, cfg.sign, std::time::Instant::now());
                }
                Err(WebhookFail::Transport(e)) => {
                    if last_fail
                        .map(|t| t.elapsed() >= Duration::from_secs(60))
                        .unwrap_or(true)
                    {
                        tracing::warn!("webhook 发送失败（进入重试队列，60s 内不重复记录）: {e}");
                        last_fail = Some(std::time::Instant::now());
                    }
                    retry.push(body_bytes, cfg.sign, std::time::Instant::now());
                }
            }
        }
    });
}

/// 暴露面定时自动扫描：auto_scan_secs=0 关闭（每分钟复查配置，保存后可即时启用）。
/// 启动后 30 秒先扫一轮（与情报任务"启动首轮"先例一致），之后按配置间隔。
pub fn spawn_exposure_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut first_round = true;
        loop {
            let secs = eng.config().exposure.auto_scan_secs;
            if secs == 0 {
                first_round = true;
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
            let interval = Duration::from_secs(secs.clamp(300, 86_400));
            tokio::time::sleep(if first_round {
                first_round = false;
                Duration::from_secs(30)
            } else {
                interval
            })
            .await;
            match eng.scan_exposure() {
                Ok(entries) => {
                    // 绑定在未指定地址（0.0.0.0/[::]）的监听是暴露面重点
                    let risky = entries
                        .iter()
                        .filter(|e| {
                            let host = e.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(&e.addr);
                            host.trim_matches(['[', ']'])
                                .parse::<std::net::IpAddr>()
                                .map(|a| a.is_unspecified())
                                .unwrap_or(false)
                        })
                        .count();
                    if risky > 0 {
                        tracing::info!(
                            "定时暴露面扫描：{} 项，其中 {} 项绑定全部地址",
                            entries.len(),
                            risky
                        );
                    }
                }
                Err(e) => tracing::warn!("定时暴露面扫描失败（下轮重试）: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_retry_queue_policy() {
        let t0 = std::time::Instant::now();
        let mut q = WebhookRetryQueue::new();
        // 退避表：10s/30s/60s
        assert_eq!(WebhookRetryQueue::delay(0).as_secs(), 10);
        assert_eq!(WebhookRetryQueue::delay(1).as_secs(), 30);
        assert_eq!(WebhookRetryQueue::delay(2).as_secs(), 60);
        assert_eq!(WebhookRetryQueue::delay(9).as_secs(), 60, "封顶 60s");
        // 未到期不可取
        q.push(b"e1".to_vec(), false, t0);
        assert!(q.take_due(t0).is_empty(), "未到 10s 退避不应到期");
        // 到期可取；重发失败再入队 → 第二档 30s
        let items = q.take_due(t0 + Duration::from_secs(10));
        assert_eq!(items.len(), 1);
        assert!(q.requeue(items.into_iter().next().unwrap(), t0 + Duration::from_secs(10)));
        assert!(q.take_due(t0 + Duration::from_secs(20)).is_empty(), "30s 档未到");
        // 放弃：重试次数用尽（0 首发 + 3 重试 = 4 发）
        let mut q2 = WebhookRetryQueue::new();
        q2.push(b"e".to_vec(), false, t0);
        let mut item = q2.take_due(t0 + Duration::from_secs(10)).pop().unwrap();
        for (attempt, wait) in [(1u32, 30u64), (2, 60), (3, 60)] {
            assert!(q2.requeue(item, t0), "第 {attempt} 次重试应入队");
            item = q2.take_due(t0 + Duration::from_secs(wait)).pop().unwrap();
            assert_eq!(item.attempts, attempt);
        }
        assert!(!q2.requeue(item, t0), "第 4 次失败应放弃");
        assert_eq!(q2.dropped(), 1);
        // 队满丢新留旧（cap 100：第 101 条被丢）
        let mut q3 = WebhookRetryQueue::new();
        for i in 0..WebhookRetryQueue::CAP {
            assert!(q3.push(format!("e{i}").into_bytes(), false, t0));
        }
        assert!(!q3.push(b"new".to_vec(), false, t0), "满后丢新");
        assert_eq!(q3.dropped(), 1);
        let due = q3.take_due(t0 + Duration::from_secs(60));
        assert_eq!(due.len(), WebhookRetryQueue::CAP);
        assert_eq!(due[0].body, b"e0".to_vec(), "最旧的保留");
    }

    /// F-webhook 已知向量：期望值由 python hashlib.hmac 独立预计算（非本实现自证）。
    /// HMAC-SHA256("test-secret", "1700000000.{\"hello\":\"world\"}")
    #[test]
    fn webhook_sign_matches_independent_vector() {
        let sig = webhook_sign("test-secret", 1_700_000_000, br#"{"hello":"world"}"#);
        assert_eq!(
            sig,
            "f85455a1b55ea86f7a15f5f9923d0abc4b888da84ec485f2ff358f427776beca"
        );
        assert_eq!(sig.len(), 64);
        // 任一输入变化 → 签名变化
        assert_ne!(webhook_sign("test-secret", 1_700_000_001, br#"{"hello":"world"}"#), sig);
        assert_ne!(webhook_sign("other-secret", 1_700_000_000, br#"{"hello":"world"}"#), sig);
        assert_ne!(webhook_sign("test-secret", 1_700_000_000, br#"{"hello":"world2"}"#), sig);
        // 空密钥/空体不 panic
        assert_eq!(webhook_sign("", 0, b"").len(), 64);
    }

    fn sample_event() -> SecurityEvent {
        SecurityEvent::Detection {
            ts: 1_792_000_000, // 2026-10-14T17:46:40Z（固定值，快照断言稳定）
            kind: "scan".into(),
            src_ip: "203.0.113.7".into(),
            confidence: "high".into(),
            severity: "medium".into(),
            evidence: "60 秒内对 4 个不同目标端口发送 SYN（采样捕获）".into(),
            rule_id: Some("builtin.tcp_scan".into()),
            http_hint: None,
            tls_fingerprint: None,
            tls_ja4: None,
        }
    }

    #[test]
    fn syslog_line_matches_rfc5424_shape() {
        let line = syslog_line(3, "wsl-host", 4242, &sample_event());
        // PRI = 3*8 + 4(warning) = 28
        assert!(
            line.starts_with("<28>1 2026-10-14T17:46:40Z wsl-host aisafeguard 4242 detection - "),
            "actual: {line}"
        );
        assert!(line.contains("[scan] 203.0.113.7: 60 秒内对"));
    }

    #[test]
    fn syslog_msg_strips_newlines_for_tcp_framing() {
        let ev = SecurityEvent::Engine {
            ts: 1_792_000_000,
            level: "error".into(),
            message: "第一行\n第二行\r\n第三行".into(),
        };
        let line = syslog_line(3, "h", 1, &ev);
        assert_eq!(line.lines().count(), 1, "MSG 含换行会破坏 TCP 分帧: {line}");
        assert!(!line.contains('\n') && !line.contains('\r'));
        // \n → 1 个空格，\r\n → 2 个空格（逐字符归位）
        assert!(line.contains("第一行 第二行  第三行"), "actual: {line}");
    }

    #[test]
    fn severity_mapping_and_thresholds() {
        assert_eq!(sample_event().severity(), 4); // detection = warning
        assert_eq!(
            SecurityEvent::Engine {
                ts: 0,
                level: "error".into(),
                message: String::new()
            }
            .severity(),
            3
        );
        assert_eq!(
            SecurityEvent::HoneypotHit {
                ts: 0,
                listener: String::new(),
                kind: String::new(),
                port: 0,
                remote_ip: String::new(),
                remote_port: 0,
                summary: String::new(),
                payload: String::new(),
                http_hint: None,
                interaction: None,
            }
            .severity(),
            5
        );
        assert_eq!(SecurityEvent::severity_threshold("info"), 6);
        assert_eq!(SecurityEvent::severity_threshold("error"), 3);
        // 非法配置值回退 warning
        assert_eq!(SecurityEvent::severity_threshold("随便"), 4);
    }

    #[test]
    fn hostname_falls_back_without_panic() {
        let h = hostname();
        assert!(!h.is_empty());
    }
}
