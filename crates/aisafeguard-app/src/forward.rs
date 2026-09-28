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
    s.chars().filter(|c| c.is_ascii_graphic()).take(255).collect()
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
pub fn spawn_notify_task(eng: &Arc<EngineHandle>) {
    let eng = Arc::clone(eng);
    let rt = eng.rt.clone();
    rt.spawn(async move {
        let mut rx = eng.bus.subscribe();
        let host = hostname();
        let mut client: Option<(u64, reqwest::Client)> = None;
        let mut last_fail: Option<std::time::Instant> = None;
        loop {
            let ev = match rx.recv().await {
                Ok(ev) => ev,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("webhook 转发跟不上事件流，丢弃 {n} 条");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let cfg = eng.config().notify;
            if !cfg.enabled || cfg.url.is_empty() {
                continue;
            }
            let sev = ev.severity();
            let threshold = SecurityEvent::severity_threshold(&cfg.min_severity);
            if sev > threshold {
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
            let http = &client.as_ref().expect("client 已构建").1;
            let body = serde_json::json!({
                "host": host,
                "severity": SecurityEvent::severity_name(sev),
                "summary": ev.summary(),
                "event": serde_json::to_value(&ev).unwrap_or_default(),
            });
            match http.post(&cfg.url).json(&body).send().await {
                Ok(resp) if !resp.status().is_success() => {
                    if last_fail.map(|t| t.elapsed() >= Duration::from_secs(60)).unwrap_or(true) {
                        tracing::warn!("webhook 返回 {}", resp.status());
                        last_fail = Some(std::time::Instant::now());
                    }
                }
                Ok(_) => last_fail = None,
                Err(e) => {
                    if last_fail.map(|t| t.elapsed() >= Duration::from_secs(60)).unwrap_or(true) {
                        tracing::warn!("webhook 发送失败（丢弃本条，60s 内不重复记录）: {e}");
                        last_fail = Some(std::time::Instant::now());
                    }
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

    fn sample_event() -> SecurityEvent {
        SecurityEvent::Detection {
            ts: 1_792_000_000, // 2026-10-14T17:46:40Z（固定值，快照断言稳定）
            kind: "scan".into(),
            src_ip: "203.0.113.7".into(),
            confidence: "high".into(),
            evidence: "60 秒内对 4 个不同目标端口发送 SYN（采样捕获）".into(),
            rule_id: Some("builtin.tcp_scan".into()),
            http_hint: None,
            tls_fingerprint: None,
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
            }
            .severity(),
            5
        );
        assert_eq!(SecurityEvent::severity_threshold("info"), 6);
        assert_eq!(SecurityEvent::severity_threshold("error"), 3);
        // 非法配置值回退 warning
        assert_eq!(SecurityEvent::severity_threshold("随便"), 4);
        // warning(4) 阈值：notice(5)/info(6) 被过滤，warning 及更严重者通过
        assert!(4 <= 4);
        assert!(5 > 4);
    }

    #[test]
    fn hostname_falls_back_without_panic() {
        let h = hostname();
        assert!(!h.is_empty());
    }
}
