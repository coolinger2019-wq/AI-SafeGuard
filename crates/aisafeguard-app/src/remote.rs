//! 远程控制台：GUI（普通权限）→ 提权服务的 HTTP 客户端。
//!
//! 传输 = 127.0.0.1 + Bearer token（服务模式 token 发布在
//! `%PROGRAMDATA%\aisafeguard\api-token`，ProgramData 继承 ACL 使本机用户可读）。
//! 安全说明见 docs/ARCHITECTURE.md"服务化拆分"一节；0.3 演进为命名管道 + 调用方模拟。

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use aisafeguard_core::config::AppConfig;
use aisafeguard_firewall::BlockSpec;
use aisafeguard_store::{AiRunRow, EventRow, ProposalRow, RuleRow, StatsSummary};
use reqwest::blocking::Client;
use serde_json::json;

use crate::console::{Console, LiveEvent};
use crate::engine::StatusReport;

pub struct RemoteConsole {
    http: Client,
    base: String,
    token: String,
}

/// 服务数据目录（LocalSystem 可写、本机用户可读）。
pub fn service_data_dir() -> Option<PathBuf> {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .map(|d| d.join("aisafeguard"))
}

/// 探测本机是否有 AI-SafeGuard 服务在运行。
/// 条件：ProgramData 里存在服务发布的 token 文件，且用它能取到 /api/status。
pub fn probe_service() -> Option<RemoteConsole> {
    let data_dir = service_data_dir()?;
    let token = std::fs::read_to_string(data_dir.join("api-token"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    // 服务端口从服务侧配置读取，读不到用默认
    let port = std::fs::read_to_string(data_dir.join("config.toml"))
        .ok()
        .and_then(|raw| toml::from_str::<AppConfig>(&raw).ok())
        .map(|cfg| cfg.api.port)
        .unwrap_or(7420);
    let console = RemoteConsole::new(port, token);
    console.status().ok()?;
    Some(console)
}

impl RemoteConsole {
    pub fn new(port: u16, token: String) -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("HTTP client 构建失败"),
            base: format!("http://127.0.0.1:{port}"),
            token,
        }
    }

    fn check(&self, resp: reqwest::blocking::Response) -> anyhow::Result<reqwest::blocking::Response> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            let body = resp.json::<serde_json::Value>().unwrap_or_default();
            let msg = body["error"]
                .as_str()
                .unwrap_or("未知错误")
                .to_string();
            Err(anyhow!("HTTP {status}: {msg}"))
        }
    }

    fn get(&self, path: &str) -> anyhow::Result<reqwest::blocking::Response> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .send()
            .context("无法连接 AI-SafeGuard 服务")?;
        self.check(resp)
    }

    fn post(&self, path: &str) -> anyhow::Result<reqwest::blocking::Response> {
        let resp = self
            .http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .send()
            .context("无法连接 AI-SafeGuard 服务")?;
        self.check(resp)
    }

    fn post_json<T: serde::Serialize>(&self, path: &str, body: &T) -> anyhow::Result<reqwest::blocking::Response> {
        let resp = self
            .http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .context("无法连接 AI-SafeGuard 服务")?;
        self.check(resp)
    }
}

impl Console for RemoteConsole {
    fn version(&self) -> String {
        self.status().map(|s| s.version).unwrap_or_else(|_| "?".into())
    }

    fn config_paths(&self) -> (String, String) {
        let dir = service_data_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_else(|| "ProgramData".into());
        (format!("{dir}\\config.toml"), dir)
    }

    fn config(&self) -> anyhow::Result<AppConfig> {
        Ok(self.get("/api/config")?.json()?)
    }

    fn status(&self) -> anyhow::Result<StatusReport> {
        Ok(self.get("/api/status")?.json()?)
    }

    fn list_events(&self, limit: u32, ip_filter: Option<&str>) -> anyhow::Result<Vec<EventRow>> {
        let mut path = format!("/api/events?limit={limit}");
        if let Some(ip) = ip_filter {
            path.push_str(&format!("&ip={ip}"));
        }
        Ok(self.get(&path)?.json()?)
    }

    fn list_rules(&self) -> anyhow::Result<Vec<RuleRow>> {
        Ok(self.get("/api/rules")?.json()?)
    }

    fn list_proposals(&self, status: Option<&str>, limit: u32) -> anyhow::Result<Vec<ProposalRow>> {
        let path = match status {
            Some(s) => format!("/api/proposals?status={s}&limit={limit}"),
            None => format!("/api/proposals?limit={limit}"),
        };
        Ok(self.get(&path)?.json()?)
    }

    fn list_ai_runs(&self, limit: u32) -> anyhow::Result<Vec<AiRunRow>> {
        Ok(self.get(&format!("/api/ai/runs?limit={limit}"))?.json()?)
    }

    fn stats_24h(&self) -> anyhow::Result<StatsSummary> {
        Ok(self.get("/api/stats")?.json()?)
    }

    fn scan_exposure(&self) -> anyhow::Result<Vec<aisafeguard_detect::exposure::Entry>> {
        let snap: crate::engine::ExposureSnapshot = self.post("/api/exposure/scan")?.json()?;
        Ok(snap.entries)
    }

    fn latest_exposure(&self) -> anyhow::Result<Option<crate::engine::ExposureSnapshot>> {
        // 无快照时 API 返回 {"ts": null, "entries": []}
        let v: serde_json::Value = self.get("/api/exposure")?.json()?;
        if v["ts"].is_null() {
            return Ok(None);
        }
        let snap: crate::engine::ExposureSnapshot = serde_json::from_value(v)
            .map_err(|e| anyhow!("解析暴露面快照失败: {e}"))?;
        Ok(Some(snap))
    }

    fn add_block(&self, spec: &BlockSpec, origin: &str) -> anyhow::Result<RuleRow> {
        // origin 由服务侧固定为 manual/API；远程控制台只发规则内容
        let _ = origin;
        Ok(self
            .post_json(
                "/api/rules",
                &json!({
                    "direction": spec.direction.as_str(),
                    "protocol": spec.protocol.as_str(),
                    "remote_ip": spec.remote_ip.map(|i| i.to_string()),
                    "local_port": spec.local_port,
                    "note": spec.note,
                }),
            )?
            .json()?)
    }

    fn remove_rule(&self, id: i64) -> anyhow::Result<()> {
        self.check(
            self.http
                .delete(format!("{}/api/rules/{id}", self.base))
                .bearer_auth(&self.token)
                .send()
                .context("无法连接 AI-SafeGuard 服务")?,
        )?;
        Ok(())
    }

    fn apply_proposal(&self, id: i64) -> anyhow::Result<RuleRow> {
        Ok(self.post(&format!("/api/proposals/{id}/apply"))?.json()?)
    }

    fn dismiss_proposal(&self, id: i64) -> anyhow::Result<()> {
        self.post(&format!("/api/proposals/{id}/dismiss"))?;
        Ok(())
    }

    fn promote_rule(&self, id: i64) -> anyhow::Result<RuleRow> {
        Ok(self.post(&format!("/api/rules/{id}/promote"))?.json()?)
    }

    fn list_feedback(&self) -> anyhow::Result<Vec<aisafeguard_store::FpRow>> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, "/api/feedback"))
            .bearer_auth(&self.token)
            .send()
            .context("无法连接 AI-SafeGuard 服务")?;
        self.check(resp)?.json().context("响应解析失败")
    }

    fn clear_false_positive(&self, ip: &str) -> anyhow::Result<usize> {
        let path = format!("/api/feedback/{ip}");
        let body: serde_json::Value = self
            .check(
                self.http
                    .delete(format!("{}{path}", self.base))
                    .bearer_auth(&self.token)
                    .send()
                    .context("无法连接 AI-SafeGuard 服务")?,
            )?
            .json()
            .context("响应解析失败")?;
        Ok(body["removed"].as_u64().unwrap_or(0) as usize)
    }

    fn mark_false_positive(&self, ip: &str, note: &str, _local_port: Option<u16>) -> anyhow::Result<(i64, usize)> {
        let v: serde_json::Value = self
            .post_json("/api/feedback", &serde_json::json!({ "remote_ip": ip, "note": note }))?
            .json()?;
        Ok((
            v["dismissed_proposals"].as_i64().unwrap_or(0),
            v["removed_rules"].as_i64().unwrap_or(0) as usize,
        ))
    }

    fn trigger_analysis(&self) -> bool {
        self.post("/api/ai/analyze").is_ok()
    }

    fn save_config(&self, cfg: AppConfig) -> anyhow::Result<()> {
        self.post_json("/api/config", &cfg)?;
        Ok(())
    }

    fn ai_key_present(&self) -> anyhow::Result<bool> {
        let v: serde_json::Value = self.get("/api/ai/key")?.json()?;
        Ok(v["present"].as_bool().unwrap_or(false))
    }

    fn set_ai_key(&self, value: &str) -> anyhow::Result<()> {
        self.post_json("/api/ai/key", &json!({ "key": value }))?;
        Ok(())
    }

    fn delete_ai_key(&self) -> anyhow::Result<()> {
        self.check(
            self.http
                .delete(format!("{}/api/ai/key", self.base))
                .bearer_auth(&self.token)
                .send()
                .context("无法连接 AI-SafeGuard 服务")?,
        )?;
        Ok(())
    }

    fn live_events(&self) -> mpsc::Receiver<LiveEvent> {
        let (tx, rx) = mpsc::channel();
        let console = RemoteConsole::new(
            self.base
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
                .unwrap_or(7420),
            self.token.clone(),
        );
        std::thread::spawn(move || {
            let mut last_id: i64 = 0;
            loop {
                // 按 id 升序转发差量；首次只对齐水位不回灌历史
                if let Ok(rows) = console.list_events(200, None) {
                    let mut new_rows: Vec<EventRow> = rows
                        .into_iter()
                        .filter(|e| e.id > last_id)
                        .collect();
                    new_rows.sort_by_key(|e| e.id);
                    if let Some(max_id) = new_rows.last().map(|e| e.id) {
                        if last_id == 0 {
                            // 首轮只对齐水位
                            last_id = max_id;
                        } else {
                            for e in new_rows {
                                last_id = last_id.max(e.id);
                                if tx.send(LiveEvent {
                                    kind: e.kind,
                                    ts: e.ts,
                                    summary: e.summary,
                                })
                                .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        });
        rx
    }
}
