use super::*;

impl AisafeApp {
    pub(crate) fn ai_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(t("AI 助手", "AI Assistant"))
                .size(type_scale::TITLE)
                .strong(),
        );
        ui.add_space(space::M);

        let status = self.cache.status.clone();
        let ai = status.as_ref().map(|s| s.ai.clone());

        if let Some(ai) = &ai {
            ui.horizontal_wrapped(|ui| {
                chip(
                    ui,
                    if ai.enabled {
                        t("AI 已启用", "AI Enabled")
                    } else {
                        t("AI 未启用", "AI Disabled")
                    },
                    if ai.enabled { ok() } else { text_dim() },
                );
                chip(
                    ui,
                    &format!("Key: {}", ai.key_source),
                    if ai.key_source == t("未配置", "Not configured") {
                        warn()
                    } else {
                        text_dim()
                    },
                );
                chip(ui, &ai.model, accent());
                chip(
                    ui,
                    &if ai.auto_apply {
                        format!(
                            "{}{}",
                            t("自动应用 ≥", "Auto apply ≥"),
                            ai.auto_apply_min_severity
                        )
                    } else {
                        t("自动应用关闭", "Auto apply off").to_string()
                    },
                    if ai.auto_apply { warn() } else { text_dim() },
                );
            });
        }

        ui.add_space(space::M);
        ui.horizontal(|ui| {
            let running = ai.as_ref().map(|a| a.running).unwrap_or(false);
            let resp = ui.add_enabled(
                !running,
                egui::Button::new(RichText::new(t("立即分析", "Analyze Now")).color(on_accent()))
                    .fill(accent())
                    .corner_radius(CornerRadius::same(6)),
            );
            if running {
                ui.spinner();
                ui.label(RichText::new(t("分析中…", "Analyzing…")).color(text_dim()));
            }
            if resp.clicked() {
                if self.eng.trigger_analysis() {
                    self.set_toast(t("AI 分析已开始", "AI analysis started"));
                } else {
                    self.set_toast(t("已有分析在运行", "An analysis is already running"));
                }
            }
            if let Some(ai) = &ai {
                ui.label(
                    RichText::new(format!(
                        "{}{} {}",
                        t("自动分析间隔", "Auto-analysis every"),
                        ai.analyze_interval_secs,
                        t("秒", "s")
                    ))
                    .size(type_scale::CAPTION)
                    .color(text_dim()),
                );
            }
        });
        ui.label(
            RichText::new(t("分析内容仅为 24h 聚合统计与最近 20 条截断记录；建议需人工确认，蜜罐数据按不可信输入隔离。", "Analysis input is 24h aggregate stats and the latest 20 truncated records; proposals need human confirmation; honeypot data is treated as untrusted input."))
                .size(type_scale::MICRO)
                .color(text_dim()),
        );

        ui.add_space(space::L);
        // 主机暴露面（0.2 P1：t("自动分析功能接口", "Auto-analysis API")第一步）
        section(ui, t("主机暴露面", "Host Exposure"));
        let exposure = self.eng.latest_exposure().ok().flatten();
        match &exposure {
            Some(snap) => {
                ui.label(
                    RichText::new(format!(
                        "{} {} · {} {}",
                        t("上次扫描", "Last scan"),
                        fmt_ts(snap.ts),
                        snap.entries.len(),
                        t(
                            "个监听端点（数据已随下次 AI 分析送评）",
                            "listening endpoints (data sent to next AI analysis)"
                        )
                    ))
                    .size(type_scale::CAPTION)
                    .color(text_dim()),
                );
                egui::CollapsingHeader::new(
                    egui::RichText::new(t("监听清单", "Listening Endpoints"))
                        .size(type_scale::BODY),
                )
                .id_salt("exposure-list")
                .default_open(false)
                .show(ui, |ui| {
                    for e in snap.entries.iter().take(30) {
                        ui.label(
                            RichText::new(format!("{}  {}  [{}]", e.addr, e.process, e.proto))
                                .monospace()
                                .size(type_scale::CAPTION),
                        );
                    }
                    if snap.entries.len() > 30 {
                        ui.label(
                            RichText::new(format!(
                                "{} {}",
                                t("…其余", "…and"),
                                snap.entries.len() - 30
                            ))
                            .size(type_scale::MICRO)
                            .color(text_dim()),
                        );
                    }
                });
            }
            None => {
                ui.label(
                    RichText::new(
                        "尚未扫描。扫描会枚举本机监听端口与归属进程，并作为下次 AI 分析的输入。",
                    )
                    .size(type_scale::BODY)
                    .color(text_dim()),
                );
            }
        }
        ui.horizontal(|ui| {
            if ui
                .button(t("立即扫描暴露面", "Scan Exposure Now"))
                .clicked()
            {
                match self.eng.scan_exposure() {
                    Ok(entries) => self.set_toast(format!(
                        "{} {}",
                        t("扫描完成：", "Scan done: "),
                        entries.len()
                    )),
                    Err(e) => self.set_toast(format!("{}{}", t("扫描失败: ", "Scan failed: "), e)),
                }
                self.refresh_cache();
            }
            if ui
                .button(t("扫描并让 AI 评估", "Scan & Let AI Assess"))
                .clicked()
            {
                let scanned = self.eng.scan_exposure().is_ok();
                if scanned {
                    if self.eng.trigger_analysis() {
                        self.set_toast(t(
                            "暴露面已扫描，AI 分析已开始",
                            "Exposure scanned, AI analysis started",
                        ));
                    } else {
                        self.set_toast(t("已有分析在运行", "An analysis is already running"));
                    }
                } else {
                    self.set_toast(t("扫描失败", "Scan failed"));
                }
                self.refresh_cache();
            }
        });

        ui.add_space(space::L);
        let pending: Vec<_> = self
            .cache
            .proposals
            .iter()
            .filter(|p| p.status == "pending")
            .cloned()
            .collect();
        section(
            ui,
            format!(
                "{} {})",
                t("待处理建议（", "Pending Proposals ("),
                pending.len()
            ),
        );
        if pending.is_empty() {
            ui.label(
                RichText::new(
                    t("暂无待处理建议。蜜罐捕获到攻击行为后，点击「立即分析」生成封禁建议。", "No pending proposals. Once honeypots capture attacks, click 'Analyze Now' to generate proposals."),
                )
                .color(text_dim())
                .size(type_scale::BODY),
            );
        }
        for p in &pending {
            Frame::new()
                .fill(bg_card())
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::same(12))
                .stroke(Stroke::new(1.0, severity_color(&p.severity)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        chip(ui, &p.severity, severity_color(&p.severity));
                        let title = if p.action == "credential_spray" {
                            format!(
                                "{}{}",
                                t("确认喷洒战役 来源 ", "Confirm Spray Campaign, source "),
                                p.remote_ip
                            )
                        } else {
                            format!(
                                "{} {} {}",
                                t("封禁", "Block"),
                                format!("{} {}", dir_cn(&p.direction), proto_up(&p.protocol)),
                                target_desc(&p.remote_ip, p.local_port)
                            )
                        };
                        ui.label(RichText::new(title).size(type_scale::BODY).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let pid = p.id;
                            if p.action == "credential_spray" {
                                // H310：观察类建议——确认战役（人工确认，不封禁）
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new(t("确认战役", "Confirm Campaign"))
                                                .color(on_accent()),
                                        )
                                        .fill(warn())
                                        .corner_radius(CornerRadius::same(6))
                                        .min_size(egui::vec2(96.0, 26.0)),
                                    )
                                    .clicked()
                                {
                                    match self.eng.confirm_campaign(pid) {
                                        Ok(()) => {
                                            self.set_toast(format!(
                                                "{}{} {}",
                                                t(
                                                    "已确认凭证喷洒战役 ",
                                                    "Confirmed credential-spray campaign "
                                                ),
                                                p.remote_ip,
                                                t(
                                                    "（进入观察，不封禁）",
                                                    "(observation only, no ban)"
                                                )
                                            ));
                                        }
                                        Err(e) => self.set_toast(format!(
                                            "{}{}",
                                            t("确认失败: ", "Confirm failed: "),
                                            e
                                        )),
                                    }
                                    self.refresh_cache();
                                }
                            } else if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(t("灰度应用", "Grey Apply"))
                                            .color(on_accent()),
                                    )
                                    .fill(danger())
                                    .corner_radius(CornerRadius::same(6))
                                    .min_size(egui::vec2(96.0, 26.0)),
                                )
                                .clicked()
                            {
                                match self.eng.apply_proposal(pid) {
                                    Ok(Some(row)) => {
                                        let until = row
                                            .expires_ts
                                            .and_then(|t| {
                                                chrono::DateTime::from_timestamp(t, 0).map(|d| {
                                                    d.with_timezone(&chrono::Local)
                                                        .format("%H:%M")
                                                        .to_string()
                                                })
                                            })
                                            .unwrap_or_default();
                                        self.set_toast(format!(
                                            "{} {} ({} {})",
                                            t("已灰度应用为规则", "Applied as grey rule"),
                                            row.name,
                                            t("自动解封", "auto-unban"),
                                            until
                                        ));
                                    }
                                    Ok(None) => {
                                        self.set_toast(t(
                                            "调参建议已采纳（待人工执行，见对话窗口）",
                                            "Adopted (manual execution pending)",
                                        ));
                                    }
                                    Err(e) => self.set_toast(format!(
                                        "{}{}",
                                        t("应用失败: ", "Apply failed: "),
                                        e
                                    )),
                                }
                                self.refresh_cache();
                            }
                            if !p.remote_ip.is_empty()
                                && ui.button(t("误报", "False Positive")).clicked()
                            {
                                // 误报一键入口（0.5.5 F7）：与事件页 / 防火墙规则行同一逻辑
                                let ip = p.remote_ip.clone();
                                self.mark_fp(&ip);
                            }
                            if ui.button(t("忽略", "Ignore")).clicked() {
                                let _ = self.eng.dismiss_proposal(pid);
                                self.refresh_cache();
                            }
                        });
                    });
                    ui.label(
                        RichText::new(&p.reason)
                            .size(type_scale::BODY)
                            .color(text_dim()),
                    );
                    ui.label(
                        RichText::new(format!(
                            "#{} · {} · {}",
                            p.id,
                            p.model,
                            fmt_ts(p.created_ts)
                        ))
                        .size(type_scale::MICRO)
                        .color(text_dim()),
                    );
                });
            ui.add_space(space::S);
        }

        ui.add_space(space::M);
        section(
            ui,
            t(
                "价值指标（口径：采纳率 = 采纳/建议，误报率 = 误报/采纳）",
                "Value Metrics (adoption = applied/proposals, FP rate = FP/applied)",
            ),
        );
        if let Some(st) = &self.cache.status {
            for (label, m) in [
                (t("近 24h", "Last 24h"), &st.metrics_24h),
                (t("近 7 天", "Last 7 days"), &st.metrics_7d),
            ] {
                let adopt_rate = if m.proposed > 0 {
                    format!("{:.0}%", m.applied as f32 / m.proposed as f32 * 100.0)
                } else {
                    "—".into()
                };
                let fp_rate = if m.applied > 0 {
                    format!("{:.0}%", m.fp as f32 / m.applied as f32 * 100.0)
                } else {
                    "—".into()
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(label).strong().size(type_scale::BODY));
                    ui.label(
                        RichText::new(format!(
                            "建议 {} · 采纳 {}（{}）· 误报 {}（{}）· 自动封禁 {}",
                            m.proposed, m.applied, adopt_rate, m.fp, fp_rate, m.auto_blocks
                        ))
                        .size(type_scale::CAPTION),
                    );
                });
            }
        }

        ui.add_space(space::M);
        section(ui, t("误报 / 白名单抑制", "FP / Suppression"));
        if self.cache.feedback.is_empty() {
            ui.label(
                RichText::new(t("无（标记误报的来源在此列出，抑制期内自动封禁跳过；可随时取消）。", "None (FP-flagged sources are listed here; auto-ban skips them during suppression; cancel anytime)."))
                    .color(text_dim())
                    .size(type_scale::BODY),
            );
        }
        let fp_secs = self
            .eng
            .config()
            .map(|c| c.ai.fp_suppress_secs as i64)
            .unwrap_or(0);
        for f in self.cache.feedback.clone() {
            let until = chrono::DateTime::from_timestamp(f.last_ts + fp_secs, 0)
                .map(|d| {
                    d.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M")
                        .to_string()
                })
                .unwrap_or_default();
            ui.horizontal(|ui| {
                ui.label(RichText::new(&f.value).strong().size(type_scale::BODY));
                ui.label(
                    RichText::new(format!(
                        "{} {} · {} · {} {}",
                        t("标记", "Flagged"),
                        f.count,
                        fmt_ts(f.last_ts),
                        t("抑制至", "suppressed until"),
                        until
                    ))
                    .size(type_scale::MICRO)
                    .color(text_dim()),
                );
                if !f.note.is_empty() {
                    ui.label(
                        RichText::new(&f.note)
                            .size(type_scale::MICRO)
                            .color(text_dim()),
                    );
                }
                if ui.button(t("取消抑制", "Cancel Suppression")).clicked() {
                    match self.eng.clear_false_positive(&f.value) {
                        Ok(1) => {
                            self.set_toast(format!(
                                "{}{} {}",
                                t("已取消 ", "Cancelled FP suppression for "),
                                f.value,
                                t("（恢复自动封禁资格）", "(auto-ban eligibility restored)")
                            ));
                            self.refresh_cache();
                        }
                        Ok(_) => {}
                        Err(e) => self.set_toast(format!("取消失败: {e}")),
                    }
                }
            });
        }

        ui.add_space(space::M);
        section(ui, t("运行记录", "Run History"));
        if self.cache.runs.is_empty() {
            ui.label(
                RichText::new(t("尚无 AI 分析记录。", "No AI analysis runs yet."))
                    .color(text_dim())
                    .size(type_scale::BODY),
            );
        }
        for r in &self.cache.runs {
            ui.horizontal(|ui| {
                ui.label(RichText::new(if r.ok { "✓" } else { "✗" }).color(if r.ok {
                    ok()
                } else {
                    danger()
                }));
                ui.label(
                    RichText::new(fmt_ts(r.ts))
                        .size(type_scale::CAPTION)
                        .color(text_dim()),
                );
                ui.label(RichText::new(&r.summary).size(type_scale::CAPTION));
            });
        }
    }
}
