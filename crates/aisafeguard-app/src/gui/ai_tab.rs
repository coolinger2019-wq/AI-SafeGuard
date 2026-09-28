use super::*;

impl AisafeApp {
    pub(crate) fn ai_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("AI 助手").size(22.0).strong());
        ui.add_space(10.0);

        let status = self.cache.status.clone();
        let ai = status.as_ref().map(|s| s.ai.clone());

        if let Some(ai) = &ai {
            ui.horizontal_wrapped(|ui| {
                chip(
                    ui,
                    if ai.enabled { "AI 已启用" } else { "AI 未启用" },
                    if ai.enabled { ok() } else { text_dim() },
                );
                chip(
                    ui,
                    &format!("Key: {}", ai.key_source),
                    if ai.key_source == "未配置" { warn() } else { text_dim() },
                );
                chip(ui, &ai.model, accent());
                chip(
                    ui,
                    &if ai.auto_apply {
                        format!("自动应用 ≥{}", ai.auto_apply_min_severity)
                    } else {
                        "自动应用关闭".to_string()
                    },
                    if ai.auto_apply { warn() } else { text_dim() },
                );
            });
        }

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let running = ai.as_ref().map(|a| a.running).unwrap_or(false);
            let resp = ui.add_enabled(
                !running,
                egui::Button::new(RichText::new("立即分析").color(on_accent()))
                    .fill(accent())
                    .corner_radius(CornerRadius::same(6)),
            );
            if running {
                ui.spinner();
                ui.label(RichText::new("分析中…").color(text_dim()));
            }
            if resp.clicked() {
                if self.eng.trigger_analysis() {
                    self.set_toast("AI 分析已开始");
                } else {
                    self.set_toast("已有分析在运行");
                }
            }
            if let Some(ai) = &ai {
                ui.label(
                    RichText::new(format!("自动分析间隔 {} 秒", ai.analyze_interval_secs))
                        .size(12.0)
                        .color(text_dim()),
                );
            }
        });
        ui.label(
            RichText::new("分析内容仅为 24h 聚合统计与最近 20 条截断记录；建议需人工确认，蜜罐数据按不可信输入隔离。")
                .size(11.0)
                .color(text_dim()),
        );

        ui.add_space(14.0);
        // 主机暴露面（0.2 P1："自动分析功能接口"第一步）
        section(ui, "主机暴露面");
        let exposure = self.eng.latest_exposure().ok().flatten();
        match &exposure {
            Some(snap) => {
                ui.label(
                    RichText::new(format!(
                        "上次扫描 {} · {} 个监听端点（数据已随下次 AI 分析送评）",
                        fmt_ts(snap.ts),
                        snap.entries.len()
                    ))
                    .size(12.0)
                    .color(text_dim()),
                );
                egui::CollapsingHeader::new(egui::RichText::new("监听清单").size(13.0))
                    .id_salt("exposure-list")
                    .default_open(false)
                    .show(ui, |ui| {
                        for e in snap.entries.iter().take(30) {
                            ui.label(
                                RichText::new(format!(
                                    "{}  {}  [{}]",
                                    e.addr, e.process, e.proto
                                ))
                                .monospace()
                                .size(12.0),
                            );
                        }
                        if snap.entries.len() > 30 {
                            ui.label(RichText::new(format!("…其余 {} 项", snap.entries.len() - 30)).size(11.0).color(text_dim()));
                        }
                    });
            }
            None => {
                ui.label(
                    RichText::new("尚未扫描。扫描会枚举本机监听端口与归属进程，并作为下次 AI 分析的输入。")
                        .size(13.0)
                        .color(text_dim()),
                );
            }
        }
        ui.horizontal(|ui| {
            if ui.button("立即扫描暴露面").clicked() {
                match self.eng.scan_exposure() {
                    Ok(entries) => self.set_toast(format!("扫描完成：{} 个监听端点", entries.len())),
                    Err(e) => self.set_toast(format!("扫描失败: {e}")),
                }
                self.refresh_cache();
            }
            if ui.button("扫描并让 AI 评估").clicked() {
                let scanned = self.eng.scan_exposure().is_ok();
                if scanned {
                    if self.eng.trigger_analysis() {
                        self.set_toast("暴露面已扫描，AI 分析已开始");
                    } else {
                        self.set_toast("已有分析在运行");
                    }
                } else {
                    self.set_toast("扫描失败");
                }
                self.refresh_cache();
            }
        });

        ui.add_space(14.0);
        let pending: Vec<_> = self
            .cache
            .proposals
            .iter()
            .filter(|p| p.status == "pending")
            .cloned()
            .collect();
        section(ui, format!("待处理建议（{}）", pending.len()));
        if pending.is_empty() {
            ui.label(
                RichText::new("暂无待处理建议。蜜罐捕获到攻击行为后，点击「立即分析」生成封禁建议。")
                    .color(text_dim())
                    .size(13.0),
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
                        ui.label(
                            RichText::new(format!(
                                "封禁 {} {} {}",
                                dir_cn(&p.direction),
                                proto_up(&p.protocol),
                                target_desc(&p.remote_ip, p.local_port)
                            ))
                            .size(14.0)
                            .strong(),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let pid = p.id;
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("灰度应用").color(on_accent()),
                                    )
                                    .fill(danger())
                                    .corner_radius(CornerRadius::same(6))
                                    .min_size(egui::vec2(96.0, 26.0)),
                                )
                                .clicked()
                            {
                                match self.eng.apply_proposal(pid) {
                                    Ok(row) => {
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
                                            "已灰度应用为规则 {row}（{until} 自动解封，可在防火墙页转正）",
                                            row = row.name
                                        ));
                                    }
                                    Err(e) => self.set_toast(format!("应用失败: {e}")),
                                }
                                self.refresh_cache();
                            }
                            if !p.remote_ip.is_empty() && ui.button("误报").clicked() {
                                match self.eng.mark_false_positive(&p.remote_ip, "") {
                                    Ok((dismissed, removed)) => {
                                        let days = self
                                            .eng
                                            .config()
                                            .map(|c| c.ai.fp_suppress_secs / 86400)
                                            .unwrap_or(30);
                                        self.set_toast(format!(
                                            "已标记误报：收弃 {dismissed} 条建议，解封 {removed} 条规则（{days} 天内不再自动封禁该来源）"
                                        ));
                                    }
                                    Err(e) => self.set_toast(format!("标记失败: {e}")),
                                }
                                self.refresh_cache();
                            }
                            if ui.button("忽略").clicked() {
                                let _ = self.eng.dismiss_proposal(pid);
                                self.refresh_cache();
                            }
                        });
                    });
                    ui.label(RichText::new(&p.reason).size(13.0).color(text_dim()));
                    ui.label(
                        RichText::new(format!("#{} · {} · {}", p.id, p.model, fmt_ts(p.created_ts)))
                            .size(11.0)
                            .color(text_dim()),
                    );
                });
            ui.add_space(8.0);
        }

        ui.add_space(10.0);
        section(ui, "生效中的误报抑制");
        if self.cache.feedback.is_empty() {
            ui.label(
                RichText::new("无（标记误报的来源在此列出，抑制期内自动封禁跳过；可随时清除）。")
                    .color(text_dim())
                    .size(13.0),
            );
        }
        for f in self.cache.feedback.clone() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&f.value).strong().size(13.0));
                ui.label(
                    RichText::new(format!("标记 {} 次 · 最近 {}", f.count, fmt_ts(f.last_ts)))
                        .size(11.0)
                        .color(text_dim()),
                );
                if !f.note.is_empty() {
                    ui.label(RichText::new(&f.note).size(11.0).color(text_dim()));
                }
                if ui.button("清除抑制").clicked() {
                    match self.eng.clear_false_positive(&f.value) {
                        Ok(1) => {
                            self.set_toast(format!("已清除 {} 的误报抑制（恢复自动封禁资格）", f.value));
                            self.refresh_cache();
                        }
                        Ok(_) => {}
                        Err(e) => self.set_toast(format!("清除失败: {e}")),
                    }
                }
            });
        }

        ui.add_space(10.0);
        section(ui, "运行记录");
        if self.cache.runs.is_empty() {
            ui.label(RichText::new("尚无 AI 分析记录。").color(text_dim()).size(13.0));
        }
        for r in &self.cache.runs {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if r.ok { "✓" } else { "✗" }).color(if r.ok { ok() } else { danger() }),
                );
                ui.label(RichText::new(fmt_ts(r.ts)).size(12.0).color(text_dim()));
                ui.label(RichText::new(&r.summary).size(12.0));
            });
        }
    }
}
