use super::*;

impl AisafeApp {
    pub(crate) fn events_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(t("事件流水", "Event Stream"))
                .size(type_scale::TITLE)
                .strong(),
        );
        ui.add_space(space::M);

        ui.horizontal(|ui| {
            ui.label(t("过滤：", "Filter: "));
            ui.add(
                egui::TextEdit::singleline(&mut self.event_filter)
                    .desired_width(240.0)
                    .hint_text(t(
                        "按 IP/内容过滤，如 203.0.113",
                        "Filter by IP/content, e.g. 203.0.113",
                    )),
            );
            if ui.button(t("刷新", "Refresh")).clicked() {
                self.refresh_cache();
            }
            ui.label(
                RichText::new(format!("{} {}", self.cache.events.len(), t("条", "rows")))
                    .size(type_scale::CAPTION)
                    .color(text_dim()),
            );
        });
        ui.add_space(space::M);

        let rows = self.cache.events.clone();
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::exact(118.0))
            .column(egui_extras::Column::exact(110.0))
            .column(egui_extras::Column::exact(70.0))
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::exact(110.0))
            .column(egui_extras::Column::remainder())
            .header(HEADER_H, |mut header| {
                for name in [
                    t("时间", "Time"),
                    t("类型", "Type"),
                    t("蜜罐", "Honeypot"),
                    t("来源", "Source"),
                    t("操作", "Actions"),
                    t("摘要", "Summary"),
                ] {
                    header.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|mut body| {
                for ev in &rows {
                    body.row(ROW_H, |mut row| {
                        row.col(|ui| {
                            ui.label(
                                RichText::new(fmt_ts(ev.ts))
                                    .size(type_scale::CAPTION)
                                    .color(text_dim()),
                            );
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(&ev.kind)
                                    .size(type_scale::CAPTION)
                                    .color(event_color(&ev.kind)),
                            );
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&ev.listener).size(type_scale::CAPTION));
                        });
                        row.col(|ui| {
                            let src = if ev.remote_ip.is_empty() {
                                "-".to_string()
                            } else {
                                format!("{}:{}", ev.remote_ip, ev.remote_port)
                            };
                            ui.label(RichText::new(src).monospace().size(type_scale::CAPTION));
                        });
                        row.col(|ui| {
                            ui.horizontal(|ui| {
                                // 误报一键入口（0.5.5 F7）：检测判定与蜜罐命中行均可标记，
                                // 与防火墙规则行 / AI 建议行走同一引擎逻辑
                                if matches!(ev.kind.as_str(), "detection" | "honeypot_hit")
                                    && !ev.remote_ip.is_empty()
                                    && ui
                                        .add(egui::Button::new(
                                            RichText::new(t("误报", "False Positive"))
                                                .size(type_scale::MICRO)
                                                .color(warn()),
                                        ))
                                        .clicked()
                                {
                                    let ip = ev.remote_ip.clone();
                                    self.mark_fp(&ip);
                                }
                                // 事件详情（0.5.6 F14）：再点一次收起
                                if ui
                                    .add(egui::Button::new(
                                        RichText::new(t("详情", "Detail"))
                                            .size(type_scale::MICRO)
                                            .color(accent()),
                                    ))
                                    .clicked()
                                {
                                    self.event_detail_id = if self.event_detail_id == Some(ev.id) {
                                        None
                                    } else {
                                        Some(ev.id)
                                    };
                                }
                            });
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&ev.summary).size(type_scale::CAPTION));
                        });
                    });
                }
            });

        ui.add_space(space::S);
        if rows.is_empty() && !self.event_filter.trim().is_empty() {
            ui.label(
                RichText::new(t(
                    "暂无关联事件（过滤条件无匹配记录）",
                    "No matching events",
                ))
                .size(type_scale::BODY)
                .color(text_dim()),
            );
        }
        // 详情面板（F14）：点开看结构化字段；不可信内容等宽展示 + 截断；再点「详情」收起
        let detail = self
            .event_detail_id
            .and_then(|id| rows.iter().find(|e| e.id == id).cloned());
        if let Some(ev) = detail {
            event_detail_ui(ui, &ev);
        }
        ui.label(
            RichText::new(t(
                "完整 payload（截断存储）可通过本地 API 查看：GET /api/events",
                "Full payload (stored truncated) via local API: GET /api/events",
            ))
            .size(type_scale::MICRO)
            .color(text_dim()),
        );
    }
}

/// 事件详情卡片：摘要之外的结构化字段（http 提示 / 指纹 / 载荷）。
fn event_detail_ui(ui: &mut egui::Ui, ev: &EventRow) {
    ui.add_space(space::S);
    Frame::new()
        .fill(bg_card())
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, border()))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{}{}", t("事件详情 #", "Event Detail #"), ev.id))
                        .size(type_scale::BODY)
                        .strong(),
                );
                chip(ui, &ev.kind, event_color(&ev.kind));
            });
            ui.add_space(space::XS);
            kv_row(ui, t("时间", "Time"), &fmt_ts(ev.ts));
            if !ev.listener.is_empty() {
                kv_row(ui, t("蜜罐", "Honeypot"), &ev.listener);
            }
            if !ev.remote_ip.is_empty() {
                kv_row(
                    ui,
                    t("来源", "Source"),
                    &format!("{}:{}", ev.remote_ip, ev.remote_port),
                );
            }
            kv_row(ui, t("摘要", "Summary"), &ev.summary);
            // http 提示（v1/v2 兼容：按 JSON 值读，不依赖版本化结构反序列化）
            if !ev.http_hint.is_empty()
                && let Ok(h) = serde_json::from_str::<serde_json::Value>(&ev.http_hint)
            {
                if let Some(m) = h["method"].as_str() {
                    kv_row(ui, t("HTTP 方法", "HTTP Method"), m);
                }
                if let Some(p) = h["path"].as_str() {
                    kv_row(ui, t("路径", "Path"), p);
                }
                if let Some(hv) = h["host"].as_str() {
                    kv_row(ui, "Host", hv);
                }
                if let Some(ua) = h["user_agent"].as_str() {
                    kv_row(ui, "User-Agent", ua);
                }
                if let Some(tags) = h["tags"].as_array()
                    && !tags.is_empty()
                {
                    let joined = tags
                        .iter()
                        .filter_map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join("  ");
                    kv_row(ui, t("标签", "Tags"), &joined);
                }
            }
            if !ev.tls_fp.is_empty() {
                kv_row(ui, "JA3", &ev.tls_fp);
            }
            if !ev.tls_ja4.is_empty() {
                kv_row(ui, "JA4", &ev.tls_ja4);
            }
            // 交互序列（0.5.9 H102：中交互假 Shell 逐命令记录；低交互事件为空串）
            if !ev.interaction.is_empty()
                && let Ok(steps) = serde_json::from_str::<Vec<serde_json::Value>>(&ev.interaction)
                && !steps.is_empty()
            {
                ui.add_space(space::XS);
                egui::CollapsingHeader::new(
                    RichText::new(format!(
                        "{} ({} {})",
                        t("交互序列", "Interaction Sequence"),
                        steps.len(),
                        t("条命令", "commands")
                    ))
                    .size(type_scale::CAPTION),
                )
                .id_salt(egui::Id::new("event-interaction").with(ev.id))
                .default_open(true)
                .show(ui, |ui| {
                    const MAX_STEPS: usize = 20;
                    for step in steps.iter().take(MAX_STEPS) {
                        let cmd = step["command"].as_str().unwrap_or("");
                        let resp = step["response"].as_str().unwrap_or("");
                        let text = format!("$ {cmd}\n{resp}");
                        ui.add_space(space::XS);
                        ui.add(
                            egui::TextEdit::multiline(&mut text.as_str())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(ui.available_width() - 8.0)
                                .desired_rows(2)
                                .interactive(false),
                        );
                    }
                    if steps.len() > MAX_STEPS {
                        ui.label(
                            RichText::new(format!(
                                "{} …{} {}",
                                steps.len() - MAX_STEPS,
                                t("条命令", "commands"),
                                t("可通过 API 查看", "viewable via API")
                            ))
                            .size(type_scale::MICRO)
                            .color(text_dim()),
                        );
                    }
                });
            }
            if !ev.payload.is_empty() {
                ui.add_space(space::XS);
                egui::CollapsingHeader::new(
                    egui::RichText::new(t("载荷（清洗截断）", "Payload (sanitized, truncated)"))
                        .size(type_scale::CAPTION),
                )
                .id_salt(egui::Id::new("event-payload").with(ev.id))
                .default_open(true)
                .show(ui, |ui| {
                    const MAX_DETAIL_PAYLOAD: usize = 2000;
                    let text: String = ev.payload.chars().take(MAX_DETAIL_PAYLOAD).collect();
                    let truncated = ev.payload.chars().count() > MAX_DETAIL_PAYLOAD;
                    ui.add(
                        egui::TextEdit::multiline(&mut text.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(ui.available_width() - 8.0)
                            .desired_rows(4)
                            .interactive(false),
                    );
                    if truncated {
                        ui.label(
                            RichText::new(format!(
                                "{} {} {}",
                                t("…已截断", "…truncated"),
                                ev.payload.chars().count(),
                                t("字符，API 可查", "chars total, via API")
                            ))
                            .size(type_scale::MICRO)
                            .color(text_dim()),
                        );
                    }
                });
            }
        });
    ui.add_space(space::S);
}

fn kv_row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(format!("{key}:"))
                .size(type_scale::CAPTION)
                .color(text_dim())
                .strong(),
        );
        ui.label(RichText::new(value).monospace().size(type_scale::CAPTION));
    });
}
