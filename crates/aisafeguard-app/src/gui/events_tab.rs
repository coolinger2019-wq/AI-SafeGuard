use super::*;

impl AisafeApp {
    pub(crate) fn events_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("事件流水").size(22.0).strong());
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label("过滤：");
            ui.add(
                egui::TextEdit::singleline(&mut self.event_filter)
                    .desired_width(240.0)
                    .hint_text("按 IP/内容过滤，如 203.0.113"),
            );
            if ui.button("刷新").clicked() {
                self.refresh_cache();
            }
            ui.label(
                RichText::new(format!("{} 条", self.cache.events.len()))
                    .size(12.0)
                    .color(text_dim()),
            );
        });
        ui.add_space(10.0);

        let rows = self.cache.events.clone();
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::exact(118.0))
            .column(egui_extras::Column::exact(110.0))
            .column(egui_extras::Column::exact(70.0))
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::exact(64.0))
            .column(egui_extras::Column::remainder())
            .header(22.0, |mut header| {
                for name in ["时间", "类型", "蜜罐", "来源", "操作", "摘要"] {
                    header.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|mut body| {
                for ev in &rows {
                    body.row(22.0, |mut row| {
                        row.col(|ui| {
                            ui.label(RichText::new(fmt_ts(ev.ts)).size(12.0).color(text_dim()));
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(&ev.kind)
                                    .size(12.0)
                                    .color(event_color(&ev.kind)),
                            );
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&ev.listener).size(12.0));
                        });
                        row.col(|ui| {
                            let src = if ev.remote_ip.is_empty() {
                                "-".to_string()
                            } else {
                                format!("{}:{}", ev.remote_ip, ev.remote_port)
                            };
                            ui.label(RichText::new(src).monospace().size(12.0));
                        });
                        row.col(|ui| {
                            // 误报一键入口（0.5.5 F7）：检测判定与蜜罐命中行均可标记，
                            // 与防火墙规则行 / AI 建议行走同一引擎逻辑
                            if matches!(ev.kind.as_str(), "detection" | "honeypot_hit")
                                && !ev.remote_ip.is_empty()
                                && ui
                                    .add(egui::Button::new(
                                        RichText::new("误报").size(11.0).color(warn()),
                                    ))
                                    .clicked()
                            {
                                let ip = ev.remote_ip.clone();
                                self.mark_fp(&ip);
                            }
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&ev.summary).size(12.0));
                        });
                    });
                }
            });

        ui.add_space(6.0);
        if rows.is_empty() && !self.event_filter.trim().is_empty() {
            ui.label(
                RichText::new("暂无关联事件（过滤条件无匹配记录）")
                    .size(13.0)
                    .color(text_dim()),
            );
        }
        ui.label(
            RichText::new("完整 payload（截断存储）可通过本地 API 查看：GET /api/events")
                .size(11.0)
                .color(text_dim()),
        );
    }
}
