use super::*;

impl AisafeApp {
    pub(crate) fn dashboard_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("仪表盘").size(type_scale::TITLE).strong());
        ui.add_space(space::M);

        let status = self.cache.status.clone();
        let hits = status.as_ref().map(|s| s.hits_24h).unwrap_or(0);
        let attackers = status.as_ref().map(|s| s.attackers_24h).unwrap_or(0);
        let rules = status.as_ref().map(|s| s.rule_count).unwrap_or(0);
        let pending = status.as_ref().map(|s| s.pending_proposals).unwrap_or(0);
        let ai_on = status.as_ref().map(|s| s.ai.enabled).unwrap_or(false);
        let ai_running = status.as_ref().map(|s| s.ai.running).unwrap_or(false);
        let ai_text = match status.as_ref().map(|s| s.ai.clone()) {
            Some(ai) if ai.running => "分析中…".to_string(),
            Some(ai) if ai.enabled => format!("{} 就绪", ai.model),
            _ => "未启用".to_string(),
        };

        ui.horizontal_wrapped(|ui| {
            card(
                ui,
                "24h 蜜罐触发",
                &hits.to_string(),
                if hits > 0 { warn() } else { text_dim() },
            );
            ui.add_space(space::M);
            card(
                ui,
                "攻击源 IP",
                &attackers.to_string(),
                if attackers > 0 { danger() } else { text_dim() },
            );
            ui.add_space(space::M);
            card(ui, "防火墙规则", &rules.to_string(), accent());
            ui.add_space(space::M);
            card(
                ui,
                "待处理 AI 建议",
                &pending.to_string(),
                if pending > 0 { purple() } else { text_dim() },
            );
            ui.add_space(space::M);
            card(
                ui,
                "AI 引擎",
                &ai_text,
                if ai_running {
                    warn()
                } else if ai_on {
                    ok()
                } else {
                    text_dim()
                },
            );
        });

        ui.add_space(space::L);
        let stats = self.cache.stats.clone();
        let max_hits = stats.top_ips.first().map(|t| t.hits).unwrap_or(1).max(1);
        let live: Vec<LiveEvent> = self.live.iter().take(14).cloned().collect();

        ui.columns(2, |cols| {
            // 左列：攻击源 TOP 10
            cols[0].label(
                RichText::new("攻击源 TOP 10（24h）")
                    .size(type_scale::SECTION)
                    .strong(),
            );
            cols[0].add_space(space::S);
            if stats.top_ips.is_empty() {
                cols[0].label(
                    RichText::new("暂无攻击数据。蜜罐被触发后这里会显示来源排行。")
                        .color(text_dim())
                        .size(type_scale::BODY),
                );
            } else {
                for t in &stats.top_ips {
                    cols[0].horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{:>15}", t.ip))
                                .monospace()
                                .size(type_scale::BODY),
                        );
                        let w = (t.hits as f32 / max_hits as f32 * 110.0).max(4.0);
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(w, 12.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, 3.0, accent());
                        ui.label(
                            RichText::new(t.hits.to_string())
                                .size(type_scale::CAPTION)
                                .color(text_dim()),
                        );
                    });
                }
            }

            // 右列：实时事件
            cols[1].label(RichText::new("实时事件").size(type_scale::SECTION).strong());
            cols[1].add_space(space::S);
            if live.is_empty() {
                cols[1].label(
                    RichText::new("等待事件…")
                        .color(text_dim())
                        .size(type_scale::BODY),
                );
            }
            for ev in live {
                cols[1].horizontal(|ui| {
                    ui.label(
                        RichText::new(fmt_ts(ev.ts))
                            .size(type_scale::MICRO)
                            .color(text_dim()),
                    );
                    ui.label(
                        RichText::new(&ev.kind)
                            .size(type_scale::MICRO)
                            .color(event_color(&ev.kind)),
                    );
                });
                let mut sum = ev.summary.clone();
                if sum.chars().count() > 120 {
                    sum = sum.chars().take(120).collect::<String>() + "…";
                }
                cols[1].label(RichText::new(sum).size(type_scale::CAPTION));
                cols[1].add_space(space::XS);
            }
        });
    }
}
