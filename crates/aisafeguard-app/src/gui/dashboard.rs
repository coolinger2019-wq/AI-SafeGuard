use super::*;

impl AisafeApp {
    pub(crate) fn dashboard_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(t("仪表盘", "Dashboard"))
                .size(type_scale::TITLE)
                .strong(),
        );
        ui.add_space(space::M);

        let status = self.cache.status.clone();
        let hits = status.as_ref().map(|s| s.hits_24h).unwrap_or(0);
        let attackers = status.as_ref().map(|s| s.attackers_24h).unwrap_or(0);
        let rules = status.as_ref().map(|s| s.rule_count).unwrap_or(0);
        let pending = status.as_ref().map(|s| s.pending_proposals).unwrap_or(0);
        let ai_on = status.as_ref().map(|s| s.ai.enabled).unwrap_or(false);
        let ai_running = status.as_ref().map(|s| s.ai.running).unwrap_or(false);
        let ai_text = match status.as_ref().map(|s| s.ai.clone()) {
            Some(ai) if ai.running => t("分析中…", "Analyzing…").to_string(),
            Some(ai) if ai.enabled => format!("{} {}", ai.model, t("就绪", "ready")),
            _ => t("未启用", "Disabled").to_string(),
        };

        ui.horizontal_wrapped(|ui| {
            card(
                ui,
                t("24h 蜜罐触发", "Honeypot Hits 24h"),
                &hits.to_string(),
                if hits > 0 { warn() } else { text_dim() },
            );
            ui.add_space(space::M);
            card(
                ui,
                t("攻击源 IP", "Attacker IPs"),
                &attackers.to_string(),
                if attackers > 0 { danger() } else { text_dim() },
            );
            ui.add_space(space::M);
            card(
                ui,
                t("防火墙规则", "Firewall Rules"),
                &rules.to_string(),
                accent(),
            );
            ui.add_space(space::M);
            card(
                ui,
                t("待处理 AI 建议", "Pending AI Proposals"),
                &pending.to_string(),
                if pending > 0 { purple() } else { text_dim() },
            );
            ui.add_space(space::M);
            card(
                ui,
                t("AI 引擎", "AI Engine"),
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
                RichText::new(t("攻击源 TOP 10（24h）", "Top Attackers (24h)"))
                    .size(type_scale::SECTION)
                    .strong(),
            );
            cols[0].add_space(space::S);
            if stats.top_ips.is_empty() {
                cols[0].label(
                    RichText::new(t(
                        "暂无攻击数据。蜜罐被触发后这里会显示来源排行。",
                        "No attack data yet. Source rankings appear once honeypots are triggered.",
                    ))
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
            cols[1].label(
                RichText::new(t("实时事件", "Live Events"))
                    .size(type_scale::SECTION)
                    .strong(),
            );
            cols[1].add_space(space::S);
            if live.is_empty() {
                cols[1].label(
                    RichText::new(t("等待事件…", "Waiting for events…"))
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
