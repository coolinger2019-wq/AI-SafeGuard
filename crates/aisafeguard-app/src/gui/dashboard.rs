use super::*;

impl AisafeApp {
    pub(crate) fn dashboard_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("仪表盘").size(22.0).strong());
        ui.add_space(12.0);

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
            card(ui, "24h 蜜罐触发", &hits.to_string(), if hits > 0 { WARN } else { TEXT_DIM });
            ui.add_space(10.0);
            card(ui, "攻击源 IP", &attackers.to_string(), if attackers > 0 { DANGER } else { TEXT_DIM });
            ui.add_space(10.0);
            card(ui, "防火墙规则", &rules.to_string(), ACCENT);
            ui.add_space(10.0);
            card(ui, "待处理 AI 建议", &pending.to_string(), if pending > 0 { PURPLE } else { TEXT_DIM });
            ui.add_space(10.0);
            card(
                ui,
                "AI 引擎",
                &ai_text,
                if ai_running { WARN } else if ai_on { OK } else { TEXT_DIM },
            );
        });

        ui.add_space(16.0);
        let stats = self.cache.stats.clone();
        let max_hits = stats.top_ips.first().map(|t| t.hits).unwrap_or(1).max(1);
        let live: Vec<LiveEvent> = self.live.iter().take(14).cloned().collect();

        ui.columns(2, |cols| {
            // 左列：攻击源 TOP 10
            cols[0].label(RichText::new("攻击源 TOP 10（24h）").size(15.0).strong());
            cols[0].add_space(8.0);
            if stats.top_ips.is_empty() {
                cols[0].label(RichText::new("暂无攻击数据。蜜罐被触发后这里会显示来源排行。").color(TEXT_DIM).size(13.0));
            } else {
                for t in &stats.top_ips {
                    cols[0].horizontal(|ui| {
                        ui.label(RichText::new(format!("{:>15}", t.ip)).monospace().size(13.0));
                        let w = (t.hits as f32 / max_hits as f32 * 110.0).max(4.0);
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 12.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, 3.0, ACCENT);
                        ui.label(RichText::new(t.hits.to_string()).size(12.0).color(TEXT_DIM));
                    });
                }
            }

            // 右列：实时事件
            cols[1].label(RichText::new("实时事件").size(15.0).strong());
            cols[1].add_space(8.0);
            if live.is_empty() {
                cols[1].label(RichText::new("等待事件…").color(TEXT_DIM).size(13.0));
            }
            for ev in live {
                cols[1].horizontal(|ui| {
                    ui.label(RichText::new(fmt_ts(ev.ts)).size(11.0).color(TEXT_DIM));
                    ui.label(RichText::new(&ev.kind).size(11.0).color(event_color(&ev.kind)));
                });
                let mut sum = ev.summary.clone();
                if sum.chars().count() > 120 {
                    sum = sum.chars().take(120).collect::<String>() + "…";
                }
                cols[1].label(RichText::new(sum).size(12.0));
                cols[1].add_space(4.0);
            }
        });
    }
}
