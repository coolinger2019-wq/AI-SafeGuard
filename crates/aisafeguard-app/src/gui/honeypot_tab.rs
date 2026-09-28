use super::*;

impl AisafeApp {
    pub(crate) fn honeypot_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("蜜罐").size(22.0).strong());
        ui.add_space(10.0);

        let status = self.cache.status.clone();
        let enabled = status.as_ref().map(|s| s.honeypot_enabled).unwrap_or(false);
        if !enabled {
            warn_banner(ui, "蜜罐功能已禁用。可在「设置」中开启（需重启生效）。");
        }

        let listeners = status
            .as_ref()
            .map(|s| s.listeners.clone())
            .unwrap_or_default();
        section(ui, format!("监听器（{} 个，修改监听需重启）", listeners.len()));
        ui.horizontal_wrapped(|ui| {
            for l in &listeners {
                let hits = self
                    .cache
                    .stats
                    .per_listener
                    .iter()
                    .find(|p| p.listener == l.name)
                    .map(|p| p.hits)
                    .unwrap_or(0);
                Frame::new()
                    .fill(bg_card())
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::same(14))
                    .stroke(Stroke::new(1.0, border()))
                    .show(ui, |ui| {
                        ui.set_min_width(150.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&l.name).size(16.0).strong());
                            chip(ui, &l.kind, accent());
                        });
                        ui.label(
                            RichText::new(format!(":{l}", l = l.port))
                                .monospace()
                                .size(14.0)
                                .color(text_dim()),
                        );
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("●").color(if enabled { ok() } else { text_dim() }).size(12.0));
                            ui.label(
                                RichText::new(if enabled { "运行中" } else { "已停止" })
                                    .size(12.0)
                                    .color(text_dim()),
                            );
                        });
                        ui.label(
                            RichText::new(format!("24h 触发 {hits}"))
                                .size(12.0)
                                .color(if hits > 0 { warn() } else { text_dim() }),
                        );
                    });
                ui.add_space(10.0);
            }
        });

        ui.add_space(14.0);
        section(ui, "工作方式");
        ui.label(
            RichText::new(
                "低交互蜜罐：监听可疑端口，对连接给出逼真假响应（SSH banner / HTTP 404 / Telnet 登录提示），\
记录来源 IP、端口与首包内容，绝不执行攻击者输入。被高频触发的来源会进入仪表盘排行，\
并作为 AI 分析的输入材料。",
            )
            .size(13.0)
            .color(text_dim()),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new("默认端口为非特权高位端口（2222/8081/2323/1337）。要监听 22/80/23 等标准端口，\
请编辑 config.toml 中 [honeypot.listeners] 并以管理员身份运行。")
                .size(13.0)
                .color(text_dim()),
        );
    }
}
