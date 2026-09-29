use super::*;

impl AisafeApp {
    pub(crate) fn honeypot_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("蜜罐").size(type_scale::TITLE).strong());
        ui.add_space(space::M);

        let status = self.cache.status.clone();
        let enabled = status.as_ref().map(|s| s.honeypot_enabled).unwrap_or(false);
        if !enabled {
            warn_banner(ui, "蜜罐功能已禁用。可在「设置」中开启（需重启生效）。");
        }

        let listeners = status
            .as_ref()
            .map(|s| s.listeners.clone())
            .unwrap_or_default();
        section(
            ui,
            format!("监听器（{} 个，修改监听需重启）", listeners.len()),
        );
        // 两个一行、行数随监听器数量增长（0.5.10：原来全部横排一列，窗口不够宽时
        // 后面的卡片被挤压变形）；可用宽度不足两个卡片时退化为单列。
        let gap = space::M;
        let avail = ui.available_width();
        let (cols, card_w) = if avail >= 420.0 {
            (2usize, (avail - gap) * 0.5)
        } else {
            (1usize, avail)
        };
        // 减去 Frame 左右内边距（14×2）得到内容宽度；卡片总宽恰占半行
        let content_w = (card_w - 28.0).max(120.0);
        for row in listeners.chunks(cols) {
            ui.horizontal(|ui| {
                for (i, l) in row.iter().enumerate() {
                    if i > 0 {
                        ui.add_space(gap);
                    }
                    let hits = self
                        .cache
                        .stats
                        .per_listener
                        .iter()
                        .find(|p| p.listener == l.name)
                        .map(|p| p.hits)
                        .unwrap_or(0);
                    // 单监听器启停（H130）：配置里关掉的监听器模式显示「未启用」
                    let running = enabled && l.mode != "未启用";
                    Frame::new()
                        .fill(bg_card())
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::same(14))
                        .stroke(Stroke::new(1.0, border()))
                        .show(ui, |ui| {
                            ui.set_width(content_w);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&l.name)
                                        .size(type_scale::SECTION)
                                        .strong(),
                                );
                                chip(ui, &l.kind, accent());
                                // 交互模式（H150）：banner 级还是假 Shell，界面上可见
                                chip(
                                    ui,
                                    &l.mode,
                                    if l.mode == "中交互" { purple() } else { text_dim() },
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!(":{l}", l = l.port))
                                        .monospace()
                                        .size(type_scale::BODY)
                                        .color(text_dim()),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format!("24h 触发 {hits}"))
                                                .size(type_scale::CAPTION)
                                                .color(if hits > 0 { warn() } else { text_dim() }),
                                        );
                                    },
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("●")
                                        .color(if running { ok() } else { text_dim() })
                                        .size(type_scale::CAPTION),
                                );
                                ui.label(
                                    RichText::new(if running { "运行中" } else { "已停止" })
                                        .size(type_scale::CAPTION)
                                        .color(text_dim()),
                                );
                            });
                        });
                }
            });
            ui.add_space(space::S);
        }
        if listeners.is_empty() {
            ui.label(
                RichText::new(if enabled {
                    "没有已启动的监听器。可在「设置 → 蜜罐」的监听表中添加。"
                } else {
                    "启用蜜罐后，这里显示各协议监听器及其交互模式。"
                })
                .size(type_scale::BODY)
                .color(text_dim()),
            );
        }

        ui.add_space(space::L);
        section(ui, "工作方式");
        ui.label(
            RichText::new(
                "低交互蜜罐：监听可疑端口，对连接给出逼真假响应（SSH banner / HTTP 404 / Telnet 登录提示），\
记录来源 IP、端口与首包内容，绝不执行攻击者输入。被高频触发的来源会进入仪表盘排行，\
并作为 AI 分析的输入材料。",
            )
            .size(type_scale::BODY)
            .color(text_dim()),
        );
        ui.add_space(space::S);
        ui.label(
            RichText::new(
                "监听器卡片上的「中交互」表示该端口开启了假 Shell（命令仿真），\
可在「设置 → 蜜罐」中开启假 Shell、编辑监听表（SSH/HTTP/Telnet/Generic 之外还支持 \
MySQL/Redis 协议），重启生效。默认端口为非特权高位端口（2222/8081/2323/1337）；\
要监听 22/80/23 等标准端口需以管理员身份运行。",
            )
            .size(type_scale::BODY)
            .color(text_dim()),
        );
    }
}
