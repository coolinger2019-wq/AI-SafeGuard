use super::*;

impl AisafeApp {
    pub(crate) fn settings_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("设置").size(22.0).strong());
        ui.add_space(10.0);

        // Key 管理不依赖配置草稿（直接读写凭据管理器）
        self.key_management_ui(ui);

        ui.add_space(10.0);
        if self.settings_draft.is_none() {
            let cfg = self.eng.config().unwrap_or_default();
            self.settings_interval = cfg.ai.analyze_interval_secs.to_string();
            self.settings_port = cfg.api.port.to_string();
            self.settings_snippet = cfg.ai.max_snippet_chars.to_string();
            self.settings_draft = Some(cfg);
        }
        let Some(draft) = self.settings_draft.as_mut() else {
            return;
        };

        section(ui, "AI 分析");
        egui::Grid::new("ai-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("启用 AI 分析");
                ui.checkbox(&mut draft.ai.enabled, "");
                ui.end_row();

                ui.label("API 地址（OpenAI 兼容）");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.ai.base_url)
                        .desired_width(440.0),
                );
                ui.end_row();

                ui.label("模型");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.ai.model).desired_width(240.0),
                );
                ui.end_row();

                ui.label("自动应用建议");
                ui.checkbox(&mut draft.ai.auto_apply, "（关闭 = 每条建议人工确认）");
                ui.end_row();

                ui.label("自动应用最低严重度");
                egui::ComboBox::from_id_salt("auto-sev")
                    .selected_text(&draft.ai.auto_apply_min_severity)
                    .show_ui(ui, |ui| {
                        for s in ["low", "medium", "high", "critical"] {
                            ui.selectable_value(&mut draft.ai.auto_apply_min_severity, s.to_string(), s);
                        }
                    });
                ui.end_row();

                ui.label("自动分析间隔（秒）");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_interval).desired_width(120.0),
                );
                ui.end_row();

                ui.label("单条 payload 上送上限（字符）");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_snippet).desired_width(120.0),
                );
                ui.end_row();
            });

        ui.add_space(14.0);
        section(ui, "本地检测（快路径）");
        egui::Grid::new("detect-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("频次检测");
                ui.checkbox(&mut draft.detect.enabled, "（端口扫描 / 暴力探测判定）");
                ui.end_row();
                ui.label("自动封禁");
                ui.checkbox(&mut draft.detect.auto_block, "（TTL 到期自动解封，内网地址永不自动封禁）");
                ui.end_row();
            });
        ui.label(
            RichText::new("阈值（扫描端口数/窗口/次数/TTL）在 config.toml [detect] 中调整，保存后即时生效。")
                .size(11.0)
                .color(TEXT_DIM),
        );

        ui.add_space(14.0);
        section(ui, "API 服务");
        egui::Grid::new("api-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("启用本地 API");
                ui.checkbox(&mut draft.api.enabled, "（仅监听 127.0.0.1）");
                ui.end_row();
                ui.label("端口");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_port).desired_width(120.0),
                );
                ui.end_row();
            });

        ui.add_space(14.0);
        section(ui, "蜜罐");
        ui.checkbox(&mut draft.honeypot.enabled, "启用蜜罐");
        ui.label(
            RichText::new("监听列表（名称/端口/类型）通过 config.toml 的 [honeypot.listeners] 编辑，重启生效。")
                .size(11.0)
                .color(TEXT_DIM),
        );

        ui.add_space(14.0);
        section(ui, "关于");
        if let Some(st) = &self.cache.status {
            ui.label(
                RichText::new(format!(
                    "版本 {} · 防火墙后端 {} · 运行 {} 秒",
                    st.version, st.backend, st.uptime_secs
                ))
                .size(12.0)
                .color(TEXT_DIM),
            );
        }
        let (cfg_path, data_dir) = self.eng.config_paths();
        ui.label(
            RichText::new(format!("配置文件: {cfg_path}"))
                .size(12.0)
                .color(TEXT_DIM),
        );
        ui.label(
            RichText::new(format!("数据目录: {data_dir}"))
                .size(12.0)
                .color(TEXT_DIM),
        );

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("保存设置").color(Color32::WHITE))
                        .fill(ACCENT)
                        .corner_radius(CornerRadius::same(6)),
                )
                .clicked()
            {
                self.save_settings();
            }
            if ui.button("放弃修改").clicked() {
                self.settings_draft = None;
            }
        });
    }

    /// API Key 管理：读写凭据管理器，不经过配置文件。
    fn key_management_ui(&mut self, ui: &mut egui::Ui) {
        section(ui, "API Key（凭据管理器）");
        ui.horizontal(|ui| {
            let stored = self.eng.ai_key_present().unwrap_or(false);
            let env_set = std::env::var_os("AISAFEGUARD_AI_KEY").is_some_and(|v| !v.is_empty());
            if env_set {
                chip(ui, "环境变量覆盖中", WARN);
            }
            chip(
                ui,
                if stored { "已存入凭据管理器" } else { "未存储" },
                if stored { OK } else { TEXT_DIM },
            );
        });
        egui::CollapsingHeader::new(egui::RichText::new("更改 Key").size(13.0))
            .id_salt("change-key")
            .default_open(false)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_key_input)
                        .password(true)
                        .desired_width(380.0)
                        .hint_text("粘贴新 Key"),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(RichText::new("保存到凭据管理器").color(Color32::WHITE))
                                .fill(ACCENT)
                                .corner_radius(CornerRadius::same(6)),
                        )
                        .clicked()
                    {
                        let value = self.settings_key_input.trim().to_string();
                        if value.is_empty() {
                            self.set_toast("Key 不能为空");
                        } else {
                            match self.eng.set_ai_key(&value) {
                                Ok(()) => {
                                    self.set_toast("Key 已存入凭据管理器");
                                    self.settings_key_input.clear();
                                }
                                Err(e) => self.set_toast(format!("保存失败: {e}")),
                            }
                            self.refresh_cache();
                        }
                    }
                    if ui.button("清除已存 Key").clicked() {
                        match self.eng.delete_ai_key() {
                            Ok(()) => self.set_toast("已清除凭据管理器中的 Key"),
                            Err(e) => self.set_toast(format!("清除失败: {e}")),
                        }
                        self.refresh_cache();
                    }
                });
            });
        ui.label(
            RichText::new("环境变量 AISAFEGUARD_AI_KEY 优先于凭据管理器（适合 CI/无头部署）。配置文件不保存任何秘密。")
                .size(11.0)
                .color(TEXT_DIM),
        );
    }

    fn save_settings(&mut self) {
        let Some(draft) = self.settings_draft.clone() else {
            return;
        };
        let mut cfg = draft;
        match self.settings_interval.trim().parse::<u64>() {
            Ok(v) if (30..=86400).contains(&v) => cfg.ai.analyze_interval_secs = v,
            _ => {
                self.set_toast("分析间隔需在 30-86400 秒之间");
                return;
            }
        }
        match self.settings_port.trim().parse::<u16>() {
            Ok(v) if v > 0 => cfg.api.port = v,
            _ => {
                self.set_toast("API 端口非法");
                return;
            }
        }
        match self.settings_snippet.trim().parse::<usize>() {
            Ok(v) if (40..=2000).contains(&v) => cfg.ai.max_snippet_chars = v,
            _ => {
                self.set_toast("payload 上送上限需在 40-2000 之间");
                return;
            }
        }
        match self.eng.save_config(cfg) {
            Ok(()) => {
                self.set_toast("设置已保存（蜜罐/API 端口等重启后生效）");
                self.settings_draft = None;
                self.refresh_cache();
            }
            Err(e) => self.set_toast(format!("保存失败: {e}")),
        }
    }
}
