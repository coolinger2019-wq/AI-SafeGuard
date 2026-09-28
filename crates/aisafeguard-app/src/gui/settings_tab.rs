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

        section(ui, "界面外观");
        ui.label(
            RichText::new("切换配色方案与字号即时预览；点底部“保存设置”后持久化。")
                .size(11.0)
                .color(text_dim()),
        );
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            for id in ThemeId::all() {
                let selected = ThemeId::from_str(&draft.ui.theme) == id;
                let spec = id.spec();
                let mut text = RichText::new(spec.name).size(13.0);
                text = if selected {
                    text.color(on_accent()).strong()
                } else {
                    text.color(text_color())
                };
                let btn = egui::Button::new(text)
                    .fill(if selected { accent() } else { bg_card() })
                    .stroke(Stroke::new(1.0, if selected { accent() } else { border() }))
                    .corner_radius(CornerRadius::same(8))
                    .min_size(egui::vec2(150.0, 30.0));
                if ui.add(btn).clicked() {
                    draft.ui.theme = id.as_str().to_string();
                }
            }
        });
        // 选中方案的色卡预览 + 说明
        {
            let spec = ThemeId::from_str(&draft.ui.theme).spec();
            ui.horizontal(|ui| {
                for (name, c) in [
                    ("背景", spec.p.bg_panel),
                    ("卡片", spec.p.bg_card),
                    ("主色", spec.p.accent),
                    ("正常", spec.p.ok),
                    ("警告", spec.p.warn),
                    ("危险", spec.p.danger),
                ] {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(46.0, 22.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, CornerRadius::same(4), c);
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        name,
                        egui::FontId::proportional(10.0),
                        if spec.dark {
                            Color32::from_gray(210)
                        } else {
                            Color32::from_gray(60)
                        },
                    );
                }
                ui.label(RichText::new(spec.desc).size(11.0).color(text_dim()));
            });
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("字号缩放");
            let mut scale = theme::normalize_font_scale(draft.ui.font_scale);
            let slider = ui.add(
                egui::Slider::new(&mut scale, theme::FONT_SCALE_MIN..=theme::FONT_SCALE_MAX)
                    .fixed_decimals(2)
                    .suffix("×"),
            );
            if slider.changed() {
                draft.ui.font_scale = scale;
            }
            for (label, v) in [
                ("紧凑", 0.95),
                ("舒适", theme::FONT_SCALE_DEFAULT),
                ("大", 1.35),
                ("特大", 1.55),
            ] {
                if ui.small_button(label).clicked() {
                    draft.ui.font_scale = v;
                }
            }
        });
        ui.label(
            RichText::new("默认“舒适”档（正文约 16.7px）；弱视或高分屏可切“特大”，配合高对比配色进一步提高可读性。")
                .size(11.0)
                .color(text_dim()),
        );

        ui.add_space(14.0);
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
                .color(text_dim()),
        );

        ui.add_space(14.0);
        section(ui, "流量采样捕获（真实流量观测）");
        egui::Grid::new("capture-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("启用采样捕获");
                ui.checkbox(
                    &mut draft.detect.capture.enabled,
                    "（被动观测，仅取副本；Windows 需管理员/服务模式，Linux 需 CAP_NET_RAW；默认关闭）",
                );
                ui.end_row();
                ui.label("采集模式");
                egui::ComboBox::from_id_salt("capture-mode")
                    .selected_text(&draft.detect.capture.mode)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut draft.detect.capture.mode,
                            "control".to_string(),
                            "control（仅 TCP SYN 包头，元数据）",
                        );
                        ui.selectable_value(
                            &mut draft.detect.capture.mode,
                            "full".to_string(),
                            "full（全 TCP 段 + 流重组取证）",
                        );
                    });
                ui.end_row();
            });
        if let Some(st) = &self.cache.status {
            ui.horizontal(|ui| {
                let cap = &st.capture;
                if !cap.enabled {
                    chip(ui, "未启用", text_dim());
                } else if cap.active {
                    chip(ui, &format!("采样中 · {} · {}", cap.backend, cap.mode), ok());
                } else {
                    chip(ui, "不可用", warn());
                }
                if !cap.note.is_empty() {
                    ui.label(RichText::new(&cap.note).size(11.0).color(warn()));
                }
            });
        }
        ui.label(
            RichText::new(
                "阈值（扫描端口数 / SYN flood 速率 / 窗口 / 流表）在 config.toml [detect.capture] 调整；\
                 采样为被动观测（仅取副本，不注回、不拦截任何包），模式与开关重启后生效。\
                 full 模式仅在判定可疑时截断留存载荷摘要。",
            )
            .size(11.0)
            .color(text_dim()),
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
                .color(text_dim()),
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
                .color(text_dim()),
            );
        }
        ui.label(
            RichText::new(concat!("AI-SafeGuard ", env!("CARGO_PKG_VERSION"), " · © 2026 coolinger · vibe coding"))
                .size(12.0)
                .color(text_color()),
        );
        ui.label(
            RichText::new("MIT License · 安全软件 · 仅供授权环境防御性使用")
                .size(11.0)
                .color(text_dim()),
        );
        let (cfg_path, data_dir) = self.eng.config_paths();
        ui.label(
            RichText::new(format!("配置文件: {cfg_path}"))
                .size(12.0)
                .color(text_dim()),
        );
        ui.label(
            RichText::new(format!("数据目录: {data_dir}"))
                .size(12.0)
                .color(text_dim()),
        );

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("保存设置").color(on_accent()))
                        .fill(accent())
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
                chip(ui, "环境变量覆盖中", warn());
            }
            chip(
                ui,
                if stored { "已存入凭据管理器" } else { "未存储" },
                if stored { ok() } else { text_dim() },
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
                            egui::Button::new(RichText::new("保存到凭据管理器").color(on_accent()))
                                .fill(accent())
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
                .color(text_dim()),
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
        // 界面外观：主题名归一化（未知值回退默认），字号收敛到合法区间
        cfg.ui.theme = ThemeId::from_str(&cfg.ui.theme).as_str().to_string();
        cfg.ui.font_scale = theme::normalize_font_scale(cfg.ui.font_scale);
        match self.eng.save_config(cfg) {
            Ok(()) => {
                self.set_toast("设置已保存（主题/字号即时生效；蜜罐/API 端口等重启后生效）");
                self.settings_draft = None;
                self.refresh_cache();
            }
            Err(e) => self.set_toast(format!("保存失败: {e}")),
        }
    }
}
