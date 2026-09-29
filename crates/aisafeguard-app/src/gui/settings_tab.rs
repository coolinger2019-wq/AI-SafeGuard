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
            self.settings_syslog_target = cfg.syslog.target.clone();
            self.settings_notify_url = cfg.notify.url.clone();
            self.settings_exposure_secs = cfg.exposure.auto_scan_secs.to_string();
            self.settings_xdp_iface = cfg.xdp.iface.clone();
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
                ui.add(egui::TextEdit::singleline(&mut draft.ai.base_url).desired_width(440.0));
                ui.end_row();

                ui.label("模型");
                ui.add(egui::TextEdit::singleline(&mut draft.ai.model).desired_width(240.0));
                ui.end_row();

                ui.label("自动应用建议");
                ui.checkbox(&mut draft.ai.auto_apply, "（关闭 = 每条建议人工确认）");
                ui.end_row();

                ui.label("自动应用最低严重度");
                egui::ComboBox::from_id_salt("auto-sev")
                    .selected_text(&draft.ai.auto_apply_min_severity)
                    .show_ui(ui, |ui| {
                        for s in ["low", "medium", "high", "critical"] {
                            ui.selectable_value(
                                &mut draft.ai.auto_apply_min_severity,
                                s.to_string(),
                                s,
                            );
                        }
                    });
                ui.end_row();

                ui.label("自动分析间隔（秒）");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_interval).desired_width(120.0),
                );
                ui.end_row();

                ui.label("单条 payload 上送上限（字符）");
                ui.add(egui::TextEdit::singleline(&mut self.settings_snippet).desired_width(120.0));
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
                ui.checkbox(
                    &mut draft.detect.auto_block,
                    "（TTL 到期自动解封，内网地址永不自动封禁）",
                );
                ui.end_row();
            });
        ui.label(
            RichText::new(
                "阈值（扫描端口数/窗口/次数/TTL）在 config.toml [detect] 中调整，保存后即时生效。",
            )
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
                    "（需重启；被动观测，仅取副本；Windows 需管理员/服务模式，Linux 需 CAP_NET_RAW；默认关闭）",
                );
                ui.end_row();
                ui.label("采集模式（需重启）");
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
                    chip(
                        ui,
                        &format!("采样中 · {} · {}", cap.backend, cap.mode),
                        ok(),
                    );
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
        section(ui, "L7 解析与指纹（full 采样模式）");
        egui::Grid::new("l7-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("HTTP 提示解析");
                ui.checkbox(
                    &mut draft.detect.l7.enabled,
                    "（full 模式流前缀解析 method/path/UA，默认关闭）",
                );
                ui.end_row();
                ui.label("JA3 客户端指纹");
                ui.checkbox(&mut draft.detect.l7.ja3, "（TLS ClientHello，md5）");
                ui.end_row();
                ui.label("JA4 客户端指纹");
                ui.checkbox(&mut draft.detect.l7.ja4, "（FoxIO JA4，默认关闭）");
                ui.end_row();
            });
        ui.label(
            RichText::new(
                "开关热更即时生效；产出字段随 Detection 事件入库（http_hint / tls_fingerprint / tls_ja4）。",
            )
            .size(11.0)
            .color(text_dim()),
        );

        ui.add_space(14.0);
        section(ui, "规则子集引擎（Suricata/ET 风格）");
        egui::Grid::new("rules-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("启用规则匹配");
                ui.checkbox(&mut draft.detect.rules.enabled, "（默认关闭）");
                ui.end_row();
                ui.label("规则包路径");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.detect.rules.path)
                        .desired_width(440.0)
                        .hint_text("本地单文件规则包，如 C:\\rules\\demo.rules"),
                );
                ui.end_row();
                ui.label("命中自动封禁");
                ui.checkbox(
                    &mut draft.detect.rules.auto_block,
                    "（默认只告警；开启后仍受内网保护与误报抑制约束）",
                );
                ui.end_row();
            });
        // 命中状态只读展示（0.5 不做规则编辑器——规则文件外置维护）
        if let Some(st) = &self.cache.status {
            ui.horizontal_wrapped(|ui| {
                let r = &st.rules;
                if !r.enabled {
                    chip(ui, "未启用", text_dim());
                } else if r.loaded {
                    chip(ui, &format!("已加载 {} 条", r.rule_count), ok());
                } else {
                    chip(ui, "未加载", warn());
                }
                ui.label(
                    RichText::new(format!("命中 {} 次", r.hits))
                        .size(11.0)
                        .color(text_dim()),
                );
                if !r.note.is_empty() {
                    ui.label(RichText::new(&r.note).size(11.0).color(text_dim()));
                }
            });
        }
        ui.label(
            RichText::new(
                "规则包 = 本地文件（任何一条越界即整包拒绝）；文件变化自动整包热重载。\
                 自写示范包见仓库 crates/aisafeguard-rules/demo.rules；范围见 docs/RULESET_SUBSET.md。",
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
                ui.label("端口（需重启）");
                ui.add(egui::TextEdit::singleline(&mut self.settings_port).desired_width(120.0));
                ui.end_row();
            });

        ui.add_space(14.0);
        section(ui, "远程日志（syslog 转发）");
        egui::Grid::new("syslog-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("转发到收集器");
                ui.checkbox(
                    &mut draft.syslog.enabled,
                    "（RFC 5424；事件总线的副本，best-effort 不阻塞引擎）",
                );
                ui.end_row();
                ui.label("收集器地址");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_syslog_target)
                        .desired_width(180.0)
                        .hint_text("127.0.0.1:514"),
                );
                ui.end_row();
                ui.label("传输协议");
                egui::ComboBox::from_id_salt("syslog-protocol")
                    .selected_text(&draft.syslog.protocol)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut draft.syslog.protocol,
                            "udp".to_string(),
                            "udp（RFC 5426）",
                        );
                        ui.selectable_value(
                            &mut draft.syslog.protocol,
                            "tcp".to_string(),
                            "tcp（换行分帧）",
                        );
                    });
                ui.end_row();
            });
        ui.label(
            RichText::new("改动下一条事件即生效；目标不可达只丢该条。完整性校验仍以本地哈希链（verify-log / 导出）为准。")
                .size(11.0)
                .color(text_dim()),
        );

        ui.add_space(14.0);
        section(ui, "告警通知（Webhook）");
        egui::Grid::new("notify-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("推送告警");
                ui.checkbox(&mut draft.notify.enabled, "（POST JSON 到接收端）");
                ui.end_row();
                ui.label("接收端 URL");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_notify_url)
                        .desired_width(240.0)
                        .hint_text("http://127.0.0.1:9000/alert"),
                );
                ui.end_row();
                ui.label("最低严重度");
                egui::ComboBox::from_id_salt("notify-severity")
                    .selected_text(&draft.notify.min_severity)
                    .show_ui(ui, |ui| {
                        for (v, label) in [
                            ("error", "error（仅错误与更严重）"),
                            ("warning", "warning（检测判定/封禁/错误）"),
                            ("notice", "notice（含蜜罐命中/AI 建议）"),
                            ("info", "info（全部事件）"),
                        ] {
                            ui.selectable_value(
                                &mut draft.notify.min_severity,
                                v.to_string(),
                                label,
                            );
                        }
                    });
                ui.end_row();
            });
        ui.label(
            RichText::new("严重度口径：detection/封禁=warning，蜜罐命中/AI 建议=notice，例行流水=info；低于所选严重度的事件不推送。")
                .size(11.0)
                .color(text_dim()),
        );

        ui.add_space(14.0);
        section(ui, "暴露面自动扫描");
        egui::Grid::new("exposure-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("定时扫描间隔（秒）");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_exposure_secs)
                        .desired_width(120.0)
                        .hint_text("0 = 关闭"),
                );
                ui.end_row();
            });
        ui.label(
            RichText::new("0 = 仅手动扫描；300-86400 秒 = 定时扫描并入库，供 AI 分析与 API 查询。")
                .size(11.0)
                .color(text_dim()),
        );

        ui.add_space(14.0);
        section(ui, "蜜罐");
        ui.checkbox(&mut draft.honeypot.enabled, "启用蜜罐（需重启）");
        ui.label(
            RichText::new("监听列表（名称/端口/类型）通过 config.toml 的 [honeypot.listeners] 编辑，重启生效。")
                .size(11.0)
                .color(text_dim()),
        );

        ui.add_space(14.0);
        section(ui, "XDP 快速执行层（仅 Linux，需重启）");
        egui::Grid::new("xdp-settings")
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                ui.label("启用 XDP");
                ui.checkbox(
                    &mut draft.xdp.enabled,
                    "（IP 级入站封禁内核直丢；nftables 永远兜底，附加失败自动降级）",
                );
                ui.end_row();
                ui.label("网卡");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_xdp_iface)
                        .desired_width(120.0)
                        .hint_text("eth0"),
                );
                ui.end_row();
                ui.label("模式");
                egui::ComboBox::from_id_salt("xdp-mode")
                    .selected_text(&draft.xdp.mode)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut draft.xdp.mode,
                            "skb".to_string(),
                            "skb（generic XDP，所有网卡可用）",
                        );
                        ui.selectable_value(
                            &mut draft.xdp.mode,
                            "native".to_string(),
                            "native（驱动级，更快，需网卡支持）",
                        );
                    });
                ui.end_row();
            });
        // XDP 运行状态（0.5.1 G1/G3 可观测，只读）+ 一键清空 map
        let xdp_status = self.cache.status.as_ref().map(|st| st.xdp.clone());
        if let Some(x) = &xdp_status {
            let backend_has_xdp = self
                .cache
                .status
                .as_ref()
                .is_some_and(|st| st.backend.contains("xdp"));
            ui.horizontal_wrapped(|ui| {
                if x.active {
                    chip(
                        ui,
                        &format!(
                            "XDP 生效 · {} · 镜像 {} 源 · 丢弃 {} 包 · 内核流 {} 条",
                            x.mode, x.mirrored, x.drops_total, x.flows
                        ),
                        ok(),
                    );
                } else if backend_has_xdp {
                    chip(ui, "XDP 未生效", warn());
                } else {
                    chip(ui, "XDP 未启用", text_dim());
                }
                if ui.button("清空 XDP map").clicked() {
                    match self.eng.clear_xdp_map() {
                        Ok(()) => {
                            self.set_toast("已清空 XDP map（nftables 兜底不受影响）");
                            self.refresh_cache();
                        }
                        Err(e) => self.set_toast(format!("清空失败: {e}")),
                    }
                }
            });
        }
        ui.label(
            RichText::new(
                "仅 Linux 生效；需 root/CAP_BPF。镜像范围 = 入站 + 任意协议 + 无端口 + IPv4 且非内网的封禁规则                 （内网/回环地址永不写入快速丢弃表，G2）。内核流表只存源三元组与包计数（无载荷，LRU 有界）。",
            )
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
            RichText::new(concat!(
                "AI-SafeGuard ",
                env!("CARGO_PKG_VERSION"),
                " · © 2026 coolinger · vibe coding"
            ))
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
                if stored {
                    "已存入凭据管理器"
                } else {
                    "未存储"
                },
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
        // 远程日志 / 告警 / 暴露面（0.3.5）
        cfg.syslog.target = self.settings_syslog_target.trim().to_string();
        if cfg.syslog.enabled && cfg.syslog.target.is_empty() {
            self.set_toast("启用 syslog 转发需填写收集器地址");
            return;
        }
        if !cfg.notify.valid_min_severity() {
            self.set_toast("告警最低严重度非法");
            return;
        }
        cfg.notify.url = self.settings_notify_url.trim().to_string();
        if cfg.notify.enabled && cfg.notify.url.is_empty() {
            self.set_toast("启用告警推送需填写接收端 URL");
            return;
        }
        match self.settings_exposure_secs.trim().parse::<u64>() {
            Ok(0) => cfg.exposure.auto_scan_secs = 0,
            Ok(v) if (300..=86400).contains(&v) => cfg.exposure.auto_scan_secs = v,
            _ => {
                self.set_toast("暴露面扫描间隔需为 0（关闭）或 300-86400 秒");
                return;
            }
        }
        cfg.xdp.iface = self.settings_xdp_iface.trim().to_string();
        if cfg.xdp.enabled && cfg.xdp.iface.is_empty() {
            self.set_toast("启用 XDP 需填写网卡名");
            return;
        }
        if !cfg.xdp.valid_mode() {
            self.set_toast("XDP 模式非法（skb | native）");
            return;
        }
        // 界面外观：主题名归一化（未知值回退默认），字号收敛到合法区间
        cfg.ui.theme = ThemeId::from_str(&cfg.ui.theme).as_str().to_string();
        cfg.ui.font_scale = theme::normalize_font_scale(cfg.ui.font_scale);
        // 热更/重启分界（A4/A5 契约）：提示哪些项需重启
        // 热更/重启分界（A4/A5 契约）：对比最近一次保存的配置，提示哪些项需重启
        let old_cfg = self.eng.config().unwrap_or_default();
        let restart_items = AppConfig::restart_required(&old_cfg, &cfg);
        match self.eng.save_config(cfg) {
            Ok(()) => {
                let toast = if restart_items.is_empty() {
                    "设置已保存（改动全部热更生效，无需重启）".to_string()
                } else {
                    format!("设置已保存；需重启生效：{}", restart_items.join("、"))
                };
                self.set_toast(&toast);
                self.settings_draft = None;
                self.refresh_cache();
            }
            Err(e) => self.set_toast(format!("保存失败: {e}")),
        }
    }
}
