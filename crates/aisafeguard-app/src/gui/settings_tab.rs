use super::*;

impl AisafeApp {
    pub(crate) fn settings_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(title("设置"));
        ui.add_space(space::S);

        // 子页导航：分段按钮，按功能域切页
        ui.horizontal_wrapped(|ui| {
            for p in SettingsPage::ALL {
                let selected = self.settings_page == p;
                let text = RichText::new(p.label())
                    .size(type_scale::BODY)
                    .color(if selected { on_accent() } else { text_color() });
                let btn = egui::Button::new(text)
                    .fill(if selected { accent() } else { bg_card() })
                    .stroke(Stroke::new(1.0, if selected { accent() } else { border() }))
                    .corner_radius(CornerRadius::same(8))
                    .min_size(egui::vec2(0.0, 28.0));
                if ui.add(btn).clicked() {
                    self.settings_page = p;
                }
            }
        });
        ui.add_space(space::M);

        // 草稿初始化：进入设置页时取一次；子页切换不重置（蜜罐页共用同一份）
        self.ensure_settings_draft();
        let Some(mut draft) = self.settings_draft.clone() else {
            return;
        };

        match self.settings_page {
            SettingsPage::Look => self.settings_look_page(ui, &mut draft),
            SettingsPage::Ai => self.settings_ai_page(ui, &mut draft),
            SettingsPage::Detect => self.settings_detect_page(ui, &mut draft),
            SettingsPage::Honeypot => self.settings_honeypot_page(ui, &mut draft),
            SettingsPage::Channels => self.settings_channels_page(ui, &mut draft),
            SettingsPage::About => self.settings_about_page(ui),
        }
        // 每帧回写草稿：主题/字号即时预览与输入框内容都保存在草稿里，
        // 语义与旧版一致（改动存草稿，保存才落盘，放弃即丢弃）。
        self.settings_draft = Some(draft);

        self.settings_footer(ui);
    }

    /// 设置草稿就绪（设置页与蜜罐页共用）：未初始化时从引擎取一次当前配置，
    /// 文本输入缓冲同步填好。改动存草稿，保存才落盘，放弃即丢弃。
    pub(crate) fn ensure_settings_draft(&mut self) {
        if self.settings_draft.is_none() {
            let cfg = self.eng.config().unwrap_or_default();
            self.settings_interval = cfg.ai.analyze_interval_secs.to_string();
            self.settings_port = cfg.api.port.to_string();
            self.settings_snippet = cfg.ai.max_snippet_chars.to_string();
            self.settings_syslog_target = cfg.syslog.target.clone();
            self.settings_notify_url = cfg.notify.url.clone();
            self.settings_exposure_secs = cfg.exposure.auto_scan_secs.to_string();
            self.settings_xdp_iface = cfg.xdp.iface.clone();
            self.settings_fp_days = (cfg.ai.fp_suppress_secs / 86400).to_string();
            self.settings_shell_max_cmds = cfg.honeypot.shell.max_commands.to_string();
            self.settings_listener_ports = cfg
                .honeypot
                .listeners
                .iter()
                .map(|l| l.port.to_string())
                .collect();
            self.settings_draft = Some(cfg);
        }
    }

    // ---------- 外观 ----------

    fn settings_look_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "配色方案");
        ui.label(
            RichText::new("切换即时预览；点底部“保存设置”后持久化。")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
        ui.add_space(space::S);
        ui.horizontal_wrapped(|ui| {
            for id in ThemeId::all() {
                let selected = ThemeId::from_str(&draft.ui.theme) == id;
                let spec = id.spec();
                let mut text = RichText::new(spec.name).size(type_scale::BODY);
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
            ui.add_space(space::XS);
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
                        egui::FontId::proportional(type_scale::MICRO),
                        if spec.dark {
                            Color32::from_gray(210)
                        } else {
                            Color32::from_gray(60)
                        },
                    );
                }
                ui.label(caption(spec.desc).color(text_dim()));
            });
        }
        ui.add_space(space::S);
        section(ui, "字号缩放");
        ui.horizontal(|ui| {
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
            RichText::new("默认“舒适”档（正文约 16.7px）；弱视或高分屏可切“特大”。全部界面文字与间距随缩放等比变化。")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- AI 分析 ----------

    fn settings_ai_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "AI 分析");
        egui::Grid::new("ai-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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

                ui.label("误报抑制时长（天）");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_fp_days)
                        .desired_width(120.0)
                        .hint_text("7～14 天较合适"),
                );
                ui.end_row();
            });

        ui.add_space(space::M);
        self.key_management_ui(ui);
    }

    // ---------- 检测与感知 ----------

    fn settings_detect_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "本地检测（快路径）");
        egui::Grid::new("detect-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );

        ui.add_space(space::M);
        section(ui, "威胁情报订阅（外部 IOC 名单）");
        egui::Grid::new("intel-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label("情报订阅");
                ui.checkbox(
                    &mut draft.intel.enabled,
                    "（对外网络请求，默认关；周期拉取外部名单与本机观测求交）",
                );
                ui.end_row();
                ui.end_row();
            });
        // F710 多源分级只读展示：能否自动封禁是每源的显式许可；编辑走 config.toml
        for src in &draft.intel.sources {
            ui.horizontal(|ui| {
                ui.label(mono_text(&src.name));
                ui.label(caption(&src.url));
                if src.auto_block && src.confidence == "high" {
                    chip(ui, "允许自动封", warn());
                } else {
                    chip(ui, "仅标注", text_dim());
                }
            });
        }
        ui.label(caption(
            "源增删与信任分级在 config.toml [intel.sources]；自动封禁 = 该源 auto_block 且 confidence=high 双条件，内网地址任何源都拒收。",
        ));
        ui.horizontal(|ui| {
            if ui.button("手动拉取一轮").clicked() {
                match self.eng.refresh_intel() {
                    Ok(()) => self.set_toast("情报刷新已开始（结果稍后进事件流/防火墙规则）"),
                    Err(e) => self.set_toast(format!("刷新失败：{e}")),
                }
            }
            ui.label(
                caption("拉取间隔默认 6 小时（config.toml [intel].interval_secs）；保存后即时生效。                 组织 fed 源与 STIX 导入源永不自动封禁，仅标注。"),
            );
        });
        // 订阅反馈（看得见名单规模与上次拉取结果，否则「只有 5 条封禁」很费解）
        if let Some(st) = &self.cache.status {
            let intel = &st.intel;
            ui.horizontal(|ui| {
                if intel.entries == 0 {
                    chip(ui, "情报库为空（未订阅或尚未拉取）", text_dim());
                } else {
                    chip(ui, &format!("情报在库 {} 条", intel.entries), ok());
                }
                match intel.last_fetch_ts {
                    None => ui.label(caption("启动后尚未拉取（周期任务启动 20s 后跑首轮）")),
                    Some(_) if !intel.last_fetch_ok => {
                        ui.label(caption("上次拉取失败（源不可达/离线；名单保持原样）"))
                    }
                    Some(ts) => ui.label(caption(format!(
                        "上次拉取 {} 前：入库 {} 条 · 在库 {} · 自动封禁 {}{}",
                        crate::explain::humanize_secs(aisafeguard_core::now_ts() - ts),
                        intel.last_fetch_added, intel.last_fetch_active, intel.last_fetch_blocked,
                        if intel.last_fetch_dropped > 0 {
                            format!(" · 丢弃 {}（网段/截断，F770 决策依据）", intel.last_fetch_dropped)
                        } else {
                            String::new()
                        },
                    ))),
                };
            });
        }

        ui.add_space(space::M);
        section(ui, "流量采样捕获（真实流量观测）");
        egui::Grid::new("capture-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label("启用采样捕获");
                ui.checkbox(
                    &mut draft.detect.capture.enabled,
                    "（需重启；Windows 需管理员/服务，Linux 需 CAP_NET_RAW；默认关闭）",
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
                    ui.label(caption(&cap.note).color(warn()));
                }
            });
        }
        ui.label(
            RichText::new("采样为被动观测（仅取副本，不注回、不拦截任何包）；full 模式仅在判定可疑时截断留存载荷摘要。")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );

        ui.add_space(space::M);
        section(ui, "L7 解析与指纹（full 采样模式）");
        egui::Grid::new("l7-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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
                "开关热更即时生效；产出字段随 Detection 事件入库（http_hint / tls_fp / tls_ja4）。",
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );

        ui.add_space(space::M);
        section(ui, "规则子集引擎（Suricata/ET 风格）");
        egui::Grid::new("rules-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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
                ui.label(caption(format!("命中 {} 次", r.hits)).color(text_dim()));
                if !r.note.is_empty() {
                    ui.label(caption(&r.note).color(text_dim()));
                }
            });
        }
        ui.label(
            RichText::new("规则包 = 本地文件（任何一条越界即整包拒绝）；文件变化自动整包热重载。自写示范包见 crates/aisafeguard-rules/demo.rules。")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- 蜜罐与执行 ----------

    fn settings_honeypot_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "蜜罐");
        ui.checkbox(&mut draft.honeypot.enabled, "启用蜜罐（需重启）");
        ui.label(
            RichText::new("蜜罐的运行状态与就地设置在「蜜罐」页——此处与该页共用同一份草稿。")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
        ui.add_space(space::M);
        // 蜜罐域编辑器与「蜜罐」页共用同一实现（0.5.12 就地设置）
        self.honeypot_listener_table(ui, draft);
        ui.add_space(space::M);
        self.honeypot_shell_editor(ui, draft);
        ui.add_space(space::M);
        self.honeypot_credentials_editor(ui, draft);
        ui.add_space(space::M);
        self.honeypot_canary_editor(ui, draft);

        ui.add_space(space::M);
        section(ui, "XDP 快速执行层（仅 Linux，需重启）");
        egui::Grid::new("xdp-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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
            RichText::new("仅 Linux 生效；需 root/CAP_BPF。内网/回环地址永不写入快速丢弃表；内核流表只存源三元组与包计数（无载荷，LRU 有界）。")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- 通道与告警 ----------

    fn settings_channels_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "API 服务");
        egui::Grid::new("api-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label("启用本地 API");
                ui.checkbox(&mut draft.api.enabled, "（仅监听 127.0.0.1）");
                ui.end_row();
                ui.label("端口（需重启）");
                ui.add(egui::TextEdit::singleline(&mut self.settings_port).desired_width(120.0));
                ui.end_row();
            });

        ui.add_space(space::M);
        section(ui, "远程日志（syslog 转发）");
        egui::Grid::new("syslog-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );

        ui.add_space(space::M);
        section(ui, "告警通知（Webhook）");
        egui::Grid::new("notify-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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
            RichText::new(
                "严重度口径：detection/封禁=warning，蜜罐命中/AI 建议=notice，例行流水=info。",
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );

        ui.add_space(space::M);
        section(ui, "暴露面自动扫描");
        egui::Grid::new("exposure-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
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
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- 关于 ----------

    fn settings_about_page(&mut self, ui: &mut egui::Ui) {
        section(ui, "版本");
        Frame::new()
            .fill(bg_card())
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(16))
            .stroke(Stroke::new(1.0, border()))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(display(format!("v{}", self.eng.version())).color(accent()));
                    ui.label(
                        RichText::new("AI-SafeGuard 安全中心")
                            .size(type_scale::BODY)
                            .color(text_dim()),
                    );
                });
            });
        ui.add_space(space::S);
        if let Some(st) = &self.cache.status {
            egui::Grid::new("about-info")
                .num_columns(2)
                .spacing([14.0, space::XS])
                .show(ui, |ui| {
                    kv_label(ui, "程序版本");
                    ui.label(mono_text(&st.version));
                    ui.end_row();
                    kv_label(ui, "防火墙后端");
                    ui.label(mono_text(&st.backend));
                    ui.end_row();
                    kv_label(ui, "权限状态");
                    ui.label(if st.elevated {
                        "管理员（防火墙可写）".to_string()
                    } else {
                        "未提权（防火墙不可写）".to_string()
                    });
                    ui.end_row();
                    kv_label(ui, "已运行");
                    ui.label(humanize_uptime(st.uptime_secs));
                    ui.end_row();
                });
        }

        ui.add_space(space::M);
        section(ui, "数据与配置");
        let (cfg_path, data_dir) = self.eng.config_paths();
        egui::Grid::new("about-paths")
            .num_columns(2)
            .spacing([14.0, space::XS])
            .show(ui, |ui| {
                kv_label(ui, "配置文件");
                ui.label(mono_text(&cfg_path));
                ui.end_row();
                kv_label(ui, "数据目录");
                ui.label(mono_text(&data_dir));
                ui.end_row();
            });

        ui.add_space(space::M);
        section(ui, "开源许可");
        ui.label(
            RichText::new(concat!(
                "AI-SafeGuard ",
                env!("CARGO_PKG_VERSION"),
                " · MIT License · © 2026 coolinger · vibe coding"
            ))
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );
        ui.label(
            RichText::new("安全软件 · 仅供授权环境防御性使用 · 架构与安全文档见仓库 docs/ 目录")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- 公共页脚 ----------

    pub(crate) fn settings_footer(&mut self, ui: &mut egui::Ui) {
        ui.add_space(space::L);
        ui.separator();
        ui.add_space(space::S);
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
            ui.label(
                RichText::new("带“需重启”标注的项保存后会明确列出；其余保存即热更生效。")
                    .size(type_scale::CAPTION)
                    .color(text_dim()),
            );
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
        egui::CollapsingHeader::new(egui::RichText::new("更改 Key").size(type_scale::BODY))
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
                .size(type_scale::CAPTION)
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
        // 误报抑制时长（0.5.5 F8）：天 → 秒；建议 7～14 天
        match self.settings_fp_days.trim().parse::<u64>() {
            Ok(d) if (1..=90).contains(&d) => cfg.ai.fp_suppress_secs = d * 86_400,
            _ => {
                self.set_toast("误报抑制时长需在 1-90 天之间");
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
        // 蜜罐监听表（0.5.10 H130）：端口解析 + 基础格式校验（范围/去重/命名），
        // 不做实时占用探测（bind 失败仅该监听器不起并留事件）
        {
            let mut seen_ports = std::collections::HashSet::new();
            for (i, l) in cfg.honeypot.listeners.iter_mut().enumerate() {
                let raw = self
                    .settings_listener_ports
                    .get(i)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                match raw.parse::<u16>() {
                    Ok(p) if p > 0 => {
                        if !seen_ports.insert(p) {
                            self.set_toast(format!("监听端口重复: {p}"));
                            return;
                        }
                        l.port = p;
                    }
                    _ => {
                        self.set_toast(format!("监听器「{}」端口非法（1-65535）", l.name));
                        return;
                    }
                }
                l.name = l.name.trim().to_string();
                if l.name.is_empty() {
                    self.set_toast("监听器名称不能为空");
                    return;
                }
            }
        }
        // 假 Shell 会话参数（H130）：命令上限收敛到合理区间
        match self.settings_shell_max_cmds.trim().parse::<usize>() {
            Ok(v) if (1..=500).contains(&v) => cfg.honeypot.shell.max_commands = v,
            _ => {
                self.set_toast("假 Shell 单会话命令上限需在 1-500 之间");
                return;
            }
        }
        // 界面外观：主题名归一化（未知值回退默认），字号收敛到合法区间
        cfg.ui.theme = ThemeId::from_str(&cfg.ui.theme).as_str().to_string();
        cfg.ui.font_scale = theme::normalize_font_scale(cfg.ui.font_scale);
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

/// 「标签：」列（关于页信息网格共用）。
fn kv_label(ui: &mut egui::Ui, key: &str) {
    ui.label(
        RichText::new(key)
            .size(type_scale::CAPTION)
            .color(text_dim()),
    );
}

/// 秒 → 人读运行时长。
fn humanize_uptime(secs: u64) -> String {
    match secs {
        s if s < 90 => format!("{s} 秒"),
        m if m < 5400 => format!("{} 分钟", (m + 30) / 60),
        h if h < 129_600 => format!("{} 小时", (h + 1800) / 3600),
        d => format!("{} 天", (d + 43_200) / 86_400),
    }
}
