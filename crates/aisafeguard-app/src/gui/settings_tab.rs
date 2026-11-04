use super::*;

impl AisafeApp {
    pub(crate) fn settings_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(title(t("设置", "Settings")));
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
        section(
            ui,
            crate::gui::i18n::t(t("配色方案", "Color Scheme"), "Color Scheme"),
        );
        ui.label(
            RichText::new(t(
                "切换即时预览；点底部“保存设置”后持久化。",
                "Live preview; persisted via 'Save Settings' at the bottom.",
            ))
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
                    (t("背景", "Background"), spec.p.bg_panel),
                    (t("卡片", "Card"), spec.p.bg_card),
                    (t("主色", "Accent"), spec.p.accent),
                    (t("正常", "Normal"), spec.p.ok),
                    (t("警告", "Warning"), spec.p.warn),
                    (t("危险", "Danger"), spec.p.danger),
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
        // 界面语言（F796c）：切换即时预览，保存持久化
        ui.add_space(space::S);
        section(ui, i18n::t(t("界面语言", "Language"), "Language"));
        ui.add_space(space::XS);
        ui.horizontal_wrapped(|ui| {
            for (val, label) in [
                (
                    "zh",
                    i18n::t(
                        t("中文（默认）", "中文（默认）"),
                        t("中文（默认）", "中文（默认）"),
                    ),
                ),
                ("en", "English"),
            ] {
                let selected = draft.ui.language == val;
                let mut text = RichText::new(label).size(type_scale::BODY);
                text = if selected {
                    text.color(on_accent()).strong()
                } else {
                    text.color(text_color())
                };
                let btn = egui::Button::new(text)
                    .fill(if selected { accent() } else { bg_card() })
                    .stroke(Stroke::new(1.0, if selected { accent() } else { border() }))
                    .min_size(egui::vec2(150.0, 30.0));
                if ui.add(btn).clicked() {
                    draft.ui.language = val.to_string();
                }
            }
        });

        section(ui, t("字号缩放", "Font Scale"));
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
                (t("紧凑", "Compact"), 0.95),
                (t("舒适", "Comfortable"), theme::FONT_SCALE_DEFAULT),
                (t("大", "Large"), 1.35),
                (t("特大", "X-Large"), 1.55),
            ] {
                if ui.small_button(label).clicked() {
                    draft.ui.font_scale = v;
                }
            }
        });
        ui.label(
            RichText::new(t("默认“舒适”档（正文约 16.7px）；弱视或高分屏可切“特大”。全部界面文字与间距随缩放等比变化。", "Defaults to Comfortable (~16.7px body); switch to X-Large for low vision or hi-dpi. All UI text and spacing scale proportionally."))
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- AI 分析 ----------

    fn settings_ai_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, t("AI 分析", "AI Analysis"));
        egui::Grid::new("ai-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("启用 AI 分析", "Enable AI Analysis"));
                ui.checkbox(&mut draft.ai.enabled, "");
                ui.end_row();

                ui.label(t("协议模板", "API Protocol"));
                egui::ComboBox::from_id_salt("ai-protocol")
                    .selected_text(match draft.ai.api_protocol.as_str() {
                        "responses" => t(
                            "OpenAI Responses（/responses）",
                            "OpenAI Responses (/responses)",
                        ),
                        "anthropic" => t(
                            "Anthropic Messages（/v1/messages）",
                            "Anthropic Messages (/v1/messages)",
                        ),
                        _ => t(
                            "OpenAI Chat（/chat/completions，默认）",
                            "OpenAI Chat (/chat/completions, default)",
                        ),
                    })
                    .show_ui(ui, |ui| {
                        for (v, zh, en) in [
                            (
                                "chat",
                                "OpenAI Chat（/chat/completions，默认）",
                                "OpenAI Chat (/chat/completions, default)",
                            ),
                            (
                                "responses",
                                "OpenAI Responses（/responses）",
                                "OpenAI Responses (/responses)",
                            ),
                            (
                                "anthropic",
                                "Anthropic Messages（/v1/messages）",
                                "Anthropic Messages (/v1/messages)",
                            ),
                        ] {
                            ui.selectable_value(
                                &mut draft.ai.api_protocol,
                                v.to_string(),
                                t(zh, en),
                            );
                        }
                    });
                ui.end_row();

                ui.label(t("API 地址（端点根 URL）", "API URL (endpoint root)"));
                ui.add(egui::TextEdit::singleline(&mut draft.ai.base_url).desired_width(440.0));
                ui.end_row();

                ui.label(t("模型", "Model"));
                ui.add(egui::TextEdit::singleline(&mut draft.ai.model).desired_width(240.0));
                ui.end_row();

                ui.label(t("自动应用建议", "Auto-apply Proposals"));
                ui.checkbox(
                    &mut draft.ai.auto_apply,
                    t(
                        "（关闭 = 每条建议人工确认）",
                        "(off = every proposal needs manual confirm)",
                    ),
                );
                ui.end_row();

                ui.label(t("自动应用最低严重度", "Auto-apply Min Severity"));
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

                ui.label(t("自动分析间隔（秒）", "Auto-analysis Interval (s)"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_interval).desired_width(120.0),
                );
                ui.end_row();

                ui.label(t(
                    "单条 payload 上送上限（字符）",
                    "Per-item payload upload cap (chars)",
                ));
                ui.add(egui::TextEdit::singleline(&mut self.settings_snippet).desired_width(120.0));
                ui.end_row();

                ui.label(t("误报抑制时长（天）", "FP Suppression (days)"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_fp_days)
                        .desired_width(120.0)
                        .hint_text(t("7～14 天较合适", "7-14 days recommended")),
                );
                ui.end_row();
            });

        ui.add_space(space::M);
        self.key_management_ui(ui);
    }

    // ---------- 检测与感知 ----------

    fn settings_detect_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, t("本地检测（快路径）", "Local Detection (Fast Path)"));
        egui::Grid::new("detect-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("频次检测", "Frequency Detection"));
                ui.checkbox(
                    &mut draft.detect.enabled,
                    t(
                        "（端口扫描 / 暴力探测判定）",
                        "(port scan / brute-force detection)",
                    ),
                );
                ui.end_row();
                ui.label(t("自动封禁", "Auto-block"));
                ui.checkbox(
                    &mut draft.detect.auto_block,
                    t(
                        "（TTL 到期自动解封，内网地址永不自动封禁）",
                        "(auto-unban at TTL expiry; private IPs are never auto-banned)",
                    ),
                );
                ui.end_row();
            });
        ui.label(
            RichText::new(
                t("阈值（扫描端口数/窗口/次数/TTL）在 config.toml [detect] 中调整，保存后即时生效。", "Thresholds (scan ports/window/hits/TTL) live in config.toml [detect]; takes effect on save."),
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );

        ui.add_space(space::M);
        section(
            ui,
            t(
                "威胁情报订阅（外部 IOC 名单）",
                "Threat Intel (external IOC feeds)",
            ),
        );
        egui::Grid::new("intel-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("情报订阅", "Intel Subscription"));
                ui.checkbox(
                    &mut draft.intel.enabled,
                    t("（对外网络请求，默认关；周期拉取外部名单与本机观测求交）", "(outbound requests, off by default; periodically pulls external feeds and intersects with observations)"),
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
                    chip(ui, t("允许自动封", "Auto-block allowed"), warn());
                } else {
                    chip(ui, t("仅标注", "Label only"), text_dim());
                }
            });
        }
        ui.label(caption(
            t("源增删与信任分级在 config.toml [intel.sources]；自动封禁 = 该源 auto_block 且 confidence=high 双条件，内网地址任何源都拒收。", "Source management & trust tiers live in config.toml [intel.sources]; auto-block = source auto_block AND confidence=high; private IPs are rejected from any source."),
        ));
        ui.horizontal(|ui| {
            if ui.button(t("手动拉取一轮", "Fetch Once")).clicked() {
                match self.eng.refresh_intel() {
                    Ok(()) => self.set_toast(t("情报刷新已开始（结果稍后进事件流/防火墙规则）", "Intel refresh started (results arrive in events/firewall rules)")),
                    Err(e) => self.set_toast(format!("{}{}", t("刷新失败：", "Refresh failed: "), e)),
                }
            }
            ui.label(
                caption(t("拉取间隔默认 6 小时（config.toml [intel].interval_secs）；保存后即时生效。                 组织 fed 源与 STIX 导入源永不自动封禁，仅标注。", "Fetch interval defaults to 6h (config.toml [intel].interval_secs); takes effect on save. Fed and STIX sources are never auto-blocked, label only.")),
            );
        });
        // 订阅反馈（看得见名单规模与上次拉取结果，否则「只有 5 条封禁」很费解）
        if let Some(st) = &self.cache.status {
            let intel = &st.intel;
            ui.horizontal(|ui| {
                if intel.entries == 0 {
                    chip(
                        ui,
                        t(
                            "情报库为空（未订阅或尚未拉取）",
                            "Intel store empty (not subscribed or not fetched yet)",
                        ),
                        text_dim(),
                    );
                } else {
                    chip(ui, &format!("情报在库 {} 条", intel.entries), ok());
                }
                match intel.last_fetch_ts {
                    None => ui.label(caption(t(
                        "启动后尚未拉取（周期任务启动 20s 后跑首轮）",
                        "Not fetched yet (first run 20s after start)",
                    ))),
                    Some(_) if !intel.last_fetch_ok => ui.label(caption(t(
                        "上次拉取失败（源不可达/离线；名单保持原样）",
                        "Last fetch failed (source unreachable; list unchanged)",
                    ))),
                    Some(ts) => ui.label(caption(format!(
                        "{} {} · {} {} · {}{}{}",
                        t("上次拉取", "Last fetch"),
                        crate::explain::humanize_secs(aisafeguard_core::now_ts() - ts),
                        t("前", "ago"),
                        intel.last_fetch_added,
                        t("在库", "in store"),
                        intel.last_fetch_blocked,
                        if intel.last_fetch_dropped > 0 {
                            format!(
                                " · {} {} {}",
                                t("丢弃", "dropped"),
                                intel.last_fetch_dropped,
                                t(
                                    "（网段/截断，F770 决策依据）",
                                    "(range/truncation, see F770)"
                                )
                            )
                        } else {
                            String::new()
                        },
                    ))),
                };
            });
        }

        ui.add_space(space::M);
        section(
            ui,
            t(
                "流量采样捕获（真实流量观测）",
                "Packet Capture (real traffic observation)",
            ),
        );
        egui::Grid::new("capture-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("启用采样捕获", "Enable Packet Capture"));
                ui.checkbox(
                    &mut draft.detect.capture.enabled,
                    t("（需重启；Windows 需管理员/服务，Linux 需 CAP_NET_RAW；默认关闭）", "(restart required; Windows needs admin/service, Linux needs CAP_NET_RAW; off by default)"),
                );
                ui.end_row();
                ui.label(t("采集模式（需重启）", "Capture Mode (restart required)"));
                egui::ComboBox::from_id_salt("capture-mode")
                    .selected_text(&draft.detect.capture.mode)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut draft.detect.capture.mode,
                            "control".to_string(),
                            t("control（仅 TCP SYN 包头，元数据）", "control (TCP SYN headers only, metadata)"),
                        );
                        ui.selectable_value(
                            &mut draft.detect.capture.mode,
                            "full".to_string(),
                            t("full（全 TCP 段 + 流重组取证）", "full (all TCP segments + flow reassembly forensics)"),
                        );
                    });
                ui.end_row();
            });
        if let Some(st) = &self.cache.status {
            ui.horizontal(|ui| {
                let cap = &st.capture;
                if !cap.enabled {
                    chip(ui, t("未启用", "Disabled"), text_dim());
                } else if cap.active {
                    chip(
                        ui,
                        &format!("采样中 · {} · {}", cap.backend, cap.mode),
                        ok(),
                    );
                } else {
                    chip(ui, t("不可用", "Unavailable"), warn());
                }
                if !cap.note.is_empty() {
                    ui.label(caption(&cap.note).color(warn()));
                }
            });
        }
        ui.label(
            RichText::new(t("采样为被动观测（仅取副本，不注回、不拦截任何包）；full 模式仅在判定可疑时截断留存载荷摘要。", "Capture is passive observation (copies only; never injects or blocks); full mode retains truncated payload summaries only when flagged suspicious."))
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );

        ui.add_space(space::M);
        section(
            ui,
            t(
                "L7 解析与指纹（full 采样模式）",
                "L7 Parsing & Fingerprints (full capture mode)",
            ),
        );
        egui::Grid::new("l7-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("HTTP 提示解析", "HTTP Hint Parsing"));
                ui.checkbox(
                    &mut draft.detect.l7.enabled,
                    t(
                        "（full 模式流前缀解析 method/path/UA，默认关闭）",
                        "(full mode parses method/path/UA from flow prefixes, off by default)",
                    ),
                );
                ui.end_row();
                ui.label(t("JA3 客户端指纹", "JA3 Client Fingerprint"));
                ui.checkbox(&mut draft.detect.l7.ja3, "（TLS ClientHello，md5）");
                ui.end_row();
                ui.label(t("JA4 客户端指纹", "JA4 Client Fingerprint"));
                ui.checkbox(
                    &mut draft.detect.l7.ja4,
                    t("（FoxIO JA4，默认关闭）", "(FoxIO JA4, off by default)"),
                );
                ui.end_row();
            });
        ui.label(
            RichText::new(
                t("开关热更即时生效；产出字段随 Detection 事件入库（http_hint / tls_fp / tls_ja4）。", "Toggles hot-reload; outputs are stored with Detection events (http_hint / tls_fp / tls_ja4)."),
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );

        ui.add_space(space::M);
        section(
            ui,
            t(
                "规则子集引擎（Suricata/ET 风格）",
                "Rule Subset Engine (Suricata/ET style)",
            ),
        );
        egui::Grid::new("rules-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("启用规则匹配", "Enable Rule Matching"));
                ui.checkbox(&mut draft.detect.rules.enabled, t("（默认关闭）", "(off by default)"));
                ui.end_row();
                ui.label(t("规则包路径", "Rule Pack Path"));
                ui.add(
                    egui::TextEdit::singleline(&mut draft.detect.rules.path)
                        .desired_width(440.0)
                        .hint_text(t("本地单文件规则包，如 C:\\rules\\demo.rules", "Local single-file rule pack, e.g. C:\\rules\\demo.rules")),
                );
                ui.end_row();
                ui.label(t("命中自动封禁", "Hit auto-block"));
                ui.checkbox(
                    &mut draft.detect.rules.auto_block,
                    t("（默认只告警；开启后仍受内网保护与误报抑制约束）", "(alert-only by default; even when on, private-IP protection and FP suppression still apply)"),
                );
                ui.end_row();
            });
        // 命中状态只读展示（0.5 不做规则编辑器——规则文件外置维护）
        if let Some(st) = &self.cache.status {
            ui.horizontal_wrapped(|ui| {
                let r = &st.rules;
                if !r.enabled {
                    chip(ui, t("未启用", "Disabled"), text_dim());
                } else if r.loaded {
                    chip(ui, &format!("已加载 {} 条", r.rule_count), ok());
                } else {
                    chip(ui, t("未加载", "Not loaded"), warn());
                }
                ui.label(caption(format!("命中 {} 次", r.hits)).color(text_dim()));
                if !r.note.is_empty() {
                    ui.label(caption(&r.note).color(text_dim()));
                }
            });
        }
        ui.label(
            RichText::new(t("规则包 = 本地文件（任何一条越界即整包拒绝）；文件变化自动整包热重载。自写示范包见 crates/aisafeguard-rules/demo.rules。", "Rule pack = local file (one out-of-range rule rejects the whole pack); file changes hot-reload atomically. Sample pack: crates/aisafeguard-rules/demo.rules."))
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- 蜜罐与执行 ----------

    fn settings_honeypot_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, t("蜜罐", "Honeypot"));
        ui.checkbox(
            &mut draft.honeypot.enabled,
            t("启用蜜罐（需重启）", "Enable Honeypot (restart required)"),
        );
        ui.label(
            RichText::new(t("蜜罐的运行状态与就地设置在「蜜罐」页——此处与该页共用同一份草稿。", "Honeypot runtime state and in-place settings live on the Honeypot page — this page shares the same draft."))
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
        section(
            ui,
            t(
                "XDP 快速执行层（仅 Linux，需重启）",
                "XDP Fast Path (Linux only, restart required)",
            ),
        );
        egui::Grid::new("xdp-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("启用 XDP", "Enable XDP"));
                ui.checkbox(
                    &mut draft.xdp.enabled,
                    t("（IP 级入站封禁内核直丢；nftables 永远兜底，附加失败自动降级）", "(IP-level inbound bans dropped in-kernel; nftables always as fallback, auto-degrades on attach failure)"),
                );
                ui.end_row();
                ui.label(t("网卡", "NIC"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_xdp_iface)
                        .desired_width(120.0)
                        .hint_text("eth0"),
                );
                ui.end_row();
                ui.label(t("模式", "Mode"));
                egui::ComboBox::from_id_salt("xdp-mode")
                    .selected_text(&draft.xdp.mode)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut draft.xdp.mode,
                            "skb".to_string(),
                            t("skb（generic XDP，所有网卡可用）", "skb (generic XDP, works on all NICs)"),
                        );
                        ui.selectable_value(
                            &mut draft.xdp.mode,
                            "native".to_string(),
                            t("native（驱动级，更快，需网卡支持）", "native (driver-level, faster, NIC support required)"),
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
                            "{} {} · {} {} · {} {} · {} {}",
                            t("XDP 生效", "XDP active"),
                            x.mode,
                            t("镜像", "mirrored"),
                            x.mirrored,
                            t("丢弃", "dropped"),
                            x.drops_total,
                            t("包 · 内核流", "pkts · kernel flows"),
                            x.flows
                        ),
                        ok(),
                    );
                } else if backend_has_xdp {
                    chip(ui, t("XDP 未生效", "XDP not active"), warn());
                } else {
                    chip(ui, t("XDP 未启用", "XDP disabled"), text_dim());
                }
                if ui.button(t("清空 XDP map", "Clear XDP Map")).clicked() {
                    match self.eng.clear_xdp_map() {
                        Ok(()) => {
                            self.set_toast(t(
                                "已清空 XDP map（nftables 兜底不受影响）",
                                "XDP map cleared (nftables fallback unaffected)",
                            ));
                            self.refresh_cache();
                        }
                        Err(e) => {
                            self.set_toast(format!("{}{}", t("清空失败: ", "Clear failed: "), e))
                        }
                    }
                }
            });
        }
        ui.label(
            RichText::new(t("仅 Linux 生效；需 root/CAP_BPF。内网/回环地址永不写入快速丢弃表；内核流表只存源三元组与包计数（无载荷，LRU 有界）。", "Linux only; requires root/CAP_BPF. Private/loopback IPs never enter the fast drop table; kernel flow table stores source tuples and counters only (no payload, bounded LRU)."))
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- 通道与告警 ----------

    fn settings_channels_page(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, t("API 服务", "API Service"));
        egui::Grid::new("api-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("启用本地 API", "Enable Local API"));
                ui.checkbox(
                    &mut draft.api.enabled,
                    t("（仅监听 127.0.0.1）", "(listens on 127.0.0.1 only)"),
                );
                ui.end_row();
                ui.label(t("端口（需重启）", "Port (restart required)"));
                ui.add(egui::TextEdit::singleline(&mut self.settings_port).desired_width(120.0));
                ui.end_row();
            });

        ui.add_space(space::M);
        section(ui, t("远程日志（syslog 转发）", "Remote Logging (syslog)"));
        egui::Grid::new("syslog-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("转发到收集器", "Forward to collector"));
                ui.checkbox(
                    &mut draft.syslog.enabled,
                    t(
                        "（RFC 5424；事件总线的副本，best-effort 不阻塞引擎）",
                        "(RFC 5424; a copy of the event bus, best-effort, never blocks the engine)",
                    ),
                );
                ui.end_row();
                ui.label(t("收集器地址", "Collector Address"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_syslog_target)
                        .desired_width(180.0)
                        .hint_text("127.0.0.1:514"),
                );
                ui.end_row();
                ui.label(t("传输协议", "Transport Protocol"));
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
                            t("tcp（换行分帧）", "tcp (newline-framed)"),
                        );
                    });
                ui.end_row();
            });
        ui.label(
            RichText::new(t("改动下一条事件即生效；目标不可达只丢该条。完整性校验仍以本地哈希链（verify-log / 导出）为准。", "Takes effect on the next event; unreachable targets drop that event only. Integrity remains anchored to the local hash chain (verify-log / export)."))
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );

        ui.add_space(space::M);
        section(ui, t("告警通知（Webhook）", "Webhook Notifications"));
        egui::Grid::new("notify-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("推送告警", "Webhook Alerts"));
                ui.checkbox(
                    &mut draft.notify.enabled,
                    t("（POST JSON 到接收端）", "(POST JSON to receiver)"),
                );
                ui.end_row();
                ui.label(t("接收端 URL", "Receiver URL"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_notify_url)
                        .desired_width(240.0)
                        .hint_text("http://127.0.0.1:9000/alert"),
                );
                ui.end_row();
                ui.label(t("最低严重度", "Min Severity"));
                egui::ComboBox::from_id_salt("notify-severity")
                    .selected_text(&draft.notify.min_severity)
                    .show_ui(ui, |ui| {
                        for (v, label) in [
                            (
                                "error",
                                t("error（仅错误与更严重）", "error (errors and above)"),
                            ),
                            (
                                "warning",
                                t(
                                    "warning（检测判定/封禁/错误）",
                                    "warning (detections/bans/errors)",
                                ),
                            ),
                            (
                                "notice",
                                t(
                                    "notice（含蜜罐命中/AI 建议）",
                                    "notice (incl. honeypot hits / AI proposals)",
                                ),
                            ),
                            ("info", t("info（全部事件）", "info (all events)")),
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
                t("严重度口径：detection/封禁=warning，蜜罐命中/AI 建议=notice，例行流水=info。", "Severity: detections/bans=warning, honeypot hits/AI proposals=notice, routine=info."),
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );

        ui.add_space(space::M);
        section(ui, t("暴露面自动扫描", "Scheduled Exposure Scan"));
        egui::Grid::new("exposure-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label(t("定时扫描间隔（秒）", "Scheduled Scan Interval (s)"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_exposure_secs)
                        .desired_width(120.0)
                        .hint_text(t("0 = 关闭", "0 = off")),
                );
                ui.end_row();
            });
        ui.label(
            RichText::new(t(
                "0 = 仅手动扫描；300-86400 秒 = 定时扫描并入库，供 AI 分析与 API 查询。",
                "0 = manual only; 300-86400s = scheduled scan, fed to AI & API.",
            ))
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );
    }

    // ---------- 关于 ----------

    fn settings_about_page(&mut self, ui: &mut egui::Ui) {
        section(ui, t("版本", "Version"));
        // 版本取缓存（srv_version），远程模式下不逐帧打 /api/status
        let about_ver = if self.srv_version.is_empty() {
            "?".to_string()
        } else {
            self.srv_version.clone()
        };
        Frame::new()
            .fill(bg_card())
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(16))
            .stroke(Stroke::new(1.0, border()))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(display(format!("v{about_ver}")).color(accent()));
                    ui.label(
                        RichText::new(t("AI-SafeGuard 安全中心", "AI-SafeGuard Security Center"))
                            .size(type_scale::BODY)
                            .color(text_dim()),
                    );
                });
            });

        // 应用内自更新（0.8.2）：检查更新 / 下载 / 一键升级（仅 Windows）
        #[cfg(windows)]
        {
            ui.add_space(space::M);
            section(ui, t("更新", "Update"));
            Frame::new()
                .fill(bg_card())
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::same(16))
                .stroke(Stroke::new(1.0, border()))
                .show(ui, |ui| {
                    self.update_section(ui);
                });
        }
        ui.add_space(space::S);
        if let Some(st) = &self.cache.status {
            egui::Grid::new("about-info")
                .num_columns(2)
                .spacing([14.0, space::XS])
                .show(ui, |ui| {
                    kv_label(ui, t("程序版本", "Program Version"));
                    ui.label(mono_text(&st.version));
                    ui.end_row();
                    kv_label(ui, t("防火墙后端", "Firewall Backend"));
                    ui.label(mono_text(&st.backend));
                    ui.end_row();
                    kv_label(ui, t("权限状态", "Privilege Status"));
                    ui.label(if st.elevated {
                        t("管理员（防火墙可写）", "Elevated (firewall writable)").to_string()
                    } else {
                        t(
                            "未提权（防火墙不可写）",
                            "Not elevated (firewall read-only)",
                        )
                        .to_string()
                    });
                    ui.end_row();
                    kv_label(ui, t("已运行", "Running"));
                    ui.label(humanize_uptime(st.uptime_secs));
                    ui.end_row();
                });
        }

        ui.add_space(space::M);
        section(ui, t("数据与配置", "Data & Config"));
        let (cfg_path, data_dir) = self.eng.config_paths();
        egui::Grid::new("about-paths")
            .num_columns(2)
            .spacing([14.0, space::XS])
            .show(ui, |ui| {
                kv_label(ui, t("配置文件", "Config File"));
                ui.label(mono_text(&cfg_path));
                ui.end_row();
                kv_label(ui, t("数据目录", "Data Directory"));
                ui.label(mono_text(&data_dir));
                ui.end_row();
            });

        ui.add_space(space::M);
        section(ui, t("开源许可", "Open Source Licenses"));
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
            RichText::new(t("安全软件 · 仅供授权环境防御性使用 · 架构与安全文档见仓库 docs/ 目录", "Security software · defensive use in authorized environments only · architecture & security docs in repo docs/"))
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }

    // ---------- 更新（0.8.2，应用内自更新，仅 Windows） ----------

    #[cfg(windows)]
    fn update_section(&mut self, ui: &mut egui::Ui) {
        let gui_ver = env!("CARGO_PKG_VERSION");
        let srv_disp = if self.srv_version.is_empty() {
            "?".to_string()
        } else {
            self.srv_version.clone()
        };
        ui.label(body_text(format!(
            "{} v{gui_ver} · {} v{srv_disp}",
            t("界面", "UI"),
            t("服务端", "Service"),
        )));
        ui.add_space(space::XS);

        // 服务端落后于界面（含"界面 0.8.2 / 服务 0.6.0"这种跨版本场景）：一键升级
        let svc_older = crate::update::parse_version(&self.srv_version)
            .zip(crate::update::parse_version(gui_ver))
            .is_some_and(|(s, c)| s < c);

        match &self.update_state {
            UpdateUi::Idle => {
                ui.horizontal(|ui| {
                    if ui.button(t("检查更新", "Check for Updates")).clicked() {
                        self.start_update_check();
                    }
                    if svc_older
                        && ui
                            .button(t(
                                "一键升级服务到当前版本",
                                "Upgrade service to this version",
                            ))
                            .clicked()
                    {
                        self.start_service_upgrade();
                    }
                });
                if svc_older {
                    ui.label(
                        RichText::new(t(
                            "服务端版本比界面旧：旧引擎缺少新接口，建议升级服务（数据与配置不动）。",
                            "The service is older than the UI; upgrade it (data/config untouched).",
                        ))
                        .size(type_scale::CAPTION)
                        .color(warn()),
                    );
                }
            }
            UpdateUi::Checking(_) => {
                ui.label(caption(t(
                    "正在检查更新（Gitee → GitHub）…",
                    "Checking for updates…",
                )));
            }
            UpdateUi::UpToDate => {
                ui.label(body_text(t("已是最新版本。", "Already up to date.")));
                if ui.button(t("重新检查", "Re-check")).clicked() {
                    self.start_update_check();
                }
            }
            UpdateUi::Available(rel) => {
                ui.label(body_text(t(
                    "发现新版本，可一键升级（服务与界面一起更新，数据不动）。",
                    "A new version is available; upgrade service and UI together.",
                )));
                ui.label(mono_text(format!("v{} → v{}", gui_ver, rel.version)));
                ui.add_space(space::XS);
                let rel2 = rel.clone();
                ui.horizontal(|ui| {
                    if ui.button(t("下载并升级", "Download && Upgrade")).clicked() {
                        self.start_update_download(rel2);
                    }
                    if ui.button(t("暂不", "Later")).clicked() {
                        self.update_state = UpdateUi::Idle;
                    }
                });
            }
            UpdateUi::Downloading { percent, .. } => {
                let p = percent.load(std::sync::atomic::Ordering::Relaxed);
                ui.add(egui::widgets::ProgressBar::new(f32::from(p) / 100.0).show_percentage());
                ui.label(caption(t(
                    "下载中…（完成后需在 UAC 确认一次提权）",
                    "Downloading… (one UAC prompt after download)",
                )));
            }
            UpdateUi::Ready { ver, workdir } => {
                let ver = ver.clone();
                let workdir = workdir.clone();
                ui.label(body_text(t(
                    "新版已就绪。点击后弹出 UAC，确认后自动完成：停服务 → 备份 → 替换 → 重启，界面会自动重新打开。",
                    "Ready. Confirm the UAC prompt: stop service → backup → replace → restart; the UI reopens automatically.",
                )));
                ui.horizontal(|ui| {
                    if ui
                        .button(t(
                            "以管理员身份升级（UAC）",
                            "Upgrade as Administrator (UAC)",
                        ))
                        .clicked()
                    {
                        self.apply_ready_update(&workdir, &ver);
                    }
                    if ui.button(t("取消", "Cancel")).clicked() {
                        self.update_state = UpdateUi::Idle;
                    }
                });
            }
            UpdateUi::Failed(e) => {
                ui.label(
                    RichText::new(format!("✗ {e}"))
                        .color(danger())
                        .size(type_scale::CAPTION),
                );
                if ui.button(t("重试", "Retry")).clicked() {
                    self.update_state = UpdateUi::Idle;
                }
            }
        }
    }

    #[cfg(windows)]
    fn start_update_check(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.update_state = UpdateUi::Checking(rx);
        std::thread::spawn(move || {
            let _ = tx.send(crate::update::check_latest().map_err(|e| e.to_string()));
        });
    }

    #[cfg(windows)]
    fn start_update_download(&mut self, rel: crate::update::Release) {
        let ver = rel.version.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let percent = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let p2 = percent.clone();
        self.update_state = UpdateUi::Downloading { rx, percent, ver };
        std::thread::spawn(move || {
            let workdir = crate::update::update_workdir();
            let res = crate::update::download_and_prepare(&rel, &workdir, &|p| {
                p2.store(p, std::sync::atomic::Ordering::Relaxed);
            })
            .map(|_| workdir)
            .map_err(|e| e.to_string());
            let _ = tx.send(res);
        });
    }

    /// 服务端落后于界面：把当前界面程序复制为"新版"来源，走同一条提权替换路径（无需下载）。
    #[cfg(windows)]
    fn start_service_upgrade(&mut self) {
        let ver = env!("CARGO_PKG_VERSION").to_string();
        let workdir = crate::update::update_workdir();
        let res = std::fs::create_dir_all(&workdir).and_then(|_| {
            let src = std::env::current_exe()?;
            std::fs::copy(src, workdir.join("aisafeguard.exe"))
        });
        self.update_state = match res {
            Ok(_) => UpdateUi::Ready { workdir, ver },
            Err(e) => UpdateUi::Failed(format!("准备升级目录失败: {e}")),
        };
    }

    /// Ready → UAC 拉起新版 exe 执行替换；UAC 通过后本界面退出让位（升级体重开界面）。
    #[cfg(windows)]
    fn apply_ready_update(&mut self, workdir: &std::path::Path, ver: &str) {
        let new_exe = workdir.join("aisafeguard.exe");
        match crate::update::spawn_elevated_apply(&new_exe, workdir, true) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                self.update_state = UpdateUi::Failed(format!("升级未执行（v{ver}）：{e}"));
            }
        }
    }

    // ---------- 公共页脚 ----------

    pub(crate) fn settings_footer(&mut self, ui: &mut egui::Ui) {
        ui.add_space(space::L);
        ui.separator();
        ui.add_space(space::S);
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(t("保存设置", "Save Settings")).color(on_accent()),
                    )
                    .fill(accent())
                    .corner_radius(CornerRadius::same(6)),
                )
                .clicked()
            {
                self.save_settings();
            }
            if ui.button(t("放弃修改", "Discard Changes")).clicked() {
                self.settings_draft = None;
            }
            ui.label(
                RichText::new(t(
                    "带“需重启”标注的项保存后会明确列出；其余保存即热更生效。",
                    "Restart-required items are listed after saving; everything else hot-reloads.",
                ))
                .size(type_scale::CAPTION)
                .color(text_dim()),
            );
        });
    }

    /// API Key 管理：读写凭据管理器，不经过配置文件。
    fn key_management_ui(&mut self, ui: &mut egui::Ui) {
        section(
            ui,
            t("API Key（凭据管理器）", "API Key (credential manager)"),
        );
        ui.horizontal(|ui| {
            let stored = self.eng.ai_key_present().unwrap_or(false);
            let env_set = std::env::var_os("AISAFEGUARD_AI_KEY").is_some_and(|v| !v.is_empty());
            if env_set {
                chip(ui, t("环境变量覆盖中", "Overridden by env var"), warn());
            }
            chip(
                ui,
                if stored {
                    t("已存入凭据管理器", "Stored in credential manager")
                } else {
                    t("未存储", "Not stored")
                },
                if stored { ok() } else { text_dim() },
            );
        });
        egui::CollapsingHeader::new(
            egui::RichText::new(t("更改 Key", "Change Key")).size(type_scale::BODY),
        )
        .id_salt("change-key")
        .default_open(false)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.settings_key_input)
                    .password(true)
                    .desired_width(380.0)
                    .hint_text(t("粘贴新 Key", "Paste New Key")),
            );
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(t("保存到凭据管理器", "Save to credential manager"))
                                .color(on_accent()),
                        )
                        .fill(accent())
                        .corner_radius(CornerRadius::same(6)),
                    )
                    .clicked()
                {
                    let value = self.settings_key_input.trim().to_string();
                    if value.is_empty() {
                        self.set_toast(t("Key 不能为空", "Key cannot be empty"));
                    } else {
                        match self.eng.set_ai_key(&value) {
                            Ok(()) => {
                                self.set_toast(t(
                                    "Key 已存入凭据管理器",
                                    "Key stored in credential manager",
                                ));
                                self.settings_key_input.clear();
                            }
                            Err(e) => {
                                self.set_toast(format!("{}{}", t("保存失败: ", "Save failed: "), e))
                            }
                        }
                        self.refresh_cache();
                    }
                }
                if ui.button(t("清除已存 Key", "Clear Stored Key")).clicked() {
                    match self.eng.delete_ai_key() {
                        Ok(()) => self.set_toast(t(
                            "已清除凭据管理器中的 Key",
                            "Key cleared from credential manager",
                        )),
                        Err(e) => {
                            self.set_toast(format!("{}{}", t("清除失败: ", "Clear failed: "), e))
                        }
                    }
                    self.refresh_cache();
                }
            });
        });
        ui.label(
            RichText::new(t("环境变量 AISAFEGUARD_AI_KEY 优先于凭据管理器（适合 CI/无头部署）。配置文件不保存任何秘密。", "Env var AISAFEGUARD_AI_KEY takes precedence over the credential manager (good for CI/headless). Config files never store secrets."))
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
                self.set_toast(t(
                    "分析间隔需在 30-86400 秒之间",
                    "Analysis interval must be 30-86400 s",
                ));
                return;
            }
        }
        match self.settings_port.trim().parse::<u16>() {
            Ok(v) if v > 0 => cfg.api.port = v,
            _ => {
                self.set_toast(t("API 端口非法", "Invalid API port"));
                return;
            }
        }
        match self.settings_snippet.trim().parse::<usize>() {
            Ok(v) if (40..=2000).contains(&v) => cfg.ai.max_snippet_chars = v,
            _ => {
                self.set_toast(t(
                    "payload 上送上限需在 40-2000 之间",
                    "payload upload cap must be 40-2000",
                ));
                return;
            }
        }
        // 误报抑制时长（0.5.5 F8）：天 → 秒；建议 7～14 天
        match self.settings_fp_days.trim().parse::<u64>() {
            Ok(d) if (1..=90).contains(&d) => cfg.ai.fp_suppress_secs = d * 86_400,
            _ => {
                self.set_toast(t(
                    "误报抑制时长需在 1-90 天之间",
                    "FP suppression must be 1-90 days",
                ));
                return;
            }
        }
        // 远程日志 / 告警 / 暴露面（0.3.5）
        cfg.syslog.target = self.settings_syslog_target.trim().to_string();
        if cfg.syslog.enabled && cfg.syslog.target.is_empty() {
            self.set_toast(t(
                "启用 syslog 转发需填写收集器地址",
                "Collector address required to enable syslog",
            ));
            return;
        }
        if !cfg.notify.valid_min_severity() {
            self.set_toast(t("告警最低严重度非法", "Invalid min webhook severity"));
            return;
        }
        cfg.notify.url = self.settings_notify_url.trim().to_string();
        if cfg.notify.enabled && cfg.notify.url.is_empty() {
            self.set_toast(t(
                "启用告警推送需填写接收端 URL",
                "Receiver URL required to enable webhooks",
            ));
            return;
        }
        match self.settings_exposure_secs.trim().parse::<u64>() {
            Ok(0) => cfg.exposure.auto_scan_secs = 0,
            Ok(v) if (300..=86400).contains(&v) => cfg.exposure.auto_scan_secs = v,
            _ => {
                self.set_toast(t(
                    "暴露面扫描间隔需为 0（关闭）或 300-86400 秒",
                    "Exposure scan interval must be 0 (off) or 300-86400 s",
                ));
                return;
            }
        }
        cfg.xdp.iface = self.settings_xdp_iface.trim().to_string();
        if cfg.xdp.enabled && cfg.xdp.iface.is_empty() {
            self.set_toast(t(
                "启用 XDP 需填写网卡名",
                "NIC name required to enable XDP",
            ));
            return;
        }
        if !cfg.xdp.valid_mode() {
            self.set_toast(t(
                "XDP 模式非法（skb | native）",
                "Invalid XDP mode (skb | native)",
            ));
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
                            self.set_toast(format!(
                                "{}{}",
                                t("监听端口重复: ", "Duplicate listener port: "),
                                p
                            ));
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
                    self.set_toast(t("监听器名称不能为空", "Listener name cannot be empty"));
                    return;
                }
            }
        }
        // 假 Shell 会话参数（H130）：命令上限收敛到合理区间
        match self.settings_shell_max_cmds.trim().parse::<usize>() {
            Ok(v) if (1..=500).contains(&v) => cfg.honeypot.shell.max_commands = v,
            _ => {
                self.set_toast(t(
                    "假 Shell 单会话命令上限需在 1-500 之间",
                    "Fake-shell command cap must be 1-500",
                ));
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
                    t(
                        "设置已保存（改动全部热更生效，无需重启）",
                        "Settings saved (all changes hot-reloaded, no restart)",
                    )
                    .to_string()
                } else {
                    format!("设置已保存；需重启生效：{}", restart_items.join("、"))
                };
                self.set_toast(&toast);
                self.settings_draft = None;
                self.refresh_cache();
            }
            Err(e) => self.set_toast(format!("{}{}", t("保存失败: ", "Save failed: "), e)),
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
        s if s < 90 => format!("{}{}", s, t("秒", "s")),
        m if m < 5400 => format!("{} 分钟", (m + 30) / 60),
        h if h < 129_600 => format!("{} 小时", (h + 1800) / 3600),
        d => format!("{} 天", (d + 43_200) / 86_400),
    }
}
