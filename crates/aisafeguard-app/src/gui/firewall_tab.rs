use super::*;
use aisafeguard_firewall::{BlockSpec, Direction, Protocol};

impl AisafeApp {
    pub(crate) fn firewall_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(t("防火墙", "Firewall"))
                .size(type_scale::TITLE)
                .strong(),
        );
        ui.add_space(space::M);

        let elevated = self
            .cache
            .status
            .as_ref()
            .map(|s| s.elevated)
            .unwrap_or(false);
        if !elevated {
            warn_banner(
                ui,
                t(
                    "未以管理员身份运行：添加/删除防火墙规则会失败。请关闭后以管理员身份重新启动 AI-SafeGuard。",
                    "Not running elevated: adding/removing firewall rules will fail. Restart AI-SafeGuard as administrator.",
                ),
            );
        }

        section(ui, t("手动封禁", "Manual Block"));
        egui::Grid::new("fw-form")
            .num_columns(4)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label(t("来源 IP", "Source IP"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_ip)
                        .desired_width(170.0)
                        .hint_text(t(
                            "如 203.0.113.7，留空=任意",
                            "e.g. 203.0.113.7, empty = any",
                        )),
                );
                ui.label(t("目标端口", "Target Port"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_port)
                        .desired_width(90.0)
                        .hint_text(t("1-65535，留空=任意", "1-65535, empty = any")),
                );
                ui.end_row();

                ui.label(t("方向", "Direction"));
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.new_dir_out, false, t("入站", "Inbound"));
                    ui.selectable_value(&mut self.new_dir_out, true, t("出站", "Outbound"));
                });
                ui.label(t("协议", "Protocol"));
                egui::ComboBox::from_id_salt("fw-proto")
                    .selected_text(["ANY", "TCP", "UDP"][self.new_proto_idx])
                    .show_ui(ui, |ui| {
                        for (i, p) in ["ANY", "TCP", "UDP"].iter().enumerate() {
                            ui.selectable_value(&mut self.new_proto_idx, i, *p);
                        }
                    });
                ui.end_row();

                ui.label(t("备注", "Note"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_note)
                        .desired_width(380.0)
                        .hint_text(t(
                            "可选，会写进防火墙规则描述",
                            "optional, stored in the firewall rule description",
                        )),
                );
                ui.end_row();

                ui.label(t("标签", "Tag"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_tag)
                        .desired_width(380.0)
                        .hint_text(t(
                            "可选，来源/用途分组（如「蜜罐」「办公网段」）",
                            "optional tag, e.g. honeypot / office subnet",
                        )),
                );
                ui.end_row();
            });
        ui.add_space(space::S);
        if ui
            .add(
                egui::Button::new(
                    RichText::new(t("添加封禁规则", "Add Block Rule")).color(on_accent()),
                )
                .fill(accent())
                .corner_radius(CornerRadius::same(6)),
            )
            .clicked()
        {
            self.apply_manual_rule();
        }

        ui.add_space(space::L);
        section(
            ui,
            format!(
                "{} {}",
                t("已管理规则", "Managed Rules"),
                self.cache.rules.len()
            ),
        );
        let rules = self.cache.rules.clone();
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::exact(52.0))
            .column(egui_extras::Column::exact(52.0))
            .column(egui_extras::Column::exact(120.0))
            .column(egui_extras::Column::exact(52.0))
            .column(egui_extras::Column::exact(64.0))
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::exact(170.0))
            .column(egui_extras::Column::remainder())
            .header(HEADER_H, |mut header| {
                for name in [
                    t("规则名", "Rule Name"),
                    t("方向", "Direction"),
                    t("协议", "Protocol"),
                    t("来源 IP", "Source IP"),
                    t("端口", "Port"),
                    t("来源", "Source"),
                    t("原因", "Reason"),
                    t("TTL / 状态", "TTL / State"),
                    "",
                ] {
                    header.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|mut body| {
                for r in &rules {
                    body.row(ROW_H, |mut row| {
                        row.col(|ui| {
                            ui.label(RichText::new(&r.name).monospace().size(type_scale::MICRO));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(dir_cn(&r.direction)).size(type_scale::CAPTION));
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(proto_up(&r.protocol)).size(type_scale::CAPTION),
                            );
                        });
                        row.col(|ui| {
                            let ip = if r.remote_ip.is_empty() {
                                t("任意", "Any").into()
                            } else {
                                r.remote_ip.clone()
                            };
                            ui.label(RichText::new(ip).monospace().size(type_scale::CAPTION));
                            if !r.tag.is_empty() {
                                ui.label(
                                    RichText::new(format!("#{}", r.tag))
                                        .size(type_scale::MICRO)
                                        .color(text_dim()),
                                );
                            }
                        });
                        row.col(|ui| {
                            let p = r
                                .local_port
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| t("任意", "Any").into());
                            ui.label(RichText::new(p).size(type_scale::CAPTION));
                        });
                        row.col(|ui| {
                            let color = match r.origin.as_str() {
                                "ai" => purple(),
                                "engine" => warn(),
                                "intel" => ok(),
                                "manual" => text_dim(),
                                _ => danger(),
                            };
                            ui.label(
                                RichText::new(&r.source)
                                    .size(type_scale::CAPTION)
                                    .color(color),
                            );
                        });
                        row.col(|ui| {
                            // F2：原因摘要一句话；清洗 + 截断在 explain 层完成
                            ui.label(RichText::new(&r.reason_summary).size(type_scale::CAPTION));
                        });
                        row.col(|ui| {
                            // F3：试封中 / 已转正 / 自动封禁 / 手动 固定文案
                            ui.label(RichText::new(&r.ttl_text).size(type_scale::MICRO));
                        });
                        row.col(|ui| {
                            let rid = r.id;
                            // F4：从规则跳到相关事件（按来源 IP 过滤）
                            if !r.remote_ip.is_empty()
                                && ui
                                    .add(egui::Button::new(
                                        RichText::new(t("查看事件", "View Events"))
                                            .size(type_scale::CAPTION)
                                            .color(accent()),
                                    ))
                                    .clicked()
                            {
                                self.event_filter = r.remote_ip.clone();
                                self.tab = Tab::Events;
                                self.refresh_cache();
                            }
                            // 误报一键入口（0.5.5 F7）：与事件页 / AI 建议行同一逻辑；
                            // 手动规则默认不动（引擎只解除 engine/ai 来源的自动封禁）
                            if !r.remote_ip.is_empty()
                                && ui
                                    .add(egui::Button::new(
                                        RichText::new(t("误报", "False Positive"))
                                            .size(type_scale::CAPTION)
                                            .color(warn()),
                                    ))
                                    .clicked()
                            {
                                let ip = r.remote_ip.clone();
                                self.mark_fp(&ip);
                            }
                            // 灰度规则（试封中）可转正：TTL 延长到 promote_ttl_secs
                            if r.ttl_state == "trial"
                                && r.enabled
                                && ui
                                    .add(egui::Button::new(
                                        RichText::new(t("转正", "Promote"))
                                            .size(type_scale::CAPTION)
                                            .color(purple()),
                                    ))
                                    .clicked()
                            {
                                match self.eng.promote_rule(rid) {
                                    Ok(row) => {
                                        let until = row
                                            .expires_ts
                                            .and_then(|t| {
                                                chrono::DateTime::from_timestamp(t, 0).map(|d| {
                                                    d.with_timezone(&chrono::Local)
                                                        .format("%Y-%m-%d %H:%M")
                                                        .to_string()
                                                })
                                            })
                                            .unwrap_or_default();
                                        self.set_toast(format!(
                                            "{} {} {} {}",
                                            t("规则 #", "Rule #"),
                                            rid,
                                            t("已转正（封禁至 ", "promoted (banned until "),
                                            until
                                        ));
                                    }
                                    Err(e) => self.set_toast(format!(
                                        "{} {}",
                                        t("转正失败: ", "Promote failed: "),
                                        e
                                    )),
                                }
                                self.refresh_cache();
                            }
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(t("删除", "Delete"))
                                            .size(type_scale::CAPTION)
                                            .color(danger()),
                                    )
                                    .fill(Color32::TRANSPARENT),
                                )
                                .clicked()
                            {
                                match self.eng.remove_rule(rid) {
                                    Ok(()) => {
                                        self.set_toast(format!("{}{}", t("规则 #", "Rule #"), rid))
                                    }
                                    Err(e) => self.set_toast(format!(
                                        "{} {}",
                                        t("删除失败: ", "Delete failed: "),
                                        e
                                    )),
                                }
                                self.refresh_cache();
                            }
                        });
                    });
                }
            });
        ui.add_space(space::XS);
        ui.label(
            RichText::new(t("来源说明：手动 = 界面/API 人工添加；检测引擎 / AI / 情报 = 自动封禁（AI 为灰度试封，可转正）。", "Sources: manual = added via UI/API; Engine / AI / Intel = automatic (AI is a trial ban, promotable)."))
                .size(type_scale::MICRO)
                .color(text_dim()),
        );
    }

    fn apply_manual_rule(&mut self) {
        let remote_ip = match self.new_ip.trim() {
            "" => None,
            s => match s.parse::<std::net::IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    self.set_toast(t("来源 IP 格式不合法", "Invalid source IP format"));
                    return;
                }
            },
        };
        let local_port = match self.new_port.trim() {
            "" => None,
            s => match s.parse::<u16>() {
                Ok(p) if p > 0 => Some(p),
                _ => {
                    self.set_toast(t("端口必须是 1-65535", "Port must be 1-65535"));
                    return;
                }
            },
        };
        let protocol = match self.new_proto_idx {
            1 => Protocol::Tcp,
            2 => Protocol::Udp,
            _ => Protocol::Any,
        };
        let spec = BlockSpec {
            direction: if self.new_dir_out {
                Direction::Out
            } else {
                Direction::In
            },
            protocol,
            remote_ip,
            local_port,
            note: if self.new_note.trim().is_empty() {
                t("界面手动添加", "Added manually via UI").into()
            } else {
                self.new_note.trim().to_string()
            },
            tag: self.new_tag.trim().to_string(),
        };
        match self.eng.add_block(&spec, "manual") {
            Ok(_) => {
                self.set_toast(format!("{} {}", t("已添加: ", "Added: "), spec.describe()));
                self.new_ip.clear();
                self.new_port.clear();
                self.new_note.clear();
                self.new_tag.clear();
            }
            Err(e) => self.set_toast(format!("{} {}", t("添加失败: ", "Add failed: "), e)),
        }
        self.refresh_cache();
    }
}
