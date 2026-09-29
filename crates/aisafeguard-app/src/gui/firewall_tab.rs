use super::*;
use aisafeguard_firewall::{BlockSpec, Direction, Protocol};

impl AisafeApp {
    pub(crate) fn firewall_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("防火墙").size(22.0).strong());
        ui.add_space(10.0);

        let elevated = self
            .cache
            .status
            .as_ref()
            .map(|s| s.elevated)
            .unwrap_or(false);
        if !elevated {
            warn_banner(
                ui,
                "未以管理员身份运行：添加/删除防火墙规则会失败。请关闭后以管理员身份重新启动 AI-SafeGuard。",
            );
        }

        section(ui, "手动封禁");
        egui::Grid::new("fw-form")
            .num_columns(4)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label("来源 IP");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_ip)
                        .desired_width(170.0)
                        .hint_text("如 203.0.113.7，留空=任意"),
                );
                ui.label("目标端口");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_port)
                        .desired_width(90.0)
                        .hint_text("1-65535，留空=任意"),
                );
                ui.end_row();

                ui.label("方向");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.new_dir_out, false, "入站");
                    ui.selectable_value(&mut self.new_dir_out, true, "出站");
                });
                ui.label("协议");
                egui::ComboBox::from_id_salt("fw-proto")
                    .selected_text(["ANY", "TCP", "UDP"][self.new_proto_idx])
                    .show_ui(ui, |ui| {
                        for (i, p) in ["ANY", "TCP", "UDP"].iter().enumerate() {
                            ui.selectable_value(&mut self.new_proto_idx, i, *p);
                        }
                    });
                ui.end_row();

                ui.label("备注");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_note)
                        .desired_width(380.0)
                        .hint_text("可选，会写进防火墙规则描述"),
                );
                ui.end_row();

                ui.label("标签");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_tag)
                        .desired_width(380.0)
                        .hint_text("可选，来源/用途分组（如「蜜罐」「办公网段」）"),
                );
                ui.end_row();
            });
        ui.add_space(6.0);
        if ui
            .add(
                egui::Button::new(RichText::new("添加封禁规则").color(on_accent()))
                    .fill(accent())
                    .corner_radius(CornerRadius::same(6)),
            )
            .clicked()
        {
            self.apply_manual_rule();
        }

        ui.add_space(14.0);
        section(ui, format!("已管理规则（{}）", self.cache.rules.len()));
        let rules = self.cache.rules.clone();
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::exact(190.0))
            .column(egui_extras::Column::exact(60.0))
            .column(egui_extras::Column::exact(60.0))
            .column(egui_extras::Column::exact(130.0))
            .column(egui_extras::Column::exact(70.0))
            .column(egui_extras::Column::exact(60.0))
            .column(egui_extras::Column::exact(110.0))
            .column(egui_extras::Column::remainder())
            .header(22.0, |mut header| {
                for name in [
                    "规则名",
                    "方向",
                    "协议",
                    "来源 IP",
                    "端口",
                    "来源",
                    "创建时间",
                    "",
                ] {
                    header.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|mut body| {
                for r in &rules {
                    body.row(24.0, |mut row| {
                        row.col(|ui| {
                            ui.label(RichText::new(&r.name).monospace().size(11.0));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(dir_cn(&r.direction)).size(12.0));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(proto_up(&r.protocol)).size(12.0));
                        });
                        row.col(|ui| {
                            let ip = if r.remote_ip.is_empty() {
                                "任意".into()
                            } else {
                                r.remote_ip.clone()
                            };
                            ui.label(RichText::new(ip).monospace().size(12.0));
                            if !r.tag.is_empty() {
                                ui.label(
                                    RichText::new(format!("#{}", r.tag))
                                        .size(10.0)
                                        .color(text_dim()),
                                );
                            }
                        });
                        row.col(|ui| {
                            let p = r
                                .local_port
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "任意".into());
                            ui.label(RichText::new(p).size(12.0));
                        });
                        row.col(|ui| {
                            let (text, color) = match r.origin.as_str() {
                                "ai" => ("AI", purple()),
                                "engine" => ("检测器", warn()),
                                "intel" => ("情报", ok()),
                                _ => ("手动", text_dim()),
                            };
                            ui.label(RichText::new(text).size(12.0).color(color));
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(fmt_ts(r.created_ts))
                                    .size(11.0)
                                    .color(text_dim()),
                            );
                        });
                        row.col(|ui| {
                            let rid = r.id;
                            // 灰度规则（AI 来源 + 带 TTL）可转正：TTL 延长到 promote_ttl_secs
                            if r.origin == "ai"
                                && r.enabled
                                && r.expires_ts.is_some()
                                && ui
                                    .add(egui::Button::new(
                                        RichText::new("转正").size(12.0).color(purple()),
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
                                            "规则 #{rid} 已转正（封禁至 {until}）"
                                        ));
                                    }
                                    Err(e) => self.set_toast(format!("转正失败: {e}")),
                                }
                                self.refresh_cache();
                            }
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("删除").size(12.0).color(danger()),
                                    )
                                    .fill(Color32::TRANSPARENT),
                                )
                                .clicked()
                            {
                                match self.eng.remove_rule(rid) {
                                    Ok(()) => self.set_toast(format!("规则 #{rid} 已删除")),
                                    Err(e) => self.set_toast(format!("删除失败: {e}")),
                                }
                                self.refresh_cache();
                            }
                        });
                    });
                }
            });
    }

    fn apply_manual_rule(&mut self) {
        let remote_ip = match self.new_ip.trim() {
            "" => None,
            s => match s.parse::<std::net::IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    self.set_toast("来源 IP 格式不合法");
                    return;
                }
            },
        };
        let local_port = match self.new_port.trim() {
            "" => None,
            s => match s.parse::<u16>() {
                Ok(p) if p > 0 => Some(p),
                _ => {
                    self.set_toast("端口必须是 1-65535");
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
                "界面手动添加".into()
            } else {
                self.new_note.trim().to_string()
            },
            tag: self.new_tag.trim().to_string(),
        };
        match self.eng.add_block(&spec, "manual") {
            Ok(_) => {
                self.set_toast(format!("已添加: {}", spec.describe()));
                self.new_ip.clear();
                self.new_port.clear();
                self.new_note.clear();
                self.new_tag.clear();
            }
            Err(e) => self.set_toast(format!("添加失败: {e}")),
        }
        self.refresh_cache();
    }
}
