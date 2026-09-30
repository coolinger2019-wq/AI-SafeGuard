//! 组织页（0.6 F500）：多节点协同面板——成员表、组织事件流、协议计数。
//! 架构红线：面板只读（数据走 GET /api/fed/panel），操作仅软隔离/解除
//! （与 fed quarantine CLI 同一 DB 通路）；离线成员展示「数据截至」。
//! 证据链跨节点跳转视图与节点详情代理归 F600（需协调者无状态代理通路）。

use super::*;

impl AisafeApp {
    pub(crate) fn org_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(title("组织协同").strong());
        ui.add_space(space::M);

        let Some(panel) = self.cache.fed_panel.clone() else {
            ui.label(body_text("组织面板数据不可用"));
            return;
        };

        if !panel.enabled || panel.role == "off" {
            section(ui, "未加入组织");
            ui.label(body_text(
                "本节点未启用组织协同。在 config.toml 的 [fed] 段配置角色与证书后加入组织：\n\
                 · 协调者：fed init-ca 创建组织 → fed issue-cert 为各节点发证\n\
                 · 成员：role = \"agent\"，coordinator 指向协调者地址\n\
                 详见 docs/FEDERATION.md",
            ));
            return;
        }

        // 角色头
        let role_text = match panel.role.as_str() {
            "coordinator" => "协调者",
            "agent" => "成员（agent）",
            _ => &panel.role,
        };
        ui.horizontal(|ui| {
            ui.label(section_title(role_text).strong());
            ui.label(body_text(format!("节点 {}", panel.node)));
            ui.label(caption(if panel.role == "agent" {
                format!("协调者 {}", panel.endpoint)
            } else {
                format!("监听 {}", panel.endpoint)
            }));
        });
        ui.add_space(space::M);

        // 成员表（仅协调者有数据）
        if panel.role == "coordinator" {
            section(ui, "成员");
            let stats = &panel.stats;
            ui.horizontal_wrapped(|ui| {
                let cnt = |k: &str| stats[k].as_u64().unwrap_or(0);
                card(ui, "成员数", &panel.members.len().to_string(), accent());
                ui.add_space(space::M);
                card(
                    ui,
                    "隔离中",
                    &panel
                        .members
                        .iter()
                        .filter(|m| m.status == "quarantined")
                        .count()
                        .to_string(),
                    warn(),
                );
                ui.add_space(space::M);
                card(ui, "消息被篡改", &cnt("sig_fail").to_string(), danger());
                ui.add_space(space::M);
                card(ui, "序列号回退", &cnt("seq_reject").to_string(), danger());
                ui.add_space(space::M);
                card(ui, "限频拦截", &cnt("rate_limited").to_string(), warn());
                ui.add_space(space::M);
                card(ui, "重复消息", &cnt("duplicates").to_string(), text_dim());
            });
            ui.add_space(space::S);

            let now = panel.data_as_of;
            egui::Grid::new("fed-members")
                .num_columns(5)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("节点");
                    ui.strong("状态");
                    ui.strong("最后在线");
                    ui.strong("证书指纹");
                    ui.strong("操作");
                    ui.end_row();

                    for m in &panel.members {
                        ui.label(mono_text(&m.node));
                        let (status_text, color) = if m.status == "quarantined" {
                            ("隔离中", warn())
                        } else {
                            ("正常", accent())
                        };
                        ui.label(RichText::new(status_text).color(color));
                        let ago = now - m.last_seen;
                        // 心跳周期（interval_secs ≥15s，默认 60s）：2 分钟内 = 在线
                        let online = ago < 120;
                        ui.label(
                            RichText::new(if online {
                                "在线".to_string()
                            } else {
                                format!("离线 · 数据截至 {} 前", crate::explain::humanize_secs(ago))
                            })
                            .color(if online { accent() } else { text_dim() }),
                        );
                        ui.label(caption(
                            m.cert_fp.get(0..16).unwrap_or(&m.cert_fp).to_string(),
                        ));
                        // 操作：与 CLI 同一 DB 通路（POST /api/fed/members/{node}/…）
                        if m.status == "quarantined" {
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.org_lift_fp)
                                        .hint_text("指纹前缀 ≥16 位")
                                        .desired_width(180.0),
                                );
                                if ui.button("解除隔离").clicked()
                                    && !self.org_lift_fp.trim().is_empty()
                                {
                                    let node = m.node.clone();
                                    let fp = self.org_lift_fp.trim().to_string();
                                    match self.eng.quarantine_member(&node, true, &fp, "") {
                                        Ok(msg) => {
                                            self.org_lift_fp.clear();
                                            self.set_toast(msg);
                                            self.refresh_cache();
                                        }
                                        Err(e) => self.set_toast(format!("解除失败：{e}")),
                                    }
                                }
                            });
                        } else {
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.org_reason)
                                        .hint_text("隔离原因（可选）")
                                        .desired_width(150.0),
                                );
                                if ui.button("软隔离").clicked() {
                                    let node = m.node.clone();
                                    let reason = self.org_reason.trim().to_string();
                                    match self.eng.quarantine_member(&node, false, "", &reason) {
                                        Ok(msg) => {
                                            self.org_reason.clear();
                                            self.set_toast(msg);
                                            self.refresh_cache();
                                        }
                                        Err(e) => self.set_toast(format!("隔离失败：{e}")),
                                    }
                                }
                            });
                        }
                        ui.end_row();
                    }
                });
            ui.add_space(space::M);
        }

        // 组织事件流（本节点账本：印证/建议/误报提示/推荐/隔离广播）
        section(ui, "组织事件流");
        ui.label(caption(
            "本节点收到的组织消息与复验结果（只读；处置仍走本地路径）",
        ));
        ui.add_space(space::S);
        if panel.org_events.is_empty() {
            ui.label(body_text("暂无组织事件"));
        } else {
            egui::Grid::new("fed-org-events")
                .num_columns(4)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("时间");
                    ui.strong("类型");
                    ui.strong("对象");
                    ui.strong("详情");
                    ui.end_row();
                    for e in panel.org_events.iter().take(30) {
                        let ago = panel.data_as_of.saturating_sub(e.ts);
                        ui.label(caption(crate::explain::humanize_secs(ago) + "前"));
                        let (kind_text, color) = match e.kind.as_str() {
                            "corroboration" => ("印证", accent()),
                            "suggestion" => ("建议", purple()),
                            "fp-flag" => ("误报提示", warn()),
                            "quorum" => ("组织推荐", purple()),
                            "quarantine" => ("隔离", danger()),
                            _ => (e.kind.as_str(), text_dim()),
                        };
                        ui.label(RichText::new(kind_text).color(color));
                        ui.label(mono_text(if e.key.is_empty() { "—" } else { &e.key }));
                        ui.label(caption(match e.kind.as_str() {
                            "corroboration" => format!(
                                "{} 节点 · 复验{}",
                                e.nodes_count,
                                if e.detail == "hit" { "命中" } else { "未命中" }
                            ),
                            "fp-flag" => format!("{} 节点标记误报", e.nodes_count),
                            "quorum" => format!("{} 节点采纳", e.nodes_count),
                            _ => e.detail.clone(),
                        }));
                        ui.end_row();
                    }
                });
        }

        ui.add_space(space::M);
        ui.label(caption(
            "红线：面板只读；仅隔离/解除可操作（与 CLI 同通路，隔离保留心跳与审计）。\
             印证事件证据链跨节点跳转视图在 0.6 收口批提供。",
        ));
    }
}
