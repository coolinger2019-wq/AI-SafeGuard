//! F760-B 评审页（egui，与 Web 控制台「评审」同源 API/存储——双端同步纪律）：
//! 系统自审建议的 人工决策界面——采纳（去向）/拒绝（理由）/完成（记录），进度留痕。

use super::*;

pub(crate) struct ReviewDraft {
    pub rows: Vec<aisafeguard_store::SuggestionRow>,
    pub loaded: bool,
    pub sel: Option<i64>,
    pub note: String,
    // 详情编辑草稿（选中行时填充；保存修正走 edit_suggestion）
    pub edit_title: String,
    pub edit_priority: String,
    pub edit_evidence: String,
    pub edit_action: String,
}

impl AisafeApp {
    pub(crate) fn review_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(t("评审", "Review"))
                .size(type_scale::TITLE)
                .strong(),
        );
        ui.add_space(space::M);

        // 首次进入加载
        if !self.review.loaded {
            self.review_reload();
        }

        ui.horizontal_wrapped(|ui| {
            if ui
                .add(egui::Button::new(
                    RichText::new(t("⟳ 刷新", "⟳ Refresh")).size(type_scale::BODY),
                ))
                .clicked()
            {
                self.review_reload();
            }
            if ui
                .add(egui::Button::new(
                    RichText::new(t("▶ 立即自审", "▶ Run review")).size(type_scale::BODY),
                ))
                .clicked()
            {
                self.eng.trigger_review();
                self.set_toast(t(
                    "自审已开始（AI 分析约需 30-60 秒），稍后点刷新",
                    "Review started (30-60 s), refresh afterwards",
                ));
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.review.note)
                    .hint_text(t(
                        "选中条目的决策备注（去向/理由/完成记录）",
                        "Decision note for selection",
                    ))
                    .desired_width(340.0),
            );
        });
        ui.add_space(space::S);

        let sel_row = self
            .review
            .sel
            .and_then(|id| self.review.rows.iter().find(|r| r.id == id).cloned());

        if let Some(row) = &sel_row {
            ui.group(|ui| {
                ui.label(RichText::new(&row.title).size(type_scale::BODY).strong());
                ui.label(caption(&format!(
                    "{} · {} · {}",
                    row.category, row.priority, row.day
                )));
                // 可编辑详情：评审者修正提案本体（如把累进阶梯改成自己的口径），
                // 修正版才是采纳/拒绝的记录；fingerprint 不动（去重锚保持原主题）
                let editable = row.status == "pending" || row.status == "adopted";
                ui.add_space(space::S);
                ui.label(caption(t("标题（可修正）", "Title (editable)")));
                ui.add(
                    egui::TextEdit::singleline(&mut self.review.edit_title)
                        .desired_width(560.0)
                        .interactive(editable),
                );
                ui.horizontal(|ui| {
                    ui.label(caption(t("优先级", "Priority")));
                    egui::ComboBox::from_id_salt("sg-pr")
                        .selected_text(&self.review.edit_priority)
                        .show_ui(ui, |ui| {
                            for p in ["P1", "P2", "P3"] {
                                ui.selectable_value(
                                    &mut self.review.edit_priority,
                                    p.to_string(),
                                    p,
                                );
                            }
                        });
                });
                ui.label(caption(t("证据（可修正）", "Evidence (editable)")));
                ui.add(
                    egui::TextEdit::multiline(&mut self.review.edit_evidence)
                        .desired_width(560.0)
                        .interactive(editable),
                );
                ui.label(caption(t("建议动作（可修正）", "Action (editable)")));
                ui.add(
                    egui::TextEdit::multiline(&mut self.review.edit_action)
                        .desired_width(560.0)
                        .interactive(editable),
                );
                if !row.note.is_empty() {
                    ui.label(caption(&format!("{}：{}", t("决策备注", "Note"), row.note)));
                }
                ui.horizontal_wrapped(|ui| {
                    let note = self.review.note.clone();
                    let (title, pr, ev, act) = (
                        self.review.edit_title.clone(),
                        self.review.edit_priority.clone(),
                        self.review.edit_evidence.clone(),
                        self.review.edit_action.clone(),
                    );
                    if editable && ui.button(t("💾 保存修正", "💾 Save amendment")).clicked()
                    {
                        match self.eng.edit_suggestion(row.id, &title, &pr, &ev, &act) {
                            Ok(()) => {
                                self.set_toast(t("修正已保存", "Amendment saved"));
                                self.review_reload();
                            }
                            Err(e) => {
                                self.set_toast(format!("{}: {e}", t("修正失败", "Edit failed")))
                            }
                        }
                    }
                    match row.status.as_str() {
                        "pending" => {
                            if ui.button(t("✓ 采纳", "✓ Adopt")).clicked() {
                                self.decide(row.id, "adopted", &note);
                            }
                            if ui.button(t("✕ 拒绝", "✕ Reject")).clicked() {
                                self.decide(row.id, "rejected", &note);
                            }
                        }
                        "adopted" => {
                            if ui.button(t("✔ 完成", "✔ Complete")).clicked() {
                                self.decide(row.id, "completed", &note);
                            }
                        }
                        _ => {
                            ui.label(caption(t("已终态", "Final state")));
                        }
                    }
                });
            });
        } else {
            ui.label(caption(t(
                "点击列表中的条目查看详情并决策",
                "Click a row to review and decide",
            )));
        }

        ui.add_space(space::M);
        let st_color = |st: &str| match st {
            "adopted" | "completed" => ok(),
            "rejected" => warn(),
            _ => text_dim(),
        };
        let st_label = |st: &str| -> String {
            match st {
                "pending" => t("待决策", "pending").to_string(),
                "adopted" => t("已采纳", "adopted").to_string(),
                "rejected" => t("已拒绝", "rejected").to_string(),
                "completed" => t("已完成", "completed").to_string(),
                other => other.to_string(),
            }
        };
        egui::ScrollArea::vertical().show(ui, |ui| {
            for r in &self.review.rows {
                let selected = self.review.sel == Some(r.id);
                let label = format!(
                    "[{}] {} · {} · {}",
                    st_label(&r.status),
                    r.priority,
                    r.category,
                    r.title
                );
                let _ = st_color(&r.status);
                if ui
                    .add(
                        egui::Button::new(RichText::new(label).size(type_scale::BODY))
                            .fill(if selected {
                                accent_soft()
                            } else {
                                Color32::TRANSPARENT
                            })
                            .min_size(egui::vec2(ui.available_width() - 8.0, 26.0)),
                    )
                    .clicked()
                {
                    self.review.sel = Some(r.id);
                    self.review.note = r.note.clone();
                    self.review.edit_title = r.title.clone();
                    self.review.edit_priority = r.priority.clone();
                    self.review.edit_evidence = r.evidence.clone();
                    self.review.edit_action = r.action.clone();
                }
            }
            if self.review.rows.is_empty() {
                ui.label(caption(t(
                    "暂无自审建议——AI 每日生成一轮，或点「立即自审」",
                    "No suggestions yet — daily, or run now",
                )));
            }
        });
    }

    fn review_reload(&mut self) {
        match self.eng.list_suggestions(200) {
            Ok(rows) => {
                self.review.rows = rows;
                self.review.loaded = true;
            }
            Err(e) => self.set_toast(format!(
                "{}: {e}",
                t("读取评审建议失败", "Failed to load suggestions")
            )),
        }
    }

    fn decide(&mut self, id: i64, status: &str, note: &str) {
        match self.eng.decide_suggestion(id, status, note) {
            Ok(()) => {
                self.set_toast(t("决策已记录", "Decision recorded"));
                self.review_reload();
            }
            Err(e) => self.set_toast(format!("{}: {e}", t("决策失败", "Decision failed"))),
        }
    }
}
