//! 蜜罐页：六协议监听器的状态控制台 + 就地设置。
//!
//! 状态列表：**六种蜜罐协议全部列出，每行一个**，统一格式显示
//! （协议名 / 端口 / 状态章 / 热切换按钮 / 配置按钮）。已配置的按真实 bind 状态
//! 显示「运行中 / 已停止」（配置里有 ≠ 真的在跑），未配置的显示「未配置」并提供添加。
//!
//! **热切换（0.5.12）**：行内「启动 / 停止」按钮即时生效——蜜罐句柄按期望状态
//! 摘下/重绑监听端口，无需重启；同时把 `ListenerConfig.enabled` 写回
//! config.toml 保持重启一致。按钮标签取真实运行态（绑定失败的行显示「启动」=重试）。
//! 名称/协议/端口的修改仍是「重启后生效」（结构变更不做热更），配置面板如实标注。
//!
//! 配置面板：点行内「配置」就地在下方展开，编辑该监听器的名称 / 协议 / 端口（即时保存）。
//! 假 Shell / 凭证采集 / 蜜饵 canary 是**全局节**（config 里不在 ListenerConfig 内），
//! 无法按协议挂到单行上，仍由下方对应分区就地编辑——这与配置结构一致，不是遗漏。
//!
//! 布局纪律（踩过的坑）：卡片内容一律走垂直堆叠 + `Label::wrap()`；
//! 换行标签放进 `horizontal`/`horizontal_wrapped` 会拿不到正确的可用宽度，
//! 被压成窄列并与相邻文字重叠。

use super::*;
use aisafeguard_core::config::ListenerConfig;

/// 行内按钮触发的即时动作：在遍历完成后再统一应用，
/// 避免"正拿着 draft 的可变借用时又要改 draft"。
enum ListenerAction {
    /// 一键开关某个已配置监听器（索引）
    Toggle(usize),
    /// 打开某个已配置监听器的配置面板（索引）
    OpenConfig(usize),
    /// 为某个未配置的协议新增监听器（kind 索引）
    Add(usize),
}

/// 各协议新增监听器时的默认端口（避开常见真实服务端口）
const KIND_DEFAULT_PORT: [u16; 6] = [2222, 8081, 2323, 1337, 3307, 6379];

impl AisafeApp {
    pub(crate) fn honeypot_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("蜜罐").size(type_scale::TITLE).strong());
        ui.add_space(space::M);

        // 与设置页共用同一份草稿：这里改、设置页看得到
        self.ensure_settings_draft();
        let status = self.cache.status.clone();
        let enabled = status.as_ref().map(|s| s.honeypot_enabled).unwrap_or(false);
        if !enabled {
            warn_banner(ui, "蜜罐功能已禁用——下方打开总开关并保存，重启后生效。");
        }
        let listeners = status
            .as_ref()
            .map(|s| s.listeners.clone())
            .unwrap_or_default();

        let hit_of = |name: &str| {
            self.cache
                .stats
                .per_listener
                .iter()
                .find(|p| p.listener == name)
                .map(|p| p.hits)
                .unwrap_or(0)
        };

        // ---------- 监听器状态列表：六协议全部列出，每行一个 ----------
        let running_n = listeners.iter().filter(|l| l.running && enabled).count();
        section(
            ui,
            format!(
                "监听器（运行中 {running_n} / 已配置 {} / 共 {} 种协议）",
                listeners.len(),
                LISTENER_KINDS.len()
            ),
        );
        let action = {
            let Some(draft) = self.settings_draft.as_ref() else {
                return;
            };
            listener_status_list(ui, &listeners, draft, enabled, &hit_of)
        };

        // ---------- 配置面板：点「配置」就地在下方展开 ----------
        ui.add_space(space::S);
        let panel_action = self.honeypot_config_panel(ui);

        ui.add_space(space::L);
        section(ui, "全局设置（改动需重启）");
        let Some(mut draft) = self.settings_draft.clone() else {
            return;
        };
        self.honeypot_shell_editor(ui, &mut draft);
        ui.add_space(space::M);
        self.honeypot_credentials_editor(ui, &mut draft);
        ui.add_space(space::M);
        self.honeypot_canary_editor(ui, &mut draft);
        ui.label(
            RichText::new(
                "低交互蜜罐对连接给出逼真假响应（SSH banner / HTTP 404 / Telnet 登录提示），\
绝不执行攻击者输入；「中交互」= 开启了假 Shell 命令仿真，逐命令留痕进事件。",
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );
        self.settings_draft = Some(draft);

        // ---------- 应用即时动作（一键开关 / 配置 / 新增） ----------
        let effective = panel_action.or(action);
        if let Some(act) = effective {
            self.apply_listener_action(act);
        }

        self.settings_footer(ui);
    }

    // ---------- 就地编辑器（与「设置 → 蜜罐」共用） ----------

    /// 监听表编辑器：启停/名称/协议/端口/增删行 + 基础格式校验（保存时）
    pub(crate) fn honeypot_listener_table(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, format!(
            "监听表（{} 行，改动需重启生效）",
            draft.honeypot.listeners.len()
        ));
        // 端口列文本缓冲与监听表行数对齐（增删行时同步维护，此处兜底重建）
        if self.settings_listener_ports.len() != draft.honeypot.listeners.len() {
            self.settings_listener_ports = draft
                .honeypot
                .listeners
                .iter()
                .map(|l| l.port.to_string())
                .collect();
        }
        let mut remove_idx: Option<usize> = None;
        // 列宽护栏：grid 的列宽只增不减（egui grid.rs 的 set_min_col_width 取 max），
        // 且默认 max_cell_size.x 为无穷——不显式设限时首帧会把列宽锁在一个偏小值上，
        // TextEdit 的 desired_width 会被 available_width 截断，表现为
        //「名称框比端口框还窄、telnet 被切成 telne」。
        // 关键字宽 = 勾选框 + 名称 + 协议 + 端口 + 删除，5 列。
        let cell_w = ((ui.available_width() - 4.0 * space::S) / 5.0).clamp(96.0, 170.0);
        egui::Grid::new("listener-table")
            .num_columns(5)
            .spacing([space::S, space::XS])
            // 下限保证名称框拿得到至少 cell_w；上限允许名称列（唯一长度不可控的字段）
            // 涨到两格但不再失控。
            .min_col_width(cell_w)
            .max_col_width(cell_w * 2.0)
            .show(ui, |ui| {
                for h in ["启用", "名称", "协议", "端口", ""] {
                    ui.label(caption(h).color(text_dim()));
                }
                ui.end_row();
                for (i, l) in draft.honeypot.listeners.iter_mut().enumerate() {
                    ui.checkbox(&mut l.enabled, "");
                    ui.add(
                        egui::TextEdit::singleline(&mut l.name)
                            .desired_width(cell_w.min(120.0)),
                    );
                    egui::ComboBox::from_id_salt(("listener-kind", i))
                        .selected_text(kind_display(&l.kind))
                        .show_ui(ui, |ui| {
                            for k in LISTENER_KINDS {
                                ui.selectable_value(&mut l.kind, k.to_string(), kind_display(k));
                            }
                        });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.settings_listener_ports[i])
                            .desired_width(56.0),
                    );
                    if ui.small_button("删除").clicked() {
                        remove_idx = Some(i);
                    }
                    ui.end_row();
                }
            });
        if let Some(i) = remove_idx {
            draft.honeypot.listeners.remove(i);
            self.settings_listener_ports.remove(i);
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("+ 添加监听器").clicked() {
                draft.honeypot.listeners.push(ListenerConfig {
                    name: "mysql".into(),
                    port: 3307,
                    kind: "mysql".into(),
                    enabled: true,
                });
                self.settings_listener_ports.push("3307".into());
            }
            ui.label(
                RichText::new("协议：SSH / HTTP / Telnet / Generic / MySQL / Redis；端口 1-65535 且不得重复。\
某一行绑定失败不影响其他监听器。")
                    .size(type_scale::CAPTION)
                    .color(text_dim()),
            );
        });
    }

    /// 假 Shell（中交互）编辑器
    pub(crate) fn honeypot_shell_editor(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "假 Shell（中交互，需重启）");
        egui::Grid::new("shell-settings")
            .num_columns(2)
            .spacing([14.0, space::S])
            .show(ui, |ui| {
                ui.label("SSH 假 Shell");
                ui.checkbox(
                    &mut draft.honeypot.shell.enabled,
                    "（默认关；开启后 ssh 监听器认证后进入命令仿真会话）",
                );
                ui.end_row();
                ui.label("Telnet 假 Shell");
                ui.checkbox(
                    &mut draft.honeypot.shell.telnet_enabled,
                    "（默认关；开启后 telnet 监听器进入命令仿真会话）",
                );
                ui.end_row();
                ui.label("假 Shell 用户名");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.honeypot.shell.username)
                        .desired_width(160.0)
                        .hint_text("deploy"),
                );
                ui.end_row();
                ui.label("假 Shell 主机名");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.honeypot.shell.hostname)
                        .desired_width(160.0)
                        .hint_text("debian-11"),
                );
                ui.end_row();
                ui.label("单会话命令上限");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_shell_max_cmds)
                        .desired_width(120.0),
                );
                ui.end_row();
            });
        ui.label(
            RichText::new(
                "假 Shell 永不执行真实命令：白名单命令返回仿真结果，逐命令留痕进事件；\
组合命令只解析首个，未知命令文案对齐真实 bash。",
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );
    }

    /// 凭证采集与喷洒检测编辑器
    pub(crate) fn honeypot_credentials_editor(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "凭证采集与喷洒检测（需重启）");
        ui.checkbox(
            &mut draft.honeypot.credentials.enabled,
            "启用（默认开）：蜜罐收到的用户名/口令对以加盐哈希入库，口令明文永不落盘",
        );
        ui.label(
            RichText::new(
                "当攻击者在蜜罐里试到与本机真实账号相同的用户名时，产生高严重度 \
「credential_spray」事件（自动封禁仍受内网保护与误报抑制约束）。\
快照刷新周期在 config.toml [honeypot.credentials].snapshot_interval_secs 配置。",
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );
    }

    /// 蜜饵 canary 编辑器
    pub(crate) fn honeypot_canary_editor(&mut self, ui: &mut egui::Ui, draft: &mut AppConfig) {
        section(ui, "蜜饵 canary（需重启）");
        ui.checkbox(
            &mut draft.honeypot.canary.enabled,
            "启用蜜饵（默认关）：HTTP 蜜罐内置 /backup.zip 等诱饵资源，下载行为即高价值事件",
        );
        ui.label(
            RichText::new(
                "诱饵内容带水印 token，外传后可用 `aisafeguard canary-decode <token>` 溯源来源节点与投放时间。\
水印密钥在 config.toml [honeypot.canary] 配置（空 = 自动生成）；文件系统蜜饵路径也在配置文件中设置（仅 Linux）。",
            )
            .size(type_scale::CAPTION)
            .color(text_dim()),
        );
    }
}

/// 监听器状态列表：**六种协议全部列出，每行一个**，统一格式。
///
/// 行格式：`协议名 | 监听器名 | 端口 | 状态章 | 开关/添加按钮 | 24h 触发`
/// 状态取自引擎的真实 bind 结果（`ListenerInfo.running`），配置里有 ≠ 真的在跑。
/// 未配置的协议也占一行，状态显示「未配置」，右侧给「+ 添加」。
fn listener_status_list(
    ui: &mut egui::Ui,
    listeners: &[crate::engine::ListenerInfo],
    draft: &AppConfig,
    honeypot_enabled: bool,
    hit_of: &dyn Fn(&str) -> i64,
) -> Option<ListenerAction> {
    let mut action: Option<ListenerAction> = None;
    // 表头：与下面每行的列顺序一一对应（协议 / 监听器 / 端口 / 状态 / 操作 / 24h）
    ui.horizontal(|ui| {
        for (h, w) in [
            ("协议", 86.0),
            ("监听器", 150.0),
            ("端口", 62.0),
            ("状态", 96.0),
            ("操作", 130.0),
            ("24h 触发", 84.0),
        ] {
            ui.allocate_ui_with_layout(
                egui::vec2(w, 0.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.label(caption(h).color(text_dim()));
                },
            );
        }
    });
    ui.add_space(space::XS);

    // 每个协议固定一行。**显示条数与任何宽度计算无关**——
    // 这里不做分栏/分块，杜绝"算出来的列数和实际渲染错位导致整条不渲染"。
    for (ki, kind) in LISTENER_KINDS.iter().enumerate() {
        let proto = kind_display(kind);
        let cfg_idx = draft.honeypot.listeners.iter().position(|l| l.kind == *kind);
        let info = cfg_idx.and_then(|i| {
            let name = &draft.honeypot.listeners[i].name;
            listeners.iter().find(|l| &l.name == name)
        });
        let cfg = cfg_idx.map(|i| &draft.honeypot.listeners[i]);

        Frame::new()
            .fill(bg_card())
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(10))
            .stroke(Stroke::new(1.0, border()))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    // ① 协议名（悬停给出该协议的用途）
                    ui.allocate_ui_with_layout(
                        egui::vec2(86.0, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.label(RichText::new(proto).size(type_scale::BODY).strong())
                                .on_hover_text(kind_pitch(kind));
                        },
                    );
                    // ② 监听器名（未配置时给引导文案）
                    ui.allocate_ui_with_layout(
                        egui::vec2(150.0, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| match cfg {
                            Some(l) => {
                                ui.label(RichText::new(&l.name).size(type_scale::BODY));
                            }
                            None => {
                                ui.label(
                                    RichText::new("未配置")
                                        .size(type_scale::BODY)
                                        .color(text_dim()),
                                );
                            }
                        },
                    );
                    // ③ 端口
                    ui.allocate_ui_with_layout(
                        egui::vec2(62.0, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| match cfg {
                            Some(c) => {
                                ui.label(
                                    RichText::new(format!("{}", c.port))
                                        .monospace()
                                        .size(type_scale::BODY),
                                );
                            }
                            None => {
                                ui.label(
                                    RichText::new(format!("{}", KIND_DEFAULT_PORT[ki]))
                                        .monospace()
                                        .size(type_scale::BODY)
                                        .color(text_dim()),
                                )
                                .on_hover_text("该协议的建议端口（添加后即使用此端口）");
                            }
                        },
                    );
                    // ④ 状态章：统一格式（圆点 + 文字），已配置一律以真实 bind 结果为准
                    ui.allocate_ui_with_layout(
                        egui::vec2(96.0, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            let (state, color) = match (cfg, info) {
                                (None, _) => ("○ 未配置".to_string(), text_dim()),
                                (Some(_), Some(l)) => {
                                    let (s, c) = running_state(l, honeypot_enabled);
                                    (format!("● {s}"), c)
                                }
                                (Some(_), None) => ("● 已停止".to_string(), text_dim()),
                            };
                            ui.label(
                                RichText::new(state).size(type_scale::CAPTION).color(color),
                            );
                        },
                    );
                    // ⑤ 操作：已配置给「热切换开关 + 配置」，未配置给「+ 添加」
                    ui.allocate_ui_with_layout(
                        egui::vec2(130.0, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| match cfg_idx {
                            Some(i) => {
                                // 热切换（0.5.12）：按钮按真实 bind 状态显示目标动作——
                                // 运行中给「停止」，否则（含绑定失败重试）给「启动」
                                let running_now = info
                                    .map(|l| l.running && honeypot_enabled)
                                    .unwrap_or(false);
                                let label = if running_now { "停止" } else { "启动" };
                                if ui
                                    .button(label)
                                    .on_hover_text("热切换：立即生效，并写入 config.toml 保持一致")
                                    .clicked()
                                {
                                    action = Some(ListenerAction::Toggle(i));
                                }
                                if ui.button("配置").clicked() {
                                    action = Some(ListenerAction::OpenConfig(i));
                                }
                            }
                            None => {
                                if ui.button("+ 添加").clicked() {
                                    action = Some(ListenerAction::Add(ki));
                                }
                            }
                        },
                    );
                    // ⑥ 24h 触发计数
                    ui.allocate_ui_with_layout(
                        egui::vec2(84.0, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            if let Some(l) = cfg {
                                ui.label(
                                    RichText::new(format!("{}", hit_of(&l.name)))
                                        .size(type_scale::CAPTION)
                                        .color(text_dim()),
                                );
                            }
                        },
                    );
                });
            });
        ui.add_space(space::XS);
    }
    action
}

/// 状态判定：以引擎的真实 bind 结果为准，「配置里有」≠「真的在跑」。
fn running_state(l: &crate::engine::ListenerInfo, honeypot_enabled: bool) -> (&'static str, Color32) {
    if l.mode == "未启用" {
        ("未启用", text_dim())
    } else if l.running && honeypot_enabled {
        ("运行中", ok())
    } else if honeypot_enabled {
        ("已停止", warn())
    } else {
        ("已停止", text_dim())
    }
}

impl AisafeApp {
    /// 就地配置面板：编辑某个已配置监听器的名称 / 协议 / 端口。
    ///
    /// 只覆盖 `ListenerConfig` 里真实存在的字段——假 Shell、凭证采集、蜜饵 canary 在
    /// config 里是全局节，无法按协议归属到单个监听器，因此不放进来（下方分区就地编辑）。
    fn honeypot_config_panel(&mut self, ui: &mut egui::Ui) -> Option<ListenerAction> {
        let idx = self.hp_config_open?;
        let cfg = self.eng.config().unwrap_or_default();
        let total = cfg.honeypot.listeners.len();
        if idx >= total {
            self.hp_config_open = None;
            return None;
        }
        let cur = cfg.honeypot.listeners[idx].clone();
        if self.hp_name_buf.is_empty() {
        self.hp_name_buf = cur.name.clone();
    }

    let mut action: Option<ListenerAction> = None;
    Frame::new()
        .fill(bg_card())
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(14))
        .stroke(Stroke::new(1.0, border()))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("配置：{}", kind_display(&cur.kind)))
                        .size(type_scale::SECTION)
                        .strong(),
                );
                chip(ui, "重启后生效", warn());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("收起").clicked() {
                        action = Some(ListenerAction::OpenConfig(usize::MAX));
                    }
                });
            });
            ui.add_space(space::S);

            // 名称 / 协议 / 端口：每行一个字段，避免横向布局里换行标签拿不到宽度
            ui.horizontal(|ui| {
                ui.label(caption("名称").color(text_dim()));
                ui.add(
                    egui::TextEdit::singleline(&mut self.hp_name_buf).desired_width(180.0),
                );
            });
            let kinds: Vec<String> = LISTENER_KINDS.iter().map(|k| (*k).to_string()).collect();
            let mut kind = cur.kind.clone();
            ui.horizontal(|ui| {
                ui.label(caption("协议").color(text_dim()));
                egui::ComboBox::from_id_salt("hp-config-kind")
                    .selected_text(kind_display(&kind))
                    .show_ui(ui, |ui| {
                        for k in &kinds {
                            ui.selectable_value(&mut kind, k.clone(), kind_display(k));
                        }
                    });
            });
            ui.horizontal(|ui| {
                ui.label(caption("端口").color(text_dim()));
                ui.add(
                    egui::TextEdit::singleline(&mut self.hp_port_buf).desired_width(80.0),
                );
                if ui.button("保存该监听器").clicked() {
                    match self.hp_save_edits(idx, &kind) {
                        Ok(()) => {
                            self.hp_config_open = None;
                            self.hp_name_buf.clear();
                        }
                        Err(msg) => self.set_toast(msg),
                    }
                }
            });
            ui.add_space(space::XS);
            ui.label(
                RichText::new(
                    "协议专属设置：SSH/Telnet 的假 Shell 开关与伪装用户名/主机名、\
凭证采集、蜜饵 canary 都在下方对应分区——它们在配置里是全局节，不随单个监听器走。",
                )
                .size(type_scale::CAPTION)
                .color(text_dim()),
            );
        });
        action
    }
}

/// 应用行内按钮的即时动作：均只改监听表并立即保存。
impl AisafeApp {
    fn apply_listener_action(&mut self, act: ListenerAction) {
        match act {
            ListenerAction::OpenConfig(i) => {
                if i == usize::MAX {
                    self.hp_config_open = None;
                } else {
                    self.hp_config_open = Some(i);
                    // 用已保存配置的现值填缓冲区，避免拖入上一次编辑的残留
                    if let Ok(cfg) = self.eng.config()
                        && let Some(l) = cfg.honeypot.listeners.get(i)
                    {
                        self.hp_name_buf = l.name.clone();
                        self.hp_port_buf = l.port.to_string();
                    }
                }
            }
            ListenerAction::Add(ki) => {
                let Some(draft) = self.settings_draft.as_mut() else {
                    return;
                };
                let kind = LISTENER_KINDS[ki];
                draft.honeypot.listeners.push(ListenerConfig {
                    name: kind.to_string(),
                    port: KIND_DEFAULT_PORT[ki],
                    kind: kind.to_string(),
                    enabled: true,
                });
                let idx = draft.honeypot.listeners.len() - 1;
                let draft = draft.clone();
                match self.eng.save_config(draft) {
                    Ok(()) => {
                        // 已写入配置后尝试立即热启动（失败不回滚——重启后会按配置自动尝试）
                        match self.eng.toggle_listener(kind, true) {
                            Ok(()) => self.set_toast(format!(
                                "已添加 {} 监听器（端口 {}）并立即启动",
                                kind_display(kind),
                                KIND_DEFAULT_PORT[ki]
                            )),
                            Err(e) => self.set_toast(format!(
                                "已添加 {} 监听器（端口 {}）；立即启动未成功: {e}（重启后自动尝试）",
                                kind_display(kind),
                                KIND_DEFAULT_PORT[ki]
                            )),
                        }
                        self.refresh_cache();
                        self.hp_config_open = Some(idx);
                    }
                    Err(e) => self.set_toast(format!("添加失败: {e}")),
                }
            }
            ListenerAction::Toggle(i) => {
                // 热切换（0.5.12）：目标状态取自引擎真实运行态——运行中→停止，
                // 否则（含绑定失败重试）→启动。即时生效，同时把 enabled 写回配置。
                let name = match self
                    .settings_draft
                    .as_ref()
                    .and_then(|d| d.honeypot.listeners.get(i))
                {
                    Some(l) => l.name.clone(),
                    None => return,
                };
                let target = !self
                    .cache
                    .status
                    .as_ref()
                    .and_then(|s| {
                        s.listeners
                            .iter()
                            .find(|x| x.name == name)
                            .map(|x| x.running && s.honeypot_enabled)
                    })
                    .unwrap_or(false);
                match self.eng.toggle_listener(&name, target) {
                    Ok(()) => {
                        // 草稿同步：避免设置页保存时把热切换结果翻回去
                        if let Some(row) = self
                            .settings_draft
                            .as_mut()
                            .and_then(|d| d.honeypot.listeners.get_mut(i))
                        {
                            row.enabled = target;
                        }
                        self.set_toast(format!(
                            "蜜罐「{name}」已热{}（即时生效，已写入配置）",
                            if target { "启动" } else { "停止" }
                        ));
                        self.refresh_cache();
                    }
                    Err(e) => self.set_toast(format!("热切换失败: {e}")),
                }
            }
        }
    }

    /// 保存配置面板的名称/协议/端口（只校验监听表，不牵连其它页的输入框）。
    fn hp_save_edits(&mut self, idx: usize, kind: &str) -> Result<(), String> {
        let Some(draft) = self.settings_draft.as_mut() else {
            return Err("配置草稿未就绪".into());
        };
        if idx >= draft.honeypot.listeners.len() {
            return Err("监听器已不存在".into());
        }
        let port: u16 = self
            .hp_port_buf
            .trim()
            .parse()
            .map_err(|_| "端口非法（需 1-65535）".to_string())?;
        if port == 0 {
            return Err("端口非法（需 1-65535）".into());
        }
        let name = self.hp_name_buf.trim().to_string();
        if name.is_empty() {
            return Err("监听器名称不能为空".into());
        }
        // 端口去重（与设置页监听表同一规则）
        if draft
            .honeypot
            .listeners
            .iter()
            .enumerate()
            .any(|(j, l)| j != idx && l.port == port)
        {
            return Err(format!("端口 {port} 已被其它监听器占用"));
        }
        {
            let l = &mut draft.honeypot.listeners[idx];
            l.name = name.clone();
            l.kind = kind.to_string();
            l.port = port;
        }
        let cfg = draft.clone();
        self.eng
            .save_config(cfg)
            .map_err(|e| format!("保存失败: {e}"))?;
        self.set_toast(format!(
            "监听器「{name}」已保存（{} / {port}）；重启程序后生效",
            kind_display(kind)
        ));
        Ok(())
    }
}

/// 未配置协议的一句能力介绍（让「还有哪些蜜罐可用」自解释）
fn kind_pitch(kind: &str) -> &'static str {
    match kind {
        "ssh" => "SSH 假服务：抓爆破与漏洞扫描",
        "http" => "HTTP 假站点：抓 Web 探测与蜜饵下载",
        "telnet" => "Telnet 假服务：抓弱口令爆破",
        "generic" => "通用 TCP 记录器：抓任意端口探测",
        "mysql" => "MySQL 蜜罐：抓数据库爆破与僵尸网络",
        "redis" => "Redis 蜜罐：抓未授权访问与写命令",
        _ => "",
    }
}
