//! 蜜罐页（0.5.12 重构）：运行状态卡片 + 就地设置。
//!
//! 卡片区：所有可用蜜罐（六协议）都可见——已配置的显示真实运行状态
//! （bind 成功才算「运行中」），未配置的协议显示占位卡引导添加；
//! 布局用 Grid 固定两列等宽，窄窗口不再出现第二张卡被裁切的问题。
//! 编辑区：监听表 / 假 Shell / 凭证采集 / 蜜饵全部就地可改，与「设置 → 蜜罐」
//! 共用同一份草稿与保存流程（改了不保存不生效，保存后按需重启）。

use super::*;
use aisafeguard_core::config::ListenerConfig;

/// 卡片内容宽度（Frame 内边距 14×2 在外层另加）
const CARD_INNER_W: f32 = 250.0;

impl AisafeApp {
    pub(crate) fn honeypot_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("蜜罐").size(type_scale::TITLE).strong());
        ui.add_space(space::M);

        // 与设置页共用同一份草稿：这里改、设置页看得到；保存走同一流程
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

        // ---------- 运行状态卡片：六协议全部可见 ----------
        section(
            ui,
            format!(
                "监听器（运行中 {} / 配置 {}）",
                listeners.iter().filter(|l| l.running).count(),
                listeners.len()
            ),
        );
        let hit_of = |name: &str| {
            self.cache
                .stats
                .per_listener
                .iter()
                .find(|p| p.listener == name)
                .map(|p| p.hits)
                .unwrap_or(0)
        };
        listener_cards(ui, &listeners, enabled, hit_of);

        ui.add_space(space::L);
        section(ui, "设置（改动保存后按提示重启生效）");
        let Some(mut draft) = self.settings_draft.clone() else {
            return;
        };
        self.honeypot_listener_table(ui, &mut draft);
        ui.add_space(space::M);
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
        egui::Grid::new("listener-table")
            .num_columns(6)
            .spacing([10.0, space::XS])
            .show(ui, |ui| {
                for h in ["启用", "名称", "协议", "端口", ""] {
                    ui.label(caption(h).color(text_dim()));
                }
                ui.end_row();
                for (i, l) in draft.honeypot.listeners.iter_mut().enumerate() {
                    ui.checkbox(&mut l.enabled, "");
                    ui.add(egui::TextEdit::singleline(&mut l.name).desired_width(90.0));
                    egui::ComboBox::from_id_salt(("listener-kind", i))
                        .selected_text(kind_display(&l.kind))
                        .show_ui(ui, |ui| {
                            for k in LISTENER_KINDS {
                                ui.selectable_value(&mut l.kind, k.to_string(), kind_display(k));
                            }
                        });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.settings_listener_ports[i])
                            .desired_width(70.0),
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

/// 运行状态卡片区：六协议全部可见（未配置的协议出占位卡），两列等宽 Grid。
fn listener_cards(
    ui: &mut egui::Ui,
    listeners: &[crate::engine::ListenerInfo],
    enabled: bool,
    hit_of: impl Fn(&str) -> i64,
) {
    let gap = space::M;
    let avail = ui.available_width();
    // 卡片外宽 = 内容 + Frame 内边距 14×2；两列 + 列间距恰占满一行
    let card_w = ((avail - gap) / 2.0).max(CARD_INNER_W + 28.0);
    let content_w = card_w - 28.0;

    // 已配置监听器 + 未配置协议的占位卡
    let mut cards: Vec<Card> = listeners
        .iter()
        .map(|l| Card::Configured(l.clone()))
        .collect();
    for kind in LISTENER_KINDS {
        if !listeners.iter().any(|l| l.kind == kind) {
            cards.push(Card::Placeholder(kind));
        }
    }

    egui::Grid::new("listener-cards")
        .num_columns(2)
        .spacing([gap, space::S])
        .min_col_width(card_w)
        .show(ui, |ui| {
            for pair in cards.chunks(2) {
                for card in pair {
                    Frame::new()
                        .fill(bg_card())
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::same(14))
                        .stroke(Stroke::new(1.0, border()))
                        .show(ui, |ui| {
                            ui.set_width(content_w);
                            match card {
                                Card::Configured(l) => configured_card(ui, l, enabled, &hit_of),
                                Card::Placeholder(kind) => placeholder_card(ui, kind),
                            }
                        });
                }
                if pair.len() == 1 {
                    ui.label("");
                }
                ui.end_row();
            }
        });
    if listeners.is_empty() {
        ui.label(
            RichText::new("尚未配置任何监听器——在下方「监听表」添加并保存，重启生效。")
                .size(type_scale::CAPTION)
                .color(text_dim()),
        );
    }
}

enum Card {
    Configured(crate::engine::ListenerInfo),
    Placeholder(&'static str),
}

fn configured_card(
    ui: &mut egui::Ui,
    l: &crate::engine::ListenerInfo,
    honeypot_enabled: bool,
    hit_of: &dyn Fn(&str) -> i64,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(&l.name).size(type_scale::SECTION).strong());
        chip(ui, &l.kind, accent());
        // 交互模式（H150）：banner 级还是假 Shell，界面上可见
        chip(
            ui,
            &l.mode,
            if l.mode == "中交互" { purple() } else { text_dim() },
        );
    });
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(":{l}", l = l.port))
                .monospace()
                .size(type_scale::BODY)
                .color(text_dim()),
        );
        // 状态章以真实 bind 状态为准（0.5.12）：配置里有 ≠ 真的在跑
        let (running, color) = if l.mode == "未启用" {
            ("未启用", text_dim())
        } else if l.running && honeypot_enabled {
            ("运行中", ok())
        } else if honeypot_enabled {
            ("已停止", warn())
        } else {
            ("已停止", text_dim())
        };
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(format!("● {running}")).size(type_scale::CAPTION).color(color));
        });
    });
    let hint = if l.mode != "未启用" && honeypot_enabled && !l.running {
        "已停止：端口可能被占用，或刚保存配置待重启".to_string()
    } else {
        String::new()
    };
    ui.horizontal(|ui| {
        if !hint.is_empty() {
            ui.label(RichText::new(hint).size(type_scale::CAPTION).color(warn()));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!("24h 触发 {}", hit_of(&l.name)))
                    .size(type_scale::CAPTION)
                    .color(text_dim()),
            );
        });
    });
}

fn placeholder_card(ui: &mut egui::Ui, kind: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(kind_display(kind)).size(type_scale::SECTION).color(text_dim()));
        chip(ui, "未配置", text_dim());
    });
    ui.label(
        RichText::new(kind_pitch(kind))
            .size(type_scale::CAPTION)
            .color(text_dim()),
    );
    ui.label(
        RichText::new("在下方监听表添加，保存后重启生效")
            .size(type_scale::CAPTION)
            .color(text_dim()),
    );
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
