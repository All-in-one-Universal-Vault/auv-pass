// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! DOS 风全屏绘制:蓝色面板/反色高亮/双线边框/底部键位栏。

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Form, Screen};
use auv_i18n::{auv_i18n_tr, auv_i18n_tr_fmt};

// Tokyo Night 系配色(低亮度不刺眼);RGB 真彩,现代终端原生支持。
const BG: Color = Color::Rgb(0x1a, 0x1b, 0x26); // 深空蓝黑底
const FG: Color = Color::Rgb(0xc0, 0xca, 0xf5); // 柔雾白
const SEL_BG: Color = Color::Rgb(0x7a, 0xa2, 0xf7); // 选中条:柔蓝
const SEL_FG: Color = Color::Rgb(0x16, 0x16, 0x1e);
const HI: Color = Color::Rgb(0xe0, 0xaf, 0x68); // 琥珀:键位/标题点缀
const DIM_FG: Color = Color::Rgb(0x56, 0x5f, 0x89); // 灰蓝:次要文字
const BAR_BG: Color = Color::Rgb(0x29, 0x2e, 0x42); // 标题/状态栏底
const BAR_FG: Color = Color::Rgb(0x7d, 0xcf, 0xff); // 柔青
const BORDER_ACTIVE: Color = Color::Rgb(0x7a, 0xa2, 0xf7);
const BORDER_IDLE: Color = Color::Rgb(0x3b, 0x42, 0x61);

fn base() -> Style {
    Style::new().bg(BG).fg(FG)
}

fn dim() -> Style {
    Style::new().bg(BG).fg(DIM_FG)
}

fn bar() -> Style {
    Style::new().bg(BAR_BG).fg(BAR_FG)
}

fn panel(active: bool) -> Block<'static> {
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Double)
        .style(base());
    if active {
        b.border_style(Style::new().fg(BORDER_ACTIVE).bg(BG))
    } else {
        b.border_style(Style::new().fg(BORDER_IDLE).bg(BG))
    }
}

pub fn draw(app: &mut App, f: &mut Frame) {
    let under_main = app.session.is_some()
        || matches!(
            app.screen,
            Screen::Main
                | Screen::Detail
                | Screen::History
                | Screen::Snapshot(_)
                | Screen::ConfirmDelete(_)
        );
    if under_main {
        draw_main(app, f);
    } else {
        draw_home(app, f);
    }
    match &app.screen {
        Screen::Detail => draw_detail(app, f),
        Screen::History => draw_history(app, f),
        Screen::Snapshot(i) => draw_snapshot(app, *i, f),
        Screen::Form(form) => draw_form(form, f),
        Screen::Message(msg) => draw_message(msg, f),
        Screen::ConfirmDelete(_) => draw_confirm(f),
        Screen::SshKeys => draw_ssh_keys(app, f),
        Screen::AgentConfirm => draw_agent_confirm(app, f),
        _ => {}
    }
}

// ===================== 首页 =====================

fn draw_home(app: &App, f: &mut Frame) {
    let area = f.area();
    f.render_widget(Clear, area);
    let bg = Block::default().style(base());
    f.render_widget(bg, area);

    let mid = centered(area, 44, 15);
    // 品牌口号(中英双行固定显示,不随语言切换)
    let slogan_area = Rect {
        x: mid.x,
        y: mid.y,
        width: mid.width,
        height: 3,
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::styled("  Keep dark. Stay light.", dim()),
            Line::styled("  守之以暗，行之以轻", dim()),
        ]),
        slogan_area,
    );
    let menu_area = Rect {
        x: mid.x,
        y: mid.y + 3,
        width: mid.width,
        height: mid.height - 3,
    };
    let block = panel(true).title(Span::styled(
        format!(" auv-pass {} ", env!("CARGO_PKG_VERSION")),
        Style::new().fg(HI).bg(BG).bold(),
    ));
    let items: Vec<ListItem> = [
        auv_i18n_tr("menu-open-vault"),
        auv_i18n_tr("menu-new-vault"),
        auv_i18n_tr("menu-password-generator"),
        auv_i18n_tr("btn-quit"),
    ]
    .iter()
    .enumerate()
    .map(|(i, t)| {
        if i == app.home_sel {
            ListItem::new(Line::styled(format!(" ▸ {t} "), sel_style()))
        } else {
            ListItem::new(Line::styled(format!("   {t} "), base()))
        }
    })
    .collect();
    let list = List::new(items).block(block).style(base());
    f.render_widget(list, menu_area);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::new().fg(HI)),
        Span::raw(auv_i18n_tr("panel-select")),
        Span::styled("Enter", Style::new().fg(HI)),
        Span::raw(auv_i18n_tr("panel-confirm")),
        Span::styled("q/Ctrl+C", Style::new().fg(HI)),
        Span::raw(auv_i18n_tr("menu-quit")),
    ]))
    .style(base())
    .alignment(ratatui::layout::Alignment::Center);
    let h = Rect {
        x: mid.x,
        y: mid.bottom(),
        width: mid.width,
        height: 1,
    };
    f.render_widget(hint, h);
}

fn sel_style() -> Style {
    Style::new().bg(SEL_BG).fg(SEL_FG).bold()
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}

// ===================== 主屏(双栏) =====================

fn draw_main(app: &mut App, f: &mut Frame) {
    let area = f.area();
    f.render_widget(Clear, area);
    f.render_widget(Block::default().style(base()), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(7), // 底部详情预览(对齐 GUI 布局)
            Constraint::Length(1),
        ])
        .split(area);

    // 标题栏
    let title = {
        let s = app.session.as_ref();
        auv_i18n_tr_fmt(
            "status-title-bar",
            &[
                (
                    "path",
                    &s.map(|s| s.path.display().to_string()).unwrap_or_default(),
                ),
                (
                    "count",
                    &s.map(|s| s.vault.entry_count()).unwrap_or(0).to_string(),
                ),
                (
                    "time",
                    &chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
                ),
            ],
        )
    };
    f.render_widget(Paragraph::new(title).style(bar()), rows[0]);

    // 双栏
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(32), Constraint::Percentage(68)])
        .split(rows[1]);

    // 组列表
    let gnames = app.group_names();
    let gitems: Vec<ListItem> = gnames
        .iter()
        .map(|g| ListItem::new(Line::styled(format!(" {g} "), base())))
        .collect();
    let glist = List::new(gitems)
        .block(panel(app.panel == crate::app::Panel::Groups).title(auv_i18n_tr("panel-groups")))
        .highlight_style(sel_style())
        .style(base());
    f.render_stateful_widget(glist, cols[0], &mut app.groups);

    // 条目列表
    let ids = app.visible_entry_ids();
    let s = app.session.as_ref();
    let eitems: Vec<ListItem> = ids
        .iter()
        .filter_map(|id| s.and_then(|s| s.vault.get_entry(*id)))
        .map(|e| {
            let totp = if e.totp.is_some() { " 🔑" } else { "" };
            ListItem::new(Line::styled(
                format!(" {} │ {}{}", e.title, e.username, totp),
                base(),
            ))
        })
        .collect();
    let etitle = if app.search_active {
        auv_i18n_tr_fmt("panel-search-results", &[("count", &ids.len().to_string())])
    } else {
        auv_i18n_tr("panel-entries").to_string()
    };
    let elist = List::new(eitems)
        .block(panel(app.panel == crate::app::Panel::Entries).title(etitle))
        .highlight_style(sel_style())
        .style(base());
    f.render_stateful_widget(elist, cols[1], &mut app.entries);

    // 底部详情预览(对齐 GUI;Enter 仍可全屏)
    if let Some(e) = app.selected_entry() {
        let pw_disp = if app.show_plain {
            e.password.as_str().to_string()
        } else {
            "********".to_string()
        };
        let totp_disp = e
            .totp
            .as_ref()
            .and_then(|c| {
                auv_pass_engine::auv_pass_totp_generate(
                    c,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0),
                )
                .ok()
            })
            .map(|c| format!("TOTP:{c}"))
            .unwrap_or_default();
        let detail_lines = vec![
            Line::styled(
                format!(" {} │ {} │ {}", e.title, e.username, pw_disp),
                base(),
            ),
            Line::styled(
                auv_i18n_tr_fmt(
                    "status-preview-modified",
                    &[
                        (
                            "url",
                            &if e.url.is_empty() {
                                "-".to_string()
                            } else {
                                e.url.clone()
                            },
                        ),
                        ("modified", &e.modified.to_string()),
                    ],
                ),
                dim(),
            ),
            Line::styled(
                auv_i18n_tr_fmt("status-preview-hintbar", &[("totp", &totp_disp)]),
                dim(),
            ),
        ];
        f.render_widget(
            Paragraph::new(detail_lines).block(panel(false).title(auv_i18n_tr("panel-detail"))),
            rows[2],
        );
    } else {
        f.render_widget(
            Paragraph::new(auv_i18n_tr("status-detail-empty"))
                .block(panel(false).title(auv_i18n_tr("panel-detail"))),
            rows[2],
        );
    }

    // 状态栏(布局第 4 行;此前误画到 rows[2],盖住详情预览首行,rows[3] 从未绘制)
    let hint = auv_i18n_tr("status-main-hintbar");
    f.render_widget(
        Paragraph::new(hint).style(bar()).wrap(Wrap { trim: false }),
        rows[3],
    );
}

// ===================== 弹窗 =====================

fn draw_detail(app: &App, f: &mut Frame) {
    let Some(e) = app.selected_entry() else {
        return;
    };
    let area = centered(f.area(), 62, 14);
    f.render_widget(Clear, area);
    let block = panel(true).title(Span::styled(
        format!(" {} ", e.title),
        Style::new().fg(HI).bg(BG).bold(),
    ));

    let pw = if app.show_plain {
        e.password.as_str().to_string()
    } else {
        "********".to_string()
    };
    let lines = vec![
        line_kv(
            auv_i18n_tr("label-group"),
            &if e.group.is_empty() {
                auv_i18n_tr("group-root-paren")
            } else {
                e.group.clone()
            },
        ),
        line_kv(auv_i18n_tr("label-username"), &e.username),
        line_kv(auv_i18n_tr("label-password"), &pw),
        line_kv(
            "URL",
            &if e.url.is_empty() {
                "-".into()
            } else {
                e.url.clone()
            },
        ),
        line_kv(
            auv_i18n_tr("label-notes"),
            &if e.notes.is_empty() {
                "-".into()
            } else {
                e.notes.clone()
            },
        ),
        line_kv(
            auv_i18n_tr("label-modified"),
            crate::app::fmt_time(e.modified),
        ),
        Line::styled(
            auv_i18n_tr_fmt(
                "status-detail-meta",
                &[
                    ("count", &e.history.len().to_string()),
                    (
                        "totp",
                        &if e.totp.is_some() {
                            auv_i18n_tr("msg-configured")
                        } else {
                            auv_i18n_tr("none")
                        },
                    ),
                ],
            ),
            dim(),
        ),
        Line::styled(
            auv_i18n_tr("status-detail-hintbar"),
            Style::new().fg(HI).bg(BG),
        ),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .style(base())
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_history(app: &App, f: &mut Frame) {
    let Some(e) = app.selected_entry() else {
        return;
    };
    let area = centered(f.area(), 62, 12);
    f.render_widget(Clear, area);
    let block = panel(true).title(Span::styled(
        auv_i18n_tr_fmt("panel-history", &[("count", &e.title)]),
        Style::new().fg(HI).bg(BG).bold(),
    ));
    if e.history.is_empty() {
        f.render_widget(
            Paragraph::new(auv_i18n_tr("status-no-history"))
                .block(block)
                .style(base()),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = e
        .history
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let style = if i == app.hist_sel {
                sel_style()
            } else {
                base()
            };
            ListItem::new(Line::styled(
                format!(
                    " {} │ {} ({})",
                    crate::app::fmt_time(s.saved_at),
                    s.title,
                    s.username
                ),
                style,
            ))
        })
        .collect();
    let mut ls = ListState::default();
    ls.select(Some(app.hist_sel));
    f.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(sel_style())
            .style(base()),
        area,
        &mut ls,
    );
}

fn draw_snapshot(app: &App, i: usize, f: &mut Frame) {
    let Some(e) = app.selected_entry() else {
        return;
    };
    let Some(s) = e.history.get(i) else { return };
    let area = centered(f.area(), 62, 11);
    f.render_widget(Clear, area);
    let block = panel(true).title(Span::styled(
        auv_i18n_tr_fmt(
            "panel-history-snapshot",
            &[("time", &crate::app::fmt_time(s.saved_at))],
        ),
        Style::new().fg(HI).bg(BG).bold(),
    ));
    let lines = vec![
        line_kv(auv_i18n_tr("label-title"), &s.title),
        line_kv(auv_i18n_tr("label-username"), &s.username),
        line_kv(
            auv_i18n_tr("label-password"),
            auv_i18n_tr("label-password-masked"),
        ),
        line_kv(
            "URL",
            &if s.url.is_empty() {
                "-".into()
            } else {
                s.url.clone()
            },
        ),
        line_kv(
            auv_i18n_tr("label-notes"),
            &if s.notes.is_empty() {
                "-".into()
            } else {
                s.notes.clone()
            },
        ),
        Line::styled(auv_i18n_tr("status-copy-esc"), Style::new().fg(HI).bg(BG)),
    ];
    f.render_widget(Paragraph::new(lines).block(block).style(base()), area);
}

fn draw_form(form: &Form, f: &mut Frame) {
    let h = (form.fields.len() as u16 + 6).min(f.area().height.saturating_sub(2));
    let area = centered(f.area(), 64, h);
    f.render_widget(Clear, area);
    let block = panel(true).title(Span::styled(
        format!(" {} ", form.title),
        Style::new().fg(HI).bg(BG).bold(),
    ));

    let mut lines: Vec<Line> = Vec::new();
    for (i, fd) in form.fields.iter().enumerate() {
        let shown = if fd.secret {
            "*".repeat(fd.value.chars().count())
        } else {
            fd.value.clone()
        };
        let marker = if i == form.selected { "▶" } else { " " };
        let style = if i == form.selected {
            Style::new().bg(SEL_BG).fg(SEL_FG).bold()
        } else {
            base()
        };
        lines.push(Line::styled(
            format!(" {marker} {:<10}: {}", fd.label, shown),
            style,
        ));
        if !fd.note.is_empty() {
            lines.push(Line::styled(format!("      └ {}", fd.note), dim()));
        }
    }
    if let Some((pw, bits)) = &form.gen_result {
        lines.push(Line::styled(
            auv_i18n_tr_fmt(
                "msg-generated-bits",
                &[("password", &pw.clone()), ("bits", &format!("{bits:.0}"))],
            ),
            Style::new().bg(BG).fg(HI),
        ));
        lines.push(Line::styled(auv_i18n_tr("status-copy-hint"), dim()));
    }
    lines.push(Line::styled(
        auv_i18n_tr("status-form-hintbar"),
        Style::new().fg(HI).bg(BG),
    ));
    f.render_widget(Paragraph::new(lines).block(block).style(base()), area);
}

fn draw_message(msg: &str, f: &mut Frame) {
    let area = centered(f.area(), 52, 8);
    f.render_widget(Clear, area);
    let block = panel(true).title(Span::styled(
        auv_i18n_tr("panel-message"),
        Style::new().fg(HI).bg(BG).bold(),
    ));
    let lines = vec![
        Line::styled(format!(" {msg} "), base()),
        Line::styled("", base()),
        Line::styled(
            auv_i18n_tr("status-press-any-key"),
            Style::new().fg(HI).bg(BG),
        ),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .style(base())
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_confirm(f: &mut Frame) {
    let area = centered(f.area(), 46, 6);
    f.render_widget(Clear, area);
    let block = panel(true).title(Span::styled(
        auv_i18n_tr("panel-confirm-delete"),
        Style::new().fg(HI).bg(BG).bold(),
    ));
    let lines = vec![
        Line::styled(
            auv_i18n_tr("status-delete-this-entry-history-included"),
            base(),
        ),
        Line::styled(
            auv_i18n_tr("status-delete-hintbar"),
            Style::new().fg(HI).bg(BG),
        ),
    ];
    f.render_widget(Paragraph::new(lines).block(block).style(base()), area);
}

// ===================== SSH 钥匙管理屏 =====================

fn draw_ssh_keys(app: &mut App, f: &mut Frame) {
    let area = f.area();
    f.render_widget(Clear, area);
    f.render_widget(Block::default().style(base()), area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    let agent_status = match &app.agent {
        Some(b) => auv_i18n_tr_fmt("status-agent-running", &[("socket", &b.handle.socket)]),
        None => auv_i18n_tr("status-agent-stopped").to_string(),
    };
    let title = auv_i18n_tr_fmt("panel-ssh-keys-status", &[("status", &agent_status)]);
    f.render_widget(Paragraph::new(title).style(bar()), rows[0]);

    let Some(s) = &app.session else { return };
    let items: Vec<ListItem> = s
        .vault
        .ssh_keys()
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let style = if i == app.ssh_sel {
                sel_style()
            } else {
                base()
            };
            let on_duty = if k.exposed {
                auv_i18n_tr("tag-exposed")
            } else {
                auv_i18n_tr("tag-hidden")
            };
            ListItem::new(Line::styled(
                format!(
                    " {on_duty} {} │ {}",
                    k.name,
                    auv_pass_engine::auv_pass_ssh_fingerprint_hex(k)
                ),
                style,
            ))
        })
        .collect();
    let list = List::new(items)
        .block(panel(true).title(auv_i18n_tr("panel-ssh-keys")))
        .highlight_style(sel_style())
        .style(base());
    let mut ls = ListState::default();
    ls.select(Some(app.ssh_sel));
    f.render_stateful_widget(list, rows[1], &mut ls);

    let hint = auv_i18n_tr("status-keys-hintbar");
    f.render_widget(Paragraph::new(hint).style(bar()), rows[2]);
}

fn draw_agent_confirm(app: &App, f: &mut Frame) {
    let area = centered(f.area(), 56, 7);
    f.render_widget(Clear, area);
    let block = panel(true).title(Span::styled(
        auv_i18n_tr("panel-sign-request"),
        Style::new().fg(HI).bg(BG).bold(),
    ));
    let name = app
        .pending_confirm
        .as_ref()
        .map(|r| r.key_name.clone())
        .unwrap_or_default();
    let lines = vec![
        Line::styled(
            auv_i18n_tr_fmt("dialog-sign-request-body", &[("name", &name)]),
            base(),
        ),
        Line::styled("", base()),
        Line::styled(
            auv_i18n_tr("status-confirm-hintbar"),
            Style::new().fg(HI).bg(BG),
        ),
    ];
    f.render_widget(Paragraph::new(lines).block(block).style(base()), area);
}

fn line_kv(k: impl AsRef<str>, v: impl AsRef<str>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {:<8}: ", k.as_ref()), Style::new().fg(HI).bg(BG)),
        Span::styled(v.as_ref().to_string(), base()),
    ])
}
