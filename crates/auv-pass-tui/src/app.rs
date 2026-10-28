// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 全屏应用状态机与事件循环(绘制在 ui.rs)。

use chrono::TimeZone as _;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::ListState;
use zeroize::Zeroizing;

use crate::Session;

use auv_i18n::{auv_i18n_lang, auv_i18n_lang_toggle, auv_i18n_tr, auv_i18n_tr_fmt, AuvI18nLang};
use auv_pass_engine::auv_pass_agent_default_socket;
use auv_pass_engine::auv_pass_write_secret_file;
use auv_pass_engine::AuvPassAgentHandle;
use auv_pass_engine::AuvPassSshKey;
use auv_pass_engine::{auv_pass_agent_start, auv_pass_ssh_fingerprint_hex};
use auv_pass_engine::{
    auv_pass_gen_entropy_bits, auv_pass_generate_password, auv_pass_totp_generate,
    auv_pass_totp_parse_otpauth, auv_pass_totp_remaining_seconds, AuvPassCipherAlgo,
    AuvPassEntryId, AuvPassEntryInput, AuvPassGenOptions, AuvPassKdfParams, AuvPassTotpConfig,
    AuvPassVault,
};

pub type BoxError = Box<dyn std::error::Error>;

// ===================== 屏与表单 =====================

#[derive(Clone)]
pub enum FormKind {
    OpenVault,
    CreateVault,
    AddEntry,
    EditEntry(AuvPassEntryId),
    ImportKdbx,
    ExportKdbx,
    Search,
    Generator,
    SshGenerate,
    SshImport,
    SshExportPrivate(AuvPassEntryId),
}

#[derive(Clone)]
pub struct Field {
    pub label: String,
    pub value: String,
    pub secret: bool,
    pub note: String,
}

#[derive(Clone)]
pub struct Form {
    pub kind: FormKind,
    pub title: String,
    pub fields: Vec<Field>,
    pub selected: usize,
    /// 生成器结果(密码, 熵 bit)。
    pub gen_result: Option<(String, f64)>,
}

impl Form {
    fn push(&mut self, label: impl Into<String>, secret: bool, note: impl Into<String>) {
        self.fields.push(Field {
            label: label.into(),
            value: String::new(),
            secret,
            note: note.into(),
        });
    }
    fn val(&self, i: usize) -> &str {
        self.fields[i].value.trim()
    }
}

pub enum Screen {
    Main,
    Detail,
    History,
    Snapshot(usize),
    Form(Form),
    Message(String),
    ConfirmDelete(AuvPassEntryId),
    Home,
    SshKeys,
    AgentConfirm,
}

#[derive(PartialEq)]
pub enum Panel {
    Groups,
    Entries,
}

pub struct App {
    pub session: Option<Session>,
    pub screen: Screen,
    pub back: Vec<Screen>,
    pub home_sel: usize,
    pub hist_sel: usize,
    pub groups: ListState,
    pub entries: ListState,
    pub panel: Panel,
    /// 搜索结果 id 缓存(配合 search_active 使用)。
    pub search_cache: Vec<AuvPassEntryId>,
    /// 是否处于搜索模式(0 命中也为真:显示空列表,不退回全量)。
    pub search_active: bool,
    pub show_plain: bool,
    pub quit: bool,
    pub ssh_sel: usize,
    pub agent: Option<AgentBridge>,
    pub pending_confirm: Option<ConfirmReq>,
    pub session_allowed: std::sync::Arc<std::sync::Mutex<Vec<AuvPassEntryId>>>,
    /// 最后活动时刻(自动锁定用)。
    pub last_activity: std::time::Instant,
}

/// 自动锁定阈值(默认 10 分钟)。
pub const AUTO_LOCK_AFTER: std::time::Duration = std::time::Duration::from_secs(600);

/// agent 确认请求(线程间)。
pub struct ConfirmReq {
    pub key_name: String,
    pub reply: std::sync::mpsc::Sender<bool>,
}

/// 运行中的 agent 桥(句柄 + 确认请求接收端)。
pub struct AgentBridge {
    pub handle: AuvPassAgentHandle,
    pub rx: std::sync::mpsc::Receiver<ConfirmReq>,
}

pub fn fmt_time(sec: i64) -> String {
    chrono::Local
        .timestamp_opt(sec, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| format!("{sec}"))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ===================== 视图数据 =====================

impl App {
    pub fn new() -> Self {
        let mut a = Self {
            session: None,
            screen: Screen::Home,
            back: Vec::new(),
            home_sel: 0,
            hist_sel: 0,
            groups: ListState::default(),
            entries: ListState::default(),
            panel: Panel::Entries,
            search_cache: Vec::new(),
            search_active: false,
            show_plain: false,
            quit: false,
            ssh_sel: 0,
            agent: None,
            pending_confirm: None,
            session_allowed: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            last_activity: std::time::Instant::now(),
        };
        a.groups.select(Some(0));
        a.entries.select(Some(0));
        a
    }

    pub fn group_names(&self) -> Vec<String> {
        let mut v = vec![auv_i18n_tr("group-all-paren").to_string()];
        if let Some(s) = &self.session {
            v.extend(s.vault.groups());
        }
        v
    }

    pub fn visible_entry_ids(&self) -> Vec<AuvPassEntryId> {
        let Some(s) = &self.session else {
            return vec![];
        };
        if self.search_active {
            // 搜索模式:0 命中 = 空列表(不退回全量,防用户误以为仍在浏览而误复制无关条目)
            return self.search_cache.clone();
        }
        let gi = self.groups.selected().unwrap_or(0);
        let all_label = auv_i18n_tr("group-all-paren");
        match self.group_names().get(gi).map(String::as_str) {
            None => s.vault.entries().iter().map(|e| e.id).collect(),
            Some(g) if g == all_label => s.vault.entries().iter().map(|e| e.id).collect(),
            Some(g) => {
                let g = g.to_string();
                s.vault.entries_in_group(&g).iter().map(|e| e.id).collect()
            }
        }
    }

    pub fn selected_entry(&self) -> Option<&auv_pass_engine::AuvPassEntry> {
        let s = self.session.as_ref()?;
        let ids = self.visible_entry_ids();
        let i = self.entries.selected()?;
        s.vault.get_entry(*ids.get(i)?)
    }

    fn clamp(&mut self) {
        let g = self
            .groups
            .selected()
            .map(|i| i.min(self.group_names().len().saturating_sub(1)))
            .unwrap_or(0);
        self.groups.select(Some(g));
        let e = self
            .entries
            .selected()
            .map(|i| i.min(self.visible_entry_ids().len().saturating_sub(1)))
            .unwrap_or(0);
        self.entries.select(Some(e));
    }

    fn go(&mut self, screen: Screen) {
        let old = std::mem::replace(&mut self.screen, screen);
        self.back.push(old);
        self.show_plain = false;
    }

    fn back(&mut self) {
        if let Some(prev) = self.back.pop() {
            self.screen = prev;
        }
        self.show_plain = false;
    }

    fn message(&mut self, text: String) {
        self.go(Screen::Message(text));
    }
}

// ===================== 事件入口 =====================

pub fn run() -> Result<(), BoxError> {
    let mut terminal = ratatui::init();
    let mut app = App::new();
    let res = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    res
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<(), BoxError> {
    while !app.quit {
        terminal.draw(|f| crate::ui::draw(app, f))?;
        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let crossterm::event::Event::Key(k) = crossterm::event::read()? {
                if k.kind == KeyEventKind::Press {
                    app.last_activity = std::time::Instant::now();
                    on_key(app, k);
                }
            }
        }
        // agent 确认请求 → 弹窗(先收集再弹,避免借用冲突)
        let mut reqs = Vec::new();
        if let Some(bridge) = &app.agent {
            while let Ok(req) = bridge.rx.try_recv() {
                reqs.push(req);
            }
        }
        for req in reqs {
            app.pending_confirm = Some(req);
            app.go(Screen::AgentConfirm);
        }
        app.clamp();
        // 自动锁定:空闲超阈值且已开库 → 清钥回首页
        if app.session.is_some()
            && app.last_activity.elapsed() > AUTO_LOCK_AFTER
            && app.agent.is_none()
        {
            app.session = None;
            app.search_cache.clear();
            app.search_active = false;
            app.screen = Screen::Home;
            app.back.clear();
        }
    }
    Ok(())
}

fn on_key(app: &mut App, k: KeyEvent) {
    if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
        app.quit = true;
        return;
    }
    // 全局语言切换:z(小写;大写保留)。
    // 表单屏不拦截——字母键要录入输入框(此前表单里按 z 无法输入,被切语言劫持)。
    if k.code == KeyCode::Char('z') && !matches!(app.screen, Screen::Form(_)) {
        auv_i18n_lang_toggle();
        let msg = match auv_i18n_lang() {
            AuvI18nLang::En => "Language: English".to_string(),
            AuvI18nLang::ZhCn => "语言:中文".to_string(),
        };
        app.message(msg);
        return;
    }
    match &app.screen {
        Screen::Home => on_home(app, k),
        Screen::Main => on_main(app, k),
        Screen::Detail => on_detail(app, k),
        Screen::History => on_history(app, k),
        Screen::Snapshot(i) => on_snapshot(app, *i, k),
        Screen::Form(_) => on_form(app, k),
        Screen::Message(_) => app.back(),
        Screen::ConfirmDelete(id) => on_confirm_delete(app, *id, k),
        Screen::SshKeys => on_ssh_keys(app, k),
        Screen::AgentConfirm => on_agent_confirm(app, k),
    }
}

// ===================== 各屏处理 =====================

/// 首页菜单(随语言切换;不能做成 const,译文在运行时查表)。
fn home_items() -> [String; 4] {
    [
        auv_i18n_tr("menu-open-vault"),
        auv_i18n_tr("menu-new-vault"),
        auv_i18n_tr("menu-password-generator"),
        auv_i18n_tr("btn-quit"),
    ]
}

fn on_home(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Up => app.home_sel = app.home_sel.saturating_sub(1),
        KeyCode::Down => app.home_sel = (app.home_sel + 1).min(home_items().len() - 1),
        KeyCode::Enter => match app.home_sel {
            0 => app.go(Screen::Form(form_open())),
            1 => app.go(Screen::Form(form_create())),
            2 => app.go(Screen::Form(form_generator())),
            _ => app.quit = true,
        },
        KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
        _ => {}
    }
}

fn on_main(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Tab => {
            app.panel = if app.panel == Panel::Groups {
                Panel::Entries
            } else {
                Panel::Groups
            };
        }
        KeyCode::Up | KeyCode::Down => {
            let (len, groups) = if app.panel == Panel::Groups {
                (app.group_names().len(), true)
            } else {
                (app.visible_entry_ids().len(), false)
            };
            let state = if groups {
                &mut app.groups
            } else {
                &mut app.entries
            };
            let i = state.selected().unwrap_or(0);
            let ni = match k.code {
                KeyCode::Up => i.saturating_sub(1),
                _ => (i + 1).min(len.saturating_sub(1)),
            };
            state.select(Some(ni));
        }
        KeyCode::Enter => {
            if app.selected_entry().is_some() {
                app.go(Screen::Detail);
            }
        }
        // Shift+C 在部分终端解码为 Char('c')+SHIFT 修饰而非 Char('C'),两种都按用户名复制认。
        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::SHIFT) => {
            if let Some(e) = app.selected_entry() {
                match crate::clipboard_copy(&e.username, 0) {
                    Ok(()) => app.message(auv_i18n_tr("msg-username-copied")),
                    Err(err) => {
                        app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &err)]))
                    }
                }
            }
        }
        KeyCode::Char('c') => {
            if let Some(e) = app.selected_entry() {
                let pw = e.password.as_str().to_string();
                match crate::clipboard_copy(&pw, crate::CLIPBOARD_CLEAR_SECS) {
                    Ok(()) => app.message(auv_i18n_tr_fmt(
                        "msg-password-copied",
                        &[("secs", &crate::CLIPBOARD_CLEAR_SECS.to_string())],
                    )),
                    Err(err) => {
                        app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &err)]))
                    }
                }
            }
        }
        KeyCode::Char('C') => {
            if let Some(e) = app.selected_entry() {
                match crate::clipboard_copy(&e.username, 0) {
                    Ok(()) => app.message(auv_i18n_tr("msg-username-copied")),
                    Err(err) => {
                        app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &err)]))
                    }
                }
            }
        }
        KeyCode::Char('n') => app.go(Screen::Form(form_add())),
        KeyCode::Char('e') => {
            if let Some(e) = app.selected_entry() {
                let id = e.id;
                let input_form = form_edit(id, app);
                app.go(Screen::Form(input_form));
            }
        }
        KeyCode::Char('d') => {
            if let Some(e) = app.selected_entry() {
                let id = e.id;
                app.go(Screen::ConfirmDelete(id));
            }
        }
        KeyCode::Char('h') => {
            if app.selected_entry().is_some() {
                app.hist_sel = 0;
                app.go(Screen::History);
            }
        }
        KeyCode::Char('s') => app.go(Screen::Form(form_search())),
        KeyCode::Char('g') => app.go(Screen::Form(form_generator())),
        KeyCode::Char('k') => {
            app.ssh_sel = 0;
            app.go(Screen::SshKeys);
        }
        KeyCode::Char('8') => app.go(Screen::Form(form_import())),
        KeyCode::Char('9') => app.go(Screen::Form(form_export())),
        KeyCode::Char('l') => {
            app.session = None;
            app.search_cache.clear();
            app.search_active = false;
            app.screen = Screen::Home;
            app.back.clear();
        }
        KeyCode::Char('q') => app.quit = true,
        KeyCode::Esc => {
            app.search_cache.clear();
            app.search_active = false;
        }
        _ => {}
    }
}

fn on_detail(app: &mut App, k: KeyEvent) {
    let Some(e) = app.selected_entry().cloned() else {
        app.back();
        return;
    };
    match k.code {
        KeyCode::Char('p') => app.show_plain = !app.show_plain,
        KeyCode::Char('c') => {
            let pw = e.password.as_str().to_string();
            match crate::clipboard_copy(&pw, crate::CLIPBOARD_CLEAR_SECS) {
                Ok(()) => app.message(auv_i18n_tr_fmt(
                    "msg-password-copied",
                    &[("secs", &crate::CLIPBOARD_CLEAR_SECS.to_string())],
                )),
                Err(err) => {
                    app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &err)]))
                }
            }
        }
        KeyCode::Char('u') => match crate::clipboard_copy(&e.username, 0) {
            Ok(()) => app.message(auv_i18n_tr("msg-username-copied")),
            Err(err) => app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &err)])),
        },
        KeyCode::Char('t') => match &e.totp {
            Some(cfg) => match auv_pass_totp_generate(cfg, now_unix()) {
                Ok(code) => {
                    let left = auv_pass_totp_remaining_seconds(cfg.period_s, now_unix());
                    app.message(auv_i18n_tr_fmt(
                        "msg-totp-code",
                        &[("code", &code), ("secs", &left.to_string())],
                    ))
                }
                Err(err) => {
                    app.message(auv_i18n_tr_fmt("error-totp", &[("err", &err.to_string())]))
                }
            },
            None => app.message(auv_i18n_tr("msg-no-totp")),
        },
        KeyCode::Char('h') => {
            app.hist_sel = 0;
            app.go(Screen::History);
        }
        KeyCode::Esc | KeyCode::Enter => app.back(),
        _ => {}
    }
}

fn on_history(app: &mut App, k: KeyEvent) {
    let Some(e) = app.selected_entry() else {
        app.back();
        return;
    };
    let len = e.history.len();
    match k.code {
        KeyCode::Up => app.hist_sel = app.hist_sel.saturating_sub(1),
        KeyCode::Down => app.hist_sel = (app.hist_sel + 1).min(len.saturating_sub(1)),
        KeyCode::Enter => {
            if len > 0 {
                let i = app.hist_sel;
                app.go(Screen::Snapshot(i));
            }
        }
        KeyCode::Esc => app.back(),
        _ => {}
    }
}

fn on_snapshot(app: &mut App, i: usize, k: KeyEvent) {
    let snap_pw = {
        let Some(e) = app.selected_entry() else {
            app.back();
            return;
        };
        e.history.get(i).map(|s| s.password.as_str().to_string())
    };
    match k.code {
        KeyCode::Char('c') => {
            if let Some(pw) = snap_pw {
                match crate::clipboard_copy(&pw, crate::CLIPBOARD_CLEAR_SECS) {
                    Ok(()) => app.message(auv_i18n_tr_fmt(
                        "msg-history-password-copied",
                        &[("secs", &crate::CLIPBOARD_CLEAR_SECS.to_string())],
                    )),
                    Err(err) => {
                        app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &err)]))
                    }
                }
            }
        }
        KeyCode::Esc | KeyCode::Enter => app.back(),
        _ => {}
    }
}

fn on_confirm_delete(app: &mut App, id: AuvPassEntryId, k: KeyEvent) {
    match k.code {
        KeyCode::Char('y') | KeyCode::Enter => {
            app.back(); // 先退出确认屏
            let res = (|| -> Result<usize, String> {
                let s = app.session.as_mut().ok_or(auv_i18n_tr("error-no-vault"))?;
                s.vault.delete_entry(id).map_err(|e| e.to_string())?;
                s.vault.save(&s.path).map_err(|e| e.to_string())?;
                Ok(s.vault.entry_count())
            })();
            match res {
                Ok(_) => app.message(auv_i18n_tr("msg-deleted-saved")),
                Err(e) => app.message(e),
            }
        }
        KeyCode::Esc | KeyCode::Char('n') => app.back(),
        _ => {}
    }
}

// ===================== 表单 =====================

// ===================== SSH 钥匙管理屏 =====================

fn on_ssh_keys(app: &mut App, k: KeyEvent) {
    let n = app
        .session
        .as_ref()
        .map(|s| s.vault.ssh_keys().len())
        .unwrap_or(0);
    match k.code {
        KeyCode::Up => app.ssh_sel = app.ssh_sel.saturating_sub(1),
        KeyCode::Down => app.ssh_sel = (app.ssh_sel + 1).min(n.saturating_sub(1)),
        KeyCode::Char('q') | KeyCode::Esc => app.back(),
        KeyCode::Char('g') => app.go(Screen::Form(form_ssh_generate())),
        KeyCode::Char('i') => app.go(Screen::Form(form_ssh_import())),
        _ => {
            let Some(s) = app.session.as_ref() else {
                return;
            };
            let Some(key) = s.vault.ssh_keys().get(app.ssh_sel) else {
                return;
            };
            let id = key.id;
            match k.code {
                KeyCode::Char('e') => {
                    let now_exposed = key.exposed;
                    let s = app.session.as_mut().unwrap();
                    if s.vault.ssh_set_exposed(id, !now_exposed).is_ok() {
                        let _ = s.vault.save(&s.path);
                        app.message(if now_exposed {
                            auv_i18n_tr("msg-key-hidden")
                        } else {
                            auv_i18n_tr("msg-key-exposed")
                        });
                    }
                }
                KeyCode::Char('c') => {
                    let line = key.public_line.clone();
                    match crate::clipboard_copy(&line, 0) {
                        Ok(()) => app.message(auv_i18n_tr("msg-public-key-copied")),
                        Err(e) => {
                            app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &e)]))
                        }
                    }
                }
                KeyCode::Char('p') => {
                    let fp = auv_pass_ssh_fingerprint_hex(key);
                    match crate::clipboard_copy(&fp, 0) {
                        Ok(()) => {
                            app.message(auv_i18n_tr_fmt("msg-fingerprint-copied", &[("fp", &fp)]))
                        }
                        Err(e) => {
                            app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &e)]))
                        }
                    }
                }
                KeyCode::Char('x') => app.go(Screen::Form(form_ssh_export(id))),
                KeyCode::Char('d') => {
                    if let Some(s) = app.session.as_mut() {
                        match s.vault.ssh_delete(id) {
                            Ok(()) => {
                                let _ = s.vault.save(&s.path);
                                app.ssh_sel = app.ssh_sel.saturating_sub(1);
                                app.message(auv_i18n_tr("msg-key-deleted"));
                            }
                            Err(e) => app.message(e.to_string()),
                        }
                    }
                }
                KeyCode::Char('a') => toggle_agent(app),
                _ => {}
            }
        }
    }
}

fn toggle_agent(app: &mut App) {
    if app.agent.is_some() {
        let bridge = app.agent.take().unwrap();
        bridge.handle.stop();
        app.message(auv_i18n_tr("msg-agent-stopped"));
        return;
    }
    let Some(s) = app.session.as_ref() else {
        return;
    };
    let keys = s.vault.ssh_exposed_keys();
    if keys.is_empty() {
        app.message(auv_i18n_tr("msg-no-exposed-keys-hint"));
        return;
    }
    let (tx, rx) = std::sync::mpsc::channel::<ConfirmReq>();
    let allowed = app.session_allowed.clone();
    let confirm = move |key: &AuvPassSshKey, _data: &[u8]| -> bool {
        if allowed.lock().unwrap().contains(&key.id) {
            return true; // 本会话已允许
        }
        let (rtx, rrx) = std::sync::mpsc::channel::<bool>();
        if tx
            .send(ConfirmReq {
                key_name: key.name.clone(),
                reply: rtx,
            })
            .is_err()
        {
            return false;
        }
        rrx.recv_timeout(std::time::Duration::from_secs(30))
            .unwrap_or(false)
    };
    let socket = auv_pass_agent_default_socket();
    match auv_pass_agent_start(keys, &socket, Box::new(confirm)) {
        Ok(handle) => {
            app.agent = Some(AgentBridge { handle, rx });
            app.message(auv_i18n_tr_fmt(
                "msg-agent-started-sock",
                &[("socket", &socket)],
            ));
        }
        Err(e) => app.message(auv_i18n_tr_fmt(
            "error-agent-start-failed",
            &[("err", &e.to_string())],
        )),
    }
}

fn on_agent_confirm(app: &mut App, k: KeyEvent) {
    let Some(req) = app.pending_confirm.take() else {
        app.back();
        return;
    };
    match k.code {
        KeyCode::Char('y') | KeyCode::Enter => {
            let _ = req.reply.send(true);
            app.back();
        }
        KeyCode::Char('a') => {
            // 本会话后续自动允许该钥匙
            if let Some(s) = app.session.as_ref() {
                if let Some(key) = s.vault.ssh_keys().iter().find(|x| x.name == req.key_name) {
                    app.session_allowed.lock().unwrap().push(key.id);
                }
            }
            let _ = req.reply.send(true);
            app.back();
        }
        _ => {
            let _ = req.reply.send(false);
            app.back();
        }
    }
}

fn form_ssh_generate() -> Form {
    let mut f = Form {
        kind: FormKind::SshGenerate,
        title: auv_i18n_tr("menu-ssh-generate-full"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(
        auv_i18n_tr("label-name"),
        false,
        auv_i18n_tr("label-key-comment"),
    );
    f
}

fn form_ssh_import() -> Form {
    let mut f = Form {
        kind: FormKind::SshImport,
        title: auv_i18n_tr("menu-ssh-import-full"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(auv_i18n_tr("label-ssh-key-path"), false, "");
    f.push(
        auv_i18n_tr("label-passphrase"),
        true,
        auv_i18n_tr("hint-no-passphrase"),
    );
    f.push(
        auv_i18n_tr("label-name"),
        false,
        auv_i18n_tr("hint-keep-comment"),
    );
    f
}

fn form_ssh_export(id: AuvPassEntryId) -> Form {
    let mut f = Form {
        kind: FormKind::SshExportPrivate(id),
        title: auv_i18n_tr("menu-ssh-export-full"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(auv_i18n_tr("label-export-file-path"), false, "");
    f
}

fn form_open() -> Form {
    let mut f = Form {
        kind: FormKind::OpenVault,
        title: auv_i18n_tr("menu-open-vault"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(auv_i18n_tr("label-vault-file"), false, "");
    f.push(
        auv_i18n_tr("label-master-password"),
        true,
        auv_i18n_tr("hint-keyfile-only-2"),
    );
    f.push(
        auv_i18n_tr("label-key-file-path"),
        false,
        auv_i18n_tr("hint-enter-skip"),
    );
    f
}

fn form_create() -> Form {
    let mut f = Form {
        kind: FormKind::CreateVault,
        title: auv_i18n_tr("menu-new-vault"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(
        auv_i18n_tr("label-vault-file"),
        false,
        auv_i18n_tr("hint-parent-autocreate"),
    );
    f.push(
        auv_i18n_tr("label-master-password"),
        true,
        auv_i18n_tr("hint-password-if-keyfile"),
    );
    f.push(auv_i18n_tr("label-repeat-master-password"), true, "");
    f.push(
        auv_i18n_tr("label-key-file-path"),
        false,
        auv_i18n_tr("hint-keyfile-any-file"),
    );
    f.fields[3].value = "1".into();
    f.fields[3].label = auv_i18n_tr("label-algorithm-short");
    f.fields[3].note = auv_i18n_tr("label-algorithm-choices");
    f
}

fn form_add() -> Form {
    let mut f = Form {
        kind: FormKind::AddEntry,
        title: auv_i18n_tr("dialog-new-entry"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(
        auv_i18n_tr("label-group"),
        false,
        auv_i18n_tr("hint-group-path"),
    );
    f.push(
        auv_i18n_tr("label-title"),
        false,
        auv_i18n_tr("error-required"),
    );
    f.push(auv_i18n_tr("label-username"), false, "");
    f.push(
        auv_i18n_tr("label-password"),
        true,
        auv_i18n_tr("hint-empty-generate"),
    );
    f.push("URL", false, "");
    f.push(auv_i18n_tr("label-notes"), false, "");
    f.push("TOTP", false, auv_i18n_tr("hint-totp-secret"));
    f
}

fn form_edit(id: AuvPassEntryId, app: &App) -> Form {
    let e = app
        .session
        .as_ref()
        .and_then(|s| s.vault.get_entry(id))
        .cloned()
        .unwrap();
    let mut f = Form {
        kind: FormKind::EditEntry(id),
        title: auv_i18n_tr_fmt("label-editing", &[("name", &e.title)]),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(auv_i18n_tr("label-group"), false, "");
    f.push(auv_i18n_tr("label-title"), false, "");
    f.push(auv_i18n_tr("label-username"), false, "");
    f.push(
        auv_i18n_tr("label-password"),
        true,
        auv_i18n_tr("hint-keep-current"),
    );
    f.push("URL", false, "");
    f.push(auv_i18n_tr("label-notes"), false, "");
    f.push("TOTP", false, auv_i18n_tr("hint-keep-or-clear"));
    let set = |f: &mut Form, i: usize, v: String| f.fields[i].value = v;
    set(&mut f, 0, e.group.clone());
    set(&mut f, 1, e.title.clone());
    set(&mut f, 2, e.username.clone());
    set(&mut f, 4, e.url.clone());
    set(&mut f, 5, e.notes.clone());
    f
}

fn form_search() -> Form {
    let mut f = Form {
        kind: FormKind::Search,
        title: auv_i18n_tr("label-search-scope"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(
        auv_i18n_tr("label-keyword"),
        false,
        auv_i18n_tr("hint-empty-cancel"),
    );
    f
}

fn form_generator() -> Form {
    let mut f = Form {
        kind: FormKind::Generator,
        title: auv_i18n_tr("menu-password-generator"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.fields.push(Field {
        label: auv_i18n_tr("label-length"),
        value: "20".into(),
        secret: false,
        note: "8..=128".into(),
    });
    f.fields.push(Field {
        label: auv_i18n_tr("label-character-set"),
        value: "1".into(),
        secret: false,
        note: auv_i18n_tr("label-charset-choices"),
    });
    f.fields.push(Field {
        label: auv_i18n_tr("label-exclude-chars"),
        value: String::new(),
        secret: false,
        note: auv_i18n_tr("hint-exclude-chars"),
    });
    f
}

fn form_import() -> Form {
    let mut f = Form {
        kind: FormKind::ImportKdbx,
        title: auv_i18n_tr("dialog-import-kdbx"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(auv_i18n_tr("label-kdbx-path"), false, "");
    f.push(
        auv_i18n_tr("label-vault-password"),
        true,
        auv_i18n_tr("hint-keyfile-only"),
    );
    f.push(
        auv_i18n_tr("label-key-file-path"),
        false,
        auv_i18n_tr("hint-enter-none"),
    );
    f
}

fn form_export() -> Form {
    let mut f = Form {
        kind: FormKind::ExportKdbx,
        title: auv_i18n_tr("menu-export-kdbx-full"),
        fields: Vec::new(),
        selected: 0,
        gen_result: None,
    };
    f.push(auv_i18n_tr("label-export-path"), false, "");
    f.push(
        auv_i18n_tr("label-export-master-password"),
        true,
        auv_i18n_tr("hint-keyfile-only"),
    );
    f.push(auv_i18n_tr("label-repeat-master-password"), true, "");
    f.push(
        auv_i18n_tr("label-key-file-path"),
        false,
        auv_i18n_tr("hint-enter-unused"),
    );
    f
}

/// Tab 路径补全结果
enum PathComplete {
    One(String),
    Many(Vec<String>),
    NotPath,
}
/// 按 Tab 时补全文件/目录路径
fn complete_path(input: &str) -> PathComplete {
    if !input.contains('/') && !input.contains('\\') {
        return PathComplete::NotPath;
    }
    let (dir, prefix) = match input.rfind(['/', '\\']) {
        Some(i) => (&input[..=i], &input[i + 1..]),
        None => return PathComplete::NotPath,
    };
    let sep = if dir.contains('\\') { "\\" } else { "/" };
    let dir_path = if dir.is_empty() { "." } else { dir };
    let Ok(entries) = std::fs::read_dir(dir_path) else {
        return PathComplete::NotPath;
    };
    let mut matches: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(prefix) {
                let suffix = if e.path().is_dir() { sep } else { "" };
                Some(format!("{dir}{name}{suffix}"))
            } else {
                None
            }
        })
        .collect();
    match matches.len() {
        0 => PathComplete::NotPath,
        1 => PathComplete::One(matches.remove(0)),
        _ => {
            let all: Vec<String> = matches
                .iter()
                .map(|m| m[dir.len()..].trim_end_matches(sep).to_string())
                .collect();
            PathComplete::Many(all)
        }
    }
}

/// 生成器表单的自由文本字段(排除字符)下标:该字段聚焦时字母键必须照常录入,
/// 不得被「c = 复制」快捷键劫持(表单输入态下字母快捷键一律不触发全局动作)。
const GENERATOR_FREE_TEXT_FIELD: usize = 2;

fn on_form(app: &mut App, k: KeyEvent) {
    // 生成器:已有结果时 c = 复制(30 秒自动清)。
    // 仅在聚焦字段为数值选择(长度/字符类)时作快捷键;排除字符字段聚焦时 c 照常录入。
    if let Screen::Form(f) = &app.screen {
        if matches!(f.kind, FormKind::Generator) && f.selected != GENERATOR_FREE_TEXT_FIELD {
            if let Some((pw, _)) = &f.gen_result {
                if k.code == KeyCode::Char('c') {
                    let pw = pw.clone();
                    match crate::clipboard_copy(&pw, crate::CLIPBOARD_CLEAR_SECS) {
                        Ok(()) => app.message(auv_i18n_tr_fmt(
                            "msg-copied",
                            &[("secs", &crate::CLIPBOARD_CLEAR_SECS.to_string())],
                        )),
                        Err(e) => {
                            app.message(auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &e)]))
                        }
                    }
                    return;
                }
            }
        }
    }
    let Screen::Form(f) = &mut app.screen else {
        return;
    };
    match k.code {
        KeyCode::Esc => app.back(),
        KeyCode::Tab => {
            let val = f.fields[f.selected].value.clone();
            match complete_path(&val) {
                PathComplete::One(s) => f.fields[f.selected].value = s,
                PathComplete::Many(cands) => {
                    app.message(auv_i18n_tr_fmt(
                        "label-matches",
                        &[("count", &cands.join(" "))],
                    ));
                }
                PathComplete::NotPath => {
                    f.selected = (f.selected + 1) % f.fields.len();
                }
            }
        }
        KeyCode::BackTab => f.selected = (f.selected + f.fields.len() - 1) % f.fields.len(),
        KeyCode::Up => f.selected = f.selected.saturating_sub(1),
        KeyCode::Down => f.selected = (f.selected + 1).min(f.fields.len() - 1),
        KeyCode::Backspace => {
            f.fields[f.selected].value.pop();
        }
        KeyCode::Char(c) => f.fields[f.selected].value.push(c),
        KeyCode::Enter => {
            let form = f.clone();
            submit_form(app, form);
        }
        _ => {}
    }
}

fn parse_totp(s: &str) -> Result<Option<AuvPassTotpConfig>, String> {
    if s.is_empty() {
        return Ok(None);
    }
    if s == "-" {
        return Ok(None); // 清除(调用方区分保留:编辑时空=保留由外层处理)
    }
    if s.starts_with("otpauth://") {
        auv_pass_totp_parse_otpauth(s)
            .map(Some)
            .map_err(|e| e.to_string())
    } else {
        let cfg = AuvPassTotpConfig {
            secret: s.to_string(),
            ..Default::default()
        };
        cfg.validate().map_err(|e| e.to_string())?;
        Ok(Some(cfg))
    }
}

fn submit_form(app: &mut App, f: Form) {
    let res: Result<String, String> = (|| match f.kind.clone() {
        FormKind::OpenVault => {
            let path = f.val(0).to_string();
            if path.is_empty() {
                return Err(auv_i18n_tr("error-path-empty"));
            }
            let kf = non_empty(f.val(2));
            match AuvPassVault::open(
                std::path::Path::new(&path),
                f.val(1).as_bytes(),
                kf.as_deref().map(std::path::Path::new),
            ) {
                Ok(v) => {
                    let n = v.entry_count();
                    app.session = Some(Session {
                        vault: v,
                        path: path.into(),
                    });
                    app.search_cache.clear();
                    app.search_active = false;
                    app.screen = Screen::Main;
                    app.back.clear();
                    Ok(auv_i18n_tr_fmt("msg-text", &[("count", &n.to_string())]))
                }
                Err(e) => Err(e.to_string()),
            }
        }
        FormKind::CreateVault => {
            let path = f.val(0).to_string();
            if path.is_empty() {
                return Err(auv_i18n_tr("error-path-empty"));
            }
            if f.fields[1].value != f.fields[2].value {
                return Err(auv_i18n_tr("error-passwords-mismatch"));
            }
            let kf = non_empty(f.val(3));
            let algo = match f.val(4) {
                "2" => AuvPassCipherAlgo::ChaCha20Poly1305,
                "3" => AuvPassCipherAlgo::Sm4Gcm,
                _ => AuvPassCipherAlgo::Aes256Gcm,
            };
            let v = AuvPassVault::create(
                f.val(1).as_bytes(),
                kf.as_deref().map(std::path::Path::new),
                algo,
                &AuvPassKdfParams::default(),
            )
            .map_err(|e| e.to_string())?;
            v.save(std::path::Path::new(&path))
                .map_err(|e| e.to_string())?;
            app.session = Some(Session {
                vault: v,
                path: path.into(),
            });
            app.search_cache.clear();
            app.search_active = false;
            app.screen = Screen::Main;
            app.back.clear();
            Ok(auv_i18n_tr("msg-vault-created"))
        }
        FormKind::AddEntry => {
            let title = f.val(1).to_string();
            if title.is_empty() {
                return Err(auv_i18n_tr("error-title-required"));
            }
            let totp = match f.val(6) {
                "" => None,
                "-" => None,
                s => parse_totp(s)?,
            };
            let password = if f.fields[3].value.is_empty() {
                let opts = AuvPassGenOptions::default();
                auv_pass_generate_password(&opts)
                    .map_err(|e| e.to_string())
                    .map(|p| Zeroizing::new(p.to_string()))?
            } else {
                Zeroizing::new(f.fields[3].value.clone())
            };
            let s = app.session.as_mut().ok_or(auv_i18n_tr("error-no-vault"))?;
            s.vault
                .add_entry(AuvPassEntryInput {
                    group: f.val(0).to_string(),
                    title,
                    username: f.val(2).to_string(),
                    password,
                    url: f.val(4).to_string(),
                    notes: f.val(5).to_string(),
                    totp,
                })
                .map_err(|e| e.to_string())?;
            s.vault.save(&s.path).map_err(|e| e.to_string())?;
            Ok(auv_i18n_tr("msg-added-saved"))
        }
        FormKind::EditEntry(id) => {
            let s = app.session.as_mut().ok_or(auv_i18n_tr("error-no-vault"))?;
            let old = s
                .vault
                .get_entry(id)
                .cloned()
                .ok_or(auv_i18n_tr("error-entry-not-found"))?;
            let password = if f.fields[3].value.is_empty() {
                old.password.clone()
            } else {
                Zeroizing::new(f.fields[3].value.clone())
            };
            let totp = match f.val(6) {
                "" => old.totp.clone(),
                "-" => None,
                s => parse_totp(s)?,
            };
            let title = if f.val(1).is_empty() {
                old.title.clone()
            } else {
                f.val(1).to_string()
            };
            s.vault
                .update_entry(
                    id,
                    AuvPassEntryInput {
                        group: f.val(0).to_string(),
                        title,
                        username: f.val(2).to_string(),
                        password,
                        url: f.val(4).to_string(),
                        notes: f.val(5).to_string(),
                        totp,
                    },
                )
                .map_err(|e| e.to_string())?;
            let n = s.vault.history(id).map(|h| h.len()).unwrap_or(0);
            s.vault.save(&s.path).map_err(|e| e.to_string())?;
            Ok(auv_i18n_tr_fmt(
                "msg-updated-history",
                &[("count", &n.to_string())],
            ))
        }
        FormKind::Search => {
            let q = f.val(0).to_string();
            if q.is_empty() {
                app.search_cache.clear();
                app.search_active = false;
                return Ok(auv_i18n_tr("msg-search-cleared"));
            }
            let s = app.session.as_ref().ok_or(auv_i18n_tr("error-no-vault"))?;
            app.search_cache = s.vault.search(&q).iter().map(|e| e.id).collect();
            // 0 命中也置搜索模式:列表显示空,不退回全量
            app.search_active = true;
            Ok(auv_i18n_tr_fmt(
                "msg-matched-count",
                &[("count", &app.search_cache.len().to_string())],
            ))
        }
        FormKind::SshGenerate => {
            let s = app.session.as_mut().ok_or(auv_i18n_tr("error-no-vault"))?;
            let id = s
                .vault
                .ssh_generate_ed25519(f.val(0))
                .map_err(|e| e.to_string())?;
            let _ = id;
            s.vault.save(&s.path).map_err(|e| e.to_string())?;
            Ok(auv_i18n_tr("msg-key-generated"))
        }
        FormKind::SshImport => {
            let pem = std::fs::read_to_string(f.val(0))
                .map_err(|e| auv_i18n_tr_fmt("error-read-failed", &[("err", &e.to_string())]))?;
            let pw = f.fields[1].value.clone();
            let s = app.session.as_mut().ok_or(auv_i18n_tr("error-no-vault"))?;
            s.vault
                .ssh_import(
                    &pem,
                    if pw.is_empty() {
                        None
                    } else {
                        Some(pw.as_str())
                    },
                    f.val(2),
                )
                .map_err(|e| e.to_string())?;
            s.vault.save(&s.path).map_err(|e| e.to_string())?;
            Ok(auv_i18n_tr("msg-ssh-key-imported"))
        }
        FormKind::SshExportPrivate(id) => {
            let s = app.session.as_ref().ok_or(auv_i18n_tr("error-no-vault"))?;
            let pem = s.vault.ssh_export_private(id).map_err(|e| e.to_string())?;
            // 明文私钥落盘收紧 0600(Unix):默认 umask 0644 属泄露面,ssh 客户端亦拒载
            auv_pass_write_secret_file(std::path::Path::new(f.val(0)), pem.as_bytes())
                .map_err(|e| auv_i18n_tr_fmt("error-write-failed", &[("err", &e.to_string())]))?;
            Ok(auv_i18n_tr("msg-ssh-key-exported"))
        }
        FormKind::Generator => {
            let len: usize = f.val(0).parse().unwrap_or(20);
            let exclude = f.val(2).to_string();
            let mk = |upper: bool, lower: bool, digits: bool, symbols: bool| AuvPassGenOptions {
                length: len,
                upper,
                lower,
                digits,
                symbols,
                exclude: exclude.clone(),
            };
            let opts = match f.val(1) {
                "2" => mk(true, true, true, false),
                "3" => mk(false, false, true, false),
                _ => mk(true, true, true, true),
            };
            match auv_pass_generate_password(&opts) {
                Ok(pw) => {
                    let bits = auv_pass_gen_entropy_bits(&opts).unwrap_or(0.0);
                    let pw_str = pw.to_string();
                    if let Screen::Form(f) = &mut app.screen {
                        f.gen_result = Some((pw_str, bits));
                    }
                    Ok(String::new()) // 留在表单显示结果
                }
                Err(e) => Err(e.to_string()),
            }
        }
        FormKind::ImportKdbx => {
            let path = f.val(0).to_string();
            let kf = non_empty(f.val(2));
            let s = app.session.as_mut().ok_or(auv_i18n_tr("error-no-vault"))?;
            let n = s
                .vault
                .import_kdbx(
                    std::path::Path::new(&path),
                    f.val(1).as_bytes(),
                    kf.as_deref().map(std::path::Path::new),
                )
                .map_err(|e| e.to_string())?;
            s.vault.save(&s.path).map_err(|e| e.to_string())?;
            Ok(auv_i18n_tr_fmt(
                "msg-imported-count",
                &[("count", &n.to_string())],
            ))
        }
        FormKind::ExportKdbx => {
            let path = f.val(0).to_string();
            if f.fields[1].value != f.fields[2].value {
                return Err(auv_i18n_tr("error-passwords-mismatch"));
            }
            let kf = non_empty(f.val(3));
            let s = app.session.as_ref().ok_or(auv_i18n_tr("error-no-vault"))?;
            let n = s
                .vault
                .export_kdbx(
                    std::path::Path::new(&path),
                    f.val(1).as_bytes(),
                    kf.as_deref().map(std::path::Path::new),
                )
                .map_err(|e| e.to_string())?;
            Ok(auv_i18n_tr_fmt(
                "msg-exported-count-path",
                &[("count", &n.to_string()), ("path", &path.clone())],
            ))
        }
    })();
    match res {
        Ok(msg) if msg.is_empty() => {} // 生成器:留在表单
        Ok(msg) => app.message(msg),
        Err(e) => app.message(format!("✗ {e}")),
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    /// 建内存测试库(低配 KDF 提速),含一条条目。
    fn app_with_vault() -> App {
        let kdf = AuvPassKdfParams {
            m_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let mut vault =
            AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &kdf).unwrap();
        vault
            .add_entry(AuvPassEntryInput {
                group: String::new(),
                title: "t1".into(),
                username: "u1".into(),
                password: Zeroizing::new("p1".to_string()),
                url: String::new(),
                notes: String::new(),
                totp: None,
            })
            .unwrap();
        let mut app = App::new();
        app.session = Some(Session {
            vault,
            path: std::path::PathBuf::new(),
        });
        app.screen = Screen::Main;
        app
    }

    /// z 键回归:表单屏按 z 必须录入输入框,不得被全局语言切换劫持。
    #[test]
    fn z_key_types_into_form_field() {
        let mut app = App::new();
        app.screen = Screen::Form(form_search());
        on_key(&mut app, key('z'));
        let Screen::Form(f) = &app.screen else {
            panic!("表单屏按 z 后应仍在表单屏");
        };
        assert_eq!(f.fields[0].value, "z", "z 应录入当前字段");
    }

    /// z 键对照:非表单屏(首页)按 z 仍切语言(弹消息屏)。
    #[test]
    fn z_key_toggles_language_outside_form() {
        let mut app = App::new();
        assert!(matches!(app.screen, Screen::Home));
        on_key(&mut app, key('z'));
        assert!(
            matches!(app.screen, Screen::Message(_)),
            "非表单屏按 z 应切语言并弹消息"
        );
        // 还原语言,避免污染同进程其他测试的断言
        auv_i18n::auv_i18n_set_lang(AuvI18nLang::ZhCn);
    }

    /// c 键回归:生成器表单的自由文本字段(排除字符)聚焦时,c 照常录入,不被复制劫持。
    #[test]
    fn generator_c_types_into_free_text_field() {
        let mut app = App::new();
        app.screen = Screen::Form(form_generator());
        if let Screen::Form(f) = &mut app.screen {
            f.gen_result = Some(("pw".to_string(), 100.0));
            f.selected = GENERATOR_FREE_TEXT_FIELD;
        }
        on_key(&mut app, key('c'));
        let Screen::Form(f) = &app.screen else {
            panic!("排除字符字段按 c 后应仍在表单屏(未触发复制)");
        };
        assert_eq!(
            f.fields[GENERATOR_FREE_TEXT_FIELD].value, "c",
            "c 应录入排除字符字段"
        );
    }

    /// c 键对照:生成器数值字段(长度)聚焦且有结果时,c 仍是复制快捷键(走复制路径 → 弹消息)。
    #[test]
    fn generator_c_copy_fires_on_numeric_field() {
        let mut app = App::new();
        app.screen = Screen::Form(form_generator());
        if let Screen::Form(f) = &mut app.screen {
            f.gen_result = Some(("pw".to_string(), 100.0));
            f.selected = 0; // 长度字段
        }
        on_key(&mut app, key('c'));
        assert!(
            matches!(app.screen, Screen::Message(_)),
            "数值字段聚焦时按 c 应触发复制并弹消息(剪贴板不可用则弹错误消息,同为 Message)"
        );
    }

    /// 搜索 0 命中回归:搜索模式下列表为空,不退回全量;退出搜索后恢复全量。
    #[test]
    fn search_zero_hits_shows_empty_list() {
        let mut app = app_with_vault();
        assert_eq!(app.visible_entry_ids().len(), 1, "普通浏览应见全部条目");
        app.search_active = true;
        app.search_cache.clear(); // 0 命中
        assert!(
            app.visible_entry_ids().is_empty(),
            "搜索 0 命中应显示空列表,不得退回全量"
        );
        app.search_active = false;
        assert_eq!(app.visible_entry_ids().len(), 1, "退出搜索应恢复全量");
    }
}
