// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use auv_i18n::{auv_i18n_lang, auv_i18n_lang_toggle, auv_i18n_tr, auv_i18n_tr_fmt, AuvI18nLang};
use auv_pass_engine::*;
use chrono::TimeZone as _;
use eframe::egui;
use rfd::FileDialog;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
/// 剪贴板自动清空秒数(安全红线:30 秒)。
pub const CLIPBOARD_CLEAR_SECS: u64 = 30;
/// 附件大文件提示阈值(100MB)。
const ATTACHMENT_WARN_BYTES: u64 = 100 * 1024 * 1024;

/// 人类可读字节数。
fn fmt_size(n: u64) -> String {
    let f = n as f64;
    if n >= 1024 * 1024 * 1024 {
        format!("{f:.1} GB")
    } else if n >= 1024 * 1024 {
        format!("{f:.1} MB")
    } else if n >= 1024 {
        format!("{f:.1} KB")
    } else {
        format!("{n} B")
    }
}
const AUTO_LOCK_AFTER: std::time::Duration = std::time::Duration::from_secs(600);
/// 剪贴板清除代数戳(epoch counter):每次复制 +1;
/// 延时清空线程只在自己仍是最新一代时才清(修竞态:旧线程不得清掉新复制的内容)。
static CLIPBOARD_EPOCH: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy, PartialEq)]
enum SortCol {
    Title,
    Username,
    Modified,
}
#[derive(Clone, Copy, PartialEq)]
enum SearchScope {
    All,
    Title,
    User,
    Url,
}
struct Session {
    vault: AuvPassVault,
    path: PathBuf,
}
struct ConfirmReq {
    key_name: String,
    reply: std::sync::mpsc::Sender<bool>,
}
struct AgentBridge {
    handle: AuvPassAgentHandle,
    rx: Receiver<ConfirmReq>,
}
enum UnlockMsg {
    Done(std::result::Result<Session, String>),
}
#[derive(PartialEq)]
enum Tab {
    Vault,
    Generator,
    Ssh,
}
#[derive(Clone)]
struct EditState {
    id: Option<AuvPassEntryId>,
    group: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    totp: String,
    old_totp: Option<AuvPassTotpConfig>,
}
#[derive(PartialEq)]
enum Modal {
    None,
    ImportKdbx,
    ExportKdbx,
    SshGenerate,
    SshImport,
    SshExport(AuvPassEntryId),
}
/// KDBX 导入预览(解析结果暂存,确认后才入库)
struct KdbxPreview {
    entries: usize,
    groups: usize,
    skipped: Vec<String>,
    path: String,
    pw: String,
    kf: String,
}
/// 覆盖确认中暂存的动作(目标文件已存在)
enum OverwriteAction {
    ExportKdbx {
        path: String,
        pw: String,
        kf: String,
    },
    SshExport {
        path: String,
        pem: zeroize::Zeroizing<String>,
    },
}
struct PassApp {
    session: Option<Session>,
    login_path: String,
    login_pw: String,
    login_pw2: String,
    login_keyfile: String,
    login_create: bool,
    login_algo: usize,
    unlock_rx: Option<Receiver<UnlockMsg>>,
    status: String,
    tab: Tab,
    search: String,
    search_scope: SearchScope,
    selected: Option<AuvPassEntryId>,
    show_plain: bool,
    selected_group: String,
    sort_col: SortCol,
    sort_asc: bool,
    /// 剪贴板倒计时起点与本次清除秒数(与实际清除语义一致;
    /// 非敏感复制 secs=0 时置 None——内容已被替换,旧清除线程因代数戳失效不会清)。
    clipboard_at: Option<(std::time::Instant, u64)>,
    edit: Option<EditState>,
    modal: Modal,
    gen_len: usize,
    gen_charset: usize,
    gen_exclude: String,
    gen_result: String,
    gen_bits: f64,
    m_path: String,
    m_pw: String,
    m_pw2: String,
    m_keyfile: String,
    m_name: String,
    agent: Option<AgentBridge>,
    agent_confirm: Option<ConfirmReq>,
    session_allowed: Arc<Mutex<Vec<AuvPassEntryId>>>,
    last_activity: std::time::Instant,
    show_qr: Option<String>,
    show_gen_opts: bool,
    show_about: bool,
    show_generator: bool,
    focus_search: bool,
    edit_tab: u8,
    last_title: String,
    save_error: Option<String>,
    save_check: Option<EditState>,
    kdbx_preview: Option<KdbxPreview>,
    overwrite: Option<OverwriteAction>,
    attach_confirm: Option<(AuvPassEntryId, PathBuf)>,
    show_change_pw: bool,
    show_props: bool,
    show_health: bool,
    dark_theme: bool,
    zoom_applied: bool,
    selected_set: std::collections::BTreeSet<AuvPassEntryId>,
    change_pw_old: String,
    change_pw_new: String,
    change_pw_new2: String,
    change_pw_keyfile: String,
}
impl Default for PassApp {
    fn default() -> Self {
        Self {
            session: None,
            login_path: String::new(),
            login_pw: String::new(),
            login_pw2: String::new(),
            login_keyfile: String::new(),
            login_create: false,
            login_algo: 0,
            unlock_rx: None,
            status: String::new(),
            tab: Tab::Vault,
            search: String::new(),
            search_scope: SearchScope::All,
            selected: None,
            show_plain: false,
            selected_group: String::new(),
            sort_col: SortCol::Title,
            sort_asc: true,
            clipboard_at: None,
            edit: None,
            modal: Modal::None,
            gen_len: 20,
            gen_charset: 0,
            gen_exclude: String::new(),
            gen_result: String::new(),
            gen_bits: 0.0,
            m_path: String::new(),
            m_pw: String::new(),
            m_pw2: String::new(),
            m_keyfile: String::new(),
            m_name: String::new(),
            agent: None,
            agent_confirm: None,
            session_allowed: Arc::new(Mutex::new(Vec::new())),
            last_activity: std::time::Instant::now(),
            show_qr: None,
            show_gen_opts: false,
            show_about: false,
            show_generator: false,
            focus_search: false,
            edit_tab: 0,
            last_title: String::new(),
            save_error: None,
            save_check: None,
            kdbx_preview: None,
            overwrite: None,
            attach_confirm: None,
            show_change_pw: false,
            show_props: false,
            show_health: false,
            dark_theme: true,
            zoom_applied: false,
            selected_set: std::collections::BTreeSet::new(),
            change_pw_old: String::new(),
            change_pw_new: String::new(),
            change_pw_new2: String::new(),
            change_pw_keyfile: String::new(),
        }
    }
}
fn browse_file() -> Option<String> {
    FileDialog::new()
        .pick_file()
        .map(|p| p.display().to_string())
}
fn browse_save(default: &str) -> Option<String> {
    FileDialog::new()
        .set_file_name(default)
        .save_file()
        .map(|p| p.display().to_string())
}
fn scan_qr(path: &str) -> Option<String> {
    let img = image::open(path).ok()?;
    bardecoder::default_decoder()
        .decode(&img)
        .into_iter()
        .next()?
        .ok()
}
fn clipboard_copy(text: &str, secs: u64) -> std::result::Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(text.to_string()).map_err(|e| e.to_string())?;
    let epoch = CLIPBOARD_EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
    if secs > 0 {
        let owned = text.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            let now = CLIPBOARD_EPOCH.load(Ordering::SeqCst);
            if let Ok(mut cb) = arboard::Clipboard::new() {
                // 代数戳 + 读回比对(read-back compare)双校验:只清自己写入的、且期间无更新复制
                let readback = cb.get_text().ok();
                if auv_pass_clipboard_should_clear(epoch, now, &owned, readback.as_deref()) {
                    let _ = cb.set_text("");
                }
            }
        });
    }
    Ok(())
}
/// 本帧是否有真实用户输入(指针移动/按键/滚轮/触摸/文本/IME/缩放手势)。
/// 自动锁定的活动判定以此为准:定时 request_repaint_after 重绘不算活动。
fn auv_pass_has_user_input_events(events: &[egui::Event]) -> bool {
    events.iter().any(|ev| {
        matches!(
            ev,
            egui::Event::PointerMoved(_)
                | egui::Event::PointerButton { .. }
                | egui::Event::MouseWheel { .. }
                | egui::Event::Key { .. }
                | egui::Event::Text(_)
                | egui::Event::Touch { .. }
                | egui::Event::Ime(_)
                | egui::Event::Zoom(_)
                | egui::Event::Rotate(_)
        )
    })
}
fn fmt_time(sec: i64) -> String {
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
fn new_edit(id: Option<AuvPassEntryId>) -> EditState {
    EditState {
        id,
        group: String::new(),
        title: String::new(),
        username: String::new(),
        password: String::new(),
        url: String::new(),
        notes: String::new(),
        totp: String::new(),
        old_totp: None,
    }
}
fn edit_from(e: &AuvPassEntry) -> EditState {
    EditState {
        id: Some(e.id),
        group: e.group.clone(),
        title: e.title.clone(),
        username: e.username.clone(),
        password: String::new(),
        url: e.url.clone(),
        notes: e.notes.clone(),
        totp: String::new(),
        old_totp: e.totp.clone(),
    }
}
fn parse_totp(s: &str, old: Option<AuvPassTotpConfig>) -> Option<AuvPassTotpConfig> {
    let s = s.trim();
    if s.is_empty() {
        return old;
    }
    if s == "-" {
        return None;
    }
    if s.starts_with("otpauth://") {
        auv_pass_totp_parse_otpauth(s).ok()
    } else {
        let c = AuvPassTotpConfig {
            secret: s.to_string(),
            ..Default::default()
        };
        c.validate().ok().map(|_| c)
    }
}
fn pw_strength(pw: &str) -> f64 {
    if pw.is_empty() {
        return 0.0;
    }
    let mut cs = 0usize;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        cs += 26
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        cs += 26
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        cs += 10
    }
    if pw.chars().any(|c| !c.is_alphanumeric()) {
        cs += 32
    }
    (pw.len() as f64) * (cs.max(1) as f64).log2()
}
fn strength_color(b: f64) -> egui::Color32 {
    if b < 40.0 {
        egui::Color32::from_rgb(220, 80, 80)
    } else if b < 70.0 {
        egui::Color32::from_rgb(230, 180, 60)
    } else if b < 100.0 {
        egui::Color32::from_rgb(100, 200, 100)
    } else {
        egui::Color32::from_rgb(80, 180, 255)
    }
}
impl PassApp {
    fn start_unlock(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel();
        let path = self.login_path.trim().to_string();
        let pw = self.login_pw.clone();
        let kf = self.login_keyfile.trim().to_string();
        let kfp = if kf.is_empty() {
            None
        } else {
            Some(PathBuf::from(kf))
        };
        let create = self.login_create;
        let algo = self.login_algo;
        self.status = auv_i18n_tr("label-deriving-key");
        std::thread::spawn(move || {
            let res = if create {
                AuvPassVault::create(
                    pw.as_bytes(),
                    kfp.as_deref(),
                    match algo {
                        1 => AuvPassCipherAlgo::ChaCha20Poly1305,
                        2 => AuvPassCipherAlgo::Sm4Gcm,
                        _ => AuvPassCipherAlgo::Aes256Gcm,
                    },
                    &AuvPassKdfParams::default(),
                )
                .and_then(|v| {
                    let p = PathBuf::from(&path);
                    v.save(&p).map(|_| Session { vault: v, path: p })
                })
            } else {
                AuvPassVault::open(std::path::Path::new(&path), pw.as_bytes(), kfp.as_deref()).map(
                    |v| Session {
                        vault: v,
                        path: path.into(),
                    },
                )
            };
            let _ = tx.send(UnlockMsg::Done(res.map_err(|e| e.to_string())));
        });
        self.unlock_rx = Some(rx);
    }
    /// 复制到剪贴板并同步状态栏倒计时语义:
    /// 成功且 secs>0 → 亮倒计时(secs 秒);成功且 secs=0(非敏感复制)→ 灭倒计时
    /// (内容已被替换,旧清除线程因代数戳失效不会清);失败 → 报错、不动倒计时。
    fn copy_clipboard(&mut self, text: &str, secs: u64) {
        match clipboard_copy(text, secs) {
            Ok(()) => {
                self.clipboard_at = if secs > 0 {
                    Some((std::time::Instant::now(), secs))
                } else {
                    None
                };
            }
            Err(e) => {
                self.status = auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &e)]);
            }
        }
    }
    /// 立即清空剪贴板(手动兑底)。
    fn clear_clipboard_now(&mut self) {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(String::new());
            CLIPBOARD_EPOCH.fetch_add(1, Ordering::SeqCst);
        }
        self.clipboard_at = None;
        self.status = auv_i18n_tr("msg-clipboard-cleared");
    }
    /// 复制选中条目的字段(0=用户名,非敏感不清;1=密码,30 秒清)。
    fn copy_selected_field(&mut self, field: u8) {
        let v = self
            .session
            .as_ref()
            .and_then(|s| self.selected.and_then(|id| s.vault.get_entry(id)))
            .map(|e| {
                if field == 0 {
                    e.username.clone()
                } else {
                    e.password.as_str().to_string()
                }
            });
        if let Some(v) = v {
            if field == 0 {
                self.copy_clipboard(&v, 0);
            } else {
                self.copy_clipboard(&v, CLIPBOARD_CLEAR_SECS);
            }
        }
    }
    /// 保存当前库——失败绝不静默(磁盘满/权限拒绝必须弹窗)。
    /// 先做空间预检:原子写约需「现库体积×2」(新库按 10 MiB 估)。
    fn save_session(&mut self) -> bool {
        let Some(s) = &self.session else { return false };
        let path = s.path.clone();
        let cur = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let needed = std::cmp::max(cur * 2, 10 * 1024 * 1024);
        if let Ok(free) = fs2::available_space(&path) {
            if free < needed {
                self.save_error = Some(auv_i18n_tr_fmt(
                    "error-disk-space",
                    &[("need", &needed.to_string()), ("free", &free.to_string())],
                ));
                return false;
            }
        }
        match self.session.as_mut().map(|s| s.vault.save(&s.path)) {
            Some(Ok(())) => true,
            Some(Err(e)) => {
                self.save_error = Some(e.to_string());
                false
            }
            None => false,
        }
    }
    fn lock(&mut self) {
        self.session = None;
        self.selected = None;
        self.search.clear();
        self.login_pw.clear();
        self.login_pw2.clear();
        if let Some(b) = self.agent.take() {
            b.handle.stop();
        }
        self.session_allowed.lock().unwrap().clear();
        self.status = auv_i18n_tr("msg-locked");
    }
    fn filtered_entries(&self) -> Vec<AuvPassEntryId> {
        let Some(s) = &self.session else {
            return vec![];
        };
        let q = self.search.trim().to_lowercase();
        let mut ids: Vec<AuvPassEntryId> = s
            .vault
            .entries()
            .iter()
            .filter(|e| match self.selected_group.as_str() {
                "" => true,
                "?" => e.notes.contains("?"),
                "X" => e.group == "X",
                g => e.group == g,
            })
            .filter(|e| {
                if q.is_empty() {
                    true
                } else {
                    match self.search_scope {
                        SearchScope::All => {
                            e.title.to_lowercase().contains(&q)
                                || e.username.to_lowercase().contains(&q)
                                || e.url.to_lowercase().contains(&q)
                                || e.notes.to_lowercase().contains(&q)
                                || e.group.to_lowercase().contains(&q)
                        }
                        SearchScope::Title => e.title.to_lowercase().contains(&q),
                        SearchScope::User => e.username.to_lowercase().contains(&q),
                        SearchScope::Url => e.url.to_lowercase().contains(&q),
                    }
                }
            })
            .map(|e| e.id)
            .collect();
        ids.sort_by(|a, b| {
            let ea = s.vault.get_entry(*a);
            let eb = s.vault.get_entry(*b);
            let ord = match self.sort_col {
                SortCol::Title => ea
                    .map(|e| e.title.clone())
                    .unwrap_or_default()
                    .cmp(&eb.map(|e| e.title.clone()).unwrap_or_default()),
                SortCol::Username => ea
                    .map(|e| e.username.clone())
                    .unwrap_or_default()
                    .cmp(&eb.map(|e| e.username.clone()).unwrap_or_default()),
                SortCol::Modified => ea
                    .map(|e| e.modified)
                    .unwrap_or(0)
                    .cmp(&eb.map(|e| e.modified).unwrap_or(0)),
            };
            if self.sort_asc {
                ord
            } else {
                ord.reverse()
            }
        });
        ids
    }
    fn toggle_agent(&mut self) {
        if self.agent.is_some() {
            if let Some(b) = self.agent.take() {
                b.handle.stop();
            }
            self.status = auv_i18n_tr("msg-agent-stopped");
            return;
        }
        let Some(s) = &self.session else { return };
        let keys = s.vault.ssh_exposed_keys();
        if keys.is_empty() {
            self.status = auv_i18n_tr("msg-no-exposed-keys");
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel::<ConfirmReq>();
        let allowed = self.session_allowed.clone();
        let confirm = move |key: &AuvPassSshKey, _d: &[u8]| -> bool {
            if allowed.lock().unwrap().contains(&key.id) {
                return true;
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
        match auv_pass_agent_start(keys, &auv_pass_agent_default_socket(), Box::new(confirm)) {
            Ok(handle) => {
                let sock = handle.socket.clone();
                self.agent = Some(AgentBridge { handle, rx });
                self.status = auv_i18n_tr_fmt("msg-agent-started", &[("socket", &sock)]);
            }
            Err(e) => {
                self.status =
                    auv_i18n_tr_fmt("error-agent-start-failed", &[("err", &e.to_string())])
            }
        }
    }

    /// 顶部菜单栏(文件/条目/工具/帮助)。
    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // 菜单栏样式:紧凑间距 + 宽按钮 + 略大字体
            ui.style_mut().spacing.item_spacing.x = 2.0;
            ui.style_mut().spacing.button_padding = egui::vec2(14.0, 5.0);
            let mt = |key: &str| egui::RichText::new(auv_i18n_tr(key)).size(16.0);

            let busy = self.unlock_rx.is_some();
            let unlocked = self.session.is_some();

            // 文件:打开库/新建库/锁定/退出
            ui.menu_button(mt("menu-file"), |ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new(auv_i18n_tr("menu-open-vault")))
                    .clicked()
                {
                    self.back_to_login(false);
                    ui.close();
                }
                if ui
                    .add_enabled(!busy, egui::Button::new(auv_i18n_tr("menu-new-vault")))
                    .clicked()
                {
                    self.back_to_login(true);
                    ui.close();
                }
                ui.separator();
                if ui
                    .add_enabled(unlocked, egui::Button::new(auv_i18n_tr("btn-lock")))
                    .clicked()
                {
                    self.lock();
                    ui.close();
                }
                ui.separator();
                if ui
                    .add_enabled(
                        unlocked,
                        egui::Button::new(auv_i18n_tr("menu-change-password")),
                    )
                    .clicked()
                {
                    self.change_pw_old.clear();
                    self.change_pw_new.clear();
                    self.change_pw_new2.clear();
                    self.change_pw_keyfile.clear();
                    self.show_change_pw = true;
                    ui.close();
                }
                ui.separator();
                if ui.button(auv_i18n_tr("btn-quit")).clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    ui.close();
                }
            });

            // 条目:新增/编辑选中/删除选中(回收站语义)/KDBX 导入导出
            ui.menu_button(mt("menu-entries"), |ui| {
                let sel = self.selected;
                let entry_ok = match (&self.session, sel) {
                    (Some(s), Some(id)) => s.vault.get_entry(id).is_some(),
                    _ => false,
                };
                if ui
                    .add_enabled(unlocked, egui::Button::new(auv_i18n_tr("menu-entry-new")))
                    .clicked()
                {
                    self.edit = Some(new_edit(None));
                    ui.close();
                }
                if ui
                    .add_enabled(entry_ok, egui::Button::new(auv_i18n_tr("menu-entry-edit")))
                    .clicked()
                {
                    let e = self
                        .session
                        .as_ref()
                        .and_then(|s| sel.and_then(|id| s.vault.get_entry(id)))
                        .cloned();
                    if let Some(e) = e {
                        self.edit = Some(edit_from(&e));
                    }
                    ui.close();
                }
                if ui
                    .add_enabled(
                        entry_ok,
                        egui::Button::new(auv_i18n_tr("menu-entry-delete")),
                    )
                    .clicked()
                {
                    self.trash_selected();
                    ui.close();
                }
                ui.separator();
                if ui
                    .add_enabled(unlocked, egui::Button::new(auv_i18n_tr("btn-import-kdbx")))
                    .clicked()
                {
                    self.modal = Modal::ImportKdbx;
                    self.m_path.clear();
                    self.m_pw.clear();
                    self.m_keyfile.clear();
                    ui.close();
                }
                if ui
                    .add_enabled(unlocked, egui::Button::new(auv_i18n_tr("btn-export-kdbx")))
                    .clicked()
                {
                    self.modal = Modal::ExportKdbx;
                    self.m_path.clear();
                    self.m_pw.clear();
                    self.m_pw2.clear();
                    self.m_keyfile.clear();
                    ui.close();
                }
            });

            // 工具:生成器/SSH 钥匙(切标签)/语言切换
            ui.menu_button(mt("menu-tools"), |ui| {
                if ui.button(auv_i18n_tr("menu-generator")).clicked() {
                    // 未开库也可用生成器(纯本地无状态):弹独立窗口
                    if unlocked {
                        self.tab = Tab::Generator;
                    } else {
                        self.show_generator = true;
                    }
                    ui.close();
                }
                if ui
                    .add_enabled(unlocked, egui::Button::new(auv_i18n_tr("menu-ssh-keys")))
                    .clicked()
                {
                    self.tab = Tab::Ssh;
                    ui.close();
                }
                ui.separator();
                // 语言切换:菜单项显示目标语言名(当前中文 → English;当前英文 → 中文)
                if ui
                    .button(match auv_i18n_lang() {
                        AuvI18nLang::En => "中文",
                        AuvI18nLang::ZhCn => "English",
                    })
                    .clicked()
                {
                    auv_i18n_lang_toggle();
                    ui.close();
                }
                ui.separator();
                if ui
                    .add_enabled(
                        unlocked,
                        egui::Button::new(auv_i18n_tr("menu-vault-properties")),
                    )
                    .clicked()
                {
                    self.show_props = true;
                    ui.close();
                }
                if ui
                    .add_enabled(
                        unlocked,
                        egui::Button::new(auv_i18n_tr("menu-health-report")),
                    )
                    .clicked()
                {
                    self.show_health = true;
                    ui.close();
                }
                ui.separator();
                if ui
                    .button(match self.dark_theme {
                        true => auv_i18n_tr("menu-light-theme"),
                        false => auv_i18n_tr("menu-dark-theme"),
                    })
                    .clicked()
                {
                    self.dark_theme = !self.dark_theme;
                    ui.close();
                }
            });

            // 帮助:关于
            ui.menu_button(mt("menu-help"), |ui| {
                if ui.button(auv_i18n_tr("menu-about")).clicked() {
                    self.show_about = true;
                    ui.close();
                }
            });
        });
    }

    /// 菜单「打开库/新建库」:回登录页(等效锁定,但不弹"已锁定"状态字)。
    fn back_to_login(&mut self, create: bool) {
        self.lock();
        self.status.clear();
        self.login_create = create;
    }

    /// 删除选中条目(与详情面板「删除」同语义:移入回收站组 "X")。
    fn trash_selected(&mut self) {
        let Some(id) = self.selected else { return };
        let Some(s) = self.session.as_ref() else {
            return;
        };
        let Some(e) = s.vault.get_entry(id) else {
            return;
        };
        let input = AuvPassEntryInput {
            group: "X".into(),
            title: e.title.clone(),
            username: e.username.clone(),
            password: e.password.clone(),
            url: e.url.clone(),
            notes: e.notes.clone(),
            totp: e.totp.clone(),
        };
        if let Some(s) = self.session.as_mut() {
            let _ = s.vault.update_entry(id, input);
        }
        self.save_session();
        self.selected = None;
    }
}

impl eframe::App for PassApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // 活动判定:仅真实输入事件刷新 last_activity;此前每帧无条件刷新,
        // TOTP 面板每秒 request_repaint_after(1s) 的重绘会把自动锁定永久废掉。
        if ui
            .ctx()
            .input(|i| auv_pass_has_user_input_events(&i.raw.events))
        {
            self.last_activity = std::time::Instant::now();
        }
        if let Some(rx) = &self.unlock_rx {
            if let Ok(msg) = rx.try_recv() {
                self.unlock_rx = None;
                match msg {
                    UnlockMsg::Done(Ok(s)) => {
                        let n = s.vault.entry_count();
                        self.status =
                            auv_i18n_tr_fmt("msg-unlocked-count", &[("count", &n.to_string())]);
                        self.session = Some(s);
                    }
                    UnlockMsg::Done(Err(e)) => self.status = format!("X {e}"),
                }
            } else {
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(80));
            }
        }
        let mut reqs = Vec::new();
        if let Some(b) = &self.agent {
            while let Ok(r) = b.rx.try_recv() {
                reqs.push(r);
            }
        }
        if let Some(r) = reqs.into_iter().next() {
            self.agent_confirm = Some(r);
        }
        // 窗口标题:库文件名/锁定状态(任务栏可辨识)
        let title = match &self.session {
            Some(s) => format!(
                "auv-pass — {}",
                s.path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default()
            ),
            None => format!("auv-pass — {}", auv_i18n_tr("title-locked")),
        };
        if title != self.last_title {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
            self.last_title = title;
        }
        // 键盘快捷键:Ctrl+N 新增 / Ctrl+F 搜索 / Ctrl+C 复制密码 / Ctrl+L 锁定
        if self.session.is_some() {
            let (n, f, c, l) = ui.ctx().input(|i| {
                (
                    i.modifiers.ctrl && i.key_pressed(egui::Key::N),
                    i.modifiers.ctrl && i.key_pressed(egui::Key::F),
                    i.modifiers.ctrl && i.key_pressed(egui::Key::C),
                    i.modifiers.ctrl && i.key_pressed(egui::Key::L),
                )
            });
            if n && self.edit.is_none() && self.save_check.is_none() {
                self.edit = Some(new_edit(None));
                self.edit_tab = 0;
            }
            if f && self.tab == Tab::Vault {
                self.focus_search = true;
            }
            if c && self.edit.is_none() && self.selected.is_some() {
                self.copy_selected_field(1);
            }
            if l {
                self.lock();
            }
        }
        // 拖拽文件 → 附加为选中条目的附件
        if self.session.is_some() && self.tab == Tab::Vault && self.edit.is_none() {
            let dropped: Vec<PathBuf> = ui.ctx().input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .collect()
            });
            if !dropped.is_empty() {
                if let Some(sel) = self.selected {
                    for p in dropped {
                        let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                        if size > ATTACHMENT_WARN_BYTES {
                            self.attach_confirm = Some((sel, p));
                        } else {
                            self.attach_file(sel, &p);
                        }
                    }
                } else {
                    self.status = auv_i18n_tr("attach-drop-hint");
                }
            }
        }
        // 主题:每帧应用（暗色偏深,不刺眼;亮色标准）
        if self.dark_theme {
            let mut v = egui::Visuals::dark();
            v.panel_fill = egui::Color32::from_rgb(18, 18, 22);
            v.window_fill = egui::Color32::from_rgb(24, 24, 30);
            v.extreme_bg_color = egui::Color32::from_rgb(12, 12, 16);
            ui.ctx().set_visuals(v);
        } else {
            ui.ctx().set_visuals(egui::Visuals::light());
        }
        // 字体:首帧一次性放大 15%(比系统默认略大;不暴露调节入口)
        if !self.zoom_applied {
            let native = ui.ctx().pixels_per_point();
            ui.ctx().set_pixels_per_point(native * 1.15);
            self.zoom_applied = true;
        }
        egui::CentralPanel::default().show(ui, |ui| {
            // 顶部菜单栏(文件/条目/工具/帮助)
            egui::containers::Panel::top("auv-pass-menubar")
                .frame(egui::Frame::NONE)
                .show(ui, |ui| self.menu_bar(ui));
            // 底部状态栏:固定 22px(先占位,内容再画)
            egui::containers::Panel::bottom("auv-pass-status")
                .exact_size(22.0)
                .frame(egui::Frame::NONE)
                .show(ui, |ui| self.status_bar(ui));
            // 详情面板:竖排字段栈,可拖拽(仅密码库标签且已解锁)
            if self.session.is_some() && self.tab == Tab::Vault {
                let avail = ui.available_height();
                let default_h = (avail * 0.40).clamp(180.0, 420.0);
                let max_h = (avail * 0.75).max(200.0);
                egui::containers::Panel::bottom("auv-pass-detail")
                    .resizable(true)
                    .default_size(default_h)
                    .size_range(140.0..=max_h)
                    .show(ui, |ui| self.detail_pane(ui));
            }
            // 左侧分组树:固定宽度(去掉 resizable 拖拽分隔线,避免竖线过界)
            if self.session.is_some() && self.tab == Tab::Vault {
                egui::containers::Panel::left("auv-pass-groups")
                    .exact_size(200.0)
                    .frame(egui::Frame::NONE)
                    .show(ui, |ui| self.group_tree(ui));
            }
            if self.session.is_none() {
                self.login_pane(ui);
                return;
            }
            self.toolbar(ui);
            ui.separator();
            // 批量操作条（多选时显示）
            if self.selected_set.len() > 1 {
                ui.horizontal(|ui| {
                    ui.label(format!("{}", self.selected_set.len()));
                    if ui.button(auv_i18n_tr("btn-delete")).clicked() {
                        self.batch_trash();
                    }
                });
                ui.separator();
            }
            match self.tab {
                Tab::Vault => self.vault_tab(ui),
                Tab::Generator => self.generator_tab(ui),
                Tab::Ssh => self.ssh_tab(ui),
            }
            self.edit_window(ui.ctx());
        });
        if self.session.is_some()
            && self.last_activity.elapsed() > AUTO_LOCK_AFTER
            && self.agent.is_none()
        {
            self.lock();
        }
        self.modals(ui.ctx());
        self.agent_confirm_popup(ui.ctx());
        self.extra_dialogs(ui.ctx());
        self.change_pw_dialog(ui.ctx());
        self.props_dialog(ui.ctx());
        self.health_report_dialog(ui.ctx());
        // 「关于」窗口
        if self.show_about {
            egui::Window::new(auv_i18n_tr("menu-about"))
                .collapsible(false)
                .open(&mut self.show_about)
                .show(ui.ctx(), |ui| {
                    ui.heading("auv-pass");
                    ui.label("Authenticated User Vault, for Password");
                    ui.separator();
                    ui.label(auv_i18n_tr_fmt(
                        "about-version",
                        &[("version", env!("CARGO_PKG_VERSION"))],
                    ));
                    ui.label(egui::RichText::new("Keep dark. Stay light.").weak());
                    ui.label(egui::RichText::new("守之以暗，行之以轻").weak().italics());
                    ui.label("MulanPSL-2.0 OR Apache-2.0");
                    ui.label(auv_i18n_tr("about-copyright"));
                });
        }
        // 开库前生成器窗口(纯本地无状态;未开库时也可用)
        if self.show_generator {
            let mut open = true;
            egui::Window::new(auv_i18n_tr("menu-password-generator"))
                .collapsible(false)
                .open(&mut open)
                .show(ui.ctx(), |ui| self.generator_ui(ui));
            if !open {
                self.show_generator = false;
            }
        }
        // TOTP 二维码显示窗
        if let Some(uri) = self.show_qr.clone() {
            let mut open = true;
            egui::Window::new(auv_i18n_tr("dialog-totp-qr"))
                .open(&mut open)
                .show(ui.ctx(), |ui| {
                    if let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) {
                        let w = code.width();
                        let scale = 8usize;
                        let quiet = 4usize;
                        let total = (w + quiet * 2) * scale;
                        let mut px = vec![255u8; total * total * 4];
                        for y in 0..w {
                            for x in 0..w {
                                if code[(x, y)] == qrcode::Color::Dark {
                                    for py in 0..scale {
                                        for pxx in 0..scale {
                                            let ox = ((x + quiet) * scale + pxx) * 4;
                                            let oy = ((y + quiet) * scale + py) * 4 * total;
                                            for ch in 0..3 {
                                                px[oy + ox + ch] = 0;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let color = egui::ColorImage::from_rgba_unmultiplied([total, total], &px);
                        let tex = ui.ctx().load_texture(
                            "qr-totp",
                            color,
                            egui::TextureOptions::default(),
                        );
                        ui.image(egui::load::SizedTexture::new(
                            tex.id(),
                            egui::vec2(256.0, 256.0),
                        ));
                        ui.label(
                            egui::RichText::new(auv_i18n_tr("hint-totp-scan"))
                                .small()
                                .weak(),
                        );
                    } else {
                        ui.label(auv_i18n_tr("error-qr-generate"));
                    }
                });
            if !open {
                self.show_qr = None;
            }
        }
    }
}
impl PassApp {
    fn status_bar(&mut self, ui: &mut egui::Ui) {
        // 先取值再进闭包,避免与 clipboard_at 写入交叉借用
        let info = self
            .session
            .as_ref()
            .map(|s| (s.path.display().to_string(), s.vault.entry_count()));
        let agent_on = self.agent.is_some();
        let lock_rem = if agent_on || self.session.is_none() {
            None
        } else {
            Some(AUTO_LOCK_AFTER.saturating_sub(self.last_activity.elapsed()))
        };
        ui.horizontal_centered(|ui| {
            if let Some((path, n)) = &info {
                ui.label(egui::RichText::new(path).small().weak());
                ui.separator();
                ui.label(
                    egui::RichText::new(auv_i18n_tr_fmt(
                        "label-entry-count",
                        &[("count", &n.to_string())],
                    ))
                    .small()
                    .weak(),
                );
                ui.separator();
            }
            if agent_on {
                ui.label(
                    egui::RichText::new(auv_i18n_tr("status-agent-active"))
                        .small()
                        .color(egui::Color32::from_rgb(100, 200, 120)),
                );
                ui.separator();
            } else if let Some(rem) = lock_rem {
                let secs = rem.as_secs();
                ui.label(
                    egui::RichText::new(auv_i18n_tr_fmt(
                        "status-lock-countdown",
                        &[("time", &format!("{}:{:02}", secs / 60, secs % 60))],
                    ))
                    .small()
                    .weak(),
                );
                ui.separator();
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(500));
            }
            if let Some((at, secs)) = self.clipboard_at {
                let el = at.elapsed().as_secs();
                if el < secs {
                    let rem = secs - el;
                    let fr = rem as f32 / secs as f32;
                    ui.colored_label(egui::Color32::from_rgb(230, 180, 60), format!("{rem}s"));
                    ui.add(egui::ProgressBar::new(fr).desired_width(60.0));
                    // 倒计时激活期间每秒重绘(不影响自动锁定:活动判定只看真实输入事件)
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_secs(1));
                } else {
                    self.clipboard_at = None;
                }
            }
            if !self.status.is_empty() {
                ui.label(egui::RichText::new(&self.status).small().weak());
            }
        });
    }
    fn login_pane(&mut self, ui: &mut egui::Ui) {
        ui.add_space(30.0);
        ui.vertical_centered(|ui| {
            ui.heading("Authenticated User Vault, for Password");
            ui.label(
                egui::RichText::new("Keep dark. Stay light.  守之以暗，行之以轻")
                    .weak()
                    .italics(),
            );
            ui.add_space(12.0);
        });
        egui::Grid::new("login").num_columns(2).show(ui, |ui| {
            ui.label(auv_i18n_tr("label-vault-file"));
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.login_path);
                if ui.small_button("...").clicked() {
                    if let Some(p) = browse_file() {
                        self.login_path = p;
                    }
                }
            });
            ui.end_row();
            ui.label(auv_i18n_tr("label-master-password"));
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.login_pw)
                        .password(true)
                        .desired_width(300.0),
                );
                // 新建库:主密码可直接生成(重复栏需手动再输入,确认持有)
                if self.login_create && ui.small_button("Gen").clicked() {
                    let opts = AuvPassGenOptions {
                        length: self.gen_len,
                        upper: self.gen_charset != 2,
                        lower: self.gen_charset != 2,
                        digits: true,
                        symbols: self.gen_charset == 0,
                        exclude: self.gen_exclude.trim().to_string(),
                    };
                    if let Ok(pw) = auv_pass_generate_password(&opts) {
                        self.login_pw = pw.to_string();
                        self.login_pw2.clear();
                        self.status = auv_i18n_tr("msg-master-pw-generated");
                    }
                }
            });
            ui.end_row();
            if self.login_create {
                ui.label(auv_i18n_tr("label-repeat-master-password"));
                ui.add(egui::TextEdit::singleline(&mut self.login_pw2).password(true));
                ui.end_row();
                // 主密码强度评估(新建库时提示弱密码)
                if !self.login_pw.is_empty() {
                    let b = pw_strength(&self.login_pw);
                    let f = (b / 130.0).min(1.0) as f32;
                    ui.label("");
                    ui.add(
                        egui::ProgressBar::new(f)
                            .desired_width(200.0)
                            .text(format!("{b:.0}b"))
                            .fill(strength_color(b)),
                    );
                    ui.end_row();
                }
                ui.label(auv_i18n_tr("label-algorithm"));
                egui::ComboBox::from_id_salt("algo")
                    .selected_text(match self.login_algo {
                        1 => "ChaCha20".to_string(),
                        2 => "SM4-GCM".to_string(),
                        _ => "AES-256-GCM".to_string(),
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.login_algo, 0, "AES-256-GCM");
                        ui.selectable_value(&mut self.login_algo, 1, "ChaCha20");
                        ui.selectable_value(&mut self.login_algo, 2, "SM4-GCM");
                    });
                ui.end_row();
            }
            ui.label(auv_i18n_tr("label-key-file"));
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.login_keyfile);
                if ui.small_button("...").clicked() {
                    if let Some(p) = browse_file() {
                        self.login_keyfile = p;
                    }
                }
            });
            ui.end_row();
        });
        ui.add_space(6.0);
        ui.checkbox(&mut self.login_create, auv_i18n_tr("btn-new-vault"));
        ui.add_space(6.0);
        let busy = self.unlock_rx.is_some();
        if ui
            .add_enabled(
                !busy,
                egui::Button::new(if self.login_create {
                    auv_i18n_tr("btn-create-enter")
                } else {
                    auv_i18n_tr("btn-unlock")
                })
                .min_size([140.0, 32.0].into()),
            )
            .clicked()
        {
            if self.login_create && self.login_pw != self.login_pw2 {
                self.status = auv_i18n_tr("error-passwords-mismatch-2");
            } else {
                self.start_unlock();
            }
        }
        ui.add_space(8.0);
        // 开库前也可用生成器(与 TUI 首页行为一致)
        if ui
            .button(egui::RichText::new(auv_i18n_tr("login-generator-hint")).small())
            .clicked()
        {
            self.show_generator = true;
        }
    }
    /// 工具栏:高频动作一排(新增/编辑/删除 | 复制用户名/密码/清空剪贴板;右侧:版本/锁定)
    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let entry_ok = match (&self.session, self.selected) {
                (Some(s), Some(id)) => s.vault.get_entry(id).is_some(),
                _ => false,
            };
            if ui.button(auv_i18n_tr("btn-add")).clicked() {
                self.edit = Some(new_edit(None));
                self.edit_tab = 0;
            }
            if ui
                .add_enabled(entry_ok, egui::Button::new(auv_i18n_tr("btn-edit")))
                .clicked()
            {
                let e = self
                    .session
                    .as_ref()
                    .and_then(|s| self.selected.and_then(|id| s.vault.get_entry(id)))
                    .cloned();
                if let Some(e) = e {
                    self.edit = Some(edit_from(&e));
                    self.edit_tab = 0;
                }
            }
            if ui
                .add_enabled(entry_ok, egui::Button::new(auv_i18n_tr("btn-delete")))
                .clicked()
            {
                self.trash_selected();
            }
            ui.separator();
            if ui
                .add_enabled(
                    entry_ok,
                    egui::Button::new(auv_i18n_tr("toolbar-copy-username")),
                )
                .clicked()
            {
                self.copy_selected_field(0);
            }
            if ui
                .add_enabled(
                    entry_ok,
                    egui::Button::new(auv_i18n_tr("toolbar-copy-password")),
                )
                .clicked()
            {
                self.copy_selected_field(1);
            }
            if ui.button(auv_i18n_tr("toolbar-clear-clipboard")).clicked() {
                self.clear_clipboard_now();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(auv_i18n_tr("btn-lock")).clicked() {
                    self.lock();
                }
                ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).weak());
            });
        });
    }
    fn vault_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let se = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text(auv_i18n_tr("label-search"))
                    .desired_width(180.0)
                    .id(egui::Id::new("auv-pass-search")),
            );
            if self.focus_search {
                se.request_focus();
                self.focus_search = false;
            }
            if ui.small_button("S").clicked() {
                self.search_scope = match self.search_scope {
                    SearchScope::All => SearchScope::Title,
                    SearchScope::Title => SearchScope::User,
                    SearchScope::User => SearchScope::Url,
                    SearchScope::Url => SearchScope::All,
                };
            }
            ui.separator();
            if ui.button(auv_i18n_tr("btn-import-kdbx")).clicked() {
                self.modal = Modal::ImportKdbx;
                self.m_path.clear();
                self.m_pw.clear();
                self.m_keyfile.clear();
            }
            if ui.button(auv_i18n_tr("btn-export-kdbx")).clicked() {
                self.modal = Modal::ExportKdbx;
                self.m_path.clear();
                self.m_pw.clear();
                self.m_pw2.clear();
                self.m_keyfile.clear();
            }
        });
        ui.add_space(4.0);
        // 空库引导
        let empty = self
            .session
            .as_ref()
            .map(|s| s.vault.entry_count() == 0)
            .unwrap_or(false);
        if empty {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                ui.label(egui::RichText::new(auv_i18n_tr("empty-vault-hint")).weak());
                ui.add_space(24.0);
            });
        }
        self.entry_table(ui);
    }
    fn group_tree(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.strong(egui::RichText::new(auv_i18n_tr("label-groups")).size(16.0));
            let s = self.session.as_ref().unwrap();
            let all_sel = self.selected_group.is_empty();
            if ui
                .selectable_label(
                    all_sel,
                    auv_i18n_tr_fmt(
                        "group-all-count",
                        &[("count", &s.vault.entry_count().to_string())],
                    ),
                )
                .clicked()
            {
                self.selected_group.clear();
            }
            let fav = s
                .vault
                .entries()
                .iter()
                .filter(|e| e.notes.contains("?"))
                .count();
            if ui
                .selectable_label(
                    self.selected_group == "?",
                    auv_i18n_tr_fmt("group-favorites-count", &[("count", &fav.to_string())]),
                )
                .clicked()
            {
                self.selected_group = "?".into();
            }
            let trash = s.vault.entries().iter().filter(|e| e.group == "X").count();
            if ui
                .selectable_label(
                    self.selected_group == "X",
                    auv_i18n_tr_fmt("group-trash-count", &[("count", &trash.to_string())]),
                )
                .clicked()
            {
                self.selected_group = "X".into();
            }
            ui.separator();
            for g in s.vault.groups() {
                if g.is_empty() || g == "X" {
                    continue;
                }
                let c = s.vault.entries_in_group(&g).len();
                if ui
                    .selectable_label(self.selected_group == g, format!("{g} ({c})"))
                    .clicked()
                {
                    self.selected_group = g.clone();
                }
            }
        });
    }
    fn entry_table(&mut self, ui: &mut egui::Ui) {
        use egui_extras::{Column, TableBuilder};
        let ids = self.filtered_entries();
        let mut clicked = None;
        let mut sort: Option<SortCol> = None;
        let tbl = TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(120.0).clip(true))
            .column(Column::initial(110.0).at_least(60.0).clip(true))
            .column(Column::exact(64.0))
            .column(Column::initial(150.0).at_least(60.0).clip(true))
            .column(Column::initial(150.0).at_least(60.0).clip(true))
            .column(Column::exact(44.0))
            .column(Column::exact(34.0))
            .column(Column::initial(110.0).at_least(84.0))
            .min_scrolled_height(0.0);
        tbl.header(24.0, |mut row| {
            let arrow = |cur: SortCol| -> String {
                if self.sort_col == cur {
                    if self.sort_asc {
                        " ▲".into()
                    } else {
                        " ▼".into()
                    }
                } else {
                    String::new()
                }
            };
            row.col(|ui| {
                let t = format!("{}{}", auv_i18n_tr("label-title"), arrow(SortCol::Title));
                if ui
                    .selectable_label(
                        self.sort_col == SortCol::Title,
                        egui::RichText::new(t).strong(),
                    )
                    .clicked()
                {
                    sort = Some(SortCol::Title);
                }
            });
            row.col(|ui| {
                let t = format!(
                    "{}{}",
                    auv_i18n_tr("label-username"),
                    arrow(SortCol::Username)
                );
                if ui
                    .selectable_label(
                        self.sort_col == SortCol::Username,
                        egui::RichText::new(t).strong(),
                    )
                    .clicked()
                {
                    sort = Some(SortCol::Username);
                }
            });
            row.col(|ui| {
                ui.strong(auv_i18n_tr("label-password"));
            });
            row.col(|ui| {
                ui.strong("URL");
            });
            row.col(|ui| {
                ui.strong(auv_i18n_tr("label-notes"));
            });
            row.col(|ui| {
                ui.strong("TOTP");
            });
            row.col(|ui| {
                ui.strong("📎");
            });
            row.col(|ui| {
                let t = format!(
                    "{}{}",
                    auv_i18n_tr("label-modified"),
                    arrow(SortCol::Modified)
                );
                if ui
                    .selectable_label(
                        self.sort_col == SortCol::Modified,
                        egui::RichText::new(t).strong(),
                    )
                    .clicked()
                {
                    sort = Some(SortCol::Modified);
                }
            });
        })
        .body(|body| {
            body.rows(22.0, ids.len(), |mut row| {
                let id = ids[row.index()];
                let e = self.session.as_ref().and_then(|s| s.vault.get_entry(id));
                let Some(e) = e else { return };
                let sel = self.selected == Some(id);
                let m = if e.group == "X" {
                    "[X] "
                } else if e.notes.contains("?") {
                    "[*] "
                } else if e.totp.is_some() {
                    "[K] "
                } else {
                    ""
                };
                row.col(|ui| {
                    let in_set = self.selected_set.contains(&id);
                    let txt = if in_set { "☑ " } else { "" };
                    let label = egui::RichText::new(format!("{txt}{m}{}", e.title)).size(14.0);
                    let resp = ui.selectable_label(sel, label);
                    if resp.clicked() {
                        let ctrl = ui.input(|i| i.modifiers.ctrl);
                        if ctrl {
                            if self.selected_set.contains(&id) {
                                self.selected_set.remove(&id);
                            } else {
                                self.selected_set.insert(id);
                            }
                        } else {
                            self.selected_set.clear();
                            self.selected_set.insert(id);
                        }
                        clicked = Some(id);
                    }
                });
                row.col(|ui| {
                    let _ = ui.selectable_label(sel, &e.username);
                });
                row.col(|ui| {
                    let _ = ui.selectable_label(sel, "••••••");
                });
                row.col(|ui| {
                    let _ = ui.selectable_label(sel, &e.url);
                });
                row.col(|ui| {
                    let _ = ui.selectable_label(sel, &e.notes);
                });
                row.col(|ui| {
                    let t = if e.totp.is_some() { "K" } else { "—" };
                    let _ = ui.selectable_label(sel, t);
                });
                row.col(|ui| {
                    let t = if e.attachments.is_empty() {
                        String::new()
                    } else {
                        e.attachments.len().to_string()
                    };
                    let _ = ui.selectable_label(sel, t);
                });
                row.col(|ui| {
                    let _ = ui.selectable_label(sel, fmt_time(e.modified));
                });
            });
        });
        if let Some(sc) = sort {
            if self.sort_col == sc {
                self.sort_asc = !self.sort_asc;
            } else {
                self.sort_col = sc;
                self.sort_asc = true;
            }
        }
        if let Some(id) = clicked {
            self.selected = Some(id);
            self.show_plain = false;
        }
    }

    fn detail_pane(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let dc = self.selected.and_then(|id| {
                    self.session
                        .as_ref()
                        .and_then(|s| s.vault.get_entry(id))
                        .map(|e| {
                            (
                                id,
                                e.group.clone(),
                                e.title.clone(),
                                e.username.clone(),
                                e.password.as_str().to_string(),
                                e.url.clone(),
                                e.notes.clone(),
                                e.modified,
                                e.totp.clone(),
                                e.attachments.clone(),
                                edit_from(e),
                            )
                        })
                });
                let Some((id, dg, dt, du, dp, dur, dn, dm, dtp, datts, ed_data)) = dc else {
                    ui.centered_and_justified(|ui| {
                        ui.label(egui::RichText::new(auv_i18n_tr("label-detail-empty")).weak())
                    });
                    return;
                };
                // 标题行:大标题 + 星标 + 组/时间,右侧编辑与删除/恢复
                ui.horizontal(|ui| {
                    ui.strong(egui::RichText::new(&dt).size(18.0));
                    let fav = dn.contains("?");
                    if ui.small_button(if fav { "★" } else { "☆" }).clicked() {
                        let nn = if fav {
                            dn.replace("?", "").trim().to_string()
                        } else {
                            format!("? {}", dn)
                        };
                        if let Some(s) = &mut self.session {
                            let _ = s.vault.update_entry(
                                id,
                                AuvPassEntryInput {
                                    group: dg.clone(),
                                    title: dt.clone(),
                                    username: du.clone(),
                                    password: zeroize::Zeroizing::new(dp.clone()),
                                    url: dur.clone(),
                                    notes: nn,
                                    totp: dtp.clone(),
                                },
                            );
                        }
                        self.save_session();
                    }
                    ui.label(
                        egui::RichText::new(if dg.is_empty() {
                            auv_i18n_tr("group-root")
                        } else {
                            dg.to_string()
                        })
                        .small()
                        .weak(),
                    );
                    ui.label(egui::RichText::new(fmt_time(dm)).small().weak());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(auv_i18n_tr("btn-edit")).clicked() {
                            self.edit = Some(ed_data);
                            self.edit_tab = 0;
                        }
                        if dg == "X" {
                            if ui.button(auv_i18n_tr("btn-restore")).clicked() {
                                if let Some(s) = &mut self.session {
                                    let _ = s.vault.update_entry(
                                        id,
                                        AuvPassEntryInput {
                                            group: String::new(),
                                            title: dt.clone(),
                                            username: du.clone(),
                                            password: zeroize::Zeroizing::new(dp.clone()),
                                            url: dur.clone(),
                                            notes: dn.clone(),
                                            totp: dtp.clone(),
                                        },
                                    );
                                }
                                self.save_session();
                                self.selected = None;
                            }
                        } else if ui.button(auv_i18n_tr("btn-delete")).clicked() {
                            if let Some(s) = &mut self.session {
                                let _ = s.vault.update_entry(
                                    id,
                                    AuvPassEntryInput {
                                        group: "X".into(),
                                        title: dt.clone(),
                                        username: du.clone(),
                                        password: zeroize::Zeroizing::new(dp.clone()),
                                        url: dur.clone(),
                                        notes: dn.clone(),
                                        totp: dtp.clone(),
                                    },
                                );
                            }
                            self.save_session();
                            self.selected = None;
                        }
                    });
                });
                ui.separator();
                ui.add_space(4.0);
                // 字段栈(对齐两列:标签 + 值/动作)
                egui::Grid::new("detail-fields")
                    .num_columns(2)
                    .spacing([10.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(auv_i18n_tr("label-username-colon")).weak());
                        ui.horizontal(|ui| {
                            ui.label(&du);
                            if ui.small_button("C").clicked() {
                                self.copy_clipboard(&du, 0);
                            }
                        });
                        ui.end_row();
                        ui.label(egui::RichText::new(auv_i18n_tr("label-password-colon")).weak());
                        ui.horizontal(|ui| {
                            if ui
                                .small_button(if self.show_plain { "H" } else { "S" })
                                .clicked()
                            {
                                self.show_plain = !self.show_plain;
                            }
                            if ui.small_button("C").clicked() {
                                // 复制成功才亮倒计时(此前先赋值再复制,失败也亮)
                                self.copy_clipboard(&dp, CLIPBOARD_CLEAR_SECS);
                            }
                            if self.show_plain {
                                ui.monospace(&dp);
                            } else {
                                ui.monospace("••••••••");
                            }
                            let bits = pw_strength(&dp);
                            let fr = (bits / 130.0).min(1.0) as f32;
                            ui.add(
                                egui::ProgressBar::new(fr)
                                    .desired_width(70.0)
                                    .text(format!("{bits:.0}b"))
                                    .fill(strength_color(bits)),
                            );
                        });
                        ui.end_row();
                        ui.label("URL");
                        ui.horizontal(|ui| {
                            if dur.is_empty() {
                                ui.label("-");
                            } else {
                                ui.hyperlink_to(&dur, &dur);
                                if ui.small_button("C").clicked() {
                                    self.copy_clipboard(&dur, 0);
                                }
                            }
                        });
                        ui.end_row();
                        if let Some(cfg) = &dtp {
                            ui.label("TOTP");
                            ui.horizontal(|ui| {
                                if let Ok(code) = auv_pass_totp_generate(cfg, now_unix()) {
                                    let rem =
                                        auv_pass_totp_remaining_seconds(cfg.period_s, now_unix());
                                    let rf = rem as f32 / cfg.period_s as f32;
                                    ui.monospace(
                                        egui::RichText::new(&code)
                                            .size(17.0)
                                            .strong()
                                            .color(egui::Color32::from_rgb(100, 200, 255)),
                                    );
                                    ui.add(egui::ProgressBar::new(rf).desired_width(36.0));
                                    if ui.small_button("C").clicked() {
                                        self.copy_clipboard(&code, 15);
                                    }
                                    if ui.small_button("QR").clicked() {
                                        let uri = format!(
                                            "otpauth://totp/{}?secret={}&digits={}&period={}",
                                            dt, cfg.secret, cfg.digits, cfg.period_s
                                        );
                                        self.show_qr = Some(uri);
                                    }
                                }
                                ui.ctx()
                                    .request_repaint_after(std::time::Duration::from_secs(1));
                            });
                            ui.end_row();
                        }
                        ui.label(egui::RichText::new(auv_i18n_tr("label-notes")).weak());
                        ui.label(egui::RichText::new(&dn).small());
                        ui.end_row();
                        if !datts.is_empty() {
                            ui.label(egui::RichText::new(auv_i18n_tr("label-attachments")).weak());
                            ui.vertical(|ui| {
                                for m in &datts {
                                    ui.horizontal(|ui| {
                                        ui.label(format!("{} ({})", m.name, fmt_size(m.size)));
                                        if ui
                                            .small_button(auv_i18n_tr("attachments-save-as"))
                                            .clicked()
                                        {
                                            if let Some(p) = rfd::FileDialog::new()
                                                .set_file_name(&m.name)
                                                .save_file()
                                                .map(|x| x.display().to_string())
                                            {
                                                self.save_attachment(m.id, &p);
                                            }
                                        }
                                    });
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
    }
    fn edit_window(&mut self, ctx: &egui::Context) {
        // 工作副本模式:窗口闭包内可同时操作 ed(本地)与 self(高级页附件管理)
        let Some(ed0) = self.edit.clone() else { return };
        let mut ed = ed0;
        let mut keep = true;
        let mut close = false;
        let mut cancel = false;
        let mut gen = false;
        egui::Window::new(if ed.id.is_some() {
            auv_i18n_tr("btn-edit")
        } else {
            auv_i18n_tr("btn-new")
        })
        .open(&mut keep)
        .default_width(460.0)
        .max_height(560.0)
        .show(ctx, |ui| {
            // 页签:基本 / 高级(高级页=附件管理,后续版本启用)
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.edit_tab, 0, auv_i18n_tr("editor-tab-basic"));
                ui.selectable_value(&mut self.edit_tab, 1, auv_i18n_tr("editor-tab-advanced"));
            });
            ui.separator();
            if self.edit_tab == 1 {
                // 高级页:附件管理(已有条目立即生效;新条目先保存)
                if let Some(id) = ed.id {
                    self.attachment_manager(ui, id);
                } else {
                    ui.vertical_centered(|ui| {
                        ui.add_space(36.0);
                        ui.label(
                            egui::RichText::new(auv_i18n_tr("attachments-placeholder")).weak(),
                        );
                    });
                }
            } else {
                // 表单可滚动,保存/取消固定在底部(小屏也不会被裁掉)
                egui::ScrollArea::vertical()
                    .max_height(440.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        egui::Grid::new("ed").num_columns(2).show(ui, |ui| {
                            ui.label(auv_i18n_tr("label-group"));
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut ed.group);
                                // 既有组下拉
                                let groups: Vec<String> = self
                                    .session
                                    .as_ref()
                                    .map(|s| s.vault.groups())
                                    .unwrap_or_default();
                                egui::ComboBox::from_id_salt("ed_group")
                                    .selected_text("▾")
                                    .width(120.0)
                                    .show_ui(ui, |ui| {
                                        for g in &groups {
                                            if g.is_empty() || g == "X" {
                                                continue;
                                            }
                                            ui.selectable_value(&mut ed.group, g.clone(), g);
                                        }
                                    });
                            });
                            ui.end_row();
                            ui.label(auv_i18n_tr("label-title"));
                            ui.text_edit_singleline(&mut ed.title);
                            ui.end_row();
                            ui.label(auv_i18n_tr("label-username"));
                            ui.text_edit_singleline(&mut ed.username);
                            ui.end_row();
                            ui.label(auv_i18n_tr("label-password"));
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut ed.password)
                                        .password(true)
                                        .desired_width(200.0),
                                );
                                if ui.button("Gen").clicked() {
                                    gen = true;
                                }
                                if ui
                                    .small_button(if self.show_gen_opts { "－" } else { "＋" })
                                    .clicked()
                                {
                                    self.show_gen_opts = !self.show_gen_opts;
                                }
                            });
                            ui.end_row();
                            if !ed.password.is_empty() {
                                let b = pw_strength(&ed.password);
                                let f = (b / 130.0).min(1.0) as f32;
                                ui.label("");
                                ui.add(
                                    egui::ProgressBar::new(f)
                                        .desired_width(200.0)
                                        .text(format!("{b:.0}b"))
                                        .fill(strength_color(b)),
                                );
                                ui.end_row();
                            }
                            if self.show_gen_opts {
                                ui.label(auv_i18n_tr("menu-generator"));
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(auv_i18n_tr("label-length"));
                                        ui.add(egui::Slider::new(&mut self.gen_len, 8..=128));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label(auv_i18n_tr("label-character-set"));
                                        egui::ComboBox::from_id_salt("ed_cs")
                                            .selected_text(match self.gen_charset {
                                                1 => {
                                                    auv_i18n_tr("label-letters-digits").to_string()
                                                }
                                                2 => auv_i18n_tr("label-digits-only").to_string(),
                                                _ => auv_i18n_tr("group-all").to_string(),
                                            })
                                            .show_ui(ui, |ui| {
                                                ui.selectable_value(
                                                    &mut self.gen_charset,
                                                    0,
                                                    auv_i18n_tr("group-all"),
                                                );
                                                ui.selectable_value(
                                                    &mut self.gen_charset,
                                                    1,
                                                    auv_i18n_tr("label-letters-digits"),
                                                );
                                                ui.selectable_value(
                                                    &mut self.gen_charset,
                                                    2,
                                                    auv_i18n_tr("label-digits-only"),
                                                );
                                            });
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label(auv_i18n_tr("label-exclude"));
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.gen_exclude)
                                                .desired_width(120.0),
                                        );
                                    });
                                });
                                ui.end_row();
                            }
                            ui.label("URL");
                            ui.text_edit_singleline(&mut ed.url);
                            ui.end_row();
                            ui.label(auv_i18n_tr("label-notes"));
                            ui.text_edit_singleline(&mut ed.notes);
                            ui.end_row();
                            ui.label("TOTP");
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut ed.totp);
                                if ui.small_button("QR").clicked() {
                                    if let Some(img_path) = browse_file() {
                                        if let Some(uri) = scan_qr(&img_path) {
                                            ed.totp = uri;
                                        }
                                    }
                                }
                            });
                            ui.end_row();
                        });
                    });
            }
            ui.separator();
            ui.horizontal(|ui| {
                let can_save = !ed.title.trim().is_empty();
                if ui
                    .add_enabled(can_save, egui::Button::new(auv_i18n_tr("btn-save")))
                    .clicked()
                {
                    close = true;
                }
                if ui.button(auv_i18n_tr("btn-cancel")).clicked() {
                    cancel = true;
                }
                if !can_save {
                    ui.label(
                        egui::RichText::new(auv_i18n_tr("error-title-required"))
                            .small()
                            .weak(),
                    );
                }
            });
        });
        if gen {
            let opts = AuvPassGenOptions {
                length: self.gen_len,
                upper: self.gen_charset != 2,
                lower: self.gen_charset != 2,
                digits: true,
                symbols: self.gen_charset == 0,
                exclude: self.gen_exclude.trim().to_string(),
            };
            if let Ok(pw) = auv_pass_generate_password(&opts) {
                ed.password = pw.to_string();
            }
        }
        if cancel {
            self.edit = None;
            self.status = auv_i18n_tr("msg-cancelled");
            return;
        }
        // 写回工作副本(供下一帧继续编辑)
        self.edit = Some(ed);
        if close {
            self.save_edit();
        }
        if !keep {
            self.edit = None;
        }
    }

    /// 编辑器「高级」页:附件管理(已有条目;操作立即生效并保存)。
    fn attachment_manager(&mut self, ui: &mut egui::Ui, entry: AuvPassEntryId) {
        let metas: Vec<AuvPassAttachmentMeta> = self
            .session
            .as_ref()
            .map(|s| s.vault.attachments_of(entry).to_vec())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            if ui.button(auv_i18n_tr("attachments-add-file")).clicked() {
                if let Some(p) = browse_file() {
                    let pb = std::path::PathBuf::from(&p);
                    let size = std::fs::metadata(&pb).map(|m| m.len()).unwrap_or(0);
                    if size > ATTACHMENT_WARN_BYTES {
                        self.attach_confirm = Some((entry, pb));
                    } else {
                        self.attach_file(entry, &pb);
                    }
                }
            }
            if metas.is_empty() {
                ui.label(egui::RichText::new(auv_i18n_tr("attachments-none")).weak());
            }
        });
        ui.add_space(4.0);
        egui::ScrollArea::vertical()
            .id_salt("att-list")
            .max_height(300.0)
            .show(ui, |ui| {
                for m in &metas {
                    ui.horizontal(|ui| {
                        ui.label(format!("{} ({})", m.name, fmt_size(m.size)));
                        if ui
                            .small_button(auv_i18n_tr("attachments-save-as"))
                            .clicked()
                        {
                            if let Some(p) = rfd::FileDialog::new()
                                .set_file_name(&m.name)
                                .save_file()
                                .map(|x| x.display().to_string())
                            {
                                self.save_attachment(m.id, &p);
                            }
                        }
                        if ui.small_button(auv_i18n_tr("btn-delete")).clicked() {
                            self.remove_attachment(entry, m.id);
                        }
                    });
                    ui.label(
                        egui::RichText::new(format!(
                            "SHA256 {} · {}",
                            m.sha256,
                            fmt_time(m.modified)
                        ))
                        .small()
                        .weak(),
                    );
                }
            });
    }

    /// 添加附件(立即生效并保存;大文件确认由调用方先行)。
    fn attach_file(&mut self, entry: AuvPassEntryId, path: &std::path::Path) {
        let mut err = None;
        let mut ok = false;
        if let Some(s) = &mut self.session {
            match s.vault.entry_add_attachment_file(entry, path) {
                Ok(_) => ok = true,
                Err(e) => err = Some(e.to_string()),
            }
        }
        if ok {
            self.save_session();
            self.status = auv_i18n_tr("msg-attachment-added");
        } else if let Some(e) = err {
            self.status = format!("X {e}");
        }
    }

    fn save_attachment(&mut self, att: AuvPassEntryId, path: &str) {
        let r = self
            .session
            .as_ref()
            .map(|s| s.vault.attachment_save_to(att, std::path::Path::new(path)));
        match r {
            Some(Ok(_)) => self.status = auv_i18n_tr("msg-attachment-saved"),
            Some(Err(e)) => self.status = format!("X {e}"),
            None => {}
        }
    }

    fn remove_attachment(&mut self, entry: AuvPassEntryId, att: AuvPassEntryId) {
        let mut ok = false;
        if let Some(s) = &mut self.session {
            ok = s.vault.entry_remove_attachment(entry, att).is_ok();
        }
        if ok {
            self.save_session();
            self.status = auv_i18n_tr("msg-attachment-removed");
        }
    }
    /// 保存前检查:疑似重复条目 / 密码首尾空格 / URL 缺前缀。返回需确认的提示项。
    fn collect_save_checks(
        &self,
        ed: &EditState,
        group: &str,
        title: &str,
        username: &str,
    ) -> Vec<String> {
        let mut items = Vec::new();
        if let Some(s) = &self.session {
            let dup = s.vault.entries().iter().any(|e| {
                e.id != ed.id.unwrap_or_default()
                    && e.group == group
                    && e.title == title
                    && e.username == username
            });
            if dup {
                items.push(auv_i18n_tr("check-dup"));
            }
        }
        if !ed.password.is_empty() && ed.password != ed.password.trim() {
            items.push(auv_i18n_tr("check-whitespace"));
        }
        let u = ed.url.trim();
        if !u.is_empty() && !(u.starts_with("http://") || u.starts_with("https://")) {
            items.push(auv_i18n_tr("check-url"));
        }
        items
    }
    fn save_edit(&mut self) {
        let Some(ed) = self.edit.take() else { return };
        let group = ed.group.trim().to_string();
        let title = ed.title.trim().to_string();
        let username = ed.username.clone();
        let checks = self.collect_save_checks(&ed, &group, &title, &username);
        if checks.is_empty() {
            self.commit_edit(ed);
        } else {
            // 有疑点:弹「保存前检查」确认框,不直接落库
            self.save_check = Some(ed);
        }
    }
    fn commit_edit(&mut self, ed: EditState) {
        let pw = if ed.password.is_empty() {
            if ed.id.is_some() {
                self.session
                    .as_ref()
                    .and_then(|s| {
                        s.vault
                            .get_entry(ed.id.unwrap())
                            .map(|e| e.password.clone())
                    })
                    .unwrap_or_default()
            } else {
                let p =
                    auv_pass_generate_password(&AuvPassGenOptions::default()).unwrap_or_default();
                zeroize::Zeroizing::new(p.to_string())
            }
        } else {
            zeroize::Zeroizing::new(ed.password.clone())
        };
        let inp = AuvPassEntryInput {
            group: ed.group.trim().to_string(),
            title: ed.title.trim().to_string(),
            username: ed.username.clone(),
            password: pw,
            url: ed.url.clone(),
            notes: ed.notes.clone(),
            totp: parse_totp(&ed.totp, ed.old_totp.clone()),
        };
        if let Some(s) = &mut self.session {
            let r = match ed.id {
                Some(id) => s.vault.update_entry(id, inp).map(|_| id),
                None => s.vault.add_entry(inp),
            };
            match r {
                Ok(id) => {
                    self.save_session();
                    self.selected = Some(id);
                    self.status = auv_i18n_tr("msg-saved");
                }
                Err(e) => self.status = format!("X {e}"),
            }
        }
    }
    fn generator_tab(&mut self, ui: &mut egui::Ui) {
        self.generator_ui(ui);
    }
    /// 生成器主体:密码库标签页与未开库的独立窗口共用(纯本地,不依赖库状态)。
    fn generator_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(auv_i18n_tr("menu-password-generator"));
        egui::Grid::new("gen").num_columns(2).show(ui, |ui| {
            ui.label(auv_i18n_tr("label-length"));
            ui.add(egui::Slider::new(&mut self.gen_len, 8..=128));
            ui.end_row();
            ui.label(auv_i18n_tr("label-character-set"));
            egui::ComboBox::from_id_salt("cs")
                .selected_text(match self.gen_charset {
                    1 => auv_i18n_tr("label-letters-digits").to_string(),
                    2 => auv_i18n_tr("label-digits-only").to_string(),
                    _ => auv_i18n_tr("group-all").to_string(),
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.gen_charset, 0, auv_i18n_tr("group-all"));
                    ui.selectable_value(
                        &mut self.gen_charset,
                        1,
                        auv_i18n_tr("label-letters-digits"),
                    );
                    ui.selectable_value(&mut self.gen_charset, 2, auv_i18n_tr("label-digits-only"));
                });
            ui.end_row();
            ui.label(auv_i18n_tr("label-exclude"));
            ui.text_edit_singleline(&mut self.gen_exclude);
            ui.end_row();
        });
        if ui.button(auv_i18n_tr("btn-generate")).clicked() {
            let o = AuvPassGenOptions {
                length: self.gen_len,
                upper: self.gen_charset != 2,
                lower: self.gen_charset != 2,
                digits: true,
                symbols: self.gen_charset == 0,
                exclude: self.gen_exclude.trim().to_string(),
            };
            if let Ok(pw) = auv_pass_generate_password(&o) {
                self.gen_bits = auv_pass_gen_entropy_bits(&o).unwrap_or(0.0);
                self.gen_result = pw.to_string();
            }
        }
        if !self.gen_result.is_empty() {
            ui.monospace(&self.gen_result);
            ui.label(format!("{:.0} bit", self.gen_bits));
            if ui.button(auv_i18n_tr("btn-copy")).clicked() {
                let result = self.gen_result.clone();
                self.copy_clipboard(&result, CLIPBOARD_CLEAR_SECS);
            }
        }
    }
    fn ssh_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button(auv_i18n_tr("btn-generate-ed25519")).clicked() {
                self.modal = Modal::SshGenerate;
                self.m_name.clear();
            }
            if ui.button(auv_i18n_tr("btn-import")).clicked() {
                self.modal = Modal::SshImport;
                self.m_path.clear();
                self.m_pw.clear();
                self.m_name.clear();
            }
            if ui
                .button(if self.agent.is_some() {
                    auv_i18n_tr("btn-stop")
                } else {
                    auv_i18n_tr("btn-start")
                })
                .clicked()
            {
                self.toggle_agent();
            }
            if let Some(b) = &self.agent {
                ui.label(format!("{}|{}", b.handle.socket, b.handle.sign_count()));
            }
        });
        ui.separator();
        let ks: Vec<_> = self
            .session
            .as_ref()
            .map(|s| s.vault.ssh_keys().to_vec())
            .unwrap_or_default();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for k in &ks {
                let id = k.id;
                let nm = k.name.clone();
                let fp = auv_pass_ssh_fingerprint_hex(k);
                let pk = k.public_line.clone();
                egui::CollapsingHeader::new(format!(
                    "{}{}",
                    if k.exposed {
                        auv_i18n_tr("tag-exposed-short")
                    } else {
                        auv_i18n_tr("tag-hidden-short")
                    },
                    nm
                ))
                .show(ui, |ui| {
                    ui.label(&fp);
                    ui.horizontal(|ui| {
                        if ui.button(auv_i18n_tr("label-public-key")).clicked() {
                            self.copy_clipboard(&pk, 0);
                        }
                        if ui.button(auv_i18n_tr("btn-export")).clicked() {
                            self.modal = Modal::SshExport(id);
                            self.m_path.clear();
                        }
                        if ui.button(auv_i18n_tr("btn-delete")).clicked() {
                            let mut ok = false;
                            if let Some(s) = &mut self.session {
                                ok = s.vault.ssh_delete(id).is_ok();
                            }
                            if ok {
                                self.save_session();
                            }
                        }
                    });
                });
                let mut ex = k.exposed;
                if ui.checkbox(&mut ex, auv_i18n_tr("expose")).changed() {
                    let mut ok = false;
                    if let Some(s) = &mut self.session {
                        ok = s.vault.ssh_set_exposed(id, ex).is_ok();
                    }
                    if ok {
                        self.save_session();
                    }
                }
            }
        });
        // 本会话已自动允许的钥匙(可见、可撤销)
        let allowed: Vec<AuvPassEntryId> = self.session_allowed.lock().unwrap().clone();
        if !allowed.is_empty() {
            egui::CollapsingHeader::new(auv_i18n_tr_fmt(
                "hint-session-allowed",
                &[("count", &allowed.len().to_string())],
            ))
            .show(ui, |ui| {
                for id in allowed {
                    let name = self
                        .session
                        .as_ref()
                        .and_then(|s| s.vault.ssh_keys().iter().find(|k| k.id == id))
                        .map(|k| k.name.clone());
                    ui.horizontal(|ui| {
                        ui.label(name.unwrap_or_default());
                        if ui.small_button(auv_i18n_tr("btn-revoke")).clicked() {
                            self.session_allowed.lock().unwrap().retain(|x| *x != id);
                        }
                    });
                }
            });
        }
    }
    fn modals(&mut self, ctx: &egui::Context) {
        if matches!(self.modal, Modal::None) {
            return;
        }
        let t = match &self.modal {
            Modal::ImportKdbx => auv_i18n_tr("btn-import-kdbx"),
            Modal::ExportKdbx => auv_i18n_tr("btn-export-kdbx"),
            Modal::SshGenerate => auv_i18n_tr("btn-generate-key"),
            Modal::SshImport => auv_i18n_tr("btn-import-ssh-key"),
            Modal::SshExport(_) => auv_i18n_tr("btn-export-ssh-key"),
            _ => String::new(),
        };
        let mut open = true;
        let mut exec = false;
        egui::Window::new(t).open(&mut open).show(ctx, |ui| {
            let pw2 = matches!(self.modal, Modal::ExportKdbx);
            let ssh = matches!(self.modal, Modal::SshImport | Modal::SshExport(_));
            egui::Grid::new("md").num_columns(2).show(ui, |ui| {
                ui.label(auv_i18n_tr("label-path"));
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.m_path);
                    if ui.small_button("...").clicked() {
                        if matches!(self.modal, Modal::ExportKdbx | Modal::SshExport(_)) {
                            if let Some(p) = browse_save("vault.kdbx") {
                                self.m_path = p;
                            }
                        } else if let Some(p) = browse_file() {
                            self.m_path = p;
                        }
                    }
                });
                ui.end_row();
                if !matches!(self.modal, Modal::SshExport(_)) {
                    ui.label(if ssh {
                        auv_i18n_tr("label-passphrase")
                    } else {
                        auv_i18n_tr("label-master-password")
                    });
                    ui.add(egui::TextEdit::singleline(&mut self.m_pw).password(true));
                    ui.end_row();
                }
                if pw2 {
                    ui.label(auv_i18n_tr("repeat"));
                    ui.add(egui::TextEdit::singleline(&mut self.m_pw2).password(true));
                    ui.end_row();
                }
                if matches!(self.modal, Modal::ImportKdbx | Modal::ExportKdbx) {
                    ui.label(auv_i18n_tr("label-key-file"));
                    ui.text_edit_singleline(&mut self.m_keyfile);
                    ui.end_row();
                }
                if matches!(self.modal, Modal::SshImport | Modal::SshGenerate) {
                    ui.label(auv_i18n_tr("label-name"));
                    ui.text_edit_singleline(&mut self.m_name);
                    ui.end_row();
                }
            });
            if ui.button(auv_i18n_tr("btn-run")).clicked() {
                exec = true;
            }
        });
        if exec {
            self.apply_modal();
            self.modal = Modal::None;
        }
        if !open {
            self.modal = Modal::None;
        }
    }
    fn apply_modal(&mut self) {
        let kf = self.m_keyfile.trim().to_string();
        let kfp = (!kf.is_empty()).then(|| std::path::Path::new(&kf));
        let pw = self.m_pw.clone();
        let p = self.m_path.trim().to_string();
        match self.modal {
            Modal::ImportKdbx => {
                // 先解析出预览(N 条/M 组/跳过清单),确认后才入库
                match auv_pass_kdbx_import(std::path::Path::new(&p), pw.as_bytes(), kfp) {
                    Ok(res) => {
                        let groups = res
                            .entries
                            .iter()
                            .map(|(inp, _, _)| inp.group.clone())
                            .filter(|g| !g.is_empty())
                            .collect::<std::collections::BTreeSet<_>>()
                            .len();
                        self.kdbx_preview = Some(KdbxPreview {
                            entries: res.entries.len(),
                            groups,
                            skipped: res.skipped,
                            path: p.clone(),
                            pw,
                            kf,
                        });
                    }
                    Err(e) => self.status = format!("X {e}"),
                }
            }
            Modal::ExportKdbx => {
                // 目标已存在 → 先覆盖确认
                if std::path::Path::new(&p).exists() {
                    self.overwrite = Some(OverwriteAction::ExportKdbx { path: p, pw, kf });
                } else {
                    self.exec_export_kdbx(&p, &pw, kfp);
                }
            }
            Modal::SshGenerate => {
                let mut ok = false;
                if let Some(s) = &mut self.session {
                    ok = s.vault.ssh_generate_ed25519(self.m_name.trim()).is_ok();
                }
                if ok {
                    self.save_session();
                    self.status = auv_i18n_tr("msg-generated");
                }
            }
            Modal::SshImport => {
                if let Ok(pem) = std::fs::read_to_string(&p) {
                    let pw_opt = if pw.is_empty() {
                        None
                    } else {
                        Some(pw.as_str())
                    };
                    let mut ok = false;
                    if let Some(s) = &mut self.session {
                        ok = s.vault.ssh_import(&pem, pw_opt, self.m_name.trim()).is_ok();
                    }
                    if ok {
                        self.save_session();
                        self.status = auv_i18n_tr("msg-imported");
                    }
                }
            }
            Modal::SshExport(id) => {
                if let Some(s) = &self.session {
                    if let Ok(pem) = s.vault.ssh_export_private(id) {
                        if std::path::Path::new(&p).exists() {
                            self.overwrite = Some(OverwriteAction::SshExport {
                                path: p,
                                pem: zeroize::Zeroizing::new(pem),
                            });
                        } else {
                            self.exec_ssh_export(&p, &zeroize::Zeroizing::new(pem));
                        }
                    }
                }
            }
            Modal::None => {}
        }
    }
    /// 确认后的 KDBX 导入(重新解析并入库)。
    fn exec_import_kdbx(&mut self, pv: KdbxPreview) {
        let kfp = (!pv.kf.is_empty()).then(|| std::path::Path::new(&pv.kf).to_path_buf());
        let kfp = kfp.as_deref();
        let mut n = None;
        if let Some(s) = &mut self.session {
            n = s
                .vault
                .import_kdbx(std::path::Path::new(&pv.path), pv.pw.as_bytes(), kfp)
                .ok();
        }
        if let Some(n) = n {
            self.save_session();
            self.status = auv_i18n_tr_fmt("btn-import-count", &[("count", &n.to_string())]);
        }
    }
    fn exec_export_kdbx(&mut self, p: &str, pw: &str, kfp: Option<&std::path::Path>) {
        let r = self.session.as_ref().map(|s| {
            s.vault
                .export_kdbx(std::path::Path::new(p), pw.as_bytes(), kfp)
        });
        match r {
            Some(Ok(n)) => {
                self.status = auv_i18n_tr_fmt("btn-export-count", &[("count", &n.to_string())])
            }
            Some(Err(e)) => self.status = format!("X {e}"),
            None => {}
        }
    }
    /// 明文私钥落盘收紧 0600(Unix):默认 umask 0644 属泄露面,ssh 客户端亦拒载。
    fn exec_ssh_export(&mut self, p: &str, pem: &zeroize::Zeroizing<String>) {
        self.status = match auv_pass_write_secret_file(std::path::Path::new(p), pem.as_bytes()) {
            Ok(()) => auv_i18n_tr("msg-exported"),
            Err(e) => auv_i18n_tr_fmt("error-write-failed", &[("err", &e.to_string())]),
        };
    }
    /// 附加对话框:保存失败告警 / 保存前检查确认 / KDBX 导入预览 / 覆盖确认。
    fn extra_dialogs(&mut self, ctx: &egui::Context) {
        // 保存失败(绝不静默)
        if let Some(err) = self.save_error.clone() {
            let mut open = true;
            let mut ok = false;
            egui::Window::new(auv_i18n_tr("save-failed-title"))
                .collapsible(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(egui::RichText::new(&err).monospace().small());
                    if ui.button(auv_i18n_tr("btn-ok")).clicked() {
                        ok = true;
                    }
                });
            if !open || ok {
                self.save_error = None;
            }
        }
        // 保存前检查确认
        if self.save_check.is_some() {
            let mut proceed = false;
            let mut back = false;
            egui::Window::new(auv_i18n_tr("save-check-title"))
                .collapsible(false)
                .show(ctx, |ui| {
                    if let Some(ed) = &self.save_check {
                        let group = ed.group.trim().to_string();
                        let title = ed.title.trim().to_string();
                        let username = ed.username.clone();
                        for c in self.collect_save_checks(ed, &group, &title, &username) {
                            ui.label(egui::RichText::new(format!("• {c}")));
                        }
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(auv_i18n_tr("save-anyway")).clicked() {
                            proceed = true;
                        }
                        if ui.button(auv_i18n_tr("go-back-edit")).clicked() {
                            back = true;
                        }
                    });
                });
            if proceed {
                if let Some(ed) = self.save_check.take() {
                    self.commit_edit(ed);
                }
            } else if back {
                self.edit_tab = 0;
                self.edit = self.save_check.take();
            }
        }
        // KDBX 导入预览
        if self.kdbx_preview.is_some() {
            let mut confirm = false;
            let mut cancel = false;
            egui::Window::new(auv_i18n_tr("import-preview-title"))
                .collapsible(false)
                .show(ctx, |ui| {
                    if let Some(pv) = &self.kdbx_preview {
                        ui.label(auv_i18n_tr_fmt(
                            "import-preview-body",
                            &[
                                ("entries", &pv.entries.to_string()),
                                ("groups", &pv.groups.to_string()),
                                ("skipped", &pv.skipped.len().to_string()),
                            ],
                        ));
                        if !pv.skipped.is_empty() {
                            ui.separator();
                            for s in pv.skipped.iter().take(5) {
                                ui.label(egui::RichText::new(format!("— {s}")).small().weak());
                            }
                            if pv.skipped.len() > 5 {
                                ui.label(
                                    egui::RichText::new(format!("… +{}", pv.skipped.len() - 5))
                                        .small()
                                        .weak(),
                                );
                            }
                        }
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(auv_i18n_tr("confirm-import")).clicked() {
                            confirm = true;
                        }
                        if ui.button(auv_i18n_tr("btn-cancel")).clicked() {
                            cancel = true;
                        }
                    });
                });
            if confirm {
                if let Some(pv) = self.kdbx_preview.take() {
                    self.exec_import_kdbx(pv);
                }
            } else if cancel {
                self.kdbx_preview = None;
            }
        }
        // 覆盖确认
        if self.overwrite.is_some() {
            let mut proceed = false;
            let mut cancel = false;
            let path = match &self.overwrite {
                Some(OverwriteAction::ExportKdbx { path, .. }) => path.clone(),
                Some(OverwriteAction::SshExport { path, .. }) => path.clone(),
                None => String::new(),
            };
            egui::Window::new(auv_i18n_tr("overwrite-title"))
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(auv_i18n_tr_fmt("overwrite-body", &[("path", &path)]));
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(auv_i18n_tr("overwrite-anyway")).clicked() {
                            proceed = true;
                        }
                        if ui.button(auv_i18n_tr("btn-cancel")).clicked() {
                            cancel = true;
                        }
                    });
                });
            if proceed || cancel {
                let action = self.overwrite.take();
                if let (Some(a), true) = (action, proceed) {
                    match a {
                        OverwriteAction::ExportKdbx { path, pw, kf } => {
                            let kfp =
                                (!kf.is_empty()).then(|| std::path::Path::new(&kf).to_path_buf());
                            self.exec_export_kdbx(&path, &pw, kfp.as_deref());
                        }
                        OverwriteAction::SshExport { path, pem } => {
                            self.exec_ssh_export(&path, &pem);
                        }
                    }
                }
            }
        }
        // 大附件确认(>100MB:内存/耗时/备份三条代价)
        if let Some((entry, path)) = self.attach_confirm.clone() {
            let mut proceed = false;
            let mut cancel = false;
            let name = path
                .file_name()
                .map(|x| x.to_string_lossy().to_string())
                .unwrap_or_default();
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            egui::Window::new(auv_i18n_tr("attach-large-title"))
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(auv_i18n_tr_fmt(
                        "attach-large-body",
                        &[("name", &name), ("size", &fmt_size(size))],
                    ));
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(auv_i18n_tr("attach-add-anyway")).clicked() {
                            proceed = true;
                        }
                        if ui.button(auv_i18n_tr("btn-cancel")).clicked() {
                            cancel = true;
                        }
                    });
                });
            if proceed || cancel {
                self.attach_confirm = None;
                if proceed {
                    self.attach_file(entry, &path);
                }
            }
        }
    }

    /// 批量移入选中条目到回收站。
    fn batch_trash(&mut self) {
        let ids: Vec<AuvPassEntryId> = self.selected_set.iter().copied().collect();
        let mut n = 0;
        if let Some(s) = &mut self.session {
            for id in &ids {
                if let Some(e) = s.vault.get_entry(*id) {
                    let inp = AuvPassEntryInput {
                        group: "X".into(),
                        title: e.title.clone(),
                        username: e.username.clone(),
                        password: e.password.clone(),
                        url: e.url.clone(),
                        notes: e.notes.clone(),
                        totp: e.totp.clone(),
                    };
                    if s.vault.update_entry(*id, inp).is_ok() {
                        n += 1;
                    }
                }
            }
        }
        self.save_session();
        self.selected_set.clear();
        self.selected = None;
        self.status = auv_i18n_tr_fmt("msg-batch-trashed", &[("n", &n.to_string())]);
    }

    /// 更改主密码窗口。
    fn change_pw_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_change_pw {
            return;
        }
        let mut open = true;
        let mut apply = false;
        let mut cancel_clicked = false;
        egui::Window::new(auv_i18n_tr("menu-change-password"))
            .collapsible(false)
            .open(&mut open)
            .show(ctx, |ui| {
                egui::Grid::new("cpw").num_columns(2).show(ui, |ui| {
                    ui.label(auv_i18n_tr("label-new-password"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.change_pw_new)
                            .password(true)
                            .desired_width(260.0),
                    );
                    ui.end_row();
                    ui.label(auv_i18n_tr("label-new-password-repeat"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.change_pw_new2)
                            .password(true)
                            .desired_width(260.0),
                    );
                    ui.end_row();
                    ui.label(auv_i18n_tr("label-new-keyfile"));
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.change_pw_keyfile);
                        if ui.small_button("...").clicked() {
                            if let Some(p) = browse_file() {
                                self.change_pw_keyfile = p;
                            }
                        }
                    });
                    ui.end_row();
                });
                if !self.change_pw_new.is_empty() {
                    let b = pw_strength(&self.change_pw_new);
                    let f = (b / 130.0).min(1.0) as f32;
                    ui.add(
                        egui::ProgressBar::new(f)
                            .desired_width(260.0)
                            .text(format!("{b:.0}b"))
                            .fill(strength_color(b)),
                    );
                }
                ui.separator();
                let can =
                    !self.change_pw_new.is_empty() && self.change_pw_new == self.change_pw_new2;
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(can, egui::Button::new(auv_i18n_tr("btn-save")))
                        .clicked()
                    {
                        apply = true;
                    }
                    if ui.button(auv_i18n_tr("btn-cancel")).clicked() {
                        cancel_clicked = true;
                    }
                    if !can
                        && !self.change_pw_new.is_empty()
                        && self.change_pw_new != self.change_pw_new2
                    {
                        ui.label(
                            egui::RichText::new(auv_i18n_tr("error-passwords-mismatch-2"))
                                .small()
                                .weak(),
                        );
                    }
                });
            });
        if !open || cancel_clicked {
            self.show_change_pw = false;
        }
        if apply {
            let kf = self.change_pw_keyfile.trim().to_string();
            let kfp = if kf.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(kf))
            };
            let mut ok = false;
            if let Some(s) = &mut self.session {
                ok = s
                    .vault
                    .change_credentials(self.change_pw_new.as_bytes(), kfp.as_deref())
                    .is_ok();
            }
            if ok {
                self.save_session();
                self.status = auv_i18n_tr("msg-password-changed");
                self.show_change_pw = false;
            }
            self.change_pw_new.clear();
            self.change_pw_new2.clear();
            self.change_pw_keyfile.clear();
        }
    }

    /// 库属性窗口。
    fn props_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_props {
            return;
        }
        let mut open = true;
        egui::Window::new(auv_i18n_tr("menu-vault-properties"))
            .collapsible(false)
            .open(&mut open)
            .show(ctx, |ui| {
                if let Some(s) = &self.session {
                    let h = s.vault.header();
                    egui::Grid::new("props").num_columns(2).show(ui, |ui| {
                        ui.label(auv_i18n_tr("props-format"));
                        ui.label(format!("v{}", 3));
                        ui.end_row();
                        ui.label(auv_i18n_tr("props-algorithm"));
                        ui.label(h.algo.label());
                        ui.end_row();
                        ui.label(auv_i18n_tr("props-kdf"));
                        ui.label(format!(
                            "Argon2id  m={}KiB t={} p={}{}",
                            h.kdf.m_kib,
                            h.kdf.t_cost,
                            h.kdf.p_cost,
                            if h.cred == AuvPassVaultCred::KeyFile {
                                " + 密钥文件"
                            } else if h.cred == AuvPassVaultCred::PasswordKeyFile {
                                " + 密码 + 密钥文件"
                            } else {
                                ""
                            }
                        ));
                        ui.end_row();
                        ui.label(auv_i18n_tr("props-entries"));
                        ui.label(s.vault.entry_count().to_string());
                        ui.end_row();
                        ui.label(auv_i18n_tr("props-attachments"));
                        let att_n: usize =
                            s.vault.entries().iter().map(|e| e.attachments.len()).sum();
                        ui.label(att_n.to_string());
                        ui.end_row();
                        // 文件信息
                        if let Ok(md) = std::fs::metadata(&s.path) {
                            ui.label(auv_i18n_tr("props-file-size"));
                            ui.label(fmt_size(md.len()));
                            ui.end_row();
                        }
                        if let Ok(data) = std::fs::read(&s.path) {
                            use sha2::Digest as _;
                            use std::fmt::Write;
                            let mut hstr = String::new();
                            for b in sha2::Sha256::digest(&data) {
                                let _ = write!(hstr, "{b:02x}");
                            }
                            ui.label(auv_i18n_tr("props-file-sha256"));
                            ui.label(egui::RichText::new(&hstr).monospace().small().weak());
                            ui.end_row();
                        }
                    });
                }
            });
        if !open {
            self.show_props = false;
        }
    }

    /// 健康报告窗口。
    fn health_report_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_health {
            return;
        }
        let mut open = true;
        egui::Window::new(auv_i18n_tr("menu-health-report"))
            .collapsible(false)
            .open(&mut open)
            .min_width(400.0)
            .show(ctx, |ui| {
                let Some(s) = &self.session else { return };
                let now = now_unix();
                let mut weak: Vec<&str> = Vec::new();
                let mut reused_groups: Vec<(String, Vec<&str>)> = Vec::new();
                let mut stale: Vec<&str> = Vec::new();

                // 弱密码 + 陈旧
                for e in s.vault.entries() {
                    if e.group == "X" {
                        continue;
                    }
                    let bits = pw_strength(e.password.as_str());
                    if bits < 60.0 {
                        weak.push(&e.title);
                    }
                    if now - e.modified > 365 * 86400 {
                        stale.push(&e.title);
                    }
                }

                // 同密码（按内容哈希分组）
                use std::collections::BTreeMap;
                let mut pw_map: BTreeMap<String, Vec<&str>> = BTreeMap::new();
                for e in s.vault.entries() {
                    if e.group == "X" || e.password.as_str().is_empty() {
                        continue;
                    }
                    pw_map
                        .entry(e.password.as_str().to_string())
                        .or_default()
                        .push(&e.title);
                }
                for titles in pw_map.values() {
                    if titles.len() > 1 {
                        reused_groups.push((format!("{}", titles.len()), titles.clone()));
                    }
                }

                let report = |ui: &mut egui::Ui, title: &str, items: &[&str]| {
                    ui.strong(title);
                    if items.is_empty() {
                        ui.label(
                            egui::RichText::new(auv_i18n_tr("health-none"))
                                .small()
                                .color(egui::Color32::from_rgb(100, 200, 100)),
                        );
                    } else {
                        for t in items {
                            ui.label(
                                egui::RichText::new(format!("  • {t}"))
                                    .small()
                                    .color(egui::Color32::from_rgb(220, 80, 80)),
                            );
                        }
                    }
                    ui.add_space(6.0);
                };

                if weak.is_empty() && reused_groups.is_empty() && stale.is_empty() {
                    ui.label(
                        egui::RichText::new(auv_i18n_tr("health-ok"))
                            .color(egui::Color32::from_rgb(100, 200, 100)),
                    );
                } else {
                    report(ui, &auv_i18n_tr("health-weak"), &weak);
                    if !reused_groups.is_empty() {
                        ui.strong(auv_i18n_tr("health-reused"));
                        for (n, titles) in &reused_groups {
                            ui.label(
                                egui::RichText::new(format!("  • {} ({n})", titles.join(", ")))
                                    .small()
                                    .color(egui::Color32::from_rgb(230, 180, 60)),
                            );
                        }
                        ui.add_space(6.0);
                    }
                    report(ui, &auv_i18n_tr("health-stale"), &stale);
                }
            });
        if !open {
            self.show_health = false;
        }
    }

    fn agent_confirm_popup(&mut self, ctx: &egui::Context) {
        let Some(req) = self.agent_confirm.take() else {
            return;
        };
        let mut dec: Option<bool> = None;
        let mut sa = false;
        egui::Window::new(auv_i18n_tr("dialog-sign-request"))
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(auv_i18n_tr_fmt(
                    "dialog-sign-request-key-title",
                    &[("name", &req.key_name)],
                ));
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button(auv_i18n_tr("btn-allow")).clicked() {
                        dec = Some(true);
                    }
                    if ui.button(auv_i18n_tr("msg-allow-all")).clicked() {
                        dec = Some(true);
                        sa = true;
                    }
                    if ui.button(auv_i18n_tr("btn-deny")).clicked() {
                        dec = Some(false);
                    }
                });
            });
        match dec {
            Some(true) => {
                if sa {
                    if let Some(s) = &self.session {
                        if let Some(k) = s.vault.ssh_keys().iter().find(|x| x.name == req.key_name)
                        {
                            self.session_allowed.lock().unwrap().push(k.id);
                        }
                    }
                }
                let _ = req.reply.send(true);
            }
            Some(false) => {
                let _ = req.reply.send(false);
            }
            None => {
                let _ = req.reply.send(false);
            }
        }
    }
}
fn main() -> eframe::Result {
    // 启动时探测语言(AUV_PASS_LANG > AUV_LANG > POSIX locale > 系统 UI 语言 > zh-CN)
    auv_pass_i18n_init();
    // 启动样板+CJK 字体(内置 Sarasa 基线+系统链兜底)由 auv-ui 提供
    let spec = auv_ui::shell::AuvUiShellSpec::new("auv-pass", [1200.0, 720.0])
        .with_min_inner_size([960.0, 560.0]);
    auv_ui::shell::auv_ui_run_shell(
        "auv-pass",
        spec,
        Box::new(|_cc| Ok(Box::new(PassApp::default()))),
    )
}

#[cfg(test)]
mod tests {
    use super::auv_pass_has_user_input_events;
    use eframe::egui;

    /// 自动锁定活动判定回归:空帧(仅定时重绘)不算活动;真实输入事件算活动。
    #[test]
    fn activity_only_on_real_input_events() {
        // 空事件(如 TOTP 面板每秒 request_repaint_after 触发的重绘):不算活动
        assert!(!auv_pass_has_user_input_events(&[]));
        // 窗口失焦/截图等系统事件:不算活动
        assert!(!auv_pass_has_user_input_events(&[
            egui::Event::WindowFocused(false)
        ]));
        // 按键:算活动
        assert!(auv_pass_has_user_input_events(&[egui::Event::Key {
            key: egui::Key::A,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }]));
        // 指针移动:算活动
        assert!(auv_pass_has_user_input_events(&[
            egui::Event::PointerMoved(egui::pos2(1.0, 2.0))
        ]));
        // 滚轮:算活动
        assert!(auv_pass_has_user_input_events(&[egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Line,
            delta: egui::vec2(0.0, -1.0),
            phase: egui::TouchPhase::Move,
            modifiers: egui::Modifiers::NONE,
        }]));
    }
}
