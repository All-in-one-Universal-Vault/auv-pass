// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! auv-pass-tui:终端界面(ratatui 全屏 DOS 风界面)。
//!
//! 模式:**无参数 = 全屏交互界面**(双栏面板/反色高亮/弹窗表单);**有参数 = 直达**
//! (`find <库> <词> [--copy]` / `list <库>` / `--version`),退出码语义独立。
//! 安全红线:主密码/密码字段输入不回显;复制密码 30 秒自动清空;明文仅显式按键上屏。

mod app;
mod ui;

use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use auv_i18n::{auv_i18n_tr, auv_i18n_tr_fmt};
use auv_pass_engine::{auv_pass_clipboard_should_clear, auv_pass_i18n_init, AuvPassVault};
use zeroize::Zeroizing;

/// 剪贴板自动清空秒数(安全红线:30 秒)。
pub const CLIPBOARD_CLEAR_SECS: u64 = 30;

/// 剪贴板清除代数戳(epoch counter):每次复制 +1;
/// 延时清空线程只在自己仍是最新一代时才清(修竞态:旧线程不得清掉新复制的内容)。
static CLIPBOARD_EPOCH: AtomicU64 = AtomicU64::new(0);

/// 复制文本到剪贴板并登记新代数;返回本次的代数戳。
fn clipboard_set(text: &str) -> Result<u64, String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(text.to_string()).map_err(|e| e.to_string())?;
    Ok(CLIPBOARD_EPOCH.fetch_add(1, Ordering::SeqCst) + 1)
}

/// 代数戳 + 读回比对(read-back compare)双校验通过才清空剪贴板。
fn clipboard_clear_if_current(epoch: u64, text: &str) {
    let now = CLIPBOARD_EPOCH.load(Ordering::SeqCst);
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let readback = cb.get_text().ok();
        if auv_pass_clipboard_should_clear(epoch, now, text, readback.as_deref()) {
            let _ = cb.set_text("");
        }
    }
}

/// 复制文本到剪贴板;敏感文本 secs 秒后自动清空(后台线程)。
pub fn clipboard_copy(text: &str, secs: u64) -> Result<(), String> {
    let epoch = clipboard_set(text)?;
    if secs > 0 {
        let owned = text.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            clipboard_clear_if_current(epoch, &owned);
        });
    }
    Ok(())
}

/// 直达模式清除段:主线程驻留 secs 秒再自行清空(KeePassCLI 同款)。
/// 直达模式末尾 process::exit 会杀死后台线程,故不能走 clipboard_copy 的异步清除;
/// 须与一次先行完成的 clipboard_set/clipboard_copy(text, 0) 配对使用。
pub fn clipboard_block_then_clear(text: &str, secs: u64) {
    if secs == 0 {
        return;
    }
    let epoch = CLIPBOARD_EPOCH.load(Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_secs(secs));
    clipboard_clear_if_current(epoch, text);
}

/// 解锁会话(主路径+库)。
pub struct Session {
    pub vault: AuvPassVault,
    pub path: std::path::PathBuf,
}

// ===================== 直达模式(非全屏,保持原样) =====================

fn usage() {
    println!("auv-pass-tui {}", env!("CARGO_PKG_VERSION"));
    println!("{}", auv_i18n_tr("usage-no-args"));
    println!("{}", auv_i18n_tr("usage-find"));
    println!("{}", auv_i18n_tr("usage-list"));
    println!("{}", auv_i18n_tr("usage-version"));
}

/// 直达模式的隐藏密码输入(不进全屏,raw mode 即可)。
fn hidden_pw_once() -> Zeroizing<String> {
    let _ = crossterm::terminal::enable_raw_mode();
    print!("{}", auv_i18n_tr("prompt-master-password"));
    let _ = std::io::stdout().flush();
    let mut buf = Zeroizing::new(String::new());
    while let Ok(ev) = crossterm::event::read() {
        if let crossterm::event::Event::Key(k) = ev {
            if k.kind != crossterm::event::KeyEventKind::Press {
                continue;
            }
            match k.code {
                crossterm::event::KeyCode::Enter => break,
                crossterm::event::KeyCode::Backspace => {
                    buf.pop();
                    print!("\u{8} \u{8}");
                    let _ = std::io::stdout().flush();
                }
                crossterm::event::KeyCode::Char('c')
                    if k.modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    let _ = crossterm::terminal::disable_raw_mode();
                    println!();
                    std::process::exit(130);
                }
                crossterm::event::KeyCode::Char(c) => {
                    buf.push(c);
                    print!("*");
                    let _ = std::io::stdout().flush();
                }
                _ => {}
            }
        }
    }
    let _ = crossterm::terminal::disable_raw_mode();
    println!("\r\n{}", auv_i18n_tr("label-deriving-key"));
    buf
}

fn keyfile_from_env() -> Option<std::path::PathBuf> {
    std::env::var("AUV_PASS_KEYFILE").ok().map(Into::into)
}

fn direct_find(vault_path: &str, query: &str, do_copy: bool) -> i32 {
    let pw = hidden_pw_once();
    if pw.is_empty() && keyfile_from_env().is_none() {
        eprintln!("{}", auv_i18n_tr("error-no-credential"));
        return 1;
    }
    let vault = match AuvPassVault::open(
        std::path::Path::new(vault_path),
        pw.as_str().as_bytes(),
        keyfile_from_env().as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("✗ {e}");
            return 1;
        }
    };
    let hits = vault.search(query);
    if hits.is_empty() {
        println!("{}", auv_i18n_tr("no-matches"));
        return 1;
    }
    let chosen = if hits.len() == 1 {
        &hits[0]
    } else {
        println!(
            "{}",
            auv_i18n_tr_fmt(
                "msg-matched-count-list",
                &[("count", &hits.len().to_string())]
            )
        );
        for (i, e) in hits.iter().enumerate() {
            println!("  {}. [{}] {} ({})", i + 1, e.group, e.title, e.username);
        }
        print!("{}", auv_i18n_tr("prompt-choice-default"));
        let _ = std::io::stdout().flush();
        let mut s = String::new();
        if std::io::stdin().read_line(&mut s).is_ok() {
            s.trim()
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=hits.len()).contains(n))
                .map(|n| &hits[n - 1])
                .unwrap_or(&hits[0])
        } else {
            &hits[0]
        }
    };
    println!("→ {} ({})", chosen.title, chosen.username);
    if do_copy {
        // 先上剪贴板并立即提示,再驻留等待清除——提示不被 30 秒等待阻塞;
        // 驻留是必要的:直达模式末尾 process::exit 会杀死后台清除线程。
        match clipboard_copy(chosen.password.as_str(), 0) {
            Ok(()) => {
                println!(
                    "✓ {}",
                    auv_i18n_tr_fmt(
                        "msg-password-copied",
                        &[("secs", &CLIPBOARD_CLEAR_SECS.to_string())],
                    )
                );
                clipboard_block_then_clear(chosen.password.as_str(), CLIPBOARD_CLEAR_SECS);
            }
            Err(e) => {
                eprintln!(
                    "✗ {}",
                    auv_i18n_tr_fmt("error-clipboard-failed", &[("err", &e)])
                );
                return 1;
            }
        }
    }
    0
}

fn direct_list(vault_path: &str) -> i32 {
    let pw = hidden_pw_once();
    let vault = match AuvPassVault::open(
        std::path::Path::new(vault_path),
        pw.as_str().as_bytes(),
        keyfile_from_env().as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("✗ {e}");
            return 1;
        }
    };
    if vault.entry_count() == 0 {
        println!("{}", auv_i18n_tr("empty-vault"));
        return 0;
    }
    for e in vault.entries() {
        println!(
            "[{}] {} | {} | {}{}",
            if e.group.is_empty() { "-" } else { &e.group },
            e.title,
            e.username,
            e.url,
            if e.totp.is_some() { " | TOTP" } else { "" }
        );
    }
    0
}

fn main() {
    // 启动时探测语言(AUV_PASS_LANG > AUV_LANG > POSIX locale > 系统 UI 语言 > zh-CN)
    auv_pass_i18n_init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None => match app::run() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!(
                    "{}",
                    auv_i18n_tr_fmt("error-ui", &[("err", &e.to_string())])
                );
                1
            }
        },
        Some("--version") | Some("-V") => {
            println!("auv-pass-tui {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("find") => match (args.get(1), args.get(2)) {
            (Some(v), Some(q)) => direct_find(v, q, args.iter().any(|a| a == "--copy")),
            _ => {
                usage();
                2
            }
        },
        Some("list") => match args.get(1) {
            Some(v) => direct_list(v),
            None => {
                usage();
                2
            }
        },
        Some("-h") | Some("--help") => {
            usage();
            0
        }
        Some(other) => {
            eprintln!(
                "{}",
                auv_i18n_tr_fmt("error-unknown-subcommand", &[("name", other)])
            );
            usage();
            2
        }
    };
    std::process::exit(code);
}
