# auv-pass

> **Keep dark. Stay light.**
> **守之以暗，行之以轻**

[中文](#中文) · [English](#english)

## 中文

**Authenticated User Vault, for Password** —— AUV 系列本地优先密码管理器：密码库、TOTP、KDBX 互导、SSH 密钥代理一体，TUI 与 GUI 双前端。

### 隐私与边界

- **零遥测**：不收集遥测、崩溃报告或任何用户数据。
- **网络出口清单**：**零外发连接**。引擎层无网络依赖；SSH 代理仅在本地监听（Unix 域套接字 / Windows 命名管道），不主动连接任何主机。
- **数据清除**：锁定或退出即清零内存密钥；复制密码 30 秒后自动清空剪贴板（TOTP 码 15 秒）。全部数据存于单个 `.auvp` 库文件——删除该文件即彻底移除；导出的 SSH 私钥文件由你自行保管与销毁。
- **更新通道**：源码分发，无内置自动更新；版本以本仓 tag 与发布页为准。

### 功能

- **三算法 AEAD 加密**：AES-256-GCM / ChaCha20-Poly1305 / SM4-GCM（国标 GB/T 32907-2016 + GB/T 17964-2021），建库时可选；
- **Argon2id** 密钥派生（默认 64 MiB / t=3 / p=1，16 字节 OS 熵盐）；
- **凭据三组合**：主密码 / 密钥文件（任意文件）/ 两者并用；v1 旧库自动升级；
- **密码库核心**：条目增删改、`/` 分层分组、五字段搜索、修改历史（默认封顶 20 条，可调，0 = 禁用）、原子写落盘；
- **TOTP**：RFC 6238 自实现，`otpauth://` 与 base32 录入，二维码显示与截图扫码导入；
- **KDBX 双向互导**：导入 KeePass 1.x–4.x，导出 KDBX 4；分组、历史、TOTP 双向保留；
- **SSH 密钥代理**：Ed25519 密钥生成 / 导入 / 导出；实现 ssh-agent 兼容协议，ssh / git / IDE 等现有工具零改动即可使用；每次签名弹窗确认，未「上岗」的密钥不对外暴露；
- **密码生成器**：NIST SP 800-63B 对齐，拒绝采样消除模偏置，可排除易混字符，显示精确熵；
- **TUI**（ratatui 全屏界面）与 **GUI**（egui 原生窗口，文件/条目/工具/帮助菜单栏）双前端；
- **zh-CN / en 双语**，运行时切换；
- **自动锁定**：空闲 10 分钟清零密钥（agent 运行期间豁免）。

### 构建与使用

需要 Rust 工具链（edition 2021）：

```bash
cargo build --release --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

- **TUI**：`auv-pass-tui` 无参数进入全屏界面；直达模式 `find <库> <词> [--copy]`、`list <库>`、`--version`；
- **GUI**：`auv-pass-gui` 原生窗口程序（Windows 下双击不弹控制台）；
- 密钥文件路径可用环境变量 `AUV_PASS_KEYFILE` 预置；语言可用 `AUV_PASS_LANG` / `AUV_LANG` 指定。

### 许可

MulanPSL-2.0 OR Apache-2.0 双许可（木兰在前），全文见 [LICENSE-MulanPSL-2.0](LICENSE-MulanPSL-2.0) 与 [LICENSE-Apache-2.0](LICENSE-Apache-2.0)。第三方组件声明见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。安全报告方式见 [SECURITY.md](SECURITY.md)。完整操作说明见 [docs/使用手册.txt](docs/使用手册.txt)。

## English

**Authenticated User Vault, for Password** — a local-first password manager in the AUV series: vault, TOTP, KDBX interop and an SSH key agent in one package, with both TUI and GUI front ends.

### Privacy and boundaries

- **Zero telemetry**: no telemetry, crash reports, or user data of any kind.
- **Network egress list**: **zero outbound connections**. The engine has no network dependencies; the SSH agent listens only on a local socket (Unix domain socket / Windows named pipe) and never connects out.
- **Data removal**: locking or exiting wipes in-memory keys; a copied password clears from the clipboard after 30 seconds (TOTP codes after 15). All data lives in a single `.auvp` vault file — delete it and everything is gone; exported SSH private key files are yours to manage and destroy.
- **Update channel**: distributed as source code, no built-in auto-update; versions follow this repository's tags and release page.

### Features

- **Three AEAD ciphers**: AES-256-GCM / ChaCha20-Poly1305 / SM4-GCM (Chinese national standard GB/T 32907-2016 + GB/T 17964-2021), chosen at vault creation;
- **Argon2id** key derivation (default 64 MiB / t=3 / p=1, 16-byte OS-entropy salt);
- **Three credential combinations**: master password / key file (any file) / both; v1 vaults upgrade automatically;
- **Vault core**: entry CRUD, `/`-separated groups, five-field search, edit history (capped at 20 by default, adjustable, 0 = off), atomic writes;
- **TOTP**: RFC 6238 implemented in-tree, `otpauth://` and base32 entry, QR display and screenshot-scan import;
- **KDBX interop**: import KeePass 1.x–4.x, export KDBX 4; groups, history and TOTP carried both ways;
- **SSH key agent**: Ed25519 generate / import / export; speaks the ssh-agent protocol so ssh / git / IDEs work unchanged; per-signature confirmation; keys not "on duty" are never exposed;
- **Password generator**: NIST SP 800-63B aligned, rejection sampling without modulo bias, excludable confusable characters, exact entropy readout;
- **TUI** (full-screen ratatui) and **GUI** (native egui window with a File/Entries/Tools/Help menu bar);
- **zh-CN / en bilingual**, switchable at runtime;
- **Auto-lock**: keys wiped after 10 minutes idle (waived while the agent runs).

### Build and use

Requires a Rust toolchain (edition 2021):

```bash
cargo build --release --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

- **TUI**: `auv-pass-tui` with no arguments opens the full-screen UI; direct modes: `find <vault> <term> [--copy]`, `list <vault>`, `--version`;
- **GUI**: `auv-pass-gui` is a native window program (no console window on Windows);
- The key-file path can be preset via `AUV_PASS_KEYFILE`; language via `AUV_PASS_LANG` / `AUV_LANG`.

### License

Dual-licensed under MulanPSL-2.0 OR Apache-2.0 (Mulan first); see [LICENSE-MulanPSL-2.0](LICENSE-MulanPSL-2.0) and [LICENSE-Apache-2.0](LICENSE-Apache-2.0). Third-party notices: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Security reporting: [SECURITY.md](SECURITY.md). Full usage guide: [docs/使用手册.txt](docs/使用手册.txt) (Chinese/English).
