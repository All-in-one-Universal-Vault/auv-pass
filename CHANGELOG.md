# 更新日志 / Changelog

本文件格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循语义化版本 2.0.0。
Format follows Keep a Changelog; versions follow Semantic Versioning 2.0.0.

## [0.1.0] - 2026-10-28

首次发布：本地优先密码管理器（TUI + GUI 双前端）。
First release: a local-first password manager with TUI and GUI front ends.

### 新增 / Added

- **加密库**：Argon2id 密钥派生（默认 64 MiB / t=3 / p=1）+ 三算法 AEAD——AES-256-GCM / ChaCha20-Poly1305 / SM4-GCM（国标 GB/T 32907-2016 + GB/T 17964-2021，标准向量 KAT 复现）；SM4 与 ChaCha20 分别面向国标合规与无 AES-NI 平台。
- **EN**: crypto core — Argon2id key derivation (default 64 MiB / t=3 / p=1) plus three AEAD ciphers: AES-256-GCM, ChaCha20-Poly1305 and SM4-GCM (Chinese national standards GB/T 32907-2016 + GB/T 17964-2021, standard-vector KATs reproduced); SM4 serves compliance paths, ChaCha20 machines without AES-NI.
- **AUVP 库格式**：明文库头（算法 / KDF 参数 / 盐 / 凭据字节）+ AEAD 密文块，头字节整体即 AAD，任何篡改在解密端整体失败；解析期重放 KDF 参数校验，恶意头在派生前被拒。
- **EN**: the AUVP vault format — plaintext header (cipher / KDF params / salt / credential byte) followed by the AEAD blob, with the whole header bound as AAD so any tamper fails decryption; KDF parameters are re-validated at parse time, so hostile headers are rejected before derivation.
- **凭据三组合**：主密码 / 密钥文件（任意文件，取 SHA-256 全文作派生材料）/ 两者并用；v1 库读入自动升级。
- **EN**: three credential combinations — master password / key file (any file, hashed whole as derivation material) / both; v1 vaults upgrade on save.
- **密码库核心**：条目 CRUD、`/` 分层分组、五字段大小写不敏感搜索、修改历史（默认封顶 20 条，可调，0 = 禁用）、同目录临时文件 + rename 原子写；Unix 下库文件与导出私钥落地即 0600。
- **EN**: vault core — entry CRUD, `/`-separated groups, case-insensitive five-field search, edit history (capped at 20 by default, adjustable, 0 = off) and atomic writes via same-directory temp file + rename; vault files and exported private keys land with 0600 on Unix.
- **TOTP**：RFC 6238 / RFC 4226 自实现（官方向量 KAT 全过），`otpauth://` URI 与 base32 密钥录入，二维码显示与截图扫码导入。
- **EN**: TOTP — RFC 6238 / RFC 4226 implemented in-tree (all official vector KATs pass), with `otpauth://` URI and base32 entry, QR display and screenshot-scan import.
- **KDBX 双向互导**：导入 KeePass 1.x–4.x，导出 KDBX 4（AES-256）；分组树、修改历史、TOTP 双向保留，导出文件经独立读回核验。
- **EN**: KDBX interop — import KeePass 1.x–4.x and export KDBX 4 (AES-256); group trees, edit history and TOTP carry both ways, with exports verified by an independent read-back.
- **SSH 密钥代理**：Ed25519 密钥生成（私钥出生到入库明文不落盘）/ 导入（带口令验口令）/ 导出 / 删除；实现 ssh-agent 兼容协议（消息 11–14），ssh / git / IDE 零改动即用；每次签名弹窗确认（可会话级允许），未「上岗」密钥不对外暴露；快照模式，变更需重启 agent。
- **EN**: SSH key agent — Ed25519 generate (private key never touches disk in the clear) / import (passphrase-checked) / export / delete; speaks the ssh-agent protocol (messages 11–14) so ssh / git / IDEs work unchanged; per-signature confirmation (session-scoped allow available), keys not "on duty" stay hidden; snapshot mode, changes require an agent restart.
- **密码生成器**：NIST SP 800-63B 对齐——均匀取样 + 拒绝采样消除模偏置，长度 8–128，字符类可选不强制，排除字符（如易混 0 O 1 l I），精确熵可算。
- **EN**: password generator aligned with NIST SP 800-63B — uniform sampling with rejection against modulo bias, length 8–128, optional character classes, excludable characters (e.g. confusable 0 O 1 l I), and exact entropy.
- **TUI**：ratatui 全屏界面——首页 / 双栏主屏（分组 + 条目）/ 详情 / 历史 / 快照 / 通用表单（敏感字段遮蔽）/ SSH 钥匙管理屏 / 签名确认弹窗；字母快捷键；Tab 路径补全；直达模式 `find` / `list`。
- **EN**: TUI — full-screen ratatui UI with home, two-pane main screen (groups + entries), detail, history, snapshot, a generic form (secret fields masked), the SSH key screen and sign-request confirmation; letter shortcuts, Tab path completion, and `find` / `list` direct modes.
- **GUI**：egui 原生窗口——顶部菜单栏（文件/条目/工具/帮助，含关于窗口与退出入口）、工具栏、多列表格（密码列遮蔽、列宽可调）与竖排详情面板（分割条可拖拽）、编辑器（内嵌生成器、组名下拉、TOTP 扫码、基本/高级页签）、独立生成器、SSH 钥匙与 agent 启停、系统文件选择器、剪贴板倒计时。
- **EN**: GUI — native egui window with a top menu bar (File/Entries/Tools/Help, including an About window and Quit), a toolbar, a multi-column entry table (masked password column, resizable) with a vertical detail pane (draggable splitters), an editor with embedded generator / group dropdown / TOTP scan / Basic-Advanced tabs, a standalone generator, SSH keys and agent start-stop, system file dialogs and a clipboard countdown.
- **交互防护**：保存前检查（同组疑似重复/密码首尾空格/URL 前缀，可选仍要保存）；KDBX 导入预览（条数/组数/跳过清单）；导出覆盖确认；保存失败显式告警与磁盘空间预检；主密码强度条；键盘快捷键（Ctrl+N/F/C/L）；状态栏自动锁定倒计时与 agent 运行标识；手动清空剪贴板；空库引导；窗口标题库状态；**开库前可用生成器**（登录页入口/工具菜单/独立窗口，新建库主密码 Gen 生成）。
- **EN**: interaction guards — pre-save checks (possible duplicate / password whitespace / URL prefix, with save-anyway), KDBX import preview (counts plus skipped list), overwrite confirmation on exports, explicit save-failure alerts with a disk-space precheck, master-password strength meter, keyboard shortcuts (Ctrl+N/F/C/L), auto-lock countdown and agent indicator in the status bar, manual clipboard clearing, empty-vault guidance, a vault-aware window title, and **generator access before unlocking** (login-page link, Tools menu, standalone window, plus Gen on the create-vault master-password field).
- **安全红线**：零网络出口；主密码不落盘、不进日志；敏感内存一律 zeroize；复制密码 30 秒自动清空（TOTP 15 秒），代数戳 + 读回比对防误清；空闲 10 分钟自动锁定；密码明文仅显式操作时上屏。
- **EN**: security commitments — zero network egress; the master password never touches disk or logs; all sensitive memory is zeroized; copied passwords self-clear after 30 seconds (TOTP after 15) with epoch + read-back checks against wiping newer copies; auto-lock after 10 minutes idle; plaintext shown only on explicit action.
- **zh-CN / en 双语**：全部界面文案经 Fluent 目录（zh-CN 源语言），`AUV_PASS_LANG` / `AUV_LANG` / 系统 UI 语言探测，GUI 按钮与 TUI `z` 键运行时切换；目录键集与源码引用有哨兵测试防漂移。
- **EN**: bilingual zh-CN / en — all UI copy flows through Fluent catalogs (zh-CN as source), detected from `AUV_PASS_LANG` / `AUV_LANG` / OS UI language, switchable at runtime via the GUI menu or the TUI `z` key; sentinel tests guard catalog/code drift.
- **附件（AUVP v3）**：任何文件原样附加到条目——字节零改动、SHA-256 登记；导出逐字节一致并还原时间戳；库格式升级 v3（索引块 + 逐附件独立 AEAD 块，AAD 绑库头与附件 id），v1/v2 旧库直开、保存自动升级；单个附件 >100MB 弹大文件提示；入口为编辑器高级页 / 详情面板 / 拖拽，条目表 📎 列显示件数；KDBX 导入导出同步携带附件。
- **EN**: attachments (AUVP v3) — attach any file to an entry verbatim with a registered SHA-256; exports are byte-identical and restore timestamps; the vault format moves to v3 (index block plus one AEAD block per attachment, AAD binding header and attachment id), with v1/v2 vaults opening directly and upgrading on save; attachments over 100 MB raise a large-file prompt; entry points are the editor's Advanced tab, the detail pane and drag-and-drop, with a 📎 count column; KDBX import/export carries attachments both ways.
- **三期功能**：更改主密码/更换密钥文件（引擎级凭据重派生+重加密）；库属性（算法/KDF/条目/附件/文件大小/整库 SHA-256）；健康报告（弱密码/同密码/陈旧，纯本地）；批量操作（Ctrl+点击多选→批量删除）；暗/亮主题切换；字体放大 15%。
- **EN**: phase-three features — change master password / replace key file (engine-level credential re-derivation with full re-encryption on save); vault properties (algorithm, KDF, entries, attachments, file size, whole-file SHA-256); a local-only health report (weak / reused / stale passwords); batch operations (Ctrl+click multi-select with batch delete); dark/light theme toggle; font scaling at 15% above native.
- **文档与图标**：双语使用手册（docs/使用手册.txt）；自制应用图标（黑底白字 AUV-PASS，多尺寸，构建期嵌入 Windows 可执行文件）。
- **EN**: docs and icon — a bilingual user manual (docs/使用手册.txt) and a self-made application icon (AUV-PASS in white on black, multi-size, embedded into the Windows executable at build time).

### 验证状态 / Verification

- Windows：构建与测试通过（72 项测试通过、1 项端到端按需运行、2 项 Unix 权限用例在 Windows 跳过）+ clippy `-D warnings` + fmt；macOS / Linux 待后续版本验证。
- **EN**: verified on Windows — build and tests pass (72 passed, one end-to-end test run on demand, two Unix-only permission cases skipped on Windows) plus clippy `-D warnings` and fmt; macOS / Linux verification is planned for a later release.
