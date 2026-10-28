# 第三方开源组件声明（Third-Party Notices）

auv-pass 使用以下开源组件（均与本项目 MulanPSL-2.0 OR Apache-2.0 双许可兼容）。按各许可要求，分发时保留版权与许可声明；各组件完整许可文本见其上游仓库。

This product uses the open-source components below, all compatible with its MulanPSL-2.0 OR Apache-2.0 dual license. Copyright and license notices are preserved on distribution; full license texts live in the upstream repositories.

## 直接依赖 / Direct dependencies

| 组件 | 用途 | 许可 |
|---|---|---|
| argon2 | Argon2id 密钥派生 | MIT OR Apache-2.0 |
| aes-gcm | AES-256-GCM AEAD（SM4-GCM 亦复用其 GCM 泛型） | MIT OR Apache-2.0 |
| chacha20poly1305 | ChaCha20-Poly1305 AEAD | MIT OR Apache-2.0 |
| sm4 | SM4 分组密码（GB/T 32907-2016） | MIT OR Apache-2.0 |
| zeroize | 敏感内存清零（serde 特性 = Zeroizing 可序列化） | MIT OR Apache-2.0 |
| getrandom | OS 熵安全随机数（盐 / nonce / 种子） | MIT OR Apache-2.0 |
| thiserror | 错误定义 | MIT OR Apache-2.0 |
| serde / serde_json | 库模型序列化与库载荷 JSON | MIT OR Apache-2.0 |
| uuid | 条目标识（v4 = OS 熵） | MIT OR Apache-2.0 |
| crossterm | 终端控制（raw mode / 按键事件） | MIT OR Apache-2.0 |
| ratatui | 全屏终端界面 | MIT OR Apache-2.0 |
| arboard | 跨平台剪贴板（复制 + 30 秒自动清） | MIT OR Apache-2.0 |
| chrono | 时间显示（clock 特性） | MIT OR Apache-2.0 |
| sha1 / sha2 | TOTP HMAC 摘要原语（HMAC 构造自实现）；sha2 亦用于库属性整库校验与附件完整性登记 | MIT OR Apache-2.0 |
| keepass | KDBX 读写（save_kdbx4 特性开写） | MIT |
| ssh-key | OpenSSH 私钥容器（ed25519 / getrandom / encryption 特性） | MIT OR Apache-2.0 |
| ed25519-dalek | Ed25519 签名原语 | MIT OR Apache-2.0 |
| interprocess | 跨平台本地套接字（Unix socket / 命名管道统一） | MIT OR Apache-2.0 |
| eframe / egui / egui_extras | GUI 框架与表格 | MIT OR Apache-2.0 |
| rfd | 系统文件选择器（FileDialog） | MIT |
| bardecoder | 二维码读码（纯 Rust 解码） | MIT |
| qrcode | 二维码显示（生成） | MIT OR Apache-2.0 |
| image | 图片加载（png / jpeg 特性） | MIT OR Apache-2.0 |
| winresource | Windows 图标资源编译（构建期依赖，仅 Windows 目标；应用图标嵌入 exe） | MIT |
| fs2 | 磁盘可用空间查询（保存前空间预检） | MIT OR Apache-2.0 |
| filetime | 文件时间戳还原（附件导出时恢复修改/访问时间） | MIT/Apache-2.0 |

## 族共享库 / Family shared libraries

| 组件 | 用途 | 许可 |
|---|---|---|
| auv-ui | GUI 启动样板（`auv_ui_run_shell`）+ CJK 字体（内置 Sarasa Mono SC 基线 + 系统链兜底）；源码见其公开仓（`<仓地址>`） | MulanPSL-2.0 OR Apache-2.0 |
| auv-i18n | Fluent 国际化机制（`auv_i18n_tr` / `auv_i18n_tr_fmt`、命名参数、回退链、缺键告警、sys-locale 探测）；源码见其公开仓（`<仓地址>`） | MulanPSL-2.0 OR Apache-2.0 |

### 经 auv-i18n 传递 / Transitive via auv-i18n

| 依赖 | 用途 | 许可 |
|---|---|---|
| fluent（含 fluent-bundle）/ fluent-syntax / unic-langid | FTL 目录装载与消息渲染 / 目录校验 AST / locale tag 解析 | Apache-2.0 OR MIT |
| sys-locale | 系统 UI 语言探测 | MIT OR Apache-2.0 |

## 内置资源（经 auv-ui 传递）/ Bundled assets (via auv-ui)

| 资源 | 用途 | 许可 |
|---|---|---|
| Sarasa Mono SC Regular（更纱黑体等宽简体，v1.0.43，原样未修改） | 内置 CJK 渲染基线字体（随 auv-ui 嵌入 GUI 二进制） | SIL Open Font License 1.1 |

Sarasa 版权行 / Sarasa copyright notice:

> Copyright (c) 2015-2025, Renzhi Li (aka. Belleve Invis, belleve@typeof.net).
> Portions Copyright (c) 2016 The Inter Project Authors.
> Portions Copyright (c) 2014-2021 Adobe Systems Incorporated (http://www.adobe.com/), with Reserved Font Name 'Source'.
> Portions Copyright (c) 2012 Google Inc.

该字体经 auv-ui **原样分发、未做任何修改**（衍生版本不得使用保留字体名 'Source'）；OFL 1.1 全文与资产核验信息（字节数 / SHA-256）见 auv-ui 仓 THIRD-PARTY-NOTICES.md，发行包随附该文件副本。
The font is redistributed unmodified through auv-ui (derivatives must not use the Reserved Font Name 'Source'); the full OFL 1.1 text and asset verification (size / SHA-256) are carried in the auv-ui repository's THIRD-PARTY-NOTICES.md, a copy of which ships with release packages.

## 义务履行方式 / How obligations are met

1. 本文件随发行版（Release）与二进制一同打包；This file ships with every release and binary.
2. 各组件的上游仓库地址与完整许可文本可通过 crates.io 对应页面获取（按上表组件名检索）；upstream repositories and full license texts are reachable from each component's crates.io page.
3. 传递依赖（aead / cipher / password-hash / rand_core 等）与直接依赖同属宽松许可家族，完整清单以 `cargo metadata` 输出为准；transitive dependencies (aead / cipher / password-hash / rand_core, etc.) belong to the same permissive families — the authoritative list is `cargo metadata` output.
