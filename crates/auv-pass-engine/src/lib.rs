// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! auv-pass-engine:密码库引擎(全称 Authenticated User Vault, for Password)。
//! 零 UI 依赖、零网络(安全红线:本 crate 永不引入网络栈)。
//! 主密码与派生密钥绝不落盘、绝不进日志;敏感内存形态一律 zeroize。
//!
//! 命名约定:engine 内一级核心/特色模块带 `auv_pass_` 前缀,
//! 专有函数 `auv_pass_*`、类型 `AuvPass*`、常量 `AUV_PASS_*`;
//! `Error`/`Result` 沿用通用惯例,局部变量与第三方 API 名不加前缀。
//!
//! 模块划分:`auv_pass_crypto`——Argon2id 派生 + 三 AEAD(AES-256-GCM/ChaCha20-Poly1305/SM4-GCM 国标);
//! `auv_pass_vault`(AUVP 自有格式 + CRUD + 分组 + 搜索 + 修改历史)、
//! `auv_pass_gen`(密码生成器,对齐 NIST SP 800-63B)、
//! `auv_pass_totp`(RFC 6238 自实现 + otpauth 解析,随条目存储)、
//! `auv_pass_kdbx`(KDBX 导入导出)、`auv_pass_agent`(SSH 密钥代理)。

mod auv_pass_agent;
mod auv_pass_clipboard;
mod auv_pass_crypto;
mod auv_pass_fs;
mod auv_pass_gen;
pub mod auv_pass_i18n;
mod auv_pass_kdbx;
mod auv_pass_totp;
mod auv_pass_vault;
mod error;

pub use auv_pass_agent::{
    auv_pass_agent_build_failure, auv_pass_agent_build_identities_answer,
    auv_pass_agent_build_sign_response, auv_pass_agent_default_socket,
    auv_pass_agent_parse_sign_request, auv_pass_agent_start, auv_pass_ssh_fingerprint_hex,
    AuvPassAgentConfirm, AuvPassAgentHandle, AuvPassSshKey,
};
pub use auv_pass_clipboard::auv_pass_clipboard_should_clear;
pub use auv_pass_crypto::{
    auv_pass_decrypt, auv_pass_derive_key, auv_pass_encrypt, auv_pass_generate_nonce,
    auv_pass_generate_salt, AuvPassCipherAlgo, AuvPassEncryptedBlob, AuvPassKdfParams,
    AUV_PASS_KEY_LEN, AUV_PASS_NONCE_LEN, AUV_PASS_SALT_LEN, AUV_PASS_TAG_LEN,
};
pub use auv_pass_fs::auv_pass_write_secret_file;
pub use auv_pass_gen::{
    auv_pass_gen_entropy_bits, auv_pass_generate_password, AuvPassGenOptions,
    AUV_PASS_GEN_DEFAULT_LEN, AUV_PASS_GEN_DIGITS, AUV_PASS_GEN_LOWER, AUV_PASS_GEN_MAX_LEN,
    AUV_PASS_GEN_MIN_LEN, AUV_PASS_GEN_SYMBOLS, AUV_PASS_GEN_UPPER,
};
pub use auv_pass_i18n::auv_pass_i18n_init;
pub use auv_pass_kdbx::{auv_pass_kdbx_export, auv_pass_kdbx_import, AuvPassKdbxImport};
pub use auv_pass_totp::{
    auv_pass_totp_base32_decode, auv_pass_totp_generate, auv_pass_totp_generate_with_key,
    auv_pass_totp_parse_otpauth, auv_pass_totp_remaining_seconds, AuvPassTotpAlgo,
    AuvPassTotpConfig, AUV_PASS_TOTP_DEFAULT_DIGITS, AUV_PASS_TOTP_DEFAULT_PERIOD,
};
pub use auv_pass_vault::{
    AuvPassAttachmentMeta, AuvPassEntry, AuvPassEntryId, AuvPassEntryInput, AuvPassEntrySnapshot,
    AuvPassVault, AuvPassVaultCred, AuvPassVaultHeader, AuvPassVaultModel,
    AUV_PASS_HISTORY_LIMIT_DEFAULT, AUV_PASS_VAULT_FORMAT_VERSION, AUV_PASS_VAULT_MAGIC,
};
pub use error::{Error, Result};
