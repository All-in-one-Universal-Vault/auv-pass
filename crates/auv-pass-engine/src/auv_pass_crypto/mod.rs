// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 加密原语模块(engine 一级核心模块,带 auv_pass_ 前缀)。
//!
//! 红线落地:
//! - 主密码只以 `Zeroizing` 形态存活于内存,绝不落盘/进日志;
//! - 派生密钥与解密明文均为 `Zeroizing`,drop 自动清零;
//! - 盐与 nonce 非敏感(安全性依赖 KDF 唯一性与 AEAD 认证),可明文入库;
//! - 随机源一律 OS 熵(`getrandom::fill`),密钥材料不经用户态 PRNG。

pub mod cipher;
pub mod kdf;

pub use cipher::{
    auv_pass_decrypt, auv_pass_encrypt, auv_pass_generate_nonce, AuvPassCipherAlgo,
    AuvPassEncryptedBlob, AUV_PASS_NONCE_LEN, AUV_PASS_TAG_LEN,
};
pub use kdf::{
    auv_pass_derive_key, auv_pass_generate_salt, AuvPassKdfParams, AUV_PASS_KEY_LEN,
    AUV_PASS_SALT_LEN,
};
