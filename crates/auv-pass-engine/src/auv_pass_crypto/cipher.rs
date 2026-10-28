// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! AEAD 对称加密:AES-256-GCM、ChaCha20-Poly1305 与 SM4-GCM(国标)三算法,用户可选。
//!
//! - nonce:12 字节,每次加密由 OS 熵源新生成,绝不复用(随机 nonce 模式,
//!   NIST 生日界下单密钥消息数上限约 2^32,密码库场景余量充足);
//! - AAD:附加认证数据——不加密但参与认证,库文件加密时绑定库头(版本/算法/KDF 参数/盐);
//! - 密文 = 明文 + 16 字节认证 tag,任何比特翻转在解密端一律失败;
//! - 失败语义:篡改/错钥/AAD 不符/畸形长度统一报 `Error::Decrypt`,不区分内部原因;
//! - 内存纪律:加解密工作缓冲均 `Zeroizing`(明文残留 drop 即清)。
//! - SM4-GCM(国标路径,GB/T 32907-2016 分组密码 + GB/T 17964-2021 GCM 工作模式):SM4 为
//!   设计,取 Argon2id 派生 32 字节的前 16 字节(输出均匀,截断即满强度);
//!   等效强度 128 位档,最高熵路径仍为 AES-256-GCM/ChaCha20-Poly1305。
//!
//! API 注:aead 0.6 起核心为 `AeadInOut` 原地分离接口(tag 独立返回),
//! 定长数组转换走 `TryFrom`(`from_slice` 已弃用)。

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut, Key, KeyInit};
use aes_gcm::{Aes256Gcm, AesGcm, Nonce as AesNonce, Tag as AesTag};
use chacha20poly1305::{ChaCha20Poly1305, Key as CcKey, Nonce as CcNonce, Tag as CcTag};
use sm4::Sm4;
use zeroize::Zeroizing;

use crate::auv_pass_crypto::kdf::AUV_PASS_KEY_LEN;
use crate::error::{Error, Result};

/// AES-GCM nonce 具体类型(12 字节)。
type AesNonce12 = AesNonce<U12>;
/// SM4-GCM 具体类型:GCM 复用 aes-gcm 0.11 泛型,块密码注入国标 SM4。
type Sm4GcmCipher = AesGcm<Sm4, U12>;

/// AEAD 算法选择(用户可选)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuvPassCipherAlgo {
    /// AES-256-GCM:有 AES-NI 硬件加速的平台首选。
    Aes256Gcm,
    /// ChaCha20-Poly1305:无硬件加速平台(老 CPU/部分 ARM)更稳,恒时安全。
    ChaCha20Poly1305,
    /// SM4-GCM(国标):GB/T 32907-2016 + GB/T 17964-2021;128 位密钥,合规路径。
    Sm4Gcm,
}

impl AuvPassCipherAlgo {
    /// 展示名(亦为库内算法标签)。
    pub fn label(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Sm4Gcm => "SM4-GCM",
        }
    }
}

/// nonce 长度(三算法一致)。
pub const AUV_PASS_NONCE_LEN: usize = 12;
/// 认证 tag 长度(三算法一致;密文长度 = 明文 + AUV_PASS_TAG_LEN)。
pub const AUV_PASS_TAG_LEN: usize = 16;

/// 一次加密的自包含产物:算法 + nonce + 密文(含 tag)。
///
/// nonce/密文非敏感,可明文入库;库文件序列化即以本结构为密文载荷。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuvPassEncryptedBlob {
    /// 加密算法(解密时按此分发,防跨算法误用)。
    pub algo: AuvPassCipherAlgo,
    /// 12 字节随机 nonce。
    pub nonce: [u8; AUV_PASS_NONCE_LEN],
    /// 密文(明文 + 16 字节 tag)。
    pub ciphertext: Vec<u8>,
}

/// 由 OS 熵源生成新 nonce。
pub fn auv_pass_generate_nonce() -> Result<[u8; AUV_PASS_NONCE_LEN]> {
    let mut nonce = [0u8; AUV_PASS_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| Error::Entropy(e.to_string()))?;
    Ok(nonce)
}

/// 用 32 字节密钥加密明文(可带 AAD),返回自包含密文块。
///
/// 明文由调用方以 `Zeroizing` 持有;密钥即 `auv_pass_derive_key` 的输出(零拷贝借用)。
/// 工作缓冲 `Zeroizing`:明文副本在加密中被密文覆盖,退出前残留一并清零。
pub fn auv_pass_encrypt(
    algo: AuvPassCipherAlgo,
    key: &[u8; AUV_PASS_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AuvPassEncryptedBlob> {
    let nonce = auv_pass_generate_nonce()?;
    let mut buf = Zeroizing::new(plaintext.to_vec());
    let tag: [u8; AUV_PASS_TAG_LEN] = match algo {
        AuvPassCipherAlgo::Aes256Gcm => {
            let cipher = Aes256Gcm::new(
                &Key::<Aes256Gcm>::try_from(key.as_slice()).expect("密钥长度恒 32 字节"),
            );
            let tag = cipher
                .encrypt_inout_detached(
                    &AesNonce12::try_from(nonce.as_slice()).expect("nonce 长度恒 12 字节"),
                    aad,
                    (&mut buf[..]).into(),
                )
                .map_err(|e| Error::Encrypt(e.to_string()))?;
            tag.as_slice().try_into().expect("GCM tag 恒 16 字节")
        }
        AuvPassCipherAlgo::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(
                &CcKey::try_from(key.as_slice()).expect("密钥长度恒 32 字节"),
            );
            let tag = cipher
                .encrypt_inout_detached(
                    &CcNonce::try_from(nonce.as_slice()).expect("nonce 长度恒 12 字节"),
                    aad,
                    (&mut buf[..]).into(),
                )
                .map_err(|e| Error::Encrypt(e.to_string()))?;
            tag.as_slice().try_into().expect("Poly1305 tag 恒 16 字节")
        }
        AuvPassCipherAlgo::Sm4Gcm => {
            // SM4 为 128 位密钥设计:取 Argon2id 派生 32 字节的前 16 字节
            //(派生输出均匀,截断即 SM4 满强度)
            let key16: &[u8; 16] = key[..16].try_into().expect("派生密钥恒 32 字节");
            let cipher = Sm4GcmCipher::new(
                &Key::<Sm4GcmCipher>::try_from(key16.as_slice()).expect("SM4 密钥恒 16 字节"),
            );
            let tag = cipher
                .encrypt_inout_detached(
                    &AesNonce12::try_from(nonce.as_slice()).expect("nonce 长度恒 12 字节"),
                    aad,
                    (&mut buf[..]).into(),
                )
                .map_err(|e| Error::Encrypt(e.to_string()))?;
            tag.as_slice().try_into().expect("GCM tag 恒 16 字节")
        }
    };
    let mut ciphertext = buf.to_vec(); // 拷出非敏感密文;Zeroizing 缓冲随后清零
    ciphertext.extend_from_slice(&tag);
    Ok(AuvPassEncryptedBlob {
        algo,
        nonce,
        ciphertext,
    })
}

/// 解密密文块;成功返回 `Zeroizing` 明文(drop 自动清零)。
///
/// 畸形长度(短于 tag)同样统一报 `Error::Decrypt`。
pub fn auv_pass_decrypt(
    blob: &AuvPassEncryptedBlob,
    key: &[u8; AUV_PASS_KEY_LEN],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.ciphertext.len() < AUV_PASS_TAG_LEN {
        return Err(Error::Decrypt);
    }
    let (ct, tag) = blob
        .ciphertext
        .split_at(blob.ciphertext.len() - AUV_PASS_TAG_LEN);
    let mut pt = Zeroizing::new(ct.to_vec()); // 密文副本,解密成功后被明文覆盖
    match blob.algo {
        AuvPassCipherAlgo::Aes256Gcm => {
            let cipher = Aes256Gcm::new(
                &Key::<Aes256Gcm>::try_from(key.as_slice()).expect("密钥长度恒 32 字节"),
            );
            cipher
                .decrypt_inout_detached(
                    &AesNonce12::try_from(blob.nonce.as_slice()).expect("nonce 长度恒 12 字节"),
                    aad,
                    (&mut pt[..]).into(),
                    &AesTag::try_from(tag).expect("tag 长度恒 16 字节"),
                )
                .map_err(|_| Error::Decrypt)?;
        }
        AuvPassCipherAlgo::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(
                &CcKey::try_from(key.as_slice()).expect("密钥长度恒 32 字节"),
            );
            cipher
                .decrypt_inout_detached(
                    &CcNonce::try_from(blob.nonce.as_slice()).expect("nonce 长度恒 12 字节"),
                    aad,
                    (&mut pt[..]).into(),
                    &CcTag::try_from(tag).expect("tag 长度恒 16 字节"),
                )
                .map_err(|_| Error::Decrypt)?;
        }
        AuvPassCipherAlgo::Sm4Gcm => {
            let key16: &[u8; 16] = key[..16].try_into().expect("派生密钥恒 32 字节");
            let cipher = Sm4GcmCipher::new(
                &Key::<Sm4GcmCipher>::try_from(key16.as_slice()).expect("SM4 密钥恒 16 字节"),
            );
            cipher
                .decrypt_inout_detached(
                    &AesNonce12::try_from(blob.nonce.as_slice()).expect("nonce 长度恒 12 字节"),
                    aad,
                    (&mut pt[..]).into(),
                    &AesTag::try_from(tag).expect("tag 长度恒 16 字节"),
                )
                .map_err(|_| Error::Decrypt)?;
        }
    }
    Ok(pt)
}
