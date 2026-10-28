// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! AUVP 库文件格式(自有格式,随仓文档化,可被第三方解析)。
//!
//! ```text
//! 偏移   内容
//! 0..4   魔数 "AUVP"
//! 4..6   格式版本 u16 LE(当前 1)
//! 6      算法标签长度 u8
//! 7..    算法标签 UTF-8("AES-256-GCM"/"ChaCha20-Poly1305"/"SM4-GCM")
//! ..     KDF 参数 m/t/p u32 LE ×3
//! ..     盐 16 字节
//! ——以上为库头(明文,非敏感;头字节整体即 AAD)——
//! ..     nonce 12 字节
//! ..     密文(条目模型 JSON + 16 字节认证 tag)
//!
//! v2 起盐后追加 **凭据字节** u8(三凭据组合):
//! 1=密码 2=密钥文件 3=密码+密钥文件;v1 无此字节(视为 1=密码,向后兼容)。
//! 凭据字节在 AAD 内——篡改凭据模式在解密端整体失败。
//! ```
//!
//! 解析时校验魔数/版本/算法标签,并重放 KDF 参数校验——
//! 恶意库头(如超大内存参数)在派生前即被拒,不会拖死解锁。

use crate::auv_pass_crypto::{AuvPassCipherAlgo, AuvPassKdfParams, AUV_PASS_SALT_LEN};
use crate::error::{Error, Result};

/// 库文件魔数。
pub const AUV_PASS_VAULT_MAGIC: &[u8; 4] = b"AUVP";
/// 库文件格式版本(v3:索引块 + 逐附件加密块;v1/v2 为单块 JSON,读入自动升级)。
pub const AUV_PASS_VAULT_FORMAT_VERSION: u16 = 3;

/// 凭据组合(v2 头部凭据字节;v1 文件视为 Password)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuvPassVaultCred {
    /// 仅主密码。
    Password,
    /// 仅密钥文件(任意文件,SHA-256 全文作材料)。
    KeyFile,
    /// 主密码 + 密钥文件。
    PasswordKeyFile,
}

impl AuvPassVaultCred {
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Password => 1,
            Self::KeyFile => 2,
            Self::PasswordKeyFile => 3,
        }
    }
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::Password),
            2 => Ok(Self::KeyFile),
            3 => Ok(Self::PasswordKeyFile),
            other => Err(Error::Format(format!("未知凭据字节:{other}"))),
        }
    }
}

/// 明文库头:算法 + KDF 参数 + 盐(非敏感,可上屏)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuvPassVaultHeader {
    pub algo: AuvPassCipherAlgo,
    pub kdf: AuvPassKdfParams,
    pub salt: [u8; AUV_PASS_SALT_LEN],
    /// 凭据组合(v1 读入恒为 Password;写出恒为 v2)。
    pub cred: AuvPassVaultCred,
}

impl AuvPassVaultHeader {
    /// 序列化为库头字节(同时就是加密时的 AAD)。
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.kdf.validate()?;
        let label = self.algo.label();
        if label.len() > u8::MAX as usize {
            return Err(Error::Format("算法标签超长".into()));
        }
        let mut out = Vec::with_capacity(7 + label.len() + 12 + AUV_PASS_SALT_LEN);
        out.extend_from_slice(AUV_PASS_VAULT_MAGIC);
        out.extend_from_slice(&AUV_PASS_VAULT_FORMAT_VERSION.to_le_bytes());
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&self.kdf.m_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.t_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.p_cost.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.push(self.cred.to_byte());
        Ok(out)
    }

    /// 从文件字节解析(返回 头 + 消费长度)。魔数/版本/算法/参数全验。
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 7 || &bytes[0..4] != AUV_PASS_VAULT_MAGIC {
            return Err(Error::Format("不是 AUVP 库文件(魔数不符)".into()));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != 1 && version != 2 && version != AUV_PASS_VAULT_FORMAT_VERSION {
            return Err(Error::Format(format!("不支持的库格式版本:{version}")));
        }
        let label_len = bytes[6] as usize;
        let need = 7 + label_len + 12 + AUV_PASS_SALT_LEN + if version >= 2 { 1 } else { 0 };
        if bytes.len() < need {
            return Err(Error::Format("库头不完整".into()));
        }
        let label = std::str::from_utf8(&bytes[7..7 + label_len])
            .map_err(|_| Error::Format("算法标签非 UTF-8".into()))?;
        let algo = match label {
            "AES-256-GCM" => AuvPassCipherAlgo::Aes256Gcm,
            "ChaCha20-Poly1305" => AuvPassCipherAlgo::ChaCha20Poly1305,
            "SM4-GCM" => AuvPassCipherAlgo::Sm4Gcm,
            other => return Err(Error::Format(format!("未知算法标签:{other}"))),
        };
        let mut off = 7 + label_len;
        let rd_u32 = |off: &mut usize| -> u32 {
            let v = u32::from_le_bytes(bytes[*off..*off + 4].try_into().expect("长度已校验"));
            *off += 4;
            v
        };
        let kdf = AuvPassKdfParams {
            m_kib: rd_u32(&mut off),
            t_cost: rd_u32(&mut off),
            p_cost: rd_u32(&mut off),
        };
        kdf.validate()?;
        let salt: [u8; AUV_PASS_SALT_LEN] = bytes[off..off + AUV_PASS_SALT_LEN]
            .try_into()
            .expect("长度已校验");
        let cred = if version >= 2 {
            AuvPassVaultCred::from_byte(bytes[need - 1])?
        } else {
            AuvPassVaultCred::Password // v1 恒为密码
        };
        Ok((
            Self {
                algo,
                kdf,
                salt,
                cred,
            },
            need,
        ))
    }
}
