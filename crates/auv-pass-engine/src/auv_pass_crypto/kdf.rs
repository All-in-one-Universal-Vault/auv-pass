// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! Argon2id 密钥派生(RFC 9106):主密码 → 32 字节 vault 密钥。
//!
//! - 盐:16 字节 OS 熵,每库首建一次,明文存库头(非敏感,只需唯一);
//! - 参数:默认 m=64 MiB/t=3/p=1(超 OWASP 2023 最低线 19 MiB/t2/p1),
//!   随库头明文存储,解锁按头重放;
//! - 红线:密码入参只借用,内部不留副本;输出 `Zeroizing`,drop 即清。

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// 派生密钥长度(AES-256 / ChaCha20 同为 32 字节)。
pub const AUV_PASS_KEY_LEN: usize = 32;
/// 盐长度(字节)。
pub const AUV_PASS_SALT_LEN: usize = 16;

/// 内存下限(8 MiB;覆盖 Argon2 规范 8×p KiB 下限在 p≤8 时的取值)。
pub const AUV_PASS_MIN_M_KIB: u32 = 8 * 1024;
/// 内存上限(4 GiB,防误配拖死解锁)。
pub const AUV_PASS_MAX_M_KIB: u32 = 4 * 1024 * 1024;
/// 并行度上限。
pub const AUV_PASS_MAX_P: u32 = 8;

/// Argon2id 参数(内存 KiB / 迭代次数 / 并行度)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuvPassKdfParams {
    /// 内存用量(KiB)。
    pub m_kib: u32,
    /// 迭代次数。
    pub t_cost: u32,
    /// 并行度(lane 数)。
    pub p_cost: u32,
}

impl Default for AuvPassKdfParams {
    fn default() -> Self {
        Self {
            m_kib: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl AuvPassKdfParams {
    /// 合法性校验:不合法直接报错,杜绝 Argon2 内部 panic 路径。
    pub fn validate(&self) -> Result<()> {
        if self.t_cost < 1 {
            return Err(Error::InvalidKdfParams("迭代次数 t 不得小于 1".into()));
        }
        if self.p_cost < 1 || self.p_cost > AUV_PASS_MAX_P {
            return Err(Error::InvalidKdfParams(format!(
                "并行度 p 须在 1..={AUV_PASS_MAX_P}"
            )));
        }
        if self.m_kib < AUV_PASS_MIN_M_KIB {
            return Err(Error::InvalidKdfParams(format!(
                "内存 m 不得低于 {AUV_PASS_MIN_M_KIB} KiB(OWASP 折中下限)"
            )));
        }
        if self.m_kib > AUV_PASS_MAX_M_KIB {
            return Err(Error::InvalidKdfParams(format!(
                "内存 m 不得高于 {AUV_PASS_MAX_M_KIB} KiB"
            )));
        }
        if self.m_kib < 8 * self.p_cost {
            return Err(Error::InvalidKdfParams(
                "Argon2 规范要求 m ≥ 8×p(KiB)".into(),
            ));
        }
        Ok(())
    }
}

/// 生成 16 字节 OS 熵盐(getrandom,与 rand 家族同底座)。
pub fn auv_pass_generate_salt() -> Result<[u8; AUV_PASS_SALT_LEN]> {
    let mut salt = [0u8; AUV_PASS_SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| Error::Entropy(e.to_string()))?;
    Ok(salt)
}

/// Argon2id 派生:同一 (password, salt, params) 恒得同一密钥;任一不同则密钥全异。
///
/// 输出为 32 字节 `Zeroizing`,drop 自动清零(红线:zeroize 所有敏感内存)。
pub fn auv_pass_derive_key(
    password: &[u8],
    salt: &[u8; AUV_PASS_SALT_LEN],
    params: &AuvPassKdfParams,
) -> Result<Zeroizing<[u8; AUV_PASS_KEY_LEN]>> {
    params.validate()?;
    let a2 = ParamsBuilder::new()
        .m_cost(params.m_kib)
        .t_cost(params.t_cost)
        .p_cost(params.p_cost)
        .output_len(AUV_PASS_KEY_LEN)
        .build()
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; AUV_PASS_KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, a2)
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(key)
}
