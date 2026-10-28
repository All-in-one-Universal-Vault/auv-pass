// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// auv-pass-engine 错误。
///
/// 解密类失败刻意不细分原因(篡改/错钥/AAD 不符同观),避免给攻击者提供 oracle。
#[derive(Debug, Error)]
pub enum Error {
    #[error("加密失败:{0}")]
    Encrypt(String),
    #[error("解密失败:密文/nonce/AAD 被篡改或密钥不符")]
    Decrypt,
    #[error("Argon2id 派生失败:{0}")]
    Kdf(String),
    #[error("KDF 参数不合法:{0}")]
    InvalidKdfParams(String),
    #[error("系统熵源失败:{0}")]
    Entropy(String),
    #[error("IO 错误:{0}")]
    Io(#[from] std::io::Error),
    #[error("库文件格式错误:{0}")]
    Format(String),
    #[error("条目不存在:{0}")]
    EntryNotFound(String),
    #[error("组非空(仍有条目),拒绝删除:{0}")]
    GroupNotEmpty(String),
    #[error("生成器参数不合法:{0}")]
    InvalidGenOptions(String),
}
