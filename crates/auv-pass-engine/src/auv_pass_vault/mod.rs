// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 密码库核心(特色功能模块)。
//!
//! 自有加密格式(AUVP):明文库头(魔数+版本+算法标签+KDF 参数+盐)+ AEAD 密文块;
//! **库头字节即 AAD**——头任何比特篡改在解密端整体失败(端到端测试锚定的绑定模式)。
//! 红线:主密码不落盘(仅内存借用);派生密钥 Zeroizing;条目密码 Zeroizing<String>。

mod format;
mod model;
mod store;

pub use format::{
    AuvPassVaultCred, AuvPassVaultHeader, AUV_PASS_VAULT_FORMAT_VERSION, AUV_PASS_VAULT_MAGIC,
};
pub use model::{
    AuvPassAttachmentMeta, AuvPassEntry, AuvPassEntryId, AuvPassEntryInput, AuvPassEntrySnapshot,
    AuvPassVaultModel, AUV_PASS_HISTORY_LIMIT_DEFAULT,
};
pub use store::AuvPassVault;
