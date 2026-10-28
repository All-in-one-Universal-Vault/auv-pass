// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 库数据模型:条目/历史快照/组/库模型,serde 序列化为库载荷 JSON。
//!
//! 敏感字段(条目密码)为 `Zeroizing<String>`(zeroize serde 特性),drop 自动清零;
//! 时间戳统一 Unix 秒(i64)——KDBX 兼容映射与显示格式化共用。

use serde::{Deserialize, Serialize};

use crate::auv_pass_totp::AuvPassTotpConfig;
use uuid::Uuid;
use zeroize::Zeroizing;

/// 条目标识(uuid v4,OS 熵)。
pub type AuvPassEntryId = Uuid;

/// 历史快照默认上限(保留 20 条;0 = 禁用历史,对齐 KeePass 语义)。
pub const AUV_PASS_HISTORY_LIMIT_DEFAULT: usize = 20;

/// 附件元数据(字节存库级池,条目只存元数据;随库加密保存)。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuvPassAttachmentMeta {
    pub id: AuvPassEntryId,
    /// 文件名(展示与导出默认名)。
    pub name: String,
    /// 字节数。
    pub size: u64,
    /// 源文件时间戳(Unix 秒):创建/修改/访问——导出时还原。
    pub created: i64,
    pub modified: i64,
    pub accessed: i64,
    /// 内容 SHA-256(hex)——加载时验完整性,导出时可校验。
    pub sha256: String,
}

/// 一个密码条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuvPassEntry {
    /// 条目标识(创建后不变)。
    pub id: AuvPassEntryId,
    /// 所属组("/"分隔层级路径;空串 = 根/未分组)。
    pub group: String,
    pub title: String,
    pub username: String,
    /// 密码(敏感,Zeroizing)。
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    /// 创建时间(Unix 秒)。
    pub created: i64,
    /// 最后修改时间(Unix 秒)。
    pub modified: i64,
    /// 修改历史(旧→新,尾部最新;封顶由库 history_limit 控制)。
    pub history: Vec<AuvPassEntrySnapshot>,
    /// TOTP 配置(None=未启用;旧库文件缺此字段反序列化为 None)。
    #[serde(default)]
    pub totp: Option<AuvPassTotpConfig>,
    /// 附件(元数据;字节在库级池。旧库缺此字段为空)。
    #[serde(default)]
    pub attachments: Vec<AuvPassAttachmentMeta>,
}

/// 修改历史快照:被覆盖前的完整字段切片(与 KDBX 历史双向映射)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuvPassEntrySnapshot {
    pub group: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    /// 快照时间 = 被覆盖版本的 modified(Unix 秒)。
    pub saved_at: i64,
    /// 被覆盖版本的 TOTP 配置。
    #[serde(default)]
    pub totp: Option<AuvPassTotpConfig>,
}

/// 新增/更新条目的全量输入(界面表单即此形态)。
#[derive(Debug, Clone, PartialEq)]
pub struct AuvPassEntryInput {
    pub group: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    /// TOTP 配置(None=不启用;编辑时由调用方决定保留/清除语义)。
    pub totp: Option<AuvPassTotpConfig>,
}

impl AuvPassEntryInput {
    /// 与条目现值比对(六字段全同 = 无变化,更新时不做快照)。
    pub fn differs_from(&self, e: &AuvPassEntry) -> bool {
        e.group != self.group
            || e.title != self.title
            || e.username != self.username
            || e.password.as_str() != self.password.as_str()
            || e.url != self.url
            || e.notes != self.notes
            || e.totp != self.totp
    }
}

/// 库内模型(序列化为密文库载荷)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuvPassVaultModel {
    /// 模型版本(与文件格式版本独立;JSON 向前容忍)。
    pub model_version: u32,
    pub entries: Vec<AuvPassEntry>,
    /// 显式注册的组(支持空组;条目引用的组自动并入 groups())。
    pub groups: Vec<String>,
    /// 历史快照上限(0 = 禁用)。
    pub history_limit: usize,
    /// SSH 密钥(旧库缺此字段反序列化为空)。
    #[serde(default)]
    pub ssh_keys: Vec<crate::auv_pass_agent::AuvPassSshKey>,
}

impl Default for AuvPassVaultModel {
    fn default() -> Self {
        Self {
            model_version: 1,
            entries: Vec::new(),
            groups: Vec::new(),
            history_limit: AUV_PASS_HISTORY_LIMIT_DEFAULT,
            ssh_keys: Vec::new(),
        }
    }
}
