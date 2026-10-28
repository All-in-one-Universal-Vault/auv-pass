// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! AuvPassVault:解锁态密码库(核心 API)。
//!
//! 生命周期:create/open → 内存持有派生密钥(Zeroizing)与模型 → CRUD/搜索 → save(原子写)。
//! 红线:主密码只在 open/create 借用,不驻留;条目密码 Zeroizing;save 走同目录临时文件+rename。

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::auv_pass_crypto::{
    auv_pass_decrypt, auv_pass_derive_key, auv_pass_encrypt, AuvPassCipherAlgo,
    AuvPassEncryptedBlob, AuvPassKdfParams, AUV_PASS_KEY_LEN, AUV_PASS_NONCE_LEN,
};
use crate::auv_pass_vault::format::{AuvPassVaultHeader, AUV_PASS_VAULT_FORMAT_VERSION};
use crate::auv_pass_vault::model::{
    AuvPassAttachmentMeta, AuvPassEntry, AuvPassEntryId, AuvPassEntryInput, AuvPassEntrySnapshot,
    AuvPassVaultModel,
};
use crate::error::{Error, Result};

/// 解锁态密码库。
#[derive(Debug)]
pub struct AuvPassVault {
    key: Zeroizing<[u8; AUV_PASS_KEY_LEN]>,
    header: AuvPassVaultHeader,
    pub(crate) model: AuvPassVaultModel,
    /// 附件字节池(id → 内容,drop 清零;v1/v2 旧库恒空)。
    pub(crate) att_pool: std::collections::BTreeMap<AuvPassEntryId, Zeroizing<Vec<u8>>>,
}

/// SHA-256 的 hex 形态(附件完整性登记/核验)。
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    let d = sha2::Sha256::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// 凭据组合判定(两者皆空拒绝)。
fn cred_mode(
    password: &[u8],
    keyfile: Option<&Path>,
) -> Result<crate::auv_pass_vault::AuvPassVaultCred> {
    use crate::auv_pass_vault::AuvPassVaultCred;
    match (password.is_empty(), keyfile) {
        (false, None) => Ok(AuvPassVaultCred::Password),
        (true, Some(_)) => Ok(AuvPassVaultCred::KeyFile),
        (false, Some(_)) => Ok(AuvPassVaultCred::PasswordKeyFile),
        (true, None) => Err(Error::Format("密码与密钥文件不能同时为空".into())),
    }
}

/// 派生输入 = 密码字节 || SHA256(密钥文件内容)(密钥文件可为任意文件)。
fn kdf_input(password: &[u8], keyfile: Option<&Path>) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use sha2::Digest as _;
    let mut input = zeroize::Zeroizing::new(Vec::with_capacity(password.len() + 32));
    input.extend_from_slice(password);
    if let Some(kf) = keyfile {
        let bytes = std::fs::read(kf)?;
        let digest = sha2::Sha256::digest(&bytes);
        input.extend_from_slice(&digest);
    }
    if input.is_empty() {
        return Err(Error::Format("密码与密钥文件不能同时为空".into()));
    }
    Ok(input)
}

fn now_unix() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))
}

impl AuvPassVault {
    /// 新建空库:生成盐、按参数派生密钥(不落盘;首次 save 时才写文件)。
    ///
    /// 凭据三组合:密码 / 密钥文件 / 密码+密钥文件;
    /// 密钥文件 = 任意文件,取 SHA-256 全文作材料;两者皆空拒绝。
    /// 派生输入 = 密码字节 || SHA256(密钥文件)(任一存在)。
    pub fn create(
        password: &[u8],
        keyfile: Option<&Path>,
        algo: AuvPassCipherAlgo,
        kdf: &AuvPassKdfParams,
    ) -> Result<Self> {
        kdf.validate()?;
        let cred = cred_mode(password, keyfile)?;
        let input = kdf_input(password, keyfile)?;
        let salt = crate::auv_pass_crypto::auv_pass_generate_salt()?;
        let key = auv_pass_derive_key(&input, &salt, kdf)?;
        Ok(Self {
            key,
            header: AuvPassVaultHeader {
                algo,
                kdf: *kdf,
                salt,
                cred,
            },
            model: AuvPassVaultModel::default(),
            att_pool: std::collections::BTreeMap::new(),
        })
    }

    /// 打开库文件:解析头 → 按头重放派生 → 解密 → 反序列化模型。
    /// v3:索引块(JSON 模型)+ 逐附件独立 AEAD 块;v1/v2:单块 JSON,读入
    /// 后保存时自动升级 v3。错密码/头篡改统一报 `Error::Decrypt`。
    pub fn open(path: &Path, password: &[u8], keyfile: Option<&Path>) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let (header, header_len) = AuvPassVaultHeader::from_bytes(&bytes)?;
        let input = kdf_input(password, keyfile)?;
        let key = auv_pass_derive_key(&input, &header.salt, &header.kdf)?;
        let rest = &bytes[header_len..];
        if rest.len() < AUV_PASS_NONCE_LEN + 16 {
            return Err(Error::Format("密文块不完整".into()));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        let aad = bytes[..header_len].to_vec();
        if version == AUV_PASS_VAULT_FORMAT_VERSION {
            // v3:[u32 索引块长][索引块:nonce+ct(JSON)] { [16B id][u32 块长][nonce+ct(附件)] }…
            let idx_len = rest
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(|| Error::Format("库索引块长度缺失".into()))?
                as usize;
            let rest = &rest[4..];
            let idx_bytes = rest
                .get(..idx_len)
                .ok_or_else(|| Error::Format("库索引块不完整".into()))?;
            let index_blob = AuvPassEncryptedBlob {
                algo: header.algo,
                nonce: idx_bytes[..AUV_PASS_NONCE_LEN]
                    .try_into()
                    .expect("长度已校验"),
                ciphertext: idx_bytes[AUV_PASS_NONCE_LEN..].to_vec(),
            };
            let plain = auv_pass_decrypt(&index_blob, &key, &aad)?;
            let model = serde_json::from_slice::<AuvPassVaultModel>(&plain)
                .map_err(|e| Error::Format(format!("库载荷解析失败:{e}")))?;
            // 附件块逐个解密(AAD = 头 ‖ 附件 id,绑死库与身份)
            let mut tail = &rest[idx_len..];
            let mut pool = std::collections::BTreeMap::new();
            while !tail.is_empty() {
                let id_bytes: [u8; 16] = tail
                    .get(..16)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| Error::Format("附件块损坏".into()))?;
                let blen = tail
                    .get(16..20)
                    .and_then(|s| s.try_into().ok())
                    .map(u32::from_le_bytes)
                    .ok_or_else(|| Error::Format("附件块损坏".into()))?
                    as usize;
                let blk = tail
                    .get(20..20 + blen)
                    .ok_or_else(|| Error::Format("附件块不完整".into()))?;
                let mut aad2 = aad.clone();
                aad2.extend_from_slice(&id_bytes);
                let blob = AuvPassEncryptedBlob {
                    algo: header.algo,
                    nonce: blk[..AUV_PASS_NONCE_LEN].try_into().expect("长度已校验"),
                    ciphertext: blk[AUV_PASS_NONCE_LEN..].to_vec(),
                };
                let data = auv_pass_decrypt(&blob, &key, &aad2)?;
                pool.insert(AuvPassEntryId::from_bytes(id_bytes), data);
                tail = &tail[20 + blen..];
            }
            // 交叉核验:池内 id 与条目引用一致 + 每件 SHA-256 复算一致
            let mut referenced = std::collections::BTreeSet::new();
            for e in &model.entries {
                for m in &e.attachments {
                    referenced.insert(m.id);
                }
            }
            let pooled: std::collections::BTreeSet<_> = pool.keys().copied().collect();
            if referenced != pooled {
                return Err(Error::Format("附件索引与内容不一致".into()));
            }
            for e in &model.entries {
                for m in &e.attachments {
                    let data = &pool[&m.id];
                    if sha256_hex(data) != m.sha256 {
                        return Err(Error::Format(format!("附件 {} 校验失败", m.name)));
                    }
                }
            }
            Ok(Self {
                key,
                header,
                model,
                att_pool: pool,
            })
        } else {
            // v1/v2:单块 JSON(无附件)
            let blob = AuvPassEncryptedBlob {
                algo: header.algo,
                nonce: rest[..AUV_PASS_NONCE_LEN].try_into().expect("长度已校验"),
                ciphertext: rest[AUV_PASS_NONCE_LEN..].to_vec(),
            };
            let plain = auv_pass_decrypt(&blob, &key, &aad)?;
            let model = serde_json::from_slice::<AuvPassVaultModel>(&plain)
                .map_err(|e| Error::Format(format!("库载荷解析失败:{e}")))?;
            Ok(Self {
                key,
                header,
                model,
                att_pool: std::collections::BTreeMap::new(),
            })
        }
    }

    /// 保存(原子写:同目录临时文件 + rename 覆盖)。v3 布局:
    /// 头 + [u32 索引块长][索引块(nonce+ct(JSON 模型))] + 逐附件
    /// [16B id][u32 块长][nonce+ct(内容)](AAD = 头 ‖ id,顺序按 id 确定性排列)。
    pub fn save(&self, path: &Path) -> Result<()> {
        let header_bytes = self.header.to_bytes()?;
        let json = serde_json::to_vec(&self.model).map_err(|e| Error::Format(e.to_string()))?;
        let index = auv_pass_encrypt(self.header.algo, &self.key, &json, &header_bytes)?;
        let mut file = header_bytes.clone();
        let idx_len = (AUV_PASS_NONCE_LEN + index.ciphertext.len()) as u32;
        file.extend_from_slice(&idx_len.to_le_bytes());
        file.extend_from_slice(&index.nonce);
        file.extend_from_slice(&index.ciphertext);
        for (id, data) in &self.att_pool {
            let mut aad = header_bytes.clone();
            aad.extend_from_slice(id.as_bytes());
            let blob = auv_pass_encrypt(self.header.algo, &self.key, data, &aad)?;
            let blen = (AUV_PASS_NONCE_LEN + blob.ciphertext.len()) as u32;
            file.extend_from_slice(id.as_bytes());
            file.extend_from_slice(&blen.to_le_bytes());
            file.extend_from_slice(&blob.nonce);
            file.extend_from_slice(&blob.ciphertext);
        }

        // 父目录缺失则自动创建(新建库任意路径直接可用)
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp: PathBuf = path.with_extension("auvp.tmp");
        std::fs::write(&tmp, &file)?;
        // 库文件权限收紧:Unix 下 0600(默认 umask 0644 会让库文件全员可读,属泄露面)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&tmp)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }
        std::fs::rename(&tmp, path)?; // 两平台 rename 均覆盖既有目标
        Ok(())
    }

    /// 库头(明文非敏感,可展示:算法/参数/盐)。
    pub fn header(&self) -> &AuvPassVaultHeader {
        &self.header
    }

    // ---------- CRUD ----------

    /// 新增条目,返回新 id。
    pub fn add_entry(&mut self, input: AuvPassEntryInput) -> Result<AuvPassEntryId> {
        let now = now_unix()?;
        let id = AuvPassEntryId::new_v4();
        self.model.entries.push(AuvPassEntry {
            id,
            group: input.group,
            title: input.title,
            username: input.username,
            password: input.password,
            url: input.url,
            notes: input.notes,
            created: now,
            modified: now,
            history: Vec::new(),
            totp: input.totp,
            attachments: Vec::new(),
        });
        Ok(id)
    }

    /// 新增条目并带入既有历史(导入用;截断至当前上限,丢最旧)。
    pub fn add_entry_with_history(
        &mut self,
        input: AuvPassEntryInput,
        history: Vec<AuvPassEntrySnapshot>,
    ) -> Result<AuvPassEntryId> {
        let limit = self.model.history_limit;
        let now = now_unix()?;
        let id = AuvPassEntryId::new_v4();
        let mut history = history;
        if limit > 0 && history.len() > limit {
            let excess = history.len() - limit;
            history.drain(..excess);
        }
        self.model.entries.push(AuvPassEntry {
            id,
            group: input.group,
            title: input.title,
            username: input.username,
            password: input.password,
            url: input.url,
            notes: input.notes,
            created: now,
            modified: now,
            history,
            totp: input.totp,
            attachments: Vec::new(),
        });
        Ok(id)
    }

    /// 按 id 取条目。
    pub fn get_entry(&self, id: AuvPassEntryId) -> Option<&AuvPassEntry> {
        self.model.entries.iter().find(|e| e.id == id)
    }

    /// 更新条目(全量替换六字段)。
    ///
    /// 有实际变化才自动快照入历史(封顶 history_limit,丢最旧);
    /// 输入与现值完全相同 = 无操作、不快照。
    pub fn update_entry(&mut self, id: AuvPassEntryId, input: AuvPassEntryInput) -> Result<()> {
        let limit = self.model.history_limit;
        let entry = self
            .model
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        if input.differs_from(entry) {
            if limit > 0 {
                entry.history.push(AuvPassEntrySnapshot {
                    group: entry.group.clone(),
                    title: entry.title.clone(),
                    username: entry.username.clone(),
                    password: entry.password.clone(),
                    url: entry.url.clone(),
                    notes: entry.notes.clone(),
                    saved_at: entry.modified,
                    totp: entry.totp.clone(),
                });
                let excess = entry.history.len().saturating_sub(limit);
                if excess > 0 {
                    entry.history.drain(..excess); // 丢最旧
                }
            }
            entry.group = input.group;
            entry.title = input.title;
            entry.username = input.username;
            entry.password = input.password;
            entry.url = input.url;
            entry.notes = input.notes;
            entry.totp = input.totp;
            entry.modified = now_unix()?;
        }
        Ok(())
    }

    /// 删除条目(条目级历史随之删除;引擎层无回收站)。
    pub fn delete_entry(&mut self, id: AuvPassEntryId) -> Result<()> {
        let before = self.model.entries.len();
        self.model.entries.retain(|e| e.id != id);
        if self.model.entries.len() == before {
            return Err(Error::EntryNotFound(id.to_string()));
        }
        Ok(())
    }

    /// 全部条目(按创建序)。
    pub fn entries(&self) -> &[AuvPassEntry] {
        &self.model.entries
    }

    pub fn entry_count(&self) -> usize {
        self.model.entries.len()
    }

    // ---------- 历史 ----------

    /// 条目历史(旧→新;无条目返回 None)。
    pub fn history(&self, id: AuvPassEntryId) -> Option<&[AuvPassEntrySnapshot]> {
        self.get_entry(id).map(|e| e.history.as_slice())
    }

    /// 当前历史上限(0 = 禁用)。
    pub fn history_limit(&self) -> usize {
        self.model.history_limit
    }

    /// 调整历史上限;收缩时立即截断全部条目的既有历史(丢最旧)。
    pub fn set_history_limit(&mut self, limit: usize) {
        self.model.history_limit = limit;
        if limit > 0 {
            for e in &mut self.model.entries {
                let excess = e.history.len().saturating_sub(limit);
                if excess > 0 {
                    e.history.drain(..excess);
                }
            }
        }
    }

    // ---------- 分组 ----------

    /// 全部组名(显式注册 ∪ 条目引用,排序;"" = 根/未分组,仅有条目在根时出现)。
    pub fn groups(&self) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        set.extend(self.model.groups.iter().cloned());
        set.extend(self.model.entries.iter().map(|e| e.group.clone()));
        set.into_iter().collect()
    }

    /// 显式注册组(支持空组;已存在则幂等)。
    pub fn add_group(&mut self, name: &str) {
        if !self.model.groups.iter().any(|g| g == name) {
            self.model.groups.push(name.to_string());
        }
    }

    /// 删除显式组;组内仍有条目则拒绝(`Error::GroupNotEmpty`)。
    pub fn delete_group(&mut self, name: &str) -> Result<()> {
        if self.model.entries.iter().any(|e| e.group == name) {
            return Err(Error::GroupNotEmpty(name.to_string()));
        }
        self.model.groups.retain(|g| g != name);
        Ok(())
    }

    /// 组内条目(精确组名匹配)。
    pub fn entries_in_group(&self, group: &str) -> Vec<&AuvPassEntry> {
        self.model
            .entries
            .iter()
            .filter(|e| e.group == group)
            .collect()
    }

    /// 更换凭据:新主密码（可选新密钥文件）→ 重派生密钥 → 后续保存即全库重加密。
    /// 换盐、保持算法与 KDF 参数不变;旧密钥即刻弃用。
    pub fn change_credentials(&mut self, password: &[u8], keyfile: Option<&Path>) -> Result<()> {
        let cred = cred_mode(password, keyfile)?;
        let input = kdf_input(password, keyfile)?;
        let salt = crate::auv_pass_crypto::auv_pass_generate_salt()?;
        self.key = auv_pass_derive_key(&input, &salt, &self.header.kdf)?;
        self.header.salt = salt;
        self.header.cred = cred;
        Ok(())
    }

    // ---------- 附件(v3) ----------

    /// 添加附件:字节与源文件三时间戳(创建/修改/访问,Unix 秒;None 补 0);
    /// SHA-256 自动登记。返回附件 id。
    pub fn entry_add_attachment(
        &mut self,
        entry: AuvPassEntryId,
        name: &str,
        bytes: &[u8],
        times: Option<(i64, i64, i64)>,
    ) -> Result<AuvPassEntryId> {
        let e = self
            .model
            .entries
            .iter_mut()
            .find(|e| e.id == entry)
            .ok_or_else(|| Error::EntryNotFound(entry.to_string()))?;
        let id = AuvPassEntryId::new_v4();
        let (created, modified, accessed) = times.unwrap_or((0, 0, 0));
        let meta = AuvPassAttachmentMeta {
            id,
            name: name.to_string(),
            size: bytes.len() as u64,
            created,
            modified,
            accessed,
            sha256: sha256_hex(bytes),
        };
        e.attachments.push(meta);
        self.att_pool.insert(id, Zeroizing::new(bytes.to_vec()));
        Ok(id)
    }

    /// 从文件添加附件:内容与三种时间戳取自文件系统(创建时间不可用时补 0)。
    pub fn entry_add_attachment_file(
        &mut self,
        entry: AuvPassEntryId,
        path: &Path,
    ) -> Result<AuvPassEntryId> {
        let bytes = std::fs::read(path)?;
        let md = std::fs::metadata(path)?;
        let unix = |t: std::io::Result<std::time::SystemTime>| {
            t.ok()
                .and_then(|x| x.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        self.entry_add_attachment(
            entry,
            &name,
            &bytes,
            Some((unix(md.created()), unix(md.modified()), unix(md.accessed()))),
        )
    }

    /// 条目的附件元数据列表。
    pub fn attachments_of(&self, entry: AuvPassEntryId) -> &[AuvPassAttachmentMeta] {
        self.model
            .entries
            .iter()
            .find(|e| e.id == entry)
            .map(|e| e.attachments.as_slice())
            .unwrap_or(&[])
    }

    /// 附件内容(库级池;无此附件返回 None)。
    pub fn attachment_bytes(&self, att: AuvPassEntryId) -> Option<&[u8]> {
        self.att_pool.get(&att).map(|z| z.as_slice())
    }

    fn find_att_meta(&self, att: AuvPassEntryId) -> Option<&AuvPassAttachmentMeta> {
        self.model
            .entries
            .iter()
            .flat_map(|e| e.attachments.iter())
            .find(|m| m.id == att)
    }

    /// 另存附件:字节原样写盘,并还原修改/访问时间戳(尽力而为,失败不阻断);
    /// 写前按登记的 SHA-256 核验。返回写入字节数。
    pub fn attachment_save_to(&self, att: AuvPassEntryId, path: &Path) -> Result<u64> {
        let Some(data) = self.att_pool.get(&att) else {
            return Err(Error::EntryNotFound(att.to_string()));
        };
        let meta = self.find_att_meta(att);
        if let Some(m) = meta {
            if sha256_hex(data) != m.sha256 {
                return Err(Error::Format("附件 SHA-256 校验失败".into()));
            }
        }
        std::fs::write(path, data.as_slice())?;
        if let Some(m) = meta {
            let mt = filetime::FileTime::from_unix_time(m.modified, 0);
            let at = filetime::FileTime::from_unix_time(m.accessed, 0);
            let _ = filetime::set_file_times(path, at, mt);
        }
        Ok(data.len() as u64)
    }

    /// 删除附件(元数据与字节一并移除)。
    pub fn entry_remove_attachment(
        &mut self,
        entry: AuvPassEntryId,
        att: AuvPassEntryId,
    ) -> Result<()> {
        let e = self
            .model
            .entries
            .iter_mut()
            .find(|e| e.id == entry)
            .ok_or_else(|| Error::EntryNotFound(entry.to_string()))?;
        let before = e.attachments.len();
        e.attachments.retain(|m| m.id != att);
        if e.attachments.len() == before {
            return Err(Error::EntryNotFound(att.to_string()));
        }
        self.att_pool.remove(&att);
        Ok(())
    }

    // ---------- 搜索 ----------

    /// 导入 KDBX 文件(keepass crate 解析;返回导入条数,跳过项打印到 stderr)。
    pub fn import_kdbx(
        &mut self,
        path: &Path,
        password: &[u8],
        keyfile: Option<&Path>,
    ) -> Result<usize> {
        let imported = crate::auv_pass_kdbx::auv_pass_kdbx_import(path, password, keyfile)?;
        let mut count = 0usize;
        for (input, history, atts) in imported.entries {
            let id = self.add_entry_with_history(input, history)?;
            for (name, bytes) in atts {
                self.entry_add_attachment(id, &name, &bytes, None)?;
            }
            count += 1;
        }
        Ok(count)
    }

    /// 导出为 KDBX 4 文件(含历史/TOTP;返回导出条数)。
    pub fn export_kdbx(
        &self,
        path: &Path,
        password: &[u8],
        keyfile: Option<&Path>,
    ) -> Result<usize> {
        crate::auv_pass_kdbx::auv_pass_kdbx_export(
            &self.model.entries,
            &self.att_pool,
            path,
            password,
            keyfile,
        )
    }

    /// 大小写不敏感子串搜索,命中 title/username/url/notes/group 任一字段。
    /// 空串返回全部条目。
    pub fn search(&self, needle: &str) -> Vec<&AuvPassEntry> {
        let q = needle.to_lowercase();
        self.model
            .entries
            .iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&q)
                    || e.username.to_lowercase().contains(&q)
                    || e.url.to_lowercase().contains(&q)
                    || e.notes.to_lowercase().contains(&q)
                    || e.group.to_lowercase().contains(&q)
            })
            .collect()
    }
}
