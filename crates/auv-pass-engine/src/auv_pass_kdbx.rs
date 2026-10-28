// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! KDBX 导入导出(特色功能模块;keepass crate 读写)。
//!
//! - 导入:KDBX(1.x/3.x/4.x 均交 crate 解析)→ 条目+"/"组路径+历史+TOTP("otp" 字段);
//! - 导出:条目 → KDBX 4 组树,历史双向保留(TOTP 写 "otp" 为 otpauth URI,KeePassXC 兼容);
//! - 历史:KDBX 列表新者在前,本库旧者在前,双向转换;
//! - 凭据:仅主密码(密钥文件支持留后续);密码经 Zeroizing 借用。

use std::path::Path;

use keepass::db::{Entry as KpEntry, Group as KpGroup, Node, Times, Value as KpValue};
use keepass::{Database, DatabaseKey};
use zeroize::Zeroizing;

use crate::auv_pass_totp::{AuvPassTotpAlgo, AuvPassTotpConfig};
use crate::auv_pass_vault::{
    AuvPassEntry, AuvPassEntryId, AuvPassEntryInput, AuvPassEntrySnapshot,
};
use crate::error::{Error, Result};

/// 导入条目:输入 + 历史 + 附件(文件名, 字节)。
pub type AuvPassKdbxImportEntry = (
    AuvPassEntryInput,
    Vec<AuvPassEntrySnapshot>,
    Vec<(String, Vec<u8>)>,
);

/// 导入结果(供 UI 反馈)。
#[derive(Debug, Default)]
pub struct AuvPassKdbxImport {
    /// 导入条目列表。
    pub entries: Vec<AuvPassKdbxImportEntry>,
    /// 跳过的条目说明(无标题等)。
    pub skipped: Vec<String>,
}

fn naive_from_unix(sec: i64) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(sec, 0)
        .map(|d| d.naive_utc())
        .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH.naive_utc())
}

fn unix_from_naive(t: chrono::NaiveDateTime) -> i64 {
    t.and_utc().timestamp()
}

fn kp_key(password: &[u8], keyfile: Option<&Path>) -> Result<DatabaseKey> {
    let pw = Zeroizing::new(String::from_utf8_lossy(password).into_owned());
    let mut key = DatabaseKey::new();
    if !pw.is_empty() {
        key = key.with_password(pw.as_str());
    }
    if let Some(kf) = keyfile {
        let mut f = std::fs::File::open(kf)?;
        key = key
            .with_keyfile(&mut f)
            .map_err(|e| Error::Format(format!("密钥文件读取失败:{e}")))?;
    }
    if pw.is_empty() && keyfile.is_none() {
        return Err(Error::Format("密码与密钥文件不能同时为空".into()));
    }
    Ok(key)
}

fn totp_from_raw(raw: &str) -> Option<AuvPassTotpConfig> {
    if raw.starts_with("otpauth://") {
        crate::auv_pass_totp::auv_pass_totp_parse_otpauth(raw).ok()
    } else {
        let cfg = AuvPassTotpConfig {
            secret: raw.trim().to_string(),
            ..Default::default()
        };
        cfg.validate().ok().map(|_| cfg)
    }
}

fn totp_to_otpauth(cfg: &AuvPassTotpConfig) -> String {
    let alg = match cfg.algorithm {
        AuvPassTotpAlgo::Sha1 => "SHA1",
        AuvPassTotpAlgo::Sha256 => "SHA256",
        AuvPassTotpAlgo::Sha512 => "SHA512",
    };
    format!(
        "otpauth://totp/auv-pass?secret={}&digits={}&period={}&algorithm={}",
        cfg.secret, cfg.digits, cfg.period_s, alg
    )
}

fn snapshot_from_kp(e: &KpEntry) -> AuvPassEntrySnapshot {
    AuvPassEntrySnapshot {
        group: String::new(), // KDBX 历史项不带组;归并入条目所在组
        title: e.get_title().unwrap_or_default().to_string(),
        username: e.get_username().unwrap_or_default().to_string(),
        password: Zeroizing::new(e.get_password().unwrap_or_default().to_string()),
        url: e.get_url().unwrap_or_default().to_string(),
        notes: e.get("Notes").unwrap_or_default().to_string(),
        saved_at: e
            .get_time("LastModificationTime")
            .map(|t| unix_from_naive(*t))
            .unwrap_or_default(),
        totp: e.get_raw_otp_value().and_then(totp_from_raw),
    }
}

/// 导入 KDBX 文件(组树 → "/" 路径;根组条目归 "")。
pub fn auv_pass_kdbx_import(
    path: &Path,
    password: &[u8],
    keyfile: Option<&Path>,
) -> Result<AuvPassKdbxImport> {
    let mut file = std::fs::File::open(path)?;
    let db = Database::open(&mut file, kp_key(password, keyfile)?)
        .map_err(|e| Error::Format(format!("KDBX 打开失败:{e}")))?;
    let mut out = AuvPassKdbxImport::default();
    walk_group(&db.root, "", &mut out);
    Ok(out)
}

fn walk_group(g: &KpGroup, prefix: &str, out: &mut AuvPassKdbxImport) {
    for node in &g.children {
        match node {
            Node::Entry(e) => {
                let title = e.get_title().unwrap_or_default().to_string();
                if title.is_empty() {
                    out.skipped.push(format!("uuid={}(无标题)", e.uuid));
                    continue;
                }
                // 历史:KDBX 新者在前 → 反转为旧→新
                let history = e
                    .history
                    .as_ref()
                    .map(|h| h.get_entries().iter().rev().map(snapshot_from_kp).collect())
                    .unwrap_or_default();
                // 附件:KDBX 的 Bytes 字段 → (文件名, 字节)
                let atts: Vec<(String, Vec<u8>)> = e
                    .fields
                    .iter()
                    .filter_map(|(k, v)| {
                        if let KpValue::Bytes(b) = v {
                            Some((k.clone(), b.clone()))
                        } else {
                            None
                        }
                    })
                    .collect();
                let input = AuvPassEntryInput {
                    group: prefix.to_string(),
                    title,
                    username: e.get_username().unwrap_or_default().to_string(),
                    password: Zeroizing::new(e.get_password().unwrap_or_default().to_string()),
                    url: e.get_url().unwrap_or_default().to_string(),
                    notes: e.get("Notes").unwrap_or_default().to_string(),
                    totp: e.get_raw_otp_value().and_then(totp_from_raw),
                };
                out.entries.push((input, history, atts));
            }
            Node::Group(sub) => {
                let path = if prefix.is_empty() {
                    sub.name.clone()
                } else {
                    format!("{prefix}/{}", sub.name)
                };
                walk_group(sub, &path, out);
            }
        }
    }
}

fn ensure_group<'a>(root: &'a mut KpGroup, path: &str) -> &'a mut KpGroup {
    let mut cur = root;
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        let idx = cur.children.iter().position(|n| match n {
            Node::Group(g) => g.name == seg,
            _ => false,
        });
        cur = match idx {
            Some(i) => match &mut cur.children[i] {
                Node::Group(g) => g,
                _ => unreachable!("位置探测为组"),
            },
            None => {
                let g = KpGroup::new(seg);
                cur.children.push(Node::Group(g));
                match cur.children.last_mut().expect("刚推入") {
                    Node::Group(g) => g,
                    _ => unreachable!(),
                }
            }
        };
    }
    cur
}

fn entry_to_kp(
    e: &AuvPassEntry,
    pool: &std::collections::BTreeMap<AuvPassEntryId, zeroize::Zeroizing<Vec<u8>>>,
) -> KpEntry {
    let mut kp = KpEntry::new();
    kp.fields
        .insert("Title".to_string(), KpValue::Unprotected(e.title.clone()));
    kp.fields.insert(
        "UserName".to_string(),
        KpValue::Unprotected(e.username.clone()),
    );
    kp.fields.insert(
        "Password".to_string(),
        KpValue::Unprotected(e.password.as_str().to_string()),
    );
    kp.fields
        .insert("URL".to_string(), KpValue::Unprotected(e.url.clone()));
    kp.fields
        .insert("Notes".to_string(), KpValue::Unprotected(e.notes.clone()));
    if let Some(cfg) = &e.totp {
        kp.fields.insert(
            "otp".to_string(),
            KpValue::Unprotected(totp_to_otpauth(cfg)),
        );
    }
    // 附件:池内字节写入 Bytes 字段(同名追加序号去重)
    for m in &e.attachments {
        if let Some(bytes) = pool.get(&m.id) {
            let mut key = m.name.clone();
            let mut n = 2;
            while kp.fields.contains_key(&key) {
                key = format!("{} ({})", m.name, n);
                n += 1;
            }
            kp.fields
                .insert(key, KpValue::Bytes(bytes.as_slice().to_vec()));
        }
    }
    kp.times = Times::new();
    kp.times
        .times
        .insert("CreationTime".to_string(), naive_from_unix(e.created));
    kp.times.times.insert(
        "LastModificationTime".to_string(),
        naive_from_unix(e.modified),
    );
    if !e.history.is_empty() {
        let mut h = keepass::db::History::default();
        for snap in &e.history {
            let mut he = KpEntry::new();
            he.fields.insert(
                "Title".to_string(),
                KpValue::Unprotected(snap.title.clone()),
            );
            he.fields.insert(
                "UserName".to_string(),
                KpValue::Unprotected(snap.username.clone()),
            );
            he.fields.insert(
                "Password".to_string(),
                KpValue::Unprotected(snap.password.as_str().to_string()),
            );
            he.fields
                .insert("URL".to_string(), KpValue::Unprotected(snap.url.clone()));
            he.fields.insert(
                "Notes".to_string(),
                KpValue::Unprotected(snap.notes.clone()),
            );
            if let Some(cfg) = &snap.totp {
                he.fields.insert(
                    "otp".to_string(),
                    KpValue::Unprotected(totp_to_otpauth(cfg)),
                );
            }
            he.times = Times::new();
            he.times.times.insert(
                "LastModificationTime".to_string(),
                naive_from_unix(snap.saved_at),
            );
            h.add_entry(he);
        }
        kp.history = Some(h);
    }
    kp
}

/// 导出条目集合为 KDBX 4 文件(组树按 "/" 重建;返回导出条数)。
pub fn auv_pass_kdbx_export(
    entries: &[AuvPassEntry],
    pool: &std::collections::BTreeMap<AuvPassEntryId, zeroize::Zeroizing<Vec<u8>>>,
    path: &Path,
    password: &[u8],
    keyfile: Option<&Path>,
) -> Result<usize> {
    let mut db = Database::new(keepass::config::DatabaseConfig::default());
    db.root.name = "auv-pass".to_string();
    for e in entries {
        let group_path = e.group.clone();
        let kp = entry_to_kp(e, pool);
        let parent = ensure_group(&mut db.root, &group_path);
        parent.children.push(Node::Entry(kp));
    }
    let mut out = std::fs::File::create(path)?;
    db.save(&mut out, kp_key(password, keyfile)?)
        .map_err(|e| Error::Format(format!("KDBX 保存失败:{e}")))?;
    Ok(entries.len())
}
