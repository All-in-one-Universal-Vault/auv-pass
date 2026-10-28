// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! KDBX 导入导出集成测试:往返(含历史/TOTP/分组/中文)+ 错密 + 独立读取核验。

use std::path::PathBuf;

use auv_pass_engine::{
    AuvPassCipherAlgo, AuvPassEntryId, AuvPassEntryInput, AuvPassKdfParams, AuvPassTotpConfig,
    AuvPassVault,
};
use zeroize::Zeroizing;

fn fast() -> AuvPassKdfParams {
    AuvPassKdfParams {
        m_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn input(group: &str, title: &str, user: &str, password: &str) -> AuvPassEntryInput {
    AuvPassEntryInput {
        group: group.to_string(),
        title: title.to_string(),
        username: user.to_string(),
        password: Zeroizing::new(password.to_string()),
        url: String::new(),
        notes: String::new(),
        totp: None,
    }
}

fn tmp(tag: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "auv-pass-m5-{tag}-{}.{}",
        AuvPassEntryId::new_v4(),
        ext
    ));
    p
}

#[test]
fn kdbx_roundtrip_fields_groups_cjk() {
    let path = tmp("rt", "kdbx");
    let mut v = AuvPassVault::create(b"kp", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    let id1 = v
        .add_entry(input(
            "工作/邮箱",
            "GitHub 企业版",
            "dev@example.com",
            "s3cret-PW!",
        ))
        .unwrap();
    let id2 = v.add_entry(input("", "根条目", "root", "pw2")).unwrap();
    v.save(&tmp("src", "auvp")).ok();
    v.export_kdbx(&path, b"kp", None).unwrap();

    let mut back = AuvPassVault::create(b"x", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    let n = back.import_kdbx(&path, b"kp", None).unwrap();
    assert_eq!(n, 2);
    let imported: Vec<_> = back.entries().to_vec();
    assert_eq!(imported.len(), 2);
    let g = imported
        .iter()
        .find(|e| e.title == "GitHub 企业版")
        .unwrap();
    assert_eq!(g.username, "dev@example.com");
    assert_eq!(g.password.as_str(), "s3cret-PW!");
    assert_eq!(g.group, "工作/邮箱", "组树应拍平为路径");
    let r = imported.iter().find(|e| e.title == "根条目").unwrap();
    assert_eq!(r.group, "", "根组条目归空组");
    let _ = (id1, id2);
    std::fs::remove_file(&path).ok();
}

#[test]
fn kdbx_history_bidirectional() {
    let path = tmp("hist", "kdbx");
    let mut v =
        AuvPassVault::create(b"kp", None, AuvPassCipherAlgo::ChaCha20Poly1305, &fast()).unwrap();
    let id = v.add_entry(input("", "条目", "u", "v0")).unwrap();
    for i in 1..=3 {
        v.update_entry(id, input("", "条目", "u", &format!("v{i}")))
            .unwrap();
    }
    assert_eq!(v.history(id).unwrap().len(), 3);
    v.export_kdbx(&path, b"kp", None).unwrap();

    let mut back = AuvPassVault::create(b"x", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    back.import_kdbx(&path, b"kp", None).unwrap();
    let e = back.entries().first().unwrap();
    assert_eq!(e.password.as_str(), "v3", "当前值取最新");
    assert_eq!(e.history.len(), 3, "历史条数保持");
    let pws: Vec<&str> = e.history.iter().map(|s| s.password.as_str()).collect();
    assert_eq!(pws, vec!["v0", "v1", "v2"], "历史顺序旧→新保持");
    std::fs::remove_file(&path).ok();
}

#[test]
fn kdbx_totp_and_independent_read_back() {
    let path = tmp("otp", "kdbx");
    let mut v = AuvPassVault::create(b"kp", None, AuvPassCipherAlgo::Sm4Gcm, &fast()).unwrap();
    let cfg = AuvPassTotpConfig {
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        ..Default::default()
    };
    let mut i = input("", "带TOTP", "u", "p");
    i.totp = Some(cfg);
    v.add_entry(i).unwrap();
    v.export_kdbx(&path, b"kp", None).unwrap();

    // 独立核验:直接用 keepass crate 读回(不经我们的导入代码)
    let mut f = std::fs::File::open(&path).unwrap();
    let key = keepass::DatabaseKey::new().with_password("kp");
    let db = keepass::Database::open(&mut f, key).unwrap();
    let title = db
        .root
        .children
        .iter()
        .filter_map(|n| match n {
            keepass::db::Node::Entry(e) => Some(e.get_title().unwrap_or_default().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(title, "带TOTP", "keepass crate 独立读回应见条目");

    // 再经自家导入:TOTP 语义保持
    let mut back = AuvPassVault::create(b"x", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    back.import_kdbx(&path, b"kp", None).unwrap();
    assert_eq!(
        back.entries()[0].totp.as_ref().unwrap().secret,
        "JBSWY3DPEHPK3PXP"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn kdbx_wrong_password_rejected() {
    let path = tmp("wrong", "kdbx");
    let mut v =
        AuvPassVault::create(b"right", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("", "t", "u", "p")).unwrap();
    v.export_kdbx(&path, b"right", None).unwrap();
    let mut back = AuvPassVault::create(b"x", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    assert!(back.import_kdbx(&path, b"wrong", None).is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn kdbx_nested_group_tree_roundtrip() {
    let path = tmp("tree", "kdbx");
    let mut v = AuvPassVault::create(b"kp", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("A/B/C", "深层条目", "u", "p")).unwrap();
    v.export_kdbx(&path, b"kp", None).unwrap();
    let mut back = AuvPassVault::create(b"x", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    back.import_kdbx(&path, b"kp", None).unwrap();
    assert_eq!(back.entries()[0].group, "A/B/C", "多层组路径往返一致");
    std::fs::remove_file(&path).ok();
}
