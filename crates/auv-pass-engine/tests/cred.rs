// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 凭据三组合测试(密码/密钥文件/密码+密钥文件)+ v1 向后兼容 + KDBX 密钥文件。

use std::path::PathBuf;

use auv_pass_engine::{
    auv_pass_decrypt, auv_pass_derive_key, auv_pass_encrypt, AuvPassCipherAlgo, AuvPassEntryId,
    AuvPassEntryInput, AuvPassKdfParams, AuvPassVault, AuvPassVaultCred, AuvPassVaultHeader,
    AUV_PASS_VAULT_FORMAT_VERSION,
};
use zeroize::Zeroizing;

fn fast() -> AuvPassKdfParams {
    AuvPassKdfParams {
        m_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn tmp(tag: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "auv-pass-cred-{tag}-{}.{}",
        AuvPassEntryId::new_v4(),
        ext
    ));
    p
}

fn input(title: &str) -> AuvPassEntryInput {
    AuvPassEntryInput {
        group: String::new(),
        title: title.to_string(),
        username: "u".into(),
        password: Zeroizing::new("p".into()),
        url: String::new(),
        notes: String::new(),
        totp: None,
    }
}

fn write_keyfile_bytes(tag: &str, bytes: &[u8]) -> PathBuf {
    let p = tmp(tag, "key");
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn v1_vault_still_opens() {
    // 手工构造 v1 头(无凭据字节)+ 旧派生(仅密码),v2 代码必须能开
    let mut path = tmp("v1", "auvp");
    let salt = [3u8; 16];
    let kdf = fast();
    let key = auv_pass_derive_key(b"old-pw", &salt, &kdf).unwrap();
    let label = AuvPassCipherAlgo::Aes256Gcm.label();
    let mut hdr = Vec::new();
    hdr.extend_from_slice(b"AUVP");
    hdr.extend_from_slice(&1u16.to_le_bytes()); // v1!
    hdr.push(label.len() as u8);
    hdr.extend_from_slice(label.as_bytes());
    hdr.extend_from_slice(&kdf.m_kib.to_le_bytes());
    hdr.extend_from_slice(&kdf.t_cost.to_le_bytes());
    hdr.extend_from_slice(&kdf.p_cost.to_le_bytes());
    hdr.extend_from_slice(&salt);
    let json = br#"{"model_version":1,"entries":[],"groups":[],"history_limit":20}"#;
    let blob = auv_pass_encrypt(AuvPassCipherAlgo::Aes256Gcm, &key, json, &hdr).unwrap();
    let mut file = hdr;
    file.extend_from_slice(&blob.nonce);
    file.extend_from_slice(&blob.ciphertext);
    std::fs::write(&path, &file).unwrap();

    let v = AuvPassVault::open(&path, b"old-pw", None).unwrap();
    assert_eq!(v.entry_count(), 0, "v1 旧库应能打开");
    assert_eq!(v.header().cred, AuvPassVaultCred::Password, "v1 视为仅密码");
    // 保存后升 v2(含凭据字节),再开仍通
    path.set_extension("v2.auvp");
    let v2 = v;
    v2.save(&path).unwrap();
    let again = AuvPassVault::open(&path, b"old-pw", None).unwrap();
    assert_eq!(again.entry_count(), 0);
    let _ = auv_pass_decrypt; // 保持导入
    std::fs::remove_file(&path).ok();
}

#[test]
fn three_credential_combos_roundtrip() {
    let kf = write_keyfile_bytes("bin", &[7u8; 64]); // 任意二进制文件当密钥文件
    for (pw, kf_use, cred) in [
        (b"pw".as_slice(), false, AuvPassVaultCred::Password),
        (b"".as_slice(), true, AuvPassVaultCred::KeyFile),
        (b"pw".as_slice(), true, AuvPassVaultCred::PasswordKeyFile),
    ] {
        let path = tmp("combo", "auvp");
        let keyfile = if kf_use { Some(kf.as_path()) } else { None };
        let mut v = AuvPassVault::create(pw, keyfile, AuvPassCipherAlgo::Sm4Gcm, &fast()).unwrap();
        assert_eq!(v.header().cred, cred);
        v.add_entry(input("条目")).unwrap();
        v.save(&path).unwrap();

        let back = AuvPassVault::open(&path, pw, keyfile).unwrap();
        assert_eq!(back.entry_count(), 1);
        assert_eq!(back.header().cred, cred);
        // 错组合必拒
        assert!(AuvPassVault::open(&path, b"wrong-pw", keyfile).is_err());
        assert!(
            AuvPassVault::open(&path, pw, if kf_use { None } else { Some(kf.as_path()) }).is_err()
        );
        std::fs::remove_file(&path).ok();
    }
    std::fs::remove_file(&kf).ok();
}

#[test]
fn any_file_as_keyfile() {
    // 文本文件(内容即"密钥"):同一内容两份副本等效;内容变一位即失效
    let content = "any file content works - 任意文件均可 2026";
    let kf1 = write_keyfile_bytes("txt", content.as_bytes());
    let kf2 = write_keyfile_bytes("txt2", content.as_bytes());
    let kf3 = write_keyfile_bytes("txt3", b"any file content works - 2027");
    let path = tmp("anyfile", "auvp");
    let mut v =
        AuvPassVault::create(b"", Some(&kf1), AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("t")).unwrap();
    v.save(&path).unwrap();
    assert!(
        AuvPassVault::open(&path, b"", Some(&kf2)).is_ok(),
        "同内容副本等效"
    );
    assert!(
        AuvPassVault::open(&path, b"", Some(&kf3)).is_err(),
        "内容差一个字符即失效(内容即密钥)"
    );
    std::fs::remove_file(&path).ok();
    for k in [&kf1, &kf2, &kf3] {
        std::fs::remove_file(k).ok();
    }
}

#[test]
fn both_empty_rejected() {
    assert!(AuvPassVault::create(b"", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).is_err());
}

#[test]
fn missing_keyfile_rejected_clearly() {
    let path = tmp("miss", "auvp");
    let mut v = AuvPassVault::create(
        b"",
        Some(PathBuf::from("/nonexistent/missing.key").as_path()),
        AuvPassCipherAlgo::Aes256Gcm,
        &fast(),
    );
    // create 时读不到密钥文件 → 报错(create 需读文件派生)
    assert!(v.is_err());
    let _ = &mut v;
    std::fs::remove_file(&path).ok();
}

#[test]
fn kdbx_keyfile_roundtrip_raw_and_xml() {
    // 裸字节密钥文件
    let kf = write_keyfile_bytes("kdbxbin", &[9u8; 48]);
    let path = tmp("kdbxkf", "kdbx");
    let mut v = AuvPassVault::create(b"kp", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("KDBX条目")).unwrap();
    v.export_kdbx(&path, b"kp", Some(&kf)).unwrap();

    // 独立核验:keepass crate 带 password+keyfile 读回
    let mut f = std::fs::File::open(&path).unwrap();
    let mut kfr = std::fs::File::open(&kf).unwrap();
    let key = keepass::DatabaseKey::new()
        .with_password("kp")
        .with_keyfile(&mut kfr)
        .unwrap();
    let db = keepass::Database::open(&mut f, key).unwrap();
    let titles: Vec<_> = db
        .root
        .children
        .iter()
        .filter_map(|n| match n {
            keepass::db::Node::Entry(e) => Some(e.get_title().unwrap_or_default().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(titles, vec!["KDBX条目"]);

    // 自家导入(带密钥文件)
    let mut back = AuvPassVault::create(b"x", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    assert_eq!(back.import_kdbx(&path, b"kp", Some(&kf)).unwrap(), 1);
    assert!(
        back.import_kdbx(&path, b"kp", None).is_err(),
        "缺密钥文件必拒"
    );
    std::fs::remove_file(&path).ok();

    // KeePass XML v2.0 密钥文件(生成器格式)
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>{:064x}</Data></Key></KeyFile>",
        0xabcu128
    );
    let kfxml = write_keyfile_bytes("xml", xml.as_bytes());
    let mut v2 = AuvPassVault::create(b"kp", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v2.add_entry(input("XML键")).unwrap();
    let p2 = tmp("kdbxxml", "kdbx");
    v2.export_kdbx(&p2, b"kp", Some(&kfxml)).unwrap();
    let mut back2 =
        AuvPassVault::create(b"x", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    assert_eq!(
        back2.import_kdbx(&p2, b"kp", Some(&kfxml)).unwrap(),
        1,
        "XML 密钥文件可用"
    );
    std::fs::remove_file(&p2).ok();
    std::fs::remove_file(&kfxml).ok();
    std::fs::remove_file(&kf).ok();
}

#[test]
fn format_version_is_three_and_cred_in_aad() {
    assert_eq!(AUV_PASS_VAULT_FORMAT_VERSION, 3, "格式契约:当前 v3");
    let h = AuvPassVaultHeader {
        algo: AuvPassCipherAlgo::Aes256Gcm,
        kdf: fast(),
        salt: [1u8; 16],
        cred: AuvPassVaultCred::KeyFile,
    };
    let b = h.to_bytes().unwrap();
    let (back, n) = AuvPassVaultHeader::from_bytes(&b).unwrap();
    assert_eq!(back.cred, AuvPassVaultCred::KeyFile);
    assert_eq!(n, b.len());
    // 篡改凭据字节 → 解析层可拒(未知值)或解密层拒(AAD);此处验证未知值被拒
    let mut evil = b.clone();
    let last = evil.len() - 1;
    evil[last] = 9;
    assert!(AuvPassVaultHeader::from_bytes(&evil).is_err());
}
