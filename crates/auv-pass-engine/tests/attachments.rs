// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 附件(v3 库格式)集成测试:加/存/开往返、字节零改动、SHA-256 完整性、
//! v2 旧库升级、删除、篡改拒绝、另存与时间戳登记。

use std::path::PathBuf;

use auv_pass_engine::{
    AuvPassCipherAlgo, AuvPassEntryId, AuvPassEntryInput, AuvPassKdfParams, AuvPassVault,
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

fn tmp_path(tag: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "auv-pass-att-{tag}-{}.{}",
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

fn vault() -> AuvPassVault {
    AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap()
}

/// 往返:附件字节零改动、元数据(名/大小/时间/SHA-256)完整保留。
#[test]
fn attachment_roundtrip_byte_identical() {
    let path = tmp_path("rt", "auvp");
    let mut v = vault();
    let id = v.add_entry(input("带附件")).unwrap();
    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 251) as u8).collect();
    let att = v
        .entry_add_attachment(id, "数据.bin", &payload, Some((111, 222, 333)))
        .unwrap();

    v.save(&path).unwrap();
    let back = AuvPassVault::open(&path, b"pw", None).unwrap();

    let metas = back.attachments_of(id);
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, "数据.bin");
    assert_eq!(metas[0].size, payload.len() as u64);
    assert_eq!(
        (metas[0].created, metas[0].modified, metas[0].accessed),
        (111, 222, 333)
    );
    assert_eq!(metas[0].sha256.len(), 64);
    // 字节逐位一致(零改动承诺)
    let bytes = back.attachment_bytes(att).unwrap();
    assert_eq!(bytes, payload.as_slice());
    std::fs::remove_file(&path).ok();
}

/// 头部版本 = 3;v2 旧库(手构造)直接打开,保存后自动升级 v3。
#[test]
fn v2_vault_opens_and_upgrades_to_v3() {
    // 手工构造 v2 库:头(version=2) + 单块 JSON
    let path = tmp_path("v2", "auvp");
    let salt = [5u8; 16];
    let kdf = fast();
    let key = auv_pass_engine::auv_pass_derive_key(b"old", &salt, &kdf).unwrap();
    let label = AuvPassCipherAlgo::ChaCha20Poly1305.label();
    let mut hdr = Vec::new();
    hdr.extend_from_slice(b"AUVP");
    hdr.extend_from_slice(&2u16.to_le_bytes());
    hdr.push(label.len() as u8);
    hdr.extend_from_slice(label.as_bytes());
    hdr.extend_from_slice(&kdf.m_kib.to_le_bytes());
    hdr.extend_from_slice(&kdf.t_cost.to_le_bytes());
    hdr.extend_from_slice(&kdf.p_cost.to_le_bytes());
    hdr.extend_from_slice(&salt);
    hdr.push(1); // 凭据字节:仅密码
    let json = br#"{"model_version":1,"entries":[],"groups":[],"history_limit":20}"#;
    let blob =
        auv_pass_engine::auv_pass_encrypt(AuvPassCipherAlgo::ChaCha20Poly1305, &key, json, &hdr)
            .unwrap();
    let mut file = hdr.clone();
    file.extend_from_slice(&blob.nonce);
    file.extend_from_slice(&blob.ciphertext);
    std::fs::write(&path, &file).unwrap();

    let v = AuvPassVault::open(&path, b"old", None).unwrap();
    assert_eq!(v.entry_count(), 0);
    let p3 = tmp_path("v3", "auvp");
    v.save(&p3).unwrap();
    let raw = std::fs::read(&p3).unwrap();
    assert_eq!(
        u16::from_le_bytes([raw[4], raw[5]]),
        AUV_PASS_VAULT_FORMAT_VERSION,
        "保存后必须升 v3"
    );
    let again = AuvPassVault::open(&p3, b"old", None).unwrap();
    assert_eq!(again.entry_count(), 0);
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&p3).ok();
}

/// 删除附件:元数据与池同时移除,重开不再存在。
#[test]
fn attachment_remove_persists() {
    let path = tmp_path("rm", "auvp");
    let mut v = vault();
    let id = v.add_entry(input("e")).unwrap();
    let a = v.entry_add_attachment(id, "a.bin", b"AAAA", None).unwrap();
    v.entry_add_attachment(id, "b.bin", b"BBBB", None).unwrap();
    v.save(&path).unwrap();

    let mut back = AuvPassVault::open(&path, b"pw", None).unwrap();
    assert_eq!(back.attachments_of(id).len(), 2);
    back.entry_remove_attachment(id, a).unwrap();
    back.save(&path).unwrap();

    let again = AuvPassVault::open(&path, b"pw", None).unwrap();
    let metas = again.attachments_of(id);
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, "b.bin");
    assert!(again.attachment_bytes(a).is_none());
    std::fs::remove_file(&path).ok();
}

/// 篡改附件密文任一字节 → 打开即拒(SHA-256/AEAD 双重拦截)。
#[test]
fn tampered_attachment_rejected() {
    let path = tmp_path("tamper", "auvp");
    let mut v = vault();
    let id = v.add_entry(input("e")).unwrap();
    v.entry_add_attachment(id, "x.bin", b"secret-bytes", None)
        .unwrap();
    v.save(&path).unwrap();
    drop(v);

    let mut raw = std::fs::read(&path).unwrap();
    // 翻转文件末尾附件密文的最后一字节(必在附件块内:JSON 索引很小)
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let evil = path.with_extension("evil.auvp");
    std::fs::write(&evil, &raw).unwrap();
    assert!(
        AuvPassVault::open(&evil, b"pw", None).is_err(),
        "附件密文篡改必须被拒"
    );
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&evil).ok();
}

/// 另存:字节原样写盘,内容与原入库一致。
#[test]
fn attachment_save_to_writes_identical_bytes() {
    let path = tmp_path("save", "auvp");
    let mut v = vault();
    let id = v.add_entry(input("e")).unwrap();
    let att = v
        .entry_add_attachment(
            id,
            "out.bin",
            [0x00u8, 0x01, 0x02, 0xfe, 0xff]
                .iter()
                .chain("文件内容".as_bytes())
                .copied()
                .collect::<Vec<u8>>()
                .as_slice(),
            None,
        )
        .unwrap();
    v.save(&path).unwrap();
    let back = AuvPassVault::open(&path, b"pw", None).unwrap();

    let out = tmp_path("out", "bin");
    let n = back.attachment_save_to(att, &out).unwrap();
    assert_eq!(n as usize, 5 + "文件内容".len());
    let expect: Vec<u8> = [0x00u8, 0x01, 0x02, 0xfe, 0xff]
        .iter()
        .chain("文件内容".as_bytes())
        .copied()
        .collect();
    assert_eq!(std::fs::read(&out).unwrap(), expect);
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&out).ok();
}

/// 同名多附件与多条目共享池语义:每件独立 id,互不串扰。
#[test]
fn multiple_attachments_same_name() {
    let path = tmp_path("multi", "auvp");
    let mut v = vault();
    let id = v.add_entry(input("e")).unwrap();
    v.entry_add_attachment(id, "同.txt", b"first", None)
        .unwrap();
    let second = v
        .entry_add_attachment(id, "同.txt", b"second", None)
        .unwrap();
    v.save(&path).unwrap();
    let back = AuvPassVault::open(&path, b"pw", None).unwrap();
    assert_eq!(back.attachments_of(id).len(), 2);
    assert_eq!(back.attachment_bytes(second).unwrap(), b"second");
    std::fs::remove_file(&path).ok();
}
