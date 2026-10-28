// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 密码库核心集成测试(公开 API 面)。
//! KDF 全用低配参数(8 MiB/t1/p1)提速——只验证格式与 CRUD 语义。

use std::path::PathBuf;

use auv_pass_engine::{
    AuvPassCipherAlgo, AuvPassEntryId, AuvPassEntryInput, AuvPassKdfParams, AuvPassVault,
    AuvPassVaultHeader, Error, AUV_PASS_VAULT_MAGIC,
};
use zeroize::Zeroizing;

const ALGOS: [AuvPassCipherAlgo; 3] = [
    AuvPassCipherAlgo::Aes256Gcm,
    AuvPassCipherAlgo::ChaCha20Poly1305,
    AuvPassCipherAlgo::Sm4Gcm,
];

fn fast() -> AuvPassKdfParams {
    AuvPassKdfParams {
        m_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn tmp_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "auv-pass-m2-{}-{}.auvp",
        tag,
        AuvPassEntryId::new_v4()
    ));
    p
}

fn input(
    group: &str,
    title: &str,
    user: &str,
    password: &str,
    url: &str,
    notes: &str,
) -> AuvPassEntryInput {
    AuvPassEntryInput {
        group: group.to_string(),
        title: title.to_string(),
        username: user.to_string(),
        password: Zeroizing::new(password.to_string()),
        url: url.to_string(),
        notes: notes.to_string(),
        totp: None,
    }
}

// ---------- 格式与往返 ----------

#[test]
fn vault_roundtrip_three_algos_with_cjk() {
    for algo in ALGOS {
        let path = tmp_path("roundtrip");
        let mut v = AuvPassVault::create("主密码-测试".as_bytes(), None, algo, &fast()).unwrap();
        let id1 = v
            .add_entry(input(
                "工作/邮箱",
                "GitHub 企业版",
                "dev@example.com",
                "s3cret-PW!",
                "https://github.com",
                "部署与令牌",
            ))
            .unwrap();
        v.add_entry(input("", "Root Entry", "root", "pw", "", ""))
            .unwrap();
        v.save(&path).unwrap();

        let reopened = AuvPassVault::open(&path, "主密码-测试".as_bytes(), None).unwrap();
        assert_eq!(reopened.entry_count(), 2, "{algo:?}");
        assert_eq!(reopened.header().algo, algo);
        let e = reopened.get_entry(id1).unwrap();
        assert_eq!(e.title, "GitHub 企业版");
        assert_eq!(e.username, "dev@example.com");
        assert_eq!(e.password.as_str(), "s3cret-PW!");
        assert_eq!(e.url, "https://github.com");
        assert_eq!(e.notes, "部署与令牌");
        assert_eq!(e.group, "工作/邮箱");
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn empty_vault_roundtrip() {
    let path = tmp_path("empty");
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    let _ = &mut v;
    v.save(&path).unwrap();
    let reopened = AuvPassVault::open(&path, b"pw", None).unwrap();
    assert_eq!(reopened.entry_count(), 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn wrong_password_rejected() {
    let path = tmp_path("wrongpw");
    let mut v = AuvPassVault::create(b"right", None, AuvPassCipherAlgo::Sm4Gcm, &fast()).unwrap();
    v.add_entry(input("", "t", "u", "p", "", "")).unwrap();
    v.save(&path).unwrap();
    assert!(matches!(
        AuvPassVault::open(&path, b"wrong", None),
        Err(Error::Decrypt)
    ));
    std::fs::remove_file(&path).ok();
}

#[test]
fn header_salt_tamper_rejected_end_to_end() {
    // 篡改盐字节:头仍可解析(参数合法),但派生密钥必变 → 解密整体失败(AAD+错钥双保险)
    let path = tmp_path("tamper");
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("", "t", "u", "p", "", "")).unwrap();
    v.save(&path).unwrap();
    drop(v);

    let mut bytes = std::fs::read(&path).unwrap();
    let header_len = {
        let (h, n) = AuvPassVaultHeader::from_bytes(&bytes).unwrap();
        let _ = h;
        n
    };
    bytes[header_len - 2] ^= 0x01; // 盐最后一字节(v2 末位是凭据字节,不翻)
    let evil = path.with_extension("evil.auvp");
    std::fs::write(&evil, &bytes).unwrap();
    assert!(matches!(
        AuvPassVault::open(&evil, b"pw", None),
        Err(Error::Decrypt)
    ));
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&evil).ok();
}

#[test]
fn save_auto_creates_missing_parent_dirs() {
    // 嵌套不存在的目录:save 应自动创建(KeePass 同款行为)
    let mut nested = std::env::temp_dir();
    nested.push(format!("auv-pass-m2-nested-{}", AuvPassEntryId::new_v4()));
    nested.push("deep");
    nested.push("test.auvp");
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("", "t", "u", "p", "", "")).unwrap();
    v.save(&nested).unwrap();
    assert!(nested.exists(), "库文件应已落盘(父目录被自动创建)");
    assert_eq!(
        AuvPassVault::open(&nested, b"pw", None)
            .unwrap()
            .entry_count(),
        1
    );
    std::fs::remove_dir_all(nested.parent().unwrap().parent().unwrap()).ok();
}

#[test]
fn hostile_or_broken_header_rejected() {
    let hdr = AuvPassVaultHeader {
        algo: AuvPassCipherAlgo::Aes256Gcm,
        kdf: fast(),
        salt: [9u8; 16],
        cred: auv_pass_engine::AuvPassVaultCred::Password,
    }
    .to_bytes()
    .unwrap();

    // 魔数不符
    let mut bad = hdr.clone();
    bad[0] = b'X';
    assert!(matches!(
        AuvPassVaultHeader::from_bytes(&bad),
        Err(Error::Format(_))
    ));
    // 版本不符
    let mut bad = hdr.clone();
    bad[4] = 99;
    assert!(matches!(
        AuvPassVaultHeader::from_bytes(&bad),
        Err(Error::Format(_))
    ));
    // 未知算法标签
    let mut bad = hdr.clone();
    let llen = bad[6] as usize;
    bad[7] = b'Q';
    let _ = llen;
    assert!(matches!(
        AuvPassVaultHeader::from_bytes(&bad),
        Err(Error::Format(_))
    ));
    // 恶意 KDF 参数(超大内存):解析期即拒,不会走到派生
    let mut bad = hdr.clone();
    let m_off = 7 + bad[6] as usize;
    bad[m_off..m_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        AuvPassVaultHeader::from_bytes(&bad),
        Err(Error::InvalidKdfParams(_))
    ));
    // 头不完整
    assert!(matches!(
        AuvPassVaultHeader::from_bytes(&hdr[..10]),
        Err(Error::Format(_))
    ));
}

// ---------- CRUD 与历史 ----------

#[test]
fn crud_and_history_flow() {
    let mut v =
        AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::ChaCha20Poly1305, &fast()).unwrap();
    let id = v
        .add_entry(input("组", "标题", "用户", "pw1", "url", "备注"))
        .unwrap();

    assert_eq!(v.entry_count(), 1);
    assert!(v.get_entry(id).is_some());

    // 变更 → 快照 1(内容 = 旧值)
    v.update_entry(id, input("组", "标题2", "用户", "pw2", "url", "备注"))
        .unwrap();
    assert_eq!(v.history(id).unwrap().len(), 1);
    assert_eq!(v.history(id).unwrap()[0].title, "标题");
    assert_eq!(v.history(id).unwrap()[0].password.as_str(), "pw1");

    // 再变 → 快照 2
    v.update_entry(id, input("组", "标题3", "用户", "pw3", "url", "备注"))
        .unwrap();
    assert_eq!(v.history(id).unwrap().len(), 2);
    assert_eq!(v.get_entry(id).unwrap().title, "标题3");

    // 相同输入 → 无变化不快照
    v.update_entry(id, input("组", "标题3", "用户", "pw3", "url", "备注"))
        .unwrap();
    assert_eq!(v.history(id).unwrap().len(), 2);

    // 删除
    v.delete_entry(id).unwrap();
    assert!(v.get_entry(id).is_none());
    assert!(matches!(v.delete_entry(id), Err(Error::EntryNotFound(_))));
    assert!(v.history(id).is_none());
}

#[test]
fn history_cap_and_immediate_shrink() {
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    let id = v.add_entry(input("", "t", "u", "pw0", "", "")).unwrap();
    v.set_history_limit(2);
    for i in 1..=4 {
        v.update_entry(id, input("", "t", "u", &format!("pw{i}"), "", ""))
            .unwrap();
    }
    // 当前=pw4;历史封顶 2 → 保留 pw2、pw3(最旧 pw0/pw1 被丢)
    let h = v.history(id).unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].password.as_str(), "pw2");
    assert_eq!(h[1].password.as_str(), "pw3");

    // 收缩上限立即截断
    v.set_history_limit(1);
    assert_eq!(v.history(id).unwrap().len(), 1);
    assert_eq!(v.history(id).unwrap()[0].password.as_str(), "pw3");
}

#[test]
fn history_disabled_with_zero_limit() {
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Sm4Gcm, &fast()).unwrap();
    let id = v.add_entry(input("", "t", "u", "a", "", "")).unwrap();
    v.set_history_limit(0);
    v.update_entry(id, input("", "t", "u", "b", "", ""))
        .unwrap();
    assert_eq!(v.history(id).unwrap().len(), 0, "上限 0 = 禁用历史");
}

#[test]
fn entry_ids_unique() {
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    let a = v.add_entry(input("", "t1", "u", "p", "", "")).unwrap();
    let b = v.add_entry(input("", "t2", "u", "p", "", "")).unwrap();
    assert_ne!(a, b);
}

// ---------- 分组 ----------

#[test]
fn groups_flow() {
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("工作/邮箱", "a", "u", "p", "", ""))
        .unwrap();
    v.add_entry(input("个人", "b", "u", "p", "", "")).unwrap();
    v.add_entry(input("", "root", "u", "p", "", "")).unwrap();

    let gs = v.groups();
    assert_eq!(gs.len(), 3, "根/工作/个人 三组:{gs:?}");
    assert!(gs.contains(&"工作/邮箱".to_string()));
    assert!(gs.contains(&"个人".to_string()));
    assert!(gs.contains(&String::new()));

    // 空组:显式注册 → 出现 → 删除
    v.add_group("空组");
    assert!(v.groups().contains(&"空组".to_string()));
    v.add_group("空组"); // 幂等
    assert!(matches!(
        v.delete_group("工作/邮箱"),
        Err(Error::GroupNotEmpty(_))
    ));
    v.delete_group("空组").unwrap();
    assert!(!v.groups().contains(&"空组".to_string()));

    assert_eq!(v.entries_in_group("个人").len(), 1);
    assert_eq!(v.entries_in_group("不存在").len(), 0);
}

// ---------- 搜索 ----------

#[test]
fn search_case_insensitive_across_fields() {
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input(
        "工作",
        "GitHub 企业版",
        "dev@example.com",
        "p",
        "https://github.com",
        "部署 token 备查",
    ))
    .unwrap();
    v.add_entry(input(
        "个人",
        "Blog",
        "me",
        "p",
        "https://blog.example.net",
        "随笔",
    ))
    .unwrap();

    assert_eq!(v.search("github").len(), 1, "标题大小写不敏感");
    assert_eq!(
        v.search("dev@").len(),
        1,
        "用户名命中(唯一针,避开另一条 URL 的 example)"
    );
    assert_eq!(v.search("token").len(), 1, "备注命中");
    assert_eq!(v.search("工作").len(), 1, "组名命中");
    assert_eq!(v.search("blog.example").len(), 1, "URL 子串命中");
    assert_eq!(v.search("完全不匹配").len(), 0);
    assert_eq!(v.search("").len(), 2, "空串返回全部");
}

// ---------- 保存 ----------

#[test]
fn save_twice_no_tmp_leftover() {
    let path = tmp_path("atomic");
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.add_entry(input("", "t", "u", "p", "", "")).unwrap();
    v.save(&path).unwrap();
    v.add_entry(input("", "t2", "u", "p", "", "")).unwrap();
    v.save(&path).unwrap();
    assert_eq!(
        AuvPassVault::open(&path, b"pw", None)
            .unwrap()
            .entry_count(),
        2
    );
    let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .contains(&path.file_stem().unwrap().to_string_lossy().to_string())
                && e.file_name().to_string_lossy().ends_with(".tmp")
        })
        .collect();
    assert!(leftovers.is_empty(), "原子写不应遗留临时文件");
    std::fs::remove_file(&path).ok();
}

#[test]
fn magic_constant_anchored() {
    assert_eq!(AUV_PASS_VAULT_MAGIC, b"AUVP", "魔数是格式契约,不许漂移");
}

/// 库文件落盘权限:Unix 下须 0600(默认 umask 0644 会让库全员可读,属泄露面)。
#[cfg(unix)]
#[test]
fn vault_save_permissions_0600() {
    use std::os::unix::fs::PermissionsExt as _;
    let path = tmp_path("perms");
    let v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    v.save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "库文件须 0600 落地");
    // 覆盖写(再次 save)后权限仍保持 0600
    v.save(&path).unwrap();
    let mode2 = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode2, 0o600, "覆盖写后库文件仍须 0600");
    std::fs::remove_file(&path).ok();
}
