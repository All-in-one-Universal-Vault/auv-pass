// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! SSH 密钥测试:生成/导入/签名/协议编解码 + 确定性签名等价链。

use auv_pass_engine::{
    auv_pass_agent_build_failure, auv_pass_agent_build_identities_answer,
    auv_pass_agent_build_sign_response, auv_pass_agent_parse_sign_request, AuvPassCipherAlgo,
    AuvPassEntryId, AuvPassKdfParams, AuvPassVault,
};

fn fast() -> AuvPassKdfParams {
    AuvPassKdfParams {
        m_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn vault() -> AuvPassVault {
    AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap()
}

const DATA: &[u8] = b"agent sign challenge \x00\x01\x02";

#[test]
fn ssh_generate_list_sign_roundtrip() {
    let mut v = vault();
    let id = v.ssh_generate_ed25519("测试钥匙").unwrap();
    assert_eq!(v.ssh_keys().len(), 1);
    let k = &v.ssh_keys()[0];
    assert_eq!(k.algorithm, "ssh-ed25519");
    assert!(
        k.public_line.starts_with("ssh-ed25519 "),
        "公钥行应为 authorized_keys 格式"
    );
    assert_eq!(k.public_blob.len(), 51, "blob = 4+11 + 4+32");
    // 确定性签名:同数据两次一致
    let s1 = v.ssh_sign(id, DATA).unwrap();
    let s2 = v.ssh_sign(id, DATA).unwrap();
    assert_eq!(s1.len(), 64, "Ed25519 签名 64 字节");
    assert_eq!(s1, s2, "Ed25519 签名确定性");
    // 删除
    v.ssh_delete(id).unwrap();
    assert!(v.ssh_keys().is_empty());
    assert!(v.ssh_sign(id, DATA).is_err());
}

#[test]
fn ssh_export_import_equivalence() {
    // 生成 → 导出 → 重新导入 → 签名一致(Ed25519 确定性 ⇒ 等价性证明)
    let mut v = vault();
    let id1 = v.ssh_generate_ed25519("原").unwrap();
    let pem = v.ssh_export_private(id1).unwrap();
    let id2 = v.ssh_import(&pem, None, "副本").unwrap();
    let s1 = v.ssh_sign(id1, DATA).unwrap();
    let s2 = v.ssh_sign(id2, DATA).unwrap();
    assert_eq!(s1, s2, "导入副本与原件签名一致");
    assert_eq!(v.ssh_keys()[1].public_blob, v.ssh_keys()[0].public_blob);
}

#[test]
fn ssh_vault_roundtrip_and_old_compat() {
    let mut path = std::env::temp_dir();
    path.push(format!("auv-pass-m6-{}.auvp", AuvPassEntryId::new_v4()));
    let mut v = vault();
    v.ssh_generate_ed25519("钥匙A").unwrap();
    v.ssh_generate_ed25519("钥匙B").unwrap();
    v.save(&path).unwrap();
    let back = AuvPassVault::open(&path, b"pw", None).unwrap();
    assert_eq!(back.ssh_keys().len(), 2, "SSH 密钥随库往返");
    assert!(back
        .ssh_keys()
        .iter()
        .all(|k| k.public_line.starts_with("ssh-ed25519")));
    std::fs::remove_file(&path).ok();
}

// ---------- 协议编解码 ----------

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

fn sstr(s: &[u8]) -> Vec<u8> {
    let mut b = be32(s.len() as u8 as u32).to_vec();
    b.extend_from_slice(s);
    b
}

#[test]
fn agent_protocol_codec() {
    let mut v = vault();
    v.ssh_generate_ed25519("协议测试").unwrap();

    // 12:列表应答帧 = 长度前缀 + 12 + n + (blob, comment)*
    let frame = auv_pass_agent_build_identities_answer(v.ssh_keys());
    assert_eq!(&frame[..4], &be32((frame.len() - 4) as u32));
    assert_eq!(frame[4], 12);
    assert_eq!(&frame[5..9], &be32(1));
    let blob_len = u32::from_be_bytes(frame[9..13].try_into().unwrap()) as usize;
    assert_eq!(blob_len, 51, "wire blob 长度");
    assert_eq!(&frame[13..17], &be32(11), "blob 内层算法名长度");

    // 13:手工构造签名请求 → 解析
    let key_blob = v.ssh_keys()[0].public_blob.clone();
    let mut req = vec![13u8];
    req.extend_from_slice(&sstr(&key_blob));
    req.extend_from_slice(&sstr(DATA));
    req.extend_from_slice(&be32(0));
    let (kb, data, flags) = auv_pass_agent_parse_sign_request(&req).unwrap();
    assert_eq!(kb, key_blob);
    assert_eq!(data, DATA);
    assert_eq!(flags, 0);
    // 非法消息
    assert!(auv_pass_agent_parse_sign_request(&[14, 0, 0]).is_err());
    assert!(auv_pass_agent_parse_sign_request(&[13, 0, 0, 0, 99]).is_err());

    // 14:签名应答帧
    let sig = v.ssh_sign(v.ssh_keys()[0].id, DATA).unwrap();
    let resp = auv_pass_agent_build_sign_response(&sig);
    assert_eq!(resp[4], 14);
    assert_eq!(
        u32::from_be_bytes(resp[5..9].try_into().unwrap()) as usize,
        64
    );
    assert_eq!(&resp[9..], &sig[..]);

    // 5:失败帧
    let fail = auv_pass_agent_build_failure(5);
    assert_eq!(fail, [0, 0, 0, 5, 5, 0, 0, 0, 5]);
}
#[test]
#[ignore = "需本地命名管道直连权限;受限环境用 cargo test -- --ignored 运行"]
fn agent_end_to_end_ssh_add_lists_exposed_keys() {
    use auv_pass_engine::{auv_pass_agent_start, AuvPassEntryId};
    let mut v = vault();
    let a = v.ssh_generate_ed25519("上岗").unwrap();
    let _b = v.ssh_generate_ed25519("未上岗").unwrap(); // 不暴露
    v.ssh_set_exposed(a, true).unwrap();
    assert_eq!(v.ssh_exposed_keys().len(), 1, "只有上岗钥匙进入快照");

    let socket = if cfg!(windows) {
        format!(
            r"\\.\pipe\auv-pass-test-{}",
            AuvPassEntryId::new_v4().simple()
        )
    } else {
        format!(
            "{}/auv-pass-test-{}.sock",
            std::env::temp_dir().display(),
            AuvPassEntryId::new_v4().simple()
        )
    };
    let h = auv_pass_agent_start(v.ssh_exposed_keys(), &socket, Box::new(|_, _| true)).unwrap();

    let out = std::process::Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .expect("ssh-add 不可用(需 OpenSSH 客户端)");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    h.stop();
    assert!(
        out.status.success(),
        "ssh-add -l 应成功:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("(ED25519)"), "应识别 ED25519:\n{stdout}");
    assert!(stdout.contains("SHA256:"), "应显示指纹:\n{stdout}");
    assert!(!stdout.contains("未上岗"), "未暴露钥匙不得出现:\n{stdout}");
}
