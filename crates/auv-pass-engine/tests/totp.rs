// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! TOTP 集成测试:RFC 6238 附录 B 官方向量 KAT + base32/otpauth/库集成。

use auv_pass_engine::{
    auv_pass_totp_base32_decode, auv_pass_totp_generate, auv_pass_totp_generate_with_key,
    auv_pass_totp_parse_otpauth, auv_pass_totp_remaining_seconds, AuvPassCipherAlgo,
    AuvPassEntryId, AuvPassEntryInput, AuvPassKdfParams, AuvPassTotpAlgo, AuvPassTotpConfig,
    AuvPassVault,
};
use zeroize::Zeroizing;

// ---------- RFC 6238 附录 B 官方向量(密钥 = 对应 ASCII 种子,8 位码) ----------

#[test]
fn rfc6238_official_vectors_sha1() {
    let cases = [
        (59i64, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ];
    for (t, expect) in cases {
        let got = auv_pass_totp_generate_with_key(
            b"12345678901234567890",
            AuvPassTotpAlgo::Sha1,
            t,
            8,
            30,
        )
        .unwrap();
        assert_eq!(got, expect, "T={t}");
    }
    // base32 配置通道同结果(小写容忍由解码器处理)
    let cfg = AuvPassTotpConfig {
        secret: "gezdgnbvgy3tqojqgezdgnbvgy3tqojq".to_string(),
        digits: 8,
        period_s: 30,
        algorithm: AuvPassTotpAlgo::Sha1,
    };
    assert_eq!(auv_pass_totp_generate(&cfg, 59).unwrap(), "94287082");
}

#[test]
fn rfc6238_official_vectors_sha256_sha512() {
    assert_eq!(
        auv_pass_totp_generate_with_key(
            b"12345678901234567890123456789012",
            AuvPassTotpAlgo::Sha256,
            59,
            8,
            30
        )
        .unwrap(),
        "46119246"
    );
    assert_eq!(
        auv_pass_totp_generate_with_key(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            AuvPassTotpAlgo::Sha512,
            59,
            8,
            30
        )
        .unwrap(),
        "90693936"
    );
}

// ---------- base32 ----------

#[test]
fn base32_decode_edges() {
    assert_eq!(
        auv_pass_totp_base32_decode("gezd gnbv-GY3TQOJQGEZDGNBVGY3TQOJQ==").unwrap(),
        b"12345678901234567890".to_vec()
    );
    assert!(auv_pass_totp_base32_decode("").is_err());
    assert!(
        auv_pass_totp_base32_decode("abc18").is_err(),
        "1/8 不在字母表"
    );
}

// ---------- otpauth ----------

#[test]
fn otpauth_parse_full_and_defaults() {
    let uri = "otpauth://totp/GitHub:dev%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60&algorithm=SHA256";
    let cfg = auv_pass_totp_parse_otpauth(uri).unwrap();
    assert_eq!(cfg.secret, "JBSWY3DPEHPK3PXP");
    assert_eq!(cfg.digits, 8);
    assert_eq!(cfg.period_s, 60);
    assert_eq!(cfg.algorithm, AuvPassTotpAlgo::Sha256);

    let minimal = auv_pass_totp_parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(minimal.digits, 6);
    assert_eq!(minimal.period_s, 30);
    assert_eq!(minimal.algorithm, AuvPassTotpAlgo::Sha1);

    assert!(auv_pass_totp_parse_otpauth("https://example.com?secret=x").is_err());
    assert!(
        auv_pass_totp_parse_otpauth("otpauth://totp/x").is_err(),
        "缺 secret 须拒"
    );
}

// ---------- 计时 ----------

#[test]
fn remaining_seconds_math() {
    assert_eq!(auv_pass_totp_remaining_seconds(30, 59), 1);
    assert_eq!(auv_pass_totp_remaining_seconds(30, 60), 30);
    assert_eq!(auv_pass_totp_remaining_seconds(60, 0), 60);
}

// ---------- 库集成 ----------

#[test]
fn vault_entry_totp_roundtrip_and_history() {
    let mut path = std::env::temp_dir();
    path.push(format!("auv-pass-m4-{}.auvp", AuvPassEntryId::new_v4()));
    let cfg = AuvPassTotpConfig {
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        ..Default::default()
    };
    let mut v = AuvPassVault::create(b"pw", None, AuvPassCipherAlgo::Aes256Gcm, &fast()).unwrap();
    let id = v
        .add_entry(AuvPassEntryInput {
            group: "g".into(),
            title: "t".into(),
            username: "u".into(),
            password: Zeroizing::new("p".into()),
            url: String::new(),
            notes: String::new(),
            totp: Some(cfg.clone()),
        })
        .unwrap();
    v.save(&path).unwrap();
    let reopened = AuvPassVault::open(&path, b"pw", None).unwrap();
    assert_eq!(reopened.get_entry(id).unwrap().totp, Some(cfg.clone()));

    // 更新换 TOTP → 历史快照携带旧配置
    let mut v2 = reopened;
    let mut new_cfg = cfg.clone();
    new_cfg.digits = 8;
    v2.update_entry(
        id,
        AuvPassEntryInput {
            group: "g".into(),
            title: "t".into(),
            username: "u".into(),
            password: Zeroizing::new("p".into()),
            url: String::new(),
            notes: String::new(),
            totp: Some(new_cfg),
        },
    )
    .unwrap();
    assert_eq!(v2.history(id).unwrap()[0].totp, Some(cfg));
    std::fs::remove_file(&path).ok();
}

fn fast() -> AuvPassKdfParams {
    AuvPassKdfParams {
        m_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}
