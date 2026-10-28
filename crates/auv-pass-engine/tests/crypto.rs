// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 加密库集成测试(公开 API 面)。
//!
//! KDF 用低配参数(8 MiB/t1/p1)提速——只验证语义,不测强度;强度由默认参数保证,
//! 全链路验收用例单独跑一次默认参数(64 MiB/t3/p1)。

use auv_pass_engine::{
    auv_pass_decrypt, auv_pass_derive_key, auv_pass_encrypt, auv_pass_generate_salt,
    AuvPassCipherAlgo, AuvPassKdfParams, Error, AUV_PASS_KEY_LEN, AUV_PASS_SALT_LEN,
    AUV_PASS_TAG_LEN,
};
use zeroize::{Zeroize, Zeroizing};

const ALGOS: [AuvPassCipherAlgo; 3] = [
    AuvPassCipherAlgo::Aes256Gcm,
    AuvPassCipherAlgo::ChaCha20Poly1305,
    AuvPassCipherAlgo::Sm4Gcm,
];

/// 测试专用低配 KDF 参数(恰在合法下限)。
fn fast() -> AuvPassKdfParams {
    AuvPassKdfParams {
        m_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

/// 固定盐 + 低配参数派生(密码可变)。
fn key_of(pwd: &str) -> Zeroizing<[u8; AUV_PASS_KEY_LEN]> {
    let salt = [7u8; AUV_PASS_SALT_LEN];
    auv_pass_derive_key(pwd.as_bytes(), &salt, &fast()).expect("KDF 派生不应失败")
}

// ---------- KDF ----------

#[test]
fn kdf_deterministic_and_input_sensitive() {
    let salt = auv_pass_generate_salt().unwrap();
    let p = fast();
    let a = auv_pass_derive_key(b"correct horse", &salt, &p).unwrap();
    let b = auv_pass_derive_key(b"correct horse", &salt, &p).unwrap();
    assert_eq!(a[..], b[..], "同输入必须同输出");

    let other_salt = auv_pass_generate_salt().unwrap();
    let c = auv_pass_derive_key(b"correct horse", &other_salt, &p).unwrap();
    assert_ne!(a[..], c[..], "换盐必须换钥");

    let mut stronger = p;
    stronger.t_cost += 1;
    let d = auv_pass_derive_key(b"correct horse", &salt, &stronger).unwrap();
    assert_ne!(a[..], d[..], "换参数必须换钥");

    let e = auv_pass_derive_key(b"wrong horse", &salt, &p).unwrap();
    assert_ne!(a[..], e[..], "换密码必须换钥");
}

#[test]
fn kdf_rejects_invalid_params() {
    let base = fast();
    let cases = [
        AuvPassKdfParams { t_cost: 0, ..base },
        AuvPassKdfParams { p_cost: 0, ..base },
        AuvPassKdfParams { p_cost: 99, ..base },
        AuvPassKdfParams {
            m_kib: 4 * 1024,
            ..base
        },
    ];
    for p in cases {
        let err = auv_pass_derive_key(b"x", &[0u8; AUV_PASS_SALT_LEN], &p).unwrap_err();
        assert!(
            matches!(err, Error::InvalidKdfParams(_)),
            "弱参数须被拒:{p:?}"
        );
    }
}

#[test]
fn generated_salts_unique() {
    let a = auv_pass_generate_salt().unwrap();
    let b = auv_pass_generate_salt().unwrap();
    assert_ne!(a, b, "两次生成盐必须不同");
}

// ---------- 往返 ----------

#[test]
fn roundtrip_both_algos_various_sizes() {
    for algo in ALGOS {
        for size in [0usize, 1, 64, 1000] {
            let pt: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let key = key_of("vault-password");
            let blob = auv_pass_encrypt(algo, &key, &pt, b"header").expect("加密不应失败");
            assert_eq!(blob.algo, algo);
            assert_eq!(blob.nonce.len(), 12);
            assert_eq!(
                blob.ciphertext.len(),
                pt.len() + AUV_PASS_TAG_LEN,
                "密文=明文+tag"
            );
            let back = auv_pass_decrypt(&blob, &key, b"header").expect("解密不应失败");
            assert_eq!(back[..], pt[..], "{algo:?} size={size} 往返不一致");
        }
    }
}

#[test]
fn roundtrip_large_payload_1mib() {
    let pt: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    for algo in ALGOS {
        let key = key_of("large-payload");
        let blob = auv_pass_encrypt(algo, &key, &pt, b"").unwrap();
        let back = auv_pass_decrypt(&blob, &key, b"").unwrap();
        assert_eq!(back[..], pt[..], "{algo:?} 1 MiB 往返不一致");
    }
}

// ---------- 防篡改 ----------

#[test]
fn tamper_ciphertext_rejected() {
    for algo in ALGOS {
        let key = key_of("tamper-test");
        let mut blob = auv_pass_encrypt(algo, &key, b"secret payload", b"").unwrap();
        for pos in [0, blob.ciphertext.len() - 1] {
            blob.ciphertext[pos] ^= 0x01;
            assert!(
                matches!(auv_pass_decrypt(&blob, &key, b""), Err(Error::Decrypt)),
                "{algo:?} 密文篡改位 {pos} 必须被拒"
            );
            blob.ciphertext[pos] ^= 0x01; // 还原,下一位置继续测
        }
    }
}

#[test]
fn truncated_ciphertext_rejected() {
    for algo in ALGOS {
        let key = key_of("trunc-test");
        let mut blob = auv_pass_encrypt(algo, &key, b"secret payload", b"").unwrap();
        blob.ciphertext.truncate(AUV_PASS_TAG_LEN - 1); // 短于 tag 的畸形密文
        assert!(
            matches!(auv_pass_decrypt(&blob, &key, b""), Err(Error::Decrypt)),
            "{algo:?} 畸形长度必须被拒"
        );
    }
}

#[test]
fn tamper_nonce_rejected() {
    for algo in ALGOS {
        let key = key_of("nonce-tamper");
        let mut blob = auv_pass_encrypt(algo, &key, b"secret payload", b"").unwrap();
        blob.nonce[0] ^= 0x80;
        assert!(
            matches!(auv_pass_decrypt(&blob, &key, b""), Err(Error::Decrypt)),
            "{algo:?} nonce 篡改必须被拒"
        );
    }
}

#[test]
fn aad_mismatch_rejected() {
    for algo in ALGOS {
        let key = key_of("aad-test");
        let blob = auv_pass_encrypt(algo, &key, b"secret payload", b"header-v1").unwrap();
        assert!(
            auv_pass_decrypt(&blob, &key, b"header-v2").is_err(),
            "{algo:?} AAD 不符必须被拒"
        );
        assert_eq!(
            auv_pass_decrypt(&blob, &key, b"header-v1").unwrap()[..],
            b"secret payload"[..]
        );
    }
}

#[test]
fn wrong_key_rejected() {
    for algo in ALGOS {
        let blob =
            auv_pass_encrypt(algo, &key_of("right-password"), b"secret payload", b"").unwrap();
        assert!(
            matches!(
                auv_pass_decrypt(&blob, &key_of("wrong-password"), b""),
                Err(Error::Decrypt)
            ),
            "{algo:?} 错钥必须被拒"
        );
    }
}

#[test]
fn nonce_freshness() {
    let key = key_of("fresh-nonce");
    let a = auv_pass_encrypt(AuvPassCipherAlgo::Aes256Gcm, &key, b"same plaintext", b"").unwrap();
    let b = auv_pass_encrypt(AuvPassCipherAlgo::Aes256Gcm, &key, b"same plaintext", b"").unwrap();
    assert_ne!(a.nonce, b.nonce, "两次加密 nonce 必须不同");
    assert_ne!(a.ciphertext, b.ciphertext, "同明文密文必不同(nonce 随机)");
    assert_eq!(
        auv_pass_decrypt(&a, &key, b"").unwrap()[..],
        b"same plaintext"[..]
    );
    assert_eq!(
        auv_pass_decrypt(&b, &key, b"").unwrap()[..],
        b"same plaintext"[..]
    );
}

// ---------- zeroize ----------

#[test]
fn zeroize_clears_buffer() {
    let mut buf: Vec<u8> = b"master-password-live-copy".to_vec();
    let cap = buf.capacity();
    buf.zeroize();
    assert!(buf.iter().all(|&b| b == 0), "zeroize 后必须全零");
    assert!(buf.capacity() >= cap, "zeroize 不缩容(缩容会留下漂移副本)");

    // Zeroizing 包装可用性;drop 后清零由 zeroize crate 编译期保证(红线绑定)
    let z = Zeroizing::new(b"derived-key-material".to_vec());
    assert_eq!(z.len(), 20);
}

// ---------- 全链路验收 ----------

#[test]
fn full_pipeline_default_params_with_header_aad() {
    // 默认参数(64 MiB/t3/p1)跑一次真实强度:"库头即 AAD"用法预演
    let salt = auv_pass_generate_salt().unwrap();
    let params = AuvPassKdfParams::default();
    let key =
        auv_pass_derive_key("真实主密码-示例".as_bytes(), &salt, &params).expect("默认参数派生");

    // 库头(明文非敏感):版本+算法标签+KDF 参数+盐
    let mut header = Vec::new();
    header.extend_from_slice(b"auvpass-v1");
    header.extend_from_slice(AuvPassCipherAlgo::ChaCha20Poly1305.label().as_bytes());
    header.extend_from_slice(&params.m_kib.to_le_bytes());
    header.extend_from_slice(&params.t_cost.to_le_bytes());
    header.extend_from_slice(&params.p_cost.to_le_bytes());
    header.extend_from_slice(&salt);

    let secret = r#"{"entries":[{"title":"示例条目","password":"p@ss"}]}"#.as_bytes();
    let blob =
        auv_pass_encrypt(AuvPassCipherAlgo::ChaCha20Poly1305, &key, secret, &header).unwrap();
    let back = auv_pass_decrypt(&blob, &key, &header).unwrap();
    assert_eq!(back[..], secret[..]);

    // 头被篡改(哪怕一字节)→ 整体解密失败
    let mut evil = header.clone();
    let last = evil.len() - 1;
    evil[last] ^= 0x01;
    assert!(
        matches!(auv_pass_decrypt(&blob, &key, &evil), Err(Error::Decrypt)),
        "头篡改必须整体失败"
    );
}

// ---------- 国标对齐 ----------

#[test]
fn sm4_block_cipher_gb_standard_kat() {
    // GB/T 32907-2016 标准向量(SM4 规范标志向量):单块加密必须逐字节复现,
    // 证明 sm4 crate 实现与国标一致(GCM 组合由上面三算法往返/防篡改测试覆盖)
    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
    let key = h("0123456789abcdeffedcba9876543210");
    let pt = h("0123456789abcdeffedcba9876543210");
    let ct = h("681edf34d206965e86b3e94f536e4246");

    use sm4::cipher::{Array, BlockCipherEncrypt, KeyInit};
    type Sm4Key = Array<u8, <sm4::Sm4 as sm4::cipher::KeySizeUser>::KeySize>;
    type Sm4Block = Array<u8, <sm4::Sm4 as sm4::cipher::BlockSizeUser>::BlockSize>;
    let cipher = sm4::Sm4::new(&Sm4Key::try_from(key.as_slice()).unwrap());
    let mut block = Sm4Block::try_from(pt.as_slice()).unwrap();
    cipher.encrypt_block(&mut block);
    assert_eq!(
        block.as_slice(),
        ct.as_slice(),
        "GB/T 32907-2016 标准向量必须复现"
    );

    assert_eq!(
        AuvPassCipherAlgo::Sm4Gcm.label(),
        "SM4-GCM",
        "国标算法标签进入库头"
    );
}
