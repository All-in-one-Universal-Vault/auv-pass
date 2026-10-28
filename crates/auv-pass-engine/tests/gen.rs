// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 密码生成器集成测试(NIST SP 800-63B 对齐:均匀+拒绝采样+长度优先)。

use auv_pass_engine::{
    auv_pass_gen_entropy_bits, auv_pass_generate_password, AuvPassGenOptions, Error,
    AUV_PASS_GEN_DIGITS, AUV_PASS_GEN_LOWER, AUV_PASS_GEN_SYMBOLS, AUV_PASS_GEN_UPPER,
};

#[test]
fn gen_length_and_charset_membership() {
    let cases = [
        (
            AuvPassGenOptions::default(),
            format!(
                "{}{}{}{}",
                AUV_PASS_GEN_LOWER, AUV_PASS_GEN_UPPER, AUV_PASS_GEN_DIGITS, AUV_PASS_GEN_SYMBOLS
            ),
        ),
        (
            AuvPassGenOptions {
                length: 16,
                upper: false,
                lower: true,
                digits: true,
                symbols: false,
                exclude: String::new(),
            },
            format!("{}{}", AUV_PASS_GEN_LOWER, AUV_PASS_GEN_DIGITS),
        ),
        (
            AuvPassGenOptions {
                length: 12,
                upper: false,
                lower: false,
                digits: true,
                symbols: false,
                exclude: String::new(),
            },
            AUV_PASS_GEN_DIGITS.to_string(),
        ),
    ];
    for (opts, charset) in &cases {
        let pw = auv_pass_generate_password(opts).unwrap();
        assert_eq!(pw.len(), opts.length);
        assert!(
            pw.chars().all(|c| charset.contains(c)),
            "生成字符必须全部来自所选字符集(不回显密码)"
        );
    }
}

#[test]
fn gen_rejects_invalid_options() {
    let bad = [
        AuvPassGenOptions {
            length: 4,
            ..Default::default()
        }, // 过短
        AuvPassGenOptions {
            length: 200,
            ..Default::default()
        }, // 过长
        AuvPassGenOptions {
            upper: false,
            lower: false,
            digits: false,
            symbols: false,
            ..Default::default()
        }, // 空字符集
    ];
    for opts in &bad {
        assert!(matches!(
            auv_pass_generate_password(opts),
            Err(Error::InvalidGenOptions(_))
        ));
        assert!(auv_pass_gen_entropy_bits(opts).is_err());
    }
}

#[test]
fn gen_uniqueness() {
    let a = auv_pass_generate_password(&AuvPassGenOptions::default()).unwrap();
    let b = auv_pass_generate_password(&AuvPassGenOptions::default()).unwrap();
    assert_ne!(a.as_str(), b.as_str(), "两次生成必不同(131 bit 熵)");
}

#[test]
fn gen_entropy_bits_exact_math() {
    let full_len = format!(
        "{}{}{}{}",
        AUV_PASS_GEN_LOWER, AUV_PASS_GEN_UPPER, AUV_PASS_GEN_DIGITS, AUV_PASS_GEN_SYMBOLS
    )
    .len() as f64;
    let bits = auv_pass_gen_entropy_bits(&AuvPassGenOptions::default()).unwrap();
    assert!(
        (bits - 20.0 * full_len.log2()).abs() < 1e-9,
        "全字符集 20 字符熵与字符表长度一致:{bits}"
    );
    let digits = auv_pass_gen_entropy_bits(&AuvPassGenOptions {
        length: 10,
        upper: false,
        lower: false,
        digits: true,
        symbols: false,
        exclude: String::new(),
    })
    .unwrap();
    assert!(
        (digits - 10.0 * (AUV_PASS_GEN_DIGITS.len() as f64).log2()).abs() < 1e-9,
        "10 位纯数字熵与数字表一致:{digits}"
    );
}
#[test]
fn gen_exclude_blacklist() {
    // 仅数字 + 排除 0 和 9:生成结果只含 1..=8,熵按 9 符号计
    let opts = AuvPassGenOptions {
        length: 40,
        upper: false,
        lower: false,
        digits: true,
        symbols: false,
        exclude: "09".to_string(),
    };
    let pw = auv_pass_generate_password(&opts).unwrap();
    assert!(
        pw.chars().all(|c| ('1'..='8').contains(&c)),
        "排除字符不得出现(不回显密码)"
    );
    let bits = auv_pass_gen_entropy_bits(&opts).unwrap();
    assert!(
        (bits - 40.0 * 8.0f64.log2()).abs() < 1e-9,
        "熵按有效字符集计算:{bits}"
    );

    // 排除后字符集为空 → 拒绝
    let empty = AuvPassGenOptions {
        length: 10,
        upper: false,
        lower: false,
        digits: true,
        symbols: false,
        exclude: "0123456789".to_string(),
    };
    assert!(auv_pass_generate_password(&empty).is_err(), "排空须拒");

    // 典型场景:全类去易混 0O1lI
    let confusables = AuvPassGenOptions {
        exclude: "0O1lI".to_string(),
        ..Default::default()
    };
    let pw2 = auv_pass_generate_password(&confusables).unwrap();
    assert!(pw2.chars().all(|c| !"0O1lI".contains(c)));
}
