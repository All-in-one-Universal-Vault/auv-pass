// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 密码生成器(特色功能模块)。
//!
//! 对齐 NIST SP 800-63B:均匀随机取样 + 长度优先 + 字符类**可选不强制**;
//! 取样用拒绝采样消除模偏置(RFC 4086 精神:拒绝 ≥ 256-(256 mod n) 的字节);
//! 随机源 = getrandom(OS 熵)。多词口令短语(EFF Diceware)留后续版本。

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// 小写字母表。
pub const AUV_PASS_GEN_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
/// 大写字母表。
pub const AUV_PASS_GEN_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// 数字表。
pub const AUV_PASS_GEN_DIGITS: &str = "0123456789";
/// 符号表(易读、无歧义字符)。
pub const AUV_PASS_GEN_SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";
/// 长度下限(NIST 800-63B 对用户口令的最低建议)。
pub const AUV_PASS_GEN_MIN_LEN: usize = 8;
/// 长度上限(防呆)。
pub const AUV_PASS_GEN_MAX_LEN: usize = 128;
/// 默认长度(20 字符 ≈ 131 bit 熵 @ 全字符集)。
pub const AUV_PASS_GEN_DEFAULT_LEN: usize = 20;

/// 生成选项(字符类多选;全不选或排除后字符集为空 = 参数错误)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuvPassGenOptions {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    /// 排除字符(黑名单):从字符集中剔除(典型:去易混淆 0 O 1 l I)。
    pub exclude: String,
}

impl Default for AuvPassGenOptions {
    fn default() -> Self {
        Self {
            length: AUV_PASS_GEN_DEFAULT_LEN,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            exclude: String::new(),
        }
    }
}

impl AuvPassGenOptions {
    fn charset(&self) -> String {
        let mut s = String::new();
        if self.lower {
            s.push_str(AUV_PASS_GEN_LOWER);
        }
        if self.upper {
            s.push_str(AUV_PASS_GEN_UPPER);
        }
        if self.digits {
            s.push_str(AUV_PASS_GEN_DIGITS);
        }
        if self.symbols {
            s.push_str(AUV_PASS_GEN_SYMBOLS);
        }
        if !self.exclude.is_empty() {
            let ex: Vec<char> = self.exclude.chars().collect();
            s = s.chars().filter(|c| !ex.contains(c)).collect();
        }
        s
    }

    fn validate(&self) -> Result<String> {
        let cs = self.charset();
        if self.length < AUV_PASS_GEN_MIN_LEN || self.length > AUV_PASS_GEN_MAX_LEN {
            return Err(Error::InvalidGenOptions(format!(
                "长度须在 {}..={}",
                AUV_PASS_GEN_MIN_LEN, AUV_PASS_GEN_MAX_LEN
            )));
        }
        if cs.is_empty() {
            return Err(Error::InvalidGenOptions(
                "至少启用一个字符类,且排除后字符集不得为空".into(),
            ));
        }
        Ok(cs)
    }
}

/// 生成随机密码(敏感,Zeroizing;均匀取样 + 拒绝采样防模偏置)。
pub fn auv_pass_generate_password(opts: &AuvPassGenOptions) -> Result<Zeroizing<String>> {
    let charset = opts.validate()?;
    let n = charset.len();
    let accept_upto = 256 - (256 % n); // 仅接受 [0, accept_upto) 内的字节 → 无偏置
    let mut out = Vec::with_capacity(opts.length);
    let mut buf = [0u8; 64];
    while out.len() < opts.length {
        getrandom::fill(&mut buf).map_err(|e| Error::Entropy(e.to_string()))?;
        for &b in &buf {
            if (b as usize) < accept_upto {
                out.push(charset.as_bytes()[b as usize % n]);
                if out.len() == opts.length {
                    break;
                }
            }
        }
    }
    let s = String::from_utf8(out).expect("字符表恒为 ASCII");
    Ok(Zeroizing::new(s))
}

/// 该选项下的理论熵(bit)= length × log2(字符集大小)。生成密码为均匀分布,此值精确。
pub fn auv_pass_gen_entropy_bits(opts: &AuvPassGenOptions) -> Result<f64> {
    let charset = opts.validate()?;
    Ok(opts.length as f64 * (charset.len() as f64).log2())
}
