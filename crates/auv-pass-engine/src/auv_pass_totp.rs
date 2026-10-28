// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! TOTP 时间型一次性验证码(特色功能模块)。
//!
//! - RFC 6238(TOTP)+ RFC 4226(HOTP 动态截断)**自实现**(约百行,减少依赖);
//! - HMAC(RFC 2104)构造自实现——构造不是原语,不为它引依赖;哈希原语用 sha1/sha2 crate;
//! - 密钥存储 base32(RFC 4648);兼容 otpauth:// URI(事实标准)解析;
//! - RFC 6238 附录 B 官方向量 KAT 见 tests/totp.rs。

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 默认位数(Google Authenticator 惯例)。
pub const AUV_PASS_TOTP_DEFAULT_DIGITS: u32 = 6;
/// 默认时间步(秒)。
pub const AUV_PASS_TOTP_DEFAULT_PERIOD: u32 = 30;

/// TOTP 哈希算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuvPassTotpAlgo {
    /// RFC 6238 默认,兼容性最好。
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// TOTP 配置(随条目存储;secret 为 base32)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuvPassTotpConfig {
    /// base32 编码的共享密钥。
    pub secret: String,
    /// 验证码位数(6..=8)。
    pub digits: u32,
    /// 时间步长秒(1..=600)。
    pub period_s: u32,
    pub algorithm: AuvPassTotpAlgo,
}

impl Default for AuvPassTotpConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            digits: AUV_PASS_TOTP_DEFAULT_DIGITS,
            period_s: AUV_PASS_TOTP_DEFAULT_PERIOD,
            algorithm: AuvPassTotpAlgo::Sha1,
        }
    }
}

impl AuvPassTotpConfig {
    /// 参数合法性校验。
    pub fn validate(&self) -> Result<()> {
        if !(6..=8).contains(&self.digits) {
            return Err(Error::Format(format!(
                "TOTP 位数须在 6..=8:{}",
                self.digits
            )));
        }
        if self.period_s == 0 || self.period_s > 600 {
            return Err(Error::Format(format!(
                "TOTP 步长须在 1..=600 秒:{}",
                self.period_s
            )));
        }
        if self.secret.trim().is_empty() {
            return Err(Error::Format("TOTP 密钥为空".into()));
        }
        Ok(())
    }
}

// ---------- HMAC 构造自实现(RFC 2104;原语来自 sha1/sha2) ----------

macro_rules! hmac_fn {
    ($name:ident, $hash_ty:path, $digest:path, $block:expr, $out:expr) => {
        fn $name(key: &[u8], msg: &[u8]) -> [u8; $out] {
            use $digest as Digest;
            let mut k = [0u8; $block];
            if key.len() > $block {
                let h = <$hash_ty>::digest(key);
                k[..h.len()].copy_from_slice(&h);
            } else {
                k[..key.len()].copy_from_slice(key);
            }
            let mut ipad = [0x36u8; $block];
            let mut opad = [0x5cu8; $block];
            for i in 0..$block {
                ipad[i] ^= k[i];
                opad[i] ^= k[i];
            }
            let mut inner = <$hash_ty>::new();
            inner.update(&ipad);
            inner.update(msg);
            let ih = inner.finalize();
            let mut outer = <$hash_ty>::new();
            outer.update(&opad);
            outer.update(&ih);
            let oh = outer.finalize();
            let mut out = [0u8; $out];
            out.copy_from_slice(&oh);
            out
        }
    };
}

hmac_fn!(hmac_sha1, sha1::Sha1, sha1::Digest, 64, 20);
hmac_fn!(hmac_sha256, sha2::Sha256, sha2::Digest, 64, 32);
hmac_fn!(hmac_sha512, sha2::Sha512, sha2::Digest, 128, 64);

// ---------- base32(RFC 4648,A-Z2-7;容忍小写/空白/-/=) ----------

/// 解码 base32 密钥。
pub fn auv_pass_totp_base32_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(Error::Format("TOTP 密钥为空".into()));
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in cleaned.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err(Error::Format(format!("base32 非法字符:{c}"))),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ---------- HOTP/TOTP 核心(RFC 4226 动态截断 + RFC 6238 时间步) ----------

/// HOTP 动态截断(RFC 4226 第 5.3 节)。
fn hotp_code(mac: &[u8], digits: u32) -> String {
    let off = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([mac[off] & 0x7f, mac[off + 1], mac[off + 2], mac[off + 3]]);
    let code = bin % 10u32.pow(digits);
    format!("{code:0>width$}", width = digits as usize)
}

/// 以原始密钥字节生成 TOTP(RFC 6238;测试直连 RFC 向量用此入口)。
pub fn auv_pass_totp_generate_with_key(
    key: &[u8],
    algorithm: AuvPassTotpAlgo,
    unix: i64,
    digits: u32,
    period_s: u32,
) -> Result<String> {
    if unix < 0 {
        return Err(Error::Format("时间早于 Unix 纪元".into()));
    }
    if !(6..=8).contains(&digits) {
        return Err(Error::Format(format!("位数须在 6..=8:{digits}")));
    }
    if period_s == 0 || period_s > 600 {
        return Err(Error::Format(format!("步长须在 1..=600:{period_s}")));
    }
    let counter = (unix as u64) / period_s as u64;
    let msg = counter.to_be_bytes();
    let mac: Vec<u8> = match algorithm {
        AuvPassTotpAlgo::Sha1 => hmac_sha1(key, &msg).to_vec(),
        AuvPassTotpAlgo::Sha256 => hmac_sha256(key, &msg).to_vec(),
        AuvPassTotpAlgo::Sha512 => hmac_sha512(key, &msg).to_vec(),
    };
    Ok(hotp_code(&mac, digits))
}

/// 按配置(base32 密钥)生成 TOTP。
pub fn auv_pass_totp_generate(cfg: &AuvPassTotpConfig, unix: i64) -> Result<String> {
    cfg.validate()?;
    let key = auv_pass_totp_base32_decode(&cfg.secret)?;
    auv_pass_totp_generate_with_key(&key, cfg.algorithm, unix, cfg.digits, cfg.period_s)
}

/// 当前时间步剩余秒数(展示用)。
pub fn auv_pass_totp_remaining_seconds(period_s: u32, unix: i64) -> u32 {
    if period_s == 0 || unix < 0 {
        return 0;
    }
    (period_s as i64 - unix.rem_euclid(period_s as i64)) as u32
}

// ---------- otpauth:// URI(事实标准)解析 ----------

/// 解析 otpauth://totp/ URI(取 secret/digits/period/algorithm;issuer/label 仅展示,不存)。
pub fn auv_pass_totp_parse_otpauth(uri: &str) -> Result<AuvPassTotpConfig> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| Error::Format("非 otpauth://totp URI".into()))?;
    let params = rest.split_once('?').map(|(_, p)| p).unwrap_or("");
    let mut cfg = AuvPassTotpConfig::default();
    for pair in params.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| Error::Format(format!("otpauth 参数缺等号:{pair}")))?;
        match k {
            "secret" => cfg.secret = v.to_string(),
            "digits" => {
                cfg.digits = v
                    .parse()
                    .map_err(|_| Error::Format(format!("digits 非数字:{v}")))?;
            }
            "period" => {
                cfg.period_s = v
                    .parse()
                    .map_err(|_| Error::Format(format!("period 非数字:{v}")))?;
            }
            "algorithm" => {
                cfg.algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => AuvPassTotpAlgo::Sha1,
                    "SHA256" => AuvPassTotpAlgo::Sha256,
                    "SHA512" => AuvPassTotpAlgo::Sha512,
                    other => return Err(Error::Format(format!("不支持的 algorithm:{other}"))),
                };
            }
            _ => {} // issuer 等展示参数忽略
        }
    }
    cfg.validate()?;
    Ok(cfg)
}
