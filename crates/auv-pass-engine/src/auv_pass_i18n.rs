// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! auv-pass 文案层:Fluent 目录内嵌与 i18n 初始化。
//!
//! 机制在 `auv-i18n` crate;本模块只负责把 auv-pass 的 zh-CN/en 目录
//! 注入全局运行时,并按优先级选定语言:
//! `AUV_PASS_LANG` > `AUV_LANG` > POSIX locale > 系统 UI 语言(sys-locale) > zh-CN。
//!
//! Embeds the FTL catalogs for auv-pass and initializes the auv-i18n runtime.
//! Precedence: `AUV_PASS_LANG` > `AUV_LANG` > POSIX locale
//! > OS UI language > zh-CN.

use auv_i18n::{auv_i18n_detect, auv_i18n_init, auv_i18n_set_lang, AuvI18nLang};

const AUV_PASS_CATALOG_ZH_CN: &str = include_str!("../locales/zh-CN.ftl");
const AUV_PASS_CATALOG_EN: &str = include_str!("../locales/en.ftl");

/// 启动初始化:注入目录并选定语言。重复调用忽略(目录以首次为准)。
pub fn auv_pass_i18n_init() -> AuvI18nLang {
    auv_i18n_init(&[
        ("zh-CN", AUV_PASS_CATALOG_ZH_CN),
        ("en", AUV_PASS_CATALOG_EN),
    ]);
    let lang = match std::env::var("AUV_PASS_LANG") {
        Ok(v) if v.to_lowercase().starts_with("en") => AuvI18nLang::En,
        Ok(v) if v.to_lowercase().starts_with("zh") => AuvI18nLang::ZhCn,
        _ => auv_i18n_detect(),
    };
    auv_i18n_set_lang(lang);
    lang
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    fn keys_of(ftl: &str) -> BTreeSet<&str> {
        ftl.lines()
            .filter_map(|l| {
                if l.starts_with(|c: char| c.is_ascii_alphabetic()) && l.contains('=') {
                    Some(l.split('=').next().unwrap().trim())
                } else {
                    None
                }
            })
            .collect()
    }

    fn args_of(ftl: &str, key: &str) -> BTreeSet<String> {
        let mut args = BTreeSet::new();
        let mut active = false;
        for l in ftl.lines() {
            if l.starts_with(|c: char| c.is_ascii_alphabetic()) {
                active = l
                    .split('=')
                    .next()
                    .map(|k| k.trim() == key)
                    .unwrap_or(false);
            }
            if active {
                for m in l.match_indices("{ $") {
                    if let Some(end) = l[m.0..].find(" }") {
                        args.insert(l[m.0 + 3..m.0 + end].to_string());
                    }
                }
            }
        }
        args
    }

    #[test]
    fn catalogs_embedded_and_parse_clean() {
        let issues = auv_i18n::auv_i18n_check_catalog("zh-CN", super::AUV_PASS_CATALOG_ZH_CN);
        assert!(issues.is_empty(), "zh-CN 目录问题: {issues:?}");
        let issues = auv_i18n::auv_i18n_check_catalog("en", super::AUV_PASS_CATALOG_EN);
        assert!(issues.is_empty(), "en 目录问题: {issues:?}");
    }

    #[test]
    fn catalogs_key_sets_match() {
        let zh = keys_of(super::AUV_PASS_CATALOG_ZH_CN);
        let en = keys_of(super::AUV_PASS_CATALOG_EN);
        let only_zh: Vec<_> = zh.difference(&en).collect();
        let only_en: Vec<_> = en.difference(&zh).collect();
        assert!(
            only_zh.is_empty() && only_en.is_empty(),
            "键集漂移: 仅 zh-CN {only_zh:?} / 仅 en {only_en:?}"
        );
        // 每键的命名参数集两语言一致
        for key in &zh {
            let a = args_of(super::AUV_PASS_CATALOG_ZH_CN, key);
            let b = args_of(super::AUV_PASS_CATALOG_EN, key);
            assert_eq!(a, b, "键 {key} 参数集漂移");
        }
    }
}
