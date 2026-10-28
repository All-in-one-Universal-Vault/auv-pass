// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 消费方哨兵测试:本 crate 源码中每个
//! `auv_i18n_tr` / `auv_i18n_tr_fmt` 字面量键都必须存在于 engine 的
//! zh-CN.ftl 目录(防代码与目录漂移;库内键完整性由 engine 侧测试承担)。

use std::collections::BTreeSet;

const CATALOG_ZH_CN: &str = include_str!("../../auv-pass-engine/locales/zh-CN.ftl");

fn catalog_keys(ftl: &str) -> BTreeSet<&str> {
    ftl.lines()
        .filter_map(|l| {
            let l = l.trim_start_matches('\u{feff}');
            if l.starts_with(|c: char| c.is_ascii_alphabetic()) && l.contains('=') {
                Some(l.split('=').next().unwrap().trim())
            } else {
                None
            }
        })
        .collect()
}

fn keys_in(src: &str) -> BTreeSet<String> {
    // 允许 `auv_i18n_tr_fmt(` 与键名字面量之间跨行空白(此前要求 `("` 同行紧邻,
    // 跨行调用逃逸检测)。`auv_i18n_tr(` 不会误吞 `auv_i18n_tr_fmt(`(后者前缀是 tr_)。
    const HEAD_PATS: [&str; 2] = ["auv_i18n_tr(", "auv_i18n_tr_fmt("];
    let mut out = BTreeSet::new();
    for pat in HEAD_PATS {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(pat) {
            let open = from + rel + pat.len();
            // 跳过注释行里的示例
            let line_start = src[..open].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line = &src[line_start..open];
            if !line.contains("//") {
                // 跳过 '(' 后的任意空白(含换行),下一个非空白字符须为 '"'
                let rest = src[open..].trim_start();
                if let Some(key_src) = rest.strip_prefix('"') {
                    if let Some(end) = key_src.find('"') {
                        let key = &key_src[..end];
                        if !key.is_empty() {
                            out.insert(key.to_string());
                        }
                    }
                }
            }
            from = open;
        }
    }
    out
}

#[test]
fn all_source_keys_present_in_catalog() {
    let catalog = catalog_keys(CATALOG_ZH_CN);
    assert!(!catalog.is_empty(), "zh-CN.ftl 未解析出任何键");
    let srcs: &[&str] = &[
        include_str!("../src/main.rs"),
        include_str!("../src/app.rs"),
        include_str!("../src/ui.rs"),
    ];
    let mut missing = Vec::new();
    for src in srcs {
        for key in keys_in(src) {
            if !catalog.contains(key.as_str()) {
                missing.push(key);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "zh-CN.ftl 缺少以下键(目录与代码漂移):\n{}",
        missing.join("\n")
    );
}
