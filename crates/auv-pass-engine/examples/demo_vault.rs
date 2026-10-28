// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 演示:生成一个可直接用 auv-pass-tui 打开的示例库。
//!
//! 用法:cargo run -p auv-pass-engine --example demo_vault -- [输出路径]
//! 不给路径则写到系统临时目录。主密码固定为 "demo"(演示用,勿存真实数据)。

use std::path::PathBuf;

use auv_pass_engine::{
    auv_pass_generate_password, AuvPassCipherAlgo, AuvPassEntryInput, AuvPassGenOptions,
    AuvPassKdfParams, AuvPassTotpConfig, AuvPassVault,
};
use zeroize::Zeroizing;

fn main() {
    let path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push("auv-pass-demo.auvp");
            p
        });

    let pw = Zeroizing::new("demo".to_string());
    let mut vault = AuvPassVault::create(
        &pw.to_string().into_bytes(),
        None,
        AuvPassCipherAlgo::Aes256Gcm,
        &AuvPassKdfParams::default(),
    )
    .expect("创建库失败");

    let generated =
        auv_pass_generate_password(&AuvPassGenOptions::default()).expect("生成密码失败");
    for (group, title, user, pass, url) in [
        (
            "工作/邮箱",
            "示例邮箱",
            "demo@example.com",
            "demo-pass-1",
            "https://mail.example.com",
        ),
        (
            "工作/开发",
            "GitHub",
            "dev@example.com",
            generated.as_str(),
            "https://github.com",
        ),
        ("个人", "论坛", "me", "demo-pass-3", ""),
    ] {
        vault
            .add_entry(AuvPassEntryInput {
                group: group.to_string(),
                title: title.to_string(),
                username: user.to_string(),
                password: Zeroizing::new(pass.to_string()),
                url: url.to_string(),
                notes: "示例条目(引擎端生成)".to_string(),
                totp: if title == "GitHub" {
                    Some(AuvPassTotpConfig {
                        secret: "JBSWY3DPEHPK3PXP".to_string(), // 经典测试密钥,勿存真实数据
                        ..Default::default()
                    })
                } else {
                    None
                },
            })
            .expect("新增条目失败");
    }
    vault.save(&path).expect("保存失败");
    println!("✓ 示例库已生成:{}", path.display());
    println!("  主密码:demo(演示用)");
    println!("  条目数:{}", vault.entry_count());
    println!(
        "  用 TUI 主菜单「1.打开库」验证,或:auv-pass-tui list {}",
        path.display()
    );
}
