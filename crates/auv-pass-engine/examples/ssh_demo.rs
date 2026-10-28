// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! 演示:生成一把 Ed25519 钥匙并导出私钥文件(供 ssh-keygen 交叉验证)。
//! 用法:cargo run -p auv-pass-engine --example ssh_demo -- [输出目录]

use auv_pass_engine::{AuvPassCipherAlgo, AuvPassKdfParams, AuvPassVault};

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let mut v = AuvPassVault::create(
        b"demo",
        None,
        AuvPassCipherAlgo::Aes256Gcm,
        &AuvPassKdfParams::default(),
    )
    .expect("建库");
    let id = v.ssh_generate_ed25519("auv-pass-demo").expect("生成");
    let pem = v.ssh_export_private(id).expect("导出");
    let path = std::path::Path::new(&dir).join("auv-pass-demo.key");
    std::fs::write(&path, pem).expect("写文件");
    println!("✓ 私钥已导出:{}", path.display());
    println!("✓ 公钥行(可直接进 authorized_keys):");
    println!("{}", v.ssh_keys()[0].public_line);
}
