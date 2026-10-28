// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
// 将应用图标嵌入 Windows 可执行文件(仅 Windows 目标)
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/app.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/app.ico");
        res.compile().expect("图标资源编译失败");
    }
}
