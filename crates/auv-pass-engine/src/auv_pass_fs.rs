// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! auv_pass_fs:敏感文件落盘助手(权限收紧)。

use std::path::Path;

use crate::error::Result;

/// 写敏感文件(导出 OpenSSH 明文私钥等):Unix 下落地即 0600——
/// 新建按 0600 创建,已存在文件也强制收紧到 0600。
/// 按默认 umask(权限掩码)0644 落地属泄露面,且 ssh 客户端会拒载过宽权限的私钥。
/// 非 Unix 平台等价于普通写。
pub fn auv_pass_write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    write_mode_600(path, contents)
}

#[cfg(unix)]
fn write_mode_600(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600) // 仅对新建生效
        .open(path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);
    // 已存在文件 mode() 不生效,显式收紧
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_mode_600(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::auv_pass_write_secret_file;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode_of(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// 导出私钥落地即 0600;已存在的 0644 文件重写后同样收紧。
    #[test]
    fn secret_file_written_with_0600() {
        let mut p = std::env::temp_dir();
        p.push(format!("auv-pass-secret-{}.key", uuid::Uuid::new_v4()));
        auv_pass_write_secret_file(&p, b"PRIVATE").unwrap();
        assert_eq!(mode_of(&p), 0o600, "新建敏感文件须 0600");

        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&p, perms).unwrap();
        auv_pass_write_secret_file(&p, b"PRIVATE2").unwrap();
        assert_eq!(mode_of(&p), 0o600, "重写已存在文件也须收紧到 0600");
        assert_eq!(std::fs::read(&p).unwrap(), b"PRIVATE2");
        let _ = std::fs::remove_file(&p);
    }
}
