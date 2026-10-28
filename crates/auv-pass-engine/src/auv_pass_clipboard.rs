// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! auv_pass_clipboard:剪贴板延时清空的竞态安全决策(纯函数,零 arboard 依赖)。
//!
//! 竞态场景:t=0 复制 A(清除线程甲已排定),t=20 复制 B(清除线程乙排定),
//! t=30 线程甲醒来无脑清空——把 B 抹掉。
//! 对策 = 代数戳(epoch counter)+ 读回比对(read-back compare)双重校验:
//! 清除线程只在自己仍是最新一代、且剪贴板内容仍是自己写入的值时才执行清空。

/// 判定延时清空线程是否应执行清空。
///
/// - `my_epoch != current_epoch`:期间已有更新的复制,旧线程让位(不清);
/// - 读回成功且内容 != 自己写入值:用户已在别处复制了别的内容,不清;
/// - 读回失败(平台/权限不支持读):偏向清空(敏感数据卫生优先);
/// - 其余(最新一代且内容未变):清。
pub fn auv_pass_clipboard_should_clear(
    my_epoch: u64,
    current_epoch: u64,
    written: &str,
    readback: Option<&str>,
) -> bool {
    if my_epoch != current_epoch {
        return false;
    }
    match readback {
        Some(cur) => cur == written,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::auv_pass_clipboard_should_clear;

    /// 竞态回归:t=0 复制 A(代数 1),t=20 复制 B(代数 2),t=30 A 的线程醒来不得清掉 B。
    #[test]
    fn clear_only_latest_epoch_and_own_content() {
        // 旧代数让位:不得清掉更新复制的内容
        assert!(!auv_pass_clipboard_should_clear(1, 2, "A", Some("B")));
        // 最新代数且内容未变:清
        assert!(auv_pass_clipboard_should_clear(2, 2, "B", Some("B")));
        // 最新代数但用户已在别处复制了别的内容:不清(防误清用户剪贴板)
        assert!(!auv_pass_clipboard_should_clear(
            2,
            2,
            "B",
            Some("用户新复制的内容")
        ));
        // 读回失败:偏向清空(敏感数据卫生优先)
        assert!(auv_pass_clipboard_should_clear(2, 2, "B", None));
    }
}
