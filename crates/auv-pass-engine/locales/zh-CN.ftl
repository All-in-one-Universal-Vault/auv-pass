# auv-pass 文案目录（zh-CN，源语言）——机制在 auv-i18n crate；键为 ASCII 语义键、连字符分层


about-copyright = 版权 © 2026 积澍技术（jishu.tech）
about-version = 版本 { $version }
attachments-placeholder = 保存条目后即可添加附件
brand-slogan = 守之以暗，行之以轻

btn-add = + 新增
btn-allow = 允许
btn-cancel = 取消
btn-copy = 复制
btn-create-enter = 创建并进入
btn-delete = 删除
btn-deny = 拒绝
btn-edit = 编辑
btn-export = 导出
btn-export-count = 导出{ $count }条
btn-export-kdbx = 导出KDBX
btn-export-ssh-key = 导出私钥
btn-generate = 生成
btn-generate-ed25519 = 生成Ed25519
btn-generate-key = 生成钥匙
btn-import = 导入
btn-import-count = 导入{ $count }条
btn-import-kdbx = 导入KDBX
btn-import-ssh-key = 导入私钥
btn-lock = 锁定
btn-new = 新增
btn-new-vault = 新建库
btn-quit = 退出
btn-restore = 恢复
btn-run = 执行
btn-save = 保存
btn-start = 启动
btn-stop = 停止
btn-unlock = 解锁

btn-ok = 确定
btn-revoke = 撤销
check-dup = 同组已有相同标题与用户名的条目——疑似重复
check-url = 网址缺少 http(s):// 前缀，超链接可能失效
check-whitespace = 密码首尾含空格——请确认不是误粘贴
editor-tab-advanced = 高级
editor-tab-basic = 基本
empty-vault-hint = 尚无条目——点工具栏「＋ 新增」添加第一个条目
error-disk-space = 磁盘空间不足：约需 { $need } 字节，可用 { $free } 字节
go-back-edit = 返回修改
dialog-import-kdbx = 导入 KDBX
dialog-new-entry = 新增条目
dialog-sign-request = 签名请求
dialog-sign-request-body =  程序请求用钥匙「{ $name }」签名 
dialog-sign-request-key-title = 钥匙「{ $name }」签名请求
dialog-totp-qr = TOTP 二维码(手机扫码导入)

empty-vault = (空库)

error-agent-start-failed = agent 启动失败:{ $err }
error-clipboard-failed = 剪贴板失败:{ $err }
error-entry-not-found = 条目不存在
error-no-credential = ✗ 主密码为空且未设 AUV_PASS_KEYFILE
error-no-vault = 未开库
error-passwords-mismatch = 两次主密码不一致
error-passwords-mismatch-2 = 两次不一致。
error-path-empty = 路径为空
error-qr-generate = 二维码生成失败
error-read-failed = 读取失败:{ $err }
error-required = 必填
error-title-required = 标题必填
error-totp = TOTP 失败:{ $err }
error-ui = 界面错误:{ $err }
error-unknown-subcommand = 未知子命令:{ $name }
error-write-failed = 写出失败:{ $err }

expose = 上岗

group-all = 全部
group-all-count = 全部 ({ $count })
group-all-paren = (全部)
group-favorites-count = 收藏 ({ $count })
group-root = 根组
group-root-paren = (根)
group-trash-count = 回收站 ({ $count })

hint-empty-cancel = 空=取消
hint-empty-generate = 留空回车=生成器生成
hint-enter-none = 回车=无
hint-enter-skip = 回车跳过=不用
hint-enter-unused = 回车=不用
hint-exclude-chars = 可选黑名单,如 0O1lI 去易混;回车=无
hint-session-allowed = 本会话已自动允许:{ $count } 把(可撤销)
import-preview-body = 将导入 { $entries } 条、{ $groups } 组；跳过 { $skipped } 条
import-preview-title = 导入预览
confirm-import = 确认导入
msg-clipboard-cleared = 剪贴板已清空
hint-group-path = '/'分层,空=根
hint-keep-comment = 留空取原注释
hint-keep-current = 留空=保留现值
hint-keep-or-clear = 留空=保留;- =清除
hint-keyfile-any-file = 任意文件可作密钥文件;回车=不用
hint-keyfile-only = 可空=仅密钥文件
hint-keyfile-only-2 = 仅密钥文件则留空
hint-no-passphrase = 无口令则留空
hint-parent-autocreate = 父目录不存在会自动创建
hint-password-if-keyfile = 将用密钥文件则可留空
hint-totp-scan = 用手机验证器扫码即可导入此密钥
hint-totp-secret = base32 或 otpauth://;回车=不用

label-algorithm = 算法
label-algorithm-choices = 1=AES-256-GCM 2=ChaCha20 3=SM4-GCM(国标)
label-algorithm-short = 算法 1/2/3
label-character-set = 字符类
label-charset-choices = 1=全部 2=字母+数字 3=仅数字
label-deriving-key = 派生密钥中…
label-detail-empty = 选择条目查看详情
label-digits-only = 仅数字
label-editing = 编辑:{ $name }
label-entry-count = { $count } 条
label-exclude = 排除
label-exclude-chars = 排除字符
label-export-file-path = 导出文件路径
label-export-master-password = 导出主密码
label-export-path = 导出路径
label-group = 组
label-groups = 分组
label-kdbx-path = KDBX 文件路径
label-key-comment = 公钥注释与库内展示名
label-key-file = 密钥文件
label-key-file-path = 密钥文件路径
label-keyword = 关键词
label-length = 长度
label-letters-digits = 字母+数字
label-master-password = 主密码
label-matches = 匹配: { $count }
label-modified = 修改于
label-name = 名称
label-notes = 备注
label-passphrase = 口令
label-password = 密码
label-password-colon = 密码:
label-password-masked = ********(c 复制30s清)
label-path = 路径
label-ssh-key-path = 私钥文件路径
label-public-key = 公钥
label-repeat-master-password = 重复主密码
label-search = 搜索…
label-search-scope = 搜索(标题/用户名/URL/备注/组)
label-title = 标题
label-username = 用户名
label-username-colon = 用户名:
label-vault-file = 库文件路径
label-vault-password = 该库主密码

attach-add-anyway = 仍要添加
attach-drop-hint = 请先选中条目再拖入文件
attach-large-body = 文件 { $name }（{ $size }）超过 100MB：入库后全库载入内存，保存耗时随库体积增长，备份体积增大。仍要添加吗？
attach-large-title = 大文件提示
attachments-add-file = 添加文件…
attachments-none = 无附件
attachments-save-as = 另存为…
label-attachments = 附件
label-current-password = 当前主密码
label-new-password = 新主密码
label-new-password-repeat = 重复新主密码
label-new-keyfile = 新密钥文件（留空=不变）
msg-password-changed = 已更改；下次保存即全库重加密
msg-batch-trashed = { $n } 条已移入回收站
msg-attachment-added = 附件已添加并保存
msg-attachment-removed = 附件已删除
msg-attachment-saved = 附件已另存
login-generator-hint = 需要随机密码？打开生成器
msg-master-pw-generated = 已生成——请妥善记录，并在重复栏再输入一次
menu-change-password = 更改主密码…
menu-vault-properties = 库属性
menu-health-report = 健康报告…
menu-font-size = 字体大小
menu-dark-theme = 暗色主题
menu-light-theme = 亮色主题
menu-about = 关于 auv-pass
menu-entries = 条目
menu-entry-delete = 删除选中条目
menu-entry-edit = 编辑选中条目
menu-entry-new = 新增条目
menu-export-kdbx-full = 导出 KDBX(KDBX 4,手机 KeePassDX 可开)
menu-file = 文件
menu-generator = 生成器
menu-help = 帮助
menu-new-vault = 新建密码库
menu-open-vault = 打开密码库
menu-password-generator = 密码生成器
menu-quit =  退出
menu-ssh-export-full = 导出 SSH 私钥(无口令形态,妥善保管!)
menu-ssh-generate-full = 生成 SSH 钥匙(Ed25519,私钥不落盘)
menu-ssh-import-full = 导入 SSH 私钥(OpenSSH 格式,公钥不变)
menu-ssh-keys = SSH 钥匙
menu-tools = 工具
menu-vault = 密码库

msg-added-saved = 已新增并保存。
msg-agent-started = agent 已启动:{ $socket }
msg-agent-started-sock = agent 已启动:{ $socket }
  设 SSH_AUTH_SOCK 指向它即可用(ssh-add -l 验证)。
msg-agent-stopped = agent 已停止。
msg-allow-all = 均允许
msg-cancelled = 已取消。
msg-configured = 已配置
msg-copied = 已复制,{ $secs } 秒后自动清空。
msg-deleted-saved = 已删除并保存。
msg-exported = 已导出
msg-exported-count-path = 已导出 { $count } 条 → { $path }。
msg-fingerprint-copied = 指纹已复制:{ $fp }
msg-generated = 已生成
msg-generated-bits =  生成:{ $password } ({ $bits } bit)
msg-history-password-copied = 历史密码已复制,{ $secs } 秒后自动清空。
msg-imported = 已导入
msg-imported-count = 已导入 { $count } 条并保存。
msg-key-deleted = 钥匙已删除。
msg-key-exposed = 已上岗(重启 agent 后对外提供)。
msg-key-generated = 钥匙已生成并入库存档(默认未上岗;e 上岗)。
msg-key-hidden = 已下岗(未暴露给 agent;重启 agent 后生效)。
msg-locked = 已锁定。
msg-matched-count = 命中 { $count } 条。
msg-matched-count-list = 命中 { $count } 条:
msg-no-exposed-keys = 没有已上岗的钥匙。
msg-no-exposed-keys-hint = 没有已上岗的钥匙——先用 e 上岗一把。
msg-no-totp = 该条目未配置 TOTP。
msg-password-copied = 密码已复制,{ $secs } 秒后自动清空。
msg-ssh-key-exported = 私钥已导出(无口令,务必妥善保管)。
msg-ssh-key-imported = 私钥已导入(公钥不变,服务器零改动)。
msg-public-key-copied = 公钥已复制(非敏感)—— 可直接贴 authorized_keys。
msg-saved = 已保存。
msg-search-cleared = 已取消搜索。
msg-showing-results = 正在展示搜索结果
msg-text = 已解锁(共 { $count } 条)
msg-totp-code = TOTP 验证码:{ $code } (剩余 { $secs } 秒,勿外传)
msg-unlocked-count = 已解锁({ $count } 条)。
msg-updated-history = 已更新(历史 { $count } 条)并保存。
msg-username-copied = 用户名已复制(非敏感,不自动清)。
msg-vault-created = 新库已创建并进入。

no-entries = (无条目)
no-matches = (无命中)

none = 无

panel-confirm =  确认  
panel-confirm-delete =  确认删除 
panel-detail =  详情 
panel-entries =  条目 
panel-groups =  分组 
panel-history =  修改历史:{ $count } 
panel-history-snapshot =  历史快照 @{ $time } 
panel-message =  消息 
panel-search-results =  搜索结果({ $count }) 
panel-select =  选择  
panel-sign-request =  签名请求 
panel-ssh-keys =  钥匙(Ed25519) 
panel-ssh-keys-status =  SSH 密钥 │ { $status }

prompt-choice-default = 选择序号(默认 1): 
prompt-master-password = 主密码(输入不回显): 

repeat = 重复

status-agent-running =  agent 运行中:{ $socket } 
status-agent-stopped =  agent 未运行(a 启动) 
status-confirm-hintbar =  y 允许 │ a 本会话均允许 │ 其他键拒绝 
status-copy-esc =  c 复制 Esc 返回 
status-copy-hint =  (按 c 复制,30 秒后自动清空)
status-delete-hintbar =  y 确认删除 │ n/Esc 取消 
status-delete-this-entry-history-included =  删除该条目(历史一并删除)? 
status-detail-empty =  (选择条目查看详情)
status-detail-hintbar =  p 明文 c 复制30s清 u 复制用户名 t TOTP h 历史 Esc 返回 
status-detail-meta =  历史:{ $count } 条 │ TOTP:{ $totp }
status-form-hintbar =  Tab/↑↓ 换字段 Enter 确认 Esc 取消 
status-keys-hintbar =  ↑↓ 选择 e 上岗/下岗 c 复制公钥 p 复制指纹 x 导出私钥 d 删除 g 生成 i 导入 a agent启停 Esc 返回 
status-main-hintbar =  Tab 切栏 Enter 详情 n 新增 e 编辑 d 删除 h 历史 s 搜索 g 生成 k 钥匙 8 导入 9 导出 l 锁定 q 退出 
status-no-history =  (无历史) Esc 返回 
status-press-any-key =  按任意键返回 
status-preview-hintbar =  { $totp } │ Enter 全屏 │ c 复制密码 │ C 复制用户名
status-preview-modified =  { $url } │ 修改 { $modified }
status-title-bar =  auv-pass │ { $path } │ { $count } 条 │ { $time }

tag-exposed = [上岗]
tag-exposed-short = [上] 
tag-hidden = [下岗]
tag-hidden-short = [下] 

usage-find =   find <库> <词> [--copy] 搜索;--copy 复制密码(30s 清)
usage-list =   list <库>               列出全部条目
usage-no-args =   (无参数)                全屏交互界面
usage-slogan =   守之以暗，行之以轻
usage-version =   --version | -V          版本
health-weak = 弱密码（熵 <60bit）
health-reused = 多账号同密码
health-stale = 超过 365 天未修改
health-ok = 全部通过
health-none = 无
props-algorithm = 算法
props-kdf = KDF 参数
props-entries = 条目数
props-attachments = 附件数
props-file-size = 文件大小
props-file-sha256 = 文件 SHA-256
props-credential = 凭据
props-format = 格式版本
error-old-password-wrong = 当前主密码不正确
overwrite-anyway = 覆盖
overwrite-body = 目标文件已存在:{ $path }
overwrite-title = 覆盖确认
save-anyway = 仍要保存
save-check-title = 保存前检查
save-failed-title = 保存失败
status-agent-active = agent 运行中·自动锁定暂停
status-lock-countdown = { $time } 后自动锁定
title-locked = 已锁定
toolbar-clear-clipboard = 清空剪贴板
toolbar-copy-password = 复制密码
toolbar-copy-username = 复制用户名
