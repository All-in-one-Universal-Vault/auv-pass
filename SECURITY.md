# 安全政策 / Security Policy

## 支持版本 / Supported Versions

| 版本                                 | 支持状态   |
| ---------------------------------- | ------ |
| auv-pass 0.1.x（最新补丁）/ latest patch | ✅ 支持   |
| 更早版本 / older lines                 | ❌ 不再支持 |

仅最新 minor 的最新补丁线受支持；下一 minor 发布后，旧 minor 退出支持（会在发布预告中说明）。

Only the latest patch release of the newest minor line is supported; once a new minor ships, the previous line reaches end of life (announced with the release notes).

## 报告漏洞 / Reporting a Vulnerability

- 邮箱 / Email: **[auv-supports@jishu.tech](mailto:auv-supports@jishu.tech)**（非公开渠道 / private channel）
- **请勿先开公开 issue**——细节提前暴露会影响所有用户。
  **Please do NOT open a public issue first**; premature disclosure puts users at risk.
- 报告请尽量包含：影响面、复现步骤或概念验证、受影响版本。
  Where possible, include the impact, reproduction steps or proof of concept, and affected versions.

## 响应承诺 / Response Commitment

- 确认收到 ≤ 72 小时 / acknowledgement within 72 hours.
- 高危问题：修复以紧急补丁随最近的补丁版本发布，不受常规发布节奏约束。
  Critical issues are fixed in an emergency patch shipped ahead of the regular schedule.
- 中低危问题：修复纳入发布计划，并同步告知报告人。
  Lower-severity fixes are planned into the next release, with the reporter kept informed.

## 协调披露 / Coordinated Disclosure

先修复、后公开细节；披露时点与报告人协商确定（报告人要求暂缓或补充的，以双方确认的一致安排为准）。

Fixes ship before details become public; disclosure timing is coordinated with, and consented to by, the reporter.

## 范围 / Scope

- 覆盖本仓源码与官方发布物。Covers this repository's source code and official artifacts.
- 第三方依赖漏洞纳入同一分级响应：命中在役依赖且影响本产品的，随依赖升级与补丁版本处理，并在 CHANGELOG 记录。
  Third-party dependency vulnerabilities receive the same triage; affected dependencies are upgraded and released as patches, recorded in the CHANGELOG.
- 本产品为本地优先密码管理器：请同时评估本地环境（磁盘加密、剪贴板管理器、内存转储策略）对威胁模型的影响。
  This is a local-first password manager: also consider how your environment (disk encryption, clipboard managers, memory-dump policy) affects the threat model.

## 致谢 / Acknowledgements

报告者默认匿名；经本人明确同意后署名致谢。

Reports are anonymous by default; public credit is given only with the reporter's explicit consent.

## 历史记录 / History

安全修复记录见 [CHANGELOG](CHANGELOG.md)。
Security fixes are listed in the [CHANGELOG](CHANGELOG.md).
