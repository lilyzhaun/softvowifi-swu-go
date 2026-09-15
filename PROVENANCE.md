# swu-go 来源与自有维护迁移

## 已知与未知

- 原 README 指向 <https://github.com/iniwex5/swu-go>，当前 `go.mod` 却声明 `github.com/1239t/swu-go`。两者不一致，不能据此推断实际下载来源。
- 可见最早本地导入为 `3e4cd8e7e320bdeb5e5ad79bd5a5baf192e21780`，提交说明为 `feat(tunnel): vendor swu-go and add patches A/B`。该树已经修改，不是纯上游版本。
- 可证明的原始上游 commit 与发布版本均为 **unknown**，manifest 中对应 `null`；不以本地导入 commit、当前主仓库 commit 或虚构 tag 填补。
- MIT 原文及 `Copyright (c) 2026 iniwex5` 保留于 `LICENSE`；维护目标不改变原始版权归属。

## 准确快照与后续维护

初始自有源码冻结点为 SoftVoWiFi `53c74b87a536eb684f0a84a474269a4cf596a1e2` 的 `engine/third_party/swu-go`。这是包含本地生产修复及回归的准确维护快照，不声称包含完整上游项目或历史。

拟定新私有目标 `lilyzhaun/softvowifi-swu-go`，所有者和最终维护者为 `lilyzhaun`，迁移工具与 PR 由 `newdamm` 提供。目标尚未确认，本任务未创建或推送该仓库；私有不可见不等于不存在。

机器事实源为主仓库 `engine/third_party/manifest.json`。导出的 `.meta.json` 区分初始冻结点与实际 `export_commit`、`source_tree`，同时保留来源说明、许可证和工具/清单指纹。旧 commit 导出仅用于基线验证，不包含本文件，不能用作正式迁移导入源。正式导入须固定包含本说明的已审核提交重新导出，并随该快照保留对应 sidecar。

当前 `go.mod` 的 `replace github.com/iniwex5/netlink => ../netlink` 未改变。独立维护前应先由 `lilyzhaun` 确定 netlink 的真实远端版本，再单独修正 swu-go 依赖并验证；主模块不继承该 nested replace。当前不得删除本地源树。完整顺序见主仓库 `docs/第三方Go依赖维护与导出.md`。

## 本地维护跨度（2026-09-15 源码就绪核对）

首次本地导入已经包含 A/B；之后的维护远不止两个修改。以下为可追溯的本地历史分组与测试入口，不是相对纯上游的完整 diff 或逐行法律审查，未找到的首次导入前来源继续 unknown。

| 本地历史锚点 | 范围与核对入口 |
|---|---|
| `0433930f` | AES-XCBC IKE PRF，`pkg/crypto` 的实现与测试 |
| `780eed13`、`f36304ea`、`f9758989` | AKA 结果边界、重认证 MAC、身份与 post-EAP transcript；`pkg/swu/aka_reference_test.go` 及认证测试 |
| `b2395296`、`69d3447e`、`16f07538` | INIT 绑定、window 孤儿请求、Child SA rekey 失败清理；`pkg/swu` 的 INIT/window/rekey 测试 |
| `e63dd3e2`、`161f5762` | EAP-only 通知与初始设备身份；`pkg/swu/eap_only_notify_test.go`、`initial_device_identity_test.go` |
| `624cdef5`、`e41300ff`、`3a0fbf80` | 嵌套 XFRM、归属/确认/清理与 selector 语义；`pkg/driver/xfrm_config_test.go`、`xfrm_ownership_*test.go` |
| `4f873368`、`3510a577`、`d99d4567` | Android TUN、socket 生命周期、只读诊断；相关 `pkg` 实现与测试，不能据历史标题推定本轮实机通过 |

根 `LICENSE` 与首次本地导入相同，SHA256 为 `b053beb685ef0d03c518220cfe95a2d33899ed9e48173e07a4086b2d56bbecc5`。MIT 文本与版权保留不等于未知原始来源已获法律批准。维护分组仍需在独立源仓首导前补齐逐组变更及直接测试映射；不把上述摘要称为穷尽台账。本切片只补来源记录及主仓打包 MIT 随附接线，不改变协议实现、模块路径、依赖版本或初始冻结点。
