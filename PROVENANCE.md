# swu-go 来源与自有维护迁移

## 已知与未知

- 原 README 指向 <https://github.com/iniwex5/swu-go>，当前 `go.mod` 却声明 `github.com/1239t/swu-go`。两者不一致，不能据此推断实际下载来源。
- 可见最早本地导入为 `3e4cd8e7e320bdeb5e5ad79bd5a5baf192e21780`，提交说明为 `feat(tunnel): vendor swu-go and add patches A/B`。该树已经修改，不是纯上游版本。
- 可证明的原始上游 commit 与发布版本均为 **unknown**，manifest 中对应 `null`；不以本地导入 commit、当前主仓库 commit 或虚构 tag 填补。
- MIT 原文及 `Copyright (c) 2026 iniwex5` 保留于 `LICENSE`；维护目标不改变原始版权归属。

## 准确快照与后续维护

初始自有源码冻结点为 SoftVoWiFi `53c74b87a536eb684f0a84a474269a4cf596a1e2` 的 `engine/third_party/swu-go`。这是包含本地生产修复及回归的准确维护快照，不声称包含完整上游项目或历史。

实际私有仓库为 [lilyzhaun/softvowifi-swu-go](https://github.com/lilyzhaun/softvowifi-swu-go)，2026-09-15 API 确认 PRIVATE；所有者和最终维护者为 `lilyzhaun`，迁移工具与后续经审查的维护 PR 由 `newdamm` 提供。本次 write 邀请状态为 **PENDINGINVITATION**，须 `newdamm` 本人接受后才能确认访问权；未授予 admin。私有快照导入不宣称属于原上游 GitHub fork network。

机器事实源为主仓库 `engine/third_party/manifest.json`。导出的 `.meta.json` 区分初始冻结点与实际 `export_commit`、`source_tree`，同时保留来源说明、许可证和工具/清单指纹。旧 `53c74b8` 导出仅用于基线验证，不包含本文件，未用作正式导入。实际首导来自 SoftVoWiFi `8ca6114de2c915473165bf0698a09ced0f9108e3` 的 `engine/third_party/swu-go`，源码树为 `6976e8f9e2884724d026c8c86fd5901716977b90`，私有首导提交为 `002f1eabfc8430e25ccb845e8b710e8c2bdb1d57`。对应 sidecar 和首导审计回执由 `lilyzhaun` 在私有证据目录保留，不在本仓库发布；初始冻结点与首导记录属于历史，不是重跑旧首导的指令。

私有维护提交 `a4e38cdc98372219f2dc60a7c59a9c0877ccda2c` 已将历史 `../netlink` 替换为 `github.com/lilyzhaun/softvowifi-netlink v0.0.0-20260915075719-be8893d91893`（固定 commit `be8893d918930ed1f6c790c41e51c13c20b20cf9`），并在 `go.sum` 保留真实校验和。主模块不继承该 nested replace，仍须显式固定 netlink。SoftVoWiFi 已验证的迁移候选消费 SWu `v0.0.0-20260915090250-a4e38cdc9837`，不是最新维护 `main` HEAD；本次仅文档提交不改变这些 pin、生产代码、模块文件或许可。主仓工作区已移除重复源码，提交与最终验收尚待完成；本说明不宣布 Issue35 完成。完整流程见主仓库 `docs/第三方Go依赖维护与导出.md`。

## 历史：本地维护跨度（2026-09-15 首导前源码就绪核对）

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
