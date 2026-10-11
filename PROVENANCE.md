# swu-go 来源与自有维护迁移

> 当前状态（2026-10-10）：本仓为PUBLIC，保留原module与MIT版权，是独立维护快照，
> 不是上游GitHub fork network。下文日期化私有/邀请/旧pin说明只作历史；当前使用、
> 后继维护说明与安全/覆盖边界见[README](README.md)及docs中的协议专题。
> 原始上游commit/version仍unknown；本轮不改源码、依赖或原许可来填补它们。

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

## 2026-09-22：策略路由规则的表归属修正

在维护基准 `16a78ac` 上，`lilyzhaun` 修正 `pkg/driver/nettools.go:AddRule`：只替换同族、同源且同目标表的规则，保留其他活动会话的同源规则。原实现试图按源地址清理旧表残留，不能区分已过期表与另一活动 owner；旧表回收仍应由所属会话的 `FlushRules(table, iface)` 完成，不新增跨表清理或迁移兜底。

直接回归为 `pkg/driver/nettools_rule_ownership_linux_test.go`，使用已有隔离内核测试防护，覆盖 IPv4/IPv6、两种添加顺序、重复安装、canary 保留及停 A 保 B。实现、测试和本条说明由 `lilyzhaun` 独立复核后提交；不改变模块路径、固定依赖、许可证或上述 unknown 上游归属，也不代表主仓已更新 pin 或完成设备验收。

## 2026-10-09：Child SA 换钥与退役的 SPI 方向

负责人`lilyzhaun`，基准`5d48a58cf8657daebeea6efde7bd4acc99ea8ab8`，分支`fix/child-sa-inbound-spi`。依据[RFC7296 §1.3.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.3.3)与[§1.4.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.4.1)，`pkg/swu/state_rekey.go`的REKEY_SA及旧SA Delete都改为本端入向SPI，并在既有公开换钥准入中要求完整双向SA。

直接生产加密报文回归先复现REKEY错误方向/缺入向SA仍发送；修正REKEY后，XFRM/非XFRM两场景独立复现旧Delete错误方向，再修正Delete。`state_rekey_commit_test.go`与`state_rekey_rejection_test.go`原来固定出向SPI的断言已按上述标准改为入向，其他报价、拒绝不提交、内核失败传播、无Delete和冷却期断言全部保留；新`state_rekey_spi_test.go`覆盖不同方向值及缺半对SA。没有复制外部实现或新引入依赖，MIT原文、版权、原模块路径与unknown上游来源保持。

最终ChildRekey聚焦race/shuffle为36个通过事件；一次全库race/shuffle为602个通过事件、6个测试包通过、22个既有隔离内核opt-in测试/子例跳过，另2包无测试文件；全库vet/改动gofmt/diff空白通过。首聚焦中旧Notify14方向契约的失败已记录，未当全库失败/通过。回归用既有pipe传输输出真实加密字节并解码，不是运营商、真实SIM或Android内核验收；主仓固定真实提交与新自然实机结果归主仓任务记录，不预报成功。

## 2026-10-10：通用IKE COOKIE重试首载荷

负责人`lilyzhaun`，基准`27a55cc9f708f8381e226cf5efed1fc5ef44c105`，分支`fix/ike-cookie-first-payload`。依据[RFC7296 §2.6](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.6)，`pkg/swu/state_init.go`仅将重试COOKIE移到第一个载荷，初次请求顺序及其他SPI/KE/Nonce/报价/FRAG/NAT-D均不改变；没有运营商、国家、域名或SIM特判。

新`state_init_cookie_order_test.go`先在原生产builder的两种报价布局/1、20、64字节合成COOKIE及正常Connect的真实loopback UDP路径观察明确RED；最小顺序修正后转绿。回归还比较Cookie之后的其他载荷字节、头部身份/消息号、连续不同Cookie不叠加、不推进鉴权状态；不是只返回200的fixture或设备认证证明。已有COOKIE/NAT-D/报价/redirect守卫断言保留。

最终6测试包/610通过事件、22既有隔离内核opt-in跳过，另2包无测试文件，全库race/shuffle及vet通过。原MIT/版权、模块路径、依赖与unknown上游来源不变，没有复制外部代码。主仓仍需实际远端版本/pin、完整构建与设备鉴权，维护库通过不预报运营商注册成功；最终源码交付回执归本修补PR。

## 2026-10-11：接收验证先于状态消费

负责人`lilyzhaun`，基准`094d484`，分支`fix/a01-receive-validation`。按RFC7296的SA/方向/受保护报文边界及RFC5282/RFC7383的AAD与Pad Length，修复短SK崩溃、认证前SPI写入、明文最终AUTH、未验证窗口消费与UDP端点锁定/端口漂移；具体契约、直接测试和仍未完成项见[接收边界](docs/receive-validation.md)。

直接失败与补充独立GCM/共享分片padding失败均保留，正常CBC/GCM独立标准库peer、非法后合法完成原pending、真实loopback UDP envelope、FIFO/取消/拒绝/内核失败和旧COOKIE/编号兼容回归保持。旧测试仅修正同端加密器/明文假对端的方向、密钥及线格式，不删原断言。无运营商分支、算法/身份猜测、失败降级或外部客户端代码复制；MIT、原module及unknown上游归属不变。库测试不替代主仓真实pin、规范构建、获授权设备或长期验收。

### 部署前后继：GCM共享KEYMAT不被nonce覆盖

基准`8a5eaec`，分支`fix/a01-gcm-key-alias`。独立标准库AES-GCM-16证明生产KEYMAT共享底层数组时，原nonce拼接在encrypt/decrypt/坏tag三个叶断言均写入相邻密钥；仅在两处append前将salt容量限定为长度，强制nonce独立存储。标准密文、合法解密、坏tag拒绝及整块KEYMAT不变直接回归，原接收边界保持。来源仅Go标准库/RFC5282，无外部代码复制、新算法或报价，许可/module/unknown归属不变；主仓须消费后继真实pin并重新构建，不能部署前序产物冒充补齐。

## 2026-10-11：初始Child/CP/TS验证后事务提交

负责人`lilyzhaun`，基准`97d4d31`，分支`fix/a02-child-selection-commit`。按RFC7296 §2.9/2.19/3.3/3.13/3.15，以本次AUTH1独立原报价快照严格匹配单完整ESP选择/CP_REPLY/TS子集，AUTH验证不再提前保存IDr，所有检查/派生后才提交Child/CP/TS/通知与ticket回调；回调参数不别名内部密钥。原六报价、CP/TS、身份、运营商参数不变；完整规则与RED/合法独立peer/剩余边界见[初始事务](docs/initial-child-transaction.md)。

同边界SA/proposal/transform及TS尾随/终止结构不再被忽略，CP高reserved位按标准保持TLV，不误当TV。旧合成peer仅改合法原proposal3/NO_ESN及补原已请求CP/TS，原认证/身份密码断言不删；新畸形包直接从独立完整合法基线突变。没有外部代码复制、新算法/降级或上游归属填补，原MIT/module/unknown来源保持；维护测试与后继真实pin/Android构建/实机分层。

### A02后继：静态拒绝分支

基准`3648adc`、分支`fix/a02-reject-reasons`。主仓首个A02真实标准候选正常实机阴性仅有通用拒绝字符串，故仅为现有拒绝添加固定分支名称/原err包装，不记录身份/地址/配置/鉴权值、不更改协议条件或参数。新四叶诊断准确性/隐私RED→GREEN及整个swu回归/vet通过；实际原因仍须主仓后继真实pin/构建/新证据，不推断运营商错误或削弱已有失败不变量。

基准`c3daded`、分支`fix/a02-source-family-diagnostic`的后继仅把实际已定位的TSi绑定失败细分为静态IPv4/IPv6、无该族分配/有分配但range不包含；无真实协议值或条件改变。合成分类RED→GREEN，正常接受/拒绝与隐私原断言保持。实机哪种仍待新证据，不在本公开库记录私有设备身份/配置或声明连接恢复。

### A02后继：部分地址分配与运行态族约束

基准`171bdb5`、分支`fix/a02-partial-address-families`。正常标准路径已定位未分配族选择器被误作整包拒绝；按RFC7296§2.9/3.15.4，在原全部严格报价/CP/TS检查后取已分配且双向有效交集，未分配族不进入运行配置/初始及换钥XFRM/路由。已分配外国host、无有效族及坏未用TS仍拒绝；原算法/身份/请求/运营商配置不改，无失败安全降级。部分分配及策略/路由直接RED→GREEN、全库770PASS22既有内核opt-in跳过/vet通过；仅族约束，不冒称族内任意范围/端口精确内核enforcement或自然换钥。详见[事务专题](docs/initial-child-transaction.md)。来源只RFC及原维护源码，无外部客户端复制，MIT/module/unknown归属保持。

### A03：完整认证分片与逻辑事务交付

基准`dbe7579`、分支`fix/a03-fragment-transaction`。首片类型保存、完整认证/解析后完成窗口与接收提交，以私有已解析消息避免再次消费最后一片；原SPI/角色/完整性/精确结构/EAP/Child门禁不减。按RFC7383§2.5–2.6.1绑定SA key代次/I-R/exchange/MID，有界片数/字节/在途组/固定超时/生命周期释放、认证PMTU重启及有界已处理请求响应缓存。直接与独立正常UDP长AUTH先29FAIL5PASS，最终聚焦52PASS/全库819PASS22旧内核opt-in跳过/vet通过；另有消费者旧pin三叶RED。没有外部客户端复制或新算法/报价/运营商分支，MIT/module/unknown来源不变；A04并发MID/全SA replay/证书链/实卡分片和长期不由本项追认，详见[专题](docs/fragment-transactions.md)。

### A04：一次MID分配与显式事务传递

基准`2030fa4`、分支`fix/a04-explicit-mid`。删除发送路径的全局计数推断，一次分配传给原SK/全部SKF/调试状态/window/整组重传；真实并发RED另复现的三处出站状态race只以对应小锁与原NAT timestamp读写同步处理，不新建调度层。原完整性/I-R/MID/FIFO/取消/参数守卫保留；普通/分片CBC/GCM确定性6FAIL1PASS→聚焦9PASS，全库827PASS22旧opt-in跳过/vet通过。来源只RFC7296§2.1/2.3、RFC7383§2.5及原源码/Go标准库，没有外部复制或算法/配置/身份变化，MIT/module/unknown保持。新Session编号复用不当并发IKE rekey旧pending退役/整Session线程原子性或实卡长期保证，见[专题](docs/message-id-transactions.md)。

### A06：通知P/S、方法MAC、结果协商与重放

基准`9661242`、分支`fix/a06-eap-notification`。依据RFC4187§6.1/6.2/9.10/9.11、RFC5448方法MAC，真实网络入口严格阶段/原字节MAC/TLV/一次通知及缓存所有权，失败正确ACK后终止不回身份，成功绑定AT_RESULT_IND与终态Identifier；已完成方法上下文的fast通知加密counter绑定。首次编译前置失败不计RED，原pin同字节只读overlay19FAIL2PASS→独立矩阵/正常Connect成功与失败ACK绿色，全库855PASS22旧opt-in跳过、后继swu677PASS及最终聚焦31PASS/vet通过。没有外部复制、运营商分支/算法降级，MIT/module/unknown不改；完整Fast Reauth与A05 Prime KDF/实卡通知/长期仍未验收，详见[专题](docs/eap-notifications.md)。

### A07：AUTH共包统一应答与认证前隐私

基准`ed8349d`、分支`fix/a07-auth-copayload`。按TS24.302 V18.7.0 §7.2.6/8.2.9.2先验证本轮全部载荷/请求格式，成功方法MAC后统一组合EAP/设备应答；两码/独立与共包一致，早期/错误/重复/无身份拒绝，不制造零身份或SV补零。新矩阵19FAIL3PASS→聚焦60PASS、一次库880PASS22旧opt-in跳过1既有缺口预期FAIL，保留原非法请求/metadata/privacy并加强为拒绝/SIM0/无应答后swu701PASS/vet。无客户端复制/特判/降级，MIT/module/unknown保持；实卡共包/PKI/完整Fast/Prime/长期未追认，详见[专题](docs/auth-round-copayloads.md)。

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
