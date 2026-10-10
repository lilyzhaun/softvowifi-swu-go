# IKE 接收边界（2026-10-11）

负责人 `lilyzhaun`，分支 `fix/a01-receive-validation`，基准 `094d484`。
本切片修接收先消费/改状态后校验的问题，不增加运营商分支、报价、身份覆盖或失败降级。

## 当前规则

- UDP 保留报文来源但不自动锁 IP、跟随端口或发布 NAT 变更；生产 Session 在接收线程启动前选择 envelope 通道。
- SA_INIT 单独执行原请求绑定的严格 decoder；未认证的响应只允许原目标端口。合法 COOKIE 保留正常重试，结构非法包丢弃并保留原 pending。
- 已报价完整套件被误编号的既有类型提示只交给 Connect 终结旧会话，不接受原 SA 或提交其端点；全新 Session 的单报价兼容保持。
- 后续响应先绑定在途 exchange/MID，再核对当前 SA 的 SPI、角色、精确长度、SK/SKF 结构及完整性，最后提交端点、完成窗口和更新活动时间。坏包不能消耗请求、推进队列、改变 SPI/端点/活动时间；晚到或无主响应不存入 `ikePending`。
- 已激活控制循环只接收受保护 INFORMATIONAL / CREATE_CHILD_SA 请求；移除依赖固定长度和错误方向位的 DPD 快路，合法空探活仍即时确认。
- 单独解析器不再接受明文最终 AUTH，也不在认证前写 SPI。短 SK/SKF、截断/零长度/未终结链、尾随数据和未知 critical 载荷明确拒绝，未知 noncritical 仍保留。
- 当前 SA 的 I 位及 SK_e/SK_a 方向跟随建立者，而非本条请求发起者；对端发起 IKE rekey 后本端为 responder，本端下一次发起 IKE rekey 后恢复 initiator。

## 同边界补充

独立 AES-GCM-16 peer 证明旧 SK/SKF 仅认证 IKE header，漏掉 generic/fragment header，且 AEAD 缺 Pad Length。
按 [RFC5282 §3/§5](https://www.rfc-editor.org/rfc/rfc5282) 与 [RFC7383](https://www.rfc-editor.org/rfc/rfc7383)
补齐 AAD 和必需的 Pad Length；CBC 的线格式不变。分片 builder 先复制当前明文片，避免 padding 覆盖下一片。
没有新增/弱化算法，没有宣称 GCM-8/12 或实卡 GCM 已验收；这不是扩展协商能力。

## 验证与限制

直接 RED → GREEN 覆盖明文 AUTH、短 SK、错 SPI/方向/长度/ICV、外国 exchange 完成窗口及 keepalive 改端口。
新增独立标准库 CBC/GCM peer、正常 UDP envelope、无效包后合法包完成同请求、队列/端点/liveness 不变、合法 DPD 和两种实际 IKE rekey 角色切换。
旧认证、拒绝、Child 内核失败、FIFO/取消及首 AUTH 密码断言全部保留；只将旧同端 wrapper / 明文 peer fixture 改为合法对端。
未知 critical SA_INIT 由“终结会话”改为“丢弃且保留 pending”，仍断言无 AUTH/无 SA 提交。

此切片只保证逐包验证边界。完整多片事务/首片类型/缓存代次与回收、并发 MID、Child/CP/TS 原报价绑定、EAP/AKA′、完整证书链和外层选网仍是独立未完成项。
完整分片响应尚不能据单片 MAC 成功当作握手可用；不把非特权主机回归当运营商、Android 内核或长期验收。
来源仅核对上述 RFC，独立 peer 用 Go 标准库，无外部实现复制；原 MIT/版权/module 及 unknown 上游归属保持。

最终聚焦 54 个 PASS 事件，全库 race/shuffle/count=1 为 688 个 PASS、22 个既有隔离内核 opt-in 跳过，6 个测试包通过、2 个包无测试文件；全库 vet、gofmt 与空白检查通过。
首次全回归中旧假对端被新守卫拒绝的失败已保留，不能把其当运营商回归结果。库 PR 之后的主仓集成/设备证据另记，不预报成功。
