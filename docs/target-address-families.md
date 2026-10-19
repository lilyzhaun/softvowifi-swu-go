# DNS 与外层 ePDG 的独立地址族选择

- 负责人：`lilyzhaun`；基准 `3d754e7b8c42`；分支 `fix/target-family-source-20261019`。
- 只修受控网络连接的本地源地址选择，不改变运营商策略、IKE 报价、身份、鉴权、重试预算、XFRM ownership 或依赖。
- 原模块路径、MIT 原文和版权、unknown 上游归属保持。实现依据 Go 标准库 `net` API、现有维护源码及 [RFC7296 §2.23](https://www.rfc-editor.org/rfc/rfc7296#section-2.23) 的 NAT 检测地址编码，没有复制外部客户端实现或添加依赖。

## 已复现的错误

旧 Session 将固定 `LocalAddr` 同时用于 DNS 和最终 UDP：IPv6 本地源加 IPv4 DNS 会在本地返回 `no suitable address found`；IPv6 DNS 返回 IPv4 ePDG（反向亦然）会被错误筛除；字面 IPv4 ePDG 也可能配上 IPv6 本地源。IPv6 字面 ePDG 的旧字符串拼接缺方括号，实际返回 `too many colons in address`。这些都不是远端拒绝或 UDP 封锁证据。

真实 loopback DNS/UDP 回归在旧代码取得行为 RED，非编译错误。后继独立 SHA-1 检查又证实 IPv6 INIT 的 NAT 源哈希未使用实际外层地址，先 RED 再修正。DNS 错误里的系统 resolver 标签不代表自定义 `Resolver.Dial` 实际拨号目标。

## 最小接口与兼容性

- 可选 `Config.SourceIP(remote net.IP) (net.IP, error)` 由选网持有人提供；DNS 的 TCP/UDP 拨号和最终 ePDG UDP 分别按真实目标调用。未设置仍保持固定 `LocalAddr` 行为。
- `NewSocketManagerWithSource` 在任何流量前保留原 `SocketControl`，无可用同族源或控制失败直接失败，禁止 system DNS/default-network 回退。单个 UDP socket 的候选轮换仅包含其自身地址族。
- 域名保留原自定义 DNS 查询；字面 IPv4/IPv6 不查询 DNS。`net.JoinHostPort` 正确处理 IPv6；NAT 检测按实际 socket 的 4/16 字节地址编码。
- 原取消、端口占用后受控重试、Session 关闭和实际 socket mark→XFRM 传递保持。不把 IKE_INIT 发出视为鉴权、隧道、IMS 或真实业务通过。

## 验证

- 覆盖 IPv4 DNS/IPv6 初始源、IPv6 DNS→IPv4 ePDG、IPv4 DNS→IPv6 ePDG、同族 DNS、双族字面地址、缺兼容源、控制拒绝和取消。
- 真实截断 UDP DNS→TCP 回退验证两族查询仍使用选择的同族源；最终 ePDG 可以是另一族。初版 TCP 测试误把 EDNS 尾部当 question，前提失败已保留并修正测试解析，未修改生产或弱化断言。
- 完整 race/shuffle/vet 终态以本 PR 最终回执为准。Android Network/实机、主仓真实 pin 和正式发布在消费者任务独立验收；本维护库不宣称更早 DNS 超时或运营商业务已修复。

最终一次完整 `go test -json -p 1 -race -shuffle=on -count=1 -timeout=120s ./...` 退出0：1172命名终态PASS、0FAIL、26项既有隔离内核 opt-in 父/子事件SKIP；7测试包通过、1包无测试文件，父子事件计数不是叶数。首尾JSON事件27.521秒，全部257项Go/module输入前后逐字一致；全库vet与diff空白检查通过。独立只读审阅未发现阻断；真实CI与最新head/base COMMENT和正常合并另由PR记录，不把主机结果冒远端成功。
