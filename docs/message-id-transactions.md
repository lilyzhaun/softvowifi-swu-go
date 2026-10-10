# 显式 Message ID 事务

基准`2030fa4`、分支`fix/a04-explicit-mid`。原发送器在普通构包和分片完成后从
`SequenceNumber.Load()-1`推测窗口MID；加密期间另一请求分配编号会让wire与pending不一致。

## 实现边界

- 每次受保护请求只分配一次MID，显式传给SK构包/全部SKF、出站调试packet/MID、
  window enqueue与既有整组重传；响应仍按原exchange/MID完成，不读取全局计数猜本事务。
- 分片估计返回“不必分片”时，同一个已分配MID用于原SK路径，不多分配或改变算法/报价。
- 两路真实并发发送另复现出站packet/MID与timestamp三字段的数据竞争。只新增对应小锁，
  同步原NAT keepalive读写并保留较新出站时间，旧内核/keepalive时间不覆盖后继请求。
  原间隔、DPD margin、网络/身份/算法/EAP业务不变；不是新的调度或安全子系统。

## 证据

直接普通/分片CBC/GCM用一次加密钩子确定性插入下一编号，均因window错配失败；真实两
goroutine同时发送触发三处race，初始6FAIL事件/1PASS，证据`swu-a04-red-20261011.jsonl`。
修复后MID聚焦与原整组重传共9PASS，无race；单次全库827PASS/22既有隔离内核opt-in
跳过，0FAIL/无race，vet/格式/空白通过。

两路请求的原wire MID分别对应pending，倒序响应只完成自己，外国MID不消费任何请求。
新Session/SA复用编号时旧SPI响应被拒绝，当前原合法响应能完成新请求。原A01/A03的
SPI/角色/窗口/FIFO/重传/取消/分片与IKE角色切换守卫全部保留。

这里的代次测试是**新Session/SA的编号复用**，不冒称并发IKE rekey时所有旧pending
的退役/旧SA保留或整个Session密码与内核状态的线程原子性；这些生命周期边界仍须独立
审查。计数溢出、完整rekey/PFS/证书链/自然窗口/实卡并发也没有本项验收声明。
后继真实pin/主仓集成/规范构建及已授权普通短验仍须分别记录，不能由库测试提前放行。

## 来源

[RFC7296 §2.1/2.3](https://www.rfc-editor.org/rfc/rfc7296)的请求/响应MID与重传契约，
[RFC7383 §2.5](https://www.rfc-editor.org/rfc/rfc7383)的共享分片MID，原维护源码与Go
标准库独立peer；没有外部客户端复制，MIT/module/unknown上游归属保持。
