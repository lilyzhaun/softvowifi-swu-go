# AUTH错误与标准BACKOFF_TIMER

负责人lilyzhaun；分支`fix/a08-auth-backoff`；基准`3c279f1`。
TS24.302 V18.7.0 §7.2.2/8.2.9.1与TS24.008 V18.5.0 §10.5.7.4a明确：
41041是状态型，NotifyData为Length1+GPRS Timer3值，不是四字节秒数。

## 边界与行为

- AUTH EAP循环、post-EAP与最终响应共享错误/timer扫描；timer须唯一、格式/协议/SPI合法，
  与**单一错误终态**及已成功验证的方法绑定。认证前、timer独立/重复、多个错误、旧4字节、
  未知状态或坏值不得产生接受的deadline；没有放宽所有status Notify。
- 普通unit0–5为10分钟/1小时/10小时/2秒/30秒/1分钟，值为低5位，准确支持零和最大31。
  unit7是停用，不是0或默认60秒；unit6的320小时只适用列明的扩展周期IE，不套用Tw3。
- 零允许按原supervisor立即重试；非零沿现有sleepCtx等待且能取消。停用为带明确字段的
  本轮NoRetry，Error不冒充账户或认证永久失败；不能通过重启引擎重置本轮等待来伪报验证。
- 保留原错误码。NETWORK_FAILURE10500不猜为永久认证失败；NO_APN_SUBSCRIPTION9002
  有自己的Tw3规则。旧误命名导出常量数值保留、增加正确别名；有限timer不弱化其他原永久
  拒绝。旧四字节/默认60测试改为标准编码/无猜测，10500移到明确Transient断言，不删测。
- 最终有Child的包仍先验证responder AUTH再处理错误/timer，非法包不提交Child/通知/ticket。

## 实际证据

独立literal单位/零/停用/结构/阶段/错误关联及真正Connect标准MAC+受保护timer矩阵
原pin27FAIL2PASS→96PASS（含原通知/共包/最终守卫），一次全库911PASS22旧内核opt-in
跳过、无FAIL/race；最后补多错误歧义拒绝，仅受影响35PASS/vet/格式。原失败证据保留。
主仓实际旧pin的factory→UDP→Supervisor通过固定合成AKA Challenge/MAC前提后，
finite/zero/deactivated均误判FATAL（10500 AUTHENTICATION_FAILED），新组合4FAIL；
加原分类器标准30秒输入后5FAIL。没有SIM错误、fixture或编译失败冒充行为RED。

主仓peer复用自身CBC/标准HMAC与原SA_INIT骨架，固定合成K_aut由维护base3c279f1
`aka_reference_test.go`的独立参考取得（已核RFC4186 A.5），不调用生产EAP KDF/encoder
作为对端oracle。此MIT维护项目来源是https://github.com/lilyzhaun/softvowifi-swu-go，
没有其他客户端复制；MIT/module/unknown不变。CI/真实pin/主仓GREEN/候选与获授权普通
设备尚待，不能把matrix或本轮停用状态提升为跨进程持久Tw3策略/完整错误码/长期运营商验收。

规范原文：
https://www.etsi.org/deliver/etsi_ts/124300_124399/124302/18.07.00_60/ts_124302v180700p.pdf
https://www.etsi.org/deliver/etsi_ts/124000_124099/124008/18.05.00_60/ts_124008v180500p.pdf
后者普通curl403，浏览器UA正常下载原文；未将403/未读取版本当来源通过。
