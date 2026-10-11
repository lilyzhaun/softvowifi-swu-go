# EAP-AKA′全Challenge标准派生

负责人`lilyzhaun`，分支`fix/a05-aka-prime-kdf`，基准`b0d1d4b`。
来源为RFC5448§3.1/3.2/3.3/3.4.1/AppendixC及原维护代码、Go标准库。
https://www.rfc-editor.org/rfc/rfc5448
没有客户端代码复制/运营商特判/算法降级，MIT/module/unknown不变。

## 边界

- 原网络入口精确EAP/TLV、有序AT_KDF列表/mandatory RAND/AUTN/MAC/KDF_INPUT，重复与
  未知mandatory拒绝；网络名非空UTF-8/actual length精确，不猜WLAN，不规范化原MAC字节。
  AMF分离位必须1，合法结构与实际已发送Identity在SIM之前确认。
- 支持KDF1；第一优先项不支持但列表有1时只回复AT_KDF1，不调用SIM。后继必须且只能
  前置选中值并保留原有序列表，只有该协商来源的重复值合法；后续/同步保持同列表。
  单一上轮请求/回应独立缓存确认相同重传、SIM不重复，reset清空；不能静默退回Type23。
- CK′||IK′按FC0x20/原网络名与AUTN前6字节派生；IK′||CK′作为PRF′key，
  ASCII`EAP-AKA'`与实际已发送Identity作为seed，直接复用标准`crypto.PrfPlus`208字节。
  删除SHA256(Identity||IK′||CK′)再seedless扩展的错误路径，不改原IDi或凭SIM猜新身份。
- Type50请求与回应必须HMAC-SHA256-128，即使diagnostic bypass字段存在也不跳过MAC；
  原字节校验后构造RES/可选RESULT_IND/MAC响应，不主动加ANY_ID_REQ或无依据KDF回显。
  完整响应后才提交MSK/方法上下文，错MAC/身份/结构不提交，错误不带calc/recv或SIM私密值。
- 同步失败回应保留Type50/AUTS14与本次KDF列表；不能当网络已认证。Type50不是Type23的
  fast KDF/cache，删除错误的Type23 fast数据保存/回调；完整Type50 fast仍明确不支持。

## 公开参考与真实路径

RFC5448 AppendixC四组公开输入与完整208字节key slices是固定oracle，独立标准HMAC
参考逐组匹配全部原文结果，再证明生产所有key slices及真实handleEAP请求/回应MAC；
没有用生产派生器生成对端挑战。PUBLIC测试向量不是真实SIM或订阅私密材料。
独立首矩阵20FAIL4PASS→GREEN，正常UDP Connect使用公开Case1/实际原IDi，
无/有RESULT_IND→Type50成功通知→独立最终initiator/responder AUTH/Child均通过。
正常Connect旧pin同字节只读overlay1FAIL（无合法Prime应答/UDP超时）保留，非编译/fixture
失败；新增纯函数helper在旧pin不存在，只有该新增helper测试从baseline overlay移除，
真正Connect和独立peer同字节保持、无源码/缓存覆盖或worktree。

单次库933PASS22旧内核opt-in跳过7FAIL（6个旧Type50 SIM坏长度叶+父节点）；旧输入只有
Type23改type50/跳过MAC，缺mandatory KDF/网络/AMF/实际Identity而提前拒绝。只补标准
输入及已发送Identity、去掉skip flag，原错误文本/一次SIM/无keys/输入所有权/隐私断言
不改，防止阶段门禁遮蔽坏长度守卫。旧diagnostic Prime错误oracle改为公开向量校准的
独立参考，原metadata/privacy保持、Type50不得缓存Type23的断言加强。
补“同步后同合法重复KDF列表”先1FAIL再修正，仅整个swu最终761PASS/vet；不伪报
重复主机全库。真实最终维护CI/主仓pin/门禁/规范候选/普通设备分别登记，不提前报通过。

完整Type50方法Identity/永久NAI前缀选择与CHECKCODE扩展、快速重认证/可选假名解密
消费、PKI/访问网本地名称策略和Type50实卡/长期仍不由本轮全Challenge派生追认。
RFC5448§3.1本地名称比较为MAY；此处只用收到的合法非空原名称，不猜实际承载来源。
普通Type23实机回归不是Type50运营商验收或整个EAP支持保证。
