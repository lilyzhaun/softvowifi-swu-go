# 初始 Child SA / CP / TS 事务（2026-10-11）

负责人`lilyzhaun`，分支`fix/a02-child-selection-commit`，基准`97d4d31`。
这是系统性整改A02，不追加运营商分支/算法/身份覆盖，不调整原六套AUTH1报价或CP/TS请求。

## 规则与来源

- AUTH1保存本次原CP/SA/TS的独立序列化快照，返回的builder对象不能修改它；新认证代清空快照。
- 受保护最终报文先验证responder AUTH但不保存IDr，再验证唯一SA/CP/TSi/TSr、原单套ESP编号/精确4字节非零SPI、全部变换与属性。不跨套件拼接，不凭算法“支持”代替“报价”。
- 原报价明确NO_ESN；按[RFC7296 §3.3.3](https://www.rfc-editor.org/rfc/rfc7296#section-3.3.3)的ESP mandatory ESN校验，不假设省略即NO_ESN。原CBC需原INTEG、原GCM-16不接受额外INTEG/GCM-8/12、初始报价无额外DH/KE。变换重排合法。
- CP须是CFG_REPLY，与本次CFG_REQUEST一致；分配地址数不超原请求数，IPv4严格4字节、IPv6严格17字节/合法prefix，已消费DNS/P-CSCF字段不截取畸形多余值。允许双栈请求只分配一族，至少须有一个合法地址。
- [RFC7296 §2.19](https://www.rfc-editor.org/rfc/rfc7296#section-2.19)允许返回未请求附加属性：不一概拒绝，不消费未知格式。netmask等已知属性保持规范单值/长度规则。CP的高位是reserved而非Transform AF，接收忽略但仍按TLV解码（§3.15.1）。
- TSi/TSr非空、范围/port有序，属于原请求的同族/协议/port/地址子集；TSi须与本轮分配地址相交，不接受外国内层host/family。SA/proposal/transform和TS解码必须精确闭合，不静默忽略尾随字节或错误链。
- 全部检查和密钥派生先在局部完成，再逻辑事务提交双向Child/CP/TS/算法/IDr/通知；没有失败路径或外部回调能观察部分提交。ticket回调最后调用，参数独立复制，不改内部ticket/SK_d。合法redirect仅返回类型提示、不提交Child/ticket；有其他畸形通知时不提前应用redirect。

## 测试与边界

- 直接测试先41个FAIL事件，包括非法选择/缺CP/坏TS/通知、六个合法回调观察到半提交和builder快照别名；修复后这些行为转绿。
- 独立CBC/HMAC受保护对端与独立responder AUTH，覆盖原六套/双栈/部分地址族/未请求可忽略属性/变换重排及请求范围收窄；旧AUTH/Identity/拒绝/COOKIE/编号/内核/FIFO测试保留。
- 旧认证fixture的CBC256对应原proposal3并显式NO_ESN；旧最终包补齐实际请求的CP/TS，不通过关校验变绿。新畸形测试直接用完整基线独立peer再突变，不走补齐helper，避免遮蔽缺字段。
- SA/TS精确闭合和CP reserved-TLV的额外直接RED保留；旧真实UDP Identity→AKA→双向AUTH完整链仅补原本缺的合法最终CP/TS，原密码/身份/终态断言保持。
- 这不认证整个协议栈。完整分片事务/并发MID/EAP/AKA′、rekey/PFS、证书链/外层网络仍独立未完成；非特权库测试不当Android内核/运营商/业务或长期验收。主仓须真实pin/标准构建及获授权设备一次正常路径。

来源仅RFC7296/RFC4303/Go标准库与现有维护源码，无外部客户端代码复制；原MIT/module/unknown上游归属保持。

最终受影响swu/ikev2两包race/shuffle/count=1为594PASS、0失败/0跳过；先前一次全库750PASS、22既有隔离内核opt-in跳过，6测试包通过/2包无测试文件。新增最后回调复制/合法key长度及CP先于SA直接RED→GREEN后仅重跑受影响包，不冒称重跑全部库。对应vet/gofmt/diff空白通过，主仓/设备结果待后继记录。

## 后继：静态拒绝分支诊断

主仓真实pin/正常构建后首个小米13原配置短验被`invalid initial Child SA transaction`拒绝，已stop/清理，不能由受保护完整载荷已解析判哪一规则失败。
在基准`3648adc`的`fix/a02-reject-reasons`只为原拒绝加固定不变量名称（原请求/编号/变换/CP类型与长度/TS绑定等），保持相同`errors.Is`和全部接受/拒绝条件，不加入运营商/安全降级。
错误文本不带身份、IP地址、配置值、密钥或payload。四种合成拒绝的分支准确性/无私密值先RED后GREEN；真实根因仍待后继标准候选的新证据，不能用这个文档预报结果。

后继标准候选实际确认拒绝在TSi与CP分配地址绑定，尚未知道是响应族未分配还是具体host范围不符。再仅细分静态`IPv4/IPv6 without allocation`与`outside allocation`，不带地址值/数量或更改任何条件；独立合成细分类先RED后GREEN。不得据通用分支名猜放宽任何规则或宣称卡已恢复。

## 后继：部分地址分配的有效交集

`171bdb5`后的标准路径证据明确定位`IPv4 without allocation`：CP只分配IPv6，但TSi保留原双栈请求中的IPv4族。先前逐个TSi要求有分配地址的规则会过度拒绝整笔事务。
依据[RFC7296 §2.9](https://www.rfc-editor.org/rfc/rfc7296#section-2.9)和[§3.15.4](https://www.rfc-editor.org/rfc/rfc7296#section-3.15.4)，在分支`fix/a02-partial-address-families`保持原全部SA/CP/TS结构、报价子集检查后，仅保存与实际分配地址及双向TS族/协议共同匹配的有效运行配置；未分配族不成为运行态TS/CP服务器/策略/路由。不改原请求或原配置，不猜另一个地址/算法，不以删测绕过已有已分配外国host约束。

没有有效双向族、已分配族地址不匹配、未使用族的坏范围/越原请求或不兼容协议仍拒绝且不提交ticket/Child。初始XFRM只为有效族安装原mandatory ESP模板，IPv6策略失败不再仅告警后伪报可用；后继换钥同样不得重装未分配族。旧双栈重键fixture明确原协商CP/TS前提，原失败传播/回滚/算法/方向断言保留。

本项只约束有效**地址族**，保留既有族内broad XFRM策略形式；任意TS地址/端口的精确内核编译、完整rekey/PFS安全性和自然换钥仍不是本项完成声明，需独立审查。直接合成部分分配正向/无效族负向、初始策略builder、真实换钥安装接口与网络配置入口回归，先5FAIL/6PASS，再swu590PASS；一次全库770PASS/22既有内核opt-in跳过，0FAIL/无race，vet/格式通过。后继主仓真实pin/构建和正常设备路径仍待验证，不能提前把协议修正当运营商恢复。
