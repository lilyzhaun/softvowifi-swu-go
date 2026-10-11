# 下层网络socket控制与外层XFRM路由

负责人lilyzhaun，分支`fix/a09-network-binding`，基准`5bb43ce`。
本维护切片只提供消费者的实际选网接线，不宣称完成Android来源/网络丢失或实机。

- `Config.SocketControl`显式进入正常Session的DNS dial与outer UDP listen，传入上下文，
  创建socket之前执行控制。选网下缺显式DNS拒绝，不走system resolver；DNS与本地地址
  同族，TCP/UDP均使用同控制器，IPv6 JoinHostPort，解析与listen失败不改到默认网络。
  只有真实EADDRINUSE可沿同控制器换本地端口，旧nil入口兼容。
- XFRMI建SA前从已绑定socket读SO_MARK，出站SA使用精确OutputMark全mask；不写入
  state.Mark/入站selector/ownership identity。Child rekey保留同输出mark，入站不加。
  认证新轮重置mark，nil旧入口保持无输出mark；没有猜Android netId或新增全局路由规则。
- 原pinConfig缺控制入口2FAIL→socket/DNS聚焦10PASS；新增路由mark测试1FAIL→
  从实际受控socket读取、driver输出/身份保持与Child rekey/旧失败回滚聚焦22PASS。
  一次库947PASS22既有内核opt-in跳过/0FAIL/无race，vet/格式通过。没有关闭密码或设备
  身份/请求窗口/Child守卫，无外部客户端复制/特判/降级，MIT/module/unknown保持。
- 首DNS fixture未剥EDNS附加字段，独立question修正后GREEN，失败证据保留；不当生产
  网络失败或用fixture错误冒称原协议RED。上层真实Android handle/interface/source/DNS、
  网络丢失取消/PANI与规范CGO候选仍须主仓接入/验证，尚无A09设备操作。

来源仅Go标准库net ListenConfig/Dialer Control、LinuxSO_MARK/XFRM OutputMark现有
netlink能力和原代码；Android消费者计划用官方NDK `android_setsocknetwork`，不复制
私有fwmark协议。参考：
https://pkg.go.dev/net#ListenConfig
https://pkg.go.dev/net#Dialer
https://developer.android.com/ndk/reference/group/networking
