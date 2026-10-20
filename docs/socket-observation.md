# 仅观察的 socket 事件

## 任务登记（2026-10-20）

- 负责人：`lilyzhaun`；GitHub 实际登录与现有 Git 身份均已核对，未修改身份。
- 分支：`feat/typed-socket-observer-20261020`。
- 基准：`6b13b1761458902e4e23e7a08a2e8c754c7de487`（当时 `main` / `origin/main`）。
- 文件范围：`pkg/ipsec/socket.go`、新增 socket 直接回归、
  `pkg/swu/config.go`、`pkg/swu/session.go` 的构造传递及本说明。
- 设备需求：无；不改消费者 pin、产品版本或 Release，不进行设备操作。
- 编译权：主任务已交接唯一 Go 编译权；本任务以 `GOMAXPROCS=2`、`-p 1`
  串行验证，不启用隔离内核 opt-in 测试。

## 范围与许可

维护项目：<https://github.com/lilyzhaun/softvowifi-swu-go>；基准版本如上。
原 `LICENSE` 的 MIT 文本及 `Copyright (c) 2026 iniwex5` 不变。
实现仅借鉴仓库已有代码与 Go 标准库公开的 `net.Resolver.Dial`、
`net.Conn`、`net.PacketConn`、`net/netip` 和 `errors.Is` / `errors.As` API，
不复制外部客户端代码，不新增依赖，不填补原始上游版本 unknown。

本项仅补真实 DNS I/O 的本进程类型化观察，不调整 DNS 选择、回退、超时、
地址族、错误返回、协议字节、解析、鉴权、IKE/IMS 参数或重试。
主仓负责即时 HMAC、脱敏持久化和取消首因；库不写观察日志、不发送遥测。
本地回归与 CI 不代表运营商、Android 或长期业务验收。

## 公共接口与语义

- 新入口 `ipsec.NewSocketManagerWithObserver(ctx, local, remote, dnsServer,
  control, sourceIP, observer)`；原 `NewSocketManagerWithSource` 签名不变，
  委托新入口并传 nil。`swu.Config.SocketObserver` 进入正常 Session 构造及
  原有 `EADDRINUSE` 换本地端口分支；自定义 `TransportFactory` 仍由消费者持有。
- `SocketObserver func(context.Context, SocketEvent)` 同步调用、可能并发，须快速返回。
  回调绑定原调用者 context；标准库 resolver 的内部 context 只供原 Dial 使用，
  不调整其生命周期、取消或 deadline，不从调用者取消状态推断底层错误。
- `SocketEvent` 只有 `Role`、`Phase`、`Result`、`Remote netip.AddrPort`、
  `Source netip.Addr`、`Bytes int`、`Cause`；角色为 DNS/Outer，阶段为
  Dial/Write/Read，结果为 Started/Success/Failure。Cause 通过 `errors.Is/As`
  分类为 None/Canceled/Timeout/Closed/Permission/Refused/Unreachable/
  AddressInUse/AddressUnavailable/Other，不包含原 error 或字符串。
- Dial 的 Started/Failure 只使用实际传给 Dial 的显式数字端点，不使用
  `Resolver.Dial` 的 system-resolver 占位参数；成功后取底层连接实际远端与本地源。
  未绑定源或未知端点保留无效地址。族从有效 `netip.Addr` 获取，不猜测。
  Outer 的 Dial 指原 `ListenPacket` 创建，不声称已经联通远端。
- 每次原 Write/Read 调用返回后才观察，返回值和 error 原样返回；零字节无错误
  不报成功，错误带有实际 n 时仍报 Failure。Read Success 只表示收到正字节，
  不是 DNS 答案、协议解析、认证或对端身份成功。outer Read 在原解析/过滤前观察，
  不改变接受条件，且不声称覆盖内核 XFRM offload 流量。
- DNS 观察包装按底层能力保留 `net.PacketConn`，避免 Go Resolver 错选 TCP framing；
  不读取、拦截、复制或解析协议内容。旧 nil 路径不创建包装，无队列、监控或重试。
  观察层不额外留存地址；消费者须在回调中即时 HMAC 后才记录，不能记录完整事件地址。

## 直接回归

API-only overlay 保留原基准运行逻辑及返回，只增加可编译的类型与纯委托入口。
原路径在真实 IPv4/IPv6 loopback 受控 DNS 正常解析、UDP question 校验与 TCP
截断回退通过时，缺 Dial/Write/Read、失败分类及正常 Session 观察，形成行为 RED，
不是用接口缺失的编译错误冒充 RED。原测试未删除、改断言或弱化。

新增 `pkg/ipsec/socket_observer_test.go` 与 `pkg/swu/socket_observer_test.go` 覆盖：
实际 DNS 端点/源、UDP/TCP framing、启用/关闭同解析结果、错误返回与 unwrap
行为不变、拒绝/超时/真实发送后取消无 response-success、固定 errno 分类、未知
端点/未绑定源不猜测、outer UDP 原字节收发及关闭错误、Session context 与占用
本地端口后的原有重试传递。

首轮测试前提纠正保留在本地证据：Go Resolver 将普通底层错误重包装为
`DNSError`，不保证底层 sentinel 的 `errors.Is`；原返回比较据其实际公共字段和
unwrap 行为完成。Resolver 还可能在调用者结束后等原生 Read deadline；测试
有界等待该真实结果，而非修改生产超时或凭 parent.Err() 生成失败事件。
初始与纠正后的 RED、首次实现失败和后续回归日志均保留，不以错误前提当实现 RED。

最终本地验证（Go 1.26.0，`GOMAXPROCS=2`、`GOFLAGS=-mod=readonly`，全部有界）：

```sh
go test -p 1 -race -shuffle=on -run '^TestSocketObserver' -count=1 -timeout=90s ./pkg/ipsec ./pkg/swu
ISSUE33_KERNEL_TEST=0 SOFTVOWIFI_REQUIRE_NETNS=0 go test -p 1 -race -shuffle=on -count=1 -timeout=120s -json ./...
go vet -p 1 ./...
```

聚焦两包通过；一次全库 7 个测试包通过、1230 个通过事件、26 个既有隔离内核
opt-in 测试/子例跳过、0 FAIL/无 race，另 `pkg/sim` 无测试文件；全库 vet、
改动文件 gofmt 和 diff 空白检查通过。PR 的真实 CI 终态与绑定最新 head/base 的
COMMENT 自审另留于该 PR，不用本地主机通过替代 CI、设备或消费者 pin 生效。
