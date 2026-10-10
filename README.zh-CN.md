# softvowifi-swu-go

[English](README.md) · **简体中文**

公开维护的Go SWu客户端库：以IKEv2和调用方提供的合法SIM/USIM EAP-AKA接口
建立到ePDG的IPsec隧道，保留`github.com/1239t/swu-go`导入路径。
这是独立维护快照，不是完整上游镜像或官方Release，也不是完整Wi-Fi Calling应用。
IMS/SIP注册、短信投递、语音媒体、Android SIM接线和账户开通不在本库范围。

## 已维护的主要路径

- COOKIE重试首载荷顺序，最终IKE_AUTH拒绝透传。
- 只在已有网关请求路径发送设备身份，不在首AUTH主动附加。
- 初始ESP完整CBC256/SHA2-512报价。
- Child SA换钥/删除的本端入向SPI语义，以及按会话归属回收规则/策略。

详见[来源与维护记录](PROVENANCE.md)、[错误透传](docs/ike-auth-final-reject.md)、
[报价说明](docs/esp-sha512-offer.md)及[身份时序](docs/request-driven-equipment-identity.md)。
源码存在、合成回归通过不等于运营商、完整鉴权或长期验收。

## 必须了解的限制

不能由AKA/最终AUTH处理成功推断完整证书链/信任锚验证已完成。
ticket、fast-reauth、MOBIKE、rekey代码存在不代表所有生命周期、无感切网、
0-RTT或SHA512换钥均已完整验证。未给出跨运营商/设备支持保证。
正常使用不要关闭EAP MAC验证或启用Wireshark密钥日志，不能把导出密钥/降级认证
当兼容修复；请先阅读[安全策略](SECURITY.md)。

## 使用与依赖

Go模块声明1.24.0，CI使用Linux/Go1.26。数据平面需要相应XFRM/TUN内核支持和
网络配置权限。SIMProvider、真实MCC/MNC/APN、上下文生命周期及资源回收由调用方负责；
不要猜MNC位数或复制虚假SIM凭据。

```sh
go mod edit -require=github.com/1239t/swu-go@v0.0.0-20261009235012-6fb3163569ae
go mod edit -replace=github.com/1239t/swu-go=github.com/lilyzhaun/softvowifi-swu-go@v0.0.0-20261009235012-6fb3163569ae
go mod edit -replace=github.com/iniwex5/netlink=github.com/lilyzhaun/softvowifi-netlink@v0.0.0-20260915075719-be8893d91893
go get github.com/1239t/swu-go/pkg/swu@v0.0.0-20261009235012-6fb3163569ae
go list -m -json github.com/1239t/swu-go github.com/iniwex5/netlink
```

主模块不会继承依赖库的replace，必须显式固定netlink；实际导入路径保持不变，
go get实际pkg/swu包会补齐新消费模块所需间接依赖和校验和，仅下载两个归档不足以编译。
上述示例不自动跟随main。英文README给出可编译的真实接口接入辅助函数，
不调用设备、不代填IMSI/密钥；实际Connect会配置网络，不能当无副作用演示运行。

## 测试与协作

```sh
go test -p 1 -race -shuffle=on -count=1 -timeout=120s ./...
go vet -p 1 ./...
```

默认CI只有合成/本地peer测试，不启用ISSUE33_KERNEL_TEST，不读真实SIM或操作手机。
特权回归必须按现有隔离护栏有界执行并回收自己拥有的资源，不能flush其他会话。
仅Shutdown返回不能冒称内核资源已清理，隧道就绪也不等于SIP注册、短信或电话成功。
贡献流程见[CONTRIBUTING](CONTRIBUTING.md)；漏洞私密报告，不提交完整身份/配置、
鉴权材料、短信正文或原始抓包。

## 许可与来源

[MIT原文与iniwex5版权](LICENSE)保持。原始上游commit/version仍为unknown，
不能用本地导入或当前仓地址补造；依赖各有自己的许可和来源限制。
[旧README](docs/README-imported.md)保留作历史，其私有状态、旧路径及完整/0-RTT
宣传不能作为当前安装或能力保证。
