# AUTH轮次的EAP与设备身份组合

负责人`lilyzhaun`，分支`fix/a07-auth-copayload`，基准`ed8349d`。
TS24.302 V18.7.0（2025-01）§7.2.6/8.2.9.2要求请求Identity Type为1/2、值为空，
网络认证成功且设备身份可用后才回复。先读取全部本轮载荷与错误/重复/设备请求格式，
再处理EAP并确认成功验证方法，统一组合回应，不让Connect的EAP continue吞掉Notify。

正常Connect保留最初标准八载荷/不主动发送身份；独立及共包两种Notify code都经过同一入口。
错误MAC/诊断跳过MAC、Identity之前请求、错误终态/重复EAP/重复设备请求/非空值/坏长度/
缺设备身份均无设备应答，坏请求在SIM之前拒绝；Notification失败只发原ACK、不附设备身份。
设备builder仅使用配置或原IMEIProvider真实可用的15/16位十进制非零身份，优先可用IMEISV，
否则IMEI，不制造全零身份/SV补零/截取坏值。原明确请求码/独立TBCD golden和隐私断言保持。

## 证据

- 新矩阵原pin19FAIL/3PASS，聚焦60PASS；直接证明两码/两顺序/独立、负向与失败ACK，
  真正独立UDP共包Challenge→EAP+Notify→原独立最终AUTH/Child通过，无SIM/MAC降级。
- 一次库复核880PASS/22旧内核opt-in跳过/1FAIL，无race；原日志UDP测试故意断言“只回EAP
  保留已知缺口”，输入是带私密标记值的非法请求+重复空请求。保留同输入/所有元数据与隐私
  断言，改为更强的整轮拒绝/SIM0/UDP无回应，而非删除/弱化失败；补整个swu701PASS/vet。
- 主仓原审计空41101缺规范type前提，补标准Length1/type1后原缺回复断言不变。
  真实维护CI/后继主仓pin、规范候选及普通实机分别登记，不提前报完成。

来源：官方ETSI TS124302 V18.7.0
https://www.etsi.org/deliver/etsi_ts/124300_124399/124302/18.07.00_60/ts_124302v180700p.pdf
（旧V17.5.0链接下载403，未当新核对证据）；只比较规范与原源码/Go标准库，无客户端复制，
MIT/module/unknown不变。PKI证书链、整个EAP线程原子性、INFORMATIONAL身份路径、
完整Fast/Prime、实卡共包/长期独立，不由本轮通用修补追认。
