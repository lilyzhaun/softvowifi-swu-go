# EAP Notification阶段、完整性与回应

基准`9661242`、分支`fix/a06-eap-notification`。按RFC4187§6.1/6.2/9.10/9.11
修复原16384失败码被当身份请求及认证后通知不验输入MAC；没有运营商分支或算法降级。

## 网络入口与事务

- P=1只能在Challenge/Reauthentication之前表示失败，必须无MAC；P=0只在已验证的
  方法轮次之后，必须验证MAC。跳过Challenge MAC的诊断状态不算已认证通知上下文。
- 16位未知通知码也按P/S位正确ACK；S=0绑定终态失败，不读取IMSI或回Identity。
  普通Connect先送受保护ACK、沿原IKE事务等待响应，然后终止，不能被后续Success逆转。
- 32768成功通知仅在双方已使用AT_RESULT_IND时接受；已协商结果指示不能跳过通知
  直接接受EAP Success，成功终态Identifier绑定通知轮次。
- AKA使用HMAC-SHA1-128/K_aut16，AKA′使用HMAC-SHA256-128/K_aut32，绑定本轮方法。
  MAC覆盖原始收到的EAP字节（含reserved），不重编码输入或泄露MAC/密钥值。
- 单一通知轮次；原相同字节重传返回独立缓存ACK，新的通知/重启认证拒绝。
  request/response与调用者不别名，AUTH身份重置清空通知/密钥状态。
- TLV与EAP长度精确闭合，重复关键属性、坏长度、未知mandatory属性、错误阶段、
  MAC缺失/坏值以及无合法上下文均拒绝，失败不提交通知缓存/结果。

## 快速重认证通知边界

已成功方法轮次的通知上下文保存counter/K_encr；P=0要求AT_IV/AT_ENCR_DATA，先验
输入MAC，再解密AES-CBC counter并匹配原轮次；padding须最后且为零。回应包含同counter
的独立随机IV/加密数据和MAC。缺字段/坏key/外国counter/坏加密数据拒绝，不把缓存K_aut
或当前身份关闭位猜成成功认证。

这里仅修复Notification的计数器绑定。既有Fast Reauth自身明文属性/派生路线仍不是完整
RFC互通，Type50全Challenge KDF仍待A05；直接已完成方法fixture的ACK绿色不追认它们。

## 实际证据与限制

初次新测试有未用导入编译失败，未当RED。修正后原pin三文件同字节只读overlay及新文件
空包取得19FAIL事件/2PASS，不覆盖生产或模块缓存，不建worktree；后继独立通知矩阵与
真正Connect失败ACK/成功通知→最终AUTH转绿。
一次全库855PASS/22既有隔离内核opt-in跳过/0FAIL/无race，后继新增reserved/完整成功
Connect与边界回归仅补整个swu677PASS、最终通知＋原Prime前提31PASS及vet/格式；
最后仅补非法RESULT_IND在SIM之前拒绝的两方法前提与通知聚焦32PASS，不伪报新跑全库。
原MAC/Identity/最终AUTH/Child与窗口断言保持；新增审计前提只明确已验证方法/结果协商，
原坏输入MAC断言不改，避免阶段守卫掩盖审计不变量。

规范候选/主仓真实pin与门禁/一次已授权普通设备短验仍分别登记，不提前当设备Notification
或真实Fast/Prime/长期验收。来源只RFC4187/5448相关MAC规范与原维护源码/Go标准库，
无外部客户端复制，MIT/module/unknown归属不变。
