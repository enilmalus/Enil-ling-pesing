# EmpireCMS（帝国 CMS）单域渗透方法论（2026-09 实战沉淀）

> 来源：某新闻媒体集团 CMS 后台主机的授权渗透（EmpireCMS 7.5 深度定制版，五轮测试，中5低5信息1）。本文件是**方法论提炼**，目标标识、账号、内网地址已脱敏。命中 EmpireCMS（`/e/` 目录结构、`e/admin/ecmsadmin.php`、后台登录失败文案「您的用户名、密码或安全答案有误」（源码锚点 `e/class/adminfun.php` 的 `LoginFail`，前台会员登录是另一条文案「您的用户名或密码有误!」）等指纹）时按 §1-§7 过一遍。

**核心思路**：EmpireCMS 是**开源可下载**的国产 CMS——先下 stock 源码做白盒对照，把黑盒行为与源码逐点比对，能快速区分「stock 就有的面」与「定制新增/删除的面」。大量负向结论可以**用源码审计一次排除**，省掉多轮发包实测；省下的时间花在定制改动的差异点上。

---

## 1. stock 源码白盒对照法（本方法论的骨架）

1. 官方渠道下载对应版本源码（确认指纹后：报错文案、`/e/` 目录、cookie 命名前缀）
2. 黑盒观察到的每个行为回源码找实现：
   - 报错文案原文 → grep 源码定位到校验函数 → 看该函数上下游还拦了什么
   - cookie 名（如 `xxxauth` 前缀）→ `$ecms_config['cks']` 配置段 → 确认定制改动
   - 参数处理 → 入口文件的 `RepPostVar` / `RepPostVar2` / `(int)` 强转调用点
3. 差异点列表 = 定制改动 = **唯一需要重点手工测的面**；与 stock 一致的面按 §3 负向锚点直接记结论

**实测收益**：搜索 SQLi、tags/wap 参数注入、消息 XSS 三类共十余个候选面，全部由源码审计确认被过滤/强转，单轮收口；真正命中的漏洞全部落在定制改动或配置缺失上。

## 2. cookie 伪造链测试（EmpireCMS 专属高危面）

EmpireCMS 的 auth cookie 是**确定性 md5 拼接**（非 HMAC），输入全部是可预测字段 + install 时填入 config.php 的**全局密钥**——密钥若为已知值，cookie 可离线重算。stock 有三层 cookie 验证（源码锚点 `e/class/functions.php` 的 `DoECookieRnd`/`DoECreateOtherRnd`、`e/member/class/user.php` 的 `qGetLoginAuthstr`）：

| cookie | 密钥（`$ecms_config`） | 拼接输入 |
|---|---|---|
| `mlauth`（会员） | `cks[ckrndtwo]` | rnd + 硬编码盐串 + userid + username + groupid |
| `loginecmsckpass`（登录） | `esafe[ecookiernd]` | rnd + IP + UA + userid + username + dbdata + groupid + adminstyle + sessval |
| `otherrndpass`（后台附加层） | `cks[ckrndtwo]` | 前者类输入 + 时间戳 + 每次轮换的随机 otherrndtwo |

**测试方法**：
1. 注册会员拿真实 auth cookie（合法凭据侧）
2. 按源码公式、用候选密钥（stock 安装器占位符、网上流传的常见部署值）离线重算
3. 重算 ≠ 实际值 → **密钥已改**，整条 cookie 伪造面一次排除
4. 相等 → 密钥泄露确认，但注意会员伪造他人 cookie 还需其 DB 内 rnd（每次登录轮换）——继续评估会话固定/rnd 猜测等链路，按证据定级，不直接断言「任意用户接管」

注意两个密钥**独立**（`ckrndtwo` / `ecookiernd`），都要过；密钥在 install 时强制填写，定制部署大概率已改，但历史/偷懒部署复用已知值的情况常见，值得单次验证。配套检查：cookie 名前缀是否 stock 默认（前台 `cks[ckvarpre]` / 后台 `cks[ckadminvarpre]`，install 时填写）——改过前缀说明做过安全定制，其他定制点概率也高。

## 3. stock 负向审计锚点（命中即记「源码确认排除」，勿重复实测）

| 面 | stock 防护机制 | 结论 |
|---|---|---|
| 搜索 keyword 注入 | `RepPostVar2` 剥离 `' " % -- ;` | 排除 |
| 搜索字段名（show）注入 | 模型 searchvar 列表白名单 | 排除 |
| wap/tags/投票模块参数 | `(int)` 强转 | 排除 |
| 消息/留言/反馈字段存储 XSS | 入库侧 `dgdb_tosave()`→`RepPostStr()` 无条件 `ehtmlspecialchars(ENT_QUOTES)`（展示侧 `tool/gbook/` 反而是裸 echo）——防护全压在入库单向转义 | 排除；**反查点：找绕过 `dgdb_tosave` 的 insert 路径，漏调一处即存储 XSS** |
| 消息 IDOR | 收件人归属校验 | 排除 |
| 登录报错用户枚举 | 前台/后台登录报错文案统一 | 排除（**注意注册接口是差分的，见 §4**） |
| 改密码 | 强制旧密码校验 | 排除 |
| 并发会话 | 「同一帐号同一时刻只能一人在线」强制 | 排除（良好项） |
| 管理后台子目录 | 未授权一律登录跳转桩 | 排除 |
| `defined()` 保护的 class/config PHP | 直接访问执行后空响应，无源码泄露 | 排除 |

**FreeBuf 176313（AdminPage.php 后台 XSS）**：需有效后台会话 + ehash，未授权不可达——无凭据时记「建议甲方核对补丁状态」即可，不要反复试。

## 4. 帝国 CMS 高命中面清单（实测漏洞集中地）

1. **后台登录**：stock 默认即无验证码（`adminloginkey=1`，后台设置 0=开启/1=关闭；登录表单 `if(empty($adminloginkey))` 才渲染验证码行、服务端 `if(!$adminloginkey)` 才校验，`ShowKey.php` 基础设施还在但两端均不启用）+ 锁定机制存在但双层可绕（`CheckLoginNum()`：cookie 层 `loginnum`/`lastlogintime` 清 cookie 即绕；DB 层 `enewsloginfail` 表按 `egetip()` 记 IP，默认 `getiptype=0` 信任 `X-Forwarded-For` → 伪造 XFF 换 IP 即绕；stock 阈值 5 次/60 分钟）→ 默认部署实践可无限速在线爆破（最坏 CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5）。检查顺序：无验证码 POST 到达凭据校验 → 保持 cookie 与 IP 连续 6 次失败看第 6 次响应：仍与前面一致 = 锁定未生效；返回「系统限制的登录次数不得超过 5 次」= 锁定生效，再测伪造 `X-Forwarded-For` 换 IP 能否绕 DB 层 → 默认凭据 `admin/admin` 单次
2. **会员注册**：无验证码无邮箱激活 → 批量注册；**无保留用户名黑名单** → 可注册 `admin` 会员名仿冒官方发站内信（与后台管理员表分离，非接管，低危）；**注册接口报错差分** → 用户名/邮箱枚举（登录接口无此问题，只有注册接口有）
3. **开放重定向双向量**（详见 playbooks/csrf-open-redirect.md §2b）：
   - `EcmsGetReturnUrl()` 把 **HTTP Referer 原样写入 returnurl cookie**（仅过滤 XSS 字符、无域名校验），登录成功页 `location.href` 执行 → 攻击者诱导受害者从恶意页访问任意会员保护页即完成植入
   - `DoingReturnUrl()`（stock connect.php:898）各写入动作成功后跳转取 **POST 参数 `ecmsfrom`**，`RepPostStrUrl()`（connect.php:1101）经查无域名校验（仅 XSS 字符过滤），跨站自动提交表单触发
   - 修复锚点：stock `connect.php` 的 `EcmsGetReturnUrl` / `DoingReturnUrl` / `RepPostStrUrl` 三处
4. **留言板 gbook**（stock 默认关闭该模块：安装 SQL `closemods=',error,gb,fb,'`，开着即为部署显式/定制开启）：版面配置 `checked` 字段直接决定入库存展示值（默认 0=无需审核立即公开）+ `gbkey_ok=0`（无验证码）+ 频控仅客户端 cookie（`lastgbooktime`，可清） → 匿名在官方域名下即时发布任意文本（入库转义正确、XSS 排除，但钓鱼话术/仿冒公告不受限）。**测试时注意：提交即公开展示，无法自删，只发一条最小探针**
5. **后台目录静态文件**：定制部署常把操作文档（docx/pdf）放在 `/e/admin/` 下无认证可下载——登录页内嵌链接即入口，内容含内部联系人姓名手机号（社工素材）。扫后台目录时**非 PHP 扩展名单单独过一遍**
6. **会话 cookie 属性**：stock `$ecms_config['cks']['ckhttponly']` 默认 0——有 secure 无 HttpOnly 是常见配置残留（一行修复）

## 5. 定制部署的功能模块矩阵（先确认开/关再分配精力）

EmpireCMS 模块开关是**系统级配置**（`eCheckCloseMods()`），关了就是整面 N/A，别在关闭模块上浪费时间：

| 模块 | 关闭时表现 | 关注点 |
|---|---|---|
| 投稿/空间 space、DoInfo | 跳转提示 | 关 → 上传面直接 N/A |
| 支付 payapi/点卡 | 流程未配置 | 关 → 业务逻辑 N/A |
| 会员 memberconnect 第三方绑定 | 极短响应体 | 关 → OAuth 面 N/A |
| 评论 pl | — | 开 → **服务端强制验证码**是 stock 强项，确认即可 |
| 留言板 gbook | stock 默认关（安装 SQL closemods 含 gb/fb） | 开 → §4.4 |
| RSS e/web | 只读 | 无参数面 |
| e/DownSys、ShopSys、NewsSys | 常被 nginx 403 | 拦截面本身记资产清单 |

nginx 拦截面（`/e/data|config|class|template|api`、`/d/`、点文件）通常已配好——目录扫描确认一次即可，别反复打。

## 6. 全功能点核对矩阵自检法（收尾防漏）

WSTG 12 类对照（`methodology-standards-map.md` §2）之后再加一层**功能点粒度**的终版核对表：把资产清单里每个功能点列一行，每行给三种结论之一——`F#`（漏洞编号）/ `✓`（测过无发现）/ `⏸`（需额外条件，声明是什么）。按入口分组（后台 / 会员 / 动态内容写入通道 / 基础设施与传输）。**每个功能点必须有结论，没有结论的就是漏测**。这个矩阵直接进报告附录，甲方复核覆盖度时一目了然。

## 7. 测试痕迹清单（内容型写入无自删能力的教训）

EmpireCMS 的公开内容面（留言板/错误报告）**提交即入库展示，测试方无法撤回**——与探针文件（可删可 404 确认）性质不同。纪律：

1. 测试前先判每个写入点的**可见性等级**：公开页可见 / 仅后台可见 / 仅入库
2. 公开可见的写入点只发**一条**最小探针，内容带唯一标记（`probe-<日期>`），复现用同一 URL 覆盖参数而非新提交
3. 报告交付时 MUST 附「测试痕迹与账号」附录，按清理优先级排序：**公开痕迹（优先）> 后台可见 > 仅数据库 > 注册的测试账号**，逐条列出内容标记与建议动作
4. 测试账号密码交甲方而非留明文报告；注明登录尝试次数与默认凭据测试次数（自证未做爆破）
