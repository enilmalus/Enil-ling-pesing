# JeecgBoot（含定制版）管理端越权实战方法论（2026-09 实战沉淀）

> 来源：某产业集团会员中心（JeecgBoot 定制版，包名 `org.<vendor>.modules.*`，API 前缀 `/dview`）的授权渗透。一个**自助注册的普通会员账号**挖出 21 条 findings（严重 1 / 高 3 / 中 9 / 低 6 / 信息 2），其中 4 条高危同根因。
> 本文件是**方法论提炼**，目标标识、凭据值已脱敏。命中 JeecgBoot / JeecgBoot 定制版 / `/dview`、`/sys` API 前缀 / `X-Access-Token` 头约定时按 §1–§10 过一遍。

---

## 0. 一句话核心

**JeecgBoot 定制版最常见的系统性缺陷是：管理端 `/sys/**` 只校验「token 是否合法」，不校验「token 属于哪类主体」。**

一个低权账号（会员/普通用户）即可拿到管理端**全部读写能力**。这不是单点漏洞，是**一条根因的多个侧面**——报告时要合并成一条严重问题，不要拆成 N 条中低危。

**为什么是「严重」而非 `idor-authz.md` 参考的「认证后任意操作 = 8.8（高）」**：聚合影响超出了单一「任意操作」——同时包含 ① **改任意用户密码**（请求体不含旧密码 → 可重置管理员口令 → 完全接管）② 数据库 root 凭据泄露 ③ 56 万条审计日志 ④ 任意表/任意列读取。按 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` 计 = **9.4（严重）**。

---

## 1. 指纹识别（先确认是不是 JeecgBoot）

| 信号 | 取法 | 备注 |
|---|---|---|
| 前端 config 对象 | `GET /_app.config.js` → `window.__PRODUCTION__XXX__CONF__` | 含 `VITE_GLOB_API_URL`（API 前缀）、`VITE_GLOB_APP_SHORT_NAME` |
| API 前缀 | 上一步的 `VITE_GLOB_API_URL` | **以该字段为准**——定制版前缀各异（本次为 `/dview`），不要照搬其他项目 |
| 后端真实 context-path | 错误体 `path` 字段 | 如 `/dview-boot`，网关前缀与后端路径不同 |
| token 头约定 | 前端请求拦截器 | `X-Access-Token`（**鉴权必需**）+ `X-Tenant-Id`（实测**非必需**，去掉仍 200） |
| localStorage key | 前端 bundle grep | `TOKEN__` / `USER__INFO__` / `ROLES__KEY__` / `PROJ__CFG__KEY__` |
| 依赖坐标与版本 | SQL 异常回显的 jar 路径 | 如 `.../apps/xxx-start-3.5.1.jar!/BOOT-INF/lib/...` |
| 内部包结构 | 审计日志的 `method` 字段 | `org.<vendor>.modules.<模块>.controller.XxxController.method()` |

> **源码核对**：定制版包名与官方不同，但**核心工具类通常沿用官方实现**。判断机制（如定时任务如何加载类）时，去 GitHub 拉官方源码逐行确认，**不要凭记忆断言**。官方仓库：`jeecgboot/JeecgBoot`（默认分支 `main`）。

---

## 2. 鉴权可达性判定：GET 探 405（零写入）

**不要直接构造写请求去测可达性。** 对写接口发 **GET**：

```bash
curl -sk "https://target/dview/sys/user/changePassword" -H "X-Access-Token: <低权token>"
# → {"success":false,"message":"不支持GET请求方法，支持以下PUT、","code":405}   ← 接口存在且已过鉴权
# → {"timestamp":"...","status":404,...}                                      ← 路径不存在
```

| 返回 | 含义 |
|---|---|
| **405** | ✅ 请求**已穿过鉴权过滤器到达路由层**，接口对当前 token 开放 |
| 403 | ❌ 被角色/权限拦截 |
| 404 | ⬜ 路径不存在 |
| 401 | ⬜ token 无效/过期 |

**405 非 403 = 无角色校验**——这是判定「管理端越权」的关键证据，且**零写入、零痕迹**。

---

## 3. 管理端接口普查清单（读 + 写必须分开扫）

### 3.1 读接口（先扫，建立基线）

```
/sys/user/list                      员工 PII（姓名/手机/邮箱/工号/userIdentity）
/sys/role/list                      角色表（含「管理员」）
/sys/permission/queryTreeList       完整菜单/按钮权限树
/sys/permission/queryRolePermission?roleId=  角色→权限映射
/sys/tenant/list                    租户表
/sys/annountCement/list             系统公告（内容为 HTML）
/sys/position/list                  职务表
/sys/dict/list  /sys/dictItem/list  全部数据字典
/sys/log/list                       审计日志（★高价值，见 §8）
/sys/dataSource/list                数据库连接配置（★含 root 凭据）
/sys/user/queryById?id=             单用户档案（IDOR）
/sys/common/static/<biz目录>/<文件名>  上传文件的公网下载入口（实测**无需任何凭据**，别漏测）
```

### 3.2 写接口（**必须单独普查，不要只扫读接口**）

> 只扫读接口是本次测试**早期就犯的错误**——直到**单独按写接口清单系统性补扫**，才挖出严重级问题。

```
/sys/user/add  /sys/user/edit  /sys/user/delete      账号增删改
/sys/user/changePassword                              ★改任意用户密码（请求体不含旧密码！）
/sys/user/frozenBatch                                批量冻结
/sys/dataSource/add|edit|delete                       ★新增任意 JDBC 数据源（JDBC 攻击面）
/sys/role/add|edit|delete                            角色增删改
/sys/permission/add|delete                           权限点增删
/sys/dict/add|delete  /sys/dictItem/add              字典增删
/sys/annountCement/add|delete                        公告增删
/sys/oss/file/upload|delete                          对象存储文件增删
/sys/tenant/add  /sys/position/add                   租户/职务新增
/sys/quartzJob/add|edit|delete|resume|pause          ★定时任务（见 §6）
/sys/common/upload                                   文件上传（见 §5）
```

---

## 4. `/sys/dict/queryTableData` —— 任意表/任意列读取（报错驱动发现法）

**发现方法**：该接口**缺参数时报 SQL 异常，把完整 SQL 打出来**。本次测试**早期一直把它当「不可用」跳过**——**报错 SQL 本身就是最好的参数名提示**。

```bash
# 缺参数 → 报错回显完整 SQL，参数名一目了然
curl -sk "https://target/dview/sys/dict/queryTableData?table=sys_role&text=roleName&code=roleCode" \
  -H "X-Access-Token: <token>"
# → ### SQL: SELECT roleName AS "text", roleCode AS "value" FROM sys_role WHERE 1 = 1 LIMIT ?
#            ↑ text 参数          ↑ code 参数        ↑ table 参数（全部来自请求！）
```

补上真实列名即可**读任意表**：

```bash
curl -sk "https://target/dview/sys/dict/queryTableData?table=sys_user&text=username&code=id" \
  -H "X-Access-Token: <token>"
# → {"success":true,"result":[{"value":"<id>","text":"<手机号>"},...]}
```

**要点**：

| 项 | 说明 |
|---|---|
| 参数 | `table` / `text` / `code`，三者**全部字符串拼接进 SQL** |
| 敏感字段黑名单 | 通常存在（`password`/`PASSWORD`/`passWord` 全拦，做了大小写归一化）；`email`/`realname` 等常放行 |
| 注入 payload | 常被**应用层过滤器 + CDN/WAF 双层拦截**（`;select` 被过滤器拦、`union select` 被 WAF 403） |
| 准确归类 | **SQL 注入（参数拼接）**，实际利用形式为**任意表/任意列读取** |
| 纪律 | 最多 1–3 条样本、全部脱敏；**不要尝试绕过黑名单去拖密码哈希** |

---

## 5. `/sys/common/upload` —— 文件上传功能越权

| 层面 | 典型结果 |
|---|---|
| 鉴权 | ❌ **无角色校验**（低权 token 可调，无 token 401） |
| 扩展名黑名单 | ⚠️ **大小写敏感**（`.jsp` 拦、`.JSP` 放行）；`.jspx`/`.jspf`/`.phtml` 常漏 |
| 文件下发方式 | `/sys/common/static/**` 常**无需鉴权**；统一 `Content-Type: application/force-download` + `Content-Disposition: attachment` → **不构成存储型 XSS** |
| 代码执行 | ⚠️ **本次未观察到执行**（文件以附件下发），但**上传目录的磁盘位置未实测**——`jeecg.path.upload` 的取值需向甲方确认后才能下「不构成 RCE」的结论 |
| `biz` 参数 | 原始 `../../` 被拒；URL 编码形式按**字面目录名**存储，非穿越 |
| 删除 | ❌ **无删除接口** → 上传的文件**永久留存**，测试痕迹必须逐条列清单交甲方清理 |

> ⚠️ **时效性**：扩展名黑名单与 WAF 规则**可能随时变化**。本次测试期间 WAF 被逐步收紧（同一扩展名 10 分钟内从「放行」变为「403」），上表为**初始快照**，复测时须重新确认。

> **纪律**：测试前先确认有无删除接口。**无删除能力时，把上传数量压到最小**（每个结论 1 个文件即可），并在报告中列出完整文件名清单。

---

## 6. `/sys/quartzJob/*` —— 定时任务：区分「能入库」与「能执行」

**这是最容易误判的一条。** 看到「`jobClassName` 无白名单校验」不要直接下「RCE」结论——**先拉源码确认执行机制**。

官方实现（`QuartzJobServiceImpl`，**GitHub main 分支**）：

```java
JobDetail jobDetail = JobBuilder.newJob(getClass(jobClassName).getClass())...;
private Job getClass(String classname) throws Exception {
    Class<?> clazz = Class.forName(classname, true, Thread.currentThread().getContextClassLoader());
    return (Job) clazz.getDeclaredConstructor().newInstance();     // ← 强转 (Job)
}
```

**关键约束**：类必须 ①存在 ②**实现 `org.quartz.Job`** ③有无参构造。

> ⚠️ **定制版行为可能与官方不同，务必实测确认**：官方源码在类名不存在时会 `throw new JeecgBootException("后台找不到该类名：" + jobClassName)`；但**本次目标对不存在的类名也返回「创建定时任务成功」**（记录入库、`status` 为 `null`），说明定制版**吞掉了这个异常**。因此：
> - **「能入库」的判据是实测**（不存在的类名是否返回成功），不要照搬官方源码推断；
> - **「能否执行」仍需回到 `(Job)` 强转这条约束**上判断（需枚举 classpath 上的 Job 实现类）。

| 已实证（可写报告） | 未实证（不可写） |
|---|---|
| 低权 token 可访问 `/sys/quartzJob/*` 全组 | 直接 RCE |
| `jobClassName` **无白名单、无存在性校验**（不存在的类名也创建成功） | |
| 可创建/删除任意任务、可指定任意 cron | |
| `resume`/`pause` **接受 GET**（`?id=` 即可触发） | |

**真实危害面**（替代 RCE 的准确定性）：**滥用已有任务**——把 `KingdeeJob`（数据导入）之类设成高频 cron → 业务数据异常 / 资源耗尽；批量创建任务 → 调度器 DoS。

**判据**：先枚举目标 classpath 上的 Job 实现类，**逐个读 `execute()` 看有没有能执行命令的**。官方核心模块只有 5 个左右（`SampleJob`/`SampleParamJob`/`AsyncJob`/`SendMsgJob`/`UserUpadtePwdJob`），**定制版会有额外业务 Job 类**（本次目标另有 `KingdeeJob` 等，可从 `/sys/quartzJob/list` 的存量任务反推）。没有能执行命令的 → 不能 RCE。

---

## 7. 认证链与凭据纪律

### 7.1 SSO 换取 JWT

```bash
# 1) 拿 code（redirect_uri 必须是已注册的白名单值）
curl -sk -o /dev/null -D - -H "Cookie: SESSION=<会话>" \
  "https://<auth域>/oauth/authorize?redirect_uri=<白名单URI>&response_type=code&client_id=<client>&scope=all"
# 2) 换 JWT —— body 字段名要对齐前端（常见漏字段导致「code错误」）
curl -sk -X POST "https://<target>/dview/sys/unifiedLogin" -H 'Content-Type: application/json' \
  -d '{"code":"<code>","type":"2","redirectUri":"<同上>"}'
```

> **踩坑**：`unifiedLogin` 的 body 常需 `code` + `type` + `redirectUri` **三字段齐全**，缺 `type`/`redirectUri` 会报「code错误，请重试」，**看起来像 code 失效，实际是参数缺失**。字段名从前端 bundle 里 grep `unifiedLogin` 的调用点确认。

> **占位符**：`<auth域>` = 统一认证域名；`<target>` = 业务系统域名；`<会话>` = 认证站会话 Cookie；`<client>` / `<白名单URI>` / `type` = 从前端 bundle 里 grep `oauth/authorize` 与 `unifiedLogin` 的调用点获取（本次为 `client_id=sport_membership_integration`、`type=2`、`redirect_uri` 为 H5 首页地址）。

### 7.2 单账号单会话（凭据互踢）

**本次目标实测**启用了单账号单会话：同一账号每次登录（含 SSO 换 JWT）**立即踢掉旧 token**。

> ⚠️ **未核实这是 JeecgBoot 的框架默认行为还是本部署的配置**。遇到时**先实测确认**（用同一账号登录两次，看旧 token 是否失效），不要假定所有 JeecgBoot 目标都如此。

```json
{"success":false,"message":"当前账户已在其它设备登录!","code":401}
```

**三个后果**：
1. **别把「token 失效」误判为「漏洞被修复」**——先看报错文案区分「已过期」vs「已在其它设备登录」。
2. **测试操作纪律**：每调一次 `unifiedLogin` 就作废上一个 token。**拿到 token 后不要再调登录接口**（哪怕只是想看 userInfo），否则自己的凭据会失效。
3. **写报告时可作为一个正向设计点**：该机制会让合法用户在攻击者使用后被踢下线，**「合法用户莫名被踢」是异常检测的现成信号**。

### 7.3 其他凭据坑

| 坑 | 现象 | 处理 |
|---|---|---|
| **软删除导致用户名不可复用** | 创建用户返回 `{"message":"操作失败","code":500}` | 该用户名被用过（含已软删除的），**换名**。批量测试用时间戳生成唯一名 |
| **token 可放 query 参数** | `?token=<jwt>` 被接受（除 header 外） | 记一条低危（凭据入 URL → CDN/Referer/日志泄露面） |
| **会话 cookie 不参与 API 鉴权** | 带 Cookie 调 `/dview/*` 返回 401 | 该 API **只认 `X-Access-Token`**；`Cookie` 仅为与浏览器流量一致 |

---

## 8. 审计日志 `/sys/log/list` —— 二次挖掘（高价值）

**审计日志本身就是一座情报矿。** 拿到日志读权限后，务必做二次挖掘：

### 8.1 可用的服务端过滤参数

| 参数 | 有效性 |
|---|---|
| `logType`（1=登录日志 / 2=操作日志） | ✅ |
| **`userid`** | ✅ |
| **`createTime_begin` / `createTime_end`** | ✅ |
| `logContent` / `username` / `method` / `requestUrl` / `ip` | ❌ 均返回 0 |

> 组合 `userid` + 时间范围可精确圈定某个账号在某个时段的活动，再**分页拉取 + 本地 grep** 即可。

### 8.2 日志里能挖到什么

| 字段 | 价值 |
|---|---|
| `requestParam` | **完整请求体**（含手机号、核销码等敏感数据）；也含**历史攻击者的载荷** |
| `method` | **完整 Java 类名** → 内部 API 全图 + 包结构 |
| `ip` / `username` | 操作轨迹、人员画像 |

### 8.3 日志注入（写入侧）

用户可控字段（如 `user/edit` 的 `name`）会被**原样写入 `requestParam`，无转义**：

```bash
# 写入
curl -sk -X POST ".../mobile/shop/user/edit" -H "X-Access-Token: <token>" \
  -H 'Content-Type: application/json' -d '{"name":"<b>probe</b>","sex":"男","birthday":"2000-01-01"}'
# 从日志读回 → requestParam 中原样出现 <b>probe</b>
```

- **已确认**：日志注入（用户输入未净化存储）
- **风险**：若管理后台日志页未转义渲染 → **存储型 XSS → 管理员中招**（**需能访问管理后台才能验证**，本次未验证，如实标注）
- **验证纪律**：用 `<b>` 而非 `<script>` —— 足以证明「HTML 未转义存储」，且不会在管理员正在看日志时真的执行

### 8.4 历史攻击痕迹

日志里常有**厂商不知情的历史攻击记录**。用关键词特征匹配（`<script` / `onclick=` / `union select` / `--sp_password` / `%u002e%u2215` / `../`）扫描，往往能挖出：

- 自动化扫描器载荷（如 XSS Cheat Sheet 的 `ha.ckers.org/xss.js`）
- SQLi 绕过技巧（`--sp_password`）
- 路径穿越（IIS Unicode `%u002e%u2215`）
- **对应账号是否仍存活**（可用 `duplicate/check` 之类接口确认）

> 这是**对甲方有独立情报价值的发现**，建议单列附录并给出核实动作（确认是否为本单位/委托方的前次测试；若非则停用账号、查 WAF 日志）。

---

## 9. 自检教训（JeecgBoot 相关 · 通用方法论见 `self-check-methodology.md`）

| # | 教训 |
|---|---|
| 1 | **只沿「前端 JS → 端点」推会系统性漏掉框架自带、前端零调用的管理面** —— Quartz 定时任务即典型，前端零调用，只能靠「按框架高危组件清单反向枚举」发现 |
| 2 | **「读接口可达」与「写接口可达」必须分别普查** —— 本次测试早期只扫读接口，直到**单独按写接口清单系统性补扫**才挖出严重级问题（可改任意用户密码 / 删账号 / 新增数据源） |
| 3 | **对报错接口不要直接判负** —— `/sys/dict/queryTableData` 缺参数时报 SQL 异常，报错原文里**直接打出了参数名**，前四轮都当「不可用」跳过 |
| 4 | **已获得的数据本身也是攻击面** —— `/sys/log/list` 读权限到手后做二次挖掘，挖出日志注入 + 历史攻击痕迹 |
| 5 | 从审计日志的 `method` 字段可反向聚合控制器类名（**只覆盖打了日志注解的操作，不完整**） |
| 6 | **结论有时效性** —— 本次 WAF 规则在测试期间被实时收紧（同一扩展名 10 分钟内变了三次），**每条结论都要记录快照时间** |

> 通用自检方法论（5 轮固定框架、六条核心教训、交付前全量复现验证）见 `references/notes/self-check-methodology.md`。

---

## 10. 修复建议的标准话术（合并成一条）

> 对 `/dview/sys/**` 全部管理端接口**按角色做功能级鉴权**，拒绝会员/普通用户角色，而非仅校验 token 有效性。需排查 `@RequiresPermissions` 注解是否在管理端 Controller 上**确实生效**。会员 H5 与管理后台应使用**不同的 JWT 签发域/受众（`aud`）**，管理端只接受管理后台签发的 token。**临时缓解**：网关层按 `userIdentity` 直接拦截 `/dview/sys/**`，仅放行管理端来源 IP，并对非管理端调用实时告警。

**报告组织建议**：读越权 / 写越权 / 定时任务 / 任意表读取 **同根因**，**合并为一条严重问题**，不要拆成 4 条中高危——否则甲方会逐个打补丁而漏掉根因。
