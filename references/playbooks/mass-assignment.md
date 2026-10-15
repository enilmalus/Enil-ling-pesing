# 批量赋值 / 过度绑定（Mass Assignment / Over-posting）

> 服务端把请求字段**批量**写进对象/模型（框架自动绑定），攻击者多送一个字段就改掉一个本来不该由他控制的属性（`role`/`is_admin`/`verified`/`balance`/`tenant_id`）。SRC/赏金里属于**逻辑越权**类，常见 P1–P2；危害取决于被改属性（改角色 → 接管；改归属 → 跨租户）。

**取材来源与定位**：结构沿用本目录 `_template.md`。
**本文件只覆盖「非 REST 专用 / 非 GraphQL 专用」的通用场景**（表单→对象自动绑定、注册/资料更新/邀请等写接口的字段注入、嵌套对象与深合并）。
- REST API 场景 → 先读 `api-testing.md` §4.2（Mass Assignment 专节，字段候选与出处见该节）
- GraphQL mutation → 先读 `graphql.md`（mutation Mass Assignment）
- 深合并 / `__proto__` 类属性注入 → `prototype-pollution.md`
- **payload 出处**：payload 取自 [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)、[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) 等权威公开源，逐条标注出处；**未标出处的一律不写入**（SKILL.md 硬约束 1）。

---

## 1. 触发信号

- 请求 body 是**整个对象**（`{"username":..,"email":..}`），而不是少量具名参数
- 框架特征：Spring `@ModelAttribute`/Jackson 反序列化、Rails/Django/Laravel 的 fillable/guarded 语义、Node 端的 `Object.assign`/`req.body` 直传 ORM
- 响应体回显了**你没有提交的**字段（往往是可写字段的线索）
- 注册、资料更新、邀请成员、组织/租户设置、订单编辑这类"对象型"写接口

## 2. 高频入口点

- 注册 / 资料更新 / 密码修改 / 邀请 / 组织或租户设置 / 角色与权限管理 / 批量导入
- 对象嵌套处：`{"profile":{"role":"admin"}}`、`{"user":{"is_admin":true}}`
- 字段名候选取自**真实来源**，不要凭空猜：前端 JS/表单模板里的字段名、OpenAPI/Swagger、错误信息里回显的字段名、**读接口返回体里出现的新字段**（返回什么往往就能写什么）

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **建差分基线**：先发**最小字段集**的正常请求，记录响应与随后用读接口看到的状态（这一步就是报告要用的 `baseline`）。
2. **逐字段追加**：每次只加一个候选字段，值取**能明确判定"被写入 / 被忽略"的值**——`admin`、`true`、`false`、`0`、随机字符串都可以；直接送 `admin`/`true` 正是为了让写入后的判权变化可判定（**前提是只用测试账号**，见 §7）。比较响应与**服务端真实状态**。
3. **判定"真写进去了"**：必须用**独立读接口 / 重新登录后读**确认属性已持久化——**响应回显了该字段 ≠ 它被持久化**（回显可能来自原样返回给你的 body）。
4. **确认影响面**：只有属性确实写入且影响判权/归属/金额时才算有效漏洞；仅"接受了未知字段但无用"→ 记为观察，**不写成漏洞**。
5. **降级路径**：字段被忽略 → 试嵌套对象形态、`[]`/JSON 数组形态、大小写与下划线/驼峰变体（`isAdmin`/`is_admin`/`IS_ADMIN`）——这属于同一次探测内的**变体尝试**，不受"重跑一次"限制。

## 4. Payload 区（每条标注出处）

**4.1 字段注入（对象型 body）** `[PayloadsAllTheThings]`

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

> 出处：[swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) `Mass Assignment/README.md`。原文要点：ORM/框架自动把用户输入赋给对象属性且不校验可写字段 → `isAdmin` 被写入即提权。

**4.2 场景化字段候选** `[本地 src-hunter api安全.md]`

- 注册时加 `role: admin` → 提权
- 改资料时加 `balance: 999999` → 改余额
- 创建订单时改 `price: 0` → 改价格
- 更新设置时加 `is_admin: true` → 拿管理权
- 根因是框架自动绑定（Spring `@ModelAttribute` / Rails `attr_accessible` 语义 / Laravel `$fillable` / Django / Node ORM 直传 `req.body`）

> 出处：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) `references/payloader/by-category/web/api安全.md`（Mass Assignment 节）；REST 场景的字段候选与绕过另见 `api-testing.md` §4.2、GraphQL mutation 见 `graphql.md`。

**4.3 差分探测模板（本 skill 自研，不依赖具体字段名）**

```jsonc
// 先 baseline，再逐字段追加（值与字段名以目标真实字段为准）
{"username":"u_probe","email":"u_probe@example.com"}                              // baseline
{"username":"u_probe","email":"u_probe@example.com","role":"probe_role_value"}    // +1 字段
{"username":"u_probe","email":"u_probe@example.com","verified":false}             // +1 字段
{"profile":{"role":"probe_role_value"}}                                           // 嵌套形态
```

## 5. 工具用法

- 手工为主：`curl`/Burp Repeater 逐字段差分（记录每次的完整请求与响应，供报告引用）
- 自动化：`ffuf`/自定义脚本对**字段名字典**做差分（字典需注明来源），但**每次只加一个字段**，否则无法归因
- 注意：自动化脚本会掩盖字节级差异，涉及编码/类型差异时改用 `curl --data-binary` 手工发

## 6. 证据要求

- `baseline`：最小字段集的正常请求/响应 + 之后的读接口状态
- `proof`：追加字段的请求/响应 + **独立读接口证明属性已生效**（截图或原文）
- `verification`：换一个字段或换一个接口复现同一机理
- 记录：目标框架/版本（若可得）、字段名来源（前端 JS / Swagger / 读接口回显）
- **禁止**：用同一时间/同一域名的另一个包充当对照（见 `_template.md` §6）

## 7. 合规边界 / 不要做的事

- **禁**：真把自己提权成管理员后**使用**管理功能（对齐 `graphql.md` 的同类纪律）——只证明属性可写与影响，不做越界操作
- **禁**：修改他人数据、改金额/余额、改租户归属做"效果验证"；只改自己测试账号的属性
- 只做最小证明：一个测试账号、一个属性、一次读写闭环；不批量刷数据
