# .NET 客户端逆向方法论（Windows exe/dll → 攻击面定位）

> 来源：用户博客「HTB-Scrambled Writeup」。触发场景：内网/靶机环境发现随共享分发的 Windows 客户端程序（`*.exe` + 配套 `*.dll`），需定位后门、还原私有协议、或为反序列化利用做前置。
> 仅限授权测试：逆向分析属只读枚举（Phase 2/3 默认可做）；据其产出构造并投递 RCE 载荷属 Phase 4「可执行代码」授权项。
> 与兄弟文件分工：APK/移动端逆向见 `references/playbooks/mobile-iot.md`；二进制漏洞利用（pwn）见 `references/notes/binary-stack-overflow.md`；本文件只管 Windows .NET 客户端的**攻击面定位**。

---

## 决策流程

```
拿到 Windows 客户端程序
   ↓ §1 判定 .NET 程序集（dnSpy 反编译近源码）
   ↓ §2 逆向目标清单（认证函数 → 后门用户 / 序列化传输 / 硬编码密钥）
   ↓ §3 运行客户端复现协议（hosts 劫持 + 后门登录验证）
   ↓ 命中"序列化对象上送服务端" → references/playbooks/rce-deserialization.md §4.5 BinaryFormatter 链
```

## 1. 判定与工具

| 程序类型 | 工具 | 判定信号 |
|---|---|---|
| .NET（C#） | dnSpy（读+调试）、ILSpy（读） | strings 出 `mscorlib`；dnSpy 直接出反编译源码 |
| 原生 PE | Ghidra / IDA | dnSpy 打不开或出 IL 混淆 |

.NET 程序集反编译即近源码。dnSpy 左侧树按 命名空间→类→方法 浏览，优先看命名含 `Logon/Login/Auth/Client/Protocol/Net` 的类。

## 2. 逆向目标清单（按产出价值排序）

1. **认证函数找后门**（来源：HTB-Scrambled，`ScrambleLib.dll` 的 `Logon()`）：用户名忽略大小写等于 `scrmdev` 时直接 `return true`（日志字符串 "Developer logon bypass used"）——开发者调试后门上线未删；其余用户走 `Username|Password` 拼接。**看日志字符串与魔法比较**，后门往往不在 UI 层而在库文件里。
2. **传输层还原**：客户端把什么对象、用哪个格式化器（`BinaryFormatter`/`Json.NET`）、按什么协议（`命令;base64` 分号分隔）发到哪个端口——`BinaryFormatter.Serialize()` + 自定义 TCP 端口 = 反序列化 RCE 入口，转 `rce-deserialization.md` §4.5。
3. **硬编码密钥/连接串**：AES key/IV、API key、DB 连接串、内网地址（顺带补资产清单）。
4. **调试残留**：`#if DEBUG` 分支、Developer 菜单、测试账号、注释里的运维提示。

## 3. 运行复现（Windows 攻击机）

客户端多半按主机名连服务端，先做 hosts 劫持（来源：HTB-Scrambled）：

```powershell
Add-Content C:\Windows\System32\drivers\etc\hosts -Value "10.129.36.208 dc1.scrm.local"
```

用逆向出的后门用户 + 任意密码登录：成功 = 协议走通且后门真实有效（证据：登录成功行为 + 代码路径）。同时 wireshark/抓包确认报文格式，为裸 TCP 复现 payload 做准备。

## 4. 红线

1. 仅限授权测试；逆向为只读操作，默认可做。
2. 按逆向产出构造利用（反序列化载荷、后门利用）属 Phase 4 受限行为，授权写明「可执行代码」才投递；无授权止步于"存在后门/存在反序列化入口"的存在性证明。
3. 证据纪律：后门判定须引用代码位置（类/方法）与日志字符串，不只写结论。
