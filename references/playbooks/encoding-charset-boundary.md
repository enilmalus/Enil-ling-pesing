# 解析与规范化差异（Encoding / Charset / Parser Differential）

> 同一段输入在**不同层**（WAF/网关 → 框架 → 业务代码 → 数据库/文件系统）被解析成**不同东西**时，鉴权与业务判定就会分裂：过滤器认为无害、业务层认为是指令。这是路径穿越、过滤器绕过、越权判定分裂、注入绕过的共同底层机理。SRC/赏金里常作为**绕过手段**出现，单独成洞时多为高/严重。

**取材来源与定位**：结构沿用本目录 `_template.md`。
**分工（避免重复维护）**：
- 本文件聚焦「**解析差异的观测方法与判据**」
- **WAF 绕过类的编码变换清单不在此重复** → `waf-bypass.md` §4.1 编码层（分块、HPP、大小写、Content-Type 混淆等）
- 路径穿越的利用面 → `path-traversal.md`；NoSQL/LDAP 的字符与类型差异 → `nosql.md`、`ldap-xpath-injection.md`；原型污染 → `prototype-pollution.md`
- **payload 出处**：payload 取自 [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)、[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) 等权威公开源，逐条标注出处；**未标出处的一律不写入**（SKILL.md 硬约束 1）。

---

## 1. 触发信号

- 请求**被 WAF 放行但应用报错**，或反过来（WAF 拦、直连源站成功）→ 说明至少两层解析不一致
- 同一参数在不同接口/不同 Content-Type 下表现不同（JSON 接受、表单拒绝，或反之）
- 路径类参数对 `..`、`/`、`\`、`;`、`%2e` 的处理在不同层不一致
- 参数以数组/标量两种形态出现时行为不同（`a=1&a=2`、`a[]=1`、`{"a":["1"]}`）
- **字面特殊字符被转义/被拦，但换成 HTML 实体形式（`&#39;` 等）就生效** → 转义与解码顺序颠倒（见 §4.4）

## 2. 高频入口点（观测维度，不是 payload 清单）

| 维度 | 观测点 |
|---|---|
| 解码层数 | 双重 URL 编码、`%25xx`、`%uXXXX`、HTML 实体、Base64 嵌套 |
| 字符集 | `Content-Type: ...; charset=` 与实际字节不符；UTF-8 无效序列/超长编码；全角与半角混用 |
| 规范化 | Unicode NFC/NFD、大小写折叠（`İ`/`ı`/`ß`）、首尾空白与 NUL、`.`/`..` 折叠 |
| 路径 | `/a/../b`、`..;/`、`%2e%2e%2f`、反斜杠、多重斜杠、尾随点/空格 |
| 形态与类型 | 数组 vs 标量 vs 对象；`"1"` vs `1`；`null` vs 缺字段 |
| 编码包装 | 压缩/分块/多重 `Content-Encoding`（详见 `waf-bypass.md` §4.1，不重复） |

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **先证"分层"存在**：找一个能区分两层的判据——同一输入让**层 A 接受、层 B 报错**（或反之）。拿不到分层证据就不要往下走（否则只是在猜）。
2. **画分层图**：用只读请求测试"同一语义、不同编码形态"是否被不同层区别对待；记录每层的判定（放行/拦截/报错/正常）。
3. **找判定分裂点**：把差异落在**安全判定**上才有价值——鉴权判定 vs 业务取值不一致（越权）、过滤器判定 vs 落盘内容不一致（注入/穿越）。
4. **确认影响并守边界**：只用只读或最小写入证明；**一旦发现可写面，先判可见性等级再动手**（对齐 SKILL.md Phase 5 测试痕迹清单）。
5. **降级路径**：找不到分层 → 记为「本入口未观察到解析差异」，按 SKILL.md Phase 3 第 5 条判断是否满足封锁四条；不满足就写 `未探尽`。

## 4. Payload 区（每条标注出处）

**4.1 Unicode 规范化差异** `[PayloadsAllTheThings]`

| 输入字符 | payload 形态 | 规范化 / 兼容映射后 |
|---|---|---|
| `‥` (U+2025) | `‥/‥/‥/etc/passwd` | `../../../etc/passwd` |
| `︰` (U+FE30) | `︰/︰/︰/etc/passwd` | `../../../etc/passwd` |
| `＇` (U+FF07) | `＇ or ＇1＇=＇1` | `' or '1'='1` |
| `＂` (U+FF02) | `＂ or ＂1＂=＂1` | `" or "1"="1` |
| `﹣` (U+FE63) | `admin'﹣﹣` | `admin'--` |
| `／` (U+FF0F) | `／／domain.com` | `//domain.com` |
| `＜` (U+FF1C) | `＜img src=a＞` | `<img src=a>` |
| `﹛` (U+FE5B) | `﹛﹛3+3﹜﹜` | `{{3+3}}` |
| `［` (U+FF3B) | `［［5+5］］` | `[[5+5]]` |
| `＆` (U+FF06) | `＆＆whoami` | `&&whoami` |
| `ｐ`+`ʰ` | `shell.ｐʰｐ` | `shell.php` |
| `ª` (U+00AA) | `ªdmin` | `admin` |

> 出处：[swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) `Encoding Transformations/README.md`（Unicode Normalization 节）。
> **判据**：只有「某一层做了规范化/兼容映射（NFKC/NFKD 或应用层 `normalize()`）而另一层没做」时差异才可利用——先证分层，再用表里对应字符。
> **本表右列已逐行用 `unicodedata.normalize('NFKC', …)` 复核**（自检代码见下）。**与上游原文共三处改动、涉及上游 4 行**：① 上游 `＜…＞` 一行右列写作 `<img src=a/>`，NFKC 实际结果是 `<img src=a>`（上游笔误），本表按实测订正；② 上游的 `。`(U+3002) 一行**不属于 Unicode 规范化**（NFKC 下不变），已移到 §4.2 的域名层等价映射；③ 上游把 `ｐ`(U+FF50) 与 `ʰ`(U+02B0) 列为两行（payload 与结果均相同），本表合并为一行。

Python 侧自检规范化结果（确认哪一层会变）：

```py
import unicodedata
s = "ᴾᵃʸˡᵒᵃᵈˢ𝓐𝓵𝓵𝕋𝕙𝕖𝒯𝒽𝒾𝓃ℊ𝓈"
for form in ("NFC", "NFD", "NFKC", "NFKD"):
    print(form, unicodedata.normalize(form, s))
```
> 出处：同上（原文示例）。

**4.2 形近字符 / 字符集等价（身份相关面）** `[PayloadsAllTheThings]`

- MySQL 中形近字符可能被判等：`SELECT 'a' = 'ᵃ'` 返回 `1`；带 `COLLATE utf8mb4_0900_as_cs` 时返回 `0`
- Punycode / IDN 同形域名：`раypal.com`（西里尔字母 `а`）↔ `xn--ypal-43d9g.com`
- **域名层等价映射**（属 IDNA/UTS-46，**不是 Unicode 规范化**）：`。`(U+3002)、`．`(U+FF0E)、`｡`(U+FF61) 在 IDN 处理中均映射为 `.`，故 `domain。com` 在支持 IDN 的解析器里等价于 `domain.com`。**注意**：只有 `．`(U+FF0E) 在 NFKC 下也变 `.`；`。`(U+3002) 与 `｡`(U+FF61) 用 `unicodedata.normalize('NFKC', …)` **复现不出来**，判定这一层必须看解析器/IDN 实现，不要用 Unicode 规范化自检。
- **受害面**：密码重置 / 找回密码 / OAuth 提供方（同形账号被判定为同一用户）

> 出处：[swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) `Encoding Transformations/README.md`（`### Punycode` 与 "similar character" 节）。**域名层映射一条核对自** [UTS-46 IDNA 映射表](https://www.unicode.org/Public/idna/latest/IdnaMappingTable.txt)：`3002 ; mapped ; 002E`、`FF0E ; mapped ; 002E`、`FF61 ; mapped ; 002E`。

**4.3 编码变换清单（本文件不重复）** → `waf-bypass.md` §4.1（编码层）–§4.3（语义层）；路径类载荷 → `path-traversal.md`

**4.4 转义与解码的先后顺序颠倒（HTML 实体绕过 `addslashes`）** `[本 skill 自研，2026-10 实战沉淀]`

> 本节是**「分层」的另一种形态**：不是"两层解码次数不同"，而是**同一层内「转义」与「解码」的先后顺序被写反了** —— 先转义、后解码，转义就白做。

**机理**：应用做了 `addslashes()`（或任何字符级转义）**之后**才做 HTML 实体解码，再拼进 SQL / 命令 / 文件路径：

```
攻击者提交：  x&#39;                ← HTML 实体形式的单引号
                    ↓
① addslashes()  字符串里【没有字面单引号】→ 无字符可转义 → 原样放行
                    ↓
② 实体解码      &#39; → '        ← 【顺序颠倒，此处失效】
                    ↓
③ 拼进 SQL      ... like '%x'%'   ← 单引号闭合字符串 → 注入
```

**测试法（关键：负向结论不能只测一种形式）**：

| 提交形式 | 编码 | 若只测这一种会怎样 |
|---|---|---|
| 字面符 | `'` | ❌ **会被正确转义，误判为「不可注入」** |
| **十进制实体** | `&#39;` | ✅ 本次命中的形式 |
| 十六进制实体 | `&#x27;` | ✅ 实测同样命中 |
| 命名实体 | `&apos;` | ⚠️ **实测未解码**（原样回显 `&apos;`）—— 见下 |

> **⚠️ `&apos;` 不一定是等价形式**：本次目标上 `&#39;` / `&#x27;` 均被解码成 `'`，但 **`&apos;` 原样回显、未被解码**。
> **原因未实测确认**（推测与解码函数支持的实体集/flags 有关，如 PHP `html_entity_decode()` 默认 `ENT_HTML401` 不含 `&apos;`；**该 PHP 行为本机未复现验证，仅作线索**）。
> **实操**：**优先用数字实体**（`&#39;`/`&#x27;`）；`&apos;` 只作补充尝试，**不可据其失败就否定整类**。

> **纪律**：注入类测试的负向结论，**必须至少覆盖「字面符 + 十进制实体 + 十六进制实体」三种形式**才能下"不可注入"的结论。只测字面符 = 证据不足。
> 同理适用于其它被"过滤"的字符：`"`（`&#34;`/`&quot;`）、`<`/`>`（`&#60;`/`&#62;`）、**`=`（`&#61;`，可绕过"剥离等号"的过滤器 —— 实测有效）**、`/`（`&#47;`）、`.`（`&#46;`）。

**双重实体编码（绕过过滤器自身的实体解码）** `[本 skill 自研]`：

若目标过滤器**自己会解一层实体**（用于黑名单匹配），可用**双重编码**让它解完一层后仍残留实体、由浏览器/应用再解一层：

```
提交：  &#38;#39;
过滤器解一层：&#38; → &     ⇒ 剩下 &#39;   ← 不含字面引号，黑名单匹配不到
浏览器/应用再解：&#39; → '    ⇒ 真正的单引号
```

**本次实战两处命中**（同一目标、同一机理）：
- **SQL 注入**：`skey=x&#39;` → 页面回显 `You have an error in your SQL syntax ... near '%')`（字面 `'` 则被正确转义、无报错）
- **XSS**：`skey=zzz&#38;#115;cript` → 过滤器解一层后剩 `&#115;cript` → 浏览器解出 `script`，绕过"打断 `script` 关键字"的黑名单

**判据门槛**：必须拿到「**同一入口、字面形式被拦/被转义，实体形式生效**」的**成对证据**才算命中；只证明"实体形式没被拦"不够（可能只是没触发规则）。

## 5. 工具用法

- **必须保留原始字节**：`curl --data-binary @file -H 'Content-Type: application/json; charset=utf-16' --path-as-is`（`--path-as-is` 阻止 curl 自己规范化路径——**默认行为会毁掉你的测试**）
- 多层对比：直连源站 IP + `Host` 头 vs 走 WAF 域名，对照两层判定
- 十六进制核对：`xxd`/`hexdump` 确认发出去的字节，不要相信终端回显

## 6. 证据要求

- `baseline`：**未做编码变形**的同一请求的正常响应（证明变形前后行为确实不同）
- `proof`：原始字节（hexdump 或文件）+ 响应原文 + 说明"哪一层把它当成了什么"
- `verification`：换一种变形方式（或换一个参数位）复现同一机理
- 判据门槛：**只有"层 A 判 X、层 B 判 Y"的可复现证据**才算命中；仅"某个编码没被拦"属于观察，不写成漏洞

## 7. 合规边界 / 不要做的事

- 变形测试**不得用于放大危害**（如用编码绕过 WAF 去打生产库的写接口）
- 不落地 web shell、不做持久化；只读优先
- 发现可写面时先记录可见性等级与内容标记，按 SKILL.md Phase 5 痕迹清单处理
