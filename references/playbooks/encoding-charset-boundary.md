# 解析与规范化差异（Encoding / Charset / Parser Differential）

> 同一段输入在**不同层**（WAF/网关 → 框架 → 业务代码 → 数据库/文件系统）被解析成**不同东西**时，鉴权与业务判定就会分裂：过滤器认为无害、业务层认为是指令。这是路径穿越、过滤器绕过、越权判定分裂、注入绕过的共同底层机理。SRC/赏金里常作为**绕过手段**出现，单独成洞时多为高/严重。

**取材来源与定位**：结构沿用本目录 `_template.md`。
**分工（避免重复维护）**：
- 本文件聚焦「**解析差异的观测方法与判据**」
- **WAF 绕过类的编码变换清单不在此重复** → `waf-bypass.md` §4.1 编码层（分块、HPP、大小写、Content-Type 混淆等）
- 路径穿越的利用面 → `path-traversal.md`；NoSQL/LDAP 的字符与类型差异 → `nosql.md`、`ldap-xpath-injection.md`；原型污染 → `prototype-pollution.md`
- **payload 出处**：payload 取自本地 clone 的取材源（`Work/Tools/PayloadsAllTheThings`、`Work/Tools/src-hunter-skill` 等），逐条标注出处；**未标出处的一律不写入**（SKILL.md 硬约束 1）。

---

## 1. 触发信号

- 请求**被 WAF 放行但应用报错**，或反过来（WAF 拦、直连源站成功）→ 说明至少两层解析不一致
- 同一参数在不同接口/不同 Content-Type 下表现不同（JSON 接受、表单拒绝，或反之）
- 路径类参数对 `..`、`/`、`\`、`;`、`%2e` 的处理在不同层不一致
- 参数以数组/标量两种形态出现时行为不同（`a=1&a=2`、`a[]=1`、`{"a":["1"]}`）

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
| `＜` (U+FF1C) | `＜img src=a＞` | `<img src=a/>` |
| `﹛` (U+FE5B) | `﹛﹛3+3﹜﹜` | `{{3+3}}` |
| `［` (U+FF3B) | `［［5+5］］` | `[[5+5]]` |
| `＆` (U+FF06) | `＆＆whoami` | `&&whoami` |
| `ｐ`+`ʰ` | `shell.ｐʰｐ` | `shell.php` |
| `ª` (U+00AA) | `ªdmin` | `admin` |
| `。` (U+3002) | `domain。com` | `domain.com` |

> 出处：`PayloadsAllTheThings/Encoding Transformations/README.md`（Unicode Normalization 节，本地 clone `Work/Tools/PayloadsAllTheThings`）。
> **判据**：只有「某一层做了规范化/兼容映射（NFKC/NFKD 或应用层 `normalize()`）而另一层没做」时差异才可利用——先证分层，再用表里对应字符。

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
- **受害面**：密码重置 / 找回密码 / OAuth 提供方（同形账号被判定为同一用户）

> 出处：同上（Punycode 与 "similar character" 节）。

**4.3 编码变换清单（本文件不重复）** → `waf-bypass.md` §4.1（编码层）–§4.3（语义层）；路径类载荷 → `path-traversal.md`

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
