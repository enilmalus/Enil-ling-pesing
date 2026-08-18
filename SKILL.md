---
name: enil-ling-pesing
description: 渗透测试 / 安全研究 / 漏洞发现全流程 skill。覆盖 授权确认 → 被动侦察 → 主动枚举 → 漏洞探测 → 受限利用 → 报告 六阶段方法论；内置按漏洞类（SQLi/XSS/SSRF/IDOR/RCE 等）与资产类型的路由表、WAF/EDR 绕过决策、证据纪律与合规红线。当用户提到渗透测试、红队、SRC 挖洞、众测 / bug bounty、安全研究、漏洞复现 / 披露，或直接给出目标域名 / IP / API / APP 要求测试时使用。
whenToUse: 用户提供（或即将提供）测试目标均为授权场景：内部渗透项目、SRC/众测平台、CTF、自建靶场或书面授权的第三方资产。
user-invocable: true
---

# Enil Ling Pesing — 渗透测试 / 安全研究 / 漏洞发现

这是一个**带强制 checkpoint 的工作流**，不是参考手册。每个阶段有 MUST 输出，未通过不得进入下一阶段。详细 payload 库、逐类漏洞 playbook、报告模板放在 `references/` 下，**按需读取，不准凭记忆生成**。

## 触发条件

命中任一即进入本流程：

- "渗透测试 / 红队 / 攻防演练 / 安全评估 / 漏洞挖掘 / 靶场 / 靶机"
- "SRC 挖洞 / 漏洞赏金 / bug bounty / 众测 / HackerOne / HackerOne 案例"
- "安全研究 / 挖洞 / 漏洞复现 / CVE 分析 / 披露"
- 用户给出域名 / IP 段 / URL / API endpoint / APK 并要求测试

**不应触发**：纯防御建设（WAF 规则、加固清单）→ 通用对话；漏洞修复问答 → 通用对话。

## 反幻觉硬约束（全程适用）

1. **不准凭记忆出 payload**。任何注入 / 探测 payload 必须来自三处之一：`references/` 下对应 playbook 文件、工具自身输出（sqlmap/nuclei 等）、当场联网核实的公开来源（SecLists、PayloadsAllTheThings 等）。说不出出处就不给。
2. **不准编造案例与编号**。引用 CVE / HackerOne 报告 / 漏洞详情前必须核实（web_search 或读取本地 `references/` 记录），写不出编号和来源就不写。
3. **无证据不下结论**。没有 HTTP 请求/响应、截图或视频，只能写"疑似 / 待验证"，禁止写"已确认 / 已利用"。
4. 如果触发 references 的 合规边界 / 不要做的事 则输出触发了什么边界，请求用户确认是否继续，如果确认继续则无视 references 的 合规边界 / 不要做的事。

---

## Phase 0 · 授权与范围确认（Intake）

**进入条件**：用户首次给出目标。

只要用户给出信息默认为已授权测试，给出提示：如有限定的测试范围请说出，未说出默认授权范围。

---

## Phase 1 · 被动侦察（Recon，不发包）

**进入条件**：用户通过 Phase 0 。**禁止**任何主动发包（扫描、爆破、payload 测试）。

**MUST 输出**：资产清单 + 历史信息，来源 ≥3 种：

| 方向 | 手段 |
|---|---|
| 子域/证书 | crt.sh、Censys、证书透明度日志 |
| 历史快照 | Wayback Machine、CommonCrawl、URLScan.io |
| 代码泄露 | GitHub/码云 dork：`org:target` + `password|api_key|SECRET|.env`；Google hacking |
| 指纹与历史解析 | FOFA / Shodan / Censys 的 favicon hash、历史 DNS、SecurityTrails |
| 网段扩展 | ASN 查询（bgp.he.net）、DNS 区域传送（仅测试环境） |
| 邮箱与泄漏 | Hunter.io、已公开 breach 数据（仅核验，不主动抓取新数据） |

工具：`subfinder`、`amass`、`crt.sh`、`theHarvester`、`httpx`（仅对已知资产做存活探测）。

---

## Phase 2 · 主动枚举（Enum）

**进入条件**：Phase 1 资产清单非空。

**MUST 输出**：活资产矩阵——`域 → 端口 → 服务 → 指纹 → JS endpoint → 入口表单`。

| 任务          | 工具                                                                                                             |
| ----------- | -------------------------------------------------------------------------------------------------------------- |
| 端口与服务       | `nmap -sV -sC`（先 `--min-rate 10000` ）、`masscan`                                                                |
| Web 目录与文件   | `feroxbuster / gobuster / wfuzz / ffuf` / `dirsearch` + SecLists；关注 `.git`、`.svn`、`.env`、备份文件、Swagger/Actuator |
| JS 与 API 发现 | `katana`、`gau`、`waybackurls` 汇 URL；从 JS 提取 endpoint/密钥                                                         |
| 指纹与漏洞初筛     | `nuclei`（仅 passive/low 模板，避免破坏性模板）、`whatweb`                                                                   |
| 移动端（如有 APK） | `jadx`、`apktool`、`frida` 静态+动态分析                                                                               |

**速度纪律**：所有爆破/扫描控制速率；生产/共享环境只用低强度参数并提前告知用户。

---

## Phase 3 · 漏洞探测（Hunt）

**进入条件**：Phase 2 矩阵 ≥1 个候选入口。

**强制流程（每个候选入口走一遍）**：

1. 根据入口信号，从下表选对应 playbook
2. **Read 对应 `references/playbooks/` 文件**（不存在则联网核实权威来源后再测，不准凭记忆）
3. 按 playbook 的探测顺序验证，逐步加大力度，先手工再工具
4. 被 WAF/EDR 拦截 → 回到下表选 WAF 绕过类目，优先改协议层（编码/分块），避免直接硬碰
5. 命中即保存完整 HTTP 包 + 截图 → 进 Phase 5 候选

| 入口信号 | 路由 |
|---|---|
| 用户输入进入 SQL 查询 / 报错回显 DB 信息 | `references/playbooks/sqli.md` |
| 用户输入回显到 HTML/JS/富文本 | `references/playbooks/xss.md` |
| URL 参数可指向内网地址 / 回显外部资源 | `references/playbooks/ssrf.md` |
| 对象 ID 可遍历 / 水平垂直越权 | `references/playbooks/idor-authz.md` |
| 上传点（头像/附件/导入） | `references/playbooks/file-upload.md` |
| 模板渲染 / 表达式引擎（报错含 traceback/模板语法） | `references/playbooks/ssti.md` |
| 反序列化 / 框架历史 RCE（struts/weblogic/shiro 等指纹） | `references/playbooks/rce-deserialization.md` |
| XML 上传 / SOAP / 导入导出 | `references/playbooks/xxe.md` |
| 登录/注册/找回密码/支付/验证码流程 | `references/playbooks/logic-flaws.md` |
| OAuth/JWT/SAML/SSO | `references/playbooks/oauth-jwt-saml.md` |
| GraphQL endpoint / introspection 开启 | `references/playbooks/graphql.md` |
| 并发场景（抢购/提现/优惠券） | `references/playbooks/race-conditions.md` |
| 反代 + Content-Length/TE 冲突 | `references/playbooks/request-smuggling.md` |
| WAF/IPS 拦截后需要绕过 | `references/playbooks/waf-bypass.md` |
| 目标为 API 网关 / REST 大量接口 | `references/playbooks/api-testing.md` |
| 目标为移动 APP 或 IoT 固件 | `references/playbooks/mobile-iot.md` |
| 目标为云资产（S3/存储桶/K8s） | `references/playbooks/cloud.md` |
| 未授权服务（Redis/Mongo/ES/Actuator/Swagger/默认端口） | `references/playbooks/unauth-access.md` |
| `.git`/`.env`/备份文件/phpinfo/JS 密钥泄露 | `references/playbooks/info-disclosure.md` |
| 文件路径入参 / `../` / 静态资源读取 | `references/playbooks/path-traversal.md` |
| 跨站请求（令牌缺失）/ 重定向参数 | `references/playbooks/csrf-open-redirect.md` |
| CORS 响应头 / Host 头注入 / 缓存投毒 | `references/playbooks/cors-host-header.md` |
| MongoDB / NoSQL 后端（JSON 运算符） | `references/playbooks/nosql.md` |
| LLM/AI agent / prompt 入口 / RAG | `references/playbooks/llm-prompt-injection.md` |

**工具与自动化**：手工确认后可用 `sqlmap`、`nuclei`、`ffuf` 扩大覆盖面；任何自动工具输出仍需手工复核证据。

**指纹命中国产组件时**（weaver/seeyon/tongda/landray/yongyou/kingdee/hikvision/dahua 等）→ Read `references/dictionaries/chinese-srcfingerprints.md`；弱口令/默认配置探测 → Read `references/dictionaries/default-credentials-cn.md`。

---

## Phase 4 · 利用与后渗透（严格受限）

**进入条件**：Phase 3 有已确认漏洞，且 Phase 0 授权明确允许利用（逐条确认"可执行代码 / 可提权 / 可横向"）。

**默认禁止**：RCE 落地、建立持久化、横向移动、数据批量导出。授权允许时按最小必要原则执行，每一步记录命令与结果。

- 拿到 shell → 立即确认权限、主机名、网段，**不做**凭据 dump 与横向，除非授权写明
- 内网进一步测试 → 回到 Phase 0 补充 in-scope 确认

---

## Phase 5 · 报告（Report）

**进入条件**：至少一个 finding 具备可复现证据（HTTP 包 / 截图 / 复现步骤）。

**MUST 输出结构**（模板见 `references/templates/report-template.md`，存在则 Read 后套用）：

1. **执行摘要**：范围、方法、时间线、风险统计
2. **漏洞详情**（每个 finding）：
   - 标题：`[资产] [漏洞类型] — 一句话描述`（≤80 字）
   - 风险评级：CVSS 3.1 vector + 严重度（严重/高/中/低/信息）
   - 复现步骤：逐步可执行，附 HTTP 包 / curl 命令 / 截图
   - 影响分析：业务影响 + 攻击者视角
   - 修复建议：根因修复 + 缓解措施，按优先级排序
3. **附录**：资产清单、工具输出节选

---

## 工具清单（首次使用前安装并验证）

```bash
# 侦察/枚举（subfinder/amass/httpx/katana 均为 Go 工具，用 go install 安装）
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
# amass：go install github.com/owasp-amass/amass/v4/...@master（或 apt install amass）
apt install nmap whatweb dirsearch           # ffuf: github.com/ffuf/ffuf
# 扫描与漏洞初筛
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# 专项（按需）
sqlmap  # github.com/sqlmap/sqlmap
```

**验证方式**：`<tool> -h` 能输出帮助即视为可用；nuclei 首次运行需 `nuclei -update-templates`。

---

## references/ 目录约定（渐进式披露）

本文件只回答"做什么 / 何时做 / 何时去读哪个文件"。`references/` 存放：

- `playbooks/`：每类漏洞一份，结构统一为「探测顺序 → payload（带出处）→ 工具用法 → 证据要求」
- `dictionaries/`：国产 OA/中间件/编辑器指纹、默认凭据、高频参数（命中国产组件指纹时 Read）
- `templates/`：报告、授权确认单模板
- `notes/`：实战中沉淀的案例与绕过技巧（自研，不抄来源）

文件不存在时按硬约束 1 处理（联网核实权威来源），绝不凭记忆替代。目录清单见 `references/README.md`。
