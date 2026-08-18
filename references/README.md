# references/ 目录说明

本目录存放 SKILL.md 主流程之外的全部细节，遵循渐进式披露：主文件只做路由，这里才是细节的落点。

## 规划结构

```
references/
├── README.md                      # 本文件
├── playbooks/                     # 逐类漏洞 playbook（✅ 已建齐 24 个）
│   ├── _template.md               # 作者模板（非路由目标，写新 playbook 时参考）
│   ├── sqli.md                    # P0/P1 深挖
│   ├── xss.md
│   ├── ssrf.md
│   ├── idor-authz.md
│   ├── file-upload.md
│   ├── ssti.md
│   ├── rce-deserialization.md
│   ├── xxe.md
│   ├── logic-flaws.md
│   ├── oauth-jwt-saml.md
│   ├── graphql.md
│   ├── race-conditions.md
│   ├── request-smuggling.md
│   ├── waf-bypass.md
│   ├── api-testing.md
│   ├── unauth-access.md           # 未授权访问（P0）
│   ├── info-disclosure.md         # 信息泄露（P0）
│   ├── path-traversal.md          # 路径遍历/LFI
│   ├── csrf-open-redirect.md      # CSRF/开放重定向
│   ├── cors-host-header.md        # CORS/Host 头/缓存投毒
│   ├── nosql.md                   # NoSQL 注入
│   ├── llm-prompt-injection.md    # LLM/AI 提示注入
│   ├── mobile-iot.md              # 精简版
│   └── cloud.md                   # 精简版
├── dictionaries/                  # 国产指纹/默认凭据/高频参数
│   ├── 00-index.md
│   ├── chinese-srcfingerprints.md
│   └── default-credentials-cn.md
├── templates/
│   └── report-template.md         # Phase 5 报告模板
└── notes/                         # 实战案例与自研绕过技巧（后续沉淀）
```

## 每个 playbook 的统一结构

1. **触发信号**：什么现象路由到这里
2. **探测顺序**：从最无害到最有杀伤力的步骤
3. **payload 区**：每条 payload 必须标注出处（如 `SecLists/...`、`PayloadsAllTheThings/...`、具体 URL）；无出处不允许写入
4. **工具用法**：sqlmap/nuclei/ffuf 等的精确命令与参数
5. **证据要求**：什么才算"已确认"（必须能保存什么）

## 未建文件时的兜底

SKILL.md 硬约束 1 规定：路由到不存在的 playbook 时，必须**联网核实权威来源**（如 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)、[SecLists](https://github.com/danielmiessler/SecLists)）后再测试，禁止凭记忆生成 payload。

## 可参考的开源资源（写 playbook 时取材）

### 取材自以下开源仓库

| 目录 | 内容 |
|---|---|
| [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) | 中文 SRC 导向，19 攻击类 playbook + 305 payload + 263 WAF 绕过 + 2887 H1 案例，与本 skill 结构最接近（**playbook 首选取材源**）|
| [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | 71 个 `hunt-*` 技能（`hunt-sqli`/`hunt-ssrf`/`hunt-xss`…），681 披露报告模式，按类正文范本 |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | `Skills/web/` 下 16 个 `offensive-*`（sqli/ssrf/ssti/xxe/idor/waf-bypass…）+ AD/云/无线/移动/EXP 开发 |
| [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) | 9 个侦察/OSINT skill（90+ 侦察模块、48 密钥正则、80+ dorks），补 Phase 1/2 侦察 |
| [akashrpatil/awesome-offensive-security-skills](https://github.com/akashrpatil/awesome-offensive-security-skills) | 191+ skills 索引（`skills/` 下 bug-hunting / penetration-testing / red-teaming / ai-red-teaming / exploit-development 等类）|
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 官方 60+ 技能（防守+进攻，含 SSRF/访问控制/JWT 测试等）|
| [trailofbits/skills](https://github.com/trailofbits/skills) | 官方审计/RE 插件（c-review、constant-time、fp-check、yara 等），代码审计质量标杆 |

### 远程高 star 资源（未 clone，写 playbook 时按需联网核实）

| 仓库 | Star | 用途 |
|---|---|---|
| [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) | ~3.9k | 终端自动化 bug bounty，26 命令 + Web2/Web3 漏洞类 + 7-Question Gate 校验 |
| [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | ~3.6k | 已 clone，见上 |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | ~2.9k | 已 clone，见上 |
| [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) | ~1.8k | 已 clone，见上 |
| [akashrpatil/awesome-offensive-security-skills](https://github.com/akashrpatil/awesome-offensive-security-skills) | 191+ | 已 clone，见上 |
| [0xGhostCAT/claude-ai-cyber-security-skills](https://github.com/0xGhostCAT/claude-ai-cyber-security-skills) | — | 30 skills + 60 工具，H1/Bugcrowd/Intigriti/Immunefi 平台化报告模板 |
| [Arenbai/SecSkills](https://github.com/Arenbai/SecSkills) | — | 中文 PTES 全流程，36 专项知识文件（19 类 Web 漏洞）|
| [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) | ~1.7k | 渗透知识库（AI 可执行格式）|
| [uphiago/recon-skills](https://github.com/uphiago/recon-skills) | ~1.2k | 侦察 + CORS/WordPress/云专项 |
| [26zl/cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) | — | 670+ 工具一键安装 + 870+ agent skills（CTF/DFIR/红蓝）|
| [awesome-copilot/security-review](https://github.com/awesome-copilot/security-review) | ~36.5k | 代码安全审查（8 语言，SQLi/XSS/密钥/访问控制/弱加密），偏源码审计 |
| [trailofbits/skills](https://github.com/trailofbits/skills) | 官方 | 已 clone |

### 权威 payload 库（playbook 里标注出处时引用）

| 仓库 | 用途 |
|---|---|
| [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | 逐类漏洞 payload 权威来源 |
| [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) | 字典（爆破/路径/fuzz）|
| [PortSwigger/Web Security Academy](https://portswigger.net/web-security) | 每类漏洞的探测方法论 |
| [HackTricks](https://book.hacktricks.xyz) | 漏洞利用与后渗透速查 |

> 本 skill 骨架借鉴 src-hunter-skill 的阶段化 checkpoint 模式与 Claude-Red 的按类拆分方式；playbook 从上述本地仓库取材后自行验证、精简，非整库复制。每条 payload 必须标注出处（见 `_template.md` 与 SKILL.md 硬约束 1）。
