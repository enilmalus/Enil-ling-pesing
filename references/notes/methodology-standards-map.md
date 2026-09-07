# 标准方法论对齐映射（PTES / OWASP WSTG / NIST 800-115 / OSSTMM / MITRE ATT&CK）

> 用途：用户要求「按某标准测试 / 报告 / 对表覆盖 / 量化风险」时读此文件。本 skill 的六阶段 checkpoint 工作流是**执行主干**；外部标准提供横向覆盖校验（防漏测）与对外报告话术，不替代工作流本身。
> 建立：2026-09-04，渗透测试模式定制时整理。所有链接为公开标准原文；具体条目以标准原文为准。

---

## 0. 总原则

| 需求 | 用什么 |
|---|---|
| 内部执行节奏 | 六阶段 checkpoint 工作流（SKILL.md），不改 |
| 漏测校验（收尾对表） | OWASP WSTG 12 类 ↔ playbook 对照表（本文 §2） |
| 对外报告的阶段话术 | PTES 七阶段 / NIST SP 800-115 四阶段命名（本文 §1） |
| 后渗透行为归类描述 | MITRE ATT&CK Enterprise 战术（本文 §3） |
| 量化风险评分 | OSSTMM 攻击面 / 通道 / RAVS 视角（本文 §4，仅在明确要求时） |

---

## 1. 阶段映射总表

| 本 skill 阶段 | PTES 七阶段 | NIST 800-115 四阶段 | WSTG 覆盖类目 | MUST 产出 |
|---|---|---|---|---|
| Phase 0 授权与范围确认 | ① Pre-engagement Interactions | Planning | — | 授权确认、范围清单 |
| Phase 1 被动侦察 | ② Intelligence Gathering | Discovery（被动部分） | WSTG-INFO | 资产清单 + 历史信息（来源 ≥3） |
| Phase 2 主动枚举 | ②③（侦察收口/建模输入） | Discovery | WSTG-INFO / WSTG-CONF | 活资产矩阵 |
| Phase 3 漏洞探测 | ④ Vulnerability Analysis | Attack（验证性探测） | 全部 12 类按路由表 | 已确认 finding（含证据） |
| Phase 4 受限利用 | ⑤ Exploitation / ⑥ Post-Exploitation | Attack | —（行为按 ATT&CK 归类） | 逐条授权的利用记录 |
| Phase 5 报告 | ⑦ Reporting | Reporting | — | 报告（模板见 `templates/`） |

- **PTES 七阶段**：Pre-engagement Interactions → Intelligence Gathering → Threat Modeling → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting。原文：<http://www.pentest-standard.org/>。Threat Modeling 在本 skill 中不设独立阶段，由 Phase 2→3 的入口信号路由承担（指纹+入口=威胁建模输入）。
- **NIST SP 800-115 四阶段**：Planning → Discovery → Attack → Reporting。原文：<https://csrc.nist.gov/pubs/sp/800/115/final>。注意 NIST 语境里 Attack 含验证性探测，对应本 skill Phase 3+4。
- OWASP 对各方法论的比较页（可直接引用作报告附录）：<https://owasp.org/www-project-web-security-testing-guide/v42/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies>

---

## 2. WSTG 12 类 ↔ playbook 对照（Phase 3 收尾查漏表）

WSTG v4.2 stable 共 12 个测试类目（WSTG-INFO … WSTG-APIT），原文：<https://owasp.org/www-project-web-security-testing-guide/v42/>。

| WSTG 类目 | 对应 playbook / 落点 |
|---|---|
| 01 Information Gathering（WSTG-INFO） | Phase 1/2 主流程 + `unauth-access.md` + `info-disclosure.md` |
| 02 Configuration & Deployment Management（WSTG-CONF） | `info-disclosure.md`（.git/.env/备份）、`cloud.md`、`unauth-access.md`（Actuator/Swagger/Druid） |
| 03 Identity Management（WSTG-IDNT） | `idor-authz.md`、`oauth-jwt-saml.md` |
| 04 Authentication（WSTG-ATHN） | `logic-flaws.md`（登录/找回/验证码）+ `dictionaries/default-credentials-cn.md` |
| 05 Authorization（WSTG-ATHZ） | `idor-authz.md`（水平/垂直越权）、`api-testing.md`（批量鉴权） |
| 06 Session Management（WSTG-SESS） | `oauth-jwt-saml.md`、`csrf-open-redirect.md` |
| 07 Input Validation（WSTG-INPV） | `sqli.md` `xss.md` `ssrf.md` `ssti.md` `xxe.md` `rce-deserialization.md` `path-traversal.md` `nosql.md` `request-smuggling.md` `file-upload.md` |
| 08 Error Handling（WSTG-ERRH） | `info-disclosure.md`（报错泄露/traceback） |
| 09 Testing for Weak Cryptography（WSTG-CRYP） | `oauth-jwt-saml.md`（弱算法/密钥）、`info-disclosure.md` |
| 10 Business Logic Testing（WSTG-BUSL） | `logic-flaws.md`、`race-conditions.md` |
| 11 Client-side Testing（WSTG-CLNT） | `xss.md`、`csrf-open-redirect.md`、`cors-host-header.md` |
| 12 API Testing（WSTG-APIT） | `api-testing.md`、`graphql.md`、`idor-authz.md` |

**用法**：
1. Phase 3 收尾前，对每个高价值入口按此表过一遍，标记「已触达 / 未触达 / 不适用（写理由）」。
2. 报告的「测试覆盖声明」直接引用此表 + 标注 N/A 理由，可显著减少甲方「测全了吗」的质疑。
3. 类目未触达 ≠ 必须补测——按风险与授权范围决定，但报告里必须如实声明。

---

## 3. ATT&CK Enterprise 战术归类（Phase 4 行为描述）

Phase 4 的每一步操作记录时，用 ATT&CK 战术语言归类（只写战术名，不编造技术编号；需要技术编号时当场到 <https://attack.mitre.org/> 核实）：

| 行为 | ATT&CK 战术 |
|---|---|
| 拿到 shell 后确认权限/主机名/网段 | Discovery |
| 凭据/配置文件收集 | Credential Access |
| 提权操作 | Privilege Escalation |
| 跨主机/跨服务移动 | Lateral Movement |
| 留存后门/计划任务 | Persistence（默认禁止，仅授权明确允许时） |
| 对外通信通道 | Command and Control（默认禁止） |
| 数据取回 | Collection / Exfiltration（默认禁止批量导出） |

Enterprise 矩阵完整战术链（Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command and Control → Exfiltration → Impact）：<https://attack.mitre.org/matrices/enterprise/>

> 报告价值：甲方安全团队按 ATT&CK 战术对照自家检测覆盖，是 Phase 5「影响分析」的标准写法之一。

---

## 4. OSSTMM 量化视角（仅在明确要求时）

OSSTMM 3（ISECOM，官网 <https://www.isecom.org/> 获取原文）提供与流程式标准不同的**量化**视角：攻击面分解为通道（channel）与向量（vector），以可复核的操作指标产出安全评分（RAVS）。

适用场景：客户明确要求「量化评分 / RAVS 报告 / 与 OSSTMM 对齐」。此时 Phase 2 资产矩阵需按通道（人/物理/数据网络/无线/通信）补全维度，评分计算严格按标准原文执行，不凭记忆。

---

## 5. 报告话术速查

- 「本次测试遵循 PTES 渗透测试执行标准的七阶段方法论，按 NIST SP 800-115 的 Planning-Discovery-Attack-Reporting 生命周期组织执行，测试覆盖对照 OWASP WSTG v4.2 十二个类目（见覆盖声明表），后渗透行为按 MITRE ATT&CK 战术归类描述。」
- 以上话术的每个实体都能在本文 §1–§3 找到支撑，报告里引用标准时附原文链接。
