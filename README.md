# Enil Ling Pesing

渗透测试 / 安全研究 / 漏洞发现全流程 Agent Skill。六阶段方法论（授权确认 → 被动侦察 → 主动枚举 → 漏洞探测 → 受限利用 → 报告），内置 24 类漏洞 playbook、国产 OA/中间件指纹与默认凭据字典、逐类证据纪律与合规红线。

> ⚠️ **仅限授权测试使用**：本 skill 用于内部渗透项目、SRC/众测平台、CTF、自建靶场，或书面授权的第三方资产。使用者须对目标拥有合法测试授权，并遵守当地法律与平台规则。作者不对任何滥用行为承担责任。

## 功能

- **六阶段 checkpoint 工作流**：每阶段有 MUST 输出，未通过不得进入下一阶段
- **24 类漏洞 playbook**：SQLi / XSS / SSRF / IDOR / RCE / 反序列化 / XXE / SSTI / 逻辑漏洞 / OAuth-JWT-SAML / GraphQL / 竞态 / 请求走私 / WAF 绕过 / API 测试 / 未授权访问 / 信息泄露 / 路径遍历 / CSRF-开放重定向 / CORS-Host 头 / NoSQL / LLM 提示注入 / 移动-IoT / 云
- **反幻觉硬约束**：payload 必须出自 references / 工具输出 / 联网核实来源，禁止凭记忆生成；无证据不下结论
- **国产 SRC 字典**：致远 / 通达 / 泛微 / 用友 / 金蝶 / 蓝凌等 OA 指纹、默认凭据、高频参数

## 安装

```bash
git clone https://github.com/enilmalus/Enil_ling_pesing.git
ln -s "$(pwd)/Enil_ling_pesing" ~/.claude/skills/enil-ling-pesing
```

重启 Claude Code 会话后生效。

## 使用

命中任一即触发：

- "渗透测试 / 红队 / 攻防演练 / 安全评估 / 漏洞挖掘 / 靶场"
- "SRC 挖洞 / 漏洞赏金 / bug bounty / 众测"
- "安全研究 / 漏洞复现 / CVE 分析"
- 直接给出目标域名 / IP / API / APP 要求测试

## 目录结构

```
├── SKILL.md               # 主流程：六阶段 + 路由表 + 硬约束
└── references/
    ├── playbooks/         # 24 类漏洞 playbook
    ├── dictionaries/      # 国产指纹 / 默认凭据 / 高频参数
    └── templates/         # 报告模板
```

## 取材来源

playbook 内容改编自以下开源项目（详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)）：

- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 以及 PayloadsAllTheThings / SecLists / PortSwigger / HackTricks 等权威公开源

## License

[MIT](LICENSE)
