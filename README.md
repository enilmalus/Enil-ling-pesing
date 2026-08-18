# Enil Ling Pesing

[中文](README.zh-CN.md) · **English**

A full-workflow Agent Skill for penetration testing, security research, and vulnerability discovery.

> ⚠️ **Authorized testing only**: This skill is intended for internal penetration projects, SRC / bug bounty platforms, CTFs, self-built labs, or third-party assets with written authorization. You must hold legal testing authorization for the target and comply with local laws and platform rules. The author assumes no responsibility for any misuse.

## Features

- **Staged checkpoint workflow**: each phase has a MUST output; you cannot advance to the next phase without passing it
- **24 vulnerability playbooks**: SQLi / XSS / SSRF / IDOR / RCE / deserialization / XXE / SSTI / business logic / OAuth-JWT-SAML / GraphQL / race conditions / request smuggling / WAF bypass / API testing / unauthorized access / information disclosure / path traversal / CSRF-open redirect / CORS-Host header / NoSQL / LLM prompt injection / mobile-IoT / cloud
- **Anti-hallucination hard constraints**: payloads must come from references / tool output / verified online sources; never generate from memory; no conclusion without evidence
- **China SRC dictionaries**: fingerprints for Seeyon / Tongda / Weaver / Yonyou / Kingdee / Landray and other OA, default credentials, high-frequency parameters

## Installation

```bash
git clone https://github.com/enilmalus/Enil-ling-pesing.git
ln -s "$(pwd)/Enil-ling-pesing" ~/.claude/skills/enil-ling-pesing
```

Restart the Claude Code session for it to take effect.

## Usage

Triggers when any of the following matches:

- "penetration testing / red team / security assessment / vulnerability hunting / lab"
- "SRC / bug bounty / crowdtesting"
- "security research / vulnerability reproduction / CVE analysis"
- A target domain / IP / API / APP is given and testing is requested

## Directory Structure

```
├── SKILL.md               # Main workflow: phases + routing table + hard constraints
└── references/
    ├── playbooks/         # 24 vulnerability playbooks
    ├── dictionaries/      # China fingerprints / default credentials / parameters
    └── templates/         # Report template
```

## Sources

Playbook content is adapted from (see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)):

- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- and authoritative public sources such as PayloadsAllTheThings / SecLists / PortSwigger / HackTricks

## License

[MIT](LICENSE)
