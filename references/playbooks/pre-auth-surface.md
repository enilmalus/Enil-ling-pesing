# 认证前可达面清点（Pre-Auth Surface Enumeration）

> 「登录前能碰到什么」是低垂果实密度最高的面：健康检查、指标、API 文档、内部网关、预发环境、注册/找回密码流程里的业务接口。这类面**不进前端菜单**，靠点页面永远发现不了，必须**系统性地清点**。SRC/赏金里多为 P2–P1（信息泄露起步，接口级无鉴权可到严重）。

**取材来源与定位**：结构沿用本目录 `_template.md`。
**分工（避免重复维护）**：
- 本文件 = **如何把免登录面找全的方法**（清点与判据）
- 具体未授权服务清单（Redis/ES/Actuator 默认口等）→ `unauth-access.md`
- 信息泄露类利用与评级 → `info-disclosure.md`；REST 接口的越权/字段级问题 → `api-testing.md`
- 框架自带管理面的反向枚举教训 → `../notes/self-check-methodology.md` §3.1
- **payload 出处**：路径/探针取自 [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) 与本 skill 既有 playbook，逐条标注出处；**未标出处的一律不写入**（SKILL.md 硬约束 1）。

---

## 1. 触发信号

- 目标有前端 SPA/微前端（路由表在 JS 里，服务端路由远多于前端可见菜单）
- 响应头/错误页暴露了网关、服务名、内部域名、环境标识（`X-Env: staging`、`Server: nginx`+内部路径）
- 同 IP 多端口/多 Host、存在预发或测试域名
- 已拿到任意一个接口的 401/403 语义差异（说明鉴权是"逐接口"而非"入口统一"）

## 2. 高频入口点（路由来源三路，缺一路必漏）

| 来源 | 做法 |
|---|---|
| **前端资产** | 抓全部 JS chunk（webpack/vite 产物）→ 提取路由表、`baseURL`/API 前缀、被注释或未挂菜单的模块名；微前端见 `../notes/mftcc-vue-microfrontend.md` |
| **服务端差异** | 对比 404 页面/错误体在不同前缀下的差异；探测常见运维前缀；对疑似存在用 **GET 探 405** 判可达（`../notes/self-check-methodology.md` §3.5） |
| **旁路情报** | 证书透明度/历史快照/备份文件/`.well-known`/robots/sitemap；同源预发域名（同 IP 不同 Host） |

> **第三方组件的自带接口是免登录面的大户**（编辑器/上传/导出/预览类组件常整目录无鉴权）：**UEditor** → `../notes/ueditor-components.md`（config/listfile/listimage/catchimage/upload* 全部免登录）；同类还有 FCKeditor / eWebEditor / KindEditor / CKFinder，路径速查见 `file-upload.md` §2「编辑器测试路径速查」。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **严格口径确认"免登录"**：清空 cookie/新会话、**不携带任何凭据**发请求，观察状态码 + **响应体是否含业务数据**。
   - `401` 与 `403` 语义不同（未认证 vs 已认证无权限）——分类记录
   - **经典漏判**：前端 302 跳到 `/login`，但**接口本身 200 且返回数据** → 必须直接请求接口本体，不能只看浏览器跳转
2. **读面清点（安全）**：健康检查/指标/调试（`/healthz`、`/metrics`、`/debug`、`/actuator` 等）、API 文档（Swagger/OpenAPI/GraphQL introspection）、版本与构建信息、静态与备份资源。
3. **写面清点（谨慎）**：注册、找回密码、验证码/短信、邀请、回调/Webhook、埋点与上报。**只做只读验证**（如发送一次可自删的最小探针），记录可见性等级。
4. **判定归属**：命中面若属于第三方或超出授权范围 → 立即停止并报告（范围纪律优先于发现）。
5. **读/写分开普查**：仅扫读接口会系统性漏掉严重级写接口（教训见 `../notes/self-check-methodology.md` §3.2）。

## 4. Payload 区（每条标注出处）

**4.1 免登录高命中路径与探针** `[本地 src-hunter unauth-access.md]`

- **关键 path 表**（基于 WooYun 案例统计的高命中表）→ [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) 的 `references/playbooks/unauth-access.md` §3.3
- 服务级指纹一行命令与单服务一键探针（Redis / Mongo / ES / Docker / rsync / Memcached / ZooKeeper / Spring Actuator）→ 同文件 §3.1–§3.2
- 默认凭据枚举纪律（**必须限速**，同文件已给速率上限）→ 同文件 §3.4

> 出处：[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) `references/playbooks/unauth-access.md`（**上游仓库的**，勿与本 skill 同名的 `references/playbooks/unauth-access.md` 混淆）。本 skill 的等价内容：本目录 `unauth-access.md` §2.2–§2.4、§4.1–§4.2（不重复维护）。

**4.2 前端路由 / 接口前缀提取** `[本 skill 自研]`

```bash
# 从全部 JS chunk 里捞路由与接口前缀（示例；产物去重后人工筛）
grep -rhoE '"/[a-zA-Z0-9_/.-]{3,}"' dist/js/*.js | sort -u | head -200
# 结合构建产物里的 API 前缀变量（不同框架命名不同，先 grep baseURL/apiPrefix）
grep -rhoE '(baseURL|apiPrefix|VITE_GLOB_API_URL)[^,;]{0,80}' dist/js/*.js | sort -u | head -40
```

> 微前端 / webpack chunk 还原与网关路由提取 → `../notes/mftcc-vue-microfrontend.md`。

**4.3 判定口径（纪律，非 payload）**：新会话 + **不带任何凭据** + 观察状态码与响应体是否含业务数据；`401`（未认证）与 `403`（已认证无权限）分开记录；**不要**只看浏览器跳转（前端 302 到 `/login` 而接口本身 200 的漏判见 §3 第 1 步）。

## 5. 工具用法

- 目录/路径面：`feroxbuster`/`ffuf` 低速率跑（生产面必须限速），字典须注明来源
- 前端路由提取：`katana`/`gau` 汇 URL + 从 JS 里 grep 路由与 `baseURL`；微前端场景参考 `../notes/mftcc-vue-microfrontend.md` 的 chunk 还原法
- 判定可达性：`curl -i` 看 405/401/403/200 语义，避免用状态码单一字段下结论

## 6. 证据要求

- `baseline`：**带凭据**的同一请求（证明该接口在认证后返回什么，用来对比未认证时是否少返回了数据）
- `proof`：**不带任何凭据**的请求/响应原文（含完整 URL 与方法）
- `verification`：换新会话/换出口 IP/换 UA 再取一次，证明不是缓存或偶发
- 记录：命中面的归属（本目标/第三方）、是否含个人数据、可见性等级
- **判据门槛**：只有"无凭据 + 返回业务数据或可执行写操作"才算命中；仅页面可达（无数据、无功能）**不算漏洞**

## 7. 合规边界 / 不要做的事

- 发现超出授权范围的资产（同 IP 的其他站点、云存储、第三方服务）→ **停手报备**，不得继续探测或下载数据
- 免登录写面**只做最小探针**，不做批量写入、不发短信轰炸、不注册他人手机号
- 命中个人数据时：只截取能证明漏洞的最小片段，报告内脱敏（对齐 `../../SKILL.md` Phase 5 与测试痕迹清单）
