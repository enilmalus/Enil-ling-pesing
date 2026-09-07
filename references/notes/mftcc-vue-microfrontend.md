# 微前端 + 微服务网关架构渗透方法论（Vue/single-spa 实战沉淀）

> 来源：某保理公司供应链金融平台两轮授权渗透（2026-09，目标 A=员工端 / B=供应商门户，同后端微服务）。两轮共产出 严重 7 / 高 5。
> 本文件是**方法论提炼**，不是案例流水账；目标标识与密钥值已脱敏。命中同类架构时按 §1-§8 顺序过一遍。

---

## 0. 指纹（命中即适用本方法）

- 前端：`mftcc-base-web` / `*-web-supplier`、SystemJS + single-spa、Vue2 + elementUI、`webpackJsonp`
- 后端：`/gateway/mftcc-{sys,cus,factor,doc,flowable,...}-server/` 微服务命名
- Server: nginx；登录字段 `opNo`（员工端）或 `loginNo`（门户端）；认证走 `token`/`refreshToken` **请求头**（非 cookie）
- mftcc 系国内金融租赁/保理/供应链金融常见框架。同类微前端架构（qiankun/single-spa）同样适用 §2-§3。

## 1. 第一步永远是配置文件（情报密度最高的入口）

SPA 根页面引用的 JS 里找 `config-prod.js` / `config-dev.js`，逐项提取：

| 字段 | 价值 |
|---|---|
| `gateway_path` | API base |
| `web_path` 微应用列表 | 后端服务名全集（比扫端口快）|
| `servers` 映射 | `$servers.xxx` 前缀 → 微服务的对应关系（读 JS API 调用必需）|
| `websocket_server` / 注释里的测试地址 | 范围外资产（问用户是否纳入）|
| `data_crypto` | true=请求体加密（见 §7，密钥必在前端）|
| `router_white_list` | **前端路由白名单 ≈ 后端免鉴权接口候选清单** |
| config-dev.js 里的内网 IP:端口 | 微服务端口布局（渗透测试报告信息泄露项）|

## 2. chunk hash 还原法（拿到全部业务代码）

微应用 `app.js` 只是壳，业务 API 在按需加载的 chunk 里。webpack runtime 的 URL 构造：

```js
i.p + "static/js/" + ({chunk名表}[e] || e) + "." + {哈希表}[e] + ".js"
// i.p = "/mftcc-<app>-web/"（相对路径，实际在 /mftcc-base-web/web/<app>/ 下）
```

**操作**：从 app.js grep 出两张表（名表 `0:"vendors~xxx"`、哈希表 `0:"a1b2..."`），拼 URL 全量下载业务 chunk，再 grep `\$servers\.[a-z]+ ?\+ ?"[^"]+"` 得到完整 API 清单（本轮 278 个端点）。

**注意**：SPA fallback 会把不存在路径也返回 200 index.html（2.5KB）——判断文件真实性看 size（chunk 通常 >2KB）或内容是否含 `System.register`。`app.js.map` 也顺手查（source map 2.3MB 泄露）。

## 3. API 端点批量鉴权探测（白名单发现）

收集端点后批量匿名 POST `{}`，按响应分三类：

| 响应 | 含义 |
|---|---|
| `{"code":1000,"message":"Token为空"}` | 网关拦截（有鉴权）|
| 业务错误（"用户名不能为空"/"查询成功"/500 参数错误）| **白名单接口，匿名可达** ← 高价值 |
| nginx 404 空 body | 服务未部署（路径探测无信号，网关 401/404 不区分存在性）|

```bash
# 服务映射：$servers.sys → mftcc-sys-server 等
while read -r s p; do
  r=$(curl -s -m 8 -X POST "https://$T/gateway/${SRV[$s]}$p" -H "Content-Type: application/json" -d '{}' | head -c 60)
  [[ "$r" != *"Token为空"* && -n "$r" ]] && echo "[NOAUTH] $s$p => $r"
done < endpoints.txt
```

## 4. 网关鉴权三层次模型（垂直越权判定）

```
L1 无 token 拦截（Token为空）  ← §3 已测
L2 token 存在性校验（有 token 就放行） ← 大多数网关只做这层 ← 漏洞高发层
L3 角色/租户校验（服务端数据权限） ← 正确实现的样子
```

**L2 判定法**：拿最低权限 token（自注册账号）调管理端接口族（`sys/sysUser/findByPage`、`sysRole`、`sysDept`）：
- 返回数据 = L2-only 网关，垂直越权成立（本轮：供应商 token 拖 89 员工/读全公司放款统计）
- 数据权限反而收敛（admin 视角 3 条 vs 供应商 89 条）说明服务端有数据过滤但不完整——两侧都测

**特判 `simulationLogin` / 切换用户类接口**：任何 token 可换任意员工凭证（含 admin），且会**顶掉目标用户当前会话**——发现后只测 1-2 个目标即停（副作用）。

## 5. 验证码/密码重置链测试清单（逻辑缺陷高发区）

前端 JS 搜这些关键词定位链路，再逐环实测：

| 检查点 | 方法 | 本轮命中 |
|---|---|---|
| 验证码回显 | JS 搜 `verifiyNum` / `telcode=e.verfiyNum`；发码接口看响应字段 | 目标 A 回显（9.8 链）|
| 重置不校验码 | forgetPassword 填 `mesCode:"000000"` 直接提交 | 目标 B 通过=任意改密 |
| 图形验证码本地化 | JS 搜 `generateCaptcha`/`identifyCode`，看是 canvas 本地绘制还是服务端 | 两站均本地 → 服务端无验证码 |
| 发码无用户校验 | 假手机号调发码接口 | 目标 B 任意号码"发送成功"（轰炸面）|
| 码无锁定/频控 | 连发 5-8 个错码看 200/锁定 | 两站均可爆破（10^6）|
| 前置接口无鉴权 | 发码/加密参数/重置接口本身匿名可达 | 两站均白名单 |

**完整 ATO 链模板**：手机号枚举接口(无鉴权) → cusId/userId 获取 → 改密(无码校验) → 登录(码可爆破)。每环单独可能是"中危"，串起来 9.8——报告里必须按链评级。

## 6. 错误消息差分枚举

统一文案做不彻底时看**标点/字段差异**：本轮"账户或密码错误"(存在) vs "账户或密码错误！"(不存在)——仅感叹号之差。diff 多个响应的原始 JSON，别只看 msg 字面。

## 7. data_crypto 加密请求构造（前端加密 = 形同虚设）

`data_crypto: true` 时 POST body = `{"encrypt": AES-128-CBC-base64(JSON)}`，头 `isCrypto: true`。全部材料在前端 JS：

```js
g="<16字节key>"          // 基础库 AES.encrypt 附近的字符串常量（示例格式：0123456789abcdef）
b="<16字节IV>"           // 同上（示例格式：fedcba9876543210）
x = AES.encrypt(t,key,{iv,mode:CBC,pad:Pkcs7})
// 签名（isSign 时）: signMsg = SHA256(排序参数k=v& + "md5Key=<盐>").toUpperCase()
```

**操作**：grep `AES.encrypt` 附近的字符串常量拿 key/IV；grep `md5Key` 拿签名盐。用 pycryptodomex 构造合法加密+签名请求（实测通过）。反向价值：**抓包里的密文也能解**。

## 8. 实战纪律（本轮踩坑/经验）

1. **simulationLogin/踢会话类接口**：调用即顶掉真实用户会话——验证 1-2 个目标立即停，记录副作用。
2. **敏感文件验证后即删**：下载银行流水/合同只验证可达性（`-w "%{content_type}"` + `head -c` 判 magic bytes），不留存。
3. **测试账号密码变更必须记录并告知**（本轮 forgetPassword 测试把账号密码改了）。
4. **JWT 拿不到密钥时**：`alg:none` + 弱密钥字典（含前端 AES key——开发者常复用）+ 看错误回显确认库（java-jwt 特征报错）。
5. **token 有效期意识**：16h token 过期前把 refreshToken 存本地，长测试会话避免反复登录。
6. **两站同后端时**：A 站的漏洞在 B 站逐项回归（白名单/无鉴权接口大概率同配置）；账号体系独立但服务共享——A 的低权限 token 可能在 B 网关直接放行。
7. **pageSize 被忽略是信号**：列表接口传 `pageSize:2` 返回 16MB → 服务端无分页强制 + 无数据权限，顺藤摸瓜找单条详情接口（downLoadOneFile 类）。

---

## 附：两轮成果索引

| 轮次 | 严重 | 高 | 代表链 |
|---|---|---|---|
| 目标 A（员工端） | 1 | 3 | 验证码回显→findPassword 重置链（前端代码证实）|
| 目标 B（供应商门户） | 4 | 2 | simulationLogin 接管 / 文件服务无隔离 11401 文件 / forgetPassword 无码校验 |

复现细节在本地证据库（脱敏要求：报告中客户/员工/PII 数据只留必要最小样本）。
