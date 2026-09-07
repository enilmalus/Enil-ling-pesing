# 契约锁/电子签平台 + 官网 CMS 链渗透方法论（2026-09 三轮实战沉淀）

> 来源：某金融集团电子签平台（契约锁私有化部署，多端口）+ 集团官网/CMS/存储/SVN 体系的授权渗透，三轮累计 60+ findings。本文件是**方法论提炼**，目标标识、密钥值、内网地址已脱敏。命中同类架构（qiyuesuo 私有化 / RuoYi CMS / MinIO/FastDFS 存储 / Resin 老中间件）时按 §1-§8 过一遍。

---

## 1. 多端口同 IP 资产的聚类判别（30 分钟省 3 小时）

同一 IP 的多个 web 端口先做**同源判定**再决定测试粒度：

| 信号 | 取法 | 含义 |
|---|---|---|
| CSP 头模板 | 逐端口 `curl -D -` 对比 | CSP 里引用的第三方域（如厂商 CDN/geetest）相同 = 同一产品集群 |
| 302 Location | 看跳转目标的 `service=` 参数 | 常泄露内部 CAS/Sso 地址（内网 IP+端口） |
| 前端目录名 | `/qyswebapp/` `/qysoss/` `/qysopen/` 等 | 同厂商不同子系统（主站/OSS 管理端/开放平台），加密协议族同源 |
| 响应头 Server | nginx 同版本 + 同 Vary 组合 | 同一 nginx 集群，漏洞全组回归 |

**实测结论**：同集群 5 个端口（80/443/9180/9181/9182）中 CORS 任意源反射**全部命中**（配置模板级缺陷）；而上轮主站的前端加密协议在新端口的前端 JS 里同款存在（签名算法/nonce 公式一致）——**上轮逆向的加密客户端直接复用，不要重写**。

## 2. 契约锁（qiyuesuo）私有化专用检查清单

- **前端 RSA 私钥**：`grep -oP 'setPrivateKey\("MIIC[^"]+' main.js`。契约锁前端登录 bundle 疑似长期内置完整私钥（与服务端公钥配对）——私有化部署版优先查这个
- **加密协议全链**（前端 JS 逆向可得全部材料）：
  - URL `?_=ms时间戳`；头 `timestamp` / `req-token=<uuid>-<ts>` / `nonce=md5(req-token+"XMLHttpRequest"+timestamp)`（"XMLHttpRequest" 是硬编码盐，跨版本通用）
  - 响应头 `blurCode`（32 字符）本身即 AES-256-CBC key，IV 硬编码（`grep 'blurCode'` + 混淆 JS 里找 16 字节 IV）；解密 `{cypher}hex` 响应体得会话 RSA 私钥
  - 开放平台（qysopen）变体：头 `x-qys-accesstoken` / `x-qys-signature=md5(token+secretKey+ts)` / `x-qys-timestamp`——需要后台创建的 token，无凭据则止
- **免鉴权接口**：`/api/login/loginWay`、`/api/login/config/type`、`/api/login/get/placeholder`（需 sourceType 参数）、`/api/reset/password/smsAndEmailConfig`、`/api/captcha/prepare`——契约锁标准白名单，直接 GET 试
- **449 INVALID_NONCE 是误导**：实为未认证统一响应，与 nonce 无关；时间同步排查后确认
- OSS 管理端（qysoss）前端 chunk 可提取 800+ 路由与 400+ API 清单，但全被 CAS 拦——**测绘价值 > 直接利用价值**（为拿到账号后的越权回归做地图）

## 3. 官网页面是后端体系的入口（被动侦察链）

官网这种"静态展示站"常被跳过，实际是**后端基础设施的泄露源**：

1. 官网 HTML 里 `<img src="http://IP:19000/...">` → 存储服务（MinIO）IP:端口直接暴露
2. 官网 JS `back_url = "http://IP/prod-api"` 或 `localStorage.setItem('back_url',...)` → CMS 后端 API 网关地址
3. 友情链接/子公司域名 → 集团资产横向扩展
4. 页脚备案号 + ICP 查询 → 主体确认

**顺序**：先被动读官网 HTML/JS（零发包）→ 顺藤摸到 prod-api 网关 → RuoYi 指纹（报错文案"认证失败，无法访问系统资源"/欢迎语"欢迎使用后台管理框架"）→ 按下节清单走。

## 4. RuoYi 后台标准速查（命中即全过一遍）

| 端点 | 检查点 | 说明 |
|---|---|---|
| `/captchaImage` | `captchaEnabled:false` | 关验证码 = 无限速爆破前提（高危链一环）|
| `/v3/api-docs`、`/swagger-ui/index.html`、`/swagger-resources` | 生产 Swagger 暴露 | 全套接口结构泄露 |
| `/login`（JSON） | 响应无 msg 差分 | admin vs 随机名响应/时延一致 = 枚举不可行（记负面结果）|
| `sendPhoneCode`/短信类 | 免鉴权 + 用户名枚举 | "该用户名不存在" vs 触发发送 = 双重问题（枚举+轰炸）|
| `system/config/configKey/*` | 免鉴权配置读取 | sys.* 配置键有时免认证（本轮 sysfile/urlPrefix 免鉴权）|
| `/register` | 是否开启 | 关闭时返回"当前系统没有开启注册功能"——不用再试 |
| `/v1/user/list`、`/common/download` | 历史 NDay | 老版本 RuoYi 未授权，新版多已修——都值得单次验证 |
| 默认凭据 | `admin/admin123` 单次 | 命中即接管；未命中按纪律停，不做爆破 |

## 5. 对象存储（MinIO/FastDFS）匿名权限三连测

```
GET  /<bucket>/?max-keys=5      → ListBucketResult = 匿名可列（翻页拿全量清单+大小统计）
PUT  /<bucket>/唯一命名探针.txt  → 200 = 匿名可写（内容投毒/覆盖官网图片 → 高危）
DELETE 同一探针                  → 204 = 匿名可删；确认后立即验证 404（不留痕）
GET  /<bucket>/?policy          → AccessDenied = 策略接口关（不影响前三个）
GET  /<不存在桶>/                → 404 NoSuchBucket vs 403 AccessDenied = 桶名枚举差分
```

- 写入测试用**唯一命名**（`pentest-ro-<日期>.txt`），验证读回后立即删除并确认 404
- 桶内如有前人测试残留（如 `securitytest/probe.txt`）——**证明缺陷早已被发现但未修复**，写进报告加重严重性
- FastDFS 变体：ListObjects 被拒但已知路径 GET/PUT/DELETE 放行（路径规律 `group1/M00/00/XX/hash.ext` 可程序化遍历）；group 名 403/404 差分同桶名枚举
- 桶名猜测优先：`<公司缩写>-cms-images` / `-cms-video` / `-files` / `backup` / 公司域名主体名式（本轮目标即以主体名直接命名桶）

## 6. 老中间件（Resin/2008 年代）暴露面处置

- Server banner 直接暴露版本（Resin 3.1.8 = 停止维护十余年）本身就是 finding
- 老框架私有 servlet 参数（如 SQF 框架 `URLCLASS=类名`）做**存在性差分**：存在类返回实体内容，不存在类返回空 body——可枚举内部类结构（信息泄露，低-中危）
- 目录爆破在纯 servlet 站收益低（168 词无命中）；时间花在登录表单的隐藏字段（TRANSCODE/systemname/menupub 命名体系）上更能还原框架结构
- **无公开漏洞情报的国产私有框架**（swotech/SQF 类）：联网核实无果后果断收手，不凭记忆编 CVE——按硬约束 2 处理

## 7. SVN/源码服务公网暴露（快速定级）

`WWW-Authenticate: Basic realm="VisualSVN Server"` 出现在公网 = 中危起步（源代码托管暴露）。默认凭据测试限 3 组（admin/admin、visualsvn/visualsvn、svn/svn）即止；有锁定机制的爆破违反纪律。真正的价值是**记录内网段连续公网化的模式**（一个 /24 段出现 OA+CMS+SVN+MinIO 全公网 = 边界管理失控，报告中按体系性缺陷写）。

## 8. DLP 加密文档的交付流程（工程坑，非漏洞）

- 目标环境 F 盘有透明加密 DLP（文件头 `%TSD`，Word 等授权进程可读写，WSL/curl 侧只见密文）
- **写入 F 盘的 docx 出去即被加密**——WSL 生成 → 复制到 F 盘 → 用户在 Word 里打开正常（双向透明）
- **无法就地编辑用户在 Word 里改过的 docx**（读出来是密文）——需要给这类文档增内容时：生成**独立 docx**（表格/附录），让用户在 Word 里打开复制粘贴进主文档
- 验证 DLP 是否存在：`head -c 4 file.docx` 看 magic（PK=明文 zip，%TSD=已加密）；自己生成的文件复制到目标盘再复制回来对比

---

## 附：三轮成果与命中率索引

| 攻击面 | 命中率 | 代表发现 |
|---|---|---|
| 官网页面 JS 引出的后端体系（§3） | 极高 | CMS 网关 + MinIO + SVN 全链 |
| RuoYi 速查清单（§4） | 高 | Swagger/无验证码/短信免鉴权三连 |
| 对象存储三连测（§5） | 高 | 双存储匿名读写（MinIO+FastDFS）|
| 契约锁清单（§2） | 中 | RSA 私钥 + 加密协议全破（上轮）；新端口仅 CORS 回归命中 |
| 老中间件差分（§6） | 低 | 仅类存在性枚举（信息级）|

评级口径提醒：无 CVSS 交付场景，按影响定级——任意密码重置/管理员接管/批量 PII/匿名写存储=高危；信息泄露/越权读取/爆破前提=中危；用户枚举/点击劫持/纯结构泄露=低危。
