# <漏洞类名>

> 一句话定义 + 为什么 SRC/赏金关注（出货率、典型赏金区间）

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 权威公开源：PayloadsAllTheThings / PortSwigger Web Security Academy / HackTricks / OWASP

---

## 1. 触发信号

（什么现象 / 入口信号 → 路由到这个 playbook）

## 2. 高频入口点

（参数名 / 路径 / Header，尽量标注统计来源；无统计就不编数字）

## 3. 探测顺序（从最无害 → 最有杀伤力）

分步，每步说明「观察什么、什么算命中、不命中怎么降级」。

## 4. Payload 区（每条标注出处）

每条 payload 后标注出处，如 `[PayloadsAllTheThings]` / `[PortSwigger]` / `[HackTricks]` / `[本地 src-hunter]`。无出处不写入。

### 4.1 基础探测
### 4.2 数据提取 / 进阶
### 4.3 Bypass 矩阵

## 5. 工具用法

sqlmap / nuclei / ffuf / 手工等精确命令与参数。

## 6. 证据要求

什么算「已确认」；必须保存 HTTP 包 / 截图 / 延时数据；CVSS 参考向量。

**证据三件套（缺 baseline 只能算「候选 / 待验证」，放报告附录·待验证项，不进漏洞详情）**：

- `baseline`：同参数、同身份的**正常对照**请求与响应（证明"这不是它本来的行为"）
- `proof`：触发漏洞的完整请求/响应原文
- `verification`：换参数位置 / 换身份 / 换路径的**独立**第二次触发

**关联纪律**：**不得用"同一个域名 / 同一时间"推定包与结论的关联**；取不到对照就写 `N/A + 原因`，不许用可疑包凑数。

## 7. 合规边界 / 不要做的事

禁破坏性操作、脱敏要求、最小数据原则。
