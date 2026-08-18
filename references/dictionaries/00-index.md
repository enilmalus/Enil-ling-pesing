# 字典 / 指纹 / 凭据合集

> 区别于国际字典（SecLists / H1）——本目录是**国产 SRC 战场**专用弹药：CN 厂商默认凭据、CN 中间件 / OA / CMS 指纹与路径、CN 高频参数。
> 数据来源：改编自[MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（其数据基于 WooYun 真实案例 + 公开厂商手册），精简后入库。

## 文件目录

| 文件 | 用途 |
|------|------|
| `chinese-srcfingerprints.md` | 国产 OA / 中间件 / 编辑器指纹 + 高危默认路径 + 高频参数 |
| `default-credentials-cn.md` | 国产 OA / CMS / 中间件 / 网管 / 摄像头默认凭据 |

## 何时读（在 SKILL.md 路由中命中即 Read）

| 命中信号 | Read |
|---|---|
| 指纹含 `weaver/seeyon/tongda/landray/yongyou/kingdee/hikvision/dahua` | `chinese-srcfingerprints.md` |
| 弱口令 / 默认配置 / 后台登录框 | `default-credentials-cn.md` + `chinese-srcfingerprints.md` §2 |
| 需要高频参数 fuzz 字典 | `chinese-srcfingerprints.md` §3 |

## 使用纪律（红线）

1. **指纹 ≠ 漏洞**：识别出致远 OA 不等于直接打 RCE，仍需走对应 playbook 走完证据链。
2. **限速**：爆破单目标 ≤ 4 并发、≤ 50 次/小时；路径探测 ≤ 5 rps。SRC 对高频爆破零容忍，国产风控更敏感。
3. **命中即停**：默认凭据命中后，仅截图登录界面 + 看到核心功能名称即停，**不做任何写操作**（建用户 / 上传 / 跑命令）。
4. **授权边界**：政府 / 国企 / 银行 / 运营商属关键基础设施，无 SRC 授权不得使用本字典。
