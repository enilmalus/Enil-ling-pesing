# 国产服务 / OA / CMS / 网络设备默认凭据

> 取材改编自 [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（数据基于 22,132 WooYun 真实案例 + 公开厂商手册）。区别于 SecLists 国际字典——本表面向国内 SRC 战场。
> 纪律：每条 ≤ 5 次尝试，单目标 ≤ 4 并发、≤ 50 次/小时；命中即停，仅截图证明可登录，不做写操作。

## 1. 国产 OA / 协同办公（核心战场）

| 系统 | 路径 | 默认凭据 |
|---|---|---|
| 致远 OA | `/seeyon/` | system/system；admin/123456；admin/000000 |
| 致远管理台 | `/seeyon/management/index.jsp` | 超级密码 `WLCCYBD@SEEYON` |
| 通达 OA | `/general/login.php` | admin/admin；hr/123456；jhadmin/123456 |
| 万户 ezOffice | `/defaultroot/login.jsp` | admin/123456 |
| 泛微 e-cology | `/login/Login.jsp` | sysadmin/1；admin/123456 |
| 用友协作 | `/oaerp/` | admin/123456 |
| 用友 NC | `/nc/` | system/1 |
| 金蝶 GSiS | `/kdgs/` | admin/888888 |
| 金蝶 Apusic | `/admin/login` | apusic/apusic |
| 蓝凌 LandrayOA | `/sys/login/login.do` | sysadmin/landray；admin/admin |

## 2. 国产中间件 / 数据库管理

| 服务 | 端口 | 路径 | 默认凭据 |
|---|---|---|---|
| Druid（阿里）| 8080 | `/druid/login.html` | admin/admin；`/druid/sql.html` 常无认证直连 |
| Nacos | 8848 | `/nacos/` | nacos/nacos |
| Apollo | 8080 | `/portal/` | apollo/admin |
| Sentinel | 8080 | `/` | sentinel/sentinel |
| XXL-JOB | 8080 | `/xxl-job-admin/` | admin/123456 |
| RuoYi | 80/8080 | `/login` | admin/admin123 |
| JeecgBoot | 8080 | `/jeecg-boot/` | jeecg/jeecg；admin/123456 |
| Eureka | 8761 | `/` | eureka/eureka |
| DolphinScheduler | 12345 | `/dolphinscheduler/ui/` | admin/dolphinscheduler123 |

## 3. 国产监控 / 工单 / 运维

| 系统 | 默认凭据 |
|---|---|
| 蓝鲸智云 | admin/blueking |
| 网御星云 SOC | admin/leadsec.com.cn |
| 安恒 EDR | admin/dbappsecurity |
| 锐捷云桌面 | admin/ruijie；admin/ruijie@123 |
| H3C iMC | admin/admin |
| 东软 NetEye | admin/neusoft |
| 360 天擎 | admin/360@admin |

## 4. 国产 CMS

| CMS | 默认凭据 |
|---|---|
| DedeCMS 织梦 | admin/admin |
| PHPCMS | phpcms/phpcms |
| 帝国 EmpireCMS | admin/admin |
| Discuz! | admin/admin；admin/123456 |
| ECshop | admin/admin |
| ThinkCMF | admin/123456 |
| MetInfo | admin/123456 |

## 5. 网络设备 / 网管（运营商场景）

| 设备 / 系统 | 默认凭据 |
|---|---|
| 华为 USG 防火墙 | admin/Admin@123 |
| 华为 iManager U2000 | admin/Changeme_123 |
| 华为家庭网关（电信）| telecomadmin/nE7jA%5m |
| 华为家庭网关（移动）| CMCCAdmin/aDm8H%MdA |
| 华为家庭网关（联通）| CUAdmin/CUAdmin |
| 中兴 ZXR10 | admin/zxr10 |
| 中兴 NetNumen | netnumen/netnumen |
| 烽火 OTNM2000 | admin/admin |
| 深信服 SSL VPN | admin/admin；admin/sangfor |
| 锐捷 | admin/admin |
| 飞塔 FortiGate | admin/空；admin/fortinet |

## 6. 国产数据库 / 缓存

| 服务 | 端口 | 默认凭据 |
|---|---|---|
| 达梦 DM | 5236 | SYSDBA/SYSDBA |
| 人大金仓 KingbaseES | 54321 | system/123456 |
| 神舟通用 OSCAR | 2003 | SYSDBA/szoscar55 |
| 南大通用 GBase | 5258 | gbasedba/gbase20110531 |
| TDengine | 6030 | root/taosdata |
| RocketMQ Console | 8080 | admin/admin |

## 7. 摄像头 / 物联网

| 厂商 | 默认凭据 |
|---|---|
| 海康威视 | admin/12345 |
| 大华 | admin/admin |
| 宇视 | admin/123456 |
| 雄迈 | admin/空 |
| 萤石（海康）| admin/Hik12345+ |

## 8. 堡垒机 / 跳板

| 堡垒机 | 默认凭据 |
|---|---|
| JumpServer | admin/admin |
| 齐治 | shterm/shterm |
| 帕拉迪 | admin/admin |

## 9. 使用流程模板

```bash
# 1. 端口指纹
nmap -sV -p 80,443,8080,8848,8761,12345,12800,8443,7001 target
# 2. 路径指纹（先判断厂商再定向爆破，别无脑撒全字典）
curl -s http://target/ | grep -iE "(seeyon|tongda|weaver|yongyou|kingdee|landray|jeecg|ruoyi|nacos|druid)"
# 3. 命中后只跑该厂商字典
hydra -l <user> -P <vendor-pass>.txt -t 4 -W 2 target http-post-form "..."
# 4. 命中即停 + 截图 + 不进入业务操作
```
