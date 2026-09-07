# 国产组件指纹 + 高危默认路径 + 高频参数

> 取材改编自 [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)（数据基于 WooYun 真实案例统计）。指纹是「入口」，不是「漏洞」——命中后仍需走对应 playbook 证明利用。

## 1. 国产 OA / 中间件指纹

### 1.1 致远 OA（Seeyon）
```
HTTP: Server: SEEYON-OA / X-Powered-By: SEEYON
路径: /seeyon/  /seeyon/main.do  /seeyon/management/index.jsp
RCE 端点: /seeyon/htmlofficeservlet
日志泄露: /ctp.log（23 例命中）/seeyon/logs/ctp.log
页面: <title>致远协同管理软件</title> / COMMON.NEED_LOGIN / ctp.*
```

### 1.2 通达 OA（Tongda）
```
路径: /general/  /general/login.php  /mobile/auth_mobi.php  /ispirit/  /Pda/
RCE 历史: /ispirit/interface/gateway.php
页面: <title>通达OA</title> / Set-Cookie: PHPSESSID
```

### 1.3 万户 ezOffice（Wanhu）
```
路径: /defaultroot/  /defaultroot/login.jsp
上传: /defaultroot/dragpage/upload.jsp  /defaultroot/upload.jsp
泄露: /defaultroot/codesettree.jsp
页面: <title>万户ezOFFICE</title>
```

### 1.4 泛微 e-cology / e-office（Weaver）
```
路径: /login/Login.jsp  /weaver/  /mobile/  /api/  /workflow/
RCE 端点: /weaver/bsh.servlet.BshServlet（BeanShell）
Cookie: ecology_JSessionId
```

### 1.5 用友 / 金蝶 / 蓝凌
```
用友 NC: /nc/  /nc/servlet/  /portal/   <title>用友NC</title>
用友协作: /oaerp/  /oaerp/ui/sync/excelUpload.jsp（任意上传）
金蝶 GSiS/EAS: /kdgs/  /kdgs/core/upload/  /eas/  KingdeeApp/kdgs
蓝凌 LandrayOA: /sys/login/login.do  /sys/web/index.jsp
```

### 1.6 国产中间件 / 框架
```
Druid: /druid/index.html  /druid/sql.html  <title>Druid</title>
Nacos: /nacos/  /nacos/v1/auth/users
XXL-JOB: /xxl-job-admin/  <title>任务调度中心</title>
Apollo: /portal/  /eureka/apps
SkyWalking: /graphql  <title>SkyWalking</title>
RuoYi/JeecgBoot: /login  /system/user  /jeecg-boot/  ruoyi/jeecg-boot
Dubbo Admin: /dubbo-admin/
```

## 2. 国产高危默认路径

### 2.1 OA 上传 / 注入入口
| 路径 | 系统 | 类型 |
|---|---|---|
| `/seeyon/htmlofficeservlet` | 致远 | RCE |
| `/weaver/bsh.servlet.BshServlet` | 泛微 | RCE |
| `/ispirit/interface/gateway.php` | 通达 | RCE（历史）|
| `/mobile/auth_mobi.php` | 通达 | 任意用户登录 |
| `/defaultroot/dragpage/upload.jsp` | 万户 | 任意上传 |
| `/oaerp/ui/sync/excelUpload.jsp` | 用友 | 任意上传 |
| `/kdgs/core/upload/upload.jsp` | 金蝶 | 任意上传 |

### 2.2 富文本编辑器（占文件上传案例 42%）
```
FCKeditor（48%）: /FCKeditor/editor/filemanager/browser/default/connectors/test.html
                 /FCKeditor/editor/filemanager/upload/test.html  /FCKeditor/UserFiles/
eWebEditor（28%）: /ewebeditor/admin/default.jsp  /ewebeditor/php/upload.php
UEditor（12%）: /ueditor/controller.jsp?action=config  /ueditor/php/controller.php
KindEditor（8%）: /kindeditor/php/upload_json.php  /kindeditor/jsp/upload_json.jsp
```

### 2.3 信息泄露专用路径（按命中率）
```
版本控制（560 例）: /.git/config  /.git/HEAD  /.svn/entries  /.svn/wc.db
备份包（530 例）: /wwwroot.rar  /wwwroot.zip  /web.zip  /backup.zip  /db.sql.gz
SQL 备份（136 例）: /backup.sql  /database.sql  /dump.sql
配置备份（101 例）: /config.php.bak  /web.config.bak  /.env.bak
PHP 探针: /phpinfo.php  /info.php  /test.php  /1.php  /probe.php
日志（23 例 ctp.log）: /ctp.log  /debug.log  /error.log  /storage/logs/
.NET: /web.config  /App_Data/  /connectionStrings.config
```

### 2.4 中间件管理面（弱口令必扫）
```
Druid: /druid/index.html  /druid/login.html
Nacos: /nacos/  Apollo: /portal/
XXL-JOB: /xxl-job-admin/  DolphinScheduler: /dolphinscheduler/ui/
RuoYi: /admin/  /monitor/  /tool/swagger   JeecgBoot: /jeecg-boot/
```

### 2.5 网管 / 运营商 / 监控
```
华为: /web/  /eMaster/  /U2000/  /uweb/
中兴: /netnumen/  /web-portal/   烽火: /OTNM2000_ch/  /OTNM2000/
zabbix: /zabbix/  Grafana: /login  Prometheus: /metrics
蓝鲸智云: /console/  /uac/login   FineReport: /finereport/  /webroot/decision/
```

## 3. 高频参数字典（27,732 SQLi 案例提炼）

### 3.1 注入参数
```
id action aid typeid username act method fileName siteId systemID
PARENTTYPEID Channel sameName selfilePath token ObjName MODE Target
Title rd version newsid categoryid puid cmd trueName out_trade_no
```

### 3.2 业务逻辑 / 越权参数
```
密码重置: phone/mobile/username/code/smsCode/verifyCode/token/step
IDOR: id/uid/userId/oid/orderId/addrid/hotelid/file_id/msg_id/tenant_id/cust_id
支付: amount/price/total/fee/quantity/count/productId/sku/out_trade_no/mch_id/sign
授权: role/role_id/isAdmin/level/permissions/authorities
回调: url/redirect/redirect_uri/callback/jumpurl/next/continue/returnUrl
文件: fileName/file/path/dir/filepath/filename
电信: phone/mobile/acc_nbr/cust_id/cardId/iccid/imsi/imei
```

### 3.3 任意 X 越权 / 伪造内网字段
```
注册塞 admin: role=admin  is_admin=true  level=9  permissions=["*"]  authorities=["ROLE_ADMIN"]
登录改账号: username=admin  X-User-Id: 1  Cookie: userId=1;isAdmin=1
签名绕过: sign=""  sign=null  signature=00000000
伪造内网: X-Forwarded-For: 127.0.0.1  X-Real-IP  X-Originating-IP  X-Client-IP
```

## 4. 高频后台 / API 路径
```
后台: /admin/  /manage/  /houtai/  /admincp/  /console/  /admin/login
API 文档: /swagger-ui.html  /v2/api-docs  /v3/api-docs  /openapi.json
调试: /actuator/  /druid/  /test/  /dev/  /staging/
移动 H5: /wechat/  /weixin/  /mp/  /applet/  /miniapp/  /h5/  /mobile/  /wxLogin
```

## 5. 指纹检测一行命令
```bash
for path in /seeyon/ /general/login.php /defaultroot/login.jsp /login/Login.jsp \
            /oaerp/ /kdgs/ /sys/login/login.do /druid/index.html /nacos/ /xxl-job-admin/; do
  curl -s -o /dev/null -w "%{http_code} $path\n" http://target$path
done
```
