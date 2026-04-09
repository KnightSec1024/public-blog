# 云原生安全
## 学习建议
- **每天2-3小时**，按分类顺序学习  
- **动手实践**：使用 kind 搭建本地 K8s 环境，配合 Kubernetes Goat 进行实验  
- **结合自身优势**：每学一个知识点，思考“如果用代码审计视角，我会关注什么”
---

| 阶段 | 学习重点（关键词） | 核心解决问题（面试必考） | 专家级回答套路（话术指引） | 关联你的背景
-- | -- | -- | -- | --
Day 1: K8s与容器安全 | RBAC, Network Policy, Admission Controller, 容器逃逸 | 如何在动态集群实现微隔离？如果Pod被破如何防止横向移动？ | “我不看物理防火墙，我通过代码定义网络策略实现零信任隔离。” | 将华为“物理/子网隔离”经验映射到“K8s 命名空间隔离”。
Day 2: DevSecOps流水线 | SAST/DAST/IAST, 镜像扫描(Trivy), CI/CD集成 | 如何在不影响研发效率的前提下，将安全工具嵌入流水线？ | “安全不是阻断开发，而是**‘左移’**。通过增量扫描降低80%的干扰。” | 结合你在互金公司推行自动化代码审计流程的实战经验。
Day 3: API安全与鉴权 | OAuth2, JWT, BOLA/IDOR(越权), API Gateway | 如何解决移动端交互中的逻辑漏洞？如何管理海量API密钥？ | “解决越权不能靠人工，要靠**‘对象级鉴权框架’**和统一身份校验。” | 发挥你4年Java/C++审计对逻辑漏洞（如越权、绕过）的敏感度。
Day 4: 攻防对抗与防御 | 红蓝对抗, Sidecar卸载, 运行时监控(HIDS/RASP) | 如果发生高并发下的安全性能冲突（如脱敏），如何架构设计？ | “利用Sidecar异步模式实现安全能力与业务解耦，确保交易零延迟。” | 运用我们在对话中讨论的“异步Ring Buffer”和“Sidecar”折中方案。
Day 5: 案例包装与复盘 | 大厂方法论, SDLC治理, 跨团队推动 | 40岁资深专家，如何证明你的“架构力”高于年轻人？ | “我提供的是**‘确定性’**。从华为严谨流程到互联网敏捷安全，我能主导体系化建设。” | 整理2个最能体现“复杂问题解决能力”的华为或互金项目案例。



---

## 第1天：云安全基础 & 云原生概念

<img width="826" height="606" alt="image" src="https://github.com/user-attachments/assets/5f565ac8-12e6-4bf1-874c-84188684fec5" />


### 1.1 RBAC and SA（Service Account）
**RBAC（基于角色的访问控制）** 是云原生安全体系的权限管理核心。简单来说，它让你能定义“谁（主体）能对什么（资源）执行哪些操作（动词）”，并且通过“角色”这个中间层来批量管理权限，而不是给每个人单独授权

在k8s中，只有2中用户类型：人类用户、服务用户
* **Service Account：**是 Kubernetes 中用于 Pod 身份**认证**的账户，让 Pod 能够安全地与 API Server 通信
* **RBAC：**是 Kubernetes 的**授权机制**，用于控制用户或服务账户对集群资源的访问权限


|概念 | 含义 | 示例
-- | -- | --
主体 | 发起操作的人或程序 | 用户"张三"、Pod "nginx-123"
角色 | 一组权限的集合 | “数据库管理员”、“应用只读者”
授权 | 将角色授予主体 | 把“数据库管理员”角色授予“张三”
作用域 | 角色生效的范围 | 整个集群、某个命名空间


Kubernetes的RBAC API是云原生中最典型的RBAC实现，由四个资源对象组成：

|K8s对象 | 作用 | 关系
-- | -- | --
Role | 定义命名空间内的权限 | “能读写default命名空间中的Pod”
ClusterRole | 定义集群级别的权限 | “能列出所有命名空间的Node”
RoleBinding | 把Role授予用户/ServiceAccount | “把运维Role绑定给张三”
ClusterRoleBinding | 把ClusterRole授予用户/ServiceAccount | “把集群管理员权限绑定给李四”

通俗理解：

```
┌─────────────────────────────────────────────────────────┐
│  没有 RBAC：                                             │
│  ┌──────┐                                               │
│  │ 张三 │ ──→ 拥有所有权限（可以删除任何东西）             │
│  └──────┘                                               │
│  ┌──────┐                                               │
│  │ 李四 │ ──→ 拥有所有权限（也可以删除任何东西）           │
│  └──────┘                                               │
├─────────────────────────────────────────────────────────┤
│  有 RBAC：                                               │
│                                                         │
│  ┌──────────┐        ┌──────────┐        ┌───────────┐ │
│  │   角色    │ ────→  │  绑定    │ ←────  │  用户/SA   │ │
│  │ (Role)   │        │(Binding) │        │           │ │
│  └──────────┘        └──────────┘        └───────────┘ │
│       ↓                                                │
│  定义权限：可以读 Pod、不能删 Pod                         │
└─────────────────────────────────────────────────────────┘
```

| 概念 | 作用 | 范围
-- | -- | --
Role | 定义一组权限（读、写、删等） | 单个命名空间
ClusterRole | 定义一组权限 | 整个集群
RoleBinding | 将 Role 绑定到用户/SA | 单个命名空间
ClusterRoleBinding | 将 ClusterRole 绑定到用户/SA | 整个集群

RBAC的工作流程：

```
┌─────────────────────────────────────────────────────────────────┐
│                         RBAC 工作流程                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 定义角色（Role/ClusterRole）                                 │
│     ┌─────────────────────────────────────────────────────┐     │
│     │ kind: Role                                           │     │
│     │ rules:                                               │     │
│     │ - apiGroups: [""]                                    │     │
│     │   resources: ["pods", "pods/log"]                    │     │
│     │   verbs: ["get", "list"]                             │     │
│     └─────────────────────────────────────────────────────┘     │
│                          ↓                                       │
│  2. 定义主体（User/ServiceAccount）                               │
│     ┌─────────────────────────────────────────────────────┐     │
│     │ ServiceAccount: my-app-sa                            │     │
│     └─────────────────────────────────────────────────────┘     │
│                          ↓                                       │
│  3. 绑定（RoleBinding）                                          │
│     ┌─────────────────────────────────────────────────────┐     │
│     │ kind: RoleBinding                                    │     │
│     │ subjects:                                            │     │
│     │ - kind: ServiceAccount                               │     │
│     │   name: my-app-sa                                    │     │
│     │ roleRef:                                             │     │
│     │   kind: Role                                         │     │
│     │   name: pod-reader                                   │     │
│     └─────────────────────────────────────────────────────┘     │
│                          ↓                                       │
│  4. 生效：my-app-sa 可以 get/list pods，但不能 delete            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

```
问题场景：
┌─────────────────────────────────────────────────────────┐
│  1. 开发者需要查看 Pod 日志，但不能删除 Pod               │
│  2. CI/CD 只需要创建/更新 Deployment，不能访问 Secret    │
│  3. 监控系统只需要读取 Metrics，不能修改任何资源          │
│  4. 不同团队只能访问自己的命名空间                       │
│  5. 审计人员只能读取，不能写入                          │
└─────────────────────────────────────────────────────────┘
```
**RBAC 实现了最小权限原则**，每个人/服务只拥有完成工作所需的最小权限。

**ServiceAccount（服务账户）** 是 Kubernetes 中用于 Pod 身份认证的账户，让 Pod 能够安全地与 API Server 通信。

通俗的理解

```
┌─────────────────────────────────────────────────────────┐
│  人 vs 服务                                              │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ UserAccount（人）                                │   │
│  │ - 管理员、开发者、运维人员                        │   │
│  │ - 通过 kubectl 操作集群                          │   │
│  │ - 凭证：kubeconfig、证书、token                  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ ServiceAccount（服务/程序）                      │   │
│  │ - Pod 里的应用（如 CI/CD、监控、日志采集）        │   │
│  │ - 通过 REST API 操作集群                         │   │
│  │ - 凭证：自动挂载的 Token                         │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

| 特征 | 说明
-- | --
自动创建 | 每个命名空间默认有一个 default ServiceAccount
自动挂载 | Pod 创建时自动挂载 token 到 /var/run/secrets/kubernetes.io/serviceaccount
可自定义 | 可以创建多个 ServiceAccount，配置不同权限
与 RBAC 配合 | 通过 RoleBinding 赋予权限

工作流程：

```
┌─────────────────────────────────────────────────────────────────┐
│                    ServiceAccount 工作流程                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 创建 ServiceAccount                                          │
│     kubectl create sa my-sa                                      │
│                          ↓                                       │
│  2. Kubernetes 自动创建对应的 Secret（包含 Token）                │
│     kubectl get secret | grep my-sa                              │
│                          ↓                                       │
│  3. 创建 Pod 时指定 ServiceAccount                                │
│     spec:                                                        │
│       serviceAccountName: my-sa                                  │
│                          ↓                                       │
│  4. Kubernetes 自动将 Token 挂载到 Pod                            │
│     /var/run/secrets/kubernetes.io/serviceaccount/               │
│                          ↓                                       │
│  5. Pod 内应用读取 Token，访问 API Server                         │
│     curl -H "Authorization: Bearer $(cat token)" ...             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

RBAC与Service Account关系图

```
┌─────────────────────────────────────────────────────────────────┐
│                         Kubernetes API Server                    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                     认证 (Authentication)                   │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │ │
│  │  │   证书认证    │  │   Token认证   │  │  匿名认证    │     │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘     │ │
│  │         ↑                 ↑                                │ │
│  │    UserAccount     ServiceAccount                          │ │
│  │    (kubectl)       (Pod 内应用)                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              ↓                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                     授权 (Authorization)                    │ │
│  │                                                             │ │
│  │   Identity (用户/SA) ──→ Role/ClusterRole ──→ 权限          │ │
│  │                                                             │ │
│  │   "system:serviceaccount:default:my-sa"                    │ │
│  │              ↓                                             │ │
│  │   RoleBinding → Role → verbs: [get, list], resources: [pods]│ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

| 关系 | 说明
-- | --
ServiceAccount 是主体 | RBAC 中的"谁"，就是 User 或 ServiceAccount
RBAC 是规则 | 定义 ServiceAccount 能做什么、不能做什么
缺一不可 | 没有 ServiceAccount，Pod 无法认证；没有 RBAC，认证了也没有权限


来看一个典型的配置：

```
# 1. 定义一个Role：只读Pod
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: 
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]

---
# 2. 把Role授予ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: 
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: my-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

> "RBAC 和 ServiceAccount 是 Kubernetes 权限体系的两大核心。ServiceAccount 解决'是谁'的问题，为 Pod 提供身份认证；RBAC 解决'能做什么'的问题，控制对资源的访问权限。
> 工作原理是：Pod 创建时自动挂载 ServiceAccount 的 Token，访问 API Server 时携带 Token 进行认证；API Server 提取 ServiceAccount 名称后，通过 RBAC 规则检查是否有权限执行操作。
> 它们共同实现了最小权限原则：每个服务只拥有完成工作所需的最小权限。例如监控系统只能读 Pod，CI/CD 只能更新 Deployment，不同团队只能访问自己的命名空间。
> 安全建议：避免使用 default ServiceAccount，为每个应用创建专用 SA；使用 Role 而不是 ClusterRole；定期审计权限配置；必要时禁用自动挂载。"

> 攻击路径：窃取Pod内Token-> 访问API Server-> 枚举权限 -> 创建特权Pod逃逸
> 防御要点：
> - automountServiceAccountToken: false # 非必要不挂载
> - 使用Bound Service Account Token
> - 审计kubectl exec/logs等高危操作




### 1.2 Network Policy

Network Policy 是 Kubernetes 的网络防火墙，用于控制 Pod 之间、Pod 与外部之间的网络流量，包括：

* 入站规则（Ingress）：谁可以访问这个 Pod
* 出站规则（Egress）：这个 Pod 可以访问谁

**注意：Network Policy 工作在 L3/L4，是传统的网络防火墙，不是应用层防火墙（如 WAF）**


#### 实现机制

```
创建 Network Policy
        ↓
API Server 存储到 etcd
        ↓
网络插件（CNI）Watch 变化
        ↓
CNI 将规则转换为底层实现
        ↓
┌─────────────────────────────────────────────┐
│  底层实现方式（取决于 CNI 插件）              │
│                                             │
│  Calico：iptables 规则                      │
│  Cilium：eBPF 程序                          │
│  Weave：iptables + 用户态路由                │
│  Antrea：OpenFlow 流表                      │
└─────────────────────────────────────────────┘
        ↓
流量经过时被过滤
```

"Network Policy 是 Kubernetes 的网络防火墙，工作在 L3/L4 层，通过 CNI 插件（如 Calico、Cilium）将规则转换为 iptables 或 eBPF 程序来实现。

它的核心目的是实现网络最小权限：只允许必要的通信，拒绝所有其他。这**解决了 Pod 之间默认全互通的安全问题，有效防止横向移动攻击**。

主要应用场景包括：**分层架构隔离（前端只能访问后端）、多租户隔离（租户间不能通信）、数据库访问控制（只允许特定应用访问）。**

使用方式是定义 podSelector 选择目标 Pod，然后配置 ingress（入站）和 egress（出站）规则，可以基于 Pod 标签、命名空间标签、IP 块来控制。

需要注意：Network Policy 需要 CNI 支持（Flannel 不支持），且不能控制 L7 内容（如 HTTP 路径）。生产环境建议配合 Cilium 使用 eBPF 模式，性能更好且支持 L7 策略。"


通过下面的例子来理解networl policy的配置和作用

```
# 只允许前端访问后端，不允许后端访问前端
---
# 后端 Pod 的 NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - port: 8080
---
# 前端 Pod 的 NetworkPolicy（禁止出站到其他）
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
spec:
  podSelector:
    matchLabels:
      tier: frontend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - port: 8080
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - port: 53
      protocol: UDP
```

#### 如何设计一个分层网络策略

```
- 数据层Pod：仅允许API层访问，拒绝直接出网
- API层Pod：允许入站443，出站仅开放至数据库和消息队列
- 监控Sidecar：允许出站到prometheus，禁止访问业务Pod
```

### 1.3 Admission Controller


### 1.4 容器逃逸

攻击者从容器内部突破隔离边界，获得宿主机（或其他容器）的访问权限
#### 危害

攻击者获得宿主机权限 → 控制所有容器

窃取宿主机上的敏感信息（kubeconfig、云凭证）

横向移动到 K8s 集群其他节点
#### 原因

1）配置不当

* 特权容器：拥有几乎与宿主机相同的root权限
* 挂载docker socket：容器内可以控制docker创建特权容器
* 挂载宿主机敏感目录：可以修改宿主机文件（/etc,/root）
* hostPID：true：可以看到宿主机进程，注入恶意代码
* hostNetwork:true：可以绕过网络隔离，访问宿主机网络

```
# 危险挂载示例：
# /var/run/docker.sock是docker守护进程在unix域的套接字，拥有root权限
# 允许容器内的程序通过这个文件与宿主机的 Docker 引擎通信
docker run -v /var/run/docker.sock:/var/run/docker.sock ...

# 特权模式 + 根目录挂载（逃逸与接管）
# --privileged：特权模式（容器不再受 AppArmor、Seccomp 等安全框架的限制，可以看到宿主机的所有硬件设备）
# -v /:/host：根目录挂载（将宿主机的真实根目录 / 映射到容器内部的 /host 路径下，容器内进程现在可以读写宿主机的敏感文件）
# chroot /host：将当前进程的根目录切换为 /host，在容器内的 Shell 看起来就像直接登录在宿主机上一样
docker run --privileged -v /:/host alpine chroot /host
```

2）内核漏洞

容器不是虚拟机，没有独立内核，也就是说所有容器共享宿主机的内核。如果内核有漏洞，任何容器都可以利用它，突破命名空间隔离。

* namespace漏洞：内核空间隔离上存在漏洞
* cgroup漏洞：资源隔离的绕过
* 系统调用漏洞：特定syscall可逃逸

3）容器运行时漏洞

|运行时 | 历史漏洞
-- | --
Docker | CVE-2019-13139
containerd | CVE-2020-15257
runc | CVE-2019-5736、CVE-2024-21626

#### 什么是Pod Security Standards (PSS)

PSS是Kubernetes 官方提供的内置的、开箱即用的Pod 安全配置策略，定义了三个级别的安全策略，用于限制 Pod 的敏感行为


|  级别 | 名称 | 适用场景 | 严格程度
-- | -- | -- | --
Privileged | 无限制 | 系统组件、网络插件 | 最宽松
Baseline | 基线 | 一般业务应用 | 中等
Restricted | 严格限制 | 敏感业务、多租户场景 | 最严格

各级别的控制内容如下：

| 控制项 | Privileged | Baseline | Restricted
-- | -- | -- | --
特权容器 | ✅ 允许 | ❌ 禁止 | ❌ 禁止
宿主机命名空间 | ✅ 允许 | ❌ 禁止 | ❌ 禁止
危险 Capabilities | ✅ 允许 | ❌ 禁止 | ❌ 禁止
非 root 运行 | ⚠️ 不强制 | ⚠️ 不强制 | ✅ 强制
只读根文件系统 | ⚠️ 不强制 | ⚠️ 不强制 | ✅ 强制
Seccomp 配置 | ⚠️ 不强制 | ⚠️ 不强制 | ✅ 强制

ymal举例：在namespace的yaml配置文件中定义了安全标签为baseline

```
# 开发命名空间：宽松
apiVersion: v1
kind: Namespace
metadata:
  name: dev
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: baseline
    pod-security.kubernetes.io/warn: baseline
```
在尝试创建特权容器时将被拦截

```
# 尝试创建特权容器
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: default
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true   # 违反 Baseline/Restricted
```

```
Error: pods "bad-pod" is forbidden: violates PodSecurity "baseline:latest": 
privileged containers are not allowed
```

#### 什么是Security Context

Kubernetes 中用于定义 Pod 或容器运行时安全配置的字段，它决定了容器进程以什么权限、什么用户、什么能力运行

通过下面这个配置可以理解security context

```
# 创建符合 Restricted 的 Pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-good
  namespace: pss-test
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
EOF

# 应该成功创建
```
#### PSS和Security Context对比

| 对比项 | Security Context | Pod Security Standards
-- | -- | --
是什么 | Pod/容器的安全配置字段 | 命名空间级别的安全策略
谁配置 | 开发者/运维 | 集群管理员
作用时机 | Pod 定义时 | Pod 创建时（准入控制）
粒度 | 单个 Pod/容器 | 整个命名空间
关系 | 配置具体值 | 定义允许哪些值

---
## 第2天：容器安全

| 知识点分类 | 具体知识点 | 应用场景 | 解决的问题 | 学习资源 |
|-----------|-----------|---------|-----------|---------|
| 镜像安全 | 基础镜像漏洞、依赖库扫描、镜像签名 | CI/CD 阶段阻断不安全镜像 | 防止漏洞进入生产环境 | [Trivy 官方文档](https://trivy.dev/) |
| 容器运行时安全 | 特权容器、root 运行、capabilities 配置 | Pod 安全配置（Pod Security Standards） | 降低容器逃逸风险 | [K8s Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) |
| 容器逃逸 | 敏感挂载（hostPath）、特权模式、docker.sock 挂载 | 容器攻防演练、安全加固 | 理解攻击者如何突破容器 | [容器逃逸技术与防御](https://blog.aquasec.com/container-escape) |
| 容器安全工具 | Falco（运行时安全）、Clair（镜像扫描） | 容器环境异常行为监控、合规检查 | 实时检测入侵行为 | [Falco 快速入门](https://falco.org/docs/getting-started/) |


### 供应链与镜像安全

供应链攻击示意图
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        软件供应链攻击链                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  开发者A        开发者B        开源社区        镜像仓库        K8s集群    │
│     ↓              ↓              ↓              ↓              ↓        │
│  ┌──────┐      ┌──────┐      ┌──────┐      ┌──────┐      ┌──────┐      │
│  │ 代码 │ ──→  │ 依赖 │ ──→  │ 基础 │ ──→  │ 镜像 │ ──→  │ 运行 │      │
│  │ 仓库 │      │ 库   │      │ 镜像 │      │ 仓库 │      │ 环境 │      │
│  └──────┘      └──────┘      └──────┘      └──────┘      └──────┘      │
│     ↑              ↑              ↑              ↑              ↑        │
│  ┌──────┐      ┌──────┐      ┌──────┐      ┌──────┐      ┌──────┐      │
│  │硬编码│      │恶意  │      │基础  │      │镜像  │      │容器  │      │
│  │密钥  │      │包    │      │漏洞  │      │篡改  │      │逃逸  │      │
│  └──────┘      └──────┘      └──────┘      └──────┘      └──────┘      │
│                                                                          │
│  攻击者在任何一个环节植入恶意代码，最终都会影响到 K8s 集群                  │
└─────────────────────────────────────────────────────────────────────────┘
```

供应链安全的三个阶段


| 阶段 | 内容 | 风险
-- | -- | --
构建阶段 | 代码、依赖库、基础镜像 | 恶意代码注入、漏洞引入
分发阶段 | 镜像仓库、传输过程 | 镜像篡改、中间人攻击
运行阶段 | 容器运行时 | 漏洞利用、恶意行为

#### 镜像安全核心内容

##### 基础镜像安全
80% 的容器镜像使用的基础镜像包含已知漏洞

```
# 危险示例：使用 latest 标签，无法确定版本
FROM ubuntu:latest

# 安全示例：指定具体版本
FROM ubuntu:22.04@sha256:6123c...

# 更安全：使用精简镜像
FROM alpine:3.19
FROM gcr.io/distroless/base
FROM scratch  # 最安全，但需要静态编译
```
##### 依赖库安全

```
# 依赖库风险示例
FROM node:18
COPY package.json .
RUN npm install   # 可能安装带有漏洞或恶意代码的包

# 安全做法
FROM node:18
COPY package.json package-lock.json .
RUN npm ci       # 使用锁定文件，确保版本固定
RUN npm audit    # 检查漏洞
```
##### 镜像层安全
核心概念：Docker 镜像是分层构建的，每一层都是只读的。

```
# 查看镜像层（之前实验的 hidden-in-layers）
docker history madhuakula/k8s-goat-hidden-in-layers

# 输出显示每一层的操作
# ADD secret.txt /root/secret.txt   ← 即使后续删除，该层仍然存在
```

风险：敏感文件在某一层添加后，即使后续层删除，原始数据仍可通过 docker history 查看。

#### 安全实践

| 工具 | 特点 | 集成方式
-- | -- | --
Trivy | 快速、全面、无数据库 | CLI、CI/CD、K8s Operator
Clair | CoreOS 出品，历史悠久 | API 服务、Registries
Grype | 与 Syft 配合好 | CLI、CI/CD
Snyk | 商业产品，功能强大 | IDE、CI/CD、GitHub
Docker Scout | Docker 原生 | Docker Desktop、Docker Hub

**基础镜像选择策略**

| 使用官方镜像 | 减少恶意注入风险 | nginx:1.25（官方）vs someone/nginx:latest
-- | -- | --
固定版本标签 | 避免意外升级 | nginx:1.25 而不是 nginx:latest
使用摘要（digest） | 最确定的方式 | nginx@sha256:6123c...
使用精简镜像 | 减少攻击面 | alpine、distroless、scratch
定期更新 | 修复已知漏洞 | 每周更新基础镜像

DevSecOps流水线

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        安全的 CI/CD 流水线                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  代码提交 → SAST → 依赖扫描 → 镜像构建 → 镜像扫描 → 签名 → 部署           │
│     ↓         ↓         ↓         ↓         ↓         ↓         ↓       │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐       │
│  │GitHub│→│CodeQL│→│npm   │→│docker│→│Trivy │→│Cosign│→│kubect│       │
│  │      │ │      │ │audit │ │build │ │      │ │      │ │l     │       │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘       │
│                                                                          │
│  每一阶段发现问题都会阻断流水线                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

**Github Actions安全流水线示例**

```
# .github/workflows/secure-build.yaml
name: Secure Build

on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # 1. SAST：代码安全扫描
      - name: Run CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: python
      
      # 2. 依赖漏洞扫描
      - name: Scan dependencies
        run: |
          trivy fs --severity HIGH,CRITICAL .
          npm audit --audit-level=high
      
      # 3. 镜像构建
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      
      # 4. 镜像漏洞扫描
      - name: Scan image
        run: |
          trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:${{ github.sha }}
      
      # 5. 签名镜像
      - name: Sign image
        run: cosign sign -y myapp:${{ github.sha }}
      
      # 6. 部署（只有通过所有检查才执行）
      - name: Deploy to K8s
        run: kubectl set image deployment/myapp myapp=myapp:${{ github.sha }}
```

> 最佳实践
> * ❌ 不要使用 latest 标签
> * ✅ 使用官方镜像 + 摘要（digest）
> * ✅ 配置镜像拉取策略为 Always
> * ✅ 使用 npm ci 而不是 npm install
> * ✅ 锁定依赖版本（package-lock.json）
> * ✅ 使用私有 npm 仓库或代理
> * ✅ 镜像仓库启用认证和 TLS
> * ✅ 使用 Network Policy 限制访问
> * ✅ 启用镜像扫描和签名

> "K8s 供应链与镜像安全涵盖三个阶段：构建、分发、运行。
> 构建阶段：使用具体版本的基础镜像（避免 latest）、多阶段构建减小攻击面、非 root 用户运行、扫描依赖库漏洞。工具包括 Trivy、hadolint。
> 分发阶段：私有镜像仓库需认证，镜像签名（Cosign）确保完整性，传输加密（TLS）。在 K8s 中配置 imagePullSecrets 拉取私有镜像。
> 运行阶段：配置 imagePullPolicy: Always 确保使用最新安全补丁，通过准入控制器（Kyverno/OPA）强制镜像策略（禁止 latest、限制仓库地址），运行时用 Falco 监控异常行为。
> 生产环境建议：在 CI/CD 中集成镜像扫描，高危漏洞阻断发布；使用镜像签名和验证；定期扫描运行中的镜像；配置镜像策略强制执行。"

---

## 第3天：Kubernetes 安全（核心）

| 知识点分类 | 具体知识点 | 应用场景 | 解决的问题 | 学习资源 |
|-----------|-----------|---------|-----------|---------|
| API Server 安全 | 匿名访问、RBAC 配置、审计日志 | K8s 集群基线加固 | 防止未授权访问 API Server | [K8s API Server 安全](https://kubernetes.io/docs/concepts/security/api-server-security/) |
| RBAC 审计 | ServiceAccount 权限、RoleBinding 配置 | 权限最小化设计、权限滥用检测 | 避免过度授权导致横向移动 | [K8s RBAC 最佳实践](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) |
| 网络隔离 | Network Policy 配置、服务网格 mTLS | 微服务间访问控制 | 限制 Pod 间非法通信 | [Network Policy 示例](https://kubernetes.io/docs/concepts/services-networking/network-policies/) |
| 准入控制 | OPA/Gatekeeper、Kyverno | 强制安全策略（如禁止特权容器） | 确保部署的 Pod 符合安全基线 | [OPA Gatekeeper 入门](https://open-policy-agent.github.io/gatekeeper/website/docs/) |
| 常见攻击 | 滥用权限的 ServiceAccount、API Server 未授权访问、etcd 未加密 | 红蓝演练、漏洞挖掘 | 理解 K8s 集群薄弱点 | [Kubernetes 安全攻防指南](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Kubernetes_Security_Cheat_Sheet.md) |
### k8s的控制的控制平面
#### kube api-server
它是集群的“唯一门户”与“通信心脏”。

它的作用： 所有的操作（无论是 kubectl、Dashboard 还是集群内部组件通信）都必须调用 API Server。它负责请求的 认证（你是谁）、鉴权（你能干什么） 和 准入控制（你的请求合规吗）。

解决的问题： 解决通信无序和权限混乱。它确保了集群状态的修改是受控的、合法的，并且是唯一能读写数据库（etcd\）的组件。

如果没有它： 集群将变成“植物人”。你无法下达任何指令，节点之间无法同步状态，整个集群的控制链条彻底断裂


#### etcd (分布式键值数据库)
它是集群的“真理来源”与“记忆体”。

它的作用： 这是一个高可用的分布式数据库，存储了整个集群的所有配置数据和所有对象的状态（比如 Pod 跑在哪个 Node 上，Service 的 IP 是多少）。

解决的问题： 解决状态持久化和数据一致性。在分布式环境下，确保多台 Master 看到的集群数据是完全统一的。

如果没有它： 集群将彻底“失忆”。即便 Pod 还在运行，K8s 也不知道它们的存在，一旦重启或发生故障，没有任何数据可以用来恢复集群。

#### Scheduler (kube-scheduler)
它是集群的“资源精算师”与“分房经理”。

它的作用： 监视新创建的、还没有被分配到 Node 的 Pod。它会根据 Pod 的资源需求（CPU/内存）和 Node 的承载能力，选出一个最合适的 Node。

解决的问题： 解决负载均衡和资源最大化利用。它避免了某些 Node 挤死，而某些 Node 闲死的尴尬局面。

如果没有它： 新创建的 Pod 将永远处于 Pending 状态。除非你手动给每个 Pod 指定 Node（这回到了原始的手动运维时代），否则自动化调度将彻底停摆。

#### Controller Manager (kube-controller-manager)
它是集群的“大总管”与“纠错中心”。

它的作用： 它内部跑着很多“控制器”（如副本控制器、节点控制器）。它不停地做一件事：对比“期望状态”和“实际状态”。

解决的问题： 解决**自愈（Self-healing）**问题。比如你想要 3 个副本，现在挂了一个，控制器就会发现并触发补齐动作。

如果没有它： 集群将失去“自动化能力”。Pod 挂了就挂了，没人管；Node 掉线了，上面的任务也不会自动迁移。K8s 就变成了一个普通的容器启动器


组件名称 | 角色定位 | 核心逻辑 | 如果缺失的后果
-- | -- | -- | --
API Server | 门户/网关 | 认证 -> 鉴权 -> 准入 | 彻底瘫痪，无法管理
etcd | 数据库 | 存储所有状态与元数据 | 配置丢失，无法恢复
Scheduler | 调度员 | 过滤 (Filter) -> 打分 (Score) | 无法部署新业务
Controller Manager | 纠错员 | 观察 -> 对比 -> 调整 | 失去自愈，手动运维

</body></html><!--EndFragment-->
</body>
</html>
---

## 第4天：CI/CD 安全 & DevSecOps

| 知识点分类 | 具体知识点 | 应用场景 | 解决的问题 | 学习资源 |
|-----------|-----------|---------|-----------|---------|
| SAST/DAST 集成 | 将安全扫描嵌入 GitLab CI/Jenkins | 自动化安全测试 | 左移安全，快速发现代码缺陷 | [GitLab 安全扫描](https://docs.gitlab.com/ee/user/application_security/) |
| 镜像扫描集成 | Trivy 与 Harbor 对接 | 镜像仓库漏洞阻断 | 防止高危镜像部署 | [Harbor 漏洞扫描](https://goharbor.io/docs/2.10.0/administration/vulnerability-scanning/) |
| IaC 安全扫描 | Checkov、tfsec | K8s YAML、Terraform 代码扫描 | 避免基础设施配置缺陷 | [Checkov 入门](https://www.checkov.io/) |
| 供应链安全 | SBOM、SLSA 框架 | 组件依赖管理、供应链攻击防护 | 提升软件供应链可见性 | [SLSA 框架介绍](https://slsa.dev/) |

---

## 第5天：综合实战 & 面试话术打磨

| 知识点分类 | 具体知识点 | 应用场景 | 解决的问题 | 学习资源 |
|-----------|-----------|---------|-----------|---------|
| 综合实战 | Kubernetes Goat 场景演练 | 模拟真实攻防环境 | 将前四天知识落地 | [Kubernetes Goat GitHub](https://github.com/madhuakula/kubernetes-goat) |
| 云原生漏洞与代码审计 | 如何审计 Spring Boot 在 K8s 中的配置错误、环境变量泄露 | 结合自身 Java 审计经验，发现云原生应用风险 | 展示迁移能力 | [OWASP Kubernetes 安全审计清单](https://owasp.org/www-project-kubernetes-top-ten/) |
| 面试常见问题 | “你如何设计 K8s 安全基线？”、“容器逃逸的检测与响应流程” | 面试应答 | 将学习内容转化为流利话术 | 参考面试经验文章：[K8s 安全面试题](https://www.magalix.com/blog/kubernetes-security-interview-questions) |
| 总结与复盘 | 绘制自己的 K8s 安全架构图 | 面试时展示 | 巩固知识、呈现体系化理解 | 根据我们之前提供的四层架构图进行手绘练习 |

---



---

## 补充资源（常用工具速览）

| 工具 | 用途 | 学习链接 |
|-----|------|---------|
| Trivy | 镜像漏洞扫描 | [trivy.dev](https://trivy.dev) |
| Falco | 运行时安全监控 | [falco.org](https://falco.org) |
| OPA/Gatekeeper | 策略即代码 | [open-policy-agent.github.io](https://open-policy-agent.github.io/gatekeeper) |
| Checkov | IaC 安全扫描 | [checkov.io](https://www.checkov.io) |
| kube-bench | CIS 基线检查 | [github.com/aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) |
| kube-hunter | 集群渗透测试 | [github.com/aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) |
| Kubescape | 综合安全扫描 | [github.com/kubescape/kubescape](https://github.com/kubescape/kubescape) |

---
