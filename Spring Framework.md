# 一、先找感觉
## 1.1 参数绑定漏洞（攻击者多提交一个role=admin参数被后端接受）

```
用户提交表单时，攻击者可以多提交一些"不该提交"的字段，而这些字段会被自动绑定到对象中。

比如：
- 正常提交：username=张三&email=zhang@example.com
- 攻击者多提交：role=ADMIN
- 如果代码没限制，用户的 role 字段就被改成了 ADMIN
```

### 原理
Spring MVC的@ModuleAttribute 或 @RequsetBody会自动将HTTP请求参数绑定到Java对象的字段

**危险代码示例：**
```
@PostMapping("/user/update")
public String updateUser(@ModelAttribute User user) {
    // User 类有 id, username, email, role, isAdmin 等字段
    userService.update(user);
    return "success";
}
```

**攻击请求：**
```
POST /user/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=newName&email=new@email.com&role=ADMIN&isAdmin=true
```
**后果：** 攻击者成功将自己的 role 改成 ADMIN，实现越权。

> 审计方法
> 审计的时候注意查找@ModuleAttribute或@RequestBody
> 查看对应的实体类有哪些字段，是否涉及敏感字段，比如：role、isAdmin、permisson、balance等
> 是否有白名单限制，比如没有使用@InitBinder或@JsonIgnore
> 是否有DTO，比如直接使用了Entity而不是DTO


**安全代码示例：**

```
// 方案1：使用 DTO（推荐）
public class UserUpdateDTO {
    private String username;
    private String email;
    // 没有 role、isAdmin 字段
}

@PostMapping("/user/update")
public String updateUser(@RequestBody UserUpdateDTO dto) {
    // 只更新允许的字段
}

// 方案2：使用 @InitBinder 设置白名单
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("username", "email");  // 只允许这两个字段
}

// 方案3：使用 @JsonIgnore 忽略敏感字段
public class User {
    private String username;
    private String email;
    
    @JsonIgnore  // JSON 反序列化时忽略
    private String role;
}
```

> *** 为何不能用Entity，必须用DTO？
> | 问法           | 答案                              |
> | :----------- | :------------------------------ |
> | 为什么审计强制 DTO？ | **Entity = 数据库全暴露，DTO = 白名单隔离** |
> | DTO 核心作用？    | **"输入过滤 + 输出脱敏 + 业务隔离"**        |
> | 终极原则？        | **"外部参数永不直接进数据库，必须经过 DTO 洗一遍"** |

## 1.2 权限注解配置错误（@permitALL的顺序、注解中拼接userInput参数等）

**通俗理解：**

```
开发者想给接口加上权限控制，但配置写错了，导致：
- 本应只有管理员能访问的接口，普通用户也能访问
- 或者所有人都访问不了（500 错误）
```

**原理：**

Spring Security 通过注解或配置类控制接口访问权限。 

常见注解： 


注解 | 作用 | 示例
-- | -- | --
@PreAuthorize | 方法执行前检查权限 | @PreAuthorize("hasRole('ADMIN')")
@PostAuthorize | 方法执行后检查权限 | @PostAuthorize("returnObject.username == authentication.name")
@Secured | 简单角色检查 | @Secured("ROLE_ADMIN")
@RolesAllowed | JSR-250 标准 | @RolesAllowed("ADMIN")

**危险代码示例1:配置顺序错误**
```
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/**").permitAll()      // ❌ 放行所有
            .antMatchers("/admin/**").hasRole("ADMIN");  // 永远不会执行
    }
}
```

**危险代码示例2:注解拼写错误**

```
@PreAuthorize("hasRole('ADMIN')")  // ✅ 正确
@PreAuthorize("hasAuthority('ADMIN')")  // ❌ 不同！需要 ROLE_ADMIN 前缀
```

**危险代码示例3:SpEL注入**
```
@PreAuthorize("hasRole('" + userInput + "')")  // ❌ 拼接用户输入
```

> **审计检查清单：**
> | 检查项 | 危险信号
> -- | --
> 配置顺序 | permitAll() 放在 hasRole() 前面
> 注解表达式 | 字符串拼接用户输入
> hasRole vs hasAuthority | 混淆 ROLE_ 前缀
> 默认配置 | 没有覆盖默认的 permitAll
> 异常处理 | 权限不足时返回敏感信息

## 1.3 SpEL表达式注入（注解使用SpEL但直接拼接了用户输入）

**通俗解释：**

> SpEL = Spring Expression Language，Spring 框架内置的"动态脚本引擎"；开发者写表达式字符串，Spring 解析执行，**解决"配置里写代码"的问题**。
> | 问题        | 不用 SpEL             | 用 SpEL                                               |
> | :-------- | :------------------ | :--------------------------------------------------- |
> | 配置想写"动态值" | 只能写死，或写 Java 代码重新打包 | `#{T(java.time.LocalDate).now()}` 直接写进 XML/YAML      |
> | 权限规则经常变   | 改代码 → 重新编译 → 重新部署   | `@PreAuthorize` 表达式放数据库，热更新                          |
> | 缓存键规则复杂   | 代码里硬编码字符串拼接         | `#user.dept.id + ':' + #user.id` 一行表达式               |
> | 条件装配太死板   | 只能按 profile 分       | `#{systemEnvironment['FEATURE_FLAG'] == 'on'}` 运行时判断 |

```
SpEL 是 Spring 的表达式语言，可以动态计算值。
但如果把用户输入直接拼接到表达式中，攻击者可以注入恶意代码。

就像 SQL 注入，但这次注入的是 SpEL 表达式。
```

**原理：**
SpEL 支持调用 Java 方法、访问属性、执行静态方法。

**危险代码示例1:@PreAuthorize拼接**
```
@PreAuthorize("hasRole('" + userInput + "')")
// 用户输入：T(java.lang.Runtime).exec('calc')
// 最终表达式：hasRole('T(java.lang.Runtime).exec('calc')')
```

**危险示例代码2:@Value注解**
```
@Value("#{systemProperties['user.' + userInput]}")
private String userProperty;
```

**危险示例代码3:直接使用SpEL解析器**
```
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // 直接解析用户输入
Object result = exp.getValue();
```

**攻击Payload示例：**
```
// 执行系统命令
T(java.lang.Runtime).getRuntime().exec('calc')

// 读取文件
new java.io.BufferedReader(new java.io.FileReader('/etc/passwd')).readLine()

// 获取系统属性
T(java.lang.System).getProperty('os.name')

// 调用静态方法
T(java.lang.System).exit(0)
```

## 1.4 关于JPA
 **通俗解释：**
> **JPA(Java Persistence API) 是一套基于 ORM（对象关系映射）的标准规范**。简单来说，它的目的是让你像操作 Java 对象一样操作数据库，而不需要频繁编写原生的 SQL 语句。常见的 Hibernate、EclipseLink 都是 JPA 的具体实现。
> 核心逻辑： 通过 @Entity 注解将 Java 类映射到数据库表，通过 EntityManager 进行增删改查。

### JPA的防SQL注入
JPA 本身确实具备很强的防注入能力，但前提是“正确使用”。
JPA 防御 SQL 注入的核心原理是 参数化查询 (Parameterized Queries)。

**安全的写法：参数绑定:**

```
// ✅ 安全：使用参数占位符
String jpql = "SELECT u FROM User u WHERE u.username = :name";
TypedQuery<User> query = entityManager.createQuery(jpql, User.class);
query.setParameter("name", userInput); // 在这种模式下，userInput 只会被当做纯字符串数据处理，而不会被解释为 SQL 命令的一部分
```

但是如果研发人员没有按照规范要求使用JPA的话，依然可能存在SQL注入的问题，例如：
```
// ❌ 危险：手动拼接字符串
String userInput = "admin' OR '1'='1";
String jpql = "SELECT u FROM User u WHERE u.username = '" + userInput + "'";
// 这里的 userInput 会被当做命令执行，导致绕过登录
```

**安全建议：**

| 特性 | 安全做法 (Recommended) | 危险做法 (Anti-pattern)
-- | -- | --
查询方式 | 使用 Criteria API 或参数化 JPQL | 手动字符串拼接串 (+ 号连接)
参数处理 | query.setParameter("key", value) | 直接将变量放入 SQL/JPQL 字符串中
复杂查询 | 使用 Specification 或 QueryDSL | 拼接复杂的 Native SQL
输入校验 | 对字段名、排序规则进行白名单校验 | 直接透传前端传入的排序字段字符串

## 1.5 关于越权
这里提到一个关于Spring Security的高级用法：

```
@PreAuthorize("#id == authentication.principal.userId") 
```

这是一种非常标准的声明式安全方案，针对**水平越权（Horizontal Privilege Escalation）**有着极强的防御效果

authentication.principal.userId 是用户在登录阶段（Authentication）经由系统核实后存入 SecurityContext 的信息，是不可伪造的。
当带有id参数的请求到达时，Spring 利用 SpEL（Spring Expression Language）将路径参数中的 id（即 101）与当前登录用户的 userId 进行实时比对。


# 二、Spring框架的审计
## 2.1 基础概念
### bean
bean是一个规范化的类，成员都是private，且具有一个无参构造，有getter/setter，由spring 容器统一管理，通过反射实现对象的创建。
现代的做法多是引入lombok框架组件，使用@Data注解实现编译后自动生成对应的标准化方法，研发人员仅需要定义好成员变量即可。

## 2.2 审计点1:反序列化漏洞

### 反序列化
反序列化漏洞是任何支持序列化的编程语言或框架、库中都可能存在的漏洞类型，并非java或spring框架特有。

> 序列化（对象->字节流）：把内存中的“活”对象，转换成字节流（比如一串二进制数据、JSON、XML字符串）的过程。目的是为了方便存储或传输。
> 
> 反序列化（字节流->对象）：是序列化的逆过程。把字节流还原成内存中可操作的对象。

**为什么需要序列化？**
> 如果不做序列化，对象只存在于程序运行的内存中。一旦程序关闭、断电或需要把数据发送到另一台机器，内存里的数据就会消失。序列化就是为了解决这个问题。
> 
> 举个例子：将程序当前运行时的状态和数据，保存到硬盘的文件或数据库中。下次程序启动时，可以直接从文件反序列化，恢复到上次的状态。
> 
> 打破生命周期限制：让对象从“临时”变成“永久”。
> 
> 打破地址空间限制：让对象从“不能出进程”变成“可以上网络”。
> 
> 打破语言壁垒：让不同语言编写的程序能够无缝交换数据。

**gadget chain**
> "反序列化漏洞 = 可控输入 + 危险类加载 + Gadget Chain 触发"

常见的危险方法，如：readObject(ios.input)，如果input外部可控，那么该部分代码存在潜在反序列化风险，但未必一定存在漏洞。

举个例子，代码审计时，如果有如下发现：

前提1:引入了漏洞组件
```
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>  <!-- 高危版本 -->
</dependency>
```
这是典型的cc链的Gadget Chain


前提2:存在反序列化入口
```
@RequestMapping("/upload")
public void handle(@RequestBody byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(
        new ByteArrayInputStream(data)  // ← 用户上传，可控！
    );
    Object obj = ois.readObject();
}
```
data属于用户上传数据，外部可控，那么下一步，就可以尝试去找一个可用的Gadget Chain来进行利用

进入Gadget Chain分析：
Commons Collections 源码的InvokerTransformer类中，transform() 方法可通过反射执行任意命令
```
public class InvokerTransformer implements Transformer, Serializable {
    public Object transform(Object input) {
        // 通过反射调用任意方法！
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    }
}
```


构建完整调用链
```
ObjectInputStream.readObject()
    ↓
AnnotationInvocationHandler.readObject()   ← 入口（JDK 原生）
    ↓
this.memberValues.entrySet()               ← 调用 Map 方法
    ↓
TransformedMap.decorate() 包装的 Map
    ↓
valueTransformer.transform(value)          ← 触发 Transformer
    ↓
ChainedTransformer.transform()             ← 链式调用多个 Transformer
    ↓
[0] ConstantTransformer.transform()        → 返回 Runtime.class
[1] InvokerTransformer.transform()         → 反射调用 getMethod("getRuntime")
[2] InvokerTransformer.transform()         → 反射调用 invoke(null)
[3] InvokerTransformer.transform()         → 反射调用 exec("calc.exe")
    ↓
Runtime.exec("calc.exe")                  ← 命令执行！
```

反序列化漏洞攻击流程图
```
攻击者本地                    目标服务器
    │                            │
    │  1. 构造 CC 链 Payload      │
    │  ===================>      │
    │  (恶意序列化字节流)          │
    │                            │
    │  2. POST /upload            │
    │  Content-Type: application/octet-stream
    │  Body: [payload.bin]  ====> │
    │                            │
    │                            │  3. 进入 Controller
    │                            │     @RequestBody byte[] data
    │                            │
    │                            │  4. new ObjectInputStream(data)
    │                            │     ois.readObject()  ← 触发！
    │                            │
    │                            │  5. 反序列化过程自动执行：
    │                            │     AnnotationInvocationHandler.readObject()
    │                            │     → TransformedMap 触发
    │                            │     → ChainedTransformer 链式调用
    │                            │     → InvokerTransformer.exec("calc")
    │                            │
    │                            │  6. 命令执行成功！
    │  <=== 7. 返回响应 (或反弹shell)
```

**攻击过程分析：**
> 这就是完整的 CC1 反序列化漏洞利用链。
> 
> 代码审计时发现有ois.readObject()来处理用户输入，且无过滤，因此判断存在反序列化的潜在风险。
> 
> 于是可以尝试输入序列化的AnnotationInvocationHandler的对象，这样在反序列化的时候，会由于jvm的机制强制执行AnnotationInvocationHandler的readObject方法，而恰巧这个方法在执行时会便利memberValues.entryset()，从而触发Transformer反序列化的利用链
> 
> 而这个链就是大家说的gadget chain

**反序列化危害**
```
攻击者发送恶意序列化数据
    ↓
目标应用反序列化（readObject/JSON.parse/XMLDecoder...）
    ↓
【分支：取决于 Gadget Chain 终点】
    │
    ├──► Runtime.exec() / ProcessBuilder ──► 🔴 RCE 反弹 Shell
    │
    ├──► TemplatesImpl / BCEL / Javassist ──► 🔴 内存马 / 类加载
    │
    ├──► URL / HttpURLConnection / JNDI ──► 🟠 SSRF 内网探测
    │
    ├──► FileInputStream / ObjectInputStream ──► 🟠 任意文件读取
    │
    ├──► DataSource / DriverManager ──► 🔴 数据库连接窃取
    │
    ├──► HashMap / TreeMap 碰撞 ──► 🟠 CPU 100% / OOM 拒绝服务
    │
    └──► 反射修改字段（isAdmin=true）───► 🟡 权限提升
```

**如何防御反序列化**
> "反序列化漏洞是'九头蛇'——RCE、内存马、数据泄露、内网渗透、拒绝服务，一个入口，全部可能；防御必须'白名单+过滤+升级'三管齐下，缺一不可。"
> 
