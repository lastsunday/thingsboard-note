# ThingsBoard 源码分析

基于版本3.3.1

## 地址

https://github.com/thingsboard/thingsboard

https://github.com/IoT-Technology/IoT-Technical-Guide

http://www.ithingsboard.com/docs/

## 项目架构

​	[**monolithic**](https://thingsboard.io/docs/reference/monolithic)

​	[**microservices**](https://thingsboard.io/docs/reference/msa)

## 部署方案

https://thingsboard.io/docs/reference/iot-platform-deployment-scenarios/

## 性能

https://thingsboard.io/docs/reference/performance/

- Number of devices: 10 000
- Publish frequency per device: once per second
- Total load: 10 000 messages per second

## 概念

### 定义了五种类型的物联网平台

1. 连接平台：提供覆盖功能和解决方案，用于连接IoT设备，管理和协调连接以及为已连接的IoT设备提供通信服务。
2. 设备管理平台：处理预配任务，以确保已连接的设备被部署，配置并通过常规的固件/软件更新保持最新。
3. IaaS /云后端平台：为物联网应用程序和服务的数据管理提供可扩展的企业级后端。
4. 应用程序启用平台（AEP）：使开发人员能够快速创建，测试和部署IoT应用程序或服务。
5. 先进的分析平台：提供复杂的分析工具，包括机器学习技术和流分析功能，以从IoT数据中提取可行的见解。

### 如果您正在考虑将您的业务迁移到云端，有三个词将萦绕在你耳边

1. IaaS（技术设施即服务）
2. PaaS（平台即服务）
3. SaaS（软件即服务）

### 多租户模型

1. 一租户一数据库
2. 一租户一名字空间
3. 全共享方式

### 持久化数据类型

> 不同数据推荐存放到特定的数据库中
>
>  SQL vs NoSQL vs Hybrid database approach

1. entities
2. [telemetry](https://thingsboard.io/docs/user-guide/telemetry/) data
3. timeseries data

### Actor model

https://thingsboard.io/docs/reference/architecture/

https://en.wikipedia.org/wiki/Actor_model

https://www.jianshu.com/p/d803e2a7de8e

```
DefaultActorService
	initActorSystem
```

### iot gateway

https://thingsboard.io/docs/iot-gateway/

https://github.com/thingsboard/thingsboard-gateway

### Key concepts

#### Entities and relations

1. **[Tenants](https://thingsboard.io/docs/user-guide/ui/tenants/)** 租户

2. **[Customers](https://thingsboard.io/docs/user-guide/ui/customers/)** 

3. **[Users](https://thingsboard.io/docs/user-guide/ui/users/)** 

4. **[Devices](https://thingsboard.io/docs/user-guide/ui/devices/)**

5. **[Assets](https://thingsboard.io/docs/user-guide/ui/assets/)**

6. **[Entity Views](https://thingsboard.io/docs/user-guide/entity-views/)** 共享部分数据，类似数据库的视图

7. **[Alarms](https://thingsboard.io/docs/user-guide/alarms/)** 

8. **[Dashboards](https://thingsboard.io/docs/user-guide/dashboards/)** 

   1. Aliases

   2. Widget Actions

      1. ##### Navigate to new dashboard state

      2. ##### Update current dashboard state

      3. ##### Navigate to other dashboard

      4. ##### Custom action

      5. ##### Custom action (with HTML template)

   3. Widgets Library

9. **Rule Node**

10. **Rule Chain**

11. Each entity supports:

    1. **[Attributes](https://thingsboard.io/docs/user-guide/attributes/)** 
    2. **[Time-series data](https://thingsboard.io/docs/user-guide/telemetry/)**
    3. **[Relations](https://thingsboard.io/docs/user-guide/entities-and-relations/#relations)**

12. Some entities support profiles:

    1. **[Tenant Profiles](https://thingsboard.io/docs/user-guide/tenant-profiles/)**
    2. **[Device Profiles](https://thingsboard.io/docs/user-guide/device-profiles/)**

#### Relations

1. [Has-a](https://en.wikipedia.org/wiki/Has-a) 

### Attributes

![image](https://thingsboard.io/images/user-guide/server-side-attributes.svg)

![image](https://thingsboard.io/images/user-guide/shared-attributes.svg)

![image](https://thingsboard.io/images/user-guide/client-side-attributes.svg)

### Rule Engine

> 核心模块
>
> 需要了解：前后端的串联，逻辑主线

1. 3 main components
   1. **Message**
   2. **Rule Node**
   3. **Rule Chain**

### White-labeling

1. Self-registration
2. Custom Translations
   1. 如何替换？利用资源拦截 service进行？
3. Custom Menu

### ？Integrations

> 内容较多
>
> 需要了解具体架构

### Analytics

### Other Feature

> 内容较多
>
> 需要了解不同的功能点与配置

1. Advanced RBAC for IoT
   1. CE版本限定三个角色
   2. PE版本，多个角色，角色权限可以自定义
2. ...还有其他特性

### Security

> 内容较多
>
> 需要了解不同的功能点与配置

### Administractor UI

### Contribution Guide

1. Widgets Development Guide
   1. 线上编码自定义图表

### MQTT

1. 发送命令远程控制
2. 读取和发布数据

### COAP

1. CoAP的主要目标之一是针对这种受限环境的特殊要求设计通用的Web协议，尤其是考虑到能源，楼宇自动化以及其他机器对机器（M2M）应用程序。
2. https://github.com/eclipse/californium

### API限流服务

### Modbus

Modbus是一种串行通讯协议，是Modicon公司(现在的施耐德电气 Schneider Electric) 于1979年为使用可编程逻辑控制器(PLC)通信而发表。Modbus已经成为工业领域通信协议事实上的业界标准，并且现在是工业电子设备之间常见的连接方式。

### OPC

> OPC是定义来自不同制造商的设备之间的数据通信的标准。

Eclipse Milo

​	Eclipse Milo™是基于Java的开源实现。Milo是OPC UA的开源实现。它包括一个高性能堆栈(通道、序列化、数据结构、安全性)以及在堆栈顶部构建的客户端和服务端SDK。

### JWT

### WebSocket

### TSL（Thing Specification Language）

​	物模型TSL（Thing Specification Language）。是一个JSON格式的文件。它是物理空间中的实体，如传感器、车载装置、楼宇、工厂等在云端的数字化表示，从属性、服务和事件三个维度，分别描述了该实体是什么、能做什么、可以对外提供哪些信息。定义了这三个维度，即完成了产品功能的定义。

### gRPC

​	gRPC 是一个高性能、开源和通用的 RPC 框架，面向服务端和移动端，基于 HTTP/2 设计。

### PostgreSQl

### MogoDB

### Kafka

### RabbitMQ

### 规则引擎

1. Easy-Rules

### Docker

### K8S

### proto3

1. Protocol Buffer是一种支持多平台、多语言、可扩展的的数据序列化机制，相较于XML来说，protobuf更小更快更简单，支持自定义的数据结构，用protobu编译器生成特定语言的源代码，如C++、Java、Python，目前protoBuf对主流的编程语言都提供了支持,非常方便的进行序列化和反序列化。
2. https://zhuanlan.zhihu.com/p/53339153
3. 例子：common/message/src/main/proto/tbmsg.proto

## 环境搭建

检出源码

编译源码

```
mvn clean install -DskipTests
```

ide导入项目源码

https://thingsboard.io/docs/user-guide/contribution/how-to-contribute/

开发测试数据搭建

1. 链接数据库文件

```shell
ln -s /Users/dev/project/thingsboard/thingsboard/dao/src/main/resources/sql /Users/yu/dev/project/thingsboard/thingsboard/application/src/main/data/sql
```

2. 安装测试数据，运行**ThingsboardInstallApplication**

   配置Environment variables

   ```
   SPRING_DATASOURCE_URL=jdbc:postgresql://192.168.64.3:5432/thingsboard;install.load_demo=true
   ```

3. 启动应用，运行**ThingsboardServerApplication**

   配置Environment variables

   ```
   SPRING_DATASOURCE_URL=jdbc:postgresql://192.168.64.3:5432/thingsboard
   ```

4. 登录http://localhost:8080/

   测试账号

   ```
   sysadmin@thingsboard.org
   ​	sysadmin
   tenant@thingsboard.org
   ​	tenant
   ```

   Get token
   
   ```shell
   curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{"username":"sysadmin@thingsboard.org", "password":"sysadmin"}' 'http://localhost:8080/api/auth/login'
   
   # Now, you should set ‘X-Authorization’ to “Bearer $YOUR_JWT_TOKEN”
   ```
   

## 分析

### 快速使用入门

1. 添加设备
   1. 可单独添加
   2. 可批量添加（通过CSV文件）
   3. 设备主动注册
   4. rest api添加
2. 连接设备（非实体设备节点）
   1. 测试工具，模拟发送数据到thingsboard
3. 创建仪表板
   1. 表格
   2. 图表
   3. 告警
4. 设置告警规则
5. 告警通知
6. 指派设备和仪表板给顾客（Customer）（顾客下有用户（Customer User））

### service

1. 分布式如何体现？

   1. 同一套源码中，使用pom的模块功能，生成不同的程序来达到微服务的形式。

2. 有没有共享的service实现方式，共享给不同的协议？实现一个实现，多个调用入口？

   1. 通过消息队列的协调，其他协议的入口发送请求处理的消息到消息队列，特定的service监听消息队列进行处理，然后将处理结果返回给消息队列。

3. 自建的mqtt服务器，netty-mqtt

4. 入口

   ```
   //数据库安装
   org.thingsboard.server.ThingsboardInstallApplication
   	updateArguments
   	ThingsboardInstallService.performInstall
   //后台程序启动
   ThingsboardServerApplication
   ```

5. Component Config

- [x] AuditLogLevelProperties

  对应业务手动执行审计日志记录逻辑

  ```
  audit-log.logging-level
  AuditLogLevelFilter
  ThingsboardSecurityConfiguration
  	auditLogLevelFilter
  AuditLogServiceImpl
  	@ConditionalOnProperty(prefix = "audit-log", value = "enabled", havingValue = "true")
  	logEntityAction
  		logAction
  			auditLogDao
  ```

- [ ] CustomOAuth2AuthorizationRequestResolver

  **前后端逻辑链暂不清晰**

  oauth2的具体配置在前端进行配置

  ```
  @Autowired方式引用
  
  security.oauth2
  	
  ```

- [x] JwtSettings

  ```
  security.jwt
  
  JwtTokenFactory
  	HS512
  	
  ThingsboardSecurityConfiguration
  	jwtAuthenticationProvider
  
  .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
  .addFilterBefore(buildRefreshTokenProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
  .addFilterBefore(buildWsJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
  ```

- [x] MvcCorsProperties

  ```
  spring.mvc.cors
  
  key value（对象类）形式
  供ThingsboardSecurityConfiguration corsFilter使用
  UrlBasedCorsConfigurationSource
  ```

- [x] RateLimitProcessingFilter

  ```
  RateLimitProcessingFilter
  	perTenantLimits.computeIfAbsent
  	perCustomerLimits.computeIfAbsent
  	
  TbRateLimits
  	LocalBucket
  		io.github.bucket4j
  ```

- [x] SchedulingConfiguration

  是否有分布式？

  ```
  org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler
  使用spring task
  ```

- [x] SwaggerConfiguration

  ```
  类库版本
  	springfox-swagger2
  配置
  		SwaggerConfiguration
  	授权
  		SwaggerConfiguration
  			securitySchemes
  	路径权限
  		SwaggerConfiguration
  			securityContext
  	API实现搜索
  		SwaggerConfiguration
  			.paths(apiPaths())
  	其他信息
  资源文件web security
  	ThingsboardSecurityConfiguration

- [x] ThingsboardMessageConfiguration

  国际化，当前项目应该没具体应用，因为资源文件内容很少。并且是前后端分离的架构

- [ ] ThingsboardSecurityConfiguration

  1. 错误码转换

  ​	ThingsboardErrorCode to HttpStatus

  ​	缺少在swagger中错误码的描述，不需要？

  2. Login controller功能在此完成，利用ProcessingFilter

  ```
  CorsFilter
  
  restAccessDeniedHandler
  	.exceptionHandling().accessDeniedHandler(restAccessDeniedHandler)
  ThingsboardErrorResponseHandler
  	@ExceptionHandler(AccessDeniedException.class)
  	@ExceptionHandler(Exception.class)
  	**ThingsboardErrorCode to HttpStatus
  web.ignoring().antMatchers("/*.js","/*.css","/*.ico","/assets/**","/static/**");
  
  ```

- [x] WebConfig

  ```
  web url重定位到index.html
  	"/assets", "/assets/", "/{path:^(?!api$)(?!assets$)(?!static$)(?!webjars$)[^\\.]*}/**"
  ```

- [ ] WebSocketConfiguration

  由于具有一定复杂性，并且需要结合业务演示才能深入解析，所以暂未具体分析

  ```
  registerWebSocketHandlers
  
  wsHandler
  	TbWebSocketHandler
  		分派实体map执行
  			
  ```

3.  后台前端部署逻辑与开发流程
4. api接口设计

5. Component ConditionalOnExpression的作用

```
TbCoreComponent
TbLwM2mTransportComponent
TbRuleEngineComponent
TbSnmpTransportComponent
TbTransportComponent
```

6. actors

7. controller

   1. @PreAuthorize("hasAuthority('SYS_ADMIN')")

   2. extends BaseController

   3. handleException

   4. only Impl

   5. AbstractRpcController

      1. RpcV1Controller ?
      2. RpcV2Controller ?

   6. Controller api设计

      1. ？

   7. Login api 接口隐藏之谜

      1. 利用了spring security ProcessingFilter的实现

      2. ```
         如restful api login
         .addFilterBefore(buildRestLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
         	FORM_BASED_LOGIN_ENTRY_POINT
         		/api/auth/login
         	RestLoginProcessingFilter
         			
         ```

8. exception

9. service

10. utils

### client admin

1. 连接到service的url

   1. 开发环境下通过ui-ngx/proxy.conf.js配置
   2. 暂未找到baseUrl的设置逻辑
      1. src/app/core/utils.ts ？

2. 前端应用于spring boot 服务

   1. 编译成jar，并引入，如：ui-ngx-3.3.2-SNAPSHOT.jar,所使用的plugin：com.github.eirslett:frontend-maven-plugin

   2. pom引用

      ```
      <dependency>
        <groupId>org.thingsboard</groupId>
        <artifactId>ui-ngx</artifactId>
        <version>${project.version}</version>
        <scope>runtime</scope>
      </dependency>
      ```

- [ ] 图表的自适应实现原理

### client iot

1. lanuage
   1. python
      1. https://thingsboard.io/docs/samples/raspberry/temperature/
   2. rust
      1. https://github.com/rust-embedded/awesome-embedded-rust

### testing

1. 单元测试的粒度
2. 单元测试的技巧，测试上下文的构建

### other

#### Api

- [ ] rpc

  - [x] Mqtt

    `v1/devices/me/rpc/[request|response]/$request_id`

    `v1/devices/me/rpc/request/+`

  ```
  发送指令
    Topic: v1/devices/me/rpc/request/27
    Message {"method":"setGpioStatus","params":{"pin":7,"enabled":true}}
  监听指令接收
  	subscribe('v1/devices/me/rpc/request/+')
  处理指令
    on_message(client,userdata,msg)
        msg.topic
        msg.payload
      data = json.loads(msg.payload)
      获取调用方法名
        data['method']
      响应指令
        //publish("v1/devices/me/rpc/response/27","{...}".1)
        publish(msg.topic.replace('request', 'response'),get_gpio_status(),1)
  ```

- [ ] attributes

  > ThingsBoard provides the ability to assign custom attributes to your entities and manage these attributes. Those attributes are stored in the database and may be used for data visualization and data processing.

  - [x] Mqtt

    `v1/devices/me/attributes/[request|response]/$request_id`

    `v1/devices/me/attributes/response/+`

- [ ] claiming devices 认领设备

  - [ ] Mqtt

    `v1/devices/me/claim`

- [ ] Device provisioning

  - [ ] Mqtt

    `/provision`

- [ ] Firmware API

  - [ ] Mqtt

    `v1/devices/me/attributes/response/+`

    `v2/fw/request/${requestId}/chunk/${chunk}` 

    `v2/fw/response/+/chunk/+`

- [ ] Custom

## 最佳实践

1. springboot yaml的默认参数与环境变量设置

```yaml
port: "${HTTP_BIND_PORT:8080}"
```

2. 开发环境不需要修改yaml文件，可使用设置环境变量
3. git upstream达到同步fork的主仓库的代码

## 学习案例

1. 搭建thingsboard到树莓派
   1. 单机版
   
      - [x] 安装到pi4
   
   2. 集群版
   
   3. 集群版-k3s
2. 将树莓派的系统信息传送到树莓派
   - [x] Cpu temperature
     - [x] pi4
     - [ ] ~~macbook~~
3. 将传感器信息传送到树莓派
   - [ ] 温湿度传感器

## 进阶

1. 将thingsboard的优点模块移植到project moon
   1. 登录模块
   2. 编译部署流程
   3. 审计(audit_log)
2. 数据结构分析
   - [ ] database schema

## 功能分析

### 登录

> 有强退逻辑，当重置密码，禁用用户，删除用户时会将用户的token设置为超时）

1. RestLogin

   1. 前端发起login请求eg: /api/auth/login

   2. spring security ProcessingFilter

      ```java
      addFilterBefore(buildRestLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
      	RestLoginProcessingFilter///api/auth/login
        	attemptAuthentication
        		UserPrincipal principal = new UserPrincipal(UserPrincipal.Type.USER_NAME, loginRequest.getUsername());
        		this.getAuthenticationManager().authenticate(token)
      					configure(AuthenticationManagerBuilder auth)
       						auth.authenticationProvider(restAuthenticationProvider);
      						supports
                    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
      				RestAuthenticationProvider.authenticate
                if userPrincipal.getType() == UserPrincipal.Type.USER_NAME
                	UserCredentials userCredentials = userService.findUserCredentialsByUserId(TenantId.SYS_TENANT_ID, user.getId());//实际查询userCredentialsRepository.findByUserId(userId)，tenant并没有使用
      						 systemSecurityService.validateUserCredentials(user.getTenantId(), userCredentials, username, password);//错误重试次数检测，user.getAdditionalInfo().failedLoginAttempts,超出次数会禁用用户，并发送提示邮件
                else
                  //public id skip
      
      addFilterBefore(buildRestPublicLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)            
      	RestPublicLoginProcessingFilter///api/auth/login/public
      		attemptAuthentication
      			UserPrincipal principal = new UserPrincipal(UserPrincipal.Type.PUBLIC_ID, loginRequest.getPublicId());
        		this.getAuthenticationManager().authenticate(token)
      					configure(AuthenticationManagerBuilder auth)
       						auth.authenticationProvider(restAuthenticationProvider);
      						supports
                    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
      				RestAuthenticationProvider.authenticate
                if userPrincipal.getType() == UserPrincipal.Type.USER_NAME
                	// username skip
                else
                  //public id
                	customerId = new CustomerId(UUID.fromString(publicId));
      						Customer publicCustomer = customerService.findCustomerById(TenantId.SYS_TENANT_ID, customerId);//实际查询customerRepository.findById(tenantId, customerId.getId()),登录需要判断additional_info {"isPublic":true}
      //---鉴权成功
      		successfulAuthentication
        		RestAwareAuthenticationSuccessHandler.onAuthenticationSuccess
            	JwtToken accessToken = tokenFactory.createAccessJwtToken(securityUser);
              JwtToken refreshToken = refreshTokenRepository.requestRefreshToken(securityUser);
            	Map<String, String> tokenMap = new HashMap<String, String>();
              tokenMap.put("token", accessToken.getToken());
              tokenMap.put("refreshToken", refreshToken.getToken());
      
              response.setStatus(HttpStatus.OK.value());
              response.setContentType(MediaType.APPLICATION_JSON_VALUE);
              mapper.writeValue(response.getWriter(), tokenMap);
      
              clearAuthenticationAttributes(request);
      ```

2. 登录强退（TokenOutdatingService,ApplicationEventPublisher）

   当重置密码，禁用用户，删除用户时会将用户的token设置为超时，使用了缓存机制

   ```
   private final ApplicationEventPublisher eventPublisher;
   
   eventPublisher.publishEvent(new UserAuthDataChangedEvent(securityUser.getId()));
   
   TokenOutdatingService.onUserAuthDataChanged
   	outdateOldUserTokens(userAuthDataChangedEvent.getUserId());
   ```

3. 缓存机制(可选用caffeine 或 redis)

```
cache:
  # caffeine or redis
  type: "${CACHE_TYPE:caffeine}"
  maximumPoolSize: "${CACHE_MAXIMUM_POOL_SIZE:16}" # max pool size to process futures that calls the external cache
  attributes:
    # make sure that if cache.type is 'redis' and cache.attributes.enabled is 'true' that you change 'maxmemory-policy' Redis config property to 'allkeys-lru', 'allkeys-lfu' or 'allkeys-random'
    enabled: "${CACHE_ATTRIBUTES_ENABLED:true}"
```

### 接口访问前鉴权

1. jwt

   Token

   ```java
   //Header JWT
   ThingsboardSecurityConfiguration
   .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)  
   //跳过权限检查的路径
   //NON_TOKEN_BASED_AUTH_ENTRY_POINTS = (/index.html", "/assets/**", "/static/**", "/api/noauth/**", "/webjars/**",  "/api/license/**) /api/ws/**，/api/auth/token，/api/auth/login，/api/auth/login/public，/api/v1/**，/webjars/**
   //处理的路径/api/**
   SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
   RawAccessJwtToken token = new RawAccessJwtToken(tokenExtractor.extract(request));
   	JwtHeaderTokenExtractor.extract
     getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
   		configure(AuthenticationManagerBuilder auth)
         	auth.authenticationProvider(jwtAuthenticationProvider);
   	JwtAuthenticationProvider.authenticate
   		SecurityUser securityUser = tokenFactory.parseAccessJwtToken(rawAccessToken);
   		if (tokenOutdatingService.isOutdated(rawAccessToken, securityUser.getId())) {
         ...
       }else{
         
       }
   		return new JwtAuthenticationToken(securityUser)
    	JwtTokenAuthenticationProcessingFilter.successfulAuthentication
         chain.doFilter(request, response);
         
   //Query Param JWT for ws
   ThingsboardSecurityConfiguration
   .addFilterBefore(buildWsJwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
   //处理的路径/api/ws/**
   AntPathRequestMatcher matcher = new AntPathRequestMatcher(WS_TOKEN_BASED_AUTH_ENTRY_POINT);
   RawAccessJwtToken token = new RawAccessJwtToken(tokenExtractor.extract(request));
   	JwtQueryTokenExtractor.extract
     getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
   		configure(AuthenticationManagerBuilder auth)
         	auth.authenticationProvider(jwtAuthenticationProvider);
   	JwtAuthenticationProvider.authenticate
   		SecurityUser securityUser = tokenFactory.parseAccessJwtToken(rawAccessToken);
   		if (tokenOutdatingService.isOutdated(rawAccessToken, securityUser.getId())) {
         ...
       }else{
         
       }
   		return new JwtAuthenticationToken(securityUser)
    	JwtTokenAuthenticationProcessingFilter.successfulAuthentication
         	chain.doFilter(request, response);
   ```

   RefreshToken

   ```java
   ThingsboardSecurityConfiguration
   .addFilterBefore(buildRefreshTokenProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
   //处理的路径/api/auth/token
   refreshTokenRequest = objectMapper.readValue(request.getReader(), RefreshTokenRequest.class);
   RawAccessJwtToken token = new RawAccessJwtToken(refreshTokenRequest.getRefreshToken());
   	getAuthenticationManager().authenticate(new RefreshAuthenticationToken(token));
   		configure(AuthenticationManagerBuilder auth)
   			auth.authenticationProvider(refreshTokenAuthenticationProvider);
   	RefreshTokenAuthenticationProvider.authenticate
   		if (principal.getType() == UserPrincipal.Type.USER_NAME) {
       	securityUser = authenticateByUserId(unsafeUser.getId());
       } else {
       	securityUser = authenticateByPublicId(principal.getValue());
       }
     RefreshTokenProcessingFilter.successfulAuthentication
     	RestAwareAuthenticationSuccessHandler.onAuthenticationSuccess
         	JwtToken accessToken = tokenFactory.createAccessJwtToken(securityUser);
           JwtToken refreshToken = refreshTokenRepository.requestRefreshToken(securityUser);
         	Map<String, String> tokenMap = new HashMap<String, String>();
           tokenMap.put("token", accessToken.getToken());
           tokenMap.put("refreshToken", refreshToken.getToken());
   
           response.setStatus(HttpStatus.OK.value());
           response.setContentType(MediaType.APPLICATION_JSON_VALUE);
           mapper.writeValue(response.getWriter(), tokenMap);
   
           clearAuthenticationAttributes(request);
   ```

### 接口限流

```java
ThingsboardSecurityConfiguration
addFilterAfter(rateLimitProcessingFilter, UsernamePasswordAuthenticationFilter.class);
RateLimitProcessingFilter.doFilter
	//未登录用户和系统管理员不进行限流检测
	//tenant限流，根据tenantId限流
		TbRateLimits rateLimits = perTenantLimits.computeIfAbsent(user.getTenantId(), id -> new TbRateLimits(perTenantLimitsConfiguration));
				//LocalBucketBuilder builder = Bucket4j.builder();
		if (!rateLimits.tryConsume()) {
                    errorResponseHandler.handle(new TbRateLimitsException(EntityType.TENANT), (HttpServletResponse) response);
                    return;
                }
	//customer限流，根据customer限流
    TbRateLimits rateLimits = perCustomerLimits.computeIfAbsent(user.getCustomerId(), id -> new TbRateLimits(perCustomerLimitsConfiguration));
                    if (!rateLimits.tryConsume()) {
                        errorResponseHandler.handle(new TbRateLimitsException(EntityType.CUSTOMER), (HttpServletResponse) response);
                        return;
                    }
```

### Oauth2（暂不研究）

### WebSocket

> 命令模式
>
> 观察者模式

```java
@EnableWebSocket
@Configuration
WebSocketConfiguration
	createWebSocketContainer
	registerWebSocketHandlers(WebSocketHandlerRegistry registry)
		//拦截/api/ws/plugins/**，使用wsHandler进行处理，并且在握手前进行用户登录认证
		registry.addHandler(wsHandler(), WS_PLUGIN_MAPPING).setAllowedOrigins("*")
                .addInterceptors(new HttpSessionHandshakeInterceptor(), new HandshakeInterceptor() {
	TbWebSocketHandler
		afterConnectionEstablished(WebSocketSession session)
			TelemetryWebSocketSessionRef sessionRef = toRef(session);
				//判断/api/ws/plugins/后接的是哪种plugin，例如/api/ws/plugins/telemetry，则截取到telemetry
				path = path.substring(WebSocketConfiguration.WS_PLUGIN_PREFIX.length());
			//检查连接限制
			if (!checkLimits(session, sessionRef)) {
			//生成SessionMetaData
			internalSessionMap.put(internalSessionId, new SessionMetaData(session, sessionRef, maxMsgQueuePerSession));
			externalSessionMap.put(externalSessionId, internalSessionId);
		handleTextMessage
			webSocketService.handleWebSocketMsg(sessionMd.sessionRef, message.getPayload());
				//处理telemetry command，嵌套层次较为复杂，需要仔细研究
				//SubscriptionCmd
        //订阅如何实现？
        //DefaultTbCoreConsumerService
        //DefaultSubscriptionManagerService
        //例如
        DefaultTelemetryWebSocketService.handleWsTimeseriesSubscriptionCmd(sessionRef, cmd);
        	handleWsTimeseriesSubscription(sessionRef, cmd, sessionId, entityId);
        		 accessValidator.validate(sessionRef.getSecurityCtx(), Operation.READ_TELEMETRY, entityId,
                on(r -> Futures.addCallback(tsService.findAllLatest(sessionRef.getSecurityCtx().getTenantId(), entityId), callback, executor), callback::onFailure));
        		callback.onSuccess
              //发送第一次数据
              sendWsMsg(sessionRef, new TelemetrySubscriptionUpdate(cmd.getCmdId(), data));
        			//订阅
        			oldSubService.addSubscription(sub);
        				DefaultTbLocalSubscriptionService.addSubscription
                  pushSubscriptionToManagerService(subscription, true);
        					registerSubscription(subscription);
                  	Map<Integer, TbSubscription> sessionSubscriptions = subscriptionsBySessionId.computeIfAbsent(subscription.getSessionId(), k -> new ConcurrentHashMap<>());
        sessionSubscriptions.put(subscription.getSubscriptionId(), subscription);
        //触发数据更新          
        DefaultTbLocalSubscriptionService.onSubscriptionUpdate
          	DefaultSubscriptionManagerService.onLocalTelemetrySubUpdate
          		onTimeSeriesUpdate
          			DefaultTbCoreConsumerService.forwardToSubMgrService
          				DefaultTbCoreConsumerService.launchMainConsumers
          					//死循环执行
          					List<TbProtoQueueMsg<ToCoreMsg>> msgs = mainConsumer.poll(pollDuration);
                    if (msgs.isEmpty()) {
                        continue;
                    }
         //消息来源
        this.mainConsumer = tbCoreQueueFactory.createToCoreMsgConsumer();
        DefaultTbCoreConsumerService.onTbApplicationEvent(PartitionChangeEvent event)
          //消息列表来自event.getPartitions()
          this.mainConsumer.subscribe(event.getPartitions());
        	//消息列表来源初始化
        	HashPartitionService.recalculatePartitions
            applicationEventPublisher.publishEvent(new PartitionChangeEvent(this, serviceQueueKey, Collections.emptySet()));
        		applicationEventPublisher.publishEvent(new PartitionChangeEvent(this, serviceQueueKey, tpiList));
        
        	//#Partitions列表源头
        	//如果没有开启zookeeper
        	DummyDiscoveryService.onApplicationEvent
            partitionService.recalculatePartitions(serviceInfoProvider.getServiceInfo(), Collections.emptyList());
        	//如果开启zookeeper
        	ZkDiscoveryService.onApplicationEvent
            recalculatePartitions();
        	//#追加msg(实时发送的场景)
        	TbMsgTimeseriesNode.onMsg
            	ctx.getTelemetryService().saveAndNotify(ctx.getTenantId(), msg.getCustomerId(), msg.getOriginator(), tsKvEntryList, ttl, new TelemetryNodeCallback(ctx, msg));
        				DefaultTelemetrySubscriptionService.saveAndNotify
                  saveAndNotifyInternal
                  	ListenableFuture<Integer> saveFuture = tsService.save(tenantId, entityId, ts, ttl);
                    addMainCallback(saveFuture, callback);
                    addWsCallback(saveFuture, success -> onTimeSeriesUpdate(tenantId, entityId, ts));
        							DefaultSubscriptionManagerService.onTimeSeriesUpdate
                        localSubscriptionService.onSubscriptionUpdate(s.getSessionId(), update, TbCallback.EMPTY);
        									DefaultTbLocalSubscriptionService.onSubscriptionUpdate
        
        //取消订阅如何实现
        DefaultTelemetryWebSocketService.unsubscribe
          oldSubService.cancelAllSessionSubscriptions(sessionId);
        	oldSubService.cancelSubscription(sessionId, cmd.getCmdId());
          	DefaultTbLocalSubscriptionService.cancelSubscription
              subscriptionManagerService.cancelSubscription(sessionId, subscriptionId, TbCallback.EMPTY);
              	DefaultSubscriptionManagerService.cancelSubscription
				//other cmd
				...
				if (cmdsWrapper.getAlarmDataCmds() != null) {
        	cmdsWrapper.getAlarmDataCmds().forEach(cmd -> handleWsAlarmDataCmd(sessionRef, cmd));
        		entityDataSubService.handleCmd(sessionRef, cmd);
        			wsService.sendWsMsg(ctx.getSessionId(), update);
        				DefaultTelemetryWebSocketService.executor
        					executor.submit(() -> {
        						msgEndpoint.send(sessionRef, cmdId, msg);
        							TbWebSocketHandler.send
        								sessionMd.sendMsg(msg);
        										...
        										//如果正在发送msg，则将msg压入队列
        										//在队列的msg，在什么时候会进行处理？
        										//在SessionMetaData.onResult进行处理
        										//调用回调来自this.asyncRemote.sendText(msg, this);//public abstract void sendText(String text,javax.websocket.SendHandler completion)
                    				msgQueue.add(msg);
        									sendMsgInternal(msg);
        										this.asyncRemote.sendText(msg, this);
        											WsRemoteEndpointAsync.sendText
        }
				...
```



### 各种协议收集数据的实现

小结：通过各种协议（某些协议实现处理器只实现部分处理场景）接收请求（遥测数据，rpc），将请求推入消息请求队列（请求队列会由ruleEngine，actor进行订阅，处理），轮训消息响应队列（处理结果队列），对请求进行响应（根据之前记录的sessionid和requestid找到相应的调用者链路进行结果返回）

#### coap

> org.eclipse.californium

Application : transport/coap/src/main/java/org/thingsboard/server/coap/ThingsboardCoapTransportApplication.java

```
CoapTransportService
	init
		CoapResource api = new CoapResource(API);
			CoapTransportResource
				processHandlePost
					switch (featureType.get()) {
                case ATTRIBUTES:
                    processRequest(exchange, SessionMsgType.POST_ATTRIBUTES_REQUEST);
                    break;
                case TELEMETRY:
                	processRequest(exchange, SessionMsgType.POST_TELEMETRY_REQUEST);
                		handlePostTelemetryRequest
                			DefaultTransportService.process
                ...
    CoapResource efento = new CoapResource(EFENTO);
```



#### http

Application : transport/http/src/main/java/org/thingsboard/server/http/ThingsboardHttpTransportApplication.java

```java
eg: postTelemetry
DeviceApiController.postTelemetry
  DefaultTransportService.process
  	//鉴权
  	transportContext.getTransportService().process(DeviceTransportType.DEFAULT, ValidateDeviceTokenRequestMsg.newBuilder().setToken(deviceToken).build(),
                new DeviceAuthCallback(transportContext, responseWriter, sessionInfo -> {
                    TransportService transportService = transportContext.getTransportService();
                  	//将指令推到消息队列
                    transportService.process(sessionInfo, JsonConverter.convertToTelemetryProto(new JsonParser().parse(json)),
                            new HttpOkCallback(responseWriter));
                }));
```



#### lwm2m（待研究）

Application : transport/lwm2m/src/main/java/org/thingsboard/server/lwm2m/ThingsboardLwm2mTransportApplication.java

> org.eclipse.leshan.server.californium.LeshanServer

```
DefaultLwM2mTransportService
	init
		?
```



#### mqtt

Application : transport/mqtt/src/main/java/org/thingsboard/server/mqtt/ThingsboardMqttTransportApplication.java

Bootstrap: common/transport/mqtt/src/main/java/org/thingsboard/server/transport/mqtt/MqttTransportService.java

```java
MqttTransportService
	@PostConstruct
	init
		MqttTransportServerInitializer.initChannel
			pipeline.addLast("decoder", new MqttDecoder(context.getMaxPayloadSize()));
      pipeline.addLast("encoder", MqttEncoder.INSTANCE);
      MqttTransportHandler handler = new MqttTransportHandler(context, sslHandler);
      pipeline.addLast(handler);
        MqttTransportHandler
          channelRegistered
          channelRead
            if (msg instanceof MqttMessage) {
              processMqttMsg(ctx, message);
                if (CONNECT.equals(msg.fixedHeader().messageType())) {
                    //处理连接与鉴权
                    processConnect(ctx, (MqttConnectMessage) msg);
                      //1.PROVISION
                      //2.x509
                      //3.authtoken
                      processAuthTokenConnect
                        DefaultTransportService.transportService.process
                      		doProcess(DeviceTransportType transportType, TbProtoQueueMsg<TransportApiRequestMsg> protoMsg,
                           TransportServiceCallback<ValidateDeviceCredentialsResponse> callback)
                        		DefaultTbQueueRequestTemplate.send
                        			//将请求和响应关系加入：请求id和响应的Map中，以便在死循环处理响应逻辑中，返回正确的响应（expectedResponse.future.set(response);）
                        			if (pendingRequests.putIfAbsent(requestId, responseMetaData) != null) {
                              //发送请求到消息队列中
                        			sendToRequestTemplate
                        				InMemoryTbQueueProducer.send
                            //消息处理
                            DefaultTbQueueRequestTemplate.mainLoop
                                fetchAndProcessResponses
                                	List<Response> responses = doPoll(); //poll js responses
                                		InMemoryTbQueueConsumer.poll
                                      
                                	responses.forEach(this::processResponse); //this can take a long time
                                		processResponse
                                      	ResponseMetaData<Response> expectedResponse = pendingRequests.remove(requestId);
                                				expectedResponse.future.set(response);
                             //对响应进行处理
                             MqttTransportHandler.onValidateDeviceResponse
                               	process(TransportProtos.SessionInfoProto sessionInfo, TransportProtos.SessionEventMsg msg, TransportServiceCallback<Void> callback) {
                               		DefaultTransportService.sendToDeviceActor
                                    DefaultTransportService.sendToDeviceActor
                                    	//返回响应后，注册device session
                                      //返回mqtt响应
                } else if (deviceSessionCtx.isProvisionOnly()) {
                    //As a device manufacturer or firmware developer,
                    //针对设备维护类的指令
                    processProvisionSessionMsg(ctx, msg);
                        if (topicName.equals(MqttTopics.DEVICE_PROVISION_REQUEST_TOPIC)) {
                        	DefaultTransportService.process
                            	DefaultTbQueueRequestTemplate.send
                } else {
                    //常规指令,最终发送到消息队列（RuleEngine QueueProducer，Actor QueueProducer）
                    enqueueRegularSessionMsg(ctx, msg);
                      processMsgQueue
                        	DeviceSessionCtx.tryProcessQueuedMsgs
                        		processRegularSessionMsg
                        			switch (msg.fixedHeader().messageType()) {
																case PUBLISH:
                                  processPublish(ctx, (MqttPublishMessage) msg);
                                  	if (topicName.startsWith(MqttTopics.BASE_GATEWAY_API_TOPIC)) {
                                      ...
                                    }else{
                                     	  processDevicePublish(ctx, mqttMsg, topicName, msgId);
                                      		...
                                          } else if (deviceSessionCtx.isDeviceTelemetryTopic(topicName)) {
                                      			 TransportProtos.PostTelemetryMsg postTelemetryMsg = payloadAdaptor.convertToPostTelemetry(deviceSessionCtx, mqttMsg);
                                           		transportService.process(deviceSessionCtx.getSessionInfo(), postTelemetryMsg, getPubAckCallback(ctx, msgId, postTelemetryMsg));
                                      				DefaultTransportService.process(TransportProtos.SessionInfoProto sessionInfo, TransportProtos.PostTelemetryMsg msg, TransportServiceCallback<Void> callback) {
                                                sendToRuleEngine
                                                  	ruleEngineMsgProducer.send(tpi, new TbProtoQueueMsg<>(tbMsg.getId(), msg), wrappedCallback);
                                                		InMemoryStorage.send
                                          ...
                                    }
                                  break;
                                case SUBSCRIBE:
                                  ...
                }
          channelUnregistered
			
```



#### snmp

Application: transport/snmp/src/main/java/org/thingsboard/server/snmp/ThingsboardSnmpTransportApplication.java

> org.snmp4j

```
SnmpTransportService
	init
		initializeSnmp();
    configureResponseDataMappers();
    configureResponseProcessors();
    	responseProcessors.put(SnmpCommunicationSpec.TELEMETRY_QUERYING, (responseData, requestInfo, sessionContext) -> {
            TransportProtos.PostTelemetryMsg postTelemetryMsg = JsonConverter.convertToTelemetryProto(responseData);
            transportService.process(sessionContext.getSessionInfo(), postTelemetryMsg, null);
            	DefaultTransportService.sendToRuleEngine
            
            log.debug("Posted telemetry for SNMP device {}: {}", sessionContext.getDeviceId(), responseData);
        });
```



### Rule Engine（待研究）

```
org.thingsboard.server.service.queue.DefaultTbRuleEngineConsumerService
	init
	
	AbstractConsumerService.onApplicationEvent(ApplicationReadyEvent event)
		DefaultTbRuleEngineConsumerService.launchMainConsumers
			consumers.forEach((queue, consumer) -> launchConsumer(consumer, consumerConfigurations.get(queue), consumerStats.get(queue), queue));
				launchConsumer
					//核心循环逻辑，消息处理，消息-》RuleEngine
					consumerLoop
						submitStrategy.submitAttempt((id, msg) -> submitExecutor.submit(() -> submitMessage(configuration, stats, ctx, id, msg)));
							//回调函数，标识任务处理是否完成
							TbMsgCallback callback = ...
              if (toRuleEngineMsg.getTbMsg() != null && !toRuleEngineMsg.getTbMsg().isEmpty()) {
              	//relationTypes，关系类型??如何实现基于rule chain，通知下一个处理器进行处理？
              	//转给actor系统执行
                forwardToRuleEngineActor(configuration.getName(), tenantId, toRuleEngineMsg, callback);
                  msg = new QueueToRuleEngineMsg(tenantId, tbMsg, relationTypes, toRuleEngineMsg.getFailureMessage());
                  actorContext.tell(msg);
                  	//appActor来自于DefaultActorService.initActorSystem的system.createRootActor
                  	appActor.tell(tbActorMsg);
                  	//tbActorMainBox带的actor为AppActor
                  	TbActorMailbox.tell
                  	...
                  	//最终由AppActor.doProcess处理
                  		
              } else {

              	callback.onSuccess();
              }
						TbRuleEngineProcessingDecision decision = ackStrategy.analyze(result);
						...
						if (decision.isCommit()) {
            	submitStrategy.stop();
            	//跳出该次消息处理的循环
            	break;
            } else {
            	submitStrategy.update(decision.getReprocessMap());
            }
        		...
        
```



### Actor Model（待研究，实现比较复杂，分tenant的actor实体）

```java
DefaultActorService
	initActorSystem
  	actorContext.setActorSystem(system);
        appActor = system.createRootActor(APP_DISPATCHER_NAME, new AppActor.ActorCreator(actorContext));
						createRootActor
              createActor
              	TbActorId actorId = creator.createActorId();
								//根据actorId创建对应的mainbox
       					TbActorMailbox actorMailbox = actors.get(actorId);
								TbActor actor = creator.createActor();
								//mailbox的actor由这里注入
								//TbActorMailbox的构造方法在哪里定义了？？lombok.Data定义了
								TbActorMailbox mailbox = new TbActorMailbox(this, settings, actorId, parentRef, actor, dispatcher);
								
        actorContext.setAppActor(appActor);
        TbActorRef statsActor = system.createRootActor(TENANT_DISPATCHER_NAME, new StatsActor.ActorCreator(actorContext, "StatsActor"));
        actorContext.setStatsActor(statsActor);
		onApplicationEvent
      appActor.tellWithHighPriority(new AppInitMsg());
				AppActor.doProcess
          initTenantActors
          	getOrCreateTenantActor
          		
//from rule engine?
ActorSystemContext
			appActor.tell(tbActorMsg);
	TbActorMailbox.tell(tbActorMsg);
		enqueue
      	tryProcessQueue(true);
					dispatcher.getExecutor().execute(this::processMailbox);
						processMailbox
              for (int i = 0; i < settings.getActorThroughput(); i++) {
                TbActorMsg msg = highPriorityMsgs.poll();
                if (msg == null) {
                    msg = normalPriorityMsgs.poll();
                }
                actor.process(msg);
                	ContextAwareActor.process
                    	protected abstract boolean doProcess(TbActorMsg msg);
```

### 类分析

#### 持久层

1. 包结构

```
entity
	org.thingsboard.server.dao.model.sql
dto
	org.thingsboard.server.common.data
repository(jpa)
	org.thingsboard.server.dao.sql
		传入参数一般为普通数据类型
		sql文本写在接口上
dao
	base dao
		org.thingsboard.server.dao
			抽象dao的定义
	jpa
    org.thingsboard.server.dao.sql
    	实体类
      抽象接口实现：getCrudRepository，getEntityClass
      使用到的工具类：DaoUtil
      互相调用到的类：dao，repository
dao service
	org.thingsboard.server.dao
		dao (base) service实现
			互相调用到的类：dao，dao service
			
针对ts类数据
	数据库模式
		postgreSQL
		postgreSQL + Cassandra
		postgreSQL + timescaleDB
	hsql
		org.hibernate.dialect.HSQLDialect
	psql
		org.hibernate.dialect.PostgreSQLDialect
	配置类
		PsqlTsDaoConfig
		HsqlTsDaoConfig
			org.hibernate.dialect.HSQLDialect
		TimescaleDaoConfig
	
	备注：
		org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
			动态判断使用的类
validate数据校验

```

2. 数据库映射类

   1. 位置：dao/src/main/java/org/thingsboard/server/dao/model/sql

   2. 实现技术：jpa

   3. 继承层级

      ```
      ToData (org.thingsboard.server.dao.model)
      		/**
           * This method convert domain model object to data transfer object.
           *
           * @return the dto object
           */
          T toData();
        AbstractTsKvEntity (org.thingsboard.server.dao.model.sql)
        AttributeKvEntity (org.thingsboard.server.dao.model.sql)
        RelationEntity (org.thingsboard.server.dao.model.sql)
        BaseEntity (org.thingsboard.server.dao.model)
      ```

   4. 数据库表名，字段名定义：dao/src/main/java/org/thingsboard/server/dao/model/ModelConstants.java

   5. 特性

      1. dm to dto **OR** dto to dm
         1. toData method `org.thingsboard.server.dao.model.sql.xxxEntity` to `org.thingsboard.server.common.data.xxx`
         2. Construct method  `org.thingsboard.server.common.data.xxx` to `org.thingsboard.server.dao.model.sql.xxxEntity`

3. dao层分析

```
Dao (org.thingsboard.server.dao)
  JpaAbstractDao (org.thingsboard.server.dao.sql)
  	getCrudRepository
  	DaoUtil
  OAuth2ClientRegistrationTemplateDao (org.thingsboard.server.dao.oauth2)
  DeviceCredentialsDao (org.thingsboard.server.dao.device)
  DashboardDao (org.thingsboard.server.dao.dashboard)
  OtaPackageDao (org.thingsboard.server.dao.ota)
  RpcDao (org.thingsboard.server.dao.rpc)
  WidgetTypeDao (org.thingsboard.server.dao.widget)
  EntityViewDao (org.thingsboard.server.dao.entityview)
  AssetDao (org.thingsboard.server.dao.asset)
  OAuth2ParamsDao (org.thingsboard.server.dao.oauth2)
  EventDao (org.thingsboard.server.dao.event)
  WidgetsBundleDao (org.thingsboard.server.dao.widget)
  EdgeEventDao (org.thingsboard.server.dao.edge)
  TbResourceInfoDao (org.thingsboard.server.dao.resource)
  OAuth2RegistrationDao (org.thingsboard.server.dao.oauth2)
  OtaPackageInfoDao (org.thingsboard.server.dao.ota)
  UserDao (org.thingsboard.server.dao.user)
  ApiUsageStateDao (org.thingsboard.server.dao.usagerecord)
  DeviceProfileDao (org.thingsboard.server.dao.device)
  DeviceDao (org.thingsboard.server.dao.device)
  OAuth2DomainDao (org.thingsboard.server.dao.oauth2)
  RuleNodeDao (org.thingsboard.server.dao.rule)
  AdminSettingsDao (org.thingsboard.server.dao.settings)
  AlarmDao (org.thingsboard.server.dao.alarm)
  EdgeDao (org.thingsboard.server.dao.edge)
  AuditLogDao (org.thingsboard.server.dao.audit)
  UserCredentialsDao (org.thingsboard.server.dao.user)
  TbResourceDao (org.thingsboard.server.dao.resource)
  TenantProfileDao (org.thingsboard.server.dao.tenant)
  RuleChainDao (org.thingsboard.server.dao.rule)
  OAuth2MobileDao (org.thingsboard.server.dao.oauth2)
  RuleNodeStateDao (org.thingsboard.server.dao.rule)
  TenantDao (org.thingsboard.server.dao.tenant)
  CustomerDao (org.thingsboard.server.dao.customer)
  ComponentDescriptorDao (org.thingsboard.server.dao.component)
  DashboardInfoDao (org.thingsboard.server.dao.dashboard)
```

```
CrudRepository (org.springframework.data.repository)
  RuleNodeRepository (org.thingsboard.server.dao.sql.rule)
  AttributeKvRepository (org.thingsboard.server.dao.sql.attributes)
  PagingAndSortingRepository (org.springframework.data.repository)
  TsKvDictionaryRepository (org.thingsboard.server.dao.sqlts.dictionary)
  OtaPackageRepository (org.thingsboard.server.dao.sql.ota)
  AlarmRepository (org.thingsboard.server.dao.sql.alarm)
  RelationRepository (org.thingsboard.server.dao.sql.relation)
  UserCredentialsRepository (org.thingsboard.server.dao.sql.user)
  OAuth2ParamsRepository (org.thingsboard.server.dao.sql.oauth2)
  TbResourceRepository (org.thingsboard.server.dao.sql.resource)
  DashboardRepository (org.thingsboard.server.dao.sql.dashboard)
  TbResourceInfoRepository (org.thingsboard.server.dao.sql.resource)
  TsKvTimescaleRepository (org.thingsboard.server.dao.sqlts.timescale)
  AdminSettingsRepository (org.thingsboard.server.dao.sql.settings)
  OAuth2RegistrationRepository (org.thingsboard.server.dao.sql.oauth2)
  TsKvLatestRepository (org.thingsboard.server.dao.sqlts.latest)
  OAuth2DomainRepository (org.thingsboard.server.dao.sql.oauth2)
  OtaPackageInfoRepository (org.thingsboard.server.dao.sql.ota)
  OAuth2ClientRegistrationTemplateRepository (org.thingsboard.server.dao.sql.oauth2)
  TsKvRepository (org.thingsboard.server.dao.sqlts.ts)
  OAuth2MobileRepository (org.thingsboard.server.dao.sql.oauth2)
  RpcRepository (org.thingsboard.server.dao.sql.rpc)
  WidgetTypeRepository (org.thingsboard.server.dao.sql.widget)
  ApiUsageStateRepository (org.thingsboard.server.dao.sql.usagerecord)
```

#### 业务层（business service）

1. 位置

​	application/src/main/java/org/thingsboard/server/service

2. 互相调用的类
   1. dao service
   2. business service
   3. actor context
   4. ...
3. Js invoke 
   1. 内容发送到消息队列
   2. js evaluator执行器有两种类型：local,remote
      1. Local :  # Built-in JVM JavaScript environment properties
         1. `org.thingsboard.server.service.script.NashornJsInvokeService`
         2. 执行器实现类
            1. delight.nashornsandbox.NashornSandbox
            2. javax.script.ScriptEngine
      2. Remote  : # Remote JavaScript environment properties
         1. `org.thingsboard.server.service.script.RemoteJsInvokeService`

#### 关键工具类

##### ListenableFuture

1. 解析:https://github.com/google/guava/wiki/ListenableFutureExplained

2. 使用
   1. 耗时的dao查询，例如org.thingsboard.server.dao.relation.BaseRelationService

### api设计

#### Restful api

1. 接口路径设计
   1. /api/[分类]/[分类].../[动作]?参数
   2. 如果添加新版本的同一功能的接口，则在方法名后面添加xxxV1,xxxV2，如saveDeviceAttributes，saveEntityAttributesV1，saveEntityAttributesV2
   3. 备注：get，delete，save等意思的字眼，不在url中体现，因为request method替代了该意思
   4. 备注：api对应的java方法名，则需要添加相应的意思

2. Request Method
   1. GET,POST,DELETE
3. 接口传入参数设计
   1. get中url的参数，一般为业务参数
   2. post
      1. url的参数，有业务参数，例如id；非业务参数，例如校验，校验算法，平台种类...
      2. body参数为json（java bean），有复杂的java 对象
         1. 备注：类似于原有的复杂java对象中没有的某些字段（简单字段，id），就会使用url参数进行补全，例如有方向的动作，assignDeviceToEdge的/api/edge/{edgeId}/device/{deviceId}
   3. 传入javabean的类定义在`org.thingsboard.server.common.data`
      1. 某些reqeust类会放在特定[分类]包下的`model`包下，如`org.thingsboard.server.service.security.model.ResetPasswordRequest`
      2. 某些request会在其他包，如import功能的`org.thingsboard.server.service.importing.BulkImportRequest`
      3. 其他
         1. `com.fasterxml.jackson.databind.JsonNode`
         2. `java.util.Map`
   4. 参数校验
      1. **没有使用**类似的hibernate validate(javax.validation.constraints) 实现
      2. 其他实现
         1. javax.validation.Valid
         2. org.thingsboard.server.common.data.validation.NoXss
      3. controller下实现代码中主动调用检测
      4. dao service主动调用继承自`DataValidator`的`validate`方法，如assetValidator.validate(asset, Asset::getTenantId);

3. 接口返回值设计
   1. 返回json(javabean),string,boolean,void,long
   2. 返回javabean的类定义在`org.thingsboard.server.common.data`

4. 异常响应设计

   1. org.thingsboard.server.common.data.exception.ThingsboardException

      1. throw exception

         1. org.thingsboard.server.controller.BaseController#handleException(java.lang.Exception)

         2. 处理逻辑

            ```java
            if (exception instanceof ThingsboardException) {
                        return (ThingsboardException) exception;
                    } else if (exception instanceof IllegalArgumentException || exception instanceof IncorrectParameterException
                            || exception instanceof DataValidationException || cause.contains("IncorrectParameterException")) {
                        return new ThingsboardException(exception.getMessage(), ThingsboardErrorCode.BAD_REQUEST_PARAMS);
                    } else if (exception instanceof MessagingException) {
                        return new ThingsboardException("Unable to send mail: " + exception.getMessage(), ThingsboardErrorCode.GENERAL);
                    } else {
                        return new ThingsboardException(exception.getMessage(), ThingsboardErrorCode.GENERAL);
                    }
            ```

      2. handle exception

         1. 声明异常处理的地方
            1. org.thingsboard.server.controller.BaseController @ExceptionHandler(ThingsboardException.class)
            2. org.thingsboard.server.exception.ThingsboardErrorResponseHandler 
               1. @ExceptionHandler(AccessDeniedException.class)
               2. @ExceptionHandler(Exception.class)
         2. org.thingsboard.server.controller.BaseController#handleThingsboardException(ThingsboardException ex, HttpServletResponse response)

   2. 返回异常结果

      1. status code

         1. 使用到的response status

            ```
            HttpStatus.UNAUTHORIZED
            HttpStatus.FORBIDDEN
            HttpStatus.BAD_REQUEST
            HttpStatus.NOT_FOUND
            HttpStatus.INTERNAL_SERVER_ERROR
            ```

         2. 基于ThingsboardException的ThingsBoardErrorCode

            ```java
            GENERAL(2),//HttpStatus.INTERNAL_SERVER_ERROR
            AUTHENTICATION(10), //HttpStatus.UNAUTHORIZED
            JWT_TOKEN_EXPIRED(11),//HttpStatus.INTERNAL_SERVER_ERROR
            CREDENTIALS_EXPIRED(15),//HttpStatus.INTERNAL_SERVER_ERROR
            PERMISSION_DENIED(20),//HttpStatus.FORBIDDEN
            INVALID_ARGUMENTS(30),//HttpStatus.BAD_REQUEST
            BAD_REQUEST_PARAMS(31),//HttpStatus.BAD_REQUEST
            ITEM_NOT_FOUND(32),//HttpStatus.NOT_FOUND
            TOO_MANY_REQUESTS(33),//HttpStatus.INTERNAL_SERVER_ERROR
            TOO_MANY_UPDATES(34),//HttpStatus.INTERNAL_SERVER_ERROR
            SUBSCRIPTION_VIOLATION(40);//HttpStatus.FORBIDDEN
            ```

         3. 基于其他exception

            ```java
            TbRateLimitsException
            	//HttpStatus.TOO_MANY_REQUESTS,ThingsboardErrorCode.TOO_MANY_REQUESTS
            
            AccessDeniedException
            	//HttpStatus.FORBIDDEN,ThingsboardErrorCode.PERMISSION_DENIED
            	//备注：org.thingsboard.server.exception.ThingsboardErrorResponseHandler#handle(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, org.springframework.security.access.AccessDeniedException)这个方法声明了@ExceptionHandler(AccessDeniedException.class)
              
            AuthenticationException
            	//HttpStatus.UNAUTHORIZED
            	//ThingsboardErrorCode.AUTHENTICATION，ThingsboardErrorCode.JWT_TOKEN_EXPIRED，ThingsboardErrorCode.CREDENTIALS_EXPIRED
            ```

         4. 前端根据errorCode区分特定的错误场景

            1. 用户鉴权，如JWT_TOKEN_EXPIRED，CREDENTIALS_EXPIRED

      2. body

         ```
         // HTTP Response Status Code
         private final HttpStatus status;
         // General Error message
         private final String message;
         // Error code
         private final ThingsboardErrorCode errorCode;
         private final Date timestamp;
         
         eg:
         Response Body
         {
           "status": 401,
           "message": "Authentication failed",
           "errorCode": 10,
           "timestamp": "2021-11-03T07:17:00.424+00:00"
         }
         Response Code
         	401
         ```

5. 分页设计

   1. 方法名

      1. getXXX
      2. getAllXXX

   2. 传入参数

      1. url参数
         1. 分页
            1. pageSize
            2. page
         2. 其他
            1. textSearch
            2. sortOrder
               1. property
               2. direction : ASC,DESC

   3. 返回结果

      1. org.thingsboard.server.common.data.page.PageData<T>

         ```
         data (Array[T], optional),
         hasNext (boolean, optional),
         totalElements (integer, optional),
         totalPages (integer, optional)
         ```

   4. 逻辑分析

      ```java
      org.thingsboard.server.controller.AlarmController#getAlarms
        	返回：org.thingsboard.server.common.data.page.PageData
        org.thingsboard.rule.engine.api.RuleEngineAlarmService#findAlarms
        	org.thingsboard.server.dao.alarm.AlarmService#findAlarms
        		org.thingsboard.server.dao.alarm.AlarmDao#findAlarms
        			**org.thingsboard.server.dao.sql.alarm.AlarmRepository#findAlarms
        						传入：1.分页：org.springframework.data.domain.Pageable
        						返回值：org.springframework.data.domain.Page
        					org.thingsboard.server.dao.DaoUtil#toPageable
        				org.thingsboard.server.dao.DaoUtil#toPageData
        						传入：org.springframework.data.domain.Page
        						返回：org.thingsboard.server.common.data.page.PageData
      ```

      备注

      	1. entity到common data的流程：dao -> dao service -> dao util -> common data
      	2. 分页传入参数转换: String->`org.thingsboard.server.common.data.page.PageLink`->`org.springframework.data.domain.Pageable`
      	3. 分页返回对象转换：`org.springframework.data.domain.Page`->`org.thingsboard.server.common.data.page.PageData`

6. rpc

   1. `org.springframework.web.context.request.async.DeferredResult`

      ```java
      org.thingsboard.server.controller.RpcV2Controller#handleTwoWayDeviceRPCRequest
      	org.thingsboard.server.controller.AbstractRpcController#handleDeviceRPCRequest
      		 final DeferredResult<ResponseEntity> response = new DeferredResult<>();
      		 accessValidator.validate
      		 	onSuccess
      		 		deviceRpcService.processRestApiRpcRequest
                  fromDeviceRpcResponse -> reply
                    DeferredResult<ResponseEntity> responseWriter = rpcRequest.getResponseWriter();
                    responseWriter.setResult
      		 	onFailure
      		 		response.setResult(entity);
      
      //将执行的任务推到规则引擎的队列，并开启timeout定时器
      deviceRpcService.processRestApiRpcRequest
        	UUID requestId = request.getId();
      		//本地记录请求和响应处理
          localToRuleEngineRpcRequests.put(requestId, responseConsumer);
          sendRpcRequestToRuleEngine(request, currentUser);
          scheduleToRuleEngineTimeout(request, requestId);
      
      //rpc消息处理处理
      AbstractConsumerService.launchNotificationsConsumer
        	//死循环遍历处理
      	DefaultTbCoreConsumerService#handleNotification
          forwardToCoreRpcService
          	TbCoreDeviceRpcService.processRpcResponseFromRuleEngine
          		onsumer<FromDeviceRpcResponse> consumer = localToRuleEngineRpcRequests.remove(requestId);
      				consumer.accept(response);
      
      //概况,后台前端调用/api/rpc/twoway/
      1.controller接收rpc请求
      2.将rpc请求（id，回调处理）记录到本地map，将rpc请求发送到消息队列（规则引擎）
      3.rpc请求处理
        1.规则引擎处理rpc请求,流转到
        	1.TbSendRPCRequestNode.onMsg
        		DefaultTbRuleEngineRpcService.sendRpcRequestToDevice
        			forwardRpcRequestToDeviceActor
        				//ToDeviceRpcRequestActorMsg rpcMsg = new ToDeviceRpcRequestActorMsg(serviceId, msg);
        				//MsgType.DEVICE_RPC_REQUEST_TO_DEVICE_ACTOR_MSG
        				DefaultTbCoreDeviceRpcService.forwardRpcRequestToDeviceActor
        					actorContext.tellWithHighPriority(rpcMsg);
      							appActor.tellWithHighPriority(tbActorMsg);//appActor = DeviceActor
      		2.DeviceActor.doProcess
            DeviceActorMessageProcessor.processRpcRequest(ctx, (ToDeviceRpcRequestActorMsg) msg);
      				sendToTransport(rpcRequest, key, value.getNodeId());
      					DefaultTbCoreToTransportService.process(nodeId, msg);
      						tbTransportProducer.send(tpi, queueMsg, new QueueCallbackAdaptor(onSuccess, onFailure));
      		3.DefaultTransportService.processToTransportMsg
            	SessionMetaData md = sessions.get(sessionId);
      					SessionMsgListener listener = md.getListener();
      						listener.onToDeviceRpcRequest(sessionId, toSessionMsg.getToDeviceRequest());
      						MqttTransportHandler.onToDeviceRpcRequest
                    MqttTransportHandler.publish
                    	deviceSessionCtx.getChannel().writeAndFlush(message);
      									ChannelHandlerContext.writeAndFlush
                          //返回发送是否成功的结果
                          	DefaultTransportService.process
      		//备注：消息->TbSendRPCRequestNode->DeviceActor->DefaultTbCoreToTransportService->(消费)DefaultTransportService的mainConsumerExecutor->DefaultTransportService->MqttTransportHandler->ChannelHandlerContext
        2.device rpc请求的处理，先有device进行订阅，再由实体的device进行处理，然后对rpc进行响应（将处理结果返回thingsboard）
        	订阅与响应v1/devices/me/rpc/[request|response]/$request_id
      4.对rpc结果进行响应（由consumerService开启线程，对消息队列的消息（rpc结果响应）进行处理）
      	1.进行响应前，先查找本地map是否存在适配的requestId，然后再进行响应
      ```

### 权限控制

接口鉴权

```
@PreAuthorize("hasAnyAuthority(...)")
	'SYS_ADMIN', 'TENANT_ADMIN', 'CUSTOMER_USER'
@PreAuthorize("isAuthenticated()")
```

业务鉴权

```java
//定义
public DefaultAccessControlService(
  @Qualifier("sysAdminPermissions") Permissions sysAdminPermissions,
  @Qualifier("tenantAdminPermissions") Permissions tenantAdminPermissions,
  @Qualifier("customerUserPermissions") Permissions customerUserPermissions) {
  authorityPermissions.put(Authority.SYS_ADMIN, sysAdminPermissions);
  authorityPermissions.put(Authority.TENANT_ADMIN, tenantAdminPermissions);
  authorityPermissions.put(Authority.CUSTOMER_USER, customerUserPermissions);
}

//权限校验
//在controller里手动调用校验方法
/**
如以下业务所使用到的
AdminController
BaseController
OAuth2ConfigTemplateController
OAuth2Controller
TenantProfileController
**/
DefaultAccessControlService
  checkPermission(SecurityUser user, Resource resource, Operation operation)
```

### 数据库设计

1. 命名规范

   1. 表名
      1. 无项目前缀（例外：tb_schema_settings，tb_user）
      2. 小写
      3. 单词间下划线隔开
   2. 字段名
      1. 通用字段（id，created_time）
      2. 外键id，业务名_id，如user_id
      3. 单词间下划线隔开
      4. 特殊关键字不简写，description
   3. 字段类型和长度
      1. uuid
      2. varchar(32)
      3. varchar(255)
         1. 通用
         2. password
         3. token
      4. varchar(10000000)
      5. varchar(1000000)
         1. image
      6. varchar
         1. 无限长
      7. bool

2. 约束

   1. 主键(xxx_pkey)eg:device_pkey
   2. 联合唯一主键(xxx_yyy_unq_key)eg:device_name_unq_key
   3. 唯一约束(xxx_key)eg:user_credentials_activate_token_key

3. 外键

   1. fk_xxx_yyy,eg:fk_default_rule_chain_device_profile

4. 索引

5. 触发器（无）

6. 函数

   1. to_uuid
   2. cleanup_timeseries_by_ttl
   3. ...

7. 数据库升级逻辑

   1. 版本识别

      1. from version

         1. 通过执行upgrade程序，传入--fromVersion=x.x.x，如

            ```
            C:\thingsboard>upgrade.bat --fromVersion=3.3.0
            ```

   2. 升级的内容

      1. schema结构
      2. 数据

   3. 采用升级技术

      1. 不使用第三方框架，手动执行Statement
      2. 需要升级的数据，写在java，sql，json文件里

   4. 如果改动了schema结构，那么在升级完成后，更新tb_schema_settings.schema_version

### 日志记录

1. 普通日志

   1. 框架

      1. logback

         1. install.log

            1. 按日滚动

            2. 最多30日

            3. 单个日志文件最大尺寸：100MB

            4. 总日志文件尺寸：3GB

            5. packaging/java/scripts/install/logback.xml

               ```
               <appender name="fileLogAppender"
                         class="ch.qos.logback.core.rolling.RollingFileAppender">
                   <file>${pkg.logFolder}/install.log</file>
                   <rollingPolicy
                           class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
                       <fileNamePattern>${pkg.logFolder}/install.%d{yyyy-MM-dd}.%i.log</fileNamePattern>
                       <maxFileSize>100MB</maxFileSize>
                       <maxHistory>30</maxHistory>
                       <totalSizeCap>3GB</totalSizeCap>
                   </rollingPolicy>
                   <encoder>
                       <pattern>%d{ISO8601} [%thread] %-5level %logger{36} - %msg%n</pattern>
                   </encoder>
               </appender>
               ```

         2. gc.log

            1. msa/tb/docker/thingsboard.conf

               ```shell
               export JAVA_OPTS="$JAVA_OPTS -Xlog:gc*,heap*,age*,safepoint=debug:file=@pkg.logFolder@/gc.log:time,uptime,level,tags:filecount=10,filesize=10M"
               ```

         3. Thingsboard.xxx.y.log(eg: thingsboard.2021-10-22.0.log)

            1. 按日滚动

            2. 最多30日

            3. 单个日志文件最大尺寸：100MB

            4. 总日志文件尺寸：3GB

            5. msa/tb/docker/logback.xml

               ```xml
               <appender name="fileLogAppender"
                         class="ch.qos.logback.core.rolling.RollingFileAppender">
                   <file>/var/log/thingsboard/thingsboard.log</file>
                   <rollingPolicy
                           class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
                       <fileNamePattern>/var/log/thingsboard/thingsboard.%d{yyyy-MM-dd}.%i.log</fileNamePattern>
                       <maxFileSize>100MB</maxFileSize>
                       <maxHistory>30</maxHistory>
                       <totalSizeCap>3GB</totalSizeCap>
                   </rollingPolicy>
                   <encoder>
                       <pattern>%d{ISO8601} [%thread] %-5level %logger{36} - %msg%n</pattern>
                   </encoder>
               </appender>
               ```

   2. 使用

      1. lombok.extern.slf4j.Slf4j
         1. private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger
         2. 等级的使用
            1. error
               1. 超出预期的，如Tenant with such ID does not exist
            2. warn
               1. 冲突的，如Message has system tenant id: {}
            3. info
               1. 肯定的，执行的，如Handling tenant deleted notification
               2. 执行结果，如Main system actor started.
            4. debug
               1. 不合法的动作，如Invalid component lifecycle msg
               2. 逻辑详情，如[{}] Creating tenant actor，[{}] Tenant actor created.
               3. 备注：对于某些复杂逻辑日志输出，debug开关的处理，使用log.isDebugEnabled()
            5. trace
               1. 事件触发类，频繁的，如[{}] Processing edge update {}

2. 审计日志

   1. 进行审计日志记录的地方（一般在controller，少数在service,provider）

      1. AlarmController
      2. AssetController
      3. CustomerController
      4. DashboardController
      5. DeviceController
      6. DeviceProfileController
      7. EdgeController
      8. EntityRelationController
      9. EntityViewController
      10. OtaPackageController
      11. RuleChainController
      12. TbResourceController
      13. UserController
      14. AbstractBulkImportService
      15. RestAuthenticationProvider

   2. 逻辑

      ```java
      AuditLogServiceImpl
      
      org.thingsboard.server.dao.audit.AuditLogServiceImpl#logAction
        //将日志记录执行放进futures
        List<ListenableFuture<Void>> futures = Lists.newArrayListWithExpectedSize(INSERTS_PER_ENTRY);
                futures.add(auditLogDao.saveByTenantId(auditLogEntry));
        //保存到其他第三方服务，如ElasticsearchAuditLogSink，开关见：audit-log.sink
        //auditLogSink动态注入，使用@ConditionalOnProperty(prefix = "audit-log.sink", value = "type", havingValue = "elasticsearch")
        auditLogSink.logAction(auditLogEntry);
      
      //
      【JpaAuditLogDao】auditLogDao.saveByTenantId(auditLogEntry)
      	  【JpaExecutorService】service.submit(() -> {
                  save(auditLog.getTenantId(), auditLog);
            				
                  return null;
              });
      ```

   3. 审计日志记录数据结构

      ```
      protected AuditLogId id;
      protected long createdTime;
      private TenantId tenantId;
      private CustomerId customerId;
      private EntityId entityId;
      private String entityName;
      private UserId userId;
      private String userName;
      private ActionType actionType;
      	ADDED(false), // log entity
        DELETED(false), // log string id
        UPDATED(false), // log entity
        ATTRIBUTES_UPDATED(false), // log attributes/values
        ATTRIBUTES_DELETED(false), // log attributes
        TIMESERIES_UPDATED(false), // log timeseries update
        TIMESERIES_DELETED(false), // log timeseries
        RPC_CALL(false), // log method and params
        CREDENTIALS_UPDATED(false), // log new credentials
        ASSIGNED_TO_CUSTOMER(false), // log customer name
        UNASSIGNED_FROM_CUSTOMER(false), // log customer name
        ACTIVATED(false), // log string id
        SUSPENDED(false), // log string id
        CREDENTIALS_READ(true), // log device id
        ATTRIBUTES_READ(true), // log attributes
        RELATION_ADD_OR_UPDATE(false),
        RELATION_DELETED(false),
        RELATIONS_DELETED(false),
        ALARM_ACK(false),
        ALARM_CLEAR(false),
        ALARM_DELETE(false),
        LOGIN(false),
        LOGOUT(false),
        LOCKOUT(false),
        ASSIGNED_FROM_TENANT(false),
        ASSIGNED_TO_TENANT(false),
        PROVISION_SUCCESS(false),
        PROVISION_FAILURE(false),
        ASSIGNED_TO_EDGE(false), // log edge name
        UNASSIGNED_FROM_EDGE(false);
      private JsonNode actionData;
      private ActionStatus actionStatus;
      	SUCCESS, FAILURE
      private String actionFailureDetails;
      ```

      schema

      ```
      id
      created_time
      tenant_id
      customer_id
      entity_id
      entity_type
      entity_name
      user_id
      user_name
      action_type
      action_data
      action_status
      action_failure_details
      ```

### 缓存

1. 配置

   ```
   cache:
     # caffeine or redis
     type: "${CACHE_TYPE:caffeine}"
     maximumPoolSize: "${CACHE_MAXIMUM_POOL_SIZE:16}" # max pool size to process futures that calls the external cache
     attributes:
       # make sure that if cache.type is 'redis' and cache.attributes.enabled is 'true' that you change 'maxmemory-policy' Redis config property to 'allkeys-lru', 'allkeys-lfu' or 'allkeys-random'
       enabled: "${CACHE_ATTRIBUTES_ENABLED:true}"
   ```

2. 种类

   1. caffeine

      1. caffeine

         ```
         @ConditionalOnProperty(prefix = "cache", value = "type", havingValue = "caffeine", matchIfMissing = true)
         org.thingsboard.server.cache.CaffeineCacheConfiguration
         ```

   2. redis

      1. standalone

         ```
         @ConditionalOnProperty(prefix = "cache", value = "type", havingValue = "redis", matchIfMissing = false)
         @ConditionalOnProperty(prefix = "redis.connection", value = "type", havingValue = "standalone")
         org.thingsboard.server.cache.TBRedisStandaloneConfiguration
         ```

      2. cluster

         ```
         @ConditionalOnProperty(prefix = "cache", value = "type", havingValue = "redis", matchIfMissing = false)
         @ConditionalOnProperty(prefix = "redis.connection", value = "type", havingValue = "cluster")
         org.thingsboard.server.cache.TBRedisClusterConfiguration
         ```

3. 使用服务类

   1. `org.springframework.cache.CacheManager`

   2. 进行缓存的地方

      1. org.thingsboard.server.service.device
      2. org.thingsboard.server.service.security.auth
      3. org.thingsboard.server.dao.asset
      4. org.thingsboard.server.dao.device
      5. org.thingsboard.server.dao.edge
      6. org.thingsboard.server.dao.entityview
      7. org.thingsboard.server.dao.ota
      8. org.thingsboard.server.dao.relation
      9. org.thingsboard.server.dao.service
      10. org.thingsboard.server.dao.tenant

   3. 使用的方法

      ```
      Cache cache = cacheManager.getCache();
      cache.get
      cache.putIfAbsent
      cache.evict
      ```

   4. key的定义

      ```java
      CacheConstants
          public static final String DEVICE_CREDENTIALS_CACHE = "deviceCredentials";
          public static final String RELATIONS_CACHE = "relations";
          public static final String DEVICE_CACHE = "devices";
          public static final String SESSIONS_CACHE = "sessions";
          public static final String ASSET_CACHE = "assets";
          public static final String ENTITY_VIEW_CACHE = "entityViews";
          public static final String EDGE_CACHE = "edges";
          public static final String CLAIM_DEVICES_CACHE = "claimDevices";
          public static final String SECURITY_SETTINGS_CACHE = "securitySettings";
          public static final String TENANT_PROFILE_CACHE = "tenantProfiles";
          public static final String DEVICE_PROFILE_CACHE = "deviceProfiles";
          public static final String ATTRIBUTES_CACHE = "attributes";
          public static final String TOKEN_OUTDATAGE_TIME_CACHE = "tokensOutdatageTime";
          public static final String OTA_PACKAGE_CACHE = "otaPackages";
          public static final String OTA_PACKAGE_DATA_CACHE = "otaPackagesData";
      ```

### [edge](https://thingsboard.io/docs/edge/)（暂未找到开源代码）

he **ThingsBoard Edge** is a ThingsBoard’s software product for edge computing. It allows bringing data analysis and management to the edge, while seamlessly synchronizing with ThingsBoard CE/PE server (cloud).

#### proto3

1. 为了序列化与反序列化消息更快
2. rpc消息交互使用了特殊的实现，如common/message/src/main/proto/tbmsg.proto自动生成org.thingsboard.server.common.msg.gen下的类实现
3. 自动生成
   1. idea的插件protocol buffers会自动生成
   2. maven编译使用了org.xolstice.maven.plugins:protobuf-maven-plugin（pom.xml）来生成
4. com.google.protobuf.protobuf-java

##### cluster api（与[edge](https://thingsboard.io/docs/edge/)有关，待研究）

##### edge api（与[edge](https://thingsboard.io/docs/edge/)有关，待研究）

### tool

1. migrator
   1. This tool used for migrating ThingsBoard into hybrid mode from Postgres.
2. python
   1. mqtt example
3. shell
   1. keygen

### 配置设计

1. thingsboard.yml

   1. application/src/main/resources/thingsboard.yml

2. 其他

   1. transport/coap/src/main/resources/tb-coap-transport.yml
   2. transport/http/src/main/resources/tb-http-transport.yml

3. 编码

   ```
   //默认值#{xxx:yyy}
   //注释，在参数上方
   server:
     # Server bind address
     address: "${HTTP_BIND_ADDRESS:0.0.0.0}"
     
   //注释，提示可选项
     http2:
       # Enable/disable HTTP/2 support
       enabled: "${HTTP2_ENABLED:true}"
   
   cache:
     # caffeine or redis
     type: "${CACHE_TYPE:caffeine}"
   ```

4. 使用

   1. @Value，数值引用
      1. @Value("${security.user_token_access_enabled}")
   2. @ConditionalOnProperty，注入逻辑判断
      1. @ConditionalOnProperty(prefix = "cache", value = "type", havingValue = "caffeine", matchIfMissing = true)

### demo数据	

1. 数据来源

   1. json文件
      1. application/src/main/data/json/demo
   2. java代码
      1. org.thingsboard.server.service.install.DefaultSystemDataLoaderService#loadDemoData

2. 使用

   1. 启动

      ```shell
      # --loadDemo option will load demo data: users, devices, assets, rules, widgets.
      sudo /usr/share/thingsboard/bin/install/install.sh --loadDemo
      ```

   2. 逻辑分析

      ```
      ThingsboardInstallService
      	@Value("${install.load_demo:false}")
      	systemDataLoaderService.loadDemoData();
      	DefaultSystemDataLoaderService.loadDemoData();
      ```

### 单元测试

1. 使用的类库

   1. junit
   2. mockito

2. 测试的层次

   1. actors.device

      1. junit
      2. mockito

   2. cache

      1. junit
      2. @ExtendWith(SpringExtension.class)

   3. controller

      1. 测试依赖

         1. junit

         2. @SpringBootTest()

         3. @RunWith(SpringRunner.class)

         4. @ActiveProfiles("test")

         5. org.thingsboard.server.controller.AbstractWebTest

            1. org.springframework.test.web.servlet.MockMvc

               1. ```
                  this.mockMvc = webAppContextSetup(webApplicationContext)
                          .apply(springSecurity()).build();
                  ```

      2. 使用

         1. org.thingsboard.server.controller.AbstractWebTest#doGet(java.lang.String, java.lang.Object...)
         2. org.thingsboard.server.controller.AbstractWebTest#doPost(java.lang.String, T, java.lang.String...)

      3. 测试覆盖

         1. 大部分api
         2. 对于复杂的api，例如查找功能，则直接在测试的方法里调用save的api(mockMvc)，然后再调用find的api(mockMvc)，最后校验，使得数据来源，数据获取，数据校验在同一个测试方法里。

   4. edge

      1. org.thingsboard.server.edge.imitator.EdgeImitator

   5. rules

      1. 测试依赖
         1. service
         2. junit
         3. @SpringBootTest()
         4. @RunWith(SpringRunner.class)
         5. @ActiveProfiles("test")
         6. org.thingsboard.server.controller.AbstractWebTest

   6. service

      1. 测试依赖
         1. @RunWith(MockitoJUnitRunner.class)
         2. org.mockito.Mock
         3. junit

   7. system

      1. 测试依赖
         1. junit
         2. @SpringBootTest()
         3. @RunWith(SpringRunner.class)
         4. @ActiveProfiles("test")
         5. org.thingsboard.server.controller.AbstractWebTest

   8. transport

      1. 测试依赖

         1. junit

         2. @SpringBootTest()

         3. @RunWith(SpringRunner.class)

         4. @ActiveProfiles("test")

         5. org.thingsboard.server.controller.AbstractWebTest

         6. mqtt

            1. org.eclipse.paho.client.mqttv3.MqttAsyncClient

               1. ```java
                  MqttAsyncClient client = new MqttAsyncClient(MQTT_URL, clientId, new MemoryPersistence());
                  ```

         7. Lwm2m //TODO
         8. Coap
            1. new org.eclipse.californium.core.CoapClient

   9. util

### 代码风格

#### 代码编码风格

1. 模块
   1. application
   2. common
   3. dao
   4. rule-engine
   5. netty-mqttt
2. 包
   1. org.thingsboard
      1. client
      2. common
      3. edge
      4. mqtt
      5. rest
      6. rule.engine
      7. server
         1. actors
         2. cache
         3. cluster
         4. coap
         5. coapserver
         6. common
            1. data
            2. msg
            3. stats
            4. transport
         7. config
         8. controller
         9. dao
            1. model
            2. service
            3. sql
            4. sqlts
            5. util
         10. edge
         11. gen
         12. http
         13. install
         14. queue
         15. ruless
         16. service
             1. security
             2. telemetry
         17. transport
         18. utils
3. 类
   1. service
      1. 接口+实现类命名
         1. 实现类：无前缀，Default前缀，，Impl后缀（部分实现类）
   2. 后接层级名字
      1. xxxController
      2. xxxService
      3. xxxActor
      4. xxxProcessor
      5. xxxMsg
      6. xxxFliter
      7. xxxConfiguration
      8. xxxTemplate
         1. common/queue/src/main/java/org/thingsboard/server/queue/common/DefaultTbQueueRequestTemplate.java
      9. xxxEvent
   3. 以项目缩写为前缀
      1. Tbxxx
         1. TbActor
         2. TBRedisCacheConfiguration
         3. ...
   4. DTO层（data包）
      1. 不添加前缀和后缀
   5. DAO层
      1. xxxDao
   6. controller层的请求和返回值
      1. 请求
         1. 字面值
         2. 普通data类
            1. org.thingsboard.server.common.data.AdminSettings
         3. data类Request
            1. org.thingsboard.server.common.data.sms.config.TestSmsRequest
      2. 返回值
         1. 基本数据类型
            1. String
            2. int
            3. Boolean
         2. void
         3. data类
4. 枚举
   1. 无修饰
      1. Operation
         1. ALL
         2. CREATE
         3. ...
   2. 后缀
      1. MsgType
         1. PARTITION_CHANGE_MSG
         2. APP_INIT_MSG
         3. ...
      2. TbAttributeSubscriptionScope
         1. ANY_SCOPE
         2. CLIENT_SCOPE
         3. ...
5. 逻辑分支
   1. if
      1. 三段式的使用，? :
      2. 部分简单的逻辑没有else

#### 代码提交信息风格

1. 以issues序号开头
   1. TB-xx
      1. TB-33: Implementation
      2. TB-34: Implementation
2. 动词
   1. added
   2. fixed,Fix,Fixed
   3. Update
3. 以模块开头
   1. UI:
      1. UI: widget config improvements.
4. 以版本开头
   1. [3.0]
      1. [3.0] Added possibility to login by url params (#2592)
   2. [2.5]
      1. [2.5] Added possibility to login by url params (#2581)

### 前端分析

1. 框架

   1. angular
   2. 代码结构
      1. 使用了标准的angular开发规范的代码结构

2. 依赖库

   1. @angular/material
      1. 主UI框架

   2. @flowjs/ngx-flow
      1. upload file

   3. @ngx-translate
      1. 国际化

   4. angular2-hotkeys
      1. 快捷键

   5. angular-gridster2
      1. 网格布局

   6. @juggle/resize-observer
      1. 尺寸调整监听器

   7. @date-io/date-fns
      1. 日期处理

   8. @auth0/angular-jwt
      1. jwt处理

   9. canvas-gauges
      1. iot device展示

   10. font-awesome ^4.7.0
       1. font图标

   11. html2canvas
   12. jquery
   13. jquery.terminal
       1. 模拟command终端（如thingsboard的rpc调试终端）

   14. js-beautify
       1. 格式化js内容

   15. jstree
       1. 树组件

   16. jszip
       1. 读写压缩文件

   17. leaflet
       1. 地图

   18. ngx-clipboard
       1. 粘贴板

   19. ngx-color-picker
       1. 颜色选择器

   20. ngx-drag-drop
       1. 拖拽

   21. qrcode
   22. screenfull
       1. 全屏

   23. split.js
   24. systemjs
       1. 动态js模块载入器

   25. typeface-roboto
       1. roboto字体

3. 多语言文件

   1. 位置
      1. src/assets/locale

   2. 文件结构
      1. 一个文件代表整个语言所有的国际化内容
         1. src/assets/locale/locale.constant-en_US.json：3287行
         2. src/assets/locale/locale.constant-zh_CN.json：2670行

      2. 例如
         1. src/assets/locale/locale.constant-en_US.json
         2. src/assets/locale/locale.constant-zh_CN.json
         3. src/assets/locale/locale.constant-zh_TW.json

      3. 内容
         1. key的层级较少，按功能模块进行区分
         2. 单词间一般用-隔开
            1. widget
            2. widget-type
            3. widget-config
            4. action

4. 配置

   1. 开发环境
   2. 产品环境

5. service api地址的映射

   1. angular.json

      ```json
      "serve": {
        "builder": "@angular-builders/custom-webpack:dev-server",
        "options": {
          "browserTarget": "thingsboard:build",
          "proxyConfig": "proxy.conf.js"
        },
      ```

   2. proxy.conf.js

      ```javascript
      const forwardUrl = "http://localhost:8080";
      const wsForwardUrl = "ws://localhost:8080";
      const ruleNodeUiforwardUrl = forwardUrl;
      
      const PROXY_CONFIG = {
        "/api": {
          "target": forwardUrl,
          "secure": false,
        },
        "/static/rulenode": {
          "target": ruleNodeUiforwardUrl,
          "secure": false,
        },
        "/static/widgets": {
          "target": forwardUrl,
          "secure": false,
        },
        "/oauth2": {
          "target": forwardUrl,
          "secure": false,
        },
        "/login/oauth2": {
          "target": forwardUrl,
          "secure": false,
        },
        "/api/ws": {
          "target": wsForwardUrl,
          "ws": true,
          "secure": false
        },
      };
      ```

6. css

   1. theme
      1. src/theme.scss

7. auth （待研究）

   1. login
   2. guard
      1. src/app/core/guards

   3. http interceptor
      1. src/app/core/interceptors/global-http-interceptor.ts
      2. Refresh token
      3. Error code handle

8. http api

   1. Page
      1. src/app/shared/models/page

9. storage

   1. src/app/core/local-storage/local-storage.service.ts

10. dashboard

    1. 展示

       1. 入口列表

          1. src/app/modules/home/pages/dashboard/dashboard-routing.module.ts

             1. path: 'dashboards',

          2. path: '',

             1. src/app/modules/home/components/entity/entities-table.component.ts

                1. DashboardsTableConfigResolver,注入配置

                2. src/app/modules/home/pages/dashboard/dashboards-table-config.resolver.ts

                   ```
                   //数据来源
                   DashboardsTableConfigResolver.constructor
                   	this.config.loadEntity = id => this.dashboardService.getDashboard(id.id);
                   	DashboardService.getDashboard
                   		this.http.get<Dashboard>(`/api/dashboard/${dashboardId}`, defaultHttpOptionsFromConfig(config));
                   		
                   //点击某项实体的open dashboard
                   configureCellActions(dashboardScope: string): Array<CellActionDescriptor<DashboardInfo>> {
                       const actions: Array<CellActionDescriptor<DashboardInfo>> = [];
                       actions.push(
                         {
                           name: this.translate.instant('dashboard.open-dashboard'),
                           icon: 'dashboard',
                           isEnabled: () => true,
                           onAction: ($event, entity) => this.openDashboard($event, entity)
                         }
                       );
                   
                   openDashboard
                   	this.router.navigateByUrl(`dashboards/${dashboard.id.id}`);
                   		//跳转到
                   		 path: ':dashboardId',
                        component: DashboardPageComponent,
                   ```

          3. path: ':dashboardId',

             1. src/app/modules/home/components/dashboard-page/dashboard-page.component.html

             2. 展示widget

                ```javascript
                dashboard-page.component.html
                	 <tb-dashboard-layout>
                	 		[widgets]="layoutCtx.widgets"
                	 	<tb-dashboard>
                        @Input()
                        widgets: Iterable<Widget>;
                    this.dashboardWidgets.setWidgets(this.widgets, this.widgetLayouts);
                    <gridster-item [item]="widget" [ngClass]="{'tb-noselect': isEdit}" *ngFor="let widget of dashboardWidgets">
                    	<tb-widget-container>
                    			src/app/modules/home/components/widget/widget-container.component.html
                    		[dashboardWidgets]="dashboardWidgets"
                				<tb-widge>
                						src/app/modules/home/components/widget/widget.component.html
                					<ng-container #widgetContent></ng-container>
                //如何动态生成组件？通过componentFactory进行生成
                						this.dynamicWidgetComponentRef = this.widgetContentContainer.createComponent(this.widgetInfo.componentFactory, 0, injector);
                					this.widgetContext.$container = $(this.dynamicWidgetComponentRef.location.nativeElement);
                					
                
                //下面为生成componentFactory而准备
                //src/app/modules/home/components/widget/widget-component.service.ts
                
                //css
                this.cssParser.cssPreviewNamespace = widgetNamespace;
                    this.cssParser.createStyleElement(widgetNamespace, widgetInfo.templateCss);
                    
                //html
                	this.dynamicComponentFactoryService.createDynamicComponentFactory(
                              class DynamicWidgetComponentInstance extends DynamicWidgetComponent {},
                              widgetInfo.templateHtml,
                              resolvedModules
                	//src/app/core/services/dynamic-component-factory.service.ts
                			node_modules/@angular/core/core.d.ts
                				Component
                    
                //script
                loadWidget
                	widgetControllerDescriptor = 		this.createWidgetControllerDescriptor(widgetInfo, key);
                ```

             3. widget生成原理
                1. 通过import('@angular/compiler')和angular的Component进行创建

2. 线上编辑

### 单体与微服务版本生成原理

1. 原理

   1. pom模块的声明

   2. pom模块的依赖

   3. springboot的org.springframework.boot.autoconfigure.condition.ConditionalOnExpression

      1. mqtt transport

         ```java
         org.thingsboard.server.transport.mqtt.MqttTransportService
         
         @ConditionalOnExpression("'${service.type:null}'=='tb-transport' || ('${service.type:null}'=='monolith' && '${transport.api_enabled:true}'=='true' && '${transport.mqtt.enabled}'=='true')")
         ```

      2. coap transport

         ```
         org.thingsboard.server.transport.coap.CoapTransportService
         
         org.thingsboard.server.coapserver.TbCoapServerComponent
         	@ConditionalOnExpression("'${service.type:null}'=='tb-transport' || ('${service.type:null}'=='monolith' && '${transport.api_enabled:true}'=='true' && '${transport.coap.enabled}'=='true')")
         ```


### 编译与打包

1. Java

   1. <pkg.type>java</pkg.type>

      1. application/pom.xml
      1. transport/coap/pom.xml
      1. transport/http/pom.xml
      1. transport/lwm2m/pom.xml
      1. transport/mqtt/pom.xml
      1. transport/snmp/pom.xml

   2. maven 执行gradle脚本

      ```xml
      <plugin>
      <groupId>org.thingsboard</groupId>
      <artifactId>gradle-maven-plugin</artifactId>
      ```

   3. 安装包的生成

      1. Rpm,Deb

         packaging/java/build.gradle

         ```
         plugins {
             id "nebula.ospackage" version "8.6.3"
         }
         
         buildRpm
         buildDeb
         ```

      2. Window exe

         1. exe(service.exe)

            pom.xml

            ```xml
            <plugin>
              <groupId>org.apache.maven.plugins</groupId>
              <artifactId>maven-dependency-plugin</artifactId>
              <executions>
                <execution>
                  <id>copy-winsw-service</id>
                  <phase>${pkg.package.phase}</phase>
                  <goals>
                    <goal>copy</goal>
                  </goals>
                  <configuration>
                    <artifactItems>
                      <artifactItem>
                        <groupId>com.sun.winsw</groupId>
                        <artifactId>winsw</artifactId>
                        <classifier>bin</classifier>
                        <type>exe</type>
                        <destFileName>service.exe</destFileName>
                      </artifactItem>
                    </artifactItems>
                    <outputDirectory>${pkg.win.dist}</outputDirectory>
                  </configuration>
                </execution>
              </executions>
            </plugin>
            ```

         2. zip(thingsboard-windows.zip)

            pom.xml

            ```xml
            <plugin>
              <groupId>org.apache.maven.plugins</groupId>
              <artifactId>maven-assembly-plugin</artifactId>
              <configuration>
                <finalName>${pkg.name}</finalName>
                <descriptors>
                  <descriptor>${main.dir}/packaging/${pkg.type}/assembly/windows.xml</descriptor>
                </descriptors>
              </configuration>
              <executions>
                <execution>
                  <id>assembly</id>
                  <phase>${pkg.package.phase}</phase>
                  <goals>
                    <goal>single</goal>
                  </goals>
                </execution>
              </executions>
            </plugin>
            ```

2. angular应用打包为jar被java项目引用

   1. application/pom.xml

      ```xml
      <dependency>
        <groupId>org.thingsboard</groupId>
        <artifactId>ui-ngx</artifactId>
        <version>${project.version}</version>
        <scope>runtime</scope>
      </dependency>
      ```

   2. ui-ngx/pom.xml

      ```xml
      <plugins>
        <plugin>
          <groupId>com.github.eirslett</groupId>
          <artifactId>frontend-maven-plugin</artifactId>
      ```

3. Js

   1. <pkg.type>js</pkg.type>
      1. msa/js-executor/pom.xml
      2. msa/web-ui/pom.xml

4. docker

   1. ```xml
      <plugin>
        <groupId>com.spotify</groupId>
        <artifactId>dockerfile-maven-plugin</artifactId>
      ```

   2. pom定义

      1. msa/js-executor/pom.xml
      2. msa/tb/pom.xml
      3. msa/tb-node/pom.xml
      4. transport类的pom.xml
         1. msa/transport/coap
         2. msa/transport/http
         3. msa/transport/lwm2m
         4. msa/transport/mqtt
         5. msa/transport/snmp

      5. msa/web-ui/pom.xml

5. k8s

   1. 基于docker创建的image，在k8s目录下保存了运行脚本

