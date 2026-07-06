# WAF 引擎系统

<cite>
**本文档引用的文件**
- [internal/core/engine/engine.go](file://internal/core/engine/engine.go)
- [internal/core/pipeline/pipeline.go](file://internal/core/pipeline/pipeline.go)
- [internal/core/rules/phases.go](file://internal/core/rules/phases.go)
- [internal/core/rules/compiler.go](file://internal/core/rules/compiler.go)
- [internal/core/rules/matcher.go](file://internal/core/rules/matcher.go)
- [internal/core/action/action.go](file://internal/core/action/action.go)
- [internal/core/pipeline/pool.go](file://internal/core/pipeline/pool.go)
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)
- [internal/waf/bot/bot.go](file://internal/waf/bot/bot.go)
- [internal/waf/owasp/owasp.go](file://internal/waf/owasp/owasp.go)
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/bot/tls_fingerprint.go](file://internal/waf/bot/tls_fingerprint.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)
- [internal/dataplane/handler.go](file://internal/dataplane/handler.go)
- [internal/core/sites/resolver.go](file://internal/core/sites/resolver.go)
- [internal/snapshot/snapshot.go](file://internal/snapshot/snapshot.go)
- [internal/core/config.go](file://internal/core/config.go)
- [internal/core/runtime.go](file://internal/core/runtime.go)
- [internal/core/lifecycle/lifecycle.go](file://internal/core/lifecycle/lifecycle.go)
</cite>


> **模块架构概述**
>
> WAF 引擎系统是 My-OpenWaf 的核心安全处理单元，采用"不可变快照 + 责任链规则管线"架构。它负责从数据平面接收请求上下文，经过站点解析、维护模式检查、多阶段规则匹配（IP 信誉 → ACL → OWASP → CVE → 机器人检测 → 速率限制 → 签名/自定义），最终返回动作结果。引擎支持规则热重载、TLS 指纹采集、TCP 层面阻断（Drop）和可观测的日志事件输出。
>
> **子页面导航索引**
>
> #### 引擎核心架构
> 涵盖引擎的设计模式、请求生命周期、管道执行、规则编译缓存、快照系统和站点解析等基础设施。
>
> - [引擎核心架构](./引擎核心架构/引擎核心架构.md) — Engine 设计、站点解析、规则编译、管道与快照的整体架构
> - [请求处理流程](./引擎核心架构/请求处理流程.md) — 从监听器到响应的完整请求生命周期
> - [管道执行机制](./引擎核心架构/管道执行机制.md) — Phase 接口、Run 函数、阶段链、短路逻辑与缓存失效
> - [规则编译缓存](./引擎核心架构/规则编译缓存.md) — compiledRules、两级缓存与版本控制机制
> - [快照系统](./引擎核心架构/快照系统.md) — 不可变快照、构建流程、热重载与 Redis 同步
> - [站点解析器](./引擎核心架构/站点解析器.md) — Resolver、精确/通配符匹配与多站点支持
>
> #### 处理阶段详解
> 详解引擎管线中的 9 个核心处理阶段，包括 ACL、OWASP、机器人检测、签名、速率限制、IP 信誉和自定义规则等。
>
> - [处理阶段详解](./处理阶段详解/处理阶段详解.md) — 9 个核心阶段的总览与流水线概述
> - [ACL 访问控制阶段](./处理阶段详解/ACL 访问控制阶段.md) — 规则匹配、白名单/黑名单、短路逻辑与 DSL 语法
> - [机器人检测阶段](./处理阶段详解/机器人检测阶段.md) — 两阶段检测（预筛选 + 深度评分）、GeoIP 与 TLS 指纹
> - [签名检测阶段](./处理阶段详解/签名检测阶段.md) — 签名规则编译、匹配以及与 OWASP/CVE 协作
> - [请求速率限制阶段](./处理阶段详解/请求速率限制阶段.md) — 固定窗口算法、Allow/Increment 与过期清理
> - [自定义规则阶段](./处理阶段详解/自定义规则阶段.md) — DSL/JSON 复合条件、短路逻辑与前端规则构建器
> - [OWASP 默认检测阶段](./处理阶段详解/OWASP 默认检测阶段.md) — 基础 + 扩展规则、归一化与误报抑制
> - [IP 信誉检查阶段](./处理阶段详解/IP 信誉检查阶段.md) — 黑白名单、自动封禁、XFF 解析与违规计数
>
> #### 规则编译与动作
> 覆盖规则 DSL 解析编译流程和动作结果系统的定义与执行。
>
> - [规则编译器](./规则编译器.md) — DSL 解析、编译流程、匹配器构建、优先级与扩展指南
> - [动作与结果系统](./动作与结果系统.md) — 动作类型、Drop 执行器、阻断页、自定义动作与动作链
>
> #### 规则匹配器
> 包括 Matcher 接口定义、复合匹配器、正则优化、扩展开发以及全部内置匹配器的参考文档。
>
> - [规则匹配器](./规则匹配器/规则匹配器.md) — Matcher 接口、编译器、阶段执行与正则缓存
> - [复合匹配器](./规则匹配器/复合匹配器.md) — AND/OR/NOT、CC Rate、JSON 解析与递归构建
> - [匹配器扩展开发](./规则匹配器/匹配器扩展开发.md) — 自定义 Matcher、buildMatcher 扩展与测试方法
> - [正则表达式优化](./规则匹配器/正则表达式优化.md) — cachedCompile、并发安全与缓存命中率
> - [内置匹配器](./规则匹配器/内置匹配器/内置匹配器.md) — 所有内置匹配器的功能概述与使用速查
> - [网络匹配器](./规则匹配器/内置匹配器/网络匹配器.md) — IP CIDR、allow_ip / block_ip 匹配
> - [头部和查询参数匹配器](./规则匹配器/内置匹配器/头部和查询参数匹配器.md) — header、UA、Cookie 与 query 匹配
> - [路径匹配器](./规则匹配器/内置匹配器/路径匹配器.md) — 前缀/精确/正则匹配与 Trie 树优化
> - [内容和主体匹配器](./规则匹配器/内置匹配器/内容和主体匹配器.md) — Content-Type、body、JSON 与 Multipart 匹配
> - [主机和 URL 匹配器](./规则匹配器/内置匹配器/主机和URL匹配器.md) — host、full_url 与端口处理
> - [地理位置阻断匹配器](./规则匹配器/内置匹配器/地理位置阻断匹配器.md) — geo_block、国家代码与 MaxMind 集成



## 目录
1. [引言](#引言)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [架构总览](#架构总览)
5. [详细组件分析](#详细组件分析)
6. [依赖关系分析](#依赖关系分析)
7. [性能考虑](#性能考虑)
8. [故障排查指南](#故障排查指南)
9. [结论](#结论)
10. [附录：配置与最佳实践](#附录配置与最佳实践)

## 引言
本文件系统性阐述 My-OpenWaf 的引擎核心架构与实现细节，重点覆盖以下方面：
- 引擎整体设计理念与架构模式（责任链、规则编译、站点解析、生命周期管理）
- 引擎初始化流程、依赖注入机制与运行时生命周期
- Process 方法的执行流程（请求上下文构建、站点解析、维护模式检查、规则阶段执行）
- 引擎与子系统的协作关系（站点解析器、速率限制器、IP 信誉系统、CVE检测器、规则引擎、阻断执行器、数据平面处理器；TLS 指纹作为 RequestCtx 派生匹配输入供规则匹配器使用）
- 配置项与性能调优建议
- 实际使用示例与最佳实践

## 项目结构
My-OpenWaf 采用分层与模块化组织方式：
- cmd 层负责应用入口与启动
- internal/app 负责服务编排、生命周期管理、监听器热重载
- internal/core 提供核心能力：引擎、规则编译与匹配、站点解析、动作定义、生命周期管理
- internal/waf 提供速率限制、IP 信誉、OWASP 检测、CVE检测、机器人与 TLS 指纹相关检测、阻断执行等安全能力
- internal/dataplane 提供数据面处理器，串联引擎与上游代理
- internal/snapshot 提供不可变快照与原子切换

```mermaid
graph TB
A["cmd/main.go<br/>应用入口"] --> B["internal/app/server.go<br/>服务编排与生命周期"]
B --> C["internal/core/runtime.go<br/>运行时装配"]
B --> D["internal/core/engine/engine.go<br/>WAF 引擎"]
D --> E["internal/core/pipeline/pipeline.go<br/>请求管线"]
D --> F["internal/core/sites/resolver.go<br/>站点解析器"]
D --> G["internal/core/rules/phases.go<br/>规则阶段"]
G --> H["internal/core/rules/compiler.go<br/>规则编译"]
H --> I["internal/core/rules/matcher.go<br/>匹配器"]
D --> J["internal/waf/ratelimit/ratelimit.go<br/>请求速率限制"]
D --> K["internal/waf/iprep/iprep.go<br/>IP 信誉"]
D --> L["internal/waf/cve/detector.go<br/>CVE检测器"]
D --> M["internal/waf/bot/tls_fingerprint.go<br/>TLS指纹元数据"]
D --> N["internal/waf/drop/drop.go<br/>阻断执行器"]
B --> O["internal/dataplane/handler.go<br/>数据面处理器"]
C --> P["internal/core/config.go<br/>配置加载"]
C --> Q["internal/snapshot/snapshot.go<br/>快照与站点运行时"]
```

**图表来源**
- [internal/core/engine/engine.go:23-176](file://internal/core/engine/engine.go#L23-L176)
- [internal/core/pipeline/pipeline.go:9-66](file://internal/core/pipeline/pipeline.go#L9-L66)
- [internal/core/sites/resolver.go:18-31](file://internal/core/sites/resolver.go#L18-L31)
- [internal/core/rules/phases.go:34-569](file://internal/core/rules/phases.go#L34-L569)
- [internal/core/rules/compiler.go:27-55](file://internal/core/rules/compiler.go#L27-L55)
- [internal/core/rules/matcher.go:167-261](file://internal/core/rules/matcher.go#L167-L261)
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/bot/tls_fingerprint.go](file://internal/waf/bot/tls_fingerprint.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)
- [internal/dataplane/handler.go:36-257](file://internal/dataplane/handler.go#L36-L257)
- [internal/core/config.go:56-115](file://internal/core/config.go#L56-L115)
- [internal/snapshot/snapshot.go:52-105](file://internal/snapshot/snapshot.go#L52-L105)

**章节来源**
- [internal/core/engine/engine.go:15-176](file://internal/core/engine/engine.go#L15-L176)
- [internal/core/rules/compiler.go:27-55](file://internal/core/rules/compiler.go#L27-L55)
- [internal/core/sites/resolver.go:18-31](file://internal/core/sites/resolver.go#L18-L31)
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/bot/tls_fingerprint.go](file://internal/waf/bot/tls_fingerprint.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)
- [internal/dataplane/handler.go:36-257](file://internal/dataplane/handler.go#L36-L257)
- [internal/core/lifecycle/lifecycle.go:30-178](file://internal/core/lifecycle/lifecycle.go#L30-L178)

## 核心组件
- 引擎 Engine：封装站点解析、维护模式检查、规则阶段执行与结果聚合，新增CVE检测器和阻断执行器
- 规则引擎：编译规则为可执行的 Compiled 结构，按阶段顺序执行
- 站点解析器 Resolver：基于当前快照将 (bind, host) 映射到 SiteRuntime
- 速率限制器 RateLimiter：固定窗口计数，支持请求与错误两类限流
- IP 信誉系统 IPReputation：白名单/黑名单/自动封禁
- CVE检测器 CVEDetector：多技术栈漏洞检测，支持PHP、Java、Node.js和通用漏洞规则
- TLS 指纹元数据：由数据面采集并写入 RequestCtx，供 Bot 检测、日志字段和 `tls_*` 规则匹配器使用
- 阻断执行器 DropExecutor：TCP连接直接终止，无HTTP响应
- 数据平面处理器：在拦截后写入响应或转发至上游
- 生命周期管理：统一启动、优雅关闭、信号处理与服务器协调

**章节来源**
- [internal/core/engine/engine.go:15-176](file://internal/core/engine/engine.go#L15-L176)
- [internal/core/rules/compiler.go:27-55](file://internal/core/rules/compiler.go#L27-L55)
- [internal/core/sites/resolver.go:18-31](file://internal/core/sites/resolver.go#L18-L31)
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/bot/tls_fingerprint.go](file://internal/waf/bot/tls_fingerprint.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)
- [internal/dataplane/handler.go:36-257](file://internal/dataplane/handler.go#L36-L257)
- [internal/core/lifecycle/lifecycle.go:30-178](file://internal/core/lifecycle/lifecycle.go#L30-L178)

## 架构总览
下图展示从 Hertz 监听器到引擎再到上游的完整链路，以及引擎内部的当前阶段执行顺序。TLS 指纹不是独立流水线阶段，而是数据面写入 RequestCtx 后供 Bot 检测、日志字段与 `tls_*` 规则匹配器使用。

```mermaid
sequenceDiagram
participant Client as "客户端"
participant DP as "数据平面处理器"
participant Eng as "WAF 引擎"
participant Res as "站点解析器"
participant Pipe as "规则管线"
participant IR as "IP 信誉"
participant AR as "AntiReplay"
participant ACL as "ACL"
participant OWASP as "OWASP默认"
participant CVE as "CVE检测"
participant Bot as "机器人检测"
participant RL as "速率限制器"
participant Sig as "签名/自定义"
Client->>DP : HTTP 请求
DP->>Eng : 构建 RequestCtx 并调用 Process()
Eng->>Res : 快照匹配站点
Res-->>Eng : 返回 SiteRuntime
Eng->>Eng : 维护模式检查
alt 维护中
Eng-->>DP : 返回拦截结果
DP-->>Client : 维护页响应
else 正常
Eng->>Pipe : 构建阶段列表
Pipe->>IR : IP信誉阶段
IR-->>Pipe : 白名单短路/黑名单拦截
Pipe->>AR : AntiReplay阶段
AR-->>Pipe : 拦截/继续
Pipe->>ACL : ACL阶段
ACL-->>Pipe : Allow/终端动作/继续
Pipe->>OWASP : OWASP默认阶段
OWASP-->>Pipe : 通用攻击检测
Pipe->>CVE : CVE检测阶段
CVE-->>Pipe : 漏洞利用尝试检测
Pipe->>Bot : 机器人检测阶段
Bot-->>Pipe : 合法/可疑/恶意判定
Pipe->>RL : 请求速率限制阶段
RL-->>Pipe : 允许/拦截
alt 检测到CVE高危
Pipe-->>Eng : 返回Drop动作
else 正常
Pipe->>Sig : 签名/自定义阶段
Sig-->>Pipe : 规则匹配结果
Pipe-->>Eng : 返回 Action 与观察命中
Eng-->>DP : 返回结果
alt 动作终止(Drop)
DP->>DE : 调用阻断执行器
DE-->>Client : TCP连接直接关闭
else 动作拦截(Intercept)
DP-->>Client : 拦截响应
else 放行
DP->>Up : 转发请求
Up-->>DP : 上游响应
DP->>RL : 错误率统计可选
DP-->>Client : 响应返回
end
end
end
```

**图表来源**
- [internal/dataplane/handler.go:36-257](file://internal/dataplane/handler.go#L36-L257)
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/sites/resolver.go:18-31](file://internal/core/sites/resolver.go#L18-L31)
- [internal/core/rules/phases.go:305-358](file://internal/core/rules/phases.go#L305-L358)
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)

## 详细组件分析

### 引擎 Engine：初始化、依赖注入与生命周期
- 初始化：通过 New 构造，注入快照持有者、请求/错误速率限制器、IP 信誉系统、CVE检测器
- 依赖注入：Resolver 由快照持有者生成；规则阶段根据保护配置动态拼装
- 生命周期：由 app 层创建、启动、热重载与优雅关闭；引擎自身不直接管理进程生命周期
- 新增功能：CVE检测器和阻断执行器的注入与配置

```mermaid
classDiagram
class Engine {
-resolver : Resolver
-reqRateLimiter : RateLimiter
-errRateLimiter : RateLimiter
-ipRep : IPReputation
-geoResolver : MaxMindResolver
-botThreshold : int
-cveDetector : CVEDetector
-dropExecutor : DropExecutor
+Process(reqCtx) ProcessResult
+Evaluate(clientIP, path, rawQuery, rules) action.Result
+Resolver() Resolver
+ErrRateLimiter() RateLimiter
+CVEDetector() CVEDetector
+DropExecutor() DropExecutor
+SetDropExecutor(d *DropExecutor) void
}
class Resolver {
-holder : Holder
+Match(bind, host) SiteRuntime,bool
+Snapshot() *Snapshot
}
class RateLimiter {
+Allow(key) bool
+Increment(key) int64
+Enabled() bool
+Reconfigure(windowSec,maxReqs,enabled) void
+Close() void
}
class IPReputation {
+Check(ip) IPDecision
+RecordViolation(ip) bool
+ConfigureAutoBan(enabled,threshold,windowSec,durationSec) void
+SetLists(black,white) void
+Close() void
}
class CVEDetector {
-phpDetector : PHPCVEDetector
-javaDetector : JavaCVEDetector
-nodeDetector : NodeCVEDetector
-generalDetector : GeneralCVEDetector
-customRules : []CustomCVERule
+Detect(req) []CVEMatch
+ReloadCustomRules(rules) void
+AddCustomRule(rule) void
+RemoveCustomRule(id) void
}
class DropExecutor {
-stats : DropStats
-enabled : bool
+Execute(conn, reason) error
+GetStats() DropStats
+SetEnabled(v bool) void
}
Engine --> Resolver : "使用"
Engine --> RateLimiter : "使用"
Engine --> IPReputation : "使用"
Engine --> CVEDetector : "使用"
Engine --> DropExecutor : "使用"
```

**图表来源**
- [internal/core/engine/engine.go:15-37](file://internal/core/engine/engine.go#L15-L37)
- [internal/core/sites/resolver.go:7-16](file://internal/core/sites/resolver.go#L7-L16)
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)

**章节来源**
- [internal/core/engine/engine.go:27-37](file://internal/core/engine/engine.go#L27-L37)
- [internal/core/engine/engine.go:152-155](file://internal/core/engine/engine.go#L152-L155)
- [internal/core/lifecycle/lifecycle.go:30-178](file://internal/core/lifecycle/lifecycle.go#L30-L178)

### Process 执行流程：请求上下文、站点解析、维护模式与规则阶段
- 请求上下文：由数据平面处理器填充 RequestCtx（含请求 ID、绑定地址、客户端 IP、方法、路径、查询、头、体、内容类型等）
- 站点解析：使用 Resolver 从当前快照中匹配站点，支持精确匹配与通配符
- 维护模式：若全局或站点启用维护，则立即返回拦截结果
- 规则阶段：按顺序执行（IPReputation → AntiReplay → ACL → OWASP → CVE → BotDetection → RequestRateLimit → Signature → Custom）。非挑战终端动作直接短路；挑战类动作会延迟保留，后续阶段仍继续执行，若后续出现更高优先级终端动作则覆盖挑战结果
- 结果返回：包含最终动作、站点信息、观察命中列表

```mermaid
flowchart TD
Start(["进入 Process"]) --> LoadSnap["加载快照"]
LoadSnap --> MatchSite["解析站点 (bind, host)"]
MatchSite --> SiteOK{"是否匹配?"}
SiteOK -- 否 --> ReturnEmpty["返回空结果"]
SiteOK -- 是 --> MaintCheck["检查维护模式"]
MaintCheck --> MaintOn{"维护开启?"}
MaintOn -- 是 --> ReturnMaint["返回拦截 + 维护标记"]
MaintOn -- 否 --> Compile["编译规则为 Compiled 列表"]
Compile --> Phases["组装阶段列表"]
Phases --> RunPipe["顺序执行阶段"]
RunPipe --> Done(["返回结果"])
```

**图表来源**
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/pipeline/pipeline.go:46-66](file://internal/core/pipeline/pipeline.go#L46-L66)

**章节来源**
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/pipeline/pipeline.go:9-66](file://internal/core/pipeline/pipeline.go#L9-L66)

### CVE检测器：多技术栈漏洞检测
- 架构设计：CVEDetector 作为门面模式，协调多个技术栈专用检测器和通用检测器
- 技术栈检测器：PHP、Java、Node.js专用检测器，针对各自生态的典型漏洞模式
- 通用检测器：检测SSRF、XXE、路径遍历、CRLF注入、HTTP请求走私等通用漏洞
- 自定义规则：支持从数据库热加载自定义CVE规则，正则表达式预编译缓存
- 顺序检测：先做可疑内容预筛选，再按 General、PHP、Java、Node.js、自定义规则与注册表顺序查找首个命中，避免每个请求产生 goroutine 开销

```mermaid
classDiagram
class CVEDetector {
-phpDetector : PHPCVEDetector
-javaDetector : JavaCVEDetector
-nodeDetector : NodeCVEDetector
-generalDetector : GeneralCVEDetector
-customRules : []CustomCVERule
+Detect(req) []CVEMatch
+ReloadCustomRules(rules) void
+AddCustomRule(rule) void
+RemoveCustomRule(id) void
}
class PHPCVEDetector {
-rules : []phpCVERule
+Detect(req) []CVEMatch
}
class JavaCVEDetector {
-rules : []javaCVERule
+Detect(req) []CVEMatch
}
class NodeCVEDetector {
-rules : []nodeCVERule
+Detect(req) []CVEMatch
}
class GeneralCVEDetector {
-rules : []generalCVERule
+Detect(req) []CVEMatch
}
CVEDetector --> PHPCVEDetector : "组合"
CVEDetector --> JavaCVEDetector : "组合"
CVEDetector --> NodeCVEDetector : "组合"
CVEDetector --> GeneralCVEDetector : "组合"
```

**图表来源**
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/cve/php.go](file://internal/waf/cve/php.go)
- [internal/waf/cve/general.go](file://internal/waf/cve/general.go)

**章节来源**
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/cve/php.go](file://internal/waf/cve/php.go)
- [internal/waf/cve/general.go](file://internal/waf/cve/general.go)

### TLS指纹元数据：JA3/JA4与 `tls_*` 规则输入
- 指纹采集：数据面监听器或 HTTP/3 内部元数据提取 JA3、JA3 Hash、JA4、TLS版本、SNI、ALPN 和 cipher suites，并写入 RequestCtx。
- 使用位置：Bot 检测、访问日志、安全事件、签名规则和自定义规则可读取 TLS 指纹字段。
- 规则匹配：`tls_ja3`、`tls_ja3_hash`、`tls_ja4`、`tls_version`、`tls_sni`、`tls_alpn`、`tls_cipher_suites` 由规则匹配器读取派生 MatchCtx 字段。
- 阶段边界：当前主引擎不会注册独立 TLS Phase，TLS 指纹不改变 `IPReputation → AntiReplay → ACL → OWASP → CVE → BotDetection → RequestRateLimit → Signature → Custom` 的阶段顺序。

```mermaid
classDiagram
class TLSClientFingerprint {
+JA3 string
+JA3Hash string
+JA4 string
+TLSVersion string
+SNI string
+ALPN []string
+CipherSuites []string
}
class RequestCtx {
+TLS TLSClientFingerprint
}
class Matcher {
+Match(ctx) bool
}
RequestCtx --> TLSClientFingerprint : "缓存"
Matcher --> RequestCtx : "读取派生 MatchCtx"
```

**图表来源**
- [internal/dataplane/tls_fingerprint_listener.go](file://internal/dataplane/tls_fingerprint_listener.go)
- [internal/dataplane/request_ctx_headers.go](file://internal/dataplane/request_ctx_headers.go)
- [internal/core/rules/matcher.go](file://internal/core/rules/matcher.go)

**章节来源**
- [internal/dataplane/tls_fingerprint_listener.go](file://internal/dataplane/tls_fingerprint_listener.go)
- [internal/dataplane/request_ctx_headers.go](file://internal/dataplane/request_ctx_headers.go)
- [internal/core/rules/matcher.go](file://internal/core/rules/matcher.go)
- [internal/core/rules/phases.go](file://internal/core/rules/phases.go)

### 阻断执行器：TCP连接直接终止
- 架构设计：独立的阻断执行器，支持启用/禁用状态管理
- 统计分析：原子计数器跟踪总阻断数、按来源分类的阻断统计、最后阻断时间
- 动作优先级：Drop动作具有最高优先级，直接终止TCP连接，不发送任何HTTP响应
- 日志记录：详细的阻断事件日志，包含来源、规则ID、客户端IP、主机、路径等

```mermaid
classDiagram
class DropExecutor {
-stats : DropStats
-enabled : bool
-log : Logger
+Execute(conn, reason) error
+GetStats() DropStats
+SetEnabled(v bool) void
}
class DropStats {
-TotalDropped : atomic.Int64
-DroppedByBot : atomic.Int64
-DroppedByCVE : atomic.Int64
-DroppedByRule : atomic.Int64
-LastDropTime : atomic.Value
}
class DropReason {
-Source : string
-RuleID : string
-ClientIP : string
-Host : string
-Path : string
}
DropExecutor --> DropStats : "统计"
DropExecutor --> DropReason : "记录"
```

**图表来源**
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)

**章节来源**
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)

### 规则编译与匹配：DSL解析、排序与执行
- 编译：将存储层规则转换为 Compiled，按优先级与 ID 排序
- DSL：支持 block_ip、block_path、block_header、block_user_agent、body_contains、query_param 等前缀，以及复合条件 JSON
- 匹配：构建具体 Matcher（CIDR、正则、包含、键值对等），缓存正则以降低开销
- 阶段：每个阶段封装一组规则，按顺序执行，遇到允许短路、拦截终止

```mermaid
classDiagram
class Compiled {
+ID : uint
+Phase : string
+Action : Type
+Priority : int
+Kind : string
+Arg : string
+Match(ctx) bool
}
class Matcher {
<<interface>>
+Match(ip,method,path,query,headers) bool
}
class Compiler {
+Compile(rs) []Compiled
+ParsePattern(p) (kind,arg)
}
Compiled --> Matcher : "持有"
Compiler --> Compiled : "生成"
```

**图表来源**
- [internal/core/rules/compiler.go:11-55](file://internal/core/rules/compiler.go#L11-L55)
- [internal/core/rules/matcher.go:11-141](file://internal/core/rules/matcher.go#L11-L141)

**章节来源**
- [internal/core/rules/compiler.go:27-55](file://internal/core/rules/compiler.go#L27-L55)
- [internal/core/rules/matcher.go:167-261](file://internal/core/rules/matcher.go#L167-L261)

### 站点解析器与快照：不可变快照与原子切换
- Resolver：从快照中查找站点，支持精确匹配与通配符（*.domain）
- Snapshot：不可变视图，包含站点映射、默认阻断页、SNI 证书、保护配置等
- Holder：原子指针保存当前快照，用于零停机切换

```mermaid
classDiagram
class Resolver {
-holder : Holder
+Match(bind, host) SiteRuntime,bool
+Snapshot() *Snapshot
}
class Snapshot {
+Sites map[string]SiteRuntime
+Protection ProtectionConfig
+MatchSite(bind, host) SiteRuntime,bool
}
class Holder {
+Store(*Snapshot) void
+Load() *Snapshot
}
Resolver --> Holder : "读取"
Holder --> Snapshot : "原子保存/读取"
```

**图表来源**
- [internal/core/sites/resolver.go:7-31](file://internal/core/sites/resolver.go#L7-L31)
- [internal/snapshot/snapshot.go:52-96](file://internal/snapshot/snapshot.go#L52-L96)

**章节来源**
- [internal/core/sites/resolver.go:18-31](file://internal/core/sites/resolver.go#L18-L31)
- [internal/snapshot/snapshot.go:74-96](file://internal/snapshot/snapshot.go#L74-L96)

### 速率限制器与 IP 信誉：固定窗口与自动封禁
- 速率限制：固定窗口计数，支持请求与错误两类；可运行时重配置
- IP 信誉：白名单短路放行、黑名单直接拦截；支持自动封禁阈值、窗口与时长

```mermaid
flowchart TD
A["Allow/Increment 调用"] --> B{"启用状态?"}
B -- 否 --> C["总是允许/计数为0"]
B -- 是 --> D["计算当前窗口"]
D --> E{"窗口过期或不存在?"}
E -- 是 --> F["创建新窗口并设置过期时间"]
E -- 否 --> G["复用现有窗口"]
F --> H["更新计数并比较上限"]
G --> H
H --> I{"超过上限?"}
I -- 是 --> J["返回超限/增加计数"]
I -- 否 --> K["返回未超限/增加计数"]
```

**图表来源**
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)

**章节来源**
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)

### 数据平面处理器：拦截、记录与转发
- 维护模式：直接输出维护页
- 拦截：记录拦截事件并写入阻断响应
- 观察命中：记录日志与安全事件
- 转发：HTTP/WebSocket/SSE 分支转发至上游；错误率统计在响应后进行
- 阻断执行：对于Drop动作调用阻断执行器直接关闭TCP连接

```mermaid
sequenceDiagram
participant DP as "数据平面处理器"
participant Eng as "引擎"
participant DE as "阻断执行器"
participant Ev as "事件写入器"
participant Up as "上游"
DP->>Eng : Process(RequestCtx)
Eng-->>DP : Action, ObserveHits, Site
alt 维护模式
DP-->>Client : 维护页
else 拦截(Drop)
DP->>DE : Execute(conn, reason)
DE-->>Client : TCP连接关闭
DE-->>Ev : 记录阻断统计
else 拦截(Intercept)
DP-->>Client : 阻断响应
else 放行
DP->>Up : 转发请求
Up-->>DP : 上游响应
DP->>RL : 错误率统计(可选)
DP-->>Client : 响应
end
```

**图表来源**
- [internal/dataplane/handler.go:36-257](file://internal/dataplane/handler.go#L36-L257)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)

**章节来源**
- [internal/dataplane/handler.go:36-257](file://internal/dataplane/handler.go#L36-L257)

## 依赖关系分析
- 引擎依赖：Resolver、规则编译器、各规则阶段、速率限制器、IP 信誉系统、CVE检测器、阻断执行器
- 数据平面依赖：引擎、快照持有者、指标、事件写入器、上游代理、阻断执行器
- 运行时依赖：数据库、可选 Redis、缓存层、快照构建器
- 生命周期依赖：Hertz 服务器适配器、信号处理、优雅关闭

```mermaid
graph LR
DP["数据平面处理器"] --> ENG["引擎"]
ENG --> RES["站点解析器"]
ENG --> PIPE["规则管线"]
PIPE --> PH1["IP信誉阶段"]
PIPE --> PH2["AntiReplay阶段"]
PIPE --> PH3["ACL阶段"]
PIPE --> PH4["OWASP阶段"]
PIPE --> PH5["CVE检测阶段"]
PIPE --> PH6["机器人阶段"]
PIPE --> PH7["请求速率限制阶段"]
PIPE --> PH8["签名/自定义阶段"]
ENG --> RL["速率限制器"]
ENG --> IR["IP信誉系统"]
ENG --> CVE["CVE检测器"]
ENG --> FP["TLS指纹元数据"]
ENG --> DE["阻断执行器"]
APP["应用编排"] --> DP
APP --> ENG
APP --> LIFE["生命周期管理"]
RUNTIME["运行时"] --> APP
RUNTIME --> SNAP["快照构建/缓存"]
```

**图表来源**
- [internal/dataplane/handler.go:36-257](file://internal/dataplane/handler.go#L36-L257)
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/lifecycle/lifecycle.go:30-178](file://internal/core/lifecycle/lifecycle.go#L30-L178)
- [internal/core/runtime.go:27-80](file://internal/core/runtime.go#L27-L80)

**章节来源**
- [internal/core/engine/engine.go:15-176](file://internal/core/engine/engine.go#L15-L176)
- [internal/core/lifecycle/lifecycle.go:30-178](file://internal/core/lifecycle/lifecycle.go#L30-L178)
- [internal/core/runtime.go:27-80](file://internal/core/runtime.go#L27-L80)

## 性能考虑
- 规则编译与缓存：规则编译一次，按优先级排序；正则表达式缓存避免重复编译
- 请求上下文池化：数据平面处理器使用对象池减少 GC 压力
- 固定窗口限流：低内存占用，定时清理过期窗口；错误率统计在响应后进行，避免阻塞请求路径
- IP 信誉：白名单短路、黑名单拦截快速路径；自动封禁定期清理过期封禁
- CVE检测：先做原始可疑内容预筛选，再按 general、php、java、node 与自定义规则顺序查找首个命中，避免每个请求产生 goroutine 开销
- TLS指纹：由数据面采集并缓存到 RequestCtx，规则匹配时作为 `tls_ja3`、`tls_ja3_hash`、`tls_ja4`、`tls_version`、`tls_sni`、`tls_alpn`、`tls_cipher_suites` 等匹配输入
- 阻断执行器：原子操作确保统计准确性，异步日志记录避免阻塞主请求路径
- 内容扫描：对不同 Content-Type 采取差异化策略，限制扫描大小，避免误报与资源滥用
- 监听器热重载：基于CVE检测配置漂移，仅重启受影响监听器，降低停机影响

## 故障排查指南
- 快照未加载：数据平面处理器在快照为空时返回 503，检查运行时初始化与迁移
- 未知虚拟主机：站点解析失败返回 404，确认监听绑定与 Host 头匹配
- 维护模式：若返回拦截且标记为维护，检查全局或站点维护开关
- 拦截日志：关注安全事件与访问日志中的规则 ID、阶段、分类与匹配描述
- 速率限制：确认启用状态、窗口与上限配置；检查错误率统计是否按预期触发
- IP 信誉：核对白/黑名单与自动封禁阈值；查看活动封禁列表
- CVE检测：检查CVE检测器状态、自定义规则加载情况、检测器并行执行状态
- TLS指纹：验证指纹数据库完整性、指纹提取正确性、评分阈值设置
- 阻断执行：确认阻断执行器启用状态、统计信息准确性、日志记录完整性
- 上游错误：转发失败返回 502，检查上游地址与网络连通性

**章节来源**
- [internal/dataplane/handler.go:54-71](file://internal/dataplane/handler.go#L54-L71)
- [internal/core/engine/engine.go:69-81](file://internal/core/engine/engine.go#L69-L81)
- [internal/waf/ratelimit/ratelimit.go](file://internal/waf/ratelimit/ratelimit.go)
- [internal/waf/iprep/iprep.go](file://internal/waf/iprep/iprep.go)
- [internal/waf/cve/detector.go](file://internal/waf/cve/detector.go)
- [internal/waf/drop/drop.go](file://internal/waf/drop/drop.go)

## 结论
My-OpenWaf 的引擎以"不可变快照 + 责任链规则管线"为核心设计，结合站点解析、IP信誉、OWASP、CVE检测、机器人检测、速率限制和阻断执行器，形成高可用、可热重载、可观测的全方位安全防护体系。TLS 指纹由数据面采集并作为规则匹配与日志输入，不作为独立流水线阶段。通过清晰的依赖注入与生命周期管理，引擎在保证性能的同时提供了灵活的扩展空间。

## 附录：配置与最佳实践

### 引擎初始化与依赖注入
- 应用入口：通过入口函数启动运行时、构建快照、装配引擎与监听器
- 运行时：打开数据库与可选 Redis，初始化缓存与快照持有者
- 引擎：注入快照持有者、请求/错误速率限制器、IP 信誉系统、CVE检测器

**章节来源**
- [internal/core/engine/engine.go:15-176](file://internal/core/engine/engine.go#L15-L176)
- [internal/core/lifecycle/lifecycle.go:30-178](file://internal/core/lifecycle/lifecycle.go#L30-L178)
- [internal/core/runtime.go:27-80](file://internal/core/runtime.go#L27-L80)

### 配置选项（环境变量）
- 数据库：驱动、DSN、数据目录
- Redis：地址、密码、DB
- 管理端绑定：控制面监听地址
- 静态资源：本地开发覆盖嵌入前端
- 机器人检测：GeoIP 数据库路径、风险国家、数据中心/VPN ASN 列表、评分阈值
- CVE检测：CVE检测启用状态、CVE动作配置、自定义CVE规则

**章节来源**
- [internal/core/config.go:56-115](file://internal/core/config.go#L56-L115)

### 使用示例与最佳实践
- 示例一：在数据平面处理器中调用引擎
  - 路径参考：[internal/dataplane/handler.go:106](file://internal/dataplane/handler.go#L106)
- 示例二：引擎评估已解析站点规则（测试辅助）
  - 路径参考：[internal/core/engine/engine.go:132-145](file://internal/core/engine/engine.go#L132-L145)
- 最佳实践
  - 将规则按阶段拆分，利用 ACL 快速短路
  - 启用机器人检测与 OWASP 默认规则，结合业务场景调整敏感度
  - 合理设置速率限制窗口与上限，避免误伤正常用户
  - 定期维护 IP 黑/白名单，启用自动封禁应对持续攻击
- 启用CVE检测功能，并结合规则覆盖配置维护 CVE 规则动作
- 在签名或自定义规则中使用 `tls_*` 匹配器，提高自动化工具与异常握手识别能力
  - 启用阻断执行器，对高危威胁实施TCP层面阻断
  - 使用热重载功能平滑更新配置，配合 Redis 分布式通知

**章节来源**
- [internal/dataplane/handler.go:106](file://internal/dataplane/handler.go#L106)
- [internal/core/engine/engine.go:132-145](file://internal/core/engine/engine.go#L132-L145)
- [internal/core/rules/phases.go:305-358](file://internal/core/rules/phases.go#L305-L358)
