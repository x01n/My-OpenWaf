# WAF 引擎系统

<cite>
**本文档引用的文件**
- [cmd/main.go](file://cmd/main.go)
- [internal/app/server.go](file://internal/app/server.go)
- [internal/core/engine/engine.go](file://internal/core/engine/engine.go)
- [internal/core/pipeline/pipeline.go](file://internal/core/pipeline/pipeline.go)
- [internal/core/rule/compile.go](file://internal/core/rules/compiler.go)
- [internal/core/rule/matcher.go](file://internal/core/rules/matcher.go)
- [internal/core/rule/phases.go](file://internal/core/rules/phases.go)
- [internal/core/action/action.go](file://internal/core/action/action.go)
- [internal/waf/ratelimit.go](file://internal/waf/ratelimit.go)
- [internal/waf/bot.go](file://internal/waf/bot.go)
- [internal/waf/iprep.go](file://internal/waf/iprep.go)
- [internal/store/models.go](file://internal/store/models.go)
- [internal/core/config.go](file://internal/core/config.go)
- [internal/core/rules/compiler_test.go](file://internal/core/rules/compiler_test.go)
- [internal/core/rules/matcher_test.go](file://internal/core/rules/matcher_test.go)
</cite>

## 目录
1. [简介](#简介)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [架构总览](#架构总览)
5. [详细组件分析](#详细组件分析)
6. [依赖关系分析](#依赖关系分析)
7. [性能考虑](#性能考虑)
8. [故障排查指南](#故障排查指南)
9. [结论](#结论)
10. [附录](#附录)

## 简介
本文件为 My-OpenWaf 的 WAF 引擎系统综合文档，面向开发者与运维人员，系统性阐述引擎核心架构、规则管道设计、处理阶段详解、性能优化策略、规则编译器工作原理（语法解析、AST 构建与代码生成）、规则匹配器实现机制（正则表达式优化、模式匹配算法与匹配优先级）、规则执行流程（阶段划分、执行顺序与短路机制），并提供规则示例与配置案例、扩展点与自定义规则开发方法。

## 项目结构
系统采用分层与模块化组织方式：
- 应用入口与生命周期管理：cmd/main.go 调用 internal/app/server.go 启动服务，负责数据库迁移、默认数据注入、监听器热重载、指标与事件收集等。
- 核心引擎：internal/core/engine/engine.go 提供请求处理主引擎，协调站点解析、维护模式检查、规则编译与管道执行。
- 规则子系统：rules 包含编译器（compiler.go）、匹配器（matcher.go）与阶段实现（phases.go），支持复合条件、正则缓存、优先级排序等。
- 动作与结果：action 包统一动作类型与结果判定（拦截、放行、观察）。
- 安全能力：waf 包提供机器人检测（bot.go）、速率限制（ratelimit.go）、IP 黑白名单与自动封禁（iprep.go）。
- 数据模型与配置：store/models.go 定义规则、站点、保护配置等；core/config.go 提供环境变量配置加载。

```mermaid
graph TB
A["应用入口<br/>cmd/main.go"] --> B["应用服务器<br/>internal/app/server.go"]
B --> C["引擎核心<br/>internal/core/engine/engine.go"]
C --> D["规则编译器<br/>internal/core/rules/compiler.go"]
C --> E["规则阶段<br/>internal/core/rules/phases.go"]
E --> F["匹配器集合<br/>internal/core/rules/matcher.go"]
C --> G["动作与结果<br/>internal/core/action/action.go"]
C --> H["速率限制<br/>internal/waf/ratelimit.go"]
C --> I["IP信誉<br/>internal/waf/iprep.go"]
C --> J["机器人检测<br/>internal/waf/bot.go"]
B --> K["数据模型与配置<br/>internal/store/models.go"]
B --> L["核心配置加载<br/>internal/core/config.go"]
```

**图表来源**
- [cmd/main.go:1-10](file://cmd/main.go#L1-L10)
- [internal/app/server.go:33-280](file://internal/app/server.go#L33-L280)
- [internal/core/engine/engine.go:15-146](file://internal/core/engine/engine.go#L15-L146)
- [internal/core/rules/compiler.go:27-83](file://internal/core/rules/compiler.go#L27-L83)
- [internal/core/rules/phases.go:32-483](file://internal/core/rules/phases.go#L32-L483)
- [internal/core/rules/matcher.go:166-343](file://internal/core/rules/matcher.go#L166-L343)
- [internal/core/action/action.go:28-53](file://internal/core/action/action.go#L28-L53)
- [internal/waf/ratelimit.go:9-117](file://internal/waf/ratelimit.go#L9-L117)
- [internal/waf/iprep.go:18-243](file://internal/waf/iprep.go#L18-L243)
- [internal/waf/bot.go:8-254](file://internal/waf/bot.go#L8-L254)
- [internal/store/models.go:44-350](file://internal/store/models.go#L44-L350)
- [internal/core/config.go:31-67](file://internal/core/config.go#L31-L67)

**章节来源**
- [cmd/main.go:1-10](file://cmd/main.go#L1-L10)
- [internal/app/server.go:33-280](file://internal/app/server.go#L33-L280)

## 核心组件
- 引擎 Engine：负责站点解析、维护模式检查、规则编译与阶段管道执行，返回最终动作与观测命中。
- 规则编译器：将存储层规则转换为运行时可直接匹配的 Compiled 结构，内置优先级排序与正则缓存。
- 规则匹配器：提供多种内置匹配器（CIDR、前缀、正则、头部、方法、内容类型、查询参数等），支持复合逻辑（AND/OR/NOT）。
- 规则阶段：按阶段顺序执行，包括 ACL、签名、自定义、请求速率限制、OWASP 默认、机器人检测、IP 信誉等。
- 动作与结果：标准化动作类型（允许/拦截/观察），并提供短路与日志判定逻辑。
- 安全能力：IP 信誉（黑白名单+自动封禁）、机器人检测（指纹与工具识别）、速率限制（固定窗口计数）。

**章节来源**
- [internal/core/engine/engine.go:15-146](file://internal/core/engine/engine.go#L15-L146)
- [internal/core/rules/compiler.go:11-83](file://internal/core/rules/compiler.go#L11-L83)
- [internal/core/rules/matcher.go:11-343](file://internal/core/rules/matcher.go#L11-L343)
- [internal/core/rules/phases.go:32-483](file://internal/core/rules/phases.go#L32-L483)
- [internal/core/action/action.go:3-53](file://internal/core/action/action.go#L3-L53)
- [internal/waf/iprep.go:18-243](file://internal/waf/iprep.go#L18-L243)
- [internal/waf/bot.go:8-254](file://internal/waf/bot.go#L8-L254)
- [internal/waf/ratelimit.go:9-117](file://internal/waf/ratelimit.go#L9-L117)

## 架构总览
引擎在每次请求进入时，先进行站点解析与维护模式检查，随后将规则编译为运行时结构，按阶段顺序执行。阶段间通过短路机制实现快速决策，优先级与动作类型决定是否终止后续阶段。

```mermaid
sequenceDiagram
participant Client as "客户端"
participant Server as "数据平面监听器"
participant Engine as "引擎 Engine"
participant Resolver as "站点解析器"
participant Pipeline as "规则管道"
participant Phases as "各阶段"
participant Actions as "动作判定"
Client->>Server : "HTTP 请求"
Server->>Engine : "Process(RequestCtx)"
Engine->>Resolver : "MatchSite(bind, host)"
Resolver-->>Engine : "返回站点运行时"
Engine->>Engine : "维护模式检查"
Engine->>Engine : "convertAndCompile(规则)"
Engine->>Pipeline : "构建阶段链"
Pipeline->>Phases : "依次执行"
Phases->>Actions : "匹配与动作判定"
Actions-->>Pipeline : "返回结果/短路"
Pipeline-->>Engine : "最终动作与观测命中"
Engine-->>Server : "返回处理结果"
Server-->>Client : "响应"
```

**图表来源**
- [internal/core/engine/engine.go:43-122](file://internal/core/engine/engine.go#L43-L122)
- [internal/core/pipeline/pipeline.go:46-66](file://internal/core/pipeline/pipeline.go#L46-L66)
- [internal/core/rules/phases.go:34-94](file://internal/core/rules/phases.go#L34-L94)

**章节来源**
- [internal/core/engine/engine.go:43-122](file://internal/core/engine/engine.go#L43-L122)
- [internal/core/pipeline/pipeline.go:37-66](file://internal/core/pipeline/pipeline.go#L37-L66)

## 详细组件分析

### 引擎 Engine 组件
- 职责：维护模式检查、站点解析、规则编译、阶段组装与执行、返回处理结果。
- 关键流程：
  - 维护模式：全局或站点级维护模式直接返回拦截动作。
  - 规则编译：将存储层规则转换为 Compiled 列表，按优先级排序。
  - 阶段组装：根据保护配置动态拼接阶段（IP信誉、ACL、机器人检测、请求速率限制、OWASP、签名、自定义）。
  - 执行：管道顺序执行，遇到终端动作立即短路。

```mermaid
classDiagram
class Engine {
-resolver : sites.Resolver
-reqRateLimiter : waf.RateLimiter
-errRateLimiter : waf.RateLimiter
-ipRep : waf.IPReputation
+Process(reqCtx) ProcessResult
+Evaluate(clientIP, path, rawQuery, rules) action.Result
+IPReputation() *waf.IPReputation
}
class ProcessResult {
+Action : action.Result
+Site : snapshot.SiteRuntime
+ObserveHits : []action.Result
+Maintenance : bool
}
Engine --> ProcessResult : "返回"
```

**图表来源**
- [internal/core/engine/engine.go:15-146](file://internal/core/engine/engine.go#L15-L146)

**章节来源**
- [internal/core/engine/engine.go:15-146](file://internal/core/engine/engine.go#L15-L146)

### 规则编译器组件
- 职责：解析规则模式字符串、构建运行时匹配器、排序与生成 Compiled 规则。
- 关键点：
  - 模式解析：支持简单前缀模式与 JSON 复合条件。
  - 匹配器构建：根据 kind 分派到具体匹配器，正则使用缓存避免重复编译。
  - 排序：优先级升序，ID 升序，确保稳定执行顺序。

```mermaid
flowchart TD
Start(["开始编译"]) --> Load["读取存储规则"]
Load --> Filter{"启用且模式有效?"}
Filter --> |否| Skip["跳过规则"]
Filter --> |是| Parse["解析模式(kind,arg)"]
Parse --> Build["构建匹配器(buildMatcher)"]
Build --> Sort["按优先级与ID排序"]
Sort --> Out(["输出 Compiled 列表"])
Skip --> Load
```

**图表来源**
- [internal/core/rules/compiler.go:27-55](file://internal/core/rules/compiler.go#L27-L55)
- [internal/core/rules/compiler.go:57-83](file://internal/core/rules/compiler.go#L57-L83)
- [internal/core/rules/matcher.go:166-261](file://internal/core/rules/matcher.go#L166-L261)

**章节来源**
- [internal/core/rules/compiler.go:11-83](file://internal/core/rules/compiler.go#L11-L83)
- [internal/core/rules/matcher.go:166-261](file://internal/core/rules/matcher.go#L166-L261)

### 规则匹配器组件
- 职责：对单条规则进行匹配判断，支持复合逻辑与正则缓存。
- 内置匹配器：
  - CIDR/IP 前缀/精确匹配
  - 路径前缀/正则/精确匹配
  - 查询串包含/正则
  - 头部包含/正则
  - 方法/内容类型
  - User-Agent 包含/正则
  - 查询参数存在/值包含
  - 复合条件（AND/OR/NOT）
- 正则优化：使用带锁的全局缓存，避免重复编译。

```mermaid
classDiagram
class Matcher {
<<interface>>
+Match(ip, method, path, query, headers) bool
}
class ipCIDRMatcher
class pathPrefixMatcher
class pathRegexMatcher
class queryContainsMatcher
class queryRegexMatcher
class headerContainsMatcher
class headerRegexMatcher
class exactPathMatcher
class methodMatcher
class contentTypeMatcher
class bodyContainsMatcher
class queryParamMatcher
class andMatcher
class orMatcher
class notMatcher
Matcher <|.. ipCIDRMatcher
Matcher <|.. pathPrefixMatcher
Matcher <|.. pathRegexMatcher
Matcher <|.. queryContainsMatcher
Matcher <|.. queryRegexMatcher
Matcher <|.. headerContainsMatcher
Matcher <|.. headerRegexMatcher
Matcher <|.. exactPathMatcher
Matcher <|.. methodMatcher
Matcher <|.. contentTypeMatcher
Matcher <|.. bodyContainsMatcher
Matcher <|.. queryParamMatcher
andMatcher ..> Matcher : "组合"
orMatcher ..> Matcher : "组合"
notMatcher ..> Matcher : "组合"
```

**图表来源**
- [internal/core/rules/matcher.go:11-141](file://internal/core/rules/matcher.go#L11-L141)
- [internal/core/rules/matcher.go:166-343](file://internal/core/rules/matcher.go#L166-L343)

**章节来源**
- [internal/core/rules/matcher.go:11-343](file://internal/core/rules/matcher.go#L11-L343)

### 规则阶段组件
- 职责：按阶段顺序执行规则匹配，支持短路与观测日志。
- 主要阶段：
  - ACL：白名单短路放行，其他动作按规则动作执行。
  - 签名/自定义：命中即按动作短路。
  - 请求速率限制：基于客户端IP+主机名的固定窗口计数。
  - OWASP 默认：多内容类型解析与扫描，命中按配置动作。
  - 机器人检测：指纹与工具识别，恶意记录IP信誉。
  - IP 信誉：白名单短路放行，黑名单直接拦截。

```mermaid
sequenceDiagram
participant P as "Pipeline"
participant ACL as "ACL阶段"
participant BOT as "机器人阶段"
participant RL as "速率限制阶段"
participant OWASP as "OWASP阶段"
participant SIG as "签名阶段"
participant CUS as "自定义阶段"
P->>ACL : "Execute()"
ACL-->>P : "允许短路/继续"
P->>BOT : "Execute()"
BOT-->>P : "拦截/观察/继续"
P->>RL : "Execute()"
RL-->>P : "拦截/继续"
P->>OWASP : "Execute()"
OWASP-->>P : "拦截/继续"
P->>SIG : "Execute()"
SIG-->>P : "拦截/继续"
P->>CUS : "Execute()"
CUS-->>P : "拦截/继续"
```

**图表来源**
- [internal/core/rules/phases.go:34-94](file://internal/core/rules/phases.go#L34-L94)
- [internal/core/rules/phases.go:96-128](file://internal/core/rules/phases.go#L96-L128)
- [internal/core/rules/phases.go:130-170](file://internal/core/rules/phases.go#L130-L170)
- [internal/core/rules/phases.go:172-213](file://internal/core/rules/phases.go#L172-L213)
- [internal/core/rules/phases.go:215-272](file://internal/core/rules/phases.go#L215-L272)

**章节来源**
- [internal/core/rules/phases.go:32-483](file://internal/core/rules/phases.go#L32-L483)

### 动作与结果组件
- 职责：标准化动作类型（允许/拦截/观察），并提供短路与日志判定。
- 关键点：规范化旧动作别名，短路仅在拦截时触发，观测命中用于日志记录。

**章节来源**
- [internal/core/action/action.go:3-53](file://internal/core/action/action.go#L3-L53)

### 速率限制组件
- 职责：固定窗口计数限流，支持并发安全与定期清理。
- 关键点：键由客户端IP+主机名组成，窗口与阈值可动态配置。

**章节来源**
- [internal/waf/ratelimit.go:9-117](file://internal/waf/ratelimit.go#L9-L117)

### IP 信誉组件
- 职责：支持黑白名单与自动封禁，提供查询与违规计数。
- 关键点：白名单命中短路放行，黑名单直接拦截；自动封禁基于窗口内违规次数。

**章节来源**
- [internal/waf/iprep.go:18-243](file://internal/waf/iprep.go#L18-L243)

### 机器人检测组件
- 职责：基于用户代理与请求特征的指纹评分，识别恶意工具。
- 关键点：内置合法爬虫白名单与恶意工具列表，支持不同敏感度等级。

**章节来源**
- [internal/waf/bot.go:8-254](file://internal/waf/bot.go#L8-L254)

## 依赖关系分析
- 引擎依赖：站点解析器、规则编译器、动作系统、速率限制、IP 信誉、机器人检测。
- 规则阶段依赖：匹配器集合、动作系统、速率限制实例、IP 信誉实例、机器人检测工具。
- 应用层依赖：数据库连接、Redis（可选）、前端静态资源、健康检查、指标导出。

```mermaid
graph TB
Engine["Engine"] --> Resolver["sites.Resolver"]
Engine --> Compiler["rules.Compile"]
Engine --> Pipeline["pipeline.New"]
Pipeline --> Phases["各阶段"]
Phases --> Matcher["匹配器集合"]
Phases --> Action["动作系统"]
Phases --> RateLimit["waf.RateLimiter"]
Phases --> IPRep["waf.IPReputation"]
Phases --> Bot["waf.CheckBot"]
```

**图表来源**
- [internal/core/engine/engine.go:69-106](file://internal/core/engine/engine.go#L69-L106)
- [internal/core/rules/phases.go:34-272](file://internal/core/rules/phases.go#L34-L272)

**章节来源**
- [internal/core/engine/engine.go:69-106](file://internal/core/engine/engine.go#L69-L106)
- [internal/core/rules/phases.go:34-272](file://internal/core/rules/phases.go#L34-L272)

## 性能考虑
- 正则优化：规则编译阶段对正则表达式进行缓存，避免重复编译，降低 CPU 开销。
- 匹配短路：ACL 允许短路放行，IP 信誉白名单短路放行，机器人检测恶意命中直接拦截，减少后续阶段开销。
- 固定窗口限流：使用原子计数与定期清理，内存占用可控，适合高 QPS 场景。
- 内容扫描限制：OWASP 默认阶段对不同内容类型采用不同的解析与扫描策略，限制扫描范围与大小，避免正则风暴。
- 并发安全：速率限制与 IP 信誉使用互斥锁与原子操作，保证多协程下的正确性。
- 预排序：规则按优先级与 ID 排序，确保稳定的执行顺序，避免不必要的回溯。

[本节为通用性能讨论，不直接分析具体文件]

## 故障排查指南
- 规则未生效：
  - 检查规则是否启用、模式是否正确、优先级是否覆盖预期。
  - 参考规则编译与匹配测试用例，验证正则与复合条件行为。
- 正则匹配异常：
  - 确认正则表达式合法性，非法正则会被视为“从不匹配”以避免错误。
  - 检查正则缓存是否被正确复用。
- 速率限制误判：
  - 核对限流键（客户端IP+主机名）是否符合预期，确认窗口与阈值配置。
- IP 信誉问题：
  - 核对黑白名单条目格式与有效期，检查自动封禁阈值与窗口设置。
- 机器人检测误报：
  - 调整敏感度等级，核对用户代理是否被误判为恶意工具。

**章节来源**
- [internal/core/rules/compiler_test.go:11-88](file://internal/core/rules/compiler_test.go#L11-L88)
- [internal/core/rules/matcher_test.go:10-221](file://internal/core/rules/matcher_test.go#L10-L221)
- [internal/waf/ratelimit.go:48-92](file://internal/waf/ratelimit.go#L48-L92)
- [internal/waf/iprep.go:89-124](file://internal/waf/iprep.go#L89-L124)
- [internal/waf/bot.go:180-249](file://internal/waf/bot.go#L180-L249)

## 结论
本 WAF 引擎系统通过清晰的分层与模块化设计，实现了高性能、可扩展的规则处理能力。规则编译器与匹配器提供了灵活的模式与复合条件支持，阶段化的执行流程结合短路机制确保了低延迟与高吞吐。速率限制、IP 信誉与机器人检测等安全能力进一步增强了整体防护效果。建议在生产环境中合理配置规则优先级、正则表达式与限流参数，并持续监控指标与日志以优化策略。

[本节为总结性内容，不直接分析具体文件]

## 附录

### 规则执行流程详解
- 阶段划分：ACL → 机器人检测 → 请求速率限制 → OWASP 默认 → 签名 → 自定义。
- 执行顺序：严格按上述顺序，每个阶段可能短路后续阶段。
- 短路机制：允许（ACL）与拦截（IP信誉/OWASP/签名/自定义）会立即终止管道。

**章节来源**
- [internal/core/engine/engine.go:69-106](file://internal/core/engine/engine.go#L69-L106)
- [internal/core/rules/phases.go:34-94](file://internal/core/rules/phases.go#L34-L94)

### 规则示例与配置案例
- 示例模式：
  - IP 白名单/黑名单：allow_ip:10.0.0.1、block_ip:192.168.1.0/24
  - 路径匹配：block_path:/admin、block_path_regex:(?i)/admin
  - 查询串匹配：block_query_contains:union、block_query_regex:(?i)union\s+select
  - 头部匹配：block_header:User-Agent:sqlmap、block_header_regex:Content-Type:image/
  - 方法与内容类型：block_method:DELETE、block_content_type:application/xml
  - 复合条件：{"op":"and","children":[{"kind":"block_path","arg":"/admin"},{"kind":"block_method","arg":"POST"}]}
- 配置要点：
  - 规则优先级：数值越小优先级越高。
  - 动作类型：allow/intercept/observe（兼容 block/log_only）。
  - OWASP 敏感度：low/mid/high，影响扫描严格程度。
  - 速率限制：窗口秒数与最大请求数需结合业务流量评估。

**章节来源**
- [internal/core/rules/compiler.go:57-83](file://internal/core/rules/compiler.go#L57-L83)
- [internal/store/models.go:44-91](file://internal/store/models.go#L44-L91)
- [internal/store/models.go:244-289](file://internal/store/models.go#L244-L289)

### 扩展点与自定义规则开发
- 新增匹配器：
  - 实现 Matcher 接口并在 buildMatcher 中注册映射。
  - 注意正则缓存与边界条件处理。
- 新增阶段：
  - 实现 pipeline.Phase 接口，按需短路与日志记录。
- 新增动作：
  - 在 action 包中扩展 Type 与 Normalize 行为，保持向后兼容。
- 配置驱动：
  - 通过 ProtectionConfig 与系统设置调整全局策略（如 OWASP、速率限制、机器人检测）。

**章节来源**
- [internal/core/rules/matcher.go:11-261](file://internal/core/rules/matcher.go#L11-L261)
- [internal/core/rules/phases.go:25-31](file://internal/core/rules/phases.go#L25-L31)
- [internal/core/action/action.go:3-26](file://internal/core/action/action.go#L3-L26)
- [internal/store/models.go:244-289](file://internal/store/models.go#L244-L289)