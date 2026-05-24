# 基本 OWASP 规则

<cite>
**本文引用的文件**
- [internal/waf/owasp.go](file://internal/waf/owasp.go)
- [internal/waf/owasp_extended.go](file://internal/waf/owasp_extended.go)
- [internal/waf/owasp_registry.go](file://internal/waf/owasp_registry.go)
- [internal/admin/detect/owasp_rules.go](file://internal/admin/detect/owasp_rules.go)
- [internal/core/rules/compiler.go](file://internal/core/rules/compiler.go)
- [internal/core/rules/matcher.go](file://internal/core/rules/matcher.go)
- [internal/core/rules/phases.go](file://internal/core/rules/phases.go)
- [internal/core/engine/engine.go](file://internal/core/engine/engine.go)
- [internal/core/pipeline/pipeline.go](file://internal/core/pipeline/pipeline.go)
- [docs/安全防护功能/OWASP 检测/OWASP 检测.md](file://docs/安全防护功能/OWASP 检测/OWASP 检测.md)
- [docs/安全防护功能/OWASP 检测/基本 OWASP 规则.md](file://docs/安全防护功能/OWASP 检测/基本 OWASP 规则.md)
- [docs/安全防护功能/OWASP 检测/检测算法与技术.md](file://docs/安全防护功能/OWASP 检测/检测算法与技术.md)
- [docs/安全防护功能/OWASP 检测/配置与管理.md](file://docs/安全防护功能/OWASP 检测/配置与管理.md)
- [internal/waf/owasp/owasp_test.go](file://internal/waf/owasp/owasp_test.go)
</cite>

## 目录
1. [简介](#简介)
2. [项目结构](#项目结构)
3. [核心组件](#核心组件)
4. [架构总览](#架构总览)
5. [详细组件分析](#详细组件分析)
6. [依赖分析](#依赖分析)
7. [性能考虑](#性能考虑)
8. [故障排查指南](#故障排查指南)
9. [结论](#结论)
10. [附录](#附录)

## 简介
本文件系统化梳理 My-OpenWaf 的基本 OWASP 规则检测实现，覆盖 OWASP Top 10 常见攻击类型的检测算法与配置管理，包括 SQL 注入、XSS、命令注入、路径穿越、服务器端请求伪造（SSRF）等核心攻击手法的识别机制。文档重点阐述：
- 规则分类与优先级（基础规则与扩展规则）
- 检测精度优化策略（误报抑制、阈值控制、输入归一化）
- 规则更新与维护机制（新增规则、阈值调整、规则组合）
- 配置示例与调试方法（敏感度、阈值、动作）
- 与其他安全机制的协同（ACL、Bot、CVE、速率限制）

## 项目结构
My-OpenWaf 采用"控制面 + 数据面"的双服务器架构，OWASP 检测位于数据面处理管线中，通过规则编译器与流水线阶段共同完成请求拦截与放行决策。

```mermaid
graph TB
subgraph "控制面"
Admin["管理接口<br/>REST API + 嵌入式前端"]
end
subgraph "数据面"
Listener["监听器"]
Engine["WAF 引擎"]
Pipeline["处理流水线"]
Phases["阶段集合<br/>ACL → Bot → OWASP → 签名 → 自定义"]
OWASP["OWASP 检测引擎<br/>基础/扩展规则"]
Block["阻断响应渲染"]
end
Admin --> Engine
Listener --> Engine
Engine --> Pipeline
Pipeline --> Phases
Phases --> OWASP
OWASP --> Block
```

**图表来源**
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/rules/phases.go:246-303](file://internal/core/rules/phases.go#L246-L303)

**章节来源**
- [internal/core/engine/engine.go:15-37](file://internal/core/engine/engine.go#L15-L37)
- [internal/core/pipeline/pipeline.go:37-71](file://internal/core/pipeline/pipeline.go#L37-L71)

## 核心组件
- OWASP 默认检测阶段：负责扫描路径、查询串、头部、表单/JSON/Multipart 字段等，支持上传文件名与内容类型校验。
- OWASP 扩展检测：针对 SSRF、命令注入、XXE、LDAP 注入、NoSQL 注入、模板注入、JNDI/Log4Shell、CRLF、表达式语言注入、反序列化、协议违规等专项规则。
- 规则编译与匹配：基于 DSL 的规则解析与缓存，支持复合条件（and/or/not）。
- 流水线与引擎：按固定顺序执行各阶段，首个拦截结果短路后续阶段；支持 ACL 白名单直接放行。
- 阻断页面渲染：根据站点运行时配置或全局默认模板生成阻断页。

**章节来源**
- [internal/core/rules/phases.go:246-303](file://internal/core/rules/phases.go#L246-L303)
- [internal/waf/owasp.go:48-234](file://internal/waf/owasp.go#L48-L234)
- [internal/waf/owasp_extended.go:58-76](file://internal/waf/owasp_extended.go#L58-L76)

## 架构总览
OWASP 检测在数据面以"OWASP 默认阶段"为核心，结合"扩展规则子系统"，在请求进入上游前完成多层过滤与评分。整体流程如下：

```mermaid
sequenceDiagram
participant Client as "客户端"
participant Listener as "监听器"
participant Engine as "WAF 引擎"
participant Pipeline as "流水线"
participant OWASP as "OWASP 阶段"
participant Ext as "扩展规则"
participant Upstream as "上游服务"
Client->>Listener : HTTP 请求
Listener->>Engine : 构建 RequestCtx
Engine->>Pipeline : 执行阶段
Pipeline->>OWASP : 提取目标并扫描
OWASP->>Ext : 调用扩展规则检查
Ext-->>OWASP : 返回命中结果
OWASP-->>Pipeline : 最佳命中或放行
alt 命中且动作为拦截/丢弃
Pipeline-->>Client : 渲染阻断页
else 放行
Pipeline-->>Upstream : 转发请求
end
```

**图表来源**
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/rules/phases.go:256-303](file://internal/core/rules/phases.go#L256-L303)
- [internal/waf/owasp.go:48-234](file://internal/waf/owasp.go#L48-L234)
- [internal/waf/owasp_extended.go:58-76](file://internal/waf/owasp_extended.go#L58-L76)

## 详细组件分析

### OWASP 默认阶段（基础规则）
- 目标收集：路径、查询串、头部（过滤标准头）、Cookie 值（剔除可能的会话标识）、Referer 查询串与片段。
- 输入归一化：多轮 URL 解码、HTML 实体解码、JS 转义解码、UTF-7 解码、SQL 注释剥离、空白折叠、大小写统一。
- 快速通道：纯字母数字 + 安全字符的字符串跳过正则扫描；超长目标截断；重编码深度检测后二次扫描。
- 敏感度阈值：低/中/高三档，分别对应不同阈值，用于聚合评分与命中判定。
- 命中后动作：依据站点保护配置选择拦截或丢弃。

```mermaid
flowchart TD
Start(["开始"]) --> Collect["收集目标<br/>路径/查询/头部/Cookie/Referer"]
Collect --> CleanCheck{"是否为安全字符串？"}
CleanCheck --> |是| Skip["跳过正则扫描"]
CleanCheck --> |否| Normalize["多轮归一化<br/>URL/HTML/JS/UTF7/SQL注释/空白/小写"]
Normalize --> Threshold["应用敏感度阈值"]
Threshold --> Scan["基础规则扫描<br/>SQLi/XSS/命令注入/路径遍历等"]
Scan --> FP["误报抑制<br/>结构化上下文判断"]
FP --> Hits{"是否有命中？"}
Hits --> |是| Action["按配置动作拦截/丢弃"]
Hits --> |否| DeepScan["深度解码扫描<br/>JS转义/URL编码/BASE64提取"]
DeepScan --> DeepFP["深度误报抑制"]
DeepFP --> DeepHits{"深度扫描命中？"}
DeepHits --> |是| Action
DeepHits --> |否| Done(["结束"])
```

**图表来源**
- [internal/waf/owasp.go:48-234](file://internal/waf/owasp.go#L48-L234)
- [internal/waf/owasp.go:375-384](file://internal/waf/owasp.go#L375-L384)
- [internal/waf/owasp.go:498-566](file://internal/waf/owasp.go#L498-L566)

**章节来源**
- [internal/waf/owasp.go:48-234](file://internal/waf/owasp.go#L48-L234)
- [internal/waf/owasp.go:375-384](file://internal/waf/owasp.go#L375-L384)
- [internal/waf/owasp.go:498-566](file://internal/waf/owasp.go#L498-L566)

### OWASP 扩展阶段（专项规则）
- SSRF：云元数据地址、私有/回环地址、本地套接字、文件/字典/LDAP 等方案、十进制/八进制/十六进制编码 IP、IPv6 映射、IMDSv2 头、Unix 套接字等。
- 命令注入：管道/分号/反引号/$() 链接、重定向、环境变量赋值、IFS 空白绕过、管道连接、Here-string、ANSI-C 引号、Newline 注入、SSI、Git 参数注入等。
- XXE：DOCTYPE、SYSTEM、实体展开、参数实体外带、XInclude。
- LDAP 注入：括号组合、对象类、通配符。
- NoSQL 注入：$where/$regex/$or/$exists/$lookup 等。
- 模板注入（SSTI）：Jinja/Django/Twig、Freemarker/Velocity/JSP EL、ERB、Smarty、Python dunder、Pebble、EJS、Handlebars/Mustache、ThinkPHP、DedeCMS 等。
- JNDI/Log4Shell：jndi:、${env/sys/java/base64:}、Unicode/URL 编码、嵌套表达式。
- CRLF：回车换行注入、响应拆分。
- 表达式语言（EL）：SpEL/OGNL/Spring EL、反射链、静态方法调用、上下文访问。
- 反序列化：Java/PHP/Python/.NET/Ruby/Marshal 等魔数与特征。
- 协议违规：CL+TE 冲突、重复 Content-Length、超大头部长度。

```mermaid
classDiagram
class OWASP扩展规则 {
+SSRF()
+命令注入()
+XXE()
+LDAP注入()
+NoSQL注入()
+模板注入()
+JNDI()
+CRLF()
+表达式语言()
+反序列化()
+协议违规()
}
```

**图表来源**
- [internal/waf/owasp_extended.go:58-76](file://internal/waf/owasp_extended.go#L58-L76)
- [internal/waf/owasp_extended.go:138-156](file://internal/waf/owasp_extended.go#L138-L156)
- [internal/waf/owasp_extended.go:185-203](file://internal/waf/owasp_extended.go#L185-L203)
- [internal/waf/owasp_extended.go:228-246](file://internal/waf/owasp_extended.go#L228-L246)
- [internal/waf/owasp_extended.go:267-282](file://internal/waf/owasp_extended.go#L267-L282)
- [internal/waf/owasp_extended.go:347-365](file://internal/waf/owasp_extended.go#L347-L365)
- [internal/waf/owasp_extended.go:473-491](file://internal/waf/owasp_extended.go#L473-L491)
- [internal/waf/owasp_extended.go:506-521](file://internal/waf/owasp_extended.go#L506-L521)
- [internal/waf/owasp_extended.go:574-592](file://internal/waf/owasp_extended.go#L574-L592)
- [internal/waf/owasp_extended.go:629-648](file://internal/waf/owasp_extended.go#L629-L648)
- [internal/waf/owasp_extended.go:652-696](file://internal/waf/owasp_extended.go#L652-L696)

**章节来源**
- [internal/waf/owasp_extended.go:11-76](file://internal/waf/owasp_extended.go#L11-L76)
- [internal/waf/owasp_extended.go:78-156](file://internal/waf/owasp_extended.go#L78-L156)
- [internal/waf/owasp_extended.go:158-203](file://internal/waf/owasp_extended.go#L158-L203)
- [internal/waf/owasp_extended.go:205-246](file://internal/waf/owasp_extended.go#L205-L246)
- [internal/waf/owasp_extended.go:248-282](file://internal/waf/owasp_extended.go#L248-L282)
- [internal/waf/owasp_extended.go:284-365](file://internal/waf/owasp_extended.go#L284-L365)
- [internal/waf/owasp_extended.go:441-491](file://internal/waf/owasp_extended.go#L441-L491)
- [internal/waf/owasp_extended.go:493-521](file://internal/waf/owasp_extended.go#L493-L521)
- [internal/waf/owasp_extended.go:523-592](file://internal/waf/owasp_extended.go#L523-L592)
- [internal/waf/owasp_extended.go:594-648](file://internal/waf/owasp_extended.go#L594-L648)
- [internal/waf/owasp_extended.go:650-696](file://internal/waf/owasp_extended.go#L650-L696)

### 规则分类与优先级
- 基础规则：由 OWASP 默认阶段扫描，覆盖 SQL 注入、XSS、命令注入、路径遍历、WebShell、反向 Shell、SSRF、XXE、LDAP 注入、NoSQL 注入、模板注入、JNDI、CRLF、表达式语言、反序列化、文件上传、协议违规等。
- 扩展规则：独立模块，针对特定攻击面的更细粒度规则与评分。
- 优先级：规则按 priority 升序、ID 升序执行；ACL allow 可短路整条流水线；首个拦截结果即终止后续阶段。

**章节来源**
- [internal/core/rules/phases.go:246-303](file://internal/core/rules/phases.go#L246-L303)
- [internal/core/engine/engine.go:157-175](file://internal/core/engine/engine.go#L157-L175)

### 检测精度优化策略
- 误报抑制：针对 XSS、SQLi、命令注入、路径遍历、SSRF、NoSQL 注入、表达式语言、反序列化等，内置上下文判断与结构化抑制逻辑。
- 敏感度阈值：低/中/高三档阈值，降低误报同时保证高敏模式下的检出率。
- 输入归一化：多轮解码与标准化，消除编码绕过与注释分割等规避手段。
- 目标截断与预过滤：超长目标截断、快速安全字符串跳过、关键字预过滤减少正则开销。
- Cookie 与 Referer 处理：剔除会话标识、仅扫描查询串与片段，避免误报。

**章节来源**
- [internal/waf/owasp.go:48-234](file://internal/waf/owasp.go#L48-L234)
- [internal/waf/owasp.go:375-384](file://internal/waf/owasp.go#L375-L384)
- [internal/waf/owasp.go:426-496](file://internal/waf/owasp.go#L426-L496)

### 规则更新与维护机制
- 新增规则：通过规则 DSL（kind:arg 或复合 JSON）定义，编译后按优先级排序执行。
- 调整现有规则：修改规则的 kind/arg、优先级、动作；复合规则可组合 and/or/not。
- 阈值调整：通过站点保护配置调整 OWASP 敏感度与动作；也可通过环境变量微调 Bot 与 Drop 阈值。
- 规则验证：提供大量单元测试覆盖典型误报与漏报场景，确保更新后稳定性。

**章节来源**
- [internal/core/rules/matcher.go:167-261](file://internal/core/rules/matcher.go#L167-L261)
- [internal/core/rules/phases.go:544-569](file://internal/core/rules/phases.go#L544-L569)
- [internal/waf/owasp/owasp_test.go:1-577](file://internal/waf/owasp/owasp_test.go#L1-L577)

### 配置示例与调试方法
- 敏感度与动作：通过站点保护配置设置 OWASPEnabled、OWASPSensitivity、OWASPAction；支持 low/mid/high 与拦截/丢弃。
- 环境变量：可通过 MY_OPENWAF_BOT_THRESHOLD、MY_OPENWAF_DROP_BOT_THRESHOLD 等调整 Bot 与 Drop 阈值。
- 调试建议：使用测试用例定位误报/漏报；关注归一化前后差异；结合 Body 解析与 Cookie/Referer 处理逻辑验证。

**章节来源**
- [internal/core/config.go:113-182](file://internal/core/config.go#L113-L182)
- [internal/core/rules/phases.go:256-303](file://internal/core/rules/phases.go#L256-L303)
- [internal/waf/owasp/owasp_test.go:1-577](file://internal/waf/owasp/owasp_test.go#L1-L577)

### 与其他安全机制的配合使用与最佳实践
- ACL 白名单：allow 规则可直接放行，跳过 OWASP、签名与自定义阶段。
- Bot 检测：两阶段评分（PreScreen → DeepScore），恶意分数达到阈值可直接丢弃连接。
- CVE 检测：在 OWASP 之后执行，针对已知漏洞利用模式自动拦截或升级为丢弃。
- 速率限制：在 Bot 之后执行，防止滥用。
- 阻断页面：根据站点运行时配置或全局默认模板渲染，支持自定义状态码与 HTML。

**章节来源**
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/rules/phases.go:172-244](file://internal/core/rules/phases.go#L172-L244)
- [internal/core/rules/phases.go:305-358](file://internal/core/rules/phases.go#L305-L358)

## 依赖分析
OWASP 检测模块与规则系统、引擎、流水线之间存在清晰的依赖关系，遵循"规则编译 → 流水线执行 → 阶段扫描 → 命中动作"的链路。

```mermaid
graph TB
OWASP["OWASP 默认阶段<br/>owasp.go"]
EXT["OWASP 扩展阶段<br/>owasp_extended.go"]
MATCHER["规则匹配器<br/>matcher.go"]
PHASES["流水线阶段<br/>phases.go"]
ENGINE["WAF 引擎<br/>engine.go"]
PIPE["处理流水线<br/>pipeline.go"]
MATCHER --> PHASES
PHASES --> ENGINE
ENGINE --> PIPE
PIPE --> OWASP
OWASP --> EXT
```

**图表来源**
- [internal/core/rules/matcher.go:167-261](file://internal/core/rules/matcher.go#L167-L261)
- [internal/core/rules/phases.go:246-303](file://internal/core/rules/phases.go#L246-L303)
- [internal/core/engine/engine.go:57-129](file://internal/core/engine/engine.go#L57-L129)
- [internal/core/pipeline/pipeline.go:37-71](file://internal/core/pipeline/pipeline.go#L37-L71)
- [internal/waf/owasp.go:48-234](file://internal/waf/owasp.go#L48-L234)
- [internal/waf/owasp_extended.go:58-76](file://internal/waf/owasp_extended.go#L58-L76)

**章节来源**
- [internal/core/rules/matcher.go:1-343](file://internal/core/rules/matcher.go#L1-L343)
- [internal/core/rules/phases.go:1-569](file://internal/core/rules/phases.go#L1-L569)
- [internal/core/engine/engine.go:1-176](file://internal/core/engine/engine.go#L1-L176)
- [internal/core/pipeline/pipeline.go:1-71](file://internal/core/pipeline/pipeline.go#L1-L71)

## 性能考虑
- 快速预过滤：纯字母数字字符串直接跳过正则；关键字预过滤减少正则匹配次数。
- 归一化成本控制：多轮解码与正则扫描限制在合理范围内，超长目标截断。
- 正则缓存：规则编译时缓存正则表达式，避免重复编译。
- 流水线短路：首个拦截结果立即终止后续阶段，降低整体延迟。
- 体数据解析：按内容类型解析表单/JSON/Multipart，限制采样大小与递归深度，避免内存与 CPU 泄漏。

**章节来源**
- [internal/waf/owasp.go:48-234](file://internal/waf/owasp.go#L48-L234)
- [internal/core/rules/phases.go:360-405](file://internal/core/rules/phases.go#L360-L405)
- [internal/core/rules/matcher.go:271-296](file://internal/core/rules/matcher.go#L271-L296)

## 故障排查指南
- 误报定位：通过测试用例验证误报场景，逐步缩小到具体规则与误报抑制逻辑。
- 归一化问题：对比原始输入与归一化后的字符串，确认是否被过度解码或注释剥离导致误判。
- 敏感度与阈值：根据业务风险调整敏感度档位与阈值，观察命中率与误报率变化。
- 体数据扫描：检查表单/JSON/Multipart 解析逻辑，确认采样大小与字段提取是否符合预期。
- Cookie/Referer：确认会话标识被正确剔除，避免误报；仅扫描查询串与片段。

**章节来源**
- [internal/waf/owasp/owasp_test.go:1-577](file://internal/waf/owasp/owasp_test.go#L1-L577)
- [internal/waf/owasp_extended.go:1-471](file://internal/waf/owasp_extended.go#L1-L471)
- [internal/waf/owasp.go:426-496](file://internal/waf/owasp.go#L426-L496)
- [internal/core/rules/phases.go:360-405](file://internal/core/rules/phases.go#L360-L405)

## 结论
My-OpenWaf 的 OWASP 检测体系通过"基础规则 + 扩展规则"的双层设计，结合严格的误报抑制、输入归一化与阈值控制，在性能与准确性之间取得平衡。规则 DSL 与流水线机制使得规则更新与维护便捷可控，配合 ACL、Bot、CVE、速率限制等安全机制，形成完整的防护闭环。

## 附录

### SQL 注入（SQLi）检测

#### 检测特征识别

系统通过以下特征识别 SQL 注入攻击：

```mermaid
flowchart TD
Input[输入数据] --> PreFilter[预过滤检查]
PreFilter --> HasIndicator{是否包含 SQL 关键词}
HasIndicator --> |否| Skip[跳过深度检测]
HasIndicator --> |是| Normalize[标准化处理]
Normalize --> RegexScan[正则表达式扫描]
RegexScan --> ContextCheck[上下文检查]
ContextCheck --> FPCheck[误报检查]
FPCheck --> Result[检测结果]
Skip --> Result
```

**图表来源**
- [internal/waf/owasp.go:1021-1069](file://internal/waf/owasp.go#L1021-L1069)
- [internal/waf/owasp.go:1935-1953](file://internal/waf/owasp.go#L1935-L1953)

#### 正则表达式匹配模式
系统为 SQL 注入检测定义了 23+ 个专门的正则表达式模式，每个模式都有特定的分数权重：

| 规则 ID | 检测模式 | 分数 | 描述 |
|---------|----------|------|------|
| sqli:001 | `union\s*(all\s*)?select` | 5 | UNION SELECT 注入 |
| sqli:002 | `'\s*(or|and)\s+['"]?\d` | 5 | OR/AND 条件注入 |
| sqli:003 | `(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(` | 5 | 时间延迟注入 |
| sqli:004 | `;\s*(select|drop|alter|create|truncate|delete|update|insert)\s` | 5 | 堆叠查询注入 |
| sqli:005 | `['"\d]\s*(--(?:[\s/]|$)|/\*)` | 3 | 注释注入 |
| sqli:006 | `'\s*;\s*\w` | 3 | 分号后跟随单词 |
| sqli:007 | `(chr|unhex|conv)\s*\(` | 3 | 字符转换函数 |
| sqli:008 | `[,=(]\s*0x[0-9a-f]{4,}` | 2 | 十六进制注入 |

#### 检测阈值设置
SQL 注入检测采用累积评分机制，阈值根据敏感度级别动态调整：
- **低敏感度（low）**：阈值 7，适合生产环境，减少误报
- **中敏感度（mid）**：阈值 4，平衡检测精度和误报率
- **高敏感度（high）**：阈值 3，适合安全审计场景

#### 上下文感知检测
系统通过复杂的上下文检查减少误报：

```mermaid
classDiagram
class SQLiContext {
+hasSQLContext() bool
+hasStructuralKeywords() bool
+hasInjectionOperators() bool
+isDocumentationText() bool
+isSearchQuery() bool
}
class FPChecker {
+checkSleepFunction() bool
+checkJavaScriptContext() bool
+checkURLPathContext() bool
+checkARNPattern() bool
}
SQLiContext --> FPChecker : 使用
```

**图表来源**
- [internal/waf/owasp.go:1249-1445](file://internal/waf/owasp.go#L1249-L1445)
- [internal/waf/owasp.go:1762-1774](file://internal/waf/owasp.go#L1762-L1774)

**章节来源**
- [internal/waf/owasp.go:1881-1953](file://internal/waf/owasp.go#L1881-L1953)
- [internal/waf/owasp.go:1249-1445](file://internal/waf/owasp.go#L1249-L1445)

### 跨站脚本（XSS）检测

#### 检测特征识别
XSS 检测系统针对现代 Web 应用的各种 XSS 攻击变种进行了专门优化：

| 检测类别 | 检测模式 | 分数 | 示例 |
|----------|----------|------|------|
| 脚本标签 | `<script[\s>]` | 5 | `<script>alert(1)</script>` |
| 事件处理器 | `\bon(error|load|click|...)\s*=` | 5 | `onload="alert(1)"` |
| JavaScript 协议 | `javascript\s*:` | 5 | `javascript:alert(1)` |
| DOM 操作 | `document\.(cookie|location|write|domain)` | 4 | `document.write()` |
| SVG 注入 | `<svg[\s>]` | 2 | `<svg onload=alert(1)>` |
| 表达式注入 | `expression\s*\(` | 3 | `expression(alert(1))` |

#### 上下文感知检测策略
XSS 检测采用了精细的上下文感知策略：

```mermaid
flowchart TD
XSSInput[XSS 输入] --> HasIndicator{是否包含 XSS 关键词}
HasIndicator --> |否| NoTrigger[不触发]
HasIndicator --> |是| CheckContext[检查执行上下文]
CheckContext --> IsActive{是否包含活动执行代码}
IsActive --> |否| FPCheck[误报检查]
IsActive --> |是| Trigger[触发检测]
FPCheck --> IsFP{是否为误报}
IsFP --> |是| NoTrigger
IsFP --> |否| Trigger
```

**图表来源**
- [internal/waf/owasp.go:1447-1573](file://internal/waf/owasp.go#L1447-L1573)
- [internal/waf/owasp.go:2069-2169](file://internal/waf/owasp.go#L2069-L2169)

#### 误报抑制机制
系统实现了多层次的误报抑制：
1. **CDN 回调抑制**：识别并抑制 CDN onload 回调参数
2. **富文本内容抑制**：CMS 富文本中的 SVG、iframe 等不会触发 XSS
3. **JavaScript 代码抑制**：纯 JavaScript 代码中的函数调用不会触发
4. **URL 参数抑制**：URL 参数中的事件处理器不会触发

**章节来源**
- [internal/waf/owasp.go:2069-2169](file://internal/waf/owasp.go#L2069-L2169)
- [internal/waf/owasp.go:1447-1573](file://internal/waf/owasp.go#L1447-L1573)

### 命令注入（CmdInject）检测

#### 检测特征识别
命令注入检测系统专门针对操作系统命令注入攻击：

| 检测模式 | 分数 | 描述 | 示例 |
|----------|------|------|------|
| 管道操作符 | 5 | `|` 管道操作符 | `id|grep admin` |
| 分号连接 | 5 | `;` 分号连接 | `id; whoami` |
| 反引号注入 | 4 | `` `command` `` | ``whoami` `` |
| 环境变量 | 3 | `VAR=value command` | `PATH=/tmp ls` |
| 重定向操作 | 4 | `>` 重定向 | `id > /tmp/out` |
| 空字节注入 | 3 | `%00` 空字节 | `cmd%00` |

#### 高置信度检测
系统要求命令注入检测达到一定置信度才能触发：

```mermaid
stateDiagram-v2
[*] --> LowConfidence
LowConfidence --> MediumConfidence : 发现弱模式
MediumConfidence --> HighConfidence : 发现强模式
HighConfidence --> Trigger : 达到阈值
LowConfidence --> Suppress : 误报抑制
MediumConfidence --> Suppress : 误报抑制
Suppress --> [*]
Trigger --> [*]
```

**图表来源**
- [internal/waf/owasp.go:1612-1629](file://internal/waf/owasp.go#L1612-L1629)
- [internal/waf/owasp.go:1631-1679](file://internal/waf/owasp.go#L1631-L1679)

#### 误报抑制策略
命令注入检测采用了严格的误报抑制策略：
1. **二进制数据抑制**：二进制 POST 主体中的空字节不会触发
2. **协议数据抑制**：Telemetry、Analytics 等协议数据中的特殊字符不会触发
3. **文档内容抑制**：技术文档中的命令示例不会触发
4. **编程语言抑制**：JavaScript 中的函数调用不会触发

**章节来源**
- [internal/waf/owasp.go:1612-1679](file://internal/waf/owasp.go#L1612-L1679)

### 路径遍历（PathTrav）检测

#### 检测特征识别
路径遍历检测系统专门针对文件系统路径遍历攻击：

| 检测模式 | 分数 | 描述 | 示例 |
|----------|------|------|------|
| 相对路径 | `(\.\./){2,}` | 多层目录遍历 | `../../../etc/passwd` |
| 敏感文件 | `(etc/passwd|etc/shadow)` | 敏感系统文件 | `/etc/passwd` |
| Windows 路径 | `win\.ini|cmd\.exe` | Windows 系统文件 | `\windows\system32\cmd.exe` |
| 进程信息 | `/proc/self/.*` | Linux 进程信息 | `/proc/self/environ` |
| Web 配置 | `(web\.xml|struts\.xml)` | Web 应用配置 | `WEB-INF/web.xml` |
| 版本控制 | `\.git[/\\]|\.svn[/\\]` | 版本控制系统 | `.git/config` |

#### 敏感路径检测
系统特别关注可能造成严重损害的敏感路径：

```mermaid
flowchart TD
PathInput["路径输入"] --> CheckSensitive{"是否包含敏感路径"}
CheckSensitive --> |否| NormalPath["普通路径"]
CheckSensitive --> |是| CheckContext{"是否在受保护环境中"}
CheckContext --> |是| Trigger["触发检测"]
CheckContext --> |否| Suppress["抑制检测"]
NormalPath --> End1[("结束")]
Trigger --> End2[("结束")]
Suppress --> End3[("结束")]
```

**图表来源**
- [internal/waf/owasp.go:1757-1760](file://internal/waf/owasp.go#L1757-L1760)
- [internal/waf/owasp.go:1778-1789](file://internal/waf/owasp.go#L1778-L1789)

**章节来源**
- [internal/waf/owasp.go:2171-2212](file://internal/waf/owasp.go#L2171-L2212)
- [internal/waf/owasp.go:1757-1789](file://internal/waf/owasp.go#L1757-L1789)

### 服务器端请求伪造（SSRF）检测

#### 检测特征识别
SSRF 检测系统专门针对服务器端请求伪造攻击：

| 检测模式 | 分数 | 描述 | 示例 |
|----------|------|------|------|
| 内部地址 | `169\.254\.169\.254` | AWS 元数据服务 | `169.254.169.254/latest` |
| 私有网络 | `10\.\d{1,3}\.\d{1,3}\.\d{1,3}` | 私有 IP 地址 | `10.0.0.1/admin` |
| 本地主机 | `localhost|127\.0\.` | 本地回环地址 | `http://localhost:8080` |
| 文件协议 | `file://` | 本地文件访问 | `file:///etc/passwd` |
| Unix 套接字 | `unix:[^\s]{10,}` | Unix 套接字 | `unix:/var/run/mysql.sock` |
| 编码绕过 | `0x[0-9a-f]{8}` | 十六进制编码 | `http://0x7f000001` |

#### 上下文感知检测
SSRF 检测采用了严格的上下文检查：

```mermaid
classDiagram
class SSRFContext {
+hasURLScheme() bool
+hasPrivateAddress() bool
+hasLocalhost() bool
+hasMetadataService() bool
+hasFileProtocol() bool
}
class SSRFFilter {
+checkURLContext() bool
+checkIPAddress() bool
+checkProtocol() bool
+checkPathTraversal() bool
}
SSRFContext --> SSRFFilter : 验证
```

**图表来源**
- [internal/waf/owasp_extended.go:14-26](file://internal/waf/owasp_extended.go#L14-L26)
- [internal/waf/owasp_extended.go:58-76](file://internal/waf/owasp_extended.go#L58-L76)

**章节来源**
- [internal/waf/owasp_extended.go:58-76](file://internal/waf/owasp_extended.go#L58-L76)

### 规则注册与管理

#### 规则注册机制
系统通过注册表机制管理所有 OWASP 规则：

```mermaid
classDiagram
class OWASPRule {
+string ID
+string Category
+string Name
+string Description
+bool Enabled
+CheckFunc(input) (int, bool, string)
}
class OWASPRuleRegistry {
+map[string]*OWASPRule rules
+Register(rule)
+Get(id) (*OWASPRule, bool)
+All() []*OWASPRule
+AllByCategory(category) []*OWASPRule
+Count() int
}
class OWASPRuleOverride {
+*bool Enabled
+[]string Whitelist
+string Action
+int StatusCode
+string RedirectTo
+string Sensitivity
}
OWASPRuleRegistry --> OWASPRule : manages
OWASPRuleRegistry --> OWASPRuleOverride : uses
```

**图表来源**
- [internal/waf/owasp_registry.go:9-34](file://internal/waf/owasp_registry.go#L9-L34)
- [internal/waf/owasp_registry.go:206-225](file://internal/waf/owasp_registry.go#L206-L225)

#### 规则管理 API
管理界面提供了完整的规则管理功能：

```mermaid
sequenceDiagram
participant Admin as 管理员
participant API as 管理 API
participant Registry as 规则注册表
participant Config as 配置存储
Admin->>API : 列出规则
API->>Registry : 获取所有规则
Registry-->>API : 返回规则列表
API-->>Admin : 显示规则
Admin->>API : 更新单个规则
API->>Registry : 验证规则存在
Registry-->>API : 返回规则
API->>Config : 保存覆盖配置
Config-->>API : 确认保存
API-->>Admin : 返回更新结果
```

**图表来源**
- [internal/admin/detect/owasp_rules.go:27-84](file://internal/admin/detect/owasp_rules.go#L27-L84)
- [internal/admin/detect/owasp_rules.go:86-150](file://internal/admin/detect/owasp_rules.go#L86-L150)

**章节来源**
- [internal/waf/owasp_registry.go:1-412](file://internal/waf/owasp_registry.go#L1-L412)
- [internal/admin/detect/owasp_rules.go:1-258](file://internal/admin/detect/owasp_rules.go#L1-L258)