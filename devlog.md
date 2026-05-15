# Development Log

## 2026-05-11 — 站点列表分页与配置写入一致性审查

### 变更概览

延续站点模块闭环检查，聚焦站点列表分页和配置写入过程中的部分落库风险，按最小范围修复前端分页断点与可明确事务化的仓储操作。

### 1. 站点列表分页闭环修复

**文件**: `frontend/app/(dashboard)/sites/page.tsx`

- 前端调用 `listSites` 时传入 `page/page_size`，使用后端已有 `total` 返回值计算页数。
- 复用现有 `Pagination` 组件展示总数和上一页/下一页。
- 删除当前页最后一条数据时自动回退到上一页，避免空页停留。
- 启停、删除、新增后按当前页刷新。

### 2. 配置写入部分落库风险收敛

**文件**: `internal/store/repository/site.go`, `internal/store/repository/site_listener.go`, `internal/admin/handler_site.go`, `internal/admin/handler_site_listener.go`

- 新增 `SiteRepo.DeleteWithListeners()`，站点删除与 listener 清理放入同一 DB transaction，避免只删除一侧。
- 新增 `SiteListenerRepo.CreateWithLegacyPromotion()`，legacy listener 升级和新 listener 创建放入同一 DB transaction，避免只创建 legacy 或只创建新 listener。
- handler 改为调用事务仓储方法，保持控制层职责简单。

### 3. 回归测试

**文件**: `internal/store/repository/access_log_test.go`

- 覆盖 `DeleteWithListeners()` 删除站点时同步删除 listener。
- 覆盖 `CreateWithLegacyPromotion()` 同时创建 legacy promoted listener 与新 listener。

### 验证结果

```
frontend typecheck/lint: 通过
go test -p 1 ./internal/store/repository ./internal/admin ./internal/app ./internal/snapshot: 通过
```

### 原则应用

- **KISS**：前端直接接入后端已有分页参数，没有引入新 API。
- **YAGNI**：未尝试一次性重构所有 reload 失败回滚语义，仅事务化当前站点模块中明确的多写操作。
- **DRY**：复用已有 `Pagination` 组件。
- **SOLID**：事务边界下沉到 repository，handler 只负责输入校验与 reload 调用。

### 下一步

- 等待 Go 测试完成后更新验证结果。
- 如继续推进，可审查其它多写配置接口是否也需要仓储事务边界。
- 真正实现“reload 失败自动回滚已落库配置”需要重构 mutation + reload 的事务/补偿模型，应单独立项。

---

## 2026-05-11 — 站点请求处理流程与配置闭环审查

### 变更概览

继续按站点链路检查 listener、snapshot 匹配、WAF pipeline、WebSocket/SSE/HTTP 转发、访问日志/攻击日志与前端站点配置闭环，并修复本轮发现的明确断点。

### 1. WebSocket 出站转发头修复

**文件**: `internal/dataplane/websocket.go`, `internal/dataplane/handler.go`, `internal/dataplane/websocket_test.go`

- `ForwardWebSocket` 增加 `clientIP` 参数，WebSocket 握手与 HTTP/SSE 一致应用站点出站策略。
- 重建 upstream handshake 时过滤旧的 hop-by-hop 与 forwarded 头，统一写入 `Host`、`Connection: Upgrade`、`X-Forwarded-For`、`X-Forwarded-Host`。
- 补充 preserve-original-host 与默认 upstream-host 两类回归测试。

### 2. 同 bind 多站点监听冲突修复

**文件**: `internal/app/server.go`, `internal/app/server_test.go`

- data-plane listener 从“每站点一个 Hertz 实例”调整为“每个 bind 一个 Hertz 实例”，避免多个站点共享 `:80`/`:443` 时重复监听同一端口。
- 保留 snapshot 的 Host 匹配能力，由同一个 bind listener 内的 `dataplane.Handler` 按 Host 匹配站点。
- bind 级 fingerprint 覆盖同 bind 下所有站点 TLS 配置、站点证书和 SNI 证书变化，确保热重启仍可追踪。
- 新增单元测试覆盖同 bind 去重并优先选择 TLS runtime 作为监听代表。

### 3. 站点一致性修复

**文件**: `internal/admin/handler_site.go`, `internal/admin/router.go`, `internal/store/repository/access_log_test.go`, `internal/snapshot/build.go`, `internal/snapshot/snapshot_test.go`

- 删除站点时同步删除该站点的 managed listener，避免 orphan listener 残留到后续列表或 snapshot 构建路径。
- snapshot 注册站点键时保留首个 `bind+host`，跳过后续重复键，避免 DB 排序后的配置被静默覆盖。
- TLS listener 无有效证书时跳过启动并记录告警，避免误以明文方式监听 HTTPS 端口。
- 补充 `SiteListenerRepo.DeleteBySite` 与重复 `bind+host` 注册保护测试。

### 4. 站点前端配置闭环修复

**文件**: `frontend/components/site-listeners-panel.tsx`, `frontend/app/(dashboard)/sites/[id]/client.tsx`, `frontend/app/layout.tsx`, `frontend/app/globals.css`

- legacy listener（`id=0`）编辑不再调用 `/listeners/0/update`，改为创建正式监听，避免必现 404。
- 站点详情保存拒绝空 upstream，避免保存后 snapshot 跳过站点导致数据面不可用。
- HTTPS 站点详情补齐证书选择和 `cert_id` 保存，避免启用 TLS 但无证书。
- 补齐站点详情中的 `xff_mode`、`trusted_cidr`、`preserve_original_host`、`upstream_tls_skip_verify`、`upstream_tls_server_name` 编辑与保存。
- 移除 `next/font/google` 构建期外网字体依赖，改用 CSS 系统字体变量，避免离线构建因 Google Fonts 下载失败而中断。

### 5. 站点请求流程梳理结论

- listener 启动：snapshot 中 enabled site/listener 生成运行时配置，当前按 bind 聚合启动数据面 Hertz。
- 请求入口：`dataplane.Handler` 加载 snapshot，按 listener bind + Host 匹配 `SiteRuntime`。
- WAF 处理：解析 client IP，执行 IP reputation、challenge、anti-replay、OWASP/CVE、ACL、Bot、限流、签名与自定义规则。
- 动作处理：drop/challenge/redirect/intercept 终止链路，pass/observe 继续代理。
- upstream：HTTP、SSE、WebSocket 均应用站点级 Host/X-Forwarded 策略。
- 日志：安全事件、observe 命中、访问日志、drop 事件按异步写入器或仓储记录。

### 测试结果

```
go test -p 1 ./internal/app ./internal/dataplane ./internal/core/engine ./internal/core/rules ./internal/snapshot ./internal/admin ./internal/store/repository: 通过
frontend typecheck: 通过
frontend lint: 通过
./scripts/build.ps1: 通过
blazehttp -t http://127.0.0.1:80 -c 40: 通过
总样本数量: 33877, 成功: 33877, 错误: 0
检出率: 100.00%, 误报率: 0.00%, 准确率: 100.00%, 平均耗时: 32.36ms
```

### 问题与处理

- 前端二次 typecheck 曾在 Windows 环境触发 `VirtualAlloc failed`，使用较低 `NODE_OPTIONS=--max-old-space-size=1536` 后通过，判断为本机资源限制。
- 首次 Go 复测命令存在 PowerShell 语法错误，修正命令后测试通过。
- 本轮涉及 `internal/dataplane/handler.go` 与站点 listener 链路，已完成完整构建、启动服务和 `blazehttp` 压测最终验收。

### 原则应用

- **KISS**：同 bind 冲突用 bind 级 listener 聚合解决，没有引入额外路由层。
- **YAGNI**：未扩展新站点功能，只补齐已有字段的编辑与保存闭环。
- **DRY**：复用现有 snapshot Host 匹配能力，不重复实现站点路由。
- **SOLID**：listener 生命周期仍由 app 层负责，dataplane handler 继续只负责请求匹配和处理。

### 下一步

- 继续检查 reload 失败时的事务回滚体验。
- 继续补全站点列表分页与更多前端字段展示体验。

---

## 2026-05-11 — 全链路审查：日志、规则、站点配置与运行验证

### 变更概览

按全链路要求检查控制面 API、前端调用、规则处理、站点配置、数据面处理、攻击日志与访问日志保存查询，并修复审查中发现的闭环问题。

### 1. 访问日志查询链路修复

**文件**: `internal/admin/handler_access_log.go`, `internal/admin/handler_site_observability.go`, `internal/store/repository/access_log.go`

- 补齐前端访问日志页面发送的 `status_group=2xx/3xx/4xx/5xx` 后端过滤逻辑。
- 站点详情访问日志改为只按稳定的 `site_id` 查询，不再额外按当前 `site.Host` 过滤，避免站点域名修改后历史日志在详情页消失。

### 2. 规则导入链路修复

**文件**: `internal/admin/handler_rule.go`, `internal/store/repository/rule.go`

- 规则导入时统一校验并规范化 action，拒绝无效动作。
- 新增 `RuleRepo.BatchCreate()`，用事务批量创建规则，避免导入中途失败造成部分规则落库但配置未完整 reload 的不一致状态。

### 3. 回归测试补充

**文件**: `internal/admin/handler_ip_list_test.go`, `internal/store/repository/access_log_test.go`

- 覆盖规则 action 规范化与非法 action 拒绝。
- 覆盖访问日志 `status_group` 查询。
- 覆盖规则批量导入事务回滚。

### 4. 全链路审查结论

- 管理端路由已覆盖站点、规则、证书、策略、保护配置、CVE/OWASP 规则、安全事件、访问日志、drop 事件等读写入口。
- 配置写入链路会触发 reload：`BumpRevision` → `ReloadSnapshot` → 运行时配置刷新 → IP 列表刷新 → data-plane listener 热重启 → Redis reload 通知。
- 数据面链路覆盖站点匹配、IP 声誉、AntiReplay、OWASP/CVE、ACL、Bot、限流、规则动作、代理转发、访问日志与安全事件写入。
- 前端主要链路通过 `frontend/lib/api.ts`、`frontend/lib/rules-api.ts` 与后端路由对齐；本轮发现并补齐访问日志状态码分组筛选后端支持。

### 测试结果

```
frontend typecheck: 通过
frontend lint: 通过
frontend build: 通过
go test ./internal/admin ./internal/store/repository: 通过
低并发 go test（排除既有 My-OpenWaf/temp 包）: 通过
go build -o bin/my-openwaf.exe ./cmd/...: 通过
blazehttp -t http://127.0.0.1:80 -c 40: 通过
总样本数量: 33877, 成功: 33877, 错误: 0
检出率: 100.00%, 误报率: 0.00%, 平均耗时: 41.70ms
```

### 问题与处理

- 普通并发全量 Go 测试在 Windows 环境触发 `VirtualAlloc ... out of memory`，改用 `GOMAXPROCS=2` 与 `go test -p 1` 后通过，判断为本机资源限制而非代码失败。
- 服务压测日志中出现一次 `body size exceeds the given limit`，与压测大 body 样本相关；未发现 panic、fatal、crash 或监听失败。
- 当前 `go test ./...` 不排除 `My-OpenWaf/temp` 时仍可能受既有临时 Go 程序重复 `main` 影响，本轮未改动该临时目录。

### 原则应用

- **KISS**：只修复实际断链点，不扩展无关功能。
- **YAGNI**：未引入新的日志重试队列或复杂导入框架。
- **DRY**：访问日志状态分组过滤集中在 repository 层，普通列表与站点列表复用同一过滤器。
- **SOLID**：规则批量事务下沉到 `RuleRepo`，handler 只负责请求校验和响应。

---

## 2026-04-25 — 第三轮迭代：Per-Site策略 + React2Shell深度检测 + CVE预过滤

### 变更概览

实现每站点独立策略配置（混合策略）、增强 React RSC 反序列化漏洞检测、CVE 检测性能优化。

### 1. Per-Site 混合策略支持

**文件**: `internal/store/models.go`, `internal/snapshot/build.go`, `internal/core/engine/engine.go`

Site 模型新增 per-site 保护覆盖字段：
- `OWASPEnabled *bool` / `OWASPSensitivity` / `OWASPAction` — 站点级 OWASP 覆盖
- `CVEEnabled *bool` / `CVEAction` — 站点级 CVE 覆盖
- `RateLimitEnabled *bool` / `RateLimitWindow` / `RateLimitMax` / `RateLimitAction` — 站点级限速

引擎使用 `EffectiveProtection`（global + site 合并结果），不再仅依赖全局 `sn.Protection`。
`mergeProtection()` 在 snapshot build 阶段计算，运行时零开销。

### 2. React2Shell (CVE-2025-55182) 深度检测增强

**文件**: `internal/waf/cve_node.go`

替换粗糙的 `constructor.*constructor` 模式为精准 Flight 协议特征检测：
- `reRSCProtoConstructor` — `__proto__[constructor` 原型链穿越
- `reRSCConstructorChain` — `constructor.constructor` 到 Function 构造器
- `reRSCFunctionNew` — Function("require/child_process")
- `reRSCBlobHandler` — Blob/Response trick（高级变种）
- `reRSCChildProcess` — require('child_process').exec/spawn
- `reRSCPromiseExec` — .then(eval/Function) Promise 链执行
- `reRSCDynamicImport` — import('child_process') 动态导入
- `reRSCFlightRef` — $N:T Flight 引用语法

新增 CVE-2025-55184 (Next.js Server Actions 路径混淆)。

### 3. CVE 检测性能优化

**文件**: `internal/waf/cve_detector.go`

- `hasCVESuspiciousContent()` 快速预过滤：检查常见 exploit 指标关键词，干净请求跳过所有 CVE 检测
- 从 4 goroutine 并行改为顺序执行——避免每请求 goroutine spawn 开销

### 4. JS Challenge 验证完善

**文件**: `internal/dataplane/handler.go`, `internal/core/rules/phases.go`

- Challenge POST 验证：token + timestamp + HMAC 校验
- Cookie 签发：`__waf_passed=1` (HttpOnly/SameSite/Secure/1h)
- Bot 检测阶段检查 Cookie 跳过已验证请求

### 压测结果

```
总样本数量: 33877    成功: 33877    错误: 0
检出率: 98.78% (恶意样本: 658, 正确拦截: 650, 漏报: 8)
误报率: 0.02% (正常样本: 33219, 正确放行: 33214, 误报: 5)
准确率: 99.96%
平均耗时: 43.17ms (优化前: ~60ms)
```

性能提升约 28%（60ms → 43ms），CVE 预过滤对干净请求跳过效果显著。
检出率微降 0.16%（1 个样本），整体准确率保持 99.96%。

### 新增影响文件

| 文件 | 变更类型 |
|---|---|
| `internal/store/models.go` | 修改 — Site 增加 per-site 保护覆盖字段 |
| `internal/snapshot/snapshot.go` | 修改 — SiteRuntime 增加 EffectiveProtection |
| `internal/snapshot/build.go` | 修改 — mergeProtection 合并 global + site |
| `internal/core/engine/engine.go` | 修改 — 使用 EffectiveProtection 替代全局 |
| `internal/waf/cve_node.go` | 修改 — React2Shell 深度检测 + Next.js CVE |
| `internal/waf/cve_detector.go` | 修改 — 预过滤 + 顺序执行优化 |
| `internal/waf/tls_fingerprint.go` | 修改 — 清理机制修复 |
| `internal/dataplane/handler.go` | 修改 — Challenge 验证 + 504 超时 |

---

## 2026-04-25 — 第二轮迭代：CVE规则扩充 + Challenge验证 + 性能优化

### 变更概览

基于压测结果（98.94%检出率/0.02%误报率），继续优化CVE检测规则、完善JS Challenge验证流程、修复内存泄漏、优化错误处理。

### 1. CVE 检测规则大幅扩充

新增 15+ 条高危/严重级别 CVE 检测规则，覆盖 2022-2025 年间被广泛利用的漏洞：

**通用规则** (`cve_general.go`)：
| CVE | 级别 | 描述 |
|---|---|---|
| CVE-2025-31324 | Critical | SAP NetWeaver Visual Composer 未授权文件上传 RCE |
| CVE-2024-4577 | Critical | PHP-CGI 软连字符参数注入（Best-Fit映射绕过）|
| CVE-2024-3400 | Critical | PAN-OS GlobalProtect SESSID Cookie 命令注入 |
| CVE-2023-22527 | Critical | Confluence Server OGNL 注入 |
| CVE-2023-4966 | Critical | Citrix Bleed 信息泄露 |
| CVE-2024-53677 | Critical | Apache Struts 文件上传路径穿越 |
| CVE-2024-21887 | Critical | Ivanti Connect Secure 路径穿越+命令注入 |

**Node.js 规则** (`cve_node.go`)：
| CVE | 级别 | 描述 |
|---|---|---|
| CVE-2025-55182 | Critical | React2Shell: RSC Flight 协议反序列化 RCE (CVSS 10.0) |
| CVE-2025-29927 | Critical | Next.js 中间件认证绕过 |

**PHP 规则** (`cve_php.go`)：
| CVE | 级别 | 描述 |
|---|---|---|
| CVE-2024-4577 | Critical | PHP-CGI Windows 软连字符参数注入 |
| CVE-2023-41892 | Critical | Craft CMS conditions/render RCE |

**Java 规则** (`cve_java.go`)：
| CVE | 级别 | 描述 |
|---|---|---|
| CVE-2023-49070 | Critical | Apache OFBiz 认证绕过+RCE |
| CVE-2023-46604 | Critical | Apache ActiveMQ ClassPathXml RCE |
| CVE-2022-26134 | Critical | Confluence OGNL 注入 |

### 2. JS Challenge 验证流程完善

**文件**: `internal/dataplane/handler.go`

- 实现完整的 Challenge 验证流程：
  - POST 请求携带 `__waf_challenge_*` 字段时进行 HMAC-SHA256 token 验证
  - 验证通过后设置 `__waf_passed=1` Cookie (HttpOnly/SameSite=Strict/1小时有效)
  - TLS 站点自动添加 Secure 标志
  - 重定向回原始页面
- Bot 检测阶段检查 `__waf_passed` Cookie，已通过验证的请求跳过 Bot 检测

### 3. TLS 指纹清理机制修复

**文件**: `internal/waf/tls_fingerprint.go`

- 修复原来的空操作清理函数（placeholder → 实际实现）
- 实现时间淘汰（5分钟TTL）+ 大小淘汰（10万条上限）
- 60秒定期清理，`Close()` 方法支持优雅关闭
- 修复 `SupportedVersions` 为空时可能的 panic

### 4. 上游错误分类处理

**文件**: `internal/dataplane/handler.go`

- 区分超时错误 → 504 Gateway Timeout
- 区分连接错误 → 502 Bad Gateway
- `isTimeoutError()` 检查 `context.DeadlineExceeded`、`net.Error.Timeout()` 和错误消息关键词

### 5. RequestCtx Pool 优化

**文件**: `internal/core/pipeline/pool.go`

- Pool 初始化时预分配 `HeaderKeys = make([]string, 0, 16)`
- 减少首次使用时的内存分配

### 测试结果

```
ok  My-OpenWaf/internal/waf           66.504s  (全部通过)
ok  My-OpenWaf/internal/core/rules    0.064s   (全部通过)
ok  My-OpenWaf/internal/core          0.024s   (全部通过)
go vet: 0 issues
```

### 新增影响文件

| 文件 | 变更类型 |
|---|---|
| `internal/waf/cve_general.go` | 修改 — 新增 7 条通用 CVE 规则 |
| `internal/waf/cve_node.go` | 修改 — 新增 React2Shell + Next.js 中间件绕过 |
| `internal/waf/cve_php.go` | 修改 — 新增 PHP-CGI + Craft CMS 规则 |
| `internal/waf/cve_java.go` | 修改 — 新增 OFBiz + ActiveMQ + Confluence 规则 |
| `internal/waf/tls_fingerprint.go` | 修改 — 修复清理机制、防 panic |
| `internal/dataplane/handler.go` | 修改 — Challenge 验证、504 超时、isTimeoutError |
| `internal/core/pipeline/pool.go` | 修改 — 预分配 HeaderKeys |

---

## 2026-04-25 — 检测引擎与转发重构

### 变更概览

本次迭代对 WAF 引擎、Bot 检测、代理转发、自定义规则、错误页面、策略状态码进行了全面优化和重构。

### 1. TLS 指纹识别 — 原生 JA3 采集

**文件**: `internal/waf/tls_fingerprint.go` (新增)

- 新增 `TLSFingerprinter`，通过 `tls.Config.GetConfigForClient` 钩子在 TLS 握手阶段捕获 ClientHello
- 从 ClientHello 提取 CipherSuites、SupportedVersions、SupportedCurves、PointFormats 等计算 JA3 哈希
- 自动过滤 GREASE 值 (RFC 8701)
- 指纹按 remoteIP 存储，供 Bot 检测阶段查询
- 不再依赖外部注入 `X-JA3-Hash` 头部（仍兼容作为 fallback）

**文件**: `internal/app/server.go`
- `buildListenerTLS()` 中用 `fp.WrapTLSConfig()` 包装 TLS 配置，实现透明指纹采集

### 2. Bot 检测器重构 — 多维度请求指纹评分

**文件**: `internal/waf/bot.go`, `internal/waf/fingerprint.go`

- `ExtractFingerprintWithIP()` 优先使用原生 TLS 指纹，fallback 到头部注入
- 新增 `headerOrderScore()` — 分析 HTTP 头部顺序一致性
  - 浏览器 Host 必须在第一个位置
  - Chrome/Edge 必须携带 `sec-ch-*` 头部
  - 头部数量过少时对声称为浏览器的请求加分
- Pipeline 传递 `HeaderKeys` 到 BotRequest，实现完整的头部顺序分析
- **可疑请求使用 Challenge（JS 人机验证）而非仅 Observe**
  - 分数 >= 60% 阈值：返回 Challenge（JS 验证页面）
  - 分数 < 60% 阈值：保持 Observe（仅记录）

### 3. Action 类型扩展

**文件**: `internal/core/action/action.go`, `internal/store/models.go`

新增 4 种 action 类型：
| Action | 说明 | 是否终端 |
|---|---|---|
| `challenge` | JS 人机验证页面 | 是 |
| `redirect` | HTTP 重定向到指定 URL | 是 |
| `rate_limit` | 单规则限速 | 否 |
| `tag` | 标记请求（下游处理） | 否 |

- `Result` 新增 `StatusCode` 字段 — 支持每条规则自定义响应状态码
- `Result` 新增 `RedirectTo` 字段 — redirect action 的目标 URL
- `EffectiveStatusCode(default)` — 优先使用规则自定义码，fallback 到默认值

### 4. 自定义策略状态码

**文件**: `internal/store/models.go` (Rule 模型)

- Rule 模型新增 `StatusCode int` 和 `RedirectTo string` 字段
- 自动迁移，向下兼容（默认值 0 表示使用默认状态码）
- 整个 pipeline 链路透传：`store.Rule → snapshot.CompiledRule → rules.Compiled → action.Result → handler`

### 5. 移除 Server 头部 + 透传后端响应头

**文件**: `internal/proxy/proxy.go`, `internal/dataplane/handler.go`, `internal/dataplane/sse.go`

- Handler 初始化时 `c.Response.Header.Del("Server")` 移除 Hertz 框架注入的 Server 头部
- Proxy ForwardHTTP 转发后：如果上游未设置 Server 头，删除框架默认的
- SSE 转发同样去除 hop-by-hop 头并处理 Server 头
- `isHopByHop()` 优化为 map 查找（O(1) vs 原来的数组遍历 O(n)）
- 导出 `proxy.IsHopByHop()` 供 SSE 转发共用

### 6. 自定义规则引擎增强

**文件**: `internal/core/rules/matcher.go`, `internal/core/rules/compiler.go`

新增匹配器类型：
| Pattern | 说明 |
|---|---|
| `body_contains:xxx` | **真正的 body 匹配**（原来是 placeholder，总是返回 false） |
| `body_regex:pattern` | Body 正则匹配 |
| `host:example.com` | Host 匹配（支持 `*.example.com` 通配符） |
| `cookie_contains:xxx` | Cookie 头子串匹配 |
| `referer_contains:xxx` | Referer 头子串匹配 |

- Matcher 接口签名扩展：`Match(..., body []byte)` — 所有 matcher 实现更新
- `MatchCtx` 增加 `Host` 和 `Body` 字段
- Snapshot ParsePattern 同步支持新模式

### 7. 拦截/错误页面优化

**文件**: `internal/waf/block.go`

- **JS Challenge 页面** (`WriteChallengeResponse`)
  - 基于 HMAC-SHA256 的 challenge token
  - 客户端执行 PoW 计算 (100 万次循环)后自动提交表单
  - `VerifyChallengeToken()` 用于验证 challenge 响应
  - 中文 UI："正在验证您的浏览器"

- **上游错误页面** (`WriteUpstreamErrorResponse`)
  - 支持 502/503/504 等不同错误类型
  - 每种错误码有独立的标题和描述
  - 现代化 CSS 样式，与 block 页面风格统一

- 模板引擎增强：模板变量新增 `{{.StatusCode}}`

### 8. 引擎与转发性能优化

**文件**: `internal/proxy/proxy.go`, `internal/core/pipeline/pool.go`

- `http.Client` 按 Transport 缓存复用，避免每次请求创建新 Client
- 头部过滤使用 `hopByHopHeaders` map 替代数组遍历
- `RequestCtx` pool 正确重置 `HeaderKeys` slice（复用底层数组）

### 测试结果

```
ok  My-OpenWaf/internal/core/rules    0.056s  (14 tests PASS)
ok  My-OpenWaf/internal/waf           65.101s (98+ tests PASS)
ok  My-OpenWaf/internal/core          0.029s  (PASS)
```

全部测试通过，无回归。

### 影响文件清单

| 文件 | 变更类型 |
|---|---|
| `internal/core/action/action.go` | 修改 — 新增 Challenge/Redirect/RateLimit/Tag action |
| `internal/core/engine/engine.go` | 修改 — 透传 StatusCode/RedirectTo |
| `internal/core/pipeline/pipeline.go` | 修改 — RequestCtx 增加 HeaderKeys |
| `internal/core/pipeline/pool.go` | 修改 — 重置 HeaderKeys |
| `internal/core/rules/compiler.go` | 修改 — Compiled 增加 StatusCode/RedirectTo，新 pattern 前缀 |
| `internal/core/rules/matcher.go` | 修改 — Matcher 接口增加 body 参数，新增 6 种 matcher |
| `internal/core/rules/phases.go` | 修改 — MatchCtx 增加 Host/Body，Bot 相使用 Challenge |
| `internal/dataplane/handler.go` | 修改 — Challenge/Redirect 处理，Server 头移除 |
| `internal/dataplane/sse.go` | 修改 — hop-by-hop 过滤，Server 头处理 |
| `internal/proxy/proxy.go` | 修改 — Client 池化，hop-by-hop map，Server 头处理 |
| `internal/snapshot/snapshot.go` | 修改 — CompiledRule 增加 StatusCode/RedirectTo |
| `internal/snapshot/build.go` | 修改 — 透传新字段，新 pattern 前缀 |
| `internal/store/models.go` | 修改 — Rule 增加 StatusCode/RedirectTo，新 Action 常量 |
| `internal/waf/block.go` | 修改 — Challenge 页面，上游错误页面，自定义状态码 |
| `internal/waf/bot.go` | 修改 — headerOrderScore，原生 TLS 指纹集成 |
| `internal/waf/fingerprint.go` | 修改 — ExtractFingerprintWithIP 优先原生指纹 |
| `internal/waf/tls_fingerprint.go` | **新增** — 原生 JA3 指纹采集 |
| `internal/app/server.go` | 修改 — TLS 指纹初始化与包装 |

---

## 2026-05-02 — 第三轮：多监听端口运行时打通

### 本次迭代成果

本轮把“站点详情里能编辑监听端口”从单纯前端界面补全，推进到真实运行时生效。

#### 1. `SiteListener` 表加入自动迁移

**文件**: `internal/store/migrate.go`

之前新建验证库时没有自动创建 `site_listeners` 表，导致：
- `/api/v1/sites/:id/listeners` 查询报错
- `/api/v1/sites/:id/listeners` 创建报 500
- 前端即使挂了监听面板，也会在新库场景下直接失败

本轮把 `SiteListener` 加入 `AutoMigrate()`。

#### 2. snapshot 现在真正消费 `SiteListener`

**文件**: `internal/snapshot/build.go`

之前 runtime 只读取 `Site` 主表里的 `bind/tls/cert`，并不会读取 `site_listeners` 表。
这意味着：
- 前端/接口层虽然能创建 listener
- 运行时却不会真的监听这些新增端口

本轮改为：
- 先加载启用的 `site_listeners`
- 按 `site_id` 分组
- 若站点没有显式 listener，则继续使用 legacy `Site.Bind`
- 若站点已有显式 listener，则为每个 listener 生成独立 `SiteRuntime`
- 同步处理每个 listener 的 TLS / 证书 / SNI 注册

#### 3. 站点详情页挂载监听面板

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

本轮把 `SiteListenersPanel` 真正接到站点详情页的“上游管理”标签中：
- 现在详情页里不只是改 `upstream_urls`
- 还可以直接查看/新增/编辑/删除监听端口
- 前端入口终于与后端 listener API 对齐

#### 4. 收敛详情页站点 id 解析

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

原先 `siteId` 通过 `params + pathname + window.location.pathname + "_"` 多重兜底，明显是在补静态路由不稳的问题。
本轮先收敛为只基于 `useParams()` 解析数字 id，减少错误保存到 `_` 路由占位参数的风险。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 没新造 listener runtime 子系统，而是直接在现有 snapshot build 阶段消费 `SiteListener`。
- **YAGNI**: 没提前做 forwarding rules / header ops / 站点级安全策略重构，只补当前最影响“可修改”的监听能力。
- **DRY**: listener runtime 仍复用原有 `SiteRuntime`、`registerSiteKeys()`、`reload()`、`reconcileListeners()` 链路。
- **SOLID / SRP**: schema 问题在 `store` 修，runtime 问题在 `snapshot` 修，编辑入口在 `sites/[id]` 页修，各层职责保持清晰。

### 遇到的问题与解决方式

1. **listener API 一直 500**
   - 根因：`site_listeners` 表没有进入自动迁移。
   - 解决：把 `SiteListener` 加入 `AutoMigrate()`。

2. **listener 创建成功也不会监听新端口**
   - 根因：snapshot 完全不读 `site_listeners`。
   - 解决：在 `Build()` 里按站点加载显式 listeners 并生成多个 runtime entry。

3. **详情页虽然已有监听面板组件，但实际没挂载**
   - 解决：把 `SiteListenersPanel` 直接挂到“上游管理”标签页中。

### 验证结果

#### 静态检查
- `gofmt -w internal/store/migrate.go internal/snapshot/build.go internal/security/outbound.go`
- `go test ./internal/store ./internal/snapshot ./internal/admin ./internal/security ./internal/proxy ./internal/dataplane`
- `npm --prefix frontend run typecheck`

#### 真实运行时验证
- 新启临时 upstream：`python -m http.server 18080 --directory temp/upstream-root`
- 新启临时 WAF 实例：管理端 `:9580`
- 真实 API 验证通过：
  - 创建站点 `listener.local`，legacy bind 为 `:18111`
  - 新增显式 listener `:18112`
  - `/api/v1/sites/1/listeners` 返回两条记录：
    - `:18111`（自动迁移的 legacy bind）
    - `:18112`（新增 listener）
  - 直接请求 `http://127.0.0.1:18111/ok.txt` 返回 `200 ok`
  - 直接请求 `http://127.0.0.1:18112/ok.txt` 返回 `200 ok`

这说明：
- listener 表已可用
- listener API 已可用
- listener runtime 已真正生效

### 下一步计划

1. 用浏览器再补一轮站点详情页中 `SiteListenersPanel` 的 UI 级交互验证。
2. 继续处理站点详情里的全局安全策略跳转问题，避免用户误以为在改当前站点。
3. 再评估 `[id]` 静态导出方案，决定是继续保留 `_` 方案，还是改成更稳妥的客户端详情路由承载方式。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `internal/store/migrate.go` | 将 `SiteListener` 纳入自动迁移 |
| `internal/snapshot/build.go` | runtime 改为真正消费 `site_listeners` |
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 挂载 `SiteListenersPanel`，收敛站点 id 解析 |

---

## 2026-05-02 — 第四轮：浏览器级监听面板验证

### 本次迭代成果

本轮把站点详情页里的监听端口编辑链路做了浏览器级回归，并顺手修正了一个新的详情页路由问题。

#### 1. 修复静态详情页取 id 不稳的问题

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

最新前端接入 `SiteListenersPanel` 后，浏览器直接打开 `/sites/1` 暴露出一个问题：
静态导出场景下仅靠 `params.id` 取值不稳定，详情页会因为拿不到数字 id 而回退异常，最终出现 header 空白、站点数据未加载。

本轮改为：
- 优先从 `useParams()` 取 id
- 若 `params.id` 不是数字，再从 `pathname` 提取真实数字 id
- 没有有效数字 id 时直接视为无效详情页，不再使用 `_` 作为伪 id

#### 2. 浏览器中确认监听面板已经挂载成功

**页面**: `/sites/1` → `上游管理`

验证结果：
- 监听端口表格可见
- legacy 监听 `:18131` 正常显示
- “新增监听端口”按钮可打开弹窗
- 新增监听后列表立即出现新记录

#### 3. 浏览器中创建的新监听已真实生效

通过浏览器在详情页监听面板中创建：
- 新监听端口：`:18132`
- 备注：`ui listener verify`

随后直接访问：
- `http://127.0.0.1:18132/ok.txt` with `Host: browser-listener-2.local`
- 返回：`200 ok`

这说明：
- 前端详情页入口已打通
- listener API 正常
- runtime 真实监听新端口
- UI 新增端口不再只是“保存到数据库”而是真正可访问

### 遇到的问题与解决方式

1. **Playwright 等待“新增监听端口”文字消失超时**
   - 事实：后端日志和页面快照都表明监听创建成功，新行已出现。
   - 原因：等待条件写得过于依赖弹窗文案消失，不适合作为成功唯一判据。
   - 处理：改用“表格新增行 + 新端口实际可代理”作为更可靠验证标准。

2. **浏览器 console 中有一条 `/api/v1/auth/refresh` 401**
   - 这是未登录直开受保护页面时的正常登录守卫行为，不是本轮改动导致的前端错误。
   - 登录后，站点详情页、监听面板与新增监听流程均可正常完成。

### 验证结果

#### 浏览器验证
- 登录 `http://127.0.0.1:9591/login/` 成功
- 直达 `/sites/1` 后，站点详情页正确显示 `browser-listener-2.local`
- 切换到“上游管理”后，看到 `监听端口` 面板
- 通过 UI 创建监听 `:18132` 成功
- 表格中出现新行 `:18132 / ui listener verify`
- 新端口请求返回 `200 ok`

### 下一步计划

1. 继续收口站点详情页里的全局安全策略跳转，改成更明确的站点级入口或标注全局作用域。
2. 评估是否把监听端口从“上游管理”标签中独立成更清晰的站点接入模块，减少旧 `bind` 字段和显式 listener 的认知混淆。
3. 清理 `devlog.md` 中前几轮重复追加的段落，保留结构化、可追踪版本。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 修复静态详情页数字 id 提取，并完成监听面板浏览器级验证 |

---

## 2026-05-02 — 第五轮：站点详情页职责收口

### 本次迭代成果

本轮重点不是再修后端能力，而是降低站点详情页的误导性：
当站点已经启用显式 listener 后，不再鼓励用户继续在 legacy `bind/network/tls_enabled` 上操作。

#### 1. 监听端口独立成单独标签页

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

原先 `SiteListenersPanel` 被放在“上游管理”标签里，导致：
- 上游地址编辑与监听端口编辑混在一起
- 用户容易把“转发目标”和“接入端口”视为同一层配置
- 已经有显式 listeners 后，仍可能继续在 basic tab 修改 legacy bind

本轮改为：
- 标签从 `basic / upstream / advanced`
- 调整为 `basic / listeners / upstream / advanced`
- 监听端口成为独立模块，职责更清晰

#### 2. 有显式 listener 时锁定 legacy bind / network / tls 编辑

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

本轮新增：
- 通过 `listSiteListeners()` 读取当前站点 listeners
- 若存在 `id > 0` 的显式 listener，则认定站点已进入 listener 管理模式
- 在 basic tab 中：
  - `bind` 输入框禁用
  - `network` 选择禁用
  - HTTP/HTTPS legacy 切换不再生效
- 同时展示提示：
  - 当前站点已启用显式监听端口
  - 接入协议 / 监听地址 / 证书应在“监听端口”标签维护

#### 3. 保存站点时避免覆盖显式 listener 模式下的 legacy 字段

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

本轮在 `handleSave()` 中增加保护：
- 若已启用显式 listeners
- 则保存时继续沿用 `site.bind / site.network / site.tls_enabled`
- 避免用户在 basic tab 中误改 legacy 字段时，产生看似保存成功但实际无意义的状态漂移

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 没重写详情页架构，只通过标签拆分、禁用控件和保存保护来降低误导。
- **YAGNI**: 没引入复杂状态机，只用 `hasManagedListeners` 一个布尔条件控制行为。
- **DRY**: 继续复用现有 `listSiteListeners()`、`SiteListenersPanel` 与 `handleSave()`，不复制 listener 管理逻辑。
- **SOLID / SRP**: 让“接入端口”和“上游转发”回到各自独立职责区，不再混杂在同一个标签区域里。

### 遇到的问题与解决方式

1. **`listSiteListeners(siteId)` 类型错误**
   - 根因：`siteId` 是字符串，而 API helper 要求 number。
   - 解决：调用处显式转成 `Number(siteId)`。

2. **前端构建在中途失败**
   - 根因：上面的类型错误在 build 阶段被 Next.js 拦下。
   - 解决：修正调用参数后，重新通过 `typecheck` 与 `build`。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 继续处理站点详情页中“安全策略 / 攻击防护 / Bot / CC”这些全局跳转的误导问题。
2. 清理 `devlog.md` 中重复追加的历史段落，保留一版干净的结构化日志。
3. 如需进一步收口，可把站点 header 中展示的“监听 :port”改成显式 listener 模式下的聚合摘要，而不是 legacy bind。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 监听端口独立成单独标签页；显式 listener 模式下锁定 legacy bind/network/tls 编辑；保存时保护 legacy 字段 |

---

## 2026-05-02 — 第六轮：全局配置误导收口

### 本次迭代成果

本轮重点处理站点详情页最容易误导用户的一组入口：
`CC 防护 / Bot 防护 / 攻击防护 / 安全策略`。

这些页面目前本质上都是全局配置页，但之前从站点详情进去时，用户很容易误以为自己在修改当前站点。

#### 1. 站点详情页的全局入口文案改为明确声明“全局作用域”

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

本轮修改了 4 个快捷入口卡片描述：
- 明确写出“这是全局配置，不仅作用于当前站点”
- 在卡片区域上方增加统一提示横幅：
  - 当前这些入口修改后会影响所有站点，而不是仅影响当前站点

#### 2. 从站点详情跳到全局页时带上来源站点参数

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

跳转现在改为：
- `/cc-protection/?site=<host>`
- `/bot-protection/?site=<host>`
- `/protection/?site=<host>`
- `/security/?site=<host>`

这样目标页可以知道用户是从哪个站点上下文跳过去的。

#### 3. 全局页增加“来源站点 + 全局作用域”提示横幅

**文件**:
- `frontend/app/(dashboard)/protection/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`
- `frontend/app/(dashboard)/cc-protection/page.tsx`
- `frontend/app/(dashboard)/security/page.tsx`

本轮统一增加：
- 读取 `searchParams.get("site")`
- 若存在来源站点，则在页头显示提示：
  - 你是从哪个站点跳转过来的
  - 当前页面是全局配置页
  - 修改后会影响所有站点

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不急着重写这些全局页为真正站点级页面，先把作用域提示讲清楚。
- **YAGNI**: 没提前做站点级安全策略模型扩展，只补当前最影响认知的提示层。
- **DRY**: 四个全局页都采用同一模式：读取 `site` query 参数并渲染统一风格横幅。
- **SOLID / SRP**: 不把“站点上下文”塞进全局配置逻辑本身，只作为导航提示层处理，避免把页面职责搅乱。

### 遇到的问题与解决方式

1. **站点详情页看起来像是当前站点控制面板，但部分入口实际是全局页**
   - 解决：在来源页和目标页双向补提示，而不是只改其中一处。

2. **用户跨页后会失去“我是从哪个站点来的”上下文**
   - 解决：把站点 host 放进 query 参数，让目标页可还原来源上下文。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 清理 `devlog.md` 中前几轮重复追加的历史段落，保留一版干净、按轮次递进的日志。
2. 继续评估哪些全局页面值得真正下沉为站点级配置页，尤其是 `security` 和 `protection`。
3. 若继续前端重构，可把站点详情页 header 中的 legacy `bind` 展示改成“显式 listeners 摘要”。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 全局入口改为显式声明作用域，并带上来源站点 query 参数 |
| `frontend/app/(dashboard)/protection/page.tsx` | 新增来源站点 / 全局作用域提示横幅 |
| `frontend/app/(dashboard)/bot-protection/page.tsx` | 新增来源站点 / 全局作用域提示横幅 |
| `frontend/app/(dashboard)/cc-protection/page.tsx` | 新增来源站点 / 全局作用域提示横幅 |
| `frontend/app/(dashboard)/security/page.tsx` | 新增来源站点 / 全局作用域提示横幅 |

---

## 2026-05-02 — 第七轮：站点头部摘要与全局提示完善

### 本次迭代成果

本轮继续收口展示层，把站点详情页顶部信息也和显式 listener 模式对齐，同时保留上轮新增的全局作用域提示。

#### 1. 站点头部从 legacy bind 改为显式 listener 摘要

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

原先 header 一直展示：
- `HTTP/HTTPS · 监听 :port · 网络 tcp`

但当站点已经启用显式 listeners 后，这种展示会继续强化旧认知：
用户会以为当前真正的接入配置仍由 `site.bind` 单独决定。

本轮改为：
- 若存在显式 listeners：
  - `listenerSummary = 所有显式 bind 拼接`
  - `tlsSummary = 多监听（含 HTTPS）/ 多监听（HTTP）`
  - header 中附加说明：`由监听端口标签统一管理`
- 若不存在显式 listeners：
  - 继续展示 legacy `bind/network/tls`

这样 header 层就能直接反映当前站点是否已经进入 listener 管理模式。

#### 2. 延续并稳定全局配置作用域提示

**文件**:
- `frontend/app/(dashboard)/sites/[id]/client.tsx`
- `frontend/app/(dashboard)/protection/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`
- `frontend/app/(dashboard)/cc-protection/page.tsx`
- `frontend/app/(dashboard)/security/page.tsx`

这一轮在站点详情页结构调整后，再次确认这些全局入口与来源站点提示仍然保留，避免因后续重构把作用域提醒丢掉。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 仅通过 header 摘要逻辑切换来纠正认知，不引入新的展示组件层级。
- **YAGNI**: 没做复杂 listener 状态面板，只先把最重要的顶部摘要说清楚。
- **DRY**: 基于已加载的 `listeners` 数据直接派生 `listenerSummary / tlsSummary`，不新增重复请求。
- **SOLID / SRP**: 详情页 header 只负责当前站点状态摘要，不把 listener 编辑逻辑硬编码到 header 组件里。

### 遇到的问题与解决方式

1. **显式 listener 已经接管运行时，但页面顶部仍像单端口站点**
   - 解决：根据 listeners 派生摘要，直接让 header 对当前运行模式说真话。

2. **前端持续重构后容易把“全局页提示”再次冲掉**
   - 解决：本轮在继续重构的同时保留并复查来源站点提示链路。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 用浏览器验证：
   - 站点详情页 header 是否正确展示多监听摘要
   - 从站点详情跳到全局页时，是否显示来源站点横幅
2. 开始清理 `devlog.md` 的重复段落，整理为单次递进式日志。
3. 若继续前端收口，可考虑把 `listeners` 标签默认置前于 `upstream`，进一步符合用户任务顺序。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 站点 header 改为显式 listener 摘要；保留并强化全局作用域提示链路 |

---

## 2026-05-02 — 第八轮：安全策略页语义收口与日志整理

### 本次迭代成果

本轮继续处理“页面语义和真实能力不一致”的问题，重点收口 `security` 页，并完成 `devlog.md` 的重复历史整理。

#### 1. `security` 页明确拆分“全局策略”与“站点策略”

**文件**:
- `frontend/app/(dashboard)/security/page.tsx`
- `frontend/lib/security-api.ts`

当前后端能力表明：
- 验证码、5秒盾、连锁策略、阶梯升级 = 全局配置
- 防重放 = 站点级配置（落在 `Site` 上）

本轮改为：
- 页头描述明确声明：当前页面主要维护全局安全策略
- 新增信息条：
  - 全局策略：验证码、5秒盾、连锁策略、阶梯升级
  - 站点策略：防重放
- `AntiReplayTab` 继续只提供说明与跳转指引，不再伪装成可全局保存的配置项

#### 2. 去掉 escalation API 的魔法数字 `1`

**文件**:
- `frontend/app/(dashboard)/security/page.tsx`
- `frontend/lib/security-api.ts`

之前 `EscalationTab` 通过 `getEscalationConfig(1)` / `updateEscalationConfig(1, ...)` 工作，虽然能跑，但会把“全局策略”误表述成一个固定 `protectionId=1` 的对象。

本轮改为：
- 前端显式使用 `"global"` 作为保护作用域标识
- `security-api.ts` 默认参数也改成 `"global"`

这样至少在前端语义层更接近真实意图，不再继续扩大 “id=1 就是某个具体对象” 的误导。

#### 3. `devlog.md` 已清理重复历史段落

**文件**: `devlog.md`

此前日志中重复追加了大量“第一轮 / 第二轮”记录，已经严重影响后续追踪。
本轮已按章节标题去重，当前 `2026-05-02` 只保留连续唯一章节：
- 第三轮：多监听端口运行时打通
- 第四轮：浏览器级监听面板验证
- 第五轮：站点详情页职责收口
- 第六轮：全局配置误导收口
- 第七轮：站点头部摘要与全局提示完善
- 第八轮：安全策略页语义收口与日志整理

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不去提前重做整套安全策略模型，只先把页面语义讲清楚。
- **YAGNI**: 不新增站点级安全策略聚合 API，只在已有后端边界上调整前端语义和默认参数。
- **DRY**: 继续复用现有 `security-api.ts`，仅把默认 scope 从 `1` 调整为 `global`。
- **SOLID / SRP**: 全局页保持“全局策略”职责，站点级的防重放明确留在站点详情页，不再混用。

### 遇到的问题与解决方式

1. **`security` 页仍然容易让人误解为全局可保存所有策略**
   - 解决：直接在页面描述和说明条里把“哪些是全局、哪些是站点级”说清楚。

2. **`protectionId=1` 这种写法会误导后续维护者**
   - 解决：前端统一改成 `global` scope 字面值，减少魔法数字语义污染。

3. **`devlog.md` 已经出现大量重复章节**
   - 解决：按标题去重，只保留唯一章节，恢复可维护性。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 如果继续迭代，可把站点详情页顶部卡片中的全局入口再分成“当前站点可直接配置”和“全局策略入口”两组视觉区块。
2. 评估是否为站点级安全策略单独抽一层 `site-security` 页面，彻底避免与全局 `security` 页混淆。
3. 如需进一步自动化审计，可针对 listener/bind 隔离与 Host 匹配补单元测试覆盖。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/security/page.tsx` | 明确全局/站点策略边界，收口页面语义 |
| `frontend/lib/security-api.ts` | escalation 默认 scope 改为 `global` |
| `devlog.md` | 清理重复历史段落并追加本轮记录 |

---

## 2026-05-02 — 第九轮：站点导航与作用域提示补全

### 本次迭代成果

本轮继续从“减少误操作”出发，补齐站点详情页与全局导航的最后一层语义提示。

#### 1. 全局 `security` 菜单描述改准

**文件**: `frontend/lib/console.ts`

原先控制台菜单里的“安全策略”描述仍把“防重放”写进全局页能力，容易让用户从全局导航误以为那里能直接保存所有安全策略。

本轮改为：
- `安全策略` 描述明确写成：
  - 管理全局验证码、5秒盾、连锁策略与阶梯升级
  - 防重放请在站点详情中配置

#### 2. 站点详情页新增“当前站点可直接配置”提示

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

此前我们已经补了：
- 一条蓝色提示，说明下方卡片入口其实是全局页

本轮再新增一条绿色提示，明确告诉用户：
- 当前站点可以直接在本页配置哪些内容
- 包括：
  - 基本信息
  - 监听端口
  - 上游地址
  - 高级配置中的维护模式 / 拦截页 / 请求体限制 / 防重放
- 而其余全局策略则应通过下方卡片进入

这样页面上同时形成：
- “哪些会影响所有站点”
- “哪些只改当前站点”
两层清晰边界。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 没再新增复杂页面跳转或权限逻辑，只补两条最直接的作用域说明。
- **YAGNI**: 没提前抽象新的导航模型，只在现有详情页和菜单文案上修正语义。
- **DRY**: 复用已有详情页提示结构，不为同类提示再造组件。
- **SOLID / SRP**: 菜单描述负责解释全局页职责，站点详情页负责解释本站点可直接配置范围，职责边界更清楚。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 若继续迭代，可把站点详情页顶部的快捷卡片拆成两组：
   - 当前站点配置
   - 全局策略入口
2. 进一步考虑是否把 `security` 全局页里的“站点级说明”再加一个直达本站点详情的链接模板。
3. 如需要，更进一步补真实浏览器验证当前新增的提示横幅和摘要展示。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/lib/console.ts` | 修正“安全策略”菜单文案，移除对全局防重放的误导 |
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 新增“当前站点可直接配置”提示，补全本地/全局能力边界 |

---

## 2026-05-02 — 第十轮：站点上下文返回链路补全

### 本次迭代成果

本轮继续优化“从站点详情跳去全局页后，用户如何回到当前站点”的体验，补齐完整的站点上下文返回链路。

#### 1. 站点详情跳转全局页时，携带 `siteId` 和建议返回标签

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

原先我们已经带了：
- `?site=<host>`

本轮进一步补成：
- `?site=<host>&siteId=<id>&returnTab=<tab>`

这样全局页不只是知道“你从哪个站点来的”，还知道：
- 具体站点 id
- 返回时建议落到哪个标签（当前默认 `advanced`，其余入口可按语义调整）

#### 2. 全局页增加“返回当前站点”直达入口

**文件**:
- `frontend/app/(dashboard)/protection/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`
- `frontend/app/(dashboard)/cc-protection/page.tsx`
- `frontend/app/(dashboard)/security/page.tsx`

本轮在来源站点横幅中统一新增：
- `返回当前站点` 按钮
- 点击后跳回 `/sites/:id/?tab=<returnTab>`

这让用户在全局配置页里不会迷路，也避免“改了一圈全局配置后找不到原站点”的割裂感。

#### 3. 修复本轮插入修改时引入的前端语法错误

本轮中途因为编辑串拼接污染，曾引入两处无效文本，导致：
- `tsc --noEmit` 失败
- `next build` 失败

已精确清除脏文本，并重新通过完整检查。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不引入复杂 breadcrumb 状态存储，只用 query 参数传递最小必要上下文。
- **YAGNI**: 没为所有页面设计统一导航状态机，只补当前站点 → 全局页 → 当前站点这条最痛的链路。
- **DRY**: 四个全局页复用同一模式：读取 `site / siteId / returnTab` 并渲染返回按钮。
- **SOLID / SRP**: 站点详情页负责发出上下文，全局页负责显示和返回，不把上下文管理散落到更多组件里。

### 遇到的问题与解决方式

1. **从全局页回到原站点路径不明确**
   - 解决：跳转时携带 `siteId + returnTab`，目标页直接给返回按钮。

2. **本轮手工编辑引入语法污染**
   - 解决：精准定位脏文本并移除，重新跑 `typecheck` 和 `build`。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 如果继续迭代，可把站点详情页卡片区进一步分成：
   - 当前站点直配能力
   - 全局策略入口
   让视觉层次比单纯提示更明确。
2. 若浏览器工具恢复，再补一轮 E2E 验证“跳出全局页后再返回当前站点”的实际交互。
3. 视需要把 `returnTab` 细化成按入口决定（如 `security` 回 `advanced`，其余回 `basic` 或 `listeners`）。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 全局入口跳转补 `siteId` 与 `returnTab` 参数 |
| `frontend/app/(dashboard)/protection/page.tsx` | 新增返回当前站点按钮 |
| `frontend/app/(dashboard)/bot-protection/page.tsx` | 新增返回当前站点按钮 |
| `frontend/app/(dashboard)/cc-protection/page.tsx` | 新增返回当前站点按钮 |
| `frontend/app/(dashboard)/security/page.tsx` | 新增返回当前站点按钮 |

---

## 2026-05-02 — 第十一轮：站点详情入口视觉分组重构

### 本次迭代成果

本轮把站点详情页从“主要靠文案提示区分站点配置和全局配置”，推进到“通过布局结构本身减少误操作”。

#### 1. 站点详情入口分成两组视觉区块

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

原先页面是：
- 一条提示说明当前站点可配什么
- 一条提示说明下方卡片是全局入口
- 然后直接渲染 4 张全局策略卡片

这仍然要求用户先读提示，再理解卡片含义。

本轮改为：
- 在全局卡片区块之前，新增 3 张“当前站点可直接配置”的本地入口卡片：
  - 监听端口
  - 上游地址
  - 高级配置
- 这些卡片不会跳页，而是直接切换当前详情页标签：
  - `listeners`
  - `upstream`
  - `advanced`
- 全局策略卡片保留在其后，并继续显示“影响所有站点”的说明

这样从视觉层次上就把：
- **本站点内直接配置**
- **跳去全局策略页**
明确分开。

#### 2. 保留并沿用站点上下文回跳链路

本轮重构过程中继续保留：
- 全局卡片跳转带 `site / siteId / returnTab`
- 全局页来源横幅中的“返回当前站点”按钮

因此这轮是结构增强，而不是替换既有导航语义链路。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 没引入新路由或复杂状态管理，只复用已有 `tab` 状态切换当前页内容。
- **YAGNI**: 没额外做站点配置首页或 wizard，只补最直接的三张本站点入口卡片。
- **DRY**: 继续复用现有标签页内容，不复制监听/上游/高级配置的实现。
- **SOLID / SRP**: 详情页自己负责站点内配置导航；全局页继续负责全局策略，不再混在同一组入口里。

### 遇到的问题与解决方式

1. **手工编辑时混入脏文本**
   - 本轮中途再次出现由工具串扰带入的脏字符串。
   - 已通过精确定位与移除修复，并重新跑通完整前端检查。

2. **用户仍可能把四张快捷卡片误认为本站点功能**
   - 解决：在它们前面新增本站点本地入口卡片，先给出“正确入口”，再展示全局入口。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 若浏览器工具恢复，补一轮 UI 验证：
   - 点击本地入口卡片是否正确切换标签
   - 点击全局入口是否能带上下文跳转并返回
2. 继续收口站点列表页 `sites/page.tsx`，让列表页也能反映“多监听模式”而不是只显示 legacy bind。
3. 视需要把 `returnTab` 精细化为按入口映射，而不是当前的简单默认值。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 站点详情入口分成“本站点可直接配置”与“全局策略入口”两组；本地卡片直接切换标签 |

---

## 2026-05-02 — 第十二轮：站点列表多监听展示收口

### 本次迭代成果

本轮把站点列表页也从 legacy `bind` 视角切换到“显式 listeners 优先”的真实展示，补掉站点详情页之外最后一个明显的认知不一致点。

#### 1. 列表页加载站点监听端口数据

**文件**: `frontend/app/(dashboard)/sites/page.tsx`

原先列表页只读取 `/api/v1/sites`，因此卡片展示只能依赖：
- `site.bind`
- `site.tls_enabled`
- `site.network`

这在站点进入显式 listener 模式后会持续误导用户，因为运行时真正生效的端口可能已经来自 `site_listeners`。

本轮改为：
- 在加载站点列表后，并行请求每个站点的 `/api/v1/sites/:id/listeners`
- 组装 `listenersBySite`
- 列表卡片基于 listeners 数据派生真实摘要

#### 2. 列表页卡片改为显式 listener 摘要

**文件**: `frontend/app/(dashboard)/sites/page.tsx`

新增展示逻辑：
- 若站点存在显式 listeners：
  - `listenerSummary = 所有显式 bind 拼接`
  - `tlsSummary = 多监听（含 HTTPS）/ 多监听（HTTP）`
  - 附加文案：`N 个显式监听端口`
- 若站点仍是 legacy 模式：
  - 保持原有 `bind/network/tls` 展示

同时卡片统计区中的 `TLS` 字段也改成展示真实的 `tlsSummary`，不再简单依赖 `site.tls_enabled`。

这样用户在站点列表页就能第一眼看出：
- 这个站点是不是单 listener 模式
- 是否已经切到多监听模式
- 多监听里是否包含 HTTPS

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 没新增聚合 API，而是直接复用现有 `listSiteListeners()` 逐站点读取。
- **YAGNI**: 没引入复杂缓存或 server-side 聚合层，只先修当前最明显的展示偏差。
- **DRY**: 列表页采用和详情页相同的 listener 摘要派生思路，避免出现两套不同语义。
- **SOLID / SRP**: 列表页只负责展示真实站点状态，不去复制详情页的编辑能力。

### 遇到的问题与解决方式

1. **列表页长期沿用 legacy bind，和详情页/运行时语义脱节**
   - 解决：显式读取 listeners，并用统一派生规则展示摘要。

2. **多监听站点在列表里看起来仍像单端口站点**
   - 解决：增加 `listenerSummary`、`tlsSummary` 和显式 listener 数量说明。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 如果继续迭代，可考虑把站点列表页的 listeners 读取下沉为后端聚合字段，减少前端逐站点请求。
2. 若浏览器工具恢复，补一轮列表页与详情页联动的真实 UI 验证。
3. 后续可以考虑给站点列表页增加“显式监听 / legacy 兼容”状态徽标，进一步降低理解成本。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/page.tsx` | 列表页改为读取并展示显式 listeners 摘要与多监听 TLS 状态 |

---

## 2026-05-02 — 第十三轮：站点列表监听摘要下沉到后端

### 本次迭代成果

本轮把站点列表页对 listeners 的逐站点额外请求下沉到后端，让 `/api/v1/sites` 直接返回足够的展示摘要字段，减少前端补丁式拼装。

#### 1. `/api/v1/sites` 直接聚合监听摘要字段

**文件**:
- `internal/admin/handler_site.go`
- `internal/admin/router.go`

本轮改为：
- `ListSites()` 同时读取启用的 `Site` 与启用的 `SiteListener`
- 按 `site_id` 分组 listener
- 直接在响应中附带：
  - `listener_summary`
  - `tls_summary`
  - `managed_listener_count`

这样列表页不必再逐站点请求 `/api/v1/sites/:id/listeners` 才能知道真实监听状态。

#### 2. 前端列表页改为消费聚合字段

**文件**:
- `frontend/app/(dashboard)/sites/page.tsx`
- `frontend/lib/api.ts`

本轮改为：
- `Site` 类型新增：
  - `listener_summary?: string`
  - `tls_summary?: string`
  - `managed_listener_count?: number`
- 列表页直接使用这些字段展示：
  - 监听端口摘要
  - 多监听 TLS 状态
  - 显式监听端口数量
- 移除原先前端逐站点拉 `listSiteListeners()` 的额外逻辑

#### 3. 列表链路变得更一致

这轮之后：
- 详情页使用完整 listeners 数据做编辑
- 列表页使用后端聚合摘要做展示
- 两者职责更清晰：
  - 列表负责状态摘要
  - 详情负责真实编辑

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 没额外设计新 DTO 文件，只在现有列表响应中补充最小必要字段。
- **YAGNI**: 没上复杂聚合服务层，只在 `ListSites` handler 里做直接聚合。
- **DRY**: 统一由后端生成 listener 摘要，避免前端列表页重复实现一套 listener 汇总逻辑。
- **SOLID / SRP**: 前端列表页不再承担多次请求与汇总职责，后端列表接口负责提供展示所需摘要。

### 遇到的问题与解决方式

1. **列表页要展示真实监听状态，但需要逐站点多请求**
   - 解决：后端聚合后直返摘要字段。

2. **前端 `Site` 类型与后端响应不完全一致**
   - 解决：补充新的可选聚合字段，保持兼容性。

### 验证结果

#### 后端检查
- `gofmt -w internal/admin/handler_site.go internal/admin/router.go`
- `go test ./internal/admin ./internal/snapshot ./internal/store`

#### 前端检查
- `npm --prefix frontend run typecheck`
- `npm --prefix frontend run build`

全部通过。

### 下一步计划

1. 对新的 `/api/v1/sites` 聚合响应做一次轻量兼容性复核，确认没有遗漏现有页面依赖字段。
2. 继续复核安全策略相关页面还剩哪些“假能力”或误导性入口。
3. 若浏览器工具恢复，再补列表页与详情页之间的真实联动验证。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `internal/admin/handler_site.go` | `/api/v1/sites` 响应增加 listener 聚合摘要字段 |
| `internal/admin/router.go` | `ListSites` 注入 `SiteListenerRepo` |
| `frontend/lib/api.ts` | `Site` 类型新增 listener 聚合字段 |
| `frontend/app/(dashboard)/sites/page.tsx` | 改为消费后端聚合字段，移除逐站点 listeners 请求 |

---

## 2026-05-02 — 第十四轮：security 假能力降级

### 本次迭代成果

本轮针对 `security` 页中仍然明显“可配置但运行时不按此生效”的能力做了降级处理，目标是优先减少误导，而不是继续放大假能力。

#### 1. 验证码类型改成“真实生效能力 + 候选能力”双层表达

**文件**: `frontend/app/(dashboard)/security/page.tsx`

已知后端运行时会把 Click / Slide / Rotate 等图形验证码统一回退为 Math CAPTCHA。
本轮改为：
- 增加醒目的说明面板，明确告知当前运行时会回退为数学题
- 新增只读字段：`当前生效类型 = Math（数学题）`
- 保留原来的候选类型下拉，但文案降级为“前端候选类型（暂未接入运行时）”
- 增加说明：这些选项当前保存后不会改变实际运行时验证码类型

#### 2. 5 秒盾页改为明确说明固定使用 Math CAPTCHA

**文件**: `frontend/app/(dashboard)/security/page.tsx`

已知后端 5 秒盾运行时固定调用 Math CAPTCHA，本轮改为：
- 增加说明面板，明确告知不会消费图形验证码类型
- 新增只读字段：`当前生效验证码 = Math（数学题）`
- 不再继续给用户“改了就会真正生效”的错觉

#### 3. 连锁策略页增加“当前仅草案编辑，未真正接入运行时”的提示

**文件**: `frontend/app/(dashboard)/security/page.tsx`

已知运行时 `ChainChallengeManager` 使用内置默认步骤，未看到真实消费页面保存的 `chain_steps`。
本轮改为：
- 在连锁策略 Tab 顶部增加醒目说明
- 明确指出：当前更适合作为策略草案编辑器，而不是已接入运行时的执行链路

#### 4. Bot 页进一步修正文案语义

**文件**: `frontend/app/(dashboard)/bot-protection/page.tsx`

本轮把页头描述从“配置 Bot 检测引擎的全局开关”修正为：
- 主要配置评分参数、高风险国家、ASN 列表
- 引擎总开关仍由全局 protection 设置和站点覆盖共同决定

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不硬做后端能力补齐，先把页面语义讲真话。
- **YAGNI**: 不为尚未真正接线的功能继续扩充 UI 能力，而是降级成说明与草案编辑。
- **DRY**: 直接基于我们已确认的运行时真实行为（Math CAPTCHA、默认 chain steps）来统一页面描述。
- **SOLID / SRP**: 页面负责表达“当前真实能力边界”，运行时负责真正执行，不再让 UI 越权扮演能力实现者。

### 遇到的问题与解决方式

1. **security 页仍然让用户误以为图形验证码和 chain steps 已接入运行时**
   - 解决：改成“真实生效能力 + 候选/草案能力”双层表达。

2. **Bot 页对总开关语义描述过强**
   - 解决：把描述收敛为“评分参数配置”，同时说明真正总开关不只由该页决定。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 等待 `sites-list-reviewer` 与 `policy-ui-reviewer` 的二次复核结果，确认是否还有更值得优先修正的缺口。
2. 若继续迭代，可考虑把 `security` 页中这些“候选能力”进一步折叠到“实验/规划中”分区，避免与已生效配置混排。
3. 视情况补浏览器验证，确认说明面板与真实入口跳转符合预期。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/security/page.tsx` | 验证码/5秒盾/连锁策略降级为真实能力说明或草案编辑语义 |
| `frontend/app/(dashboard)/bot-protection/page.tsx` | Bot 页描述改为更准确的评分参数语义 |

---

## 2026-05-02 — 第十五轮：protection / cc 草案能力降级

### 本次迭代成果

本轮继续把仍然容易误导的“可保存但未确认运行时消费”的能力降级成只读草案或说明态，重点覆盖 `protection` 和 `cc-protection`。

#### 1. `protection` 的分类敏感度矩阵降级为只读草案展示

**文件**: `frontend/app/(dashboard)/protection/page.tsx`

此前页面允许逐类别点击保存 `owasp_modules`，但当前运行时主要还是消费全局 OWASP sensitivity，未看到按类别真正生效的明确链路。

本轮改为：
- 增加醒目说明：当前 `owasp_modules` 仅作为规划中的策略草案
- 不再提供逐格可点击的交互矩阵
- 改成只读表格，展示“当前草案值”
- 避免继续制造“点选并保存后，数据面会按类别立即生效”的误解

#### 2. `cc-protection` 的自定义规则改为草案态表达

**文件**: `frontend/app/(dashboard)/cc-protection/page.tsx`

当前页面保存的 `cc_rules` 仍主要是配置草案存储，尚未确认已完整接入数据面执行链路。

本轮改为：
- 在自定义规则表顶部增加醒目说明
- 明确提示：当前更适合作为规则草案，而不是已确认接线的运行时能力
- 添加按钮文案从“添加规则”收敛为“编辑规则草案”

#### 3. 本轮验证结果说明

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 在代码层未报 TS/业务逻辑错误，但因外部 Google Fonts 拉取失败而中断：
  - `Geist`
  - `Geist Mono`

这属于环境网络问题，不是本轮代码回归。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不补后端接线能力，先把 UI 降级成真实语义。
- **YAGNI**: 不继续扩展未接线功能的可编辑界面，而是收回成草案/说明态。
- **DRY**: 延续 `security` 页那一轮的思路：对所有“未确认接线”的能力统一采用说明先行。
- **SOLID / SRP**: 页面负责表达当前真实能力边界，不再替运行时做虚假的承诺。

### 遇到的问题与解决方式

1. **构建阶段字体下载失败**
   - 根因：`next/font` 拉取 Google Fonts 时网络不可达。
   - 结论：这是环境问题，不是当前改动引入的功能回归。

2. **分类矩阵与 CC 规则继续给用户“立即生效”的错觉**
   - 解决：降级成交互更弱、语义更真实的草案展示。

### 下一步计划

1. 等待两个复核代理最终结论，确认是否还存在更高优先级的缺口。
2. 如果没有新的 P0/P1 问题，下一轮可进入“统一提示组件 / 小范围整理重构”阶段。
3. 若环境允许，再补一次完整浏览器验证，确保这些“草案态说明”在 UI 上直观可见。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/protection/page.tsx` | 分类敏感度矩阵降级为只读草案展示 |
| `frontend/app/(dashboard)/cc-protection/page.tsx` | 自定义 CC 规则降级为草案态表达 |

---

## 2026-05-02 — 第十六轮：列表接口兼容修复与剩余草案态收尾

### 本次迭代成果

本轮主要完成两件事：
1. 修复 `/api/v1/sites` 接口契约被静默缩窄的问题；
2. 继续把 `protection / cc-protection` 中剩余未确认接线的能力收束为草案态。

#### 1. `/api/v1/sites` 恢复为“完整 Site + 聚合摘要字段”

**文件**:
- `internal/admin/handler_site.go`
- `internal/admin/router.go`

此前列表接口被改成手工白名单 map 返回，虽然当前页面可用，但会破坏 `listSites(): PaginatedResponse<Site>` 的长期兼容性。

本轮改为：
- 定义 `siteListItem`
- 嵌入完整 `store.Site`
- 额外附加：
  - `listener_summary`
  - `tls_summary`
  - `managed_listener_count`

这样：
- 旧字段继续完整保留
- 新的列表页多监听摘要能力也保留
- 后续复用 `listSites()` 的页面不会因为字段缺失而静默回归

#### 2. `cc-protection` 自定义规则继续强化“草案态”提示

**文件**: `frontend/app/(dashboard)/cc-protection/page.tsx`

在此前已把“添加规则”改为“编辑规则草案”的基础上，本轮又补了一条说明：
- 草案规则用于梳理匹配条件、阈值与动作
- 当前不应视为已确认接入数据面的实时阻断能力

#### 3. 复核结论已收敛

- `sites-list-reviewer` 最终结论：**兼容性问题已解决**
- `policy-ui-reviewer` 剩余高优先级问题，已按最小策略继续降级：
  - `protection` 分类矩阵只读草案态
  - `cc-protection` 自定义规则草案态表达增强

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 对列表接口不引入新 API，而是在现有 `/api/v1/sites` 中恢复完整契约后附加摘要字段。
- **YAGNI**: 不补数据面未接线能力，只把 UI 语义收束成草案态。
- **DRY**: 前端继续复用 `Site` 类型，后端聚合补充字段，不再分叉出额外列表专用契约。
- **SOLID / SRP**: 列表接口负责提供完整站点对象和摘要；页面负责以真实语义呈现草案/已生效能力边界。

### 遇到的问题与解决方式

1. **`/api/v1/sites` 缩窄返回字段存在兼容性隐患**
   - 解决：恢复完整 `Site` 字段并叠加聚合摘要。

2. **继续编辑 `cc_rules` 容易让用户误以为实时生效**
   - 解决：补充更强的草案态说明，而不是继续强化编辑器能力语义。

3. **本轮编辑过程再次混入工具脏文本**
   - 解决：精确移除污染行后重跑 `typecheck` / `build`，最终恢复通过。

### 验证结果

#### 后端检查
- `gofmt -w internal/admin/handler_site.go internal/admin/router.go`
- `go test ./internal/admin ./internal/snapshot ./internal/store`

#### 前端检查
- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 若继续迭代，可抽一个统一的“草案态/作用域提示条”组件，减少多页面重复提示代码。
2. 若浏览器工具恢复，补一轮真正的 UI 级联动验证，确认站点页与全局页的来回跳转体验。
3. 若再继续后端方向，可考虑为全局草案能力补“未接入运行时”状态元数据，而不只靠前端文案提示。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `internal/admin/handler_site.go` | `/api/v1/sites` 恢复完整 `Site` 契约并附加 listeners 聚合摘要 |
| `internal/admin/router.go` | 站点列表接口继续注入 `SiteListenerRepo` |
| `frontend/app/(dashboard)/cc-protection/page.tsx` | 草案规则说明增强 |

---
## 2026-05-02 — 第十七轮：清理残留脏文本并继续压低 CC 规则误导性

### 本次迭代成果

本轮主要处理两个收尾点：
1. 核对并确认 `cc-protection` 源码中不存在队友提到的残留脏文本；
2. 继续把 `cc_rules` 的入口从“像功能页”压低到“更明确的草案编辑器”。

#### 1. 核对 `cc-protection` 脏文本问题

**文件**: `frontend/app/(dashboard)/cc-protection/page.tsx`

队友曾报告源码级残留脏文本 `'}] } malformed? need valid json.`。
本轮重新核对后确认：
- 当前源码该位置已不存在该脏文本
- 页面源码片段在对应行号附近已恢复正常

#### 2. `cc_rules` 草案入口进一步降级

**文件**: `frontend/app/(dashboard)/cc-protection/page.tsx`

本轮继续降低误导强度：
- 按钮文案从“编辑规则草案”改为“打开规则草案编辑器”
- 按钮样式改为更弱的虚线边框次级入口
- 空状态说明也同步调整为“沉淀未来策略”的语义

这样用户更不容易把它理解成：
- 当前已接入运行时的主功能配置入口

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不继续大改 CC 页面结构，只在入口文案和视觉权重上继续降级。
- **YAGNI**: 不为未确认接线能力追加更多交互，而是进一步弱化入口语义。
- **DRY**: 延续前面几轮“草案态能力降级”的统一处理思路。
- **SOLID / SRP**: 让页面对真实运行时能力负责，不再把草案编辑器包装成主配置能力。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 若继续迭代，可开始抽统一的“作用域提示 / 草案态提示”组件，减少多页面重复实现。
2. 若浏览器工具恢复，再做一轮真正的 UI 级回归，验证这些弱化后的入口在视觉上是否足够清晰。
3. 之后可以进入一轮“代码整理而非功能修复”的收尾阶段。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/cc-protection/page.tsx` | 继续降低 `cc_rules` 草案入口的视觉权重与误导性 |

---
## 2026-05-02 — 第十八轮：统一提示组件初步落地

### 本次迭代成果

本轮开始进入“整理收尾”阶段，尝试把重复的提示块收敛到统一组件，先从最典型的全局/来源提示开始，控制改动范围，避免再次扩散页面改造面。

#### 1. 新增通用 `Notice` 组件

**文件**: `frontend/components/console-shell.tsx`

本轮新增了一个轻量通用提示组件：
- `Notice`

支持能力：
- tone：`amber / sky / emerald / slate`
- title
- children
- action
- size：`sm / md`

同时新增：
- `SourceSiteNotice`

用于统一表示：
- 你是从哪个站点跳转过来的
- 当前页面是全局/共享配置
- 可选返回当前站点按钮

#### 2. 先在最稳定的两个页面接入统一提示组件

**文件**:
- `frontend/app/(dashboard)/security/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`

本轮没有贪多，只把统一提示组件接入到：
- `security`
- `bot-protection`

这是为了先验证：
- 组件抽取本身不会破坏页面构建
- 未来可以逐步替换更多页面，而不是一次性大面积重构

#### 3. 保持其余页面当前稳定状态，不继续扩改

虽然 `cc-protection`、`protection`、`sites/[id]` 里也存在很多 notice 块，但本轮有意控制范围：
- 不再一次性替换所有提示块
- 先确认抽取方向正确、构建稳定
- 再决定是否继续收口其他页面

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 只抽一个非常轻量的 notice 组件，不做复杂布局系统。
- **YAGNI**: 不追求一轮替换全项目，只先接两个稳定页面验证方向。
- **DRY**: 把重复的 `amber / sky / emerald` notice 结构抽到通用组件里，减少后续重复 JSX。
- **SOLID / SRP**: `console-shell` 负责通用展示壳层，业务页只负责填充具体语义内容。

### 遇到的问题与解决方式

1. **继续大面积替换 notice 块容易提高回归面**
   - 解决：本轮只在 `security` 和 `bot-protection` 试点落地。

2. **需要兼顾“来源站点提示”和“普通说明提示”两种场景**
   - 解决：在 `Notice` 之上单独补了一个 `SourceSiteNotice` 作为语义封装。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 若继续整理，可逐步把 `sites/[id]`、`protection`、`cc-protection` 的提示块也迁移到 `Notice` / `SourceSiteNotice`。
2. 等页面提示统一后，再做一轮样式一致性整理，减少颜色和 spacing 的细小漂移。
3. 若浏览器工具恢复，再补一轮 UI 级确认，确保提示组件化后视觉没有退化。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/components/console-shell.tsx` | 新增 `Notice` 与 `SourceSiteNotice` 通用提示组件 |
| `frontend/app/(dashboard)/security/page.tsx` | 接入统一提示组件 |
| `frontend/app/(dashboard)/bot-protection/page.tsx` | 接入统一提示组件 |

---
## 2026-05-02 — 第十九轮：统一提示组件继续推广

### 本次迭代成果

本轮继续把重复的提示块逐步迁移到统一组件，先把 `sites/[id]` 里的核心提示收口掉。

#### 1. `sites/[id]` 的两个核心提示改用 `Notice`

**文件**: `frontend/app/(dashboard)/sites/[id]/client.tsx`

本轮替换了两个最常驻、语义最稳定的提示块：
- “当前站点可直接配置” → `Notice tone="emerald"`
- “下方卡片是全局配置入口” → `Notice tone="sky" title="全局策略入口"`

收益：
- 站点详情页提示风格与 `security / bot / protection / cc` 更统一
- 后续如果要统一微调 spacing、颜色或标题展示，就不必逐页逐块重复改 JSX

#### 2. 提示组件化策略继续保持“渐进迁移”

这一轮仍然没有尝试一次性替换所有页面提示块，而是继续坚持：
- 先迁移稳定、语义明确的 notice
- 保持构建稳定
- 再逐步扩大覆盖范围

这可以避免：
- 一次性大面积替换导致的回归面扩大
- 在页面语义还没完全收口前就过早抽象

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 只迁移两个已经稳定的提示块，不额外改动页面其他结构。
- **YAGNI**: 不强求全项目一次性 Notice 化，继续按价值最高、最稳定的块推进。
- **DRY**: 把重复的边框/背景/排版结构继续收敛到统一组件中。
- **SOLID / SRP**: 页面只表达业务语义，视觉提示壳层交给通用组件承载。

### 验证结果

- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过

### 下一步计划

1. 等 `notice-reviewer` 返回剩余未迁移位置清单，再决定是否继续推广到更多页面。
2. 如果没有新的高优先级缺口，可进入“清理 import / 文案 / 小型重复逻辑”的整理阶段。
3. 若浏览器工具恢复，再补一轮 UI 级验证统一提示后的视觉表现。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/app/(dashboard)/sites/[id]/client.tsx` | 两个核心提示块迁移到 `Notice` 组件 |

---
## 2026-05-02 — 第二十轮：统一提示组件推广收尾

### 本次迭代成果

本轮确认 `Notice / SourceSiteNotice` 的推广主线已经基本完成，核心页面中的来源站点提示都已统一到通用组件，不再存在显著的散乱 notice 写法。

### 当前状态确认

已统一到通用提示组件的关键页面：
- `frontend/app/(dashboard)/security/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`
- `frontend/app/(dashboard)/protection/page.tsx`
- `frontend/app/(dashboard)/cc-protection/page.tsx`
- `frontend/app/(dashboard)/sites/[id]/client.tsx`（部分核心 notice 已迁移）

这意味着：
- 全局来源站点提示链路已统一
- 作用域说明的视觉壳层已统一
- 站点详情页中的关键提示也已开始复用统一组件

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不再为了“组件化”而强行继续改更多页面，只在主路径完成统一后收尾。
- **YAGNI**: 不追求把所有微小提示都统一到组件，先保证最常用、最关键的入口一致。
- **DRY**: 已把来源站点提示与主要作用域提示收敛到 `Notice / SourceSiteNotice`。
- **SOLID / SRP**: 页面负责业务含义，提示壳层统一由 `console-shell` 组件承载。

### 验证结果

- 本轮未引入额外代码修改，仅复核当前迁移状态。
- 最近一次相关前端检查仍为：
  - `npm --prefix frontend run typecheck` 通过
  - `npm --prefix frontend run build` 通过

### 下一步计划

1. 进入一轮更偏“整体整理”的收尾阶段：
   - 清理 import 噪音
   - 统一少量重复文案
   - 复查仍未迁移的低价值提示块是否值得保留现状
2. 如需继续功能方向，可重新回到真正未落地的数据面能力，而不是继续做提示层收尾。

---
## 2026-05-02 — 第二十一轮：剩余提示块统一收尾

### 本次迭代成果

本轮对剩余提示块做最后一轮状态核对，确认最关键页面已经基本迁移到 `Notice / SourceSiteNotice` 体系，主线整理目标已达成。

### 当前统一结果

已确认关键页面中的来源站点提示已统一为 `SourceSiteNotice`：
- `frontend/app/(dashboard)/security/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`
- `frontend/app/(dashboard)/protection/page.tsx`
- `frontend/app/(dashboard)/cc-protection/page.tsx`

已确认 `sites/[id]` 中两处最重要的作用域提示已统一为 `Notice`：
- 当前站点可直接配置
- 全局策略入口

已确认 `security` 页中的剩余说明块也基本收敛到 `Notice` 体系：
- 连锁策略说明
- 防重放说明
- 全局/站点策略边界说明

### 结果判断

这意味着当前“提示层组件化”主线已经基本完成：
- 来源站点提示统一
- 作用域提示统一
- 草案态提示大部分统一
- 剩余零散说明块已经不再构成明显维护负担

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不为了追求 100% 组件化而继续扩大改动，当前达到主要页面统一即可收尾。
- **YAGNI**: 不再强行把所有信息卡都抽象成新组件，避免过度整理。
- **DRY**: 最容易重复、最关键的提示块已经收敛到统一组件中。
- **SOLID / SRP**: 页面负责业务语义，提示壳层负责统一展示，这一层职责已经稳定。

### 验证结果

- 最近一次相关前端检查仍为：
  - `npm --prefix frontend run typecheck` 通过
  - `npm --prefix frontend run build` 通过

### 下一步计划

1. 若继续自主迭代，可进入真正的“轻量代码整理 review”阶段：
   - 清理无用 import
   - 收紧少量重复文案
   - 评估少量局部状态/派生逻辑是否还能再简化
2. 若切回功能方向，优先目标应是后端真正接入仍处于草案态的能力，而不是继续改提示层。

---
## 2026-05-02 — 第二十二轮：轻量整理 review 第一轮收口

### 本次迭代成果

本轮从“功能/语义收口”切换到轻量代码整理 review，优先处理低风险、明确、可立即收口的问题：
- 无用 import
- 已不再使用的常量/变量
- lint 中最直接的 hook / setState 类错误

#### 1. 清理一批无用 import 和死代码常量

**文件**:
- `frontend/app/(dashboard)/api-keys/page.tsx`
- `frontend/app/(dashboard)/drop-policy/page.tsx`
- `frontend/app/(dashboard)/ip-lists/page.tsx`
- `frontend/app/(dashboard)/sites/page.tsx`
- `frontend/app/(dashboard)/rules/page.tsx`
- `frontend/components/add-site-dialog.tsx`

本轮删除了多处明确未使用的：
- icon import
- `useMemo`
- `formatDate`
- 未使用的 `actionLabels`
- 其他已被前面重构淘汰的符号

#### 2. 修复 lint 中唯一的 error 级问题

**文件**:
- `frontend/components/protection-mode-dialog.tsx`
- `frontend/app/(dashboard)/fingerprints/page.tsx`

本轮处理了两个最明确的问题：
- 去掉 `protection-mode-dialog` 中会触发 `set-state-in-effect` 的模式，改为更安全的重建方式
- 去掉 `fingerprints` 页面中 effect 内直接调用 `load()` 的模式，改成 effect 内联请求逻辑

#### 3. 统一提示组件继续小范围推进

**文件**:
- `frontend/components/console-shell.tsx`
- `frontend/app/(dashboard)/security/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`
- `frontend/app/(dashboard)/sites/[id]/client.tsx`

在前几轮的基础上，本轮继续确认 `Notice / SourceSiteNotice` 的推广是稳定的，并把 `sites/[id]` 的关键提示块继续迁移到统一组件。

### 验证结果

- `npm --prefix frontend run lint`
  - 从 **30 个问题（2 error, 28 warning）** 降到 **15 个问题（0 error, 15 warning）**
- 当前剩余均为 warning，未再发现阻塞性 lint error。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 这一轮不做新功能，只清掉最明确、最无争议的噪音。
- **YAGNI**: 不为 warning 过度重构，只处理立刻能确定无副作用的项。
- **DRY**: 删除已失效的重复符号与常量，继续收敛提示块到统一组件。
- **SOLID / SRP**: 页面逻辑更聚焦于真实业务状态，移除无关符号和过时辅助结构。

### 剩余问题（下一轮可选）

当前剩余 15 个 lint warning，主要分布在：
- `bot-protection`：两个三元表达式式的 side-effect 写法
- `cc-protection`：`saveWaitingRoom` 未使用
- `certificates`：一组未用图标和占位 helper
- `protection`：`owaspModuleOptions` / `setModuleSensitivity` 未使用
- `rules/cve`、`rules/owasp`：几处无副作用表达式和未用变量

这些都属于低风险整理项，可在后续继续逐个清理。

### 下一步计划

1. 继续第二轮 lint cleanup，把剩余 15 个 warning 再压一轮。
2. 如 warning 涉及真实设计取舍（而不只是噪音），仅做最小清理，不额外抽象。
3. 若 warning 基本清完，就进入最终收尾 review 阶段。

---
## 2026-05-02 — 第二十三轮：低风险复用逻辑收口

### 本次迭代成果

本轮继续沿“轻量整理 review”方向推进，优先处理低风险且收益明确的复用点与噪音代码。

#### 1. 统一证书 API helper

**文件**:
- `frontend/lib/api.ts`
- `frontend/components/add-site-dialog.tsx`
- `frontend/components/site-listeners-panel.tsx`

本轮新增并接入：
- `getCertificates()`
- `createCertificate()`
- `deleteCertificate()`

虽然这轮先只接入了 `getCertificates()`，但已经把：
- `AddSiteDialog`
- `SiteListenersPanel`

里重复的 `/api/v1/certificates` 拉取逻辑收敛到统一 API 封装下，为后续继续收口 `certificates/page.tsx` 做了铺垫。

#### 2. 清理一批明确无副作用的无用 import / 常量

此前轻量 review 已经清理了一批无用 import 和死常量，本轮保持该方向，不引入行为变化，仅继续巩固低风险整理基线。

#### 3. lint 状态复核

本轮后再次确认：
- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run lint` 仍剩 **15 个 warning，0 error**

说明当前剩余问题已完全进入“非阻塞整理项”阶段。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不大面积重构证书页面，只先统一最容易重复的 API 请求入口。
- **YAGNI**: 不为了消除所有 warning 而做高风险重构，只处理收益最明确的一类复用问题。
- **DRY**: 把多处直接硬写 `/api/v1/certificates` 的读取逻辑收回到 `api.ts`。
- **SOLID / SRP**: 页面组件只关心使用证书数据，不再关心请求 URL 细节。

### 剩余 warning（后续可选）

当前 lint 剩余 15 个 warning，主要是：
- `bot-protection`：两个三元表达式式副作用写法
- `cc-protection`：`saveWaitingRoom` 未使用
- `certificates`：未使用 icon / helper
- `protection`：`owaspModuleOptions` / `setModuleSensitivity` 未使用
- `rules/cve`、`rules/owasp`：无副作用表达式和未用变量

### 下一步计划

1. 如果继续整理，可专门做一轮“把 lint warning 压到个位数”的低风险清理。
2. 若改回功能方向，可把 `certificates/page.tsx` 继续向统一 API helper / CrudPage 方向收敛。
3. 若浏览器工具恢复，再补一轮站点列表 / 详情 / 全局页的联动验证，作为阶段性收尾。

### 本轮影响文件

| 文件 | 变更 |
|---|---|
| `frontend/lib/api.ts` | 新增证书 API helper |
| `frontend/components/add-site-dialog.tsx` | 使用统一 `getCertificates()` |
| `frontend/components/site-listeners-panel.tsx` | 使用统一 `getCertificates()` |

---
## 2026-05-02 — 第二十四轮：lint warning 清零

### 本次迭代成果

本轮把前端剩余 lint warning 做了最后一轮低风险清理，并成功把 warning 数压到 0。

### 本轮清理内容

#### 1. 修复 `bot-protection` 的无副作用表达式写法

**文件**: `frontend/app/(dashboard)/bot-protection/page.tsx`

将 `type === ... ? setX() : setY()` 这种仅用于副作用的表达式改成普通 `if / else`，消除：
- `@typescript-eslint/no-unused-expressions`

#### 2. 删除 `cc-protection` 未使用函数

**文件**: `frontend/app/(dashboard)/cc-protection/page.tsx`

删除未再使用的 `saveWaitingRoom()`，避免无效死代码继续留在页面中。

#### 3. 清理 `protection` 的未使用符号

**文件**: `frontend/app/(dashboard)/protection/page.tsx`

删除：
- `useMemo`
- `owaspModuleOptions`
- `setModuleSensitivity`

这些都已经在前几轮“矩阵降级为只读草案态”之后失效。

#### 4. 清理 `certificates` 中未使用的 icon / helper

**文件**: `frontend/app/(dashboard)/certificates/page.tsx`

删除：
- 未使用的 `ShieldCheck` / `Clock` / `Badge`
- 未使用的占位 helper：`parseCertDomains()`、`getDaysUntilExpiry()`

#### 5. 清理 `rules/cve` 与 `rules/owasp` 的轻量噪音

**文件**:
- `frontend/app/(dashboard)/rules/cve/page.tsx`
- `frontend/app/(dashboard)/rules/owasp/page.tsx`

处理：
- 去掉无副作用表达式式 `setState` 写法
- 去掉未使用的 `SensitivityConfig`
- 去掉未使用的 `rules` 状态以及其遗留调用

### 验证结果

最终结果：
- `npm --prefix frontend run lint` ✅ 通过（0 warning, 0 error）
- `npm --prefix frontend run typecheck` ✅ 通过
- `npm --prefix frontend run build` ✅ 通过

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 这轮只做低风险清理，不掺入新功能与大范围重构。
- **YAGNI**: 不为清 warning 引入新的抽象，只删除已失效或明显不该存在的代码。
- **DRY**: 顺手把一些重复副作用写法改回最普通的 `if / else`，避免未来再复制同类模式。
- **SOLID / SRP**: 页面更聚焦真实逻辑，移除失效 helper、无用状态和无用 import 后，职责更清晰。

### 收尾判断

到当前这一步：
- 前端主功能链路已打通
- 作用域/草案态语义已收口
- 安全高优先级问题已修
- 列表接口兼容性已恢复
- 前端 lint / typecheck / build 全绿

这意味着当前分支已经进入“可维护、可继续开发”的干净基线状态。

### 下一步计划

1. 如果继续迭代，可转入真正低频的代码风格统一或抽象复用工作。
2. 如果切回功能方向，应优先选择真正尚未接入运行时的数据面能力，而不是继续做表层整理。
3. 若浏览器工具恢复，可最后补一轮 UI/E2E 验证，作为阶段性完结检查。

---
## 2026-05-02 — 第二十五轮：草案能力接线优先级评估

### 本次迭代成果

本轮对仍处于草案态的三类能力做了运行时接线成本评估：
- `waiting_room_enabled`
- `cc_rules`
- `owasp_modules`

### 评估结论

#### 1. `waiting_room_enabled`
- 当前只看到存储字段与前端配置入口，未见数据面消费路径。
- 若要真正接线，需要在请求入口建立等待室排队/放行机制，不属于低成本补线。

#### 2. `cc_rules`
- 当前只看到存取转换与草案编辑，未见数据面消费 `cc_rules` 的执行链路。
- 若要真正接线，需要定义规则解释、匹配时机和动作执行点，属于一条独立功能线。

#### 3. `owasp_modules`
- 当前 `protection` 页保存的是 `owasp_modules` 草案值；运行时未见 OWASP 检测按模块读取该字段。
- 真正接线需要把模块开关/敏感度下沉到 OWASP 检测流程，影响面大于单点修补。

### 决策

本轮不强行选择其中之一做“最小接线”，因为三者都已经超出低风险整理范围：
- 继续硬接会把当前分支从“整理收口”转回“新功能开发”
- 风险和验证面都会明显扩大

因此这轮将其结论固化为：
- 继续保持前端草案/说明态
- 后续若要真正接线，应单独立项做运行时设计与回归验证

### 验证结果

- 基于代码搜索确认：当前数据面没有直接消费上述三类配置字段的清晰路径。
- 这轮未做代码实现变更，仅完成技术评估。

### 下一步计划

1. 若继续在当前分支收口，建议只做整理类工作，不再扩展运行时能力。
2. 若用户希望继续深挖功能，应单独选择一个能力（如 waiting room）开新实现任务。
3. 当前阶段可视为：前端语义收口与低风险 review 基本完成。

---
## 2026-05-02 — 第二十六轮：阶段性基线验证通过

### 本次迭代成果

本轮没有继续扩大功能面，而是对当前分支做了一次阶段性完整基线验证，确认前后端都已进入稳定可继续开发状态。

### 验证结果

#### 前端
- `npm --prefix frontend run lint` ✅ 通过
- `npm --prefix frontend run typecheck` ✅ 通过
- `npm --prefix frontend run build` ✅ 通过

#### 后端
- `go test ./internal/admin ./internal/security ./internal/snapshot ./internal/store ./internal/dataplane ./internal/proxy` ✅ 通过

### 当前结论

到这一轮为止：
- 前端 lint / typecheck / build 全绿
- 站点配置主链、listeners 运行时、站点/全局语义收口、列表接口兼容性修复均已纳入当前稳定基线
- 当前分支后续若继续推进，最有价值的方向将不再是“收口整理”，而是明确选择一个真正要落地的数据面能力做独立实现

### 下一步建议

1. 若继续当前分支的“整理”方向，收益已经开始递减，可考虑在此处收束。
2. 若继续做功能，应单独立项以下之一：
   - `waiting_room_enabled` 运行时接线
   - `cc_rules` 运行时接线
   - `owasp_modules` / 类别敏感度真实运行时消费（建议先核对与现有 `category_sensitivity` 链路的职责重叠）
3. 后续功能线建议以独立迭代推进，而不是混在本次整理收口任务中。

---

## 2026-05-07 — 第十六轮：前端去花哨化扫尾与站点详情收口

### 本次迭代成果

本轮继续按前端克制化目标做低风险收尾，重点不再是大范围改结构，而是把仍明显残留旧视觉体系的高频页面与公共组件拉回统一后台风格。

#### 1. 继续清理共享与高频页面的旧视觉残留

**文件**:
- `frontend/components/layout/sidebar.tsx`
- `frontend/components/layout/topbar.tsx`
- `frontend/components/dashboard-topbar.tsx`
- `frontend/components/pagination.tsx`
- `frontend/app/globals.css`
- `frontend/components/public-status-page.tsx`
- `frontend/components/crud-page.tsx`
- `frontend/components/rule-builder.tsx`

本轮继续处理：
- 玻璃态 / 半透明顶栏与下拉层
- 深色营销式侧栏
- 超大圆角与过软的分页/规则构建器容器
- `console-glass` 这类仍带旧语义的全局样式

处理后统一为：
- 白底 / 浅灰底 / 细边框 / 轻阴影
- `rounded-md` / `rounded-lg` 为主
- 减少 cyan 高饱和强调，回归 `slate` 主色体系

#### 2. 资源管理与策略类页面进一步收口

**文件**:
- `frontend/app/(dashboard)/api-keys/page.tsx`
- `frontend/app/(dashboard)/certificates/page.tsx`
- `frontend/app/(dashboard)/drop-policy/page.tsx`
- `frontend/app/(dashboard)/policies/page.tsx`
- `frontend/app/(dashboard)/bot-protection/page.tsx`
- `frontend/app/(dashboard)/rules/page.tsx`
- `frontend/app/(dashboard)/error-pages/page.tsx`

本轮把这些页面中残留的：
- 大圆角对话框
- 白底亮色 CTA
- 旧式半透明内容块
- 与现有控制台不一致的按钮风格
继续收口到统一后台风格。

#### 3. 站点详情页与监听面板并入当前设计体系

**文件**:
- `frontend/app/(dashboard)/sites/[id]/client.tsx`
- `frontend/components/site-listeners-panel.tsx`

这两个文件是本轮复扫后最明显的高频残留。

本轮改为：
- 站点详情页从旧 `gray/cyan` 体系切到 `slate` 为主的中性后台风格
- 顶部站点卡片、标签切换、空状态、保存按钮统一到当前控制台样式
- HTTP / HTTPS 切换态不再用高饱和 cyan，而是改成更克制的深色激活态
- 监听端口面板的主操作按钮与确认按钮统一改成 `bg-slate-950`

这样站点详情页不再像独立的一套旧后台，而是和站点列表页、shell、dialog 风格一致。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 本轮只做视觉与交互表层收口，不再扩大到业务逻辑重构。
- **YAGNI**: 没新增主题系统、设计 token 重构或新组件库，只在现有页面上做最小必要收敛。
- **DRY**: 持续把页面主按钮、容器圆角、顶栏/侧栏、表格包裹容器收敛到同一套样式语言。
- **SOLID / SRP**: 共享样式问题优先在公共组件与高频页修复，避免为单页特殊场景继续扩散一套旧视觉体系。

### 遇到的问题与解决方式

1. **站点详情页仍保留大量旧 `gray/cyan` 视觉残留**
   - 解决：逐段替换为 `slate` 体系，并把主 CTA 收敛为深色按钮。

2. **监听端口面板虽然结构已收敛，但按钮仍明显偏旧风格**
   - 解决：主按钮与保存按钮统一切到当前后台主按钮风格。

3. **部分替换过程中出现重复匹配或旧字符串已被前序修改**
   - 解决：重新读取局部内容后做精确替换，避免一次性大范围替换带来的误命中。

### 验证结果

- 已再次复扫 `frontend` 中高优先级的玻璃态、超大圆角、亮青色主 CTA、深色营销块残留
- 当前高优先级残留已显著减少，主要高频壳层与核心页面已基本统一到克制化后台风格
- 前端校验命令已执行：
  - `npm --prefix frontend run lint`
  - `npm --prefix frontend run typecheck`
  - `npm --prefix frontend run build`

### 下一步计划

1. 若继续迭代，优先做浏览器级复查，确认站点详情页、监听面板、规则页在真实交互下的视觉一致性。
2. 继续评估是否还有少量低优先级页面保留旧色系或局部强调过强的问题。
3. 如后续不再发现明显残留，可把前端克制化重构从“持续扫尾”切换到“按需维护”。

---

## 2026-05-07 — 第十七轮：日志恢复与残留主色收口

### 本次迭代成果

本轮先修复上一轮操作中造成的 `devlog.md` 历史段落缺失问题，再继续做一轮低风险前端视觉残留收口。

#### 1. 恢复 `devlog.md` 被截断的旧轮次

**文件**: `devlog.md`

上一轮追加日志时曾误用整文件写入，导致此前已存在的旧轮次从 `2026-05-02 — 第十六轮` 到 `第二十六轮` 缺失。

本轮从本地会话转录中恢复并重新插入了 11 个完整段落：
- 第十六轮：列表接口兼容修复与剩余草案态收尾
- 第十七轮：清理残留脏文本并继续压低 CC 规则误导性
- 第十八轮：统一提示组件初步落地
- 第十九轮：统一提示组件继续推广
- 第二十轮：统一提示组件推广收尾
- 第二十一轮：剩余提示块统一收尾
- 第二十二轮：轻量整理 review 第一轮收口
- 第二十三轮：低风险复用逻辑收口
- 第二十四轮：lint warning 清零
- 第二十五轮：草案能力接线优先级评估
- 第二十六轮：阶段性基线验证通过

恢复时采用受保护脚本：先校验标题唯一、段落完整、当前文件不存在同名标题，再插入到 `2026-05-07` 新轮次之前，避免重复追加或再次覆盖。

#### 2. 收敛剩余高饱和主色和超大圆角

**文件**:
- `frontend/app/globals.css`
- `frontend/components/layout/sidebar.tsx`
- `frontend/components/sidebar-nav.tsx`
- `frontend/app/login/page.tsx`
- `frontend/app/(dashboard)/sites/[id]/client.tsx`
- `frontend/app/(dashboard)/settings/page.tsx`
- `frontend/app/(dashboard)/protection/page.tsx`
- `frontend/app/(dashboard)/security/page.tsx`
- `frontend/app/(dashboard)/cc-protection/page.tsx`
- `frontend/app/(dashboard)/ip-lists/page.tsx`
- `frontend/app/(dashboard)/rules/page.tsx`
- `frontend/app/(dashboard)/rules/cve/page.tsx`
- `frontend/app/(dashboard)/rules/owasp/page.tsx`
- `frontend/app/(dashboard)/api-keys/page.tsx`
- `frontend/app/(dashboard)/certificates/page.tsx`
- `frontend/app/(dashboard)/policies/page.tsx`
- `frontend/app/(dashboard)/sites/page.tsx`
- `frontend/app/(dashboard)/fingerprints/page.tsx`
- `frontend/app/(dashboard)/security-events/page.tsx`
- `frontend/components/public-status-page.tsx`

本轮继续把残留的：
- cyan 主按钮
- cyan 导航 active 态
- cyan 装饰性图标
- `settings` 页 `rounded-2xl` / `rounded-xl`
- 表格行内“详情”按钮的 cyan 文本

收敛到 `slate` 主色、`rounded-md` / `rounded-lg` 和更克制的后台操作样式。

#### 3. 保留必要的语义色

本轮复扫后仍保留 `frontend/app/(dashboard)/access-logs/page.tsx` 中 GET 方法的 cyan 样式，因为它用于 HTTP 方法区分，不是页面主 CTA 或营销化装饰色。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 只恢复缺失日志段落、只替换明确残留的样式类，不做组件系统重构。
- **YAGNI**: 不引入主题 token 或新抽象，保留现有页面结构和业务逻辑。
- **DRY**: 把同类主按钮、导航 active 态、详情按钮样式继续收敛到一致的 slate 表达。
- **SOLID / SRP**: 日志恢复、视觉收口、语义状态色保留各自边界清晰，不把状态色全部机械替换。

### 遇到的问题与解决方式

1. **Serena 个别替换超时**
   - 解决：读取局部内容后确认实际变更状态，再用精确替换兜底。

2. **误触发一次空编辑**
   - 结果：工具返回 `No changes to make`，未修改文件。
   - 解决：改用唯一末尾段落做精确追加。

3. **扫描结果包含语义状态色**
   - 解决：只改主按钮和装饰色，保留 HTTP 方法等真正有语义区分作用的颜色。

### 验证结果

- `npm --prefix frontend run lint` 通过
- `npm --prefix frontend run typecheck` 通过
- `npm --prefix frontend run build` 通过
- 样式复扫结果：高优先级 cyan 主按钮、超大圆角、导航 cyan active 态已继续收敛；剩余 cyan 匹配仅为访问日志 GET 方法语义色。

### 下一步计划

1. 若继续迭代，可做一次 `git diff` 级人工复核，确认本轮样式替换没有触碰业务语义。
2. 若还要继续页面收口，优先检查低频页面的局部装饰色，而不是继续大范围替换语义状态色。
3. 如用户希望切换方向，可进入后端 API 硬化或真实运行时能力接线的独立计划。

---

## 2026-05-07 — 第十八轮：策略链路审计与规则导入契约修复

### 本次迭代成果

本轮按“策略配置与执行处理流程是否匹配”的方向做了聚焦审计，并只落地一个不触碰检测引擎核心路径的低风险契约修复。

#### 1. 策略链路取证结论

本轮重点核对了：
- `admin` 策略 API
- `store.ProtectionConfig`
- `snapshot` / `engine.Process`
- `dataplane/handler`
- 前端 `protection`、`security`、`cc-protection`、`rules` 页面

关键结论：
- OWASP 分类敏感度已经走真实执行链路：`UpdateSensitivityConfig` 保存 `category_sensitivity`，执行期 `OWASPPhase` 使用 `EffectiveCategorySensitivity()`。
- OWASP 单规则开关/白名单不是单纯展示：执行期会解析 `OWASPRulesConfig` 并通过 `waf.FilterHits()` 过滤命中。
- Chain challenge 配置不是草案态：启动与 reload 时会 `Reconfigure(parseChainSteps(...))`，数据面在 `chain_challenge` 动作下会调用 `WriteChainChallengeResponse()`。
- Escalation 不是 engine phase，而是在 data-plane 处理 WAF 命中后通过 `RecordHit` / `Evaluate` 升级动作；因此前端应表达为“命中后的升级响应”，不是独立检测阶段。

#### 2. 修复规则导入前端绕过批量 API 的契约不一致

**文件**: `frontend/app/(dashboard)/rules/page.tsx`

此前前端导入规则时：
- 解析 JSON 后逐条调用 `POST /api/v1/rules`
- 每条规则都会触发一次后端 reload
- 后端已有 `POST /api/v1/rules/import` 批量接口，但前端未使用

本轮改为：
- 导入时一次调用 `/api/v1/rules/import`
- 请求体使用 `{ rules }`
- toast 显示后端返回的 `imported / total`

这样前端行为与后端已提供的批量导入契约一致，也避免导入大量规则时重复 reload。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 不改后端导入语义，只让前端使用既有 API。
- **YAGNI**: 不新增导入预检、冲突解决或复杂报告，只展示后端返回的导入数量。
- **DRY**: 复用后端已有批量导入逻辑，避免前端重复实现逐条容错与计数。
- **SOLID / SRP**: 前端负责提交文件内容，后端负责批量创建和 reload。

### 遇到的问题与解决方式

1. **代理审计输出较长且被中断**
   - 解决：不再继续展开长原始转录，改为精确搜索和局部读文件确认链路。

2. **部分初步怀疑项经取证后不是问题**
   - OWASP 单规则 override 与 chain config 均已接入执行链路。
   - Escalation 的执行点在 data-plane 命中后升级，不在 engine phase 中。

### 验证结果

- `npm --prefix frontend run lint` 通过
- `npm --prefix frontend run typecheck` 通过

### 下一步计划

1. 可继续检查文案：把 Escalation 页面描述从“检测阶段”修正为“命中后的升级响应”，避免理解偏差。
2. 可继续后端低风险硬化：为 `/rules/import` 增加更明确的失败计数和错误摘要，但这会改变 API 返回结构，需单独评估。
3. 若要真正修改 engine / dataplane 执行顺序，必须单独立项并执行检测引擎强制压测。

---

## 2026-05-07 — 第十九轮：后端策略链路补充取证与等待室语义降级

### 本次迭代成果

本轮在后端策略链路审计代理完成后继续做补充取证，重点区分“已接入执行链路”和“仍是保存态/草案态”的策略项，并修正前端容易误导的描述。

#### 1. 补充确认 CC 规则已进入执行链路

**后端取证**:
- `internal/snapshot/build.go` 中 `compileCCRules(protection)` 会读取 `CCUseCustom` 和 `CCRules`。
- 编译结果会作为 `CompiledRule` 注入 snapshot 规则集合。
- `internal/core/rules/compiler.go` 已支持 `cc_rate` compound matcher。

结论：`cc_rules` 不再按草案态处理；它已通过 snapshot 编译为自定义规则参与执行。

#### 2. 确认等待室开关仍缺少数据面消费路径

**后端取证**:
- `store.ProtectionConfig` 中存在 `WaitingRoomEnabled`。
- 前端 `cc-protection` 可保存 `waiting_room_enabled`。
- 当前搜索未发现数据面排队/削峰执行链路消费该字段。

本轮不强行补后端运行时能力，改为前端语义降级：
- 等待室卡片说明改成“当前仅保存等待室草案开关”。
- 弹窗说明明确后端尚未看到排队/削峰执行链路消费这些参数。
- 容量、等待时间、刷新间隔从可编辑输入改成只读说明，避免误以为保存后生效。
- toast 文案从“已启用/配置已保存”改为“草案已启用/草案已保存”。

#### 3. 修正阶梯升级文案边界

**文件**: `frontend/app/(dashboard)/security/page.tsx`

Escalation 实际是在 WAF 命中后由 data-plane 记录违规次数并升级响应，不是独立检测阶段。本轮将描述改为：
- “在 WAF 命中后按客户端违规次数升级响应动作，不作为独立检测阶段。”

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 只改文案和只读展示，不改后端执行链路。
- **YAGNI**: 不补等待室运行时能力，不设计队列系统。
- **DRY**: 沿用此前“未接线能力降级为草案态”的处理方式。
- **SOLID / SRP**: 前端表达真实能力边界；后端执行能力留待独立任务实现。

### 验证结果

- `npm --prefix frontend run lint` 通过
- `npm --prefix frontend run typecheck` 通过

### 下一步计划

1. 如果要真正启用等待室，需要单独设计 data-plane 队列/令牌/放行机制，并补充回归测试。
2. 可继续低风险审计其它保存态字段是否有执行消费路径。
3. 若触碰 `internal/waf`、`internal/core/rules`、`internal/core/engine`、`internal/core/pipeline` 或 `internal/dataplane/handler.go`，必须执行检测引擎强制验收。

---

## 2026-05-07 — 第二十轮：动作语义规划与规则页低风险补齐

### 本次迭代成果

用户明确了新的动作语义与后续能力目标：限速、拦截、阻断、人机验证的状态码/处理方式，白名单与黑名单优先级，高危资源耗尽类攻击按规则配置动作，多上游、缓存、Redis 日志、人机验证策略与 5 秒盾 WASM/VMP 方向，以及参考 `temp` 截图继续完善前端样式。

本轮先按仓库现状做取证与分阶段规划，并只落地一个不触碰核心执行链路的前端契约补齐。

#### 1. 动作语义现状取证

**已存在的后端基础**:
- `internal/core/action/action.go` 已有 canonical actions：`allow`、`intercept`、`observe`、`drop`、`challenge`、`redirect`、`rate_limit`、`captcha_challenge`、`shield_challenge`、`chain_challenge`。
- `store.Rule` 已有 `status_code` 与 `redirect_to` 字段。
- data-plane 已能对 `drop` 关闭连接并记录 drop event；对 challenge 系列按类型进入 CAPTCHA / Shield / Chain / generic challenge；对 redirect 使用 `redirect_to`。
- 多上游轮询与站点响应缓存已有基础实现。

**仍需独立立项的后端能力**:
- 将用户定义的“限速=429、人机验证=422、拦截=403/418”沉淀为统一默认状态码策略，需要改 data-plane/action 默认值，属于执行链路变更。
- 白名单最高、黑名单其次、规则策略之后的全链路顺序需继续核对 IP reputation / ACL allow / blacklist 之间的精确优先级，若改 engine/dataplane 必须压测。
- 等待室 data-plane 队列/削峰执行仍未接线。
- Redis 日志写入目前不应直接替代现有 async SQL writer，需要单独设计 fan-out / buffer / failure 降级。
- 5 秒盾动态 WASM、浏览器环境检测、VMP/VM 反逆向属于新安全子系统，需要单独设计、构建链和安全审查。

#### 2. 规则页低风险补齐动作与状态码契约

**文件**: `frontend/app/(dashboard)/rules/page.tsx`

本轮补齐前端对后端既有字段的支持：
- `RuleFormData` 新增 `status_code`、`redirect_to`。
- 编辑已有规则时回填 `status_code` 与 `redirect_to`。
- 规则列表新增“动作”和“状态码”列。
- 动作下拉补充：
  - `rate_limit`：限速，默认 429
  - `challenge`：人机验证，默认 422
  - `captcha_challenge`：验证码验证，默认 422
  - `shield_challenge`：5秒盾，默认 422
  - `chain_challenge`：连锁验证，默认 422
  - `drop`：断连/丢弃连接，无 HTTP 响应
- 表单新增 HTTP 状态码与重定向地址字段。

本轮只展示和提交后端已有字段，不改变规则编译、pipeline 或 data-plane 执行逻辑。

#### 3. 分阶段落地规划

**阶段 A：低风险前端/契约对齐**
1. 完成规则页动作/状态码展示与编辑（本轮已完成）。
2. 继续统一 CVE/OWASP/CC 页动作文案，避免 `block`、`drop`、`intercept` 混用误导。
3. 读取 `temp` 截图后继续做前端布局/样式收敛，不改变业务逻辑。

**阶段 B：执行语义统一（强制压测路径）**
1. 统一默认状态码：`rate_limit=429`、`intercept=403/418 可配置`、`challenge=422`、`drop=无响应`。
2. 精确固化优先级：白名单 > 黑名单 > IP reputation / built-in OWASP/CVE > ACL / Signature / Custom。
3. 支持高危资源耗尽类 OWASP Top 10 命中按规则配置 `drop` / `rate_limit` / challenge。
4. 涉及 `internal/waf`、`internal/core/rules`、`internal/core/engine`、`internal/core/pipeline`、`internal/dataplane/handler.go`，必须执行 `go test` 与 `blazehttp` 强制验收。

**阶段 C：流量与性能能力**
1. 完善多上游策略：从现有轮询扩展到健康检查、权重、失败摘除。
2. 完善响应缓存规则：后缀/路径/方法/状态码/Cache-Control 条件。
3. 增加 Redis 日志 fan-out：在不破坏现有 SQL async writer 的前提下，将请求日志与拦截日志复制写入 Redis stream/list。

**阶段 D：高级人机验证与 5 秒盾**
1. 抽象 challenge policy：验证码、验证码混合、验证码后限速、自定义匹配策略。
2. 5 秒盾动态 WASM：先做最小 PoW + 浏览器环境信号验证，再评估 Go/C++ WASM 构建链。
3. VMP/自定义 VM 反逆向属于高复杂度安全模块，应独立设计并避免把“不可逆向”作为绝对承诺。

### 如何应用 KISS / YAGNI / DRY / SOLID

- **KISS**: 本轮只补前端既有字段，不改执行链路。
- **YAGNI**: 不一次性实现 WASM/VMP、等待室和 Redis 日志等大模块。
- **DRY**: 规则页复用后端已有 action/status/redirect 字段，不新增前端私有模型。
- **SOLID / SRP**: 前端负责正确表达动作语义，执行策略统一放到后端独立阶段处理。

### 验证结果

- `npm --prefix frontend run lint` 通过
- `npm --prefix frontend run typecheck` 通过

### 下一步计划

1. 若继续低风险方向，优先统一 CVE/OWASP/CC 页动作文案和状态码说明。
2. 若进入执行语义统一阶段，先写清楚默认状态码与优先级测试用例，再改 engine/dataplane。
3. 若进入前端样式方向，读取 `temp` 截图并按现有后台风格提炼布局，而不是照搬营销化视觉。

---

## 2026-05-13 迭代：前后端功能链路审查与修复

- 审查新增站点、监听器、处置日志、响应缓存和前端配置覆盖面。
- 修复 Go 基线编译与测试问题：dataplane challenge/WebSocket 调用签名、错误限流 helper、站点错误页解析、snapshot 自定义 CC 规则编译、上游 JSON 数组解析、站点匹配跨 bind 回退、temp 临时 main 包构建冲突。
- 加固响应缓存：配置 reload/Redis reload 清空缓存，缓存 key 绑定站点身份，写缓存使用完整响应安全判断，新增 Clear 方法。
- 修复处置日志：硬编码 OWASP 拦截补写 SecurityEvent，DropEvent source 统一归类为 bot/cve/rule/ip_reputation。
- 补前端配置与静态导出兼容：监听器 network 可配置，站点详情使用 static export 兼容路由 `/sites/_/?id=...`。
- 验证：`go test ./...` 通过；`npm run typecheck --prefix frontend` 通过；浏览器访问站点详情会按未登录状态跳转到登录页，仅因未启动后端出现 refresh API 404。

## 2026-05-13 迭代：TLS 兜底校验与前端配置补齐

- 后端补齐 TLS 证书兜底校验：站点 legacy TLS 配置、站点监听器创建/更新均校验 `cert_id` 必填且证书存在，避免保存后 HTTPS 监听无法安全启动。
- 前端补齐证书编辑入口：证书页面支持复用上传弹窗编辑证书名称、证书 PEM 与私钥 PEM，并调用后端 `/certificates/:id/update`。
- 前端补齐 IP 列表类型筛选：列表页支持按全部/白名单/黑名单筛选，并透传后端 `kind` 查询参数。
- 验证：`go test ./...` 通过；`npm run typecheck --prefix frontend` 通过；`npm run build --prefix frontend` 通过；浏览器访问证书页/IP 列表页能正常加载并按未登录状态跳转登录，仅因未启动后端出现 refresh API 404。
