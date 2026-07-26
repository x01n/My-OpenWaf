# Lua 策略插件

> [返回 扩展与插件系统](./扩展与插件系统.md)

<cite>
**本文档引用的文件**
- [runtime.go](file://internal/waf/luaplugin/runtime.go)
- [sandbox.go](file://internal/waf/luaplugin/sandbox.go)
- [exec.go](file://internal/waf/luaplugin/exec.go)
- [api.go](file://internal/waf/luaplugin/api.go)
- [engine.go](file://internal/waf/luaplugin/engine.go)
- [dryrun.go](file://internal/waf/luaplugin/dryrun.go)
- [lua_phase.go](file://internal/core/rules/lua_phase.go)
- [engine.go](file://internal/core/engine/engine.go)
- [pipeline.go](file://internal/core/pipeline/pipeline.go)
- [action.go](file://internal/core/action/action.go)
- [lua.go](file://internal/snapshot/lua.go)
- [lua_plugin.go](file://internal/store/lua_plugin.go)
- [lua_plugin.go](file://internal/admin/system/lua_plugin.go)
- [lua_plugin.go](file://internal/store/repository/lua_plugin.go)
- [router.go](file://internal/admin/router.go)
- [redis_kv.go](file://internal/cache/redis_kv.go)
- [handler.go](file://internal/dataplane/handler.go)
</cite>

## 目录
1. [简介](#简介)
2. [快速开始](#快速开始)
3. [执行时机：pre 与 post](#执行时机pre-与-post)
4. [沙箱能力与限制](#沙箱能力与限制)
5. [ctx 字段完整参考](#ctx-字段完整参考)
6. [ctx.kv 跨请求存储](#ctxkv-跨请求存储)
7. [返回值的三种形态](#返回值的三种形态)
8. [可用动作与终止性](#可用动作与终止性)
9. [超时与失败语义](#超时与失败语义)
10. [管理 API 一览](#管理-api-一览)
11. [排错指引](#排错指引)
12. [示例脚本](#示例脚本)
13. [常量速查表](#常量速查表)

## 简介

Lua 策略插件让运维在不改动 Go 代码、不重新编译的前提下写自定义判定逻辑。脚本存在数据库表 `lua_plugins` 里，随配置重载编译并热替换，运行在受限沙箱中，每请求同步执行。

适用场景：内置规则 DSL 表达不了的组合条件（多字段联合判断、按 IP 计数、按站点分流、对已确认误报定点放行）。

不适用场景：需要访问文件系统、发起网络请求、调用外部命令、或做重计算的逻辑。沙箱不提供这些能力，且 50 ms 的默认超时不允许长耗时操作。

实现分布：

| 文件 | 职责 |
| --- | --- |
| `internal/waf/luaplugin/runtime.go` | `Script`/`Decision`/`Stage` 定义、编译入口、统计 |
| `internal/waf/luaplugin/sandbox.go` | 标准库白名单、危险函数摘除、状态机池、全局清理 |
| `internal/waf/luaplugin/exec.go` | `RequestView` 定义、单次执行、返回值转换、panic 隔离 |
| `internal/waf/luaplugin/api.go` | `ctx` 表构造、`ctx.kv` 方法表、键前缀与体积限制 |
| `internal/waf/luaplugin/engine.go` | 脚本集合持有、按阶段分桶、热替换、逐个执行 |
| `internal/waf/luaplugin/dryrun.go` | `Validate`（仅编译）与 `DryRun`（编译 + 试跑） |
| `internal/core/rules/lua_phase.go` | `pre` 阶段的管道实现、`RequestView` 构造 |
| `internal/core/engine/engine.go` | `post` 阶段执行与覆盖规则（`applyPostLuaDecision`） |
| `internal/snapshot/lua.go` | 从数据库加载并编译，编译错误记入快照 |

## 快速开始

脚本必须定义一个**全局**函数 `handle(ctx)`：

```lua
function handle(ctx)
  if ctx.path == "/health" then
    return "allow"
  end
  return nil
end
```

要点：

- 函数名固定为 `handle`，且必须是全局的（写 `local function handle` 会被判为「未定义入口」）。入口名来自 `exec.go` 的 `handlerName` 常量。
- 顶层代码**每次调用都会重新跑一遍**（`exec.go` 每次都先 `PCall` 整个 chunk 再取 `handle`）。所以顶层的 `local T = {...}` 每个请求都会重建，且顶层的可变状态不会跨请求保留（非白名单全局在每次执行前被清空）。跨请求状态请用 `ctx.kv`；顶层大表的开销见[性能](#性能)。
- 返回 `nil` 表示「不判定」，请求继续走后续流程。这应该是绝大多数请求走到的分支。

## 执行时机：pre 与 post

数据面的完整阶段顺序（`internal/core/engine/engine.go` 的 `getOrBuildPhases`）：

```
IPReputation → AntiReplay → ACL → LuaPre → OWASP → CVE → BotDetection
             → BrowserSign → RequestRateLimit → Signature → Custom
             ─────（管道结束）─────
             → LuaPost
```

`LuaPre` 只在存在启用的 `pre` 脚本时才会被加入阶段链，不存在时零开销（`Engine.HasScripts`）。

`LuaPost` **不是**管道阶段。它在 `pipeline.Run` 返回之后、由 `Engine.processResolved` 调用 `applyPostLuaDecision` 执行。原因是管道遇到终止动作就立即 return，挂在链尾的阶段永远读不到「已被拦截」的判定，也就没法实现「对误报放行」这个核心用例。

### 两个阶段的语义差异

| 维度 | `pre` | `post` |
| --- | --- | --- |
| 位置 | ACL 之后、OWASP 之前 | 全部内置阶段之后 |
| 能读到内置判定 | 否，`ctx.phase` / `ctx.action` 恒为空串 | 是 |
| 能省掉昂贵检测 | 是，`allow` 会短路 OWASP/CVE/Bot 等后续阶段 | 否，检测已经跑完了 |
| 能推翻内置拦截 | 不适用（内置阶段还没跑） | **只有 `allow` 能** |
| 典型用途 | 自定义限速、扫描器拦截、指纹分流、观察打点 | 误报放行、基于内置判定的二次决策 |

### post 阶段的覆盖规则

`applyPostLuaDecision` 刻意收紧了覆盖能力：

1. 脚本返回 `allow` → 清空内置判定，请求继续走向上游。**这是唯一能推翻内置拦截的动作。**
2. 脚本返回其他有效动作，且内置判定**不是**终止动作 → 采用脚本的判定。
3. 脚本返回其他有效动作，但内置判定**是**终止动作 → 保留内置判定，脚本判定被丢弃。
4. 脚本返回无法识别的动作 → 忽略，保留内置判定。

第 3 条是有意为之：否则脚本可以把 `drop` 降级成 `redirect`，绕过内置的终止优先级语义（`drop > intercept > rate_limit > challenge > redirect`）。

所以：**想在 post 阶段拦截什么，只有在内置引擎放行了它的时候才生效。** 如果目标是「无论内置怎么判都要拦」，应该写 `pre` 阶段脚本。

### 同阶段内的执行顺序

同一阶段的多个脚本按 `priority ASC, id ASC` 排序（`internal/snapshot/lua.go` 与 `LuaPluginRepo.ListEnabled`），数值小的先执行。`Engine.Evaluate` 返回**第一个给出判定的脚本**的结果，之后的脚本不再执行。返回 `nil` 的脚本不算判定，链会继续往下走。

### 站点范围的注意事项

`lua_plugins` 表有 `site_id` 列（`null` 表示全站），管理 API 也能读写它，但**当前的加载逻辑不按站点过滤**：`internal/snapshot/lua.go` 的 `loadLuaPlugins` 只按 `enabled` 过滤，编译出的 `luaplugin.Script` 不携带站点信息。

因此 `site_id` 目前只是一个标注字段，**不影响脚本实际生效范围**。要做按站点区分，必须在脚本内部判断 `ctx.site_id`（见 `lua-examples/06-per-site-policy.lua`）。

## 沙箱能力与限制

### 可用的标准库

只注册四个库（`sandbox.go` 的 `allowedLibs`）：

| 库 | 说明 |
| --- | --- |
| `base` | 部分可用，见下方摘除清单 |
| `table` | 完整可用 |
| `string` | 完整可用（`find` / `match` / `gmatch` / `gsub` / `sub` / `lower` / `upper` / `format` / `rep` / `len` / `byte` / `char` / `reverse`） |
| `math` | 完整可用 |

### 被禁用的库与原因

| 被禁 | 原因 |
| --- | --- |
| `io` / `os` | 文件系统、环境变量、子进程与时钟访问，策略脚本绝不应触达 |
| `debug` | 能绕过一切沙箱限制：改别人的函数、读局部变量、拿到上值 |
| `package`（`require` / `loadlib`） | 能加载任意 Lua 模块与 C 动态库 |
| `coroutine` | 与超时中断机制冲突——协程内的执行不受调用方 context 约束 |

### 从 base 库摘除的函数

清单来自 `sandbox.go` 的 `bannedBaseFuncs`：

| 被摘除 | 原因 |
| --- | --- |
| `load` / `loadstring` / `loadfile` / `dofile` / `require` | 能从字符串动态构造并执行代码，使静态审计与体积限制形同虚设 |
| `collectgarbage` | 允许脚本主动触发 STW GC，是廉价的拒绝服务手段 |
| `print` | 直接写进程 stdout，绕过统一日志且可被用于刷日志 |
| `getmetatable` / `setmetatable` | 实测可用的沙箱穿透入口：`getmetatable("").__index.upper = ...` 能改写字符串方法，而字符串元表是状态机级共享对象，池化复用下会污染同一状态机上后续执行的所有脚本 |
| `rawset` / `rawget` / `rawequal` / `rawlen` | 绕过元方法直接操作表，同样可用于篡改共享结构 |
| `newproxy` | 能创建带元表的 userdata，是另一条构造共享可变状态的路径 |
| `module` | 会写全局命名空间 |

仍可用的 base 函数：`assert`、`error`、`ipairs`、`next`、`pairs`、`pcall`、`xpcall`、`select`、`tonumber`、`tostring`、`type`、`unpack`，以及 `_G` / `_VERSION`。

> 注意：`#`（长度运算符）、`..`（连接）、`==` 等**运算符**不受影响，被禁的只是 `rawlen` 这类函数形式。

### 跨请求与跨脚本隔离

- Lua 状态机通过 `sync.Pool` 复用（创建一个状态机约几十微秒，每请求新建会直接压垮吞吐）。
- 每次执行前调用 `resetGlobals`，清除所有不在 `scriptGlobalWhitelist` 里的全局名。所以**脚本无法借全局变量在请求之间传递状态**——需要跨请求状态就用 `ctx.kv`。
- 白名单只含上面列出的安全名字。它刻意不包含任何被摘除的函数名，否则脚本重新定义一个同名全局就不会被清掉，等于把穿透入口还回去了。

### 脚本体积

单脚本源码上限 **256 KiB**（`runtime.go` 的 `maxScriptBytes`）。超限在编译期就被拒绝，保存时即报错。

## ctx 字段完整参考

`ctx` 由 `api.go` 的 `buildContextTable` 构造，是当次请求的**只读副本视图**——改 `ctx` 的字段不会影响 WAF 内部状态，也不会影响转发给上游的请求。

### 请求基础字段

| 字段 | Lua 类型 | 说明 |
| --- | --- | --- |
| `ctx.request_id` | string | 请求 ID，与访问日志/安全事件里的 `request_id` 一致；dry-run 时固定为 `"dry-run"` |
| `ctx.client_ip` | string | 经转发头与可信 CIDR 解析后的客户端 IP；解析失败时为空串 |
| `ctx.method` | string | HTTP 方法，大写（如 `"GET"`） |
| `ctx.path` | string | **原始未解码**路径（`URI().PathOriginal()`），百分号编码保持原样 |
| `ctx.query` | string | **原始未解码**查询串，不含 `?` |
| `ctx.host` | string | 请求 Host 头 |
| `ctx.user_agent` | string | User-Agent，原始大小写 |
| `ctx.site_id` | number | 匹配到的站点 ID |
| `ctx.content_type` | string | Content-Type 头原值 |
| `ctx.body` | string | 请求体，**最多 48 KiB**（数据面检查窗口，超出部分截断）；无体时为空串 |

### 表字段

| 字段 | 说明 |
| --- | --- |
| `ctx.headers` | 请求头映射，**键一律小写**（数据面的 `populateRequestCtxHeaders` 保证）。用 `ctx.headers["user-agent"]`，不要用 `ctx.headers["User-Agent"]`。缺失的头返回 `nil` |
| `ctx.query_params` | 查询参数映射。**运行时恒为空表**——见下方警告 |

> **`ctx.query_params` 目前在数据面不可用。**
> `pipeline.RequestCtx.QueryParams` 在整个数据面路径上从未被填充（只在对象池里被重置为 `nil`），所以线上请求走到脚本时这个表总是空的。而 dry-run 接口**可以**显式传 `query_params`，于是脚本在试运行里能通过、上线后静默失效。
> **要读查询参数，请自己解析 `ctx.query`**（示例见 `lua-examples/03-scanner-block.lua` 里的 `string.find` 用法）。

### TLS 指纹字段

`ctx.tls` 是一个子表。纯 HTTP 请求或指纹采集不可用时，各字段为空串。

| 字段 | 说明 |
| --- | --- |
| `ctx.tls.version` | 取值为 `""` / `"SSL3"` / `"TLS10"` / `"TLS11"` / `"TLS12"` / `"TLS13"`（`tlsmeta.CanonicalVersionName`） |
| `ctx.tls.ja3` | JA3 **哈希**（MD5 十六进制），不是原始 JA3 串——原始串未暴露给脚本 |
| `ctx.tls.ja4` | JA4 指纹全串，格式见下 |
| `ctx.tls.sni` | TLS SNI |

JA4 格式为 `ja4_a` + `_` + `ja4_b` + `_` + `ja4_c`，其中 `ja4_a` 是 10 个字符（`github.com/wu238121-a11y/go-ja4`）：

| 位置 | 含义 | 取值 |
| --- | --- | --- |
| 1 | 传输协议 | `t` = TCP/TLS 监听器；`q` = QUIC/HTTP3 监听器 |
| 2-3 | TLS 版本 | `13` / `12` / `11` / `10` / `00`（未知） |
| 4 | SNI | `d` = 带 SNI；`i` = 无 SNI（按 IP 访问） |
| 5-6 | 密码套件数量 | 两位十进制，去 GREASE 后计数，上限 `99` |
| 7-8 | 扩展数量 | 两位十进制，去 GREASE 后计数，上限 `99` |
| 9-10 | 首个 ALPN | 取 ALPN 串的首字符 + 末字符（`h2` → `h2`，`http/1.1` → `h1`）；无 ALPN 时为 `00` |

`ja4_b` 与 `ja4_c` 各为 12 个十六进制字符（截断的 SHA-256）。

举例：`t13d1516h2_8daaf6152771_e5627efa2ab1` 表示 TCP + TLS 1.3 + 带 SNI + 15 个密码套件 + 16 个扩展 + ALPN 为 h2。

### 内置判定字段（仅 post 阶段有值）

| 字段 | 说明 |
| --- | --- |
| `ctx.phase` | 给出判定的内置阶段名 |
| `ctx.action` | 内置判定的动作名；内置未命中任何规则时为空串 |

`ctx.phase` 的可能取值，即当前实际接进阶段链的各阶段名（`Name()` 与 `Result.Phase`）：

`ip_reputation`、`anti_replay`、`acl`、`lua_pre`、`owasp_default`、`cve_detection`、`bot_detection`、`browser_sign`、`rate_limit`、`signature`、`custom`。

`lua_pre` 出现在这里是正常的：前置脚本给出的判定同样会被后置脚本看到。

一个容易误以为会出现但实际不会的值：`maintenance`——维护模式在管道之前就直接 return 了，压根不会走到 post 阶段。

（此前这里还列过 `acl_allow_precheck`。那个阶段类型已随冗余代码一并移除：ACL 主阶段本身就带 `allow` 短路，预检阶段从未被接入过阶段链。）

`pre` 阶段这两个字段恒为空串——那时内置阶段还没跑。

## ctx.kv 跨请求存储

`ctx.kv` 是脚本唯一的跨请求状态通道，后端是共享的 `cache.RedisKV`（即 `MY_OPENWAF_REDIS_ADDR` 配置的那个 Redis）。

### 方法

**这些是普通函数，不是方法。必须用点号调用，不能用冒号。** 用 `ctx.kv:incr(...)` 会把表本身当成第一个参数传进去，导致 `CheckString(1)` 报错、脚本执行失败。

| 调用 | 返回 | 说明 |
| --- | --- | --- |
| `ctx.kv.available()` | boolean | 后端是否可用。Redis 未配置时为 `false` |
| `ctx.kv.get(key)` | string 或 `nil` | 读取；未命中、键非法、后端不可用时均为 `nil` |
| `ctx.kv.set(key, value [, ttl])` | boolean | 写入是否成功；键非法、值超限、后端不可用时为 `false` |
| `ctx.kv.delete(key)` | 无返回 | 删除 |
| `ctx.kv.incr(key [, ttl])` | number 或 `nil` | 原子自增并返回新值；失败时为 `nil` |

`ttl` 单位是**秒**，可省略。

### 限制

| 限制 | 值 | 来源 |
| --- | --- | --- |
| 键长上限 | 256 字节 | `kvMaxKeyLen` |
| 值大小上限 | 64 KiB | `kvMaxValueLen` |
| 默认 TTL | 5 分钟 | `kvDefaultTTL`，用于未传 `ttl` 或传了非正数/非数值 |
| TTL 上限 | 24 小时 | `kvMaxTTL`，超出的值被钳制到 24 小时 |
| 键前缀 | `owaf:lua:` | `kvKeyPrefix`，自动加上，脚本不用也不能绕过 |

键前缀隔离是必需的：限速计数、挑战会话、防重放 nonce 都在同一个 Redis 实例里，没有前缀的话脚本能覆盖 WAF 自己的缓存键。空键和超长键会被拒绝（降级为 `nil` / `false`，不报错）。

实际写入 Redis 的键名还会再套一层 `RedisKV` 自己的 `openwaf:` 前缀，即完整键形如 `openwaf:owaf:lua:<你的键>`。排查时按这个前缀查。

### 降级而非报错

后端不可用（Redis 未配置或客户端为 nil）时，所有 `kv.*` 调用返回 `nil` / `false`，**不抛错**。这是有意的：Redis 故障应让策略降级，而不是让脚本抛错、进而使判定失败。

所以依赖 KV 的脚本应该显式处理不可用的情况：

```lua
if not ctx.kv.available() then
  return nil   -- 拿不到计数就别判定，放行给后续阶段
end
```

### `incr` 的窗口语义（重要）

`cache.RedisKV.Incr` 用一个 pipeline 执行 `INCR` + `EXPIRE`，**每次调用都会重置过期时间**。所以它不是固定时间窗口，而是**空闲过期窗口**：只要该键持续被自增，计数就一直不清零；停止 `ttl` 秒无任何请求后计数才消失。

后果：

- 持续打请求的客户端，计数会一路累加上去，达到阈值后会一直被判中，直到它停手 `ttl` 秒。类似 fail2ban 的计数器，对压制持续扫描是合适的。
- **做不到**「每分钟允许 100 次、整点清零」这种固定窗口。脚本里没有时钟（`os` 库被禁），无法在键里编时间桶。真需要固定窗口请用内置的请求速率限制阶段。

## 返回值的三种形态

`exec.go` 的 `decisionFromLua` 接受三种返回值：

### 1. 不判定

```lua
return nil        -- 或 return false，或干脆不写 return
```

`nil`、`false`、无返回值都表示「不判定」，请求继续走后续阶段/脚本。返回 `true` 也被当作不判定（`true` 没有明确语义，按不判定处理以免误拦）。

### 2. 只给动作（字符串）

```lua
return "intercept"
```

### 3. 表（可携带附加信息）

```lua
return {
  action = "redirect",
  message = "unrecognized client fingerprint",
  redirect_to = "/verify",
  status_code = 302,
}
```

表的字段（`decisionFromTable`）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `action` | string | 动作名。缺失或空串等于不判定 |
| `message` | string | 写入 `Result.MatchDesc`，出现在安全事件的 `match_desc` 与拦截页调试信息里。不参与判定 |
| `redirect_to` | string | 仅 `action = "redirect"` 时有意义 |
| `status_code` | number | 覆盖响应码；0 或缺失时用动作的默认码（`intercept` → 403，`rate_limit` → 429，`redirect` → 302，各挑战 → 403） |
| `headers` | table | **当前未生效**，见下 |
| `tags` | table | **当前未生效**，见下 |

> **`headers` 与 `tags` 目前会被解析但不会被应用。**
> `decisionFromTable` 会把它们填进 `Decision.SetHeaders` / `Decision.Tags`，但 `lua_phase.go` 和 `applyPostLuaDecision` 都没有读这两个字段——它们不会被加到转发给上游的请求头上，也不会进日志。写了不报错，只是没有任何效果。需要给下游传标记时，暂时用 `message`（它会进安全事件）。

类型不匹配的字段会被静默忽略（例如 `status_code = "302"` 是字符串，不会被采纳）。返回上述三种之外的类型（如 number、function）会被当作执行错误。

## 可用动作与终止性

动作名经 `action.Normalize` 归一化：前后空白被去掉、大写转小写，`block` 映射为 `intercept`，`log_only` 映射为 `observe`。归一化后仍不认识的动作会被**忽略**（按不判定处理），而不是拦截——自定义策略的笔误不应升级为对正常流量的误封。

| 动作 | `pre` 阶段行为 | `post` 阶段行为 |
| --- | --- | --- |
| `allow` | 短路后续阶段，请求直接走向上游 | **清空内置判定**，请求走向上游 |
| `intercept`（或 `block`） | 终止，返回拦截页（默认 403） | 仅当内置未终止时生效 |
| `drop` | 终止，直接断开 TCP，不发响应 | 仅当内置未终止时生效 |
| `rate_limit` | 终止，返回限速响应（默认 429） | 仅当内置未终止时生效 |
| `redirect` | 终止，302 跳转到 `redirect_to` | 仅当内置未终止时生效 |
| `challenge` | 终止，JS 挑战 | 仅当内置未终止时生效 |
| `captcha_challenge` | 终止，图形验证码 | 仅当内置未终止时生效 |
| `shield_challenge` | 终止，5 秒盾 | 仅当内置未终止时生效 |
| `chain_challenge` | 终止，多步链式验证 | 仅当内置未终止时生效 |
| `observe`（或 `log_only`） | 非终止，**记一条安全事件**后继续 | 非终止，但不产生日志（见下） |
| `tag` | 非终止，继续；**当前不产生任何记录** | 非终止；不产生任何记录 |

关于挑战动作在 `pre` 阶段的一个细节：`pipeline.Run` 会把挑战判定**暂存**而不是立即返回，继续跑后续阶段。如果后面出现优先级更高的终止动作（如 OWASP 判 `intercept`），它会覆盖脚本给的挑战；没有的话，链尾再把挑战返回。

### 想做观察打点，用 `pre` + `observe`

只有这一个组合会真正落库：

- `pre` + `observe` → `pipeline.Run` 把它收进 `ObserveHits` → 数据面写一条 `action = "observe"` 的安全事件，`phase = "lua_pre"`、`category = "lua_plugin"`、`match_desc` 取你的 `message`。
- `pre` + `tag` → `Result.ShouldLog()` 对 `tag` 返回 false，既不进 `ObserveHits` 也不进任何日志。**当前完全没有可观测效果。**
- `post` + `observe` / `tag` → 成为最终的非终止判定，而数据面只对 `IsTerminal()` 为真的判定写安全事件，对 `ObserveHits` 之外的非终止结果不记录。**也没有可观测效果。**

## 超时与失败语义

核心原则：**自定义策略出问题绝不能让站点不可用。**

| 情况 | 结果 |
| --- | --- |
| 脚本执行超过超时 | 被中断，记 `timeouts` 统计，写一条 warn 日志，该脚本视为未判定，继续下一个脚本 |
| 脚本 `error()` 或运行时报错 | 记 `failures` 统计，写 warn 日志，视为未判定，继续下一个脚本 |
| 脚本 panic（如栈溢出） | 被 `recover` 转为普通错误，同上处理，不会打崩数据面 |
| 脚本未定义 `handle` | 视为失败（`ErrNoHandler`），记 `failures`，不判定 |
| 脚本返回不支持的类型 | 视为失败，不判定 |
| 编译失败（语法错误/超限） | 该脚本被跳过，不进入运行集合，错误记入 `Snapshot.LuaPluginErrors` 并在 reload 时打 warn 日志。**其他脚本与整份配置照常生效** |

超时相关的数值：

- 默认超时 **50 ms**（`runtime.go` 的 `defaultTimeout`）。取这个值是因为脚本在数据面每请求同步执行，再长会显著拉高 P99；而正常脚本（读几个字段 + 少量字符串判断）耗时在微秒级，50 ms 足以覆盖含一次 KV 往返的场景。
- 单脚本可用 `timeout_ms` 覆盖，管理 API 限制在 **0 ~ 1000 ms**（`luaMaxTimeoutMS`），`0` 表示用默认值。
- 除了挂钟超时，调用方 context 取消（客户端断开）也会中断脚本执行。
- `while true do end` 这类死循环会被可靠中断——这是沙箱最关键的一条保证，有专门的测试覆盖（`TestInfiniteLoopIsInterrupted`）。

一个重要的细节：**「不判定」不等于「放行」**。脚本失败只是这个脚本没给判定，请求会继续走剩下的阶段，内置检测照常生效。

## 管理 API 一览

全部在 `/api/v1` 下，遵循项目「只用 GET 和 POST」的约定。读接口在 `readGroup` 下，`admin` / `operator` / `readonly` 三种角色都可访问；写接口（含 `validate` 与 `dry-run`）在 `opsGroup` 下，需要 `admin` 或 `operator`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/lua-plugins` | 列出全部脚本，返回 `{items, total}`，按 `stage, priority, id` 排序 |
| GET | `/lua-plugins/:id` | 取单个脚本 |
| POST | `/lua-plugins` | 新建。`name` / `stage` / `source` 必填，保存前会做编译校验 |
| POST | `/lua-plugins/:id/update` | 更新，只覆盖请求里提供的字段 |
| POST | `/lua-plugins/:id/delete` | 删除（软删除） |
| POST | `/lua-plugins/:id/toggle` | 切换启用状态；不带 body 时取反，带 `{"enabled": bool}` 时按值设置 |
| POST | `/lua-plugins/validate` | 只编译校验，不保存不执行。返回 `{"valid": bool}`，失败时带 `error` |
| POST | `/lua-plugins/dry-run` | 用样例请求试跑，不影响线上配置 |

所有写接口成功后都会触发配置 reload（重建快照、重新编译脚本、热替换脚本集合）。

### 创建/更新的请求体

```json
{
  "name": "api-rate-limit",
  "stage": "pre",
  "source": "function handle(ctx) return nil end",
  "enabled": true,
  "priority": 100,
  "timeout_ms": 0,
  "description": "按 IP 限制 /api/ 请求频率",
  "site_id": null
}
```

| 字段 | 说明 |
| --- | --- |
| `name` | 脚本名，用于日志与统计。新建必填 |
| `stage` | `pre` 或 `post`。新建必填 |
| `source` | Lua 源码。新建必填，上限 256 KiB |
| `enabled` | 省略时新建默认 `true`、更新时保持原值 |
| `priority` | 同阶段执行顺序，小者先执行。默认 `100` |
| `timeout_ms` | 0 ~ 1000，`0` 表示用 50 ms 默认值 |
| `description` | 备注，上限 512 字符 |
| `site_id` | 三态：**字段缺失**保持原值；**显式 `null`** 改为全站；**正整数**绑定站点（`0` 与非数字会报错）。注意这个字段目前不影响实际生效范围 |

### dry-run 的请求体

```json
{
  "stage": "post",
  "source": "function handle(ctx) ... end",
  "timeout_ms": 200,
  "request": {
    "client_ip": "203.0.113.9",
    "method": "POST",
    "path": "/api/report/render",
    "query": "id=1",
    "host": "app.example.com",
    "user_agent": "Mozilla/5.0",
    "site_id": 1,
    "content_type": "application/json",
    "body": "{\"tpl\":\"a\"}",
    "headers": {"x-real-ip": "203.0.113.9"},
    "query_params": {"id": "1"},
    "tls_version": "TLS13",
    "tls_ja3": "",
    "tls_ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
    "tls_sni": "app.example.com",
    "phase": "owasp_default",
    "action": "intercept"
  }
}
```

`request.phase` / `request.action` 用来模拟内置判定，是验证 post 脚本分支的关键。`timeout_ms` 超过 1000 或非正数时回落到默认超时。

响应：

```json
{
  "compile_error": "",
  "runtime_error": "",
  "decision": {"Action": "allow", "Message": "known false positive", "RedirectTo": "", "StatusCode": 0, "SetHeaders": null, "Tags": null},
  "elapsed_ms": 0.12
}
```

`compile_error` 非空时其余字段无意义。`runtime_error` 非空表示执行出错（含超时）。`decision.Action` 为空串表示脚本未做判定。

> dry-run 用独立的状态机池，不复用线上状态机，试运行不会污染生产请求。但它**会**用真实的 KV 后端，所以试跑带 `kv.incr` 的脚本会真的写 Redis 计数。

## 排错指引

### 保存时报错

`POST /lua-plugins` 与 `/update` 在写库前调用 `luaplugin.Validate`，语法错误和超限会直接以 400 返回，错误文案形如：

```
luaplugin: compile "validate": <file>:3: unexpected symbol near 'end'
```

想在写代码时快速循环，用 `POST /lua-plugins/validate`，它只编译不执行。

### 脚本存下来了但不生效

按这个顺序查：

1. **`enabled` 是不是 true。** `LuaPluginRepo.Create` 对 `enabled=false` 有专门的回写处理，但列表接口返回的值是权威的，直接看它。
2. **reload 时有没有编译失败。** 保存成功不代表能加载——`snapshot.Build` 会重新编译一次。失败的脚本被跳过，同时：
   - 进程日志有一条 warn：`lua plugin compile failed, skipped`，带 `script` 与 `err` 字段（`internal/app/server.go` 的 reload 回调）。
   - 错误也记在 `Snapshot.LuaPluginErrors` 里（`map[脚本名]错误信息`）。
   查日志时按 logger 名 `lua_plugin` 或消息 `lua plugin compile failed` 过滤。
3. **入口函数是不是全局的 `handle`。** `local function handle` 拿不到，会被判为 `ErrNoHandler`（记入 `failures` 统计，不产生判定）。
4. **阶段选对了没。** 想推翻内置拦截必须是 `post` + `allow`；想在 OWASP 之前决策必须是 `pre`。
5. **前面有没有别的脚本先给了判定。** 同阶段按 `priority` 升序执行，`Engine.Evaluate` 返回第一个有判定的结果，后面的脚本根本不会跑。
6. **返回的动作名是不是有效的。** 无法识别的动作被静默忽略。对照上面的动作表。
7. **是不是踩了 `ctx.query_params` 恒空 / `headers`、`tags` 不生效 / `tag` 无日志这几个坑。**

### 运行时报错与超时

每次脚本失败都会写一条 warn 日志（`Engine.Evaluate`）：

```
lua plugin failed, skipping   script=<脚本名> stage=<pre|post> err=<错误>
```

错误文案的几种形态：

| 文案 | 含义 |
| --- | --- |
| `luaplugin: "x" exceeded 50ms: context deadline exceeded` | 超时 |
| `luaplugin: "x" handle() failed: ...` | `handle` 内部报错 |
| `luaplugin: "x" init failed: ...` | 顶层代码报错 |
| `luaplugin: "x" panicked: ...` | panic 被 recover |
| `luaplugin: script must define a global function handle(ctx)` | 入口缺失 |

每个脚本的累计 `runs` / `failures` / `timeouts` / 平均耗时有三个查看入口，数据同源（`Engine.Stats()`），都是**进程级计数器，重启归零**：

- **管理页面**：Lua 策略页的运行时统计区，按脚本名与列表行对应，直接给出失败率与超时率
- **管理 API**：`GET /api/v1/lua-plugins/stats`，返回 `{"items":[{"name","stage","runs","failures","timeouts","avg_ms"}],"total"}`
- **Prometheus**：`/metrics` 上的 `openwaf_lua_script_runs_total`、`openwaf_lua_script_failures_total`、`openwaf_lua_script_timeouts_total`、`openwaf_lua_script_avg_duration_ms`，label 为 `{script,stage}`

用它判断某个脚本是不是在持续失败或持续超时。`avg_duration_ms` 尤其值得和超时阈值对照看：实测一个只做两次字符串比较的脚本平均耗时约 **0.13 ms**，而默认超时是 50 ms——两者差三个数量级时，出现的超时基本都来自运行时抖动而非脚本本身。

看 `Timeouts` 时请看**占比**而不是绝对值。默认超时是 50 ms 挂钟时间，而正常脚本只需一两百微秒，中间三个数量级的余量会被 GC 停顿、CPU 争抢这类运行时抖动吃掉——实测在 4000 次连续调用里出现过一次孤立超时，脚本本身并没有问题。偶发几次不用查；`Timeouts / Runs` 持续偏高才说明脚本真的太慢或卡在某个分支上。

### 判定和预期不符

用 `POST /lua-plugins/dry-run` 固定一个样例请求逐步排查。它返回确切的 `decision` 与 `elapsed_ms`，比看线上日志快得多。注意两点差异：

- dry-run 的 `query_params` 能传值，线上恒空。**别用 dry-run 验证依赖 `query_params` 的逻辑。**
- dry-run 里的 `phase` / `action` 是你自己填的，不代表内置引擎真的会那样判。想知道内置怎么判，看安全事件里的 `phase` 与 `action` 字段。

### 排查 KV

脚本写的键在 Redis 里的完整键名是 `openwaf:owaf:lua:<脚本里的键>`。想确认脚本到底写没写进去，按这个前缀扫。`kv.available()` 返回 false 说明 Redis 根本没配置或客户端未连上，此时所有 KV 调用都静默降级。

### 性能

脚本在数据面每请求同步执行，所以单次开销直接进 P99。

关键机制：**每次调用都会重新执行脚本的顶层代码**。`exec.go` 的 `callHandler` 每次都 `NewFunctionFromProto` + `PCall(0, MultRet)` 跑完整个 chunk，然后才取全局 `handle` 来调用。也就是说写在顶层的 `local T = {...}` **每个请求都会重建一遍**，哪怕 `handle` 第一行就 `return nil`。

在本机实测（`Engine.Evaluate` 共享状态机池，每脚本 2000~4000 次取均值）：

| 脚本形态 | 单次均值 |
| --- | --- |
| `function handle(ctx) return nil end`（固定开销下限） | 约 75 µs |
| 顶层两张十几项的常量表 + 两个闭包，`handle` 立刻返回 | 约 240 µs |
| 同样的表挪进 `handle`、放在早退判断之后 | 约 130 µs |
| `lua-examples/` 里的六个示例 | 约 150 ~ 275 µs |

约 75 µs 是拿不掉的固定成本（`resetGlobals` 清全局 + 跑顶层 chunk + 构造 `ctx` 表 + 调 `handle`）。剩下的差值几乎全是顶层常量表的重建开销。

据此的建议：

- **尽早 `return nil`。** 绝大多数请求应该在头几行就被排除掉，这是收益最大的一条。
- **热路径上的大常量表，放进 `handle` 的早退判断之后再构造**，而不是留在顶层——上表第二行和第三行的差距就是这个。表小（几项）时不值得为此牺牲可读性，`lua-examples/` 里的示例为了易读都用了顶层写法。
- 优先用 `string.find(s, needle, 1, true)`（plain 模式）做子串匹配，比模式匹配快，也避免特殊字符被当模式解析。
- 避免遍历 `ctx.body`——它可能有 48 KiB。
- 每个请求都调 `kv.incr` 就是每个请求加一次 Redis 往返。先用路径/方法过滤掉不需要计数的请求。
- 别指望顶层的可变状态跨请求存活。它每次都会被重建，且 `resetGlobals` 会清掉非白名单全局。跨请求状态只能用 `ctx.kv`。

检测引擎相关改动后按项目约定跑压测（`./blazehttp -t http://127.0.0.1:80 -c 40`），确认没有明显性能回退。

## 示例脚本

`lua-examples/` 目录下的脚本都经过 `luaplugin.DryRun` 验证，可直接复制到管理界面使用。使用前请按注释调整常量（路径、阈值、指纹、站点 ID）。

| 文件 | 阶段 | 用途 |
| --- | --- | --- |
| [01-ip-rate-limit.lua](./lua-examples/01-ip-rate-limit.lua) | `pre` | 用 `kv.incr` 做按 IP 的自定义限速 |
| [02-post-allow-false-positive.lua](./lua-examples/02-post-allow-false-positive.lua) | `post` | 对已确认误报的路径放行，推翻内置拦截 |
| [03-scanner-block.lua](./lua-examples/03-scanner-block.lua) | `pre` | 按 UA + 路径组合拦截扫描器 |
| [04-ja4-client-classify.lua](./lua-examples/04-ja4-client-classify.lua) | `pre` | 基于 TLS JA4 指纹识别与分流客户端 |
| [05-observe-suspicious.lua](./lua-examples/05-observe-suspicious.lua) | `pre` | 给可疑请求打观察记录而不拦截 |
| [06-per-site-policy.lua](./lua-examples/06-per-site-policy.lua) | `pre` | 用 `ctx.site_id` 按站点区分策略 |

## 常量速查表

| 项 | 值 | 定义位置 |
| --- | --- | --- |
| 入口函数名 | `handle` | `exec.go` `handlerName` |
| 默认执行超时 | 50 ms | `runtime.go` `defaultTimeout` |
| 单脚本超时可配范围 | 0 ~ 1000 ms | `admin/system/lua_plugin.go` `luaMaxTimeoutMS` |
| 脚本源码上限 | 256 KiB | `runtime.go` `maxScriptBytes` |
| 请求体可见上限 | 48 KiB | `dataplane/handler.go` `maxWAFBody` |
| KV 键前缀 | `owaf:lua:` | `api.go` `kvKeyPrefix` |
| KV 键长上限 | 256 字节 | `api.go` `kvMaxKeyLen` |
| KV 值大小上限 | 64 KiB | `api.go` `kvMaxValueLen` |
| KV 默认 TTL | 5 分钟 | `api.go` `kvDefaultTTL` |
| KV TTL 上限 | 24 小时 | `api.go` `kvMaxTTL` |
| Redis 实际键前缀 | `openwaf:` | `cache/redis_kv.go` `redisPrefix` |
| 同阶段执行顺序 | `priority ASC, id ASC` | `snapshot/lua.go` |
| 描述字段上限 | 512 字符 | `store/lua_plugin.go` |
