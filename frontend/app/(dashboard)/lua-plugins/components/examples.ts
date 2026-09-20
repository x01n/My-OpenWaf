import type { LuaPluginStage } from "@/lib/types"

/**
 * @typedef {object} LuaExample
 * @property {string} id 唯一标识，同时用作 i18n 子键
 * @property {LuaPluginStage} stage 该示例适用的阶段
 * @property {string} source Lua 源码
 */
export interface LuaExample {
  id: string
  stage: LuaPluginStage
  source: string
}

/**
 * 可一键填入编辑区的示例脚本。
 *
 * 三段源码均已用后端 luaplugin.DryRun 实测通过（编译无错、判定符合预期），
 * 修改时请同步复验，不要凭 Lua 直觉改动。沙箱只开放 base/table/string/math；线上
 * Engine 还会在 KV 不可用时 fail-open，不执行该阶段的任何脚本。因此示例里不出现
 * io、os、require、协程等能力。
 */
export const LUA_EXAMPLES: LuaExample[] = [
  {
    id: "rateLimit",
    stage: "pre",
    source: `-- 按客户端 IP 限速：60 秒空闲过期窗口内超过 100 次即触发 rate_limit。
-- 线上 KV 为 nil/不可用时 Engine 会跳过 Lua 阶段并 fail-open；
-- dry-run 会直接执行脚本，因此仍保留 available() 检查以准确展示降级分支。
function handle(ctx)
  if not ctx.kv.available() then
    return nil
  end

  local hits = ctx.kv.incr("rl:" .. ctx.client_ip, 60)
  if hits ~= nil and hits > 100 then
    return {
      action = "rate_limit",
      message = "per-ip rate limit exceeded",
      tags = { "lua_rate_limit" },
    }
  end

  return nil
end
`,
  },
  {
    id: "allowFalsePositive",
    stage: "post",
    source: `-- post 阶段：对内置引擎误报的接口放行。
-- 只有返回 allow 能推翻内置拦截；ctx.action 为内置判定，空串表示未拦截。
function handle(ctx)
  if ctx.action == "" then
    return nil
  end

  if ctx.method == "POST" and ctx.path == "/api/report" then
    return {
      action = "allow",
      message = "known false positive on report endpoint",
    }
  end

  return nil
end
`,
  },
  {
    id: "blockScanner",
    stage: "pre",
    source: `-- pre 阶段：在 OWASP 等昂贵检测之前拦掉明显的扫描器，省下检测开销。
-- headers/response_body 只会用于普通 Lua 终止响应；challenge/redirect/drop 不消费它们。
-- tags 会进入 action.Result，但当前没有独立的持久化日志字段。
function handle(ctx)
  local ua = string.lower(ctx.user_agent)
  local scanners = { "sqlmap", "nikto", "nessus", "acunetix" }

  for _, name in ipairs(scanners) do
    if string.find(ua, name, 1, true) ~= nil then
      return {
        action = "intercept",
        status_code = 403,
        message = "scanner blocked: " .. name,
        headers = {
          ["content-type"] = "application/json; charset=utf-8",
          ["x-owaf-policy"] = "lua-scanner",
        },
        response_body = '{"error":"request blocked by Lua policy"}',
        tags = { "lua_scanner" },
      }
    end
  end

  return nil
end
`,
  },
]

/**
 * 新建脚本时预填的骨架，给出最小可编译结构。
 */
export const LUA_SKELETON = `-- 返回 nil 表示不判定，请求继续走后续阶段。
function handle(ctx)
  return nil
end
`

/**
 * ctx 可读字段清单，用于帮助面板。
 *
 * 名称与后端 buildContextTable 逐一对应，不可臆改大小写或下划线。
 */
export const CTX_FIELDS: { name: string; type: string }[] = [
  { name: "ctx.request_id", type: "string" },
  { name: "ctx.client_ip", type: "string" },
  { name: "ctx.method", type: "string" },
  { name: "ctx.path", type: "string" },
  { name: "ctx.query", type: "string" },
  { name: "ctx.host", type: "string" },
  { name: "ctx.user_agent", type: "string" },
  { name: "ctx.site_id", type: "number" },
  { name: "ctx.content_type", type: "string" },
  { name: "ctx.body", type: "string" },
  { name: "ctx.headers", type: "table<string, string>" },
  { name: "ctx.query_params", type: "table<string, string>" },
  { name: "ctx.tls.version", type: "string" },
  { name: "ctx.tls.ja3", type: "string" },
  { name: "ctx.tls.ja4", type: "string" },
  { name: "ctx.tls.sni", type: "string" },
  { name: "ctx.phase", type: "string" },
  { name: "ctx.action", type: "string" },
]

/**
 * ctx.kv 提供的跨请求存储方法。
 */
export const KV_METHODS: { name: string; type: string }[] = [
  { name: "ctx.kv.available()", type: "boolean" },
  { name: "ctx.kv.get(key)", type: "string | nil" },
  { name: "ctx.kv.set(key, value, ttl?)", type: "boolean" },
  { name: "ctx.kv.delete(key)", type: "-" },
  { name: "ctx.kv.incr(key, ttl?)", type: "number | nil" },
]

/**
 * Lua Decision 输出限制，与后端 runtime.go/exec.go 的边界保持一致。
 */
export const LUA_DECISION_LIMITS = {
  stringBytes: 16 * 1024,
  responseBodyBytes: 16 * 1024,
  headerEntries: 256,
  headerValueBytes: 4 * 1024,
  tagEntries: 32,
  statusMin: 100,
  statusMax: 599,
} as const

/**
 * Lua 不得覆盖的敏感、逐跳及宿主控制响应头；比较时不区分大小写。
 */
export const LUA_BLOCKED_RESPONSE_HEADERS = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "www-authenticate",
  "proxy-authenticate",
  "connection",
  "keep-alive",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
  "location",
] as const

/**
 * 脚本可返回的合法动作。顺序按「放行 -> 观察 -> 验证 -> 拦截」的强度递进排列，
 * 取值本身对齐后端 action.IsValid 的白名单。
 */
export const LUA_ACTIONS = [
  "allow",
  "observe",
  "tag",
  "redirect",
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
  "rate_limit",
  "intercept",
  "drop",
] as const
