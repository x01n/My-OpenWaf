import type { LuaPluginStage } from "@/lib/types";

/**
 * @typedef {object} LuaExample
 * @property {string} id 唯一标识，同时用作 i18n 子键
 * @property {LuaPluginStage} stage 该示例适用的阶段
 * @property {string} source Lua 源码
 */
export interface LuaExample {
  id: string;
  stage: LuaPluginStage;
  source: string;
}

/**
 * 可一键填入编辑区的示例脚本。
 *
 * 三段源码均已用后端 luaplugin.DryRun 实测通过（编译无错、判定符合预期），
 * 修改时请同步复验，不要凭 Lua 直觉改动。沙箱只开放 base/table/string/math，
 * 因此示例里不出现 io、os、require、协程等能力。
 */
export const LUA_EXAMPLES: LuaExample[] = [
  {
    id: "rateLimit",
    stage: "pre",
    source: `-- 按客户端 IP 限速：60 秒窗口内超过 100 次请求即触发 rate_limit。
-- 依赖 ctx.kv；配置 Redis 后计数在多实例间共享。
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
function handle(ctx)
  local ua = string.lower(ctx.user_agent)
  local scanners = { "sqlmap", "nikto", "nessus", "acunetix" }

  for _, name in ipairs(scanners) do
    if string.find(ua, name, 1, true) ~= nil then
      return {
        action = "intercept",
        status_code = 403,
        message = "scanner blocked: " .. name,
        tags = { "lua_scanner" },
      }
    end
  end

  return nil
end
`,
  },
];

/**
 * 新建脚本时预填的骨架，给出最小可编译结构。
 */
export const LUA_SKELETON = `-- 返回 nil 表示不判定，请求继续走后续阶段。
function handle(ctx)
  return nil
end
`;

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
];

/**
 * ctx.kv 提供的跨请求存储方法。
 */
export const KV_METHODS: { name: string; type: string }[] = [
  { name: "ctx.kv.available()", type: "boolean" },
  { name: "ctx.kv.get(key)", type: "string | nil" },
  { name: "ctx.kv.set(key, value, ttl?)", type: "boolean" },
  { name: "ctx.kv.delete(key)", type: "-" },
  { name: "ctx.kv.incr(key, ttl?)", type: "number | nil" },
];

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
] as const;
