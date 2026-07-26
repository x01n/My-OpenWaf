--[[
用途：给可疑请求留一条观察记录，不拦截。用于上线新拦截规则之前评估误伤面。
阶段：pre —— 这是唯一会真正落库的观察组合。

为什么用 observe 而不是 tag：
  action = "tag" 虽然也是非终止动作，但 action.Result.ShouldLog() 对 tag 返回
  false，它既不会被 pipeline.Run 收进 ObserveHits，也不会写安全事件 —— 当前
  完全没有可观测效果。
  而 pre 阶段返回 observe 会被收进 ObserveHits，由数据面写一条安全事件：
    action     = "observe"
    phase      = "lua_pre"
    category   = "lua_plugin"
    match_desc = 你在 message 里写的内容
  post 阶段返回 observe 也不会产生日志（数据面只对终止判定写事件），所以
  观察类脚本一定要放在 pre 阶段。

注意点：
  1. observe 是非终止动作，管道会继续跑后续阶段，内置检测照常生效，请求
     该拦的还是会被拦。
  2. 同阶段只有第一个给出判定的脚本生效。本脚本返回 observe 会让同阶段排在
     它后面的脚本不再执行 —— 观察类脚本建议把 priority 设大（靠后执行），
     避免挡住真正做拦截的脚本。
  3. message 会进安全事件的 match_desc，把命中原因写清楚，便于事后统计。
]]

-- 可疑但不足以直接拦截的请求头（键必须小写：ctx.headers 的键一律是小写）
local SUSPICIOUS_HEADERS = {
  "x-forwarded-host",  -- 常见于 Host 头注入尝试
  "x-original-url",    -- 常见于反向代理路径绕过尝试
  "x-rewrite-url",
  "x-http-method-override",
}

-- 可疑的 Content-Type（正常业务基本不用，反序列化攻击常用）
local SUSPICIOUS_CONTENT_TYPES = {
  "application/x-java-serialized-object",
  "application/x-php-serialized",
  "application/x-amf",
}

-- 请求体检查窗口上限，与数据面的 maxWAFBody 一致
local BODY_INSPECTION_CAP = 48 * 1024

local function first_suspicious_header(ctx)
  for _, name in ipairs(SUSPICIOUS_HEADERS) do
    if ctx.headers[name] ~= nil then
      return name
    end
  end
  return nil
end

function handle(ctx)
  local reasons = {}

  local hdr = first_suspicious_header(ctx)
  if hdr then
    reasons[#reasons + 1] = "header:" .. hdr
  end

  local content_type = string.lower(ctx.content_type)
  for _, bad in ipairs(SUSPICIOUS_CONTENT_TYPES) do
    if string.find(content_type, bad, 1, true) then
      reasons[#reasons + 1] = "content-type:" .. bad
      break
    end
  end

  -- 完全没有 User-Agent，且不是探活请求
  if ctx.user_agent == "" and ctx.path ~= "/health" and ctx.path ~= "/healthz" then
    reasons[#reasons + 1] = "empty-user-agent"
  end

  -- 请求体已顶到检查窗口上限，可能是刻意用大体积把载荷推到窗口之外
  if #ctx.body >= BODY_INSPECTION_CAP then
    reasons[#reasons + 1] = "body-at-inspection-cap"
  end

  -- 声明了 JSON 但体不是以 { 或 [ 开头
  if string.find(content_type, "application/json", 1, true) and #ctx.body > 0 then
    local first = string.sub(ctx.body, 1, 1)
    if first ~= "{" and first ~= "[" then
      reasons[#reasons + 1] = "json-content-type-with-non-json-body"
    end
  end

  if #reasons == 0 then
    return nil
  end

  return {
    action = "observe",
    message = "lua watch: " .. table.concat(reasons, ", "),
  }
end
