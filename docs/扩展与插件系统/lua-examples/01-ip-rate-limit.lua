--[[
用途：按客户端 IP 对指定路径前缀做自定义限速。
阶段：pre（放在 OWASP 之前，超限请求不必再跑昂贵检测）

注意点：
  1. ctx.kv.incr 的窗口是「空闲过期」语义，不是固定窗口 —— cache.RedisKV.Incr
     每次调用都会重置 TTL。所以持续打请求的 IP 计数不会清零，该 IP 停手
     WINDOW_SECONDS 秒之后计数才消失。想要「每分钟整点清零」这种固定窗口，
     脚本里做不到（沙箱禁用了 os 库，拿不到时钟），请用内置的请求速率限制阶段。
  2. Redis 未配置时 ctx.kv.available() 返回 false，此处降级为不判定 —— 拿不到
     计数就不做限速，交给内置阶段处理，而不是误拦。
  3. ctx.kv.* 是普通函数不是方法，必须用点号调用（ctx.kv.incr(...)）。
     用冒号会把 kv 表本身当成第一个参数传进去，导致脚本执行报错。
  4. 先按路径过滤再计数，避免给每个请求都加一次 Redis 往返。
]]

-- 需要限速的路径前缀
local PATH_PREFIX = "/api/"

-- 窗口内允许的最大请求数
local MAX_REQUESTS = 100

-- 空闲过期秒数：该 IP 停止请求这么久之后计数清零。上限 86400（24 小时），
-- 超出会被运行时钳制。
local WINDOW_SECONDS = 60

function handle(ctx)
  -- 只对目标路径计数
  if string.sub(ctx.path, 1, #PATH_PREFIX) ~= PATH_PREFIX then
    return nil
  end

  -- 客户端 IP 解析失败时为空串，无从计数
  if ctx.client_ip == "" then
    return nil
  end

  -- Redis 不可用：降级为不判定
  if not ctx.kv.available() then
    return nil
  end

  -- 键会自动加上 owaf:lua: 前缀（Redis 里的完整键是 openwaf:owaf:lua:rl:api:<ip>）
  local count = ctx.kv.incr("rl:api:" .. ctx.client_ip, WINDOW_SECONDS)

  -- 自增失败（Redis 超时、键非法等）：同样降级为不判定
  if count == nil then
    return nil
  end

  if count > MAX_REQUESTS then
    return {
      action = "rate_limit",
      message = "lua rate limit: " .. ctx.client_ip .. " reached " .. tostring(count) ..
                " requests on " .. PATH_PREFIX .. " (limit " .. tostring(MAX_REQUESTS) .. ")",
      status_code = 429,
    }
  end

  return nil
end
