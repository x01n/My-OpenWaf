--[[
用途：用 ctx.site_id 按站点区分策略。
阶段：pre

为什么必须在脚本里判站点：
  lua_plugins 表有 site_id 列，管理 API 也能读写它，但 internal/snapshot/lua.go
  的 loadLuaPlugins 只按 enabled 过滤、不按站点过滤，编译出的 luaplugin.Script
  也不携带站点信息。所以 site_id 目前只是一个标注字段，**不影响脚本实际生效
  范围** —— 一个启用的脚本会对所有站点执行。按站点区分只能靠 ctx.site_id。

注意点：
  1. 站点 ID 是数据库主键，从管理界面的站点列表或 GET /api/v1/sites 取。
     ID 会随环境变化，别把开发环境的 ID 直接搬到生产。
  2. 没有配置的站点走默认分支，务必让默认分支是安全的 —— 这里返回 nil
     （不判定，交给内置检测），而不是 allow。
  3. require_tls 依据的是 ctx.tls.version 是否为空。如果本 WAF 前面还有一层
     反向代理做 TLS 卸载，那么到 WAF 这里本来就是明文，这个判断会把所有请求
     都跳转，形成重定向循环。这种部署下请改成检查上游传来的协议头，
     例如 ctx.headers["x-forwarded-proto"] ~= "https"。
  4. ctx.host 可能带非默认端口（如 example.com:8443），拼 redirect_to 时注意。
]]

-- 按站点 ID 配置策略。请替换成你环境里的真实站点 ID。
local SITE_POLICY = {
  -- 站点 1：对外公开站点，管理后台路径一律拦掉
  [1] = {
    blocked_prefixes = { "/admin", "/manage", "/actuator" },
    require_tls      = true,
  },
  -- 站点 2：内部系统，只要求走 TLS，不限制路径
  [2] = {
    blocked_prefixes = {},
    require_tls      = true,
  },
  -- 站点 3：遗留系统，仍有明文 HTTP 客户端，不强制 TLS，只挡敏感文件
  [3] = {
    blocked_prefixes = { "/.git/", "/.env" },
    require_tls      = false,
  },
}

local function has_prefix(s, prefix)
  return string.sub(s, 1, #prefix) == prefix
end

function handle(ctx)
  local policy = SITE_POLICY[ctx.site_id]

  -- 未配置的站点：不判定，交给内置检测
  if policy == nil then
    return nil
  end

  for _, prefix in ipairs(policy.blocked_prefixes) do
    if has_prefix(ctx.path, prefix) then
      return {
        action = "intercept",
        message = "lua site policy: site " .. tostring(ctx.site_id) ..
                  " blocks prefix " .. prefix,
        status_code = 403,
      }
    end
  end

  -- 要求 TLS 的站点上，明文请求跳转到 HTTPS
  if policy.require_tls and ctx.tls.version == "" then
    return {
      action = "redirect",
      message = "lua site policy: site " .. tostring(ctx.site_id) .. " requires TLS",
      redirect_to = "https://" .. ctx.host .. ctx.path,
      status_code = 301,
    }
  end

  return nil
end
