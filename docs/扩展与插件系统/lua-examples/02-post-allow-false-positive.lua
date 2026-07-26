--[[
用途：对已确认的误报定点放行。
阶段：post —— **只有 post 阶段的 allow 能推翻内置拦截**，pre 阶段做不到
      （那时内置检测还没跑）。

工作原理：
  post 阶段在整条管道跑完之后执行，能读到内置判定：
    ctx.phase  = 给出判定的阶段名（如 owasp_default、cve_detection、signature）
    ctx.action = 判定的动作名（内置未命中任何规则时为空串）
  返回 allow 会清空内置判定，请求继续走向上游。返回其他动作只在内置**没有**
  给出终止判定时才生效 —— 这是为了防止脚本把 drop 降级成 redirect，绕过内置
  的终止优先级语义。

注意点：
  1. 这是在关掉针对某个路径的防护，放行条件写得越窄越好。建议同时约束
     path、phase、method，跨站点部署时再加 host 或 ctx.site_id。
  2. ctx.path 是原始未解码路径。这里用精确等值比较，不用前缀或模式匹配 ——
     前缀匹配会让 /api/report/render/../../secret 之类的路径一起被放行。
  3. 放行前请先确认真的是误报：在安全事件里看 phase、rule_id_str 与 match_desc，
     能定位到具体规则的话，优先用误报管理/规则例外，而不是整条路径放行。
]]

-- 已确认的误报清单。method 为 nil 表示不限方法。
local FALSE_POSITIVES = {
  { path = "/api/report/render",    phase = "owasp_default", method = "POST" },
  { path = "/api/template/preview", phase = "owasp_default", method = "POST" },
  { path = "/admin/rules/import",   phase = "owasp_default", method = "POST" },
}

function handle(ctx)
  -- 内置没拦，就没什么要放行的
  if ctx.action ~= "intercept" then
    return nil
  end

  for _, fp in ipairs(FALSE_POSITIVES) do
    if ctx.path == fp.path
      and ctx.phase == fp.phase
      and (fp.method == nil or ctx.method == fp.method)
    then
      return {
        action = "allow",
        message = "lua post: confirmed false positive on " .. fp.path ..
                  " (blocked by " .. fp.phase .. ")",
      }
    end
  end

  return nil
end
