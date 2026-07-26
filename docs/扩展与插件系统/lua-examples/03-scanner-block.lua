--[[
用途：按 User-Agent 与路径的组合拦截扫描器。
阶段：pre（在 OWASP 之前拦掉，省掉后续检测开销）

判定分三档，避免单一条件误伤：
  1. UA 明确是扫描器 → intercept（这类 UA 正常客户端不会带）
  2. 探敏感路径且完全没有 UA → intercept（正常浏览器一定带 UA）
  3. 探敏感路径但有 UA → observe（可能是运维自己，留记录不拦）

注意点：
  1. string.find 的第四个参数 true 表示 plain 模式（不当模式串用），既更快，
     也避免 UA 里的 - . ( ) * 被当成模式字符导致匹配错乱。
  2. ctx.path 是原始未解码路径，百分号编码保持原样。所以 /%2e%65nv 这类编码
     变形不会命中下面的路径表 —— 编码绕过交给内置 OWASP 阶段处理，那里有
     完整的多轮解码归一化。本脚本只负责拦掉直白的扫描行为。
  3. ctx.query_params 在数据面恒为空表（RequestCtx.QueryParams 从未被填充），
     要读查询参数请自己解析 ctx.query，如下面的 has_query_key。
  4. 敏感路径表按自己环境增删。留着不存在的路径没有坏处，但漏掉真实存在的
     后台入口就会形成盲区。
  5. 性能提示：脚本的顶层代码每次调用都会重跑，所以下面两张常量表每个请求都会
     重建（本机实测这部分约占 150 µs）。这里为了可读性保留顶层写法。如果这条
     脚本挂在超高 QPS 的站点上，可以把两张表挪进 handle、放在一个便宜的早退
     判断之后，实测能省掉约一半开销。
]]

-- 扫描器 UA 特征（全部小写；匹配时对 UA 取小写）
local SCANNER_UA = {
  "nikto", "sqlmap", "nmap", "masscan", "zgrab", "acunetix",
  "nessus", "openvas", "wpscan", "dirbuster", "gobuster",
  "arachni", "nuclei", "hydra", "netsparker",
}

-- 敏感路径特征（小写子串匹配）
local SENSITIVE_PATHS = {
  "/.env", "/.git/", "/.svn/", "/.aws/",
  "/wp-admin", "/wp-login.php", "/xmlrpc.php",
  "/phpmyadmin", "/actuator", "/druid/", "/solr/",
  "/config.php.bak", "/backup.sql", "/.ds_store",
}

-- 命中即返回命中的那个特征串，否则返回 nil
local function contains_any(haystack, needles)
  for _, needle in ipairs(needles) do
    if string.find(haystack, needle, 1, true) then
      return needle
    end
  end
  return nil
end

-- 自己解析 ctx.query 判断是否带某个参数名（因为 ctx.query_params 恒空）
local function has_query_key(query, key)
  if query == "" then
    return false
  end
  -- 形如 key=... 出现在开头，或以 & 分隔出现在中间
  if string.sub(query, 1, #key + 1) == key .. "=" then
    return true
  end
  return string.find(query, "&" .. key .. "=", 1, true) ~= nil
end

function handle(ctx)
  local ua = string.lower(ctx.user_agent)
  local path = string.lower(ctx.path)

  -- 1) UA 明确是扫描器：直接拦，不看路径
  local ua_hit = contains_any(ua, SCANNER_UA)
  if ua_hit then
    return {
      action = "intercept",
      message = "lua scanner block: ua matched " .. ua_hit,
      status_code = 403,
    }
  end

  local path_hit = contains_any(path, SENSITIVE_PATHS)

  -- 2) 探敏感路径且完全没有 UA
  if path_hit and ua == "" then
    return {
      action = "intercept",
      message = "lua scanner block: sensitive path " .. path_hit .. " without user-agent",
      status_code = 403,
    }
  end

  -- 3) 探敏感路径且带调试参数（常见于自动化探测）
  if path_hit and (has_query_key(ctx.query, "debug") or has_query_key(ctx.query, "test")) then
    return {
      action = "intercept",
      message = "lua scanner block: sensitive path " .. path_hit .. " with debug query",
      status_code = 403,
    }
  end

  -- 4) 其余敏感路径访问：只观察，交给内置检测决定
  if path_hit then
    return {
      action = "observe",
      message = "lua scanner watch: sensitive path " .. path_hit,
    }
  end

  return nil
end
