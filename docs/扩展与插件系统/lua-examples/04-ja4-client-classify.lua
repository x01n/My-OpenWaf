--[[
用途：基于 TLS JA4 指纹识别客户端，对已知恶意栈拦截、对未知栈留观察记录。
阶段：pre

前置条件：
  JA4 只在 TLS/QUIC 监听器上有值。明文 HTTP 请求、或指纹采集不可用时
  ctx.tls.ja4 为空串，脚本必须先判空再用，否则会把所有明文请求一起误判。

JA4 全串格式：ja4_a .. "_" .. ja4_b .. "_" .. ja4_c
  ja4_a 共 10 个字符：
    第 1 位     传输协议    t = TCP/TLS 监听器，q = QUIC/HTTP3 监听器
    第 2-3 位   TLS 版本    13 / 12 / 11 / 10 / 00（未知）
    第 4 位     SNI         d = 带 SNI，i = 无 SNI（直接按 IP 建连）
    第 5-6 位   密码套件数  两位十进制，去 GREASE 后计数，上限 99
    第 7-8 位   扩展数      两位十进制，去 GREASE 后计数，上限 99
    第 9-10 位  首个 ALPN   取 ALPN 串首字符+末字符：h2 → h2、http/1.1 → h1；
                            无 ALPN 时为 00
  ja4_b、ja4_c 各为 12 个十六进制字符（截断的 SHA-256）
  例：t13d1516h2_8daaf6152771_e5627efa2ab1

注意点：
  1. 下面两张指纹表**默认是空的**，必须填你自己环境里实测到的指纹。
     直接抄别处的清单会误伤 —— 指纹随客户端版本变化，同一个浏览器的不同
     大版本、不同操作系统都可能不同。
     采集方法：在安全事件/访问日志的 tls_ja4 字段里看，或先只留本脚本的
     observe 分支跑一段时间收集样本。
  2. 指纹不是身份凭证，可被刻意模仿。JA4 适合做分流与打分，不适合作为唯一的
     拦截依据 —— 所以未知指纹这里只 observe 不拦。
  3. TRUSTED_JA4 里的 allow 会短路 OWASP/CVE/Bot 等**全部**后续检测。只在确实
     需要给可信客户端省开销时才用，且要清楚一旦指纹被模仿就等于绕过全部防护。
     不确定的话把那一段改成 return nil。
]]

-- 已确认恶意/不允许访问的完整 JA4 指纹 → 说明。填入自己环境实测到的值。
local BLOCKED_JA4 = {
  -- ["t13d1516h2_8daaf6152771_e5627efa2ab1"] = "内部压测工具，禁止打生产",
}

-- 已知可信的完整 JA4 指纹 → 说明（例如自家 App、监控探针）。
-- 谨慎填写：命中会跳过全部后续检测。
local TRUSTED_JA4 = {
  -- ["t13d1517h2_8daaf6152771_02713d6af862"] = "自家移动端 App",
}

-- 需要观察未知客户端的路径前缀。设为 "" 表示不做这项观察。
local WATCH_PREFIX = "/api/"

function handle(ctx)
  local ja4 = ctx.tls.ja4

  -- 明文 HTTP，或指纹采集不可用：本脚本无从判断
  if ja4 == "" then
    return nil
  end

  local blocked = BLOCKED_JA4[ja4]
  if blocked then
    return {
      action = "intercept",
      message = "lua ja4 block: " .. blocked .. " [" .. ja4 .. "]",
      status_code = 403,
    }
  end

  if TRUSTED_JA4[ja4] then
    return { action = "allow", message = "lua ja4: trusted client [" .. ja4 .. "]" }
  end

  -- 第 4 位为 i 表示握手里没有 SNI，即客户端直接按 IP 建连。
  -- 正常浏览器访问域名一定带 SNI，所以这通常是扫描器或探测工具。
  if string.sub(ja4, 4, 4) == "i" then
    return {
      action = "observe",
      message = "lua ja4 watch: TLS handshake without SNI [" .. ja4 .. "]",
    }
  end

  -- 老版本 TLS：第 2-3 位是 10/11 说明客户端只支持 TLS 1.0/1.1
  local version = string.sub(ja4, 2, 3)
  if version == "10" or version == "11" then
    return {
      action = "observe",
      message = "lua ja4 watch: obsolete TLS " .. version .. " client [" .. ja4 .. "]",
    }
  end

  -- 其余未知指纹在关注路径上留一条观察记录，便于收集样本
  if WATCH_PREFIX ~= "" and string.sub(ctx.path, 1, #WATCH_PREFIX) == WATCH_PREFIX then
    return {
      action = "observe",
      message = "lua ja4 watch: unknown fingerprint [" .. ja4 .. "]",
    }
  end

  return nil
end
