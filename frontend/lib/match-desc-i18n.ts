/**
 * 安全事件 match_desc 字段的历史英文值本地化映射。
 *
 * 后端 `internal/waf/owasp/owasp.go` 与 `owasp_extended.go` 的 `OWASPHit.Desc`
 * 已全部改为中文，经 `internal/core/rules/phases.go` 的 `MatchDesc: hit.Desc`
 * 原样落库到 `security_events.match_desc`。但数据库里已存在的历史事件仍保存
 * 着改动前的英文原文，且这些记录不会被回填改写。
 *
 * 因此这里维护一张「改动前英文原文 -> 改动后中文」的映射表：key 一律是英文，
 * 新写入的中文值查不到 key，按未命中规则原样返回，正好是期望结果。
 *
 * 注：`internal/dataplane/handler.go` 仍有一处独立产出
 * `"opaque encoded body without content-type"` 的英文 MatchDesc，不在 owasp
 * 包内，本表同样兜住它。
 */

/**
 * 全等映射：Desc 为固定字面量、不含运行时拼接后缀的条目。
 */
const EXACT_DESC_MAP: Readonly<Record<string, string>> = {
  // owasp.go
  "bare CR/LF in URL path": "URL 路径中的裸 CR/LF 字符",
  "opaque encoded body without content-type": "无 content-type 的不透明编码请求体",
  "Cisco translation-table path traversal pattern":
    "Cisco translation-table 路径遍历模式",
  "Java serialization magic bytes (URL-encoded)": "Java 序列化魔数（URL 编码）",
  "null byte in filename": "文件名中包含空字节",
  "path traversal in filename": "文件名中包含路径遍历",
  "null byte in path filename": "路径文件名中包含空字节",
  "F5 BIG-IP RCE endpoint": "F5 BIG-IP 远程代码执行端点",
  "Liferay JSONWS deserialization endpoint": "Liferay JSONWS 反序列化端点",
  "Apache OFBiz webtools RCE endpoint": "Apache OFBiz webtools 远程代码执行端点",
  "Confluence OGNL injection endpoint": "Confluence OGNL 注入端点",
  "Cisco ASA path traversal": "Cisco ASA 路径遍历",
  "ThinkPHP invokefunction RCE": "ThinkPHP invokefunction 远程代码执行",
  "Atlassian gadgets SSRF endpoint": "Atlassian gadgets SSRF 端点",
  "Nexus Repository Manager RCE": "Nexus Repository Manager 远程代码执行",
  "Coremail config leak": "Coremail 配置泄露",
  ".git directory access": ".git 目录访问",
  "Jenkins Script Security RCE": "Jenkins Script Security 远程代码执行",
  "OFS XXE endpoint": "OFS XML 外部实体端点",
  "Semicolon path parameter bypass": "分号路径参数绕过",
  "Joomla API config information leak": "Joomla API 配置信息泄露",
  "Nexus Repository Manager API": "Nexus Repository Manager API 访问",
  "ExtDirect RCE endpoint": "ExtDirect 远程代码执行端点",
  "webshell/code execution signals": "WebShell/代码执行特征",
  "reverse shell / remote execution signals": "反弹 Shell / 远程执行特征",
  "XSS signals": "XSS 特征",
  "SQL injection signals": "SQL 注入特征",
  "path traversal signals": "路径遍历特征",
  // owasp_extended.go
  "SSRF signals": "SSRF 特征",
  "command injection signals": "命令注入特征",
  "XML external entity signals": "XML 外部实体特征",
  "LDAP injection signals": "LDAP 注入特征",
  "NoSQL injection signals": "NoSQL 注入特征",
  "template injection signals": "模板注入特征",
  "htaccess override attempt": "htaccess 覆写尝试",
  "content-type mismatch for image": "图片文件的 content-type 不匹配",
  "executable extension with image content-type":
    "可执行扩展名伪装为图片 content-type",
  "JNDI/Log4Shell injection signals": "JNDI/Log4Shell 注入特征",
  "CRLF injection / HTTP response splitting": "CRLF 注入 / HTTP 响应拆分",
  "expression language injection signals": "表达式语言注入特征",
  "Java serialization magic bytes": "Java 序列化魔数",
  "deserialization attack signals": "反序列化攻击特征",
  "request smuggling: CL+TE conflict": "请求走私：CL+TE 冲突",
  "duplicate content-length header": "重复的 content-length 头",
  "CONNECT method (tunneling)": "CONNECT 方法（隧道）",
  "DEBUG method (ASP.NET diagnostics)": "DEBUG 方法（ASP.NET 诊断）",
  "PATCH method (uncommon)": "PATCH 方法（不常见）",
  "OPTIONS method (non-CORS)": "OPTIONS 方法（非 CORS 预检）",
  "GraphQL introspection/injection signals": "GraphQL 内省/注入特征",
  "request rate limit exceeded": "请求频率限制已超出",
  "replayed nonce detected": "检测到重复使用的 nonce",
  "expired or invalid nonce": "nonce 已过期或无效",
  "request replay detected or invalid nonce": "检测到请求重放或无效 nonce",
  "error rate limit exceeded": "错误率限制已超出",
  "invalid browser env fingerprint": "浏览器环境指纹无效",
  "browser env hard-fail": "浏览器环境校验失败",
  "known good bot": "已知可信 Bot",
  "pre-screen passed": "预筛选通过",
  "two-phase score": "两阶段评分",
  "maintenance mode active": "维护模式已启用",
  "auto-banned": "自动封禁",
  "port_scanner": "端口扫描器",
  "web_scanner": "Web 扫描器",
  "dir_bruteforcer": "目录爆破工具",
  "vuln_scanner": "漏洞扫描器",
  "sqli_tool": "SQL 注入工具",
  "password_cracker": "密码破解工具",
  "malicious_crawler": "恶意爬虫",
  "exploit_tool": "漏洞利用工具",
  "web_app_scanner": "Web 应用扫描器",
  "cms_scanner": "CMS 扫描器",
  "recon_bot": "侦察 Bot",
  "scraper_lib": "抓取库",
  "http_lib": "HTTP 客户端库",
  "cli_tool": "命令行工具",
  "api_client": "API 客户端",
  "empty_ua": "User-Agent 为空",
  "short_ua": "User-Agent 过短",
  "no_accept": "缺少 Accept",
  "unusual_accept": "Accept 异常",
  "no_accept_language": "缺少 Accept-Language",
  "no_accept_encoding": "缺少 Accept-Encoding",
  "automation_lib_ua": "自动化库 User-Agent",
  "fake_mozilla": "伪造 Mozilla 标识",
  "conn_close": "连接使用 close",
  "no_cookie_post": "POST 请求缺少 Cookie",
  "scanner_path": "扫描器路径特征",
  "post_no_referer": "POST 请求缺少 Referer",
  "chrome_without_safari": "Chrome User-Agent 缺少 Safari 标识",
  "legacy_tls_version": "旧版 TLS",
  "chrome_tls_http_mismatch": "Chrome TLS 与 HTTP 特征不匹配",
  "firefox_encoding_mismatch": "Firefox 编码特征不匹配",
}

/**
 * 前缀映射：后端以 `前缀字面量 + 运行时值` 拼接生成的 Desc。
 *
 * 这类历史值带动态后缀（扩展名、请求头名、HTTP 方法名），全等匹配永远命不中，
 * 必须按前缀替换并把后缀原样拼回中文前缀之后。
 * 数组顺序按 key 长度降序，避免任一 key 是另一 key 前缀时匹配到较短者。
 */
const PREFIX_DESC_MAP: ReadonlyArray<readonly [string, string]> = [
  ["site whitelist: ", "站点白名单："],
  ["site blacklist: ", "站点黑名单："],
  ["whitelist: ", "白名单："],
  ["ip reputation: ", "IP 声誉："],
  ["tls_sni=", "TLS SNI="],
  ["auto_ban: ", "自动封禁："],
  ["dangerous file extension: ", "危险文件扩展名："],
  ["double extension in path: ", "路径中的双扩展名："],
  ["double extension upload: ", "双扩展名上传："],
  ["dangerous HTTP method: ", "危险 HTTP 方法："],
  ["oversized header: ", "超长请求头："],
  ["WebDAV method: ", "WebDAV 方法："],
]

/**
 * 按当前界面语言本地化安全事件的 match_desc 值。
 *
 * 英文界面保留后端原文；中文界面将历史英文描述映射为中文，并兼容已经是中文的新值。
 *
 * @param desc 后端返回的 match_desc 原值，可能为 undefined/null（字段可选）
 * @param language i18next 当前解析语言（优先传入 resolvedLanguage）
 * @returns 中文界面命中映射时返回中文文案；其他情况原样返回。
 *          入参为空值时返回空字符串，调用方自行决定占位符。
 */
export function localizeMatchDesc(
  desc: string | null | undefined,
  language: string
): string {
  if (!desc) return ""
  if (!language.startsWith("zh")) return desc

  const exact = EXACT_DESC_MAP[desc]
  if (exact !== undefined) return exact
  for (const [prefix, localized] of PREFIX_DESC_MAP) {
    if (desc.startsWith(prefix)) {
      return localized + desc.slice(prefix.length)
    }
  }
  return desc
}
