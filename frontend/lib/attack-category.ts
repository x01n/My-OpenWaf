/**
 * 命中防护模块（category）到中文标签的映射。
 *
 * 与后端 pipeline phase / 引擎产出的 category 值保持一致。
 * 未知值原样返回，避免因新增分类导致 UI 空白。
 */
const CATEGORY_LABELS_ZH: Record<string, string> = {
  owasp: "OWASP 攻击",
  cve: "CVE 漏洞",
  cve_general: "通用 CVE 漏洞",
  cve_java: "Java CVE 漏洞",
  cve_php: "PHP CVE 漏洞",
  cve_node: "Node.js CVE 漏洞",
  general: "通用漏洞",
  java: "Java 漏洞",
  php: "PHP 漏洞",
  node: "Node.js 漏洞",
  bot: "Bot 检测",
  bot_malicious: "恶意 Bot 检测",
  bot_suspicious: "可疑 Bot 检测",
  bot_detection: "Bot 检测",
  rate_limit: "频率限制",
  error_rate_limit: "错误率限制",
  ip_rep: "IP 声誉 / 黑名单",
  blacklist: "黑名单",
  auto_ban: "自动封禁",
  access: "访问控制",
  anti_replay: "防重放",
  replay: "重放检测",
  tls: "TLS 检测",
  tls_sni: "TLS SNI 检测",
  browser_sign: "浏览器签名",
  lua_plugin: "Lua 插件",
  owasp_default: "OWASP 检测",
  cve_detection: "CVE 检测",
  whitelist: "白名单",
  site_blacklist: "站点黑名单",
  signature: "特征签名",
  custom: "自定义规则",
}

const PHASE_LABELS_ZH: Record<string, string> = {
  tls: "TLS",
  anti_replay: "防重放",
  rate_limit: "频率限制",
  ip_reputation: "IP 声誉",
  bot_detection: "Bot 检测",
  owasp_default: "OWASP 检测",
  cve_detection: "CVE 检测",
  browser_sign: "浏览器签名",
  error_rate_limit: "错误率限制",
  lua_pre: "Lua 前置",
  lua_post: "Lua 后置",
  maintenance: "维护",
  acl: "访问控制",
  signature: "特征签名",
  custom: "自定义规则",
}

/**
 * 将后端返回的阶段代码转换为可读名称。
 *
 * @param phase 后端返回的 phase 值
 * @returns 对应中文标签；未知值原样返回，空值返回"未知"
 */
export function phaseLabel(phase: string | undefined | null): string {
  if (!phase) return "未知"
  return PHASE_LABELS_ZH[phase] ?? phase
}

/**
 * OWASP 类别代码到中文名称的映射。
 */
const OWASP_CATEGORY_LABELS_ZH: Record<string, string> = {
  sqli: "SQL 注入检测",
  xss: "XSS 攻击检测",
  file_upload: "文件上传检测",
  path_traversal: "文件包含检测",
  cmd_injection: "命令注入检测",
  template_injection: "模板注入检测",
  jndi_injection: "JNDI 注入检测",
  expression_language: "表达式语言注入检测",
  deserialization: "反序列化检测",
  webshell: "WebShell 检测",
  revshell: "反弹 Shell 检测",
  ssrf: "SSRF 检测",
  xxe: "XXE 检测",
  ldap_injection: "LDAP 注入检测",
  nosql_injection: "NoSQL 注入检测",
  crlf_injection: "CRLF 注入检测",
  graphql_injection: "GraphQL 注入检测",
  protocol_violation: "协议违规检测",
}

/**
 * 将后端返回的攻击分类代码转换为中文可读名称。
 *
 * @param category 命中防护模块代码，例如 "owasp"、"cve"
 * @returns 对应中文标签；未知代码原样返回，空值返回"未知"
 */
export function owaspCategoryLabel(
  category: string | undefined | null
): string {
  if (!category) return "未知"
  return (
    OWASP_CATEGORY_LABELS_ZH[category] ??
    CATEGORY_LABELS_ZH[category] ??
    category
  )
}

export function categoryLabel(category: string | undefined | null): string {
  if (!category) return "未知"
  return (
    CATEGORY_LABELS_ZH[category] ??
    OWASP_CATEGORY_LABELS_ZH[category] ??
    category
  )
}

export function severityLabel(severity: string | undefined | null): string {
  if (!severity) return "未知"
  const value = severity.toLowerCase()
  const labels: Record<string, string> = {
    critical: "严重",
    high: "高危",
    medium: "中危",
    mid: "中危",
    low: "低危",
    info: "提示",
    informational: "提示",
  }
  return labels[value] ?? severity
}
