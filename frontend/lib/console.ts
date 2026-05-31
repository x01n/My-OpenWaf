import {
  AlertTriangle,
  Ban,
  BarChart3,
  Bot,
  Bug,
  FileText,
  FolderCog,
  Globe,
  Key,
  LayoutDashboard,
  List,
  ListChecks,
  Lock,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Zap,
  type LucideIcon,
} from "lucide-react"

export interface ConsoleNavItem {
  href: string
  label: string
  description: string
  icon: LucideIcon
  group: string
  enabled?: boolean
  exact?: boolean
  children?: ConsoleNavItem[]
}

export interface ConsoleNavGroup {
  title: string
  items: ConsoleNavItem[]
}

export const consoleNavGroups: ConsoleNavGroup[] = [
  {
    title: "",
    items: [
      {
        href: "/dashboard/",
        label: "统计报表",
        description: "流量分析、安全态势与防护报告。",
        icon: BarChart3,
        group: "概览",
      },
      {
        href: "/sites/",
        label: "防护应用",
        description: "管理站点接入、转发目标和站点级防护策略。",
        icon: Globe,
        group: "概览",
      },
      {
        href: "/protection/",
        label: "攻击防护",
        description: "配置 OWASP、CVE 和安全策略。",
        icon: Shield,
        group: "防护",
        children: [
          {
            href: "/rules/cve/",
            label: "CVE 规则",
            description: "CVE 检测规则管理。",
            icon: Bug,
            group: "防护",
          },
          {
            href: "/rules/owasp/",
            label: "OWASP 规则",
            description: "OWASP 规则管理。",
            icon: AlertTriangle,
            group: "防护",
          },
        ],
      },
      {
        href: "/rules/",
        label: "访问控制",
        description: "自定义 ACL 规则、路径匹配与 IP 黑白名单。",
        icon: List,
        group: "规则",
        exact: false,
        children: [
          {
            href: "/rules/",
            label: "自定义规则",
            description: "ACL 与自定义匹配规则。",
            icon: ListChecks,
            group: "规则",
            exact: false,
          },
          {
            href: "/ip-lists/",
            label: "IP 黑白名单",
            description: "按 IP 或 CIDR 管理黑白名单。",
            icon: List,
            group: "规则",
          },
        ],
      },
      {
        href: "/access-logs/",
        label: "请求日志",
        description: "检索请求明细、状态码、WAF 动作与 TLS 指纹。",
        icon: FileText,
        group: "日志",
      },
      {
        href: "/security-events/",
        label: "拦截日志",
        description: "查看拦截、观察、验证和限速命中的安全事件。",
        icon: ShieldAlert,
        group: "日志",
      },
      {
        href: "/cc-protection/",
        label: "CC 防护",
        description: "管理 CC 防护与频率限制策略。",
        icon: Zap,
        group: "防护",
        children: [
          {
            href: "/cc-protection/",
            label: "频率限制",
            description: "CC 防护规则。",
            icon: Zap,
            group: "防护",
          },
          {
            href: "/drop-policy/",
            label: "阻断策略",
            description: "管理主动断连策略。",
            icon: Ban,
            group: "防护",
          },
        ],
      },
      {
        href: "/security/",
        label: "人机验证",
        description: "验证码、5秒盾与连锁验证策略。",
        icon: ShieldCheck,
        group: "防护",
      },
      {
        href: "/bot-protection/",
        label: "Bot 防护",
        description: "Bot 检测、评分阈值与访问身份风险控制。",
        icon: Bot,
        group: "防护",
      },
      {
        href: "/settings/",
        label: "通用设置",
        description: "系统配置、证书管理与数据清理。",
        icon: Settings,
        group: "配置",
        children: [
          {
            href: "/certificates/",
            label: "证书管理",
            description: "维护 TLS 证书。",
            icon: Lock,
            group: "配置",
          },
          {
            href: "/error-pages/",
            label: "拦截页面",
            description: "自定义错误页面。",
            icon: TriangleAlert,
            group: "配置",
          },
          {
            href: "/policies/",
            label: "策略管理",
            description: "策略及规则分组。",
            icon: FolderCog,
            group: "配置",
          },
          {
            href: "/api-keys/",
            label: "API 密钥",
            description: "管理 API Token。",
            icon: Key,
            group: "配置",
          },

          {
            href: "/settings/",
            label: "系统设置",
            description: "系统级配置。",
            icon: Settings,
            group: "配置",
          },
        ],
      },
    ],
  },
]

export const consoleNavItems: ConsoleNavItem[] = consoleNavGroups.flatMap(
  (g) => {
    const items: ConsoleNavItem[] = []
    for (const item of g.items) {
      items.push(item)
      if (item.children) items.push(...item.children)
    }
    return items
  }
)

export const dashboardTabs = [
  { key: "traffic", label: "流量分析" },
  { key: "overview", label: "安全态势" },
  { key: "threats", label: "防护报告" },
] as const

export function getNavMeta(pathname: string | null | undefined) {
  const currentPath = pathname || "/"
  const item = consoleNavItems.find((entry) => {
    if (entry.exact === false)
      return currentPath === entry.href || currentPath.startsWith(entry.href)
    return currentPath === entry.href
  })

  if (item) return item

  return {
    href: "/dashboard/",
    label: "控制台",
    description: "统一管理 My-OpenWAF 的接入、防护与配置。",
    icon: LayoutDashboard,
    group: "概览",
  } satisfies ConsoleNavItem
}

export type WAFActionValue =
  | "allow"
  | "observe"
  | "intercept"
  | "rate_limit"
  | "drop"
  | "redirect"
  | "challenge"
  | "captcha_challenge"
  | "shield_challenge"
  | "chain_challenge"

export interface WAFActionMeta {
  value: WAFActionValue
  label: string
  shortLabel: string
  defaultStatus: string
  className: string
  description: string
}

export const wafActionOptions: WAFActionMeta[] = [
  {
    value: "observe",
    label: "观察",
    shortLabel: "观察",
    defaultStatus: "—",
    className: "border-slate-200 bg-slate-50 text-slate-600",
    description: "只记录事件，不阻断上游。",
  },
  {
    value: "rate_limit",
    label: "限速 429",
    shortLabel: "限速",
    defaultStatus: "429",
    className: "border-amber-200 bg-amber-50 text-amber-700",
    description: "高频访问命中后返回 429。",
  },
  {
    value: "intercept",
    label: "拦截 403/418",
    shortLabel: "拦截",
    defaultStatus: "403",
    className: "border-rose-200 bg-rose-50 text-rose-700",
    description: "默认 403，可用规则状态码改为 418。",
  },
  {
    value: "challenge",
    label: "人机验证 422",
    shortLabel: "验证",
    defaultStatus: "422",
    className: "border-violet-200 bg-violet-50 text-violet-700",
    description: "通用 JS 人机验证。",
  },
  {
    value: "captcha_challenge",
    label: "验证码 422",
    shortLabel: "验证码",
    defaultStatus: "422",
    className: "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700",
    description: "强制 CAPTCHA 验证。",
  },
  {
    value: "shield_challenge",
    label: "5s 盾 422",
    shortLabel: "5s盾",
    defaultStatus: "422",
    className: "border-indigo-200 bg-indigo-50 text-indigo-700",
    description: "CAPTCHA + PoW + 环境一致性检查。",
  },
  {
    value: "chain_challenge",
    label: "混合验证 422",
    shortLabel: "混合验证",
    defaultStatus: "422",
    className: "border-purple-200 bg-purple-50 text-purple-700",
    description: "按链式流程组合验证步骤。",
  },
  {
    value: "drop",
    label: "阻断 Drop",
    shortLabel: "Drop",
    defaultStatus: "DROP",
    className: "border-slate-300 bg-slate-100 text-slate-800",
    description: "直接关闭连接，不返回 HTTP body。",
  },
  {
    value: "redirect",
    label: "重定向 302",
    shortLabel: "重定向",
    defaultStatus: "302",
    className: "border-sky-200 bg-sky-50 text-sky-700",
    description: "命中后跳转到指定地址。",
  },
  {
    value: "allow",
    label: "白名单放行",
    shortLabel: "放行",
    defaultStatus: "—",
    className: "border-emerald-200 bg-emerald-50 text-emerald-700",
    description: "ACL 白名单动作，命中后跳过后续检测。",
  },
]

export const terminalWAFActionOptions = wafActionOptions.filter(
  (item) => item.value !== "allow"
)
export const ruleWAFActionOptions = wafActionOptions

export function normalizeWAFAction(value: string | null | undefined): string {
  if (!value) return "observe"
  if (value === "block") return "drop"
  if (value === "log_only") return "observe"
  return value
}

export function getWAFActionMeta(
  value: string | null | undefined
): WAFActionMeta {
  const normalized = normalizeWAFAction(value)
  return (
    wafActionOptions.find((item) => item.value === normalized) ?? {
      value: "observe",
      label: normalized || "未知",
      shortLabel: normalized || "未知",
      defaultStatus: "—",
      className: "border-slate-200 bg-slate-50 text-slate-600",
      description: normalized || "未知动作",
    }
  )
}

export const owaspModuleOptions = [
  { key: "sqli", label: "SQL 注入" },
  { key: "xss", label: "XSS" },
  { key: "webshell", label: "WebShell" },
  { key: "revshell", label: "反弹 Shell" },
  { key: "path_traversal", label: "路径遍历" },
  { key: "ssrf", label: "SSRF" },
  { key: "cmd_injection", label: "命令注入" },
  { key: "xxe", label: "XXE" },
  { key: "ldap_injection", label: "LDAP 注入" },
  { key: "nosql_injection", label: "NoSQL 注入" },
  { key: "template_injection", label: "模板注入" },
  { key: "jndi_injection", label: "JNDI 注入" },
  { key: "crlf_injection", label: "CRLF 注入" },
  { key: "expression_language", label: "表达式语言" },
  { key: "deserialization", label: "反序列化" },
  { key: "file_upload", label: "文件上传" },
  { key: "protocol_violation", label: "协议违规" },
  { key: "graphql_injection", label: "GraphQL 注入" },
] as const

export const phaseLabels: Record<string, string> = {
  acl: "ACL 访问控制",
  rate_limit: "频率限制",
  owasp_default: "OWASP 检测",
  signature: "签名匹配",
  custom: "自定义规则",
  cve_detection: "CVE 检测",
  bot_detection: "Bot 检测",
  anti_replay: "防重放",
  ip_reputation: "IP 信誉",
  maintenance: "维护模式",
}

export const categoryLabels: Record<string, string> = {
  sqli: "SQL 注入",
  xss: "XSS 跨站脚本",
  cmd_injection: "命令注入",
  path_traversal: "路径遍历",
  ssrf: "SSRF",
  xxe: "XXE 外部实体",
  ldap_injection: "LDAP 注入",
  nosql_injection: "NoSQL 注入",
  template_injection: "模板注入",
  jndi_injection: "JNDI 注入",
  crlf_injection: "CRLF 注入",
  expression_language: "表达式注入",
  deserialization: "反序列化",
  graphql_injection: "GraphQL 注入",
  webshell: "WebShell",
  revshell: "反弹 Shell",
  file_upload: "文件上传",
  protocol_violation: "协议违规",
  cve_general: "CVE 通用",
  cve_java: "CVE Java",
  cve_node: "CVE Node",
  cve_php: "CVE PHP",
  bot: "Bot 检测",
  bot_malicious: "恶意 Bot",
  ip_reputation: "IP 信誉",
  rate_limit: "速率限制",
  challenge: "人机验证",
}
