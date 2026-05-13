import {
  AlertTriangle,
  Ban,
  BarChart3,
  Bot,
  Bug,
  FileText,
  Fingerprint,
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
} from "lucide-react";

export interface ConsoleNavItem {
  href: string;
  label: string;
  description: string;
  icon: LucideIcon;
  group: string;
  enabled?: boolean;
  exact?: boolean;
}

export interface ConsoleNavGroup {
  title: string;
  items: ConsoleNavItem[];
}

export const consoleNavGroups: ConsoleNavGroup[] = [
  {
    title: "概览",
    items: [
      { href: "/dashboard/", label: "总览", description: "查看流量、拦截、Bot、CVE 与运行状态总览。", icon: BarChart3, group: "概览" },
      { href: "/sites/", label: "防护应用", description: "管理站点接入、转发目标和站点级防护策略。", icon: Globe, group: "概览" },
      { href: "/security-events/", label: "安全事件", description: "按动作、类别、IP 和时间检索安全事件。", icon: ShieldAlert, group: "概览" },
      { href: "/access-logs/", label: "访问日志", description: "查看请求结果、缓存命中与上游访问情况。", icon: FileText, group: "概览" },
    ],
  },
  {
    title: "防护",
    items: [
      { href: "/protection/", label: "攻击防护", description: "配置 OWASP、限流、维护模式和登录安全策略。", icon: Shield, group: "防护" },
      { href: "/cc-protection/", label: "CC 防护", description: "管理 CC 防护、自定义规则和等待室策略。", icon: Zap, group: "防护" },
      { href: "/bot-protection/", label: "Bot 防护", description: "调整 Bot 阈值、风险国家、ASN 和评分日志。", icon: Bot, group: "防护" },
      { href: "/security/", label: "安全策略", description: "验证码、5秒盾、连锁策略、防重放与阶梯升级。", icon: ShieldCheck, group: "防护" },
      { href: "/drop-policy/", label: "阻断策略", description: "管理主动断连策略和阻断事件。", icon: Ban, group: "防护" },
    ],
  },
  {
    title: "规则",
    items: [
      { href: "/rules/cve/", label: "CVE 规则", description: "筛选、搜索、批量操作和编辑 CVE 检测规则。", icon: Bug, group: "规则" },
      { href: "/rules/owasp/", label: "OWASP 规则", description: "按类别管理 OWASP 规则和敏感度矩阵。", icon: AlertTriangle, group: "规则" },
      { href: "/rules/", label: "自定义规则", description: "管理 ACL 与自定义匹配规则。", icon: ListChecks, group: "规则", exact: false },
      { href: "/ip-lists/", label: "IP 黑白名单", description: "按 IP 或 CIDR 管理黑白名单条目。", icon: List, group: "规则" },
    ],
  },
  {
    title: "分析",
    items: [
      { href: "/fingerprints/", label: "指纹分析", description: "查看 TLS 指纹聚合统计和异常特征。", icon: Fingerprint, group: "分析" },
    ],
  },
  {
    title: "配置",
    items: [
      { href: "/error-pages/", label: "错误页面", description: "管理默认和站点级自定义错误页面。", icon: TriangleAlert, group: "配置" },
      { href: "/certificates/", label: "证书管理", description: "维护 TLS 证书并分配给 HTTPS 站点。", icon: Lock, group: "配置" },
      { href: "/policies/", label: "策略管理", description: "管理策略对象并为规则分组。", icon: FolderCog, group: "配置" },
      { href: "/api-keys/", label: "API 密钥", description: "管理用于自动化访问的 Bearer Token。", icon: Key, group: "配置" },
      { href: "/settings/", label: "系统设置", description: "查看系统级配置、登录策略和平台资源。", icon: Settings, group: "配置" },
    ],
  },
];

// Flat list for backward compatibility
export const consoleNavItems: ConsoleNavItem[] = consoleNavGroups.flatMap((g) => g.items);

export const dashboardTabs = [
  { key: "overview", label: "态势总览" },
  { key: "traffic", label: "流量视图" },
  { key: "threats", label: "威胁视图" },
] as const;

export function getNavMeta(pathname: string | null | undefined) {
  const currentPath = pathname || "/";
  const item = consoleNavItems.find((entry) => {
    if (entry.exact) return currentPath === entry.href;
    return currentPath === entry.href || currentPath.startsWith(entry.href);
  });

  if (item) return item;

  return {
    href: "/dashboard/",
    label: "控制台",
    description: "统一管理 My-OpenWAF 的接入、防护与配置。",
    icon: LayoutDashboard,
    group: "概览",
  } satisfies ConsoleNavItem;
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
  | "chain_challenge";

export interface WAFActionMeta {
  value: WAFActionValue;
  label: string;
  shortLabel: string;
  defaultStatus: string;
  className: string;
  description: string;
}

export const wafActionOptions: WAFActionMeta[] = [
  { value: "observe", label: "观察", shortLabel: "观察", defaultStatus: "—", className: "border-slate-200 bg-slate-50 text-slate-600", description: "只记录事件，不阻断上游。" },
  { value: "rate_limit", label: "限速 429", shortLabel: "限速", defaultStatus: "429", className: "border-amber-200 bg-amber-50 text-amber-700", description: "高频访问命中后返回 429。" },
  { value: "intercept", label: "拦截 403/418", shortLabel: "拦截", defaultStatus: "403", className: "border-rose-200 bg-rose-50 text-rose-700", description: "默认 403，可用规则状态码改为 418。" },
  { value: "challenge", label: "人机验证 422", shortLabel: "验证", defaultStatus: "422", className: "border-violet-200 bg-violet-50 text-violet-700", description: "通用 JS 人机验证。" },
  { value: "captcha_challenge", label: "验证码 422", shortLabel: "验证码", defaultStatus: "422", className: "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700", description: "强制 CAPTCHA 验证。" },
  { value: "shield_challenge", label: "5s 盾 422", shortLabel: "5s盾", defaultStatus: "422", className: "border-indigo-200 bg-indigo-50 text-indigo-700", description: "CAPTCHA + PoW + 环境一致性检查。" },
  { value: "chain_challenge", label: "混合验证 422", shortLabel: "混合验证", defaultStatus: "422", className: "border-purple-200 bg-purple-50 text-purple-700", description: "按链式流程组合验证步骤。" },
  { value: "drop", label: "阻断 Drop", shortLabel: "Drop", defaultStatus: "DROP", className: "border-slate-300 bg-slate-100 text-slate-800", description: "直接关闭连接，不返回 HTTP body。" },
  { value: "redirect", label: "重定向 302", shortLabel: "重定向", defaultStatus: "302", className: "border-sky-200 bg-sky-50 text-sky-700", description: "命中后跳转到指定地址。" },
  { value: "allow", label: "白名单放行", shortLabel: "放行", defaultStatus: "—", className: "border-emerald-200 bg-emerald-50 text-emerald-700", description: "ACL 白名单动作，命中后跳过后续检测。" },
];

export const terminalWAFActionOptions = wafActionOptions.filter((item) => item.value !== "allow");
export const ruleWAFActionOptions = wafActionOptions;

export function normalizeWAFAction(value: string | null | undefined): string {
  if (!value) return "observe";
  if (value === "block") return "drop";
  if (value === "log_only") return "observe";
  return value;
}

export function getWAFActionMeta(value: string | null | undefined): WAFActionMeta {
  const normalized = normalizeWAFAction(value);
  return wafActionOptions.find((item) => item.value === normalized) ?? {
    value: "observe",
    label: normalized || "未知",
    shortLabel: normalized || "未知",
    defaultStatus: "—",
    className: "border-slate-200 bg-slate-50 text-slate-600",
    description: normalized || "未知动作",
  };
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
] as const;
