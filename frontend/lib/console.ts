import {
  Activity,
  BadgeAlert,
  Blocks,
  Bot,
  FileText,
  FileWarning,
  Fingerprint,
  Globe,
  KeyRound,
  LayoutDashboard,
  Lock,
  Radar,
  Server,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  TriangleAlert,
  Waypoints,
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

export const consoleNavItems: ConsoleNavItem[] = [
  {
    href: "/dashboard/",
    label: "总览",
    description: "查看流量、拦截、Bot、CVE 与运行状态总览。",
    icon: LayoutDashboard,
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
    href: "/security-events/",
    label: "安全事件",
    description: "按动作、类别、IP 和时间检索安全事件。",
    icon: Activity,
    group: "概览",
  },
  {
    href: "/access-logs/",
    label: "访问日志",
    description: "查看请求结果、缓存命中与上游访问情况。",
    icon: FileText,
    group: "概览",
  },
  {
    href: "/protection/",
    label: "攻击防护",
    description: "配置 OWASP、限流、维护模式和登录安全策略。",
    icon: ShieldAlert,
    group: "防护",
  },
  {
    href: "/cc-protection/",
    label: "CC 防护",
    description: "管理 CC 防护、自定义规则和等待室策略。",
    icon: Radar,
    group: "防护",
  },
  {
    href: "/bot-protection/",
    label: "Bot 防护",
    description: "调整 Bot 阈值、风险国家、ASN 和评分日志。",
    icon: Bot,
    group: "防护",
  },
  {
    href: "/drop-policy/",
    label: "阻断策略",
    description: "管理主动断连策略和阻断事件。",
    icon: Blocks,
    group: "防护",
  },
  {
    href: "/fingerprints/",
    label: "指纹分析",
    description: "查看 TLS 指纹聚合统计和异常特征。",
    icon: Fingerprint,
    group: "防护",
  },
  {
    href: "/security/",
    label: "安全策略",
    description: "验证码、5秒盾、连锁策略、防重放与阶梯升级。",
    icon: ShieldCheck,
    group: "防护",
  },
  {
    href: "/cve-rules/",
    label: "CVE 规则",
    description: "同步、审阅和维护漏洞检测规则。",
    icon: BadgeAlert,
    group: "防护",
  },
  {
    href: "/rules/cve/",
    label: "CVE 规则管理",
    description: "筛选、搜索、批量操作和编辑 CVE 检测规则。",
    icon: BadgeAlert,
    group: "防护",
  },
  {
    href: "/rules/owasp/",
    label: "OWASP 规则管理",
    description: "按类别管理 OWASP 规则和敏感度矩阵。",
    icon: ShieldCheck,
    group: "防护",
  },
  {
    href: "/error-pages/",
    label: "错误页面",
    description: "管理默认和站点级自定义错误页面。",
    icon: FileWarning,
    group: "配置",
  },
  {
    href: "/policies/",
    label: "策略",
    description: "管理策略对象并为规则分组。",
    icon: Shield,
    group: "配置",
  },
  {
    href: "/rules/",
    label: "规则管理",
    description: "管理 CVE 规则、OWASP 规则、ACL 与自定义匹配规则。",
    icon: SlidersHorizontal,
    group: "配置",
    exact: false,
  },
  {
    href: "/certificates/",
    label: "证书",
    description: "维护 TLS 证书并分配给 HTTPS 站点。",
    icon: Lock,
    group: "配置",
  },
  {
    href: "/ip-lists/",
    label: "IP 黑白名单",
    description: "按 IP 或 CIDR 管理黑白名单条目。",
    icon: Shield,
    group: "配置",
  },
  {
    href: "/api-keys/",
    label: "API 密钥",
    description: "管理用于自动化访问的 Bearer Token。",
    icon: KeyRound,
    group: "配置",
  },
  {
    href: "/settings/",
    label: "系统设置",
    description: "查看系统级配置、登录策略和平台资源。",
    icon: Settings2,
    group: "配置",
  },
  {
    href: "/listeners/",
    label: "监听器（规划中）",
    description: "当前后端未暴露独立监听器接口，页面仅做架构说明。",
    icon: Server,
    group: "架构",
    enabled: false,
  },
  {
    href: "/forwarding-profiles/",
    label: "转发配置（规划中）",
    description: "当前后端未暴露独立转发配置接口，已并入站点配置。",
    icon: Waypoints,
    group: "架构",
    enabled: false,
  },
];

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
