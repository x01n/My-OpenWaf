/**
 * 管理台导航配置。
 * 每个条目对应一个独立功能页面，按领域分组展示在侧边栏。
 *
 * 文案不落库：`titleKey` / `labelKey` 指向 i18n 语言包，
 * 由侧栏在渲染期通过 `useI18n()` 解析，保证中英文切换即时生效。
 */
import type { MessageKey } from "@/i18n";

export type NavItem = {
  /** 路由路径 */
  href: string;
  /** 展示名称的 i18n 键 */
  labelKey: MessageKey;
  /** 权限要求：readonly 及以上可见 */
  minRole?: "readonly" | "operator" | "admin";
  /** 图标键名，由 Sidebar 映射到具体图标 */
  icon: string;
};

export type NavGroup = {
  /** 分组标题的 i18n 键 */
  titleKey: MessageKey;
  items: NavItem[];
};

export const NAV_GROUPS: NavGroup[] = [
  {
    titleKey: "nav.group.overview",
    items: [
      { href: "/dashboard", labelKey: "nav.dashboard", icon: "dashboard" },
    ],
  },
  {
    titleKey: "nav.group.assets",
    items: [
      { href: "/sites", labelKey: "nav.sites", icon: "sites" },
      { href: "/certificates", labelKey: "nav.certificates", icon: "certificate" },
    ],
  },
  {
    titleKey: "nav.group.security",
    items: [
      { href: "/protection", labelKey: "nav.protection", icon: "shield" },
      { href: "/ip-lists", labelKey: "nav.ipLists", icon: "ip" },
      { href: "/threat-intel", labelKey: "nav.threatIntel", icon: "intel" },
    ],
  },
  {
    titleKey: "nav.group.rules",
    items: [
      { href: "/rules", labelKey: "nav.rules", icon: "rules" },
      { href: "/policies", labelKey: "nav.policies", icon: "policy" },
      { href: "/cve-rules", labelKey: "nav.cveRules", icon: "cve" },
      { href: "/owasp-rules", labelKey: "nav.owaspRules", icon: "owasp" },
    ],
  },
  {
    titleKey: "nav.group.observability",
    items: [
      { href: "/security-events", labelKey: "nav.securityEvents", icon: "events" },
      { href: "/access-logs", labelKey: "nav.accessLogs", icon: "logs" },
    ],
  },
  {
    titleKey: "nav.group.plugins",
    items: [
      { href: "/lua-plugins", labelKey: "nav.luaPlugins", icon: "plugin" },
      { href: "/js-plugins", labelKey: "nav.jsPlugins", icon: "plugin" },
    ],
  },
  {
    titleKey: "nav.group.system",
    items: [
      { href: "/settings", labelKey: "nav.settings", icon: "settings" },
      { href: "/admin", labelKey: "nav.admin", icon: "users", minRole: "admin" },
    ],
  },
];

/** 按路径查找导航条目，供侧栏高亮与页面标题复用。 */
export function findNavItem(pathname: string): NavItem | undefined {
  return NAV_GROUPS.flatMap((group) => group.items).find(
    (item) => pathname === item.href || pathname.startsWith(item.href + "/"),
  );
}
