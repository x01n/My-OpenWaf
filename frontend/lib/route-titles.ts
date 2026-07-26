/**
 * 路由标题映射（单一数据源）
 * 顶层路由路径 -> i18n key，供 top-bar、breadcrumb、tab-workspace 复用。
 */

/** 顶层路由前缀（"/xxx"）到 i18n key 的映射 */
export const routeTitleKeyMap: Record<string, string> = {
  "/dashboard": "nav.dashboard",
  "/sites": "nav.sites",
  "/attacks": "nav.attacks",
  "/rules": "nav.rules",
  "/cc-protection": "nav.ccProtection",
  "/captcha": "nav.captcha",
  "/auth-config": "nav.authConfig",
  "/lua-plugins": "nav.luaPlugins",
  "/settings": "nav.settings",
  "/security-events": "nav.securityEvents",
  "/access-logs": "nav.accessLogs",
  "/drop-events": "nav.dropEvents",
  "/false-positives": "nav.falsePositives",
  "/certificates": "nav.certificates",
  "/ip-lists": "nav.ipLists",
  "/threat-intel": "nav.threatIntel",
  "/upstream-status": "nav.upstreamStatus",
  "/api-keys": "nav.apiKeys",
  "/admin-users": "nav.adminUsers",
  "/backup": "nav.backup",
  "/request-trace": "nav.requestTrace",
  "/page-templates": "nav.pageTemplates",
};

/** 面包屑按单个路径片段查找 key（片段 -> i18n key） */
export const segmentKeyMap: Record<string, string> = {
  dashboard: "nav.dashboard",
  sites: "nav.sites",
  detail: "common.detail",
  "security-events": "nav.securityEvents",
  "access-logs": "nav.accessLogs",
  "drop-events": "nav.dropEvents",
  attacks: "nav.attacks",
  "false-positives": "nav.falsePositives",
  rules: "nav.rules",
  "cc-protection": "nav.ccProtection",
  captcha: "nav.captcha",
  "auth-config": "nav.authConfig",
  "lua-plugins": "nav.luaPlugins",
  certificates: "nav.certificates",
  "ip-lists": "nav.ipLists",
  "threat-intel": "nav.threatIntel",
  "upstream-status": "nav.upstreamStatus",
  "api-keys": "nav.apiKeys",
  "admin-users": "nav.adminUsers",
  backup: "nav.backup",
  "request-trace": "nav.requestTrace",
  "page-templates": "nav.pageTemplates",
  settings: "nav.settings",
};

/**
 * 按 pathname 前缀解析顶层标题 key。
 * @param pathname 完整路径
 * @returns i18n key；无匹配返回 undefined
 */
export function getPageTitleKey(pathname: string): string | undefined {
  for (const [path, key] of Object.entries(routeTitleKeyMap)) {
    if (pathname === path || pathname.startsWith(path + "/")) return key;
  }
  return undefined;
}
