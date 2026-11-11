/**
 * CVE 规则类型（internal/admin/detect/cverules/、internal/store/cve/、internal/waf/cve/feed.go）
 *
 * 契约要点：
 * - 列表返回作用域有效视图：规则本体 + effective（合并后生效配置）+ override（当前作用域覆盖行）。
 * - 写操作分两类：/cve-rules/:id/patch|batch|reset 只改作用域覆盖；
 *   /cve-rules/:id/update|delete 与 POST /cve-rules 仅 admin 且只允许 source=custom。
 * - 覆盖模型六个字段全为指针，省略表示「本作用域不表态」，由上一层继承。
 */

import type { ListResponse } from "@/lib/api/client";

/** 作用域类型（internal/store/cve/cve_scope.go） */
export type CVEScope = "global" | "policy" | "site";

/** 规则来源（internal/waf/cve/catalog.go、feed.go） */
export type CVESource = "catalog" | "nvd" | "github" | "auto_generated" | "custom";

/** 危险度（internal/waf/cve 注册表回落到 medium） */
export type CVESeverity = "critical" | "high" | "medium" | "low";

/** 匹配目标（internal/admin/detect/cverules/cve.go validateCustomCVERule） */
export type CVETarget = "all" | "url" | "url_body" | "body" | "header" | "cookie";

/** 合并后的生效配置（cveEffectiveConfig） */
export type CVEEffectiveConfig = {
  enabled: boolean;
  action: string;
  sensitivity?: string;
  status_code?: number;
  redirect_to?: string;
  captcha_type?: string;
};

/** 作用域覆盖行（store/cve.CVERuleScopeOverride） */
export type CVERuleScopeOverride = {
  id?: number;
  rule_id: number;
  scope: CVEScope;
  scope_id: number;
  enabled?: boolean;
  action?: string;
  sensitivity?: string;
  status_code?: number;
  redirect_to?: string;
  captcha_type?: string;
  created_at?: string;
  updated_at?: string;
};

/** 作用域有效视图（cveScopedRuleView） */
export type CVERule = {
  id: number;
  created_at: string;
  updated_at: string;
  cve_id: string;
  category: string;
  pattern: string;
  target: string;
  severity: string;
  action: string;
  captcha_type?: string;
  enabled: boolean;
  description: string;
  source: string;
  approved: boolean;
  cvss_score: number;
  cwe_type: string;
  references: string;
  effective: CVEEffectiveConfig;
  override: CVERuleScopeOverride | null;
  overridden: boolean;
  inherited_from: string;
};

/** GET /cve-rules/stats（cveRuleStats） */
export type CVERuleStats = {
  total: number;
  enabled_count: number;
  disabled_count: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  scope: CVEScope;
  scope_id: number;
};

/** GET /cve-rules 响应 */
export type CVERuleListResponse = ListResponse<CVERule> & {
  scope: CVEScope;
  scope_id: number;
  stats: CVERuleStats;
};

/** GET /cve-feed/status */
export type CVEFeedStatus = {
  last_sync: string | null;
  last_error: string;
  syncing: boolean;
  pending_review: number;
};

/** POST /cve-rules/:id/patch 与 /cve-rules/batch 的覆盖载荷 */
export type CVERuleOverridePayload = {
  scope: CVEScope;
  policy_id?: number;
  site_id?: number;
  enabled?: boolean;
  action?: string;
  sensitivity?: string;
  status_code?: number;
  redirect_to?: string;
  captcha_type?: string;
};

/** POST /cve-rules/batch 请求体 */
export type CVERuleBatchPayload = CVERuleOverridePayload & {
  ids: number[];
};

/** 自定义规则本体载荷（POST /cve-rules、POST /cve-rules/:id/update） */
export type CVERuleBodyPayload = {
  cve_id?: string;
  category?: string;
  pattern?: string;
  target?: string;
  severity?: string;
  action?: string;
  description?: string;
  captcha_type?: string;
  enabled?: boolean;
};
