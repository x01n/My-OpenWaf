/**
 * OWASP 规则类型（internal/admin/detect/owasprules/、internal/store/owasp/owasp.go）
 *
 * 契约要点：
 * - 列表视图 id 是字符串规则 ID（如 owasp:sqli:001），catalog_id 才是数字主键；
 *   单条更新/重置的路径参数同时接受两者，此处统一使用 id。
 * - 页面始终在某个策略范围内操作：路径 /policies/:policyId/owasp-rules 优先于查询参数。
 * - 覆盖行的空值语义为「清除该项覆盖」，enabled 为三态（缺省表示继承目录默认值）。
 */

/** 列表视图（owaspRuleView） */
export type OWASPRule = {
  id: string;
  catalog_id: number;
  builtin_id: string;
  policy_id: number;
  category: string;
  name: string;
  description: string;
  pattern: string;
  score: number;
  default_enabled: boolean;
  default_action: string;
  default_sensitivity?: string;
  enabled: boolean;
  whitelist?: string[];
  action: string;
  status_code?: number;
  redirect_to?: string;
  captcha_type?: string;
  sensitivity?: string;
  cisco_asa_mode?: string;
  note?: string;
  overridden: boolean;
};

/** GET /owasp-rules/stats（owaspRuleStats） */
export type OWASPRuleStats = {
  total: number;
  enabled_count: number;
  disabled_count: number;
  by_category: Record<string, number>;
  policy_id: number;
};

/** GET /owasp-rules 响应（include_grouped=false 时无 grouped 字段） */
export type OWASPRuleListResponse = {
  items: OWASPRule[];
  total: number;
  policy_id: number;
  stats: OWASPRuleStats;
  grouped?: Record<string, OWASPRule[]>;
};

/** 单条覆盖补丁（owaspRulePatch）；空串表示清除该项覆盖 */
export type OWASPRulePatch = {
  policy_id?: number;
  enabled?: boolean;
  whitelist?: string[];
  action?: string;
  status_code?: number;
  redirect_to?: string;
  captcha_type?: string;
  sensitivity?: string;
  cisco_asa_mode?: string;
  note?: string;
};

/** POST /owasp-rules/batch 请求体 */
export type OWASPRuleBatchPayload = {
  policy_id?: number;
  ids?: number[];
  reset_all?: boolean;
  patch?: OWASPRulePatch;
};
