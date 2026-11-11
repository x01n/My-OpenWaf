/**
 * 策略领域的数据模型：OWASP 统计类型与表单状态。
 */

import type { Policy } from "@/lib/types/rule";

/** GET /policies/:policyId/owasp-rules/stats 响应（internal/admin/detect/owasprules） */
export type OwaspRuleStats = {
  total: number;
  enabled_count: number;
  disabled_count: number;
  by_category: Record<string, number>;
  policy_id: number;
};

/** 新建 / 编辑表单状态 */
export type PolicyFormState = { name: string; description: string };

/** 新建表单初值 */
export const EMPTY_FORM: PolicyFormState = { name: "", description: "" };

/** 由策略记录生成编辑表单初值 */
export function policyToForm(p: Policy): PolicyFormState {
  return { name: p.name, description: p.description };
}
