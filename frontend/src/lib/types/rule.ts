/** 策略与规则类型（internal/store/policy.go、internal/admin/rule/） */

export type Policy = {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  description: string;
  is_default: boolean;
};

export type RulePhase = "acl" | "signature" | "custom";

export type Rule = {
  id: number;
  name: string;
  policy_id: number;
  phase: RulePhase;
  pattern: string;
  action: string;
  priority: number;
  enabled: boolean;
  status_code?: number;
  redirect_to?: string;
  captcha_type?: string;
  window_seconds?: number;
  request_count?: number;
  captcha_minutes?: number;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
};

export type RuleTemplate = {
  name: string;
  description: string;
  pattern: string;
  category: string;
  phase: string;
  action: string;
};

export type RuleTestRequest = {
  pattern: string;
  client_ip?: string;
  path?: string;
  query?: string;
  headers?: string;
  method?: string;
  body?: string;
};

export type RuleTestResult = {
  matched: boolean;
  kind: string;
  arg: string;
};

export type RuleValidateResult = {
  valid: boolean;
  message: string;
  kind: string;
  arg: string;
  errors?: unknown;
};
