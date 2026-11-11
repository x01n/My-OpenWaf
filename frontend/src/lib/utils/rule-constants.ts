/**
 * CVE / OWASP 规则页共享常量
 *
 * 取值来自后端权威实现，禁止凭印象猜测：
 * - 动作集合与归一化：internal/core/action/action.go、internal/admin/shared/helpers.go
 * - 验证码类型：internal/waf/challenge/captcha.go（math/click/slide/rotate）
 * - 灵敏度六档 + medium 别名：internal/store/protection.go、internal/admin/detect/cverules/cve_scope.go
 * - CVE 类别：internal/waf/cve/catalog.go（回落 cve_general）、docs/管理 API 系统/CVE 规则管理 API.md
 * - OWASP 类别：internal/waf/owasp/owasp.go OWASPCategory 常量
 * - 目标值：internal/admin/detect/cverules/cve.go validateCustomCVERule
 *
 * 选项一律采用 `LocalizedOption`：`label` 保留后端技术原值（便于对照日志与接口），
 * `labelKey` 提供面向用户的文案；调用方用 `localizeOptions()` + `t()` 渲染。
 */

import type { LocalizedOption } from "@/i18n/localized-options";
import type { MessageKey, TranslateFn } from "@/i18n";

export { localizeOptions, type LocalizedOption } from "@/i18n/localized-options";

/**
 * 将后端枚举值解析为当前语言文案。
 *
 * 未登记的值原样返回（保留后端技术原值便于排查），空值返回空串。
 */
export function translateLabel(
  t: TranslateFn,
  table: Record<string, MessageKey>,
  value: string | null | undefined,
): string {
  if (!value) return "";
  const key = table[value];
  return key ? t(key) : value;
}

/* ---------- 动作（internal/core/action/action.go Type） ---------- */

/** OWASP 覆盖动作：redirect 合法但必须同时提交 redirect_to */
export const ACTION_OPTIONS: LocalizedOption[] = [
  { key: "intercept", label: "intercept", labelKey: "action.option.intercept" },
  { key: "drop", label: "drop", labelKey: "action.option.drop" },
  { key: "challenge", label: "challenge", labelKey: "action.option.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "action.option.captchaChallenge",
  },
  {
    key: "shield_challenge",
    label: "shield_challenge",
    labelKey: "action.option.shieldChallenge",
  },
  {
    key: "chain_challenge",
    label: "chain_challenge",
    labelKey: "action.option.chainChallenge",
  },
  { key: "redirect", label: "redirect", labelKey: "action.option.redirect" },
  { key: "rate_limit", label: "rate_limit", labelKey: "action.option.rateLimit" },
  { key: "observe", label: "observe", labelKey: "action.option.observe" },
];

export const ACTION_LABELS: Record<string, MessageKey> = {
  intercept: "action.intercept",
  block: "action.block",
  drop: "action.drop",
  challenge: "action.challenge",
  captcha_challenge: "action.captchaChallenge",
  shield_challenge: "action.shieldChallenge",
  chain_challenge: "action.chainChallenge",
  redirect: "action.redirect",
  rate_limit: "action.rateLimit",
  observe: "action.observe",
};

/** CVE 规则本体动作不禁 redirect；作用域覆盖动作允许 redirect 与 status_code/redirect_to */
export const CVE_SCOPE_ACTION_OPTIONS: LocalizedOption[] = [
  { key: "intercept", label: "intercept", labelKey: "action.option.intercept" },
  { key: "drop", label: "drop", labelKey: "action.option.drop" },
  { key: "challenge", label: "challenge", labelKey: "action.option.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "action.option.captchaChallenge",
  },
  {
    key: "shield_challenge",
    label: "shield_challenge",
    labelKey: "action.option.shieldChallenge",
  },
  {
    key: "chain_challenge",
    label: "chain_challenge",
    labelKey: "action.option.chainChallenge",
  },
  { key: "redirect", label: "redirect", labelKey: "action.option.redirect" },
  { key: "observe", label: "observe", labelKey: "action.option.observe" },
];

/** 动作语义配色：拦截/丢弃=danger、挑战系/限流=warning、观察=success、重定向=accent */
export function actionTone(
  action: string,
): "danger" | "warning" | "success" | "accent" | "default" {
  switch (action) {
    case "intercept":
    case "block":
    case "drop":
      return "danger";
    case "challenge":
    case "captcha_challenge":
    case "shield_challenge":
    case "chain_challenge":
    case "rate_limit":
      return "warning";
    case "observe":
      return "success";
    case "redirect":
      return "accent";
    default:
      return "default";
  }
}

/** 挑战系动作：需要展示验证码类型字段 */
export const CHALLENGE_ACTIONS = new Set([
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
]);

/* ---------- 验证码类型（internal/waf/challenge/captcha.go） ---------- */

export const CAPTCHA_TYPE_OPTIONS: LocalizedOption[] = [
  { key: "math", label: "math", labelKey: "siteDetail.advanced.captcha.math" },
  { key: "click", label: "click", labelKey: "siteDetail.advanced.captcha.click" },
  { key: "slide", label: "slide", labelKey: "siteDetail.advanced.captcha.slide" },
  { key: "rotate", label: "rotate", labelKey: "siteDetail.advanced.captcha.rotate" },
];

/* ---------- 灵敏度档位（六档 + medium/mid 别名） ---------- */

export const SENSITIVITY_OPTIONS: LocalizedOption[] = [
  { key: "off", label: "off", labelKey: "ruleOptions.sensitivity.off" },
  { key: "low", label: "low", labelKey: "ruleOptions.sensitivity.low" },
  { key: "mid", label: "mid", labelKey: "ruleOptions.sensitivity.mid" },
  { key: "high", label: "high", labelKey: "ruleOptions.sensitivity.high" },
  { key: "very_high", label: "very_high", labelKey: "ruleOptions.sensitivity.veryHigh" },
  { key: "strict", label: "strict", labelKey: "ruleOptions.sensitivity.strict" },
];

export const SENSITIVITY_LABELS: Record<string, MessageKey> = {
  off: "ruleOptions.sensitivity.off",
  low: "ruleOptions.sensitivity.low",
  mid: "ruleOptions.sensitivity.mid",
  medium: "ruleOptions.sensitivity.mid",
  high: "ruleOptions.sensitivity.high",
  very_high: "ruleOptions.sensitivity.veryHigh",
  strict: "ruleOptions.sensitivity.strict",
};

/* ---------- Cisco ASA 档位（internal/waf/owasp/cisco_asa.go） ---------- */

export const CISCO_ASA_OPTIONS: LocalizedOption[] = [
  { key: "", label: "scoped", labelKey: "ruleOptions.cisco.inherit" },
  { key: "legacy", label: "legacy", labelKey: "ruleOptions.cisco.legacy" },
  { key: "strict", label: "strict", labelKey: "ruleOptions.cisco.strict" },
  { key: "scoped", label: "scoped", labelKey: "ruleOptions.cisco.scoped" },
];

/* ---------- CVE 类别（internal/waf/cve/catalog.go 注册表 + 回落值） ---------- */

export const CVE_CATEGORY_OPTIONS: LocalizedOption[] = [
  { key: "", label: "", labelKey: "ruleOptions.category.all" },
  { key: "cve_general", label: "cve_general", labelKey: "ruleOptions.category.general" },
  { key: "cve_java", label: "cve_java", labelKey: "ruleOptions.category.java" },
  { key: "cve_php", label: "cve_php", labelKey: "ruleOptions.category.php" },
  { key: "cve_node", label: "cve_node", labelKey: "ruleOptions.category.node" },
];

export const CVE_CATEGORY_LABELS: Record<string, MessageKey> = {
  cve_general: "ruleOptions.category.general",
  cve_java: "ruleOptions.category.java",
  cve_php: "ruleOptions.category.php",
  cve_node: "ruleOptions.category.node",
};

/* ---------- CVE 危险度（catalog 空值回落 medium） ---------- */

export const CVE_SEVERITY_OPTIONS: LocalizedOption[] = [
  { key: "", label: "", labelKey: "ruleOptions.severity.all" },
  { key: "critical", label: "critical", labelKey: "ruleOptions.severity.critical" },
  { key: "high", label: "high", labelKey: "ruleOptions.severity.high" },
  { key: "medium", label: "medium", labelKey: "ruleOptions.severity.medium" },
  { key: "low", label: "low", labelKey: "ruleOptions.severity.low" },
];

export const CVE_SEVERITY_LABELS: Record<string, MessageKey> = {
  critical: "ruleOptions.severity.critical",
  high: "ruleOptions.severity.high",
  medium: "ruleOptions.severity.medium",
  low: "ruleOptions.severity.low",
};

/** CVE 匹配目标（cve.go validateCustomCVERule） */
export const CVE_TARGET_OPTIONS: LocalizedOption[] = [
  { key: "all", label: "all", labelKey: "ruleOptions.target.all" },
  { key: "url", label: "url" },
  { key: "url_body", label: "url_body" },
  { key: "body", label: "body" },
  { key: "header", label: "header" },
  { key: "cookie", label: "cookie" },
];

/* ---------- OWASP 类别（internal/waf/owasp/owasp.go OWASPCategory） ---------- */

export const OWASP_CATEGORY_OPTIONS: LocalizedOption[] = [
  { key: "", label: "", labelKey: "ruleOptions.category.all" },
  { key: "sqli", label: "sqli", labelKey: "ruleOptions.owasp.sqli" },
  { key: "webshell", label: "webshell", labelKey: "ruleOptions.owasp.webshell" },
  { key: "revshell", label: "revshell", labelKey: "ruleOptions.owasp.revshell" },
  { key: "xss", label: "xss", labelKey: "ruleOptions.owasp.xss" },
  {
    key: "path_traversal",
    label: "path_traversal",
    labelKey: "ruleOptions.owasp.pathTraversal",
  },
  { key: "ssrf", label: "ssrf", labelKey: "ruleOptions.owasp.ssrf" },
  {
    key: "cmd_injection",
    label: "cmd_injection",
    labelKey: "ruleOptions.owasp.cmdInjection",
  },
  { key: "xxe", label: "xxe", labelKey: "ruleOptions.owasp.xxe" },
  {
    key: "ldap_injection",
    label: "ldap_injection",
    labelKey: "ruleOptions.owasp.ldapInjection",
  },
  { key: "file_upload", label: "file_upload", labelKey: "ruleOptions.owasp.fileUpload" },
  {
    key: "protocol_violation",
    label: "protocol_violation",
    labelKey: "ruleOptions.owasp.protocolViolation",
  },
  {
    key: "nosql_injection",
    label: "nosql_injection",
    labelKey: "ruleOptions.owasp.nosqlInjection",
  },
  {
    key: "template_injection",
    label: "template_injection",
    labelKey: "ruleOptions.owasp.templateInjection",
  },
  {
    key: "jndi_injection",
    label: "jndi_injection",
    labelKey: "ruleOptions.owasp.jndiInjection",
  },
  {
    key: "crlf_injection",
    label: "crlf_injection",
    labelKey: "ruleOptions.owasp.crlfInjection",
  },
  {
    key: "expression_language",
    label: "expression_language",
    labelKey: "ruleOptions.owasp.expressionLanguage",
  },
  {
    key: "deserialization",
    label: "deserialization",
    labelKey: "ruleOptions.owasp.deserialization",
  },
  {
    key: "graphql_injection",
    label: "graphql_injection",
    labelKey: "ruleOptions.owasp.graphqlInjection",
  },
  {
    key: "malicious_client",
    label: "malicious_client",
    labelKey: "ruleOptions.owasp.maliciousClient",
  },
];

export const OWASP_CATEGORY_LABELS: Record<string, MessageKey> = {
  sqli: "ruleOptions.owasp.sqli",
  webshell: "ruleOptions.owasp.webshell",
  revshell: "ruleOptions.owasp.revshell",
  xss: "ruleOptions.owasp.xss",
  path_traversal: "ruleOptions.owasp.pathTraversal",
  ssrf: "ruleOptions.owasp.ssrf",
  cmd_injection: "ruleOptions.owasp.cmdInjection",
  xxe: "ruleOptions.owasp.xxe",
  ldap_injection: "ruleOptions.owasp.ldapInjection",
  file_upload: "ruleOptions.owasp.fileUpload",
  protocol_violation: "ruleOptions.owasp.protocolViolation",
  nosql_injection: "ruleOptions.owasp.nosqlInjection",
  template_injection: "ruleOptions.owasp.templateInjection",
  jndi_injection: "ruleOptions.owasp.jndiInjection",
  crlf_injection: "ruleOptions.owasp.crlfInjection",
  expression_language: "ruleOptions.owasp.expressionLanguage",
  deserialization: "ruleOptions.owasp.deserialization",
  graphql_injection: "ruleOptions.owasp.graphqlInjection",
  malicious_client: "ruleOptions.owasp.maliciousClient",
};

/** CVE 作用域选项 */
export const CVE_SCOPE_OPTIONS: LocalizedOption[] = [
  { key: "global", label: "global", labelKey: "ruleOptions.scope.global" },
  { key: "policy", label: "policy", labelKey: "ruleOptions.scope.policy" },
  { key: "site", label: "site", labelKey: "ruleOptions.scope.site" },
];

export const CVE_SCOPE_LABELS: Record<string, MessageKey> = {
  global: "ruleOptions.scope.global",
  policy: "ruleOptions.scope.policy",
  site: "ruleOptions.scope.site",
};