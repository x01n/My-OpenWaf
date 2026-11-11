/**
 * 站点高级配置的数据模型：draft 构建、差异比较与枚举常量。
 *
 * 精确对齐 internal/store/site.go 与 internal/admin/shared/json_bind.go：
 * - 三态 *bool 覆盖字段：null = 继承全局，true/false = 覆盖；
 * - 三态 *string 覆盖字段：空串 = 继承全局（后端在绑定层把空串归一为 null）；
 * - skip_path_by_phase 必须是 JSON 对象或 JSON null，空串会被后端拒绝。
 */

import type { Site } from "@/lib/types/site";
import type { LocalizedOption } from "@/i18n/localized-options";

export { localizeOptions, type LocalizedOption } from "@/i18n/localized-options";

/** 高级配置草稿：全部为可直接绑定的基础类型 */
export type SiteAdvancedDraft = {
  network: string;
  upstream_host: string;
  max_body_bytes: number;
  upstream_tls_skip_verify: boolean;
  upstream_tls_server_name: string;
  preserve_original_host: boolean;

  min_tls_version: string;
  max_tls_version: string;
  cipher_suites: string;
  alpn: string;

  xff_mode: string;
  trusted_cidr: string;
  client_ip_header_order: string;

  bot_protection_enabled: boolean | null;
  bot_protection_level: string;
  owasp_enabled: boolean | null;
  owasp_sensitivity: string;
  owasp_action: string;
  cve_enabled: boolean | null;
  cve_action: string;
  rate_limit_enabled: boolean | null;
  rate_limit_window: number;
  rate_limit_max: number;
  rate_limit_action: string;
  anti_replay_enabled: boolean | null;
  anti_replay_ttl: number;
  anti_replay_action: string;
  anti_replay_cookie_mode: string;
  challenge_action: string;
  captcha_type: string;
  skip_path_by_phase: string | null;

  cache_enabled: boolean;
  cache_default_ttl: number;
  cache_rules: string;

  maintenance_enabled: boolean;
  maintenance_html: string;
  maintenance_status: number;
  block_html: string;
  block_status: number;

  dynamic_protection_enabled: boolean | null;
  dynamic_html_enabled: boolean | null;
  dynamic_js_enabled: boolean | null;
  dynamic_js_mode: string;
  dynamic_js_paths: string;
  dynamic_decrypt_cache_ttl: number | null;

  cc_use_custom: boolean | null;
  cc_rules: string;
};

/** JSON blob 文本字段（保存前必须通过 JSON.parse 校验） */
export const JSON_BLOB_FIELDS = [
  "cipher_suites",
  "client_ip_header_order",
  "skip_path_by_phase",
  "cache_rules",
  "dynamic_js_paths",
  "cc_rules",
] as const satisfies readonly (keyof SiteAdvancedDraft)[];

/** 下拉选项类型与本地化函数从 i18n 公共模块再导出（见文件头）。 */

/** 网络协议（internal/snapshot/tls.go NormalizeNetwork） */
export const NETWORK_OPTIONS: LocalizedOption[] = [
  { key: "tcp", label: "tcp" },
  { key: "tcp4", label: "tcp4" },
  { key: "tcp6", label: "tcp6" },
];

/** X-Forwarded-For 解析模式（internal/store/site.go XFFMode*） */
export const XFF_MODE_OPTIONS: LocalizedOption[] = [
  {
    key: "strip_all_and_set_remote",
    label: "strip_all_and_set_remote",
    labelKey: "siteDetail.advanced.xff.stripAll",
  },
  {
    key: "trust_outer_waf_cidr_then_take_leftmost",
    label: "trust_outer_waf_cidr_then_take_leftmost",
    labelKey: "siteDetail.advanced.xff.trustOuter",
  },
];

/** 客户端 IP 请求头白名单（internal/store/site.go ClientIPHeader*） */
export const CLIENT_IP_HEADERS = [
  { key: "x_forwarded_for", label: "X-Forwarded-For" },
  { key: "x_real_ip", label: "X-Real-IP" },
  { key: "forwarded", label: "Forwarded" },
];

/** TLS 运行版本（internal/tlsmeta CanonicalVersionName）；空串 = 继承 */
export const TLS_VERSION_OPTIONS: LocalizedOption[] = [
  { key: "", label: "inherit", labelKey: "siteDetail.advanced.inherit" },
  { key: "TLS10", label: "TLS 1.0" },
  { key: "TLS11", label: "TLS 1.1" },
  { key: "TLS12", label: "TLS 1.2" },
  { key: "TLS13", label: "TLS 1.3" },
];

/** OWASP 敏感度（internal/admin/protect/sensitivity normalizeSensitivityLevel） */
export const OWASP_SENSITIVITY_OPTIONS: LocalizedOption[] = [
  { key: "", label: "inherit", labelKey: "siteDetail.advanced.inherit" },
  { key: "off", label: "off" },
  { key: "low", label: "low" },
  { key: "mid", label: "mid" },
  { key: "high", label: "high" },
  { key: "very_high", label: "very_high" },
  { key: "strict", label: "strict" },
];

/** 站点级防护动作：不接受 redirect（无跳转目标，internal/admin/shared ValidateActionWithoutRedirectTarget） */
export const SITE_ACTION_OPTIONS: LocalizedOption[] = [
  { key: "", label: "inherit", labelKey: "siteDetail.advanced.protection.inheritDefault" },
  {
    key: "intercept",
    label: "intercept",
    labelKey: "siteDetail.advanced.action.intercept",
  },
  { key: "observe", label: "observe", labelKey: "siteDetail.advanced.action.observe" },
  { key: "drop", label: "drop", labelKey: "siteDetail.advanced.action.drop" },
  { key: "challenge", label: "challenge", labelKey: "siteDetail.advanced.action.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "siteDetail.advanced.action.captchaChallenge",
  },
  {
    key: "shield_challenge",
    label: "shield_challenge",
    labelKey: "siteDetail.advanced.action.shieldChallenge",
  },
  {
    key: "chain_challenge",
    label: "chain_challenge",
    labelKey: "siteDetail.advanced.action.chainChallenge",
  },
  {
    key: "rate_limit",
    label: "rate_limit",
    labelKey: "siteDetail.advanced.action.rateLimit",
  },
];

/** 站点级质询动作（internal/admin/shared ValidateChallengeAction）；继承项由 TriStateText 注入 */
export const CHALLENGE_ACTION_OPTIONS: LocalizedOption[] = [
  { key: "challenge", label: "challenge", labelKey: "action.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "action.captchaChallenge",
  },
  { key: "shield_challenge", label: "shield_challenge", labelKey: "action.shieldChallenge" },
  { key: "chain_challenge", label: "chain_challenge", labelKey: "action.chainChallenge" },
];

/** 验证码类型（internal/waf/challenge）；继承项由 TriStateText 注入 */
export const CAPTCHA_TYPE_OPTIONS: LocalizedOption[] = [
  { key: "math", label: "math", labelKey: "siteDetail.advanced.captcha.math" },
  { key: "click", label: "click", labelKey: "siteDetail.advanced.captcha.click" },
  { key: "slide", label: "slide", labelKey: "siteDetail.advanced.captcha.slide" },
  { key: "rotate", label: "rotate", labelKey: "siteDetail.advanced.captcha.rotate" },
];

/** anti-replay Cookie 模式（internal/admin/shared ValidateAntiReplayCookieMode）；继承项由 TriStateText 注入 */
export const ANTI_REPLAY_COOKIE_MODE_OPTIONS: LocalizedOption[] = [
  { key: "standard", label: "standard" },
  { key: "dual", label: "dual" },
];

/** 动态 JS 保护模式（internal/waf/dynamic IsValidJSProtectionMode） */
export const DYNAMIC_JS_MODE_OPTIONS: LocalizedOption[] = [
  { key: "", label: "default", labelKey: "siteDetail.advanced.jsMode.default" },
  { key: "all", label: "all", labelKey: "siteDetail.advanced.jsMode.all" },
  { key: "paths", label: "paths", labelKey: "siteDetail.advanced.jsMode.paths" },
];

/** 三态布尔归一化：仅 true/false 视为覆盖，其余为继承 */
function triBool(value: unknown): boolean | null {
  return value === true ? true : value === false ? false : null;
}

/** 三态字符串归一化：非字符串或 null 视为继承（空串） */
function triString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** 数字归一化，非法值回退到默认值 */
function num(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

/** JSON blob 归一化为文本；null/undefined 转为空串 */
function blob(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** 从站点数据构建高级配置草稿 */
export function buildAdvancedDraft(site: Site): SiteAdvancedDraft {
  return {
    network: triString(site.network) || "tcp",
    upstream_host: triString(site.upstream_host),
    max_body_bytes: num(site.max_body_bytes, 10485760),
    upstream_tls_skip_verify: site.upstream_tls_skip_verify === true,
    upstream_tls_server_name: triString(site.upstream_tls_server_name),
    preserve_original_host: site.preserve_original_host === true,

    min_tls_version: triString(site.min_tls_version),
    max_tls_version: triString(site.max_tls_version),
    cipher_suites: blob(site.cipher_suites),
    alpn: triString(site.alpn),

    xff_mode: triString(site.xff_mode) || "strip_all_and_set_remote",
    trusted_cidr: triString(site.trusted_cidr),
    client_ip_header_order: blob(site.client_ip_header_order),

    bot_protection_enabled: triBool(site.bot_protection_enabled),
    bot_protection_level: triString(site.bot_protection_level),
    owasp_enabled: triBool(site.owasp_enabled),
    owasp_sensitivity: triString(site.owasp_sensitivity),
    owasp_action: triString(site.owasp_action),
    cve_enabled: triBool(site.cve_enabled),
    cve_action: triString(site.cve_action),
    rate_limit_enabled: triBool(site.rate_limit_enabled),
    rate_limit_window: num(site.rate_limit_window, 0),
    rate_limit_max: num(site.rate_limit_max, 0),
    rate_limit_action: triString(site.rate_limit_action),
    anti_replay_enabled: triBool(site.anti_replay_enabled),
    anti_replay_ttl: num(site.anti_replay_ttl, 300),
    anti_replay_action: triString(site.anti_replay_action),
    anti_replay_cookie_mode: triString(site.anti_replay_cookie_mode),
    challenge_action: triString(site.challenge_action),
    captcha_type: triString(site.captcha_type),
    skip_path_by_phase: typeof site.skip_path_by_phase === "string" ? site.skip_path_by_phase : null,

    cache_enabled: site.cache_enabled === true,
    cache_default_ttl: num(site.cache_default_ttl, 0),
    cache_rules: blob(site.cache_rules),

    maintenance_enabled: site.maintenance_enabled === true,
    maintenance_html: triString(site.maintenance_html),
    maintenance_status: num(site.maintenance_status, 503),
    block_html: triString(site.block_html),
    block_status: num(site.block_status, 403),

    dynamic_protection_enabled: triBool(site.dynamic_protection_enabled),
    dynamic_html_enabled: triBool(site.dynamic_html_enabled),
    dynamic_js_enabled: triBool(site.dynamic_js_enabled),
    dynamic_js_mode: triString(site.dynamic_js_mode),
    dynamic_js_paths: blob(site.dynamic_js_paths),
    dynamic_decrypt_cache_ttl:
      typeof site.dynamic_decrypt_cache_ttl === "number" ? site.dynamic_decrypt_cache_ttl : null,

    cc_use_custom: triBool(site.cc_use_custom),
    cc_rules: blob(site.cc_rules),
  };
}

/**
 * 计算相对初始草稿的差异补丁。
 *
 * 后端 UpdateSite 按「请求体出现过的字段」绑定，只提交差异可避免误覆盖
 * 其它并发修改；三态字段的 null 会在绑定层还原为「继承全局」。
 */
export function buildAdvancedPatch(
  draft: SiteAdvancedDraft,
  initial: SiteAdvancedDraft,
): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const key of Object.keys(draft) as (keyof SiteAdvancedDraft)[]) {
    if (draft[key] !== initial[key]) {
      patch[key] = draft[key];
    }
  }
  return patch;
}

/** 校验 JSON blob 文本字段；返回首个非法字段名，全部合法返回 null */
export function validateJsonBlobs(draft: SiteAdvancedDraft): keyof SiteAdvancedDraft | null {
  for (const field of JSON_BLOB_FIELDS) {
    const value = draft[field];
    if (typeof value !== "string" || value.trim() === "") continue;
    try {
      JSON.parse(value);
    } catch {
      return field;
    }
  }
  return null;
}
