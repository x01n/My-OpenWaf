/**
 * 防护设置各 Tab 共用的枚举选项与字段表。
 *
 * 所有文案通过 `labelKey` 指向语言包，渲染时由 `localizeOptions()` 按当前
 * 语言解析；`label` 保留后端技术原值，便于日志与接口排查。
 */

import type { MessageKey } from "@/i18n";
import type { LocalizedOption } from "@/i18n/localized-options";
import type {
  BotScoreLog,
  ChainStepType,
  PageTemplateConfig,
  PageTemplateType,
} from "@/lib/types/protection";

/** 敏感度等级（internal/store/protection.go normalizeProtectionSensitivityLevel 白名单） */
export const SENSITIVITY_LEVELS: LocalizedOption[] = [
  { key: "off", label: "off", labelKey: "protection.sensitivity.off" },
  { key: "low", label: "low", labelKey: "protection.sensitivity.low" },
  { key: "mid", label: "mid", labelKey: "protection.sensitivity.mid" },
  { key: "high", label: "high", labelKey: "protection.sensitivity.high" },
  { key: "very_high", label: "very_high", labelKey: "protection.sensitivity.veryHigh" },
  { key: "strict", label: "strict", labelKey: "protection.sensitivity.strict" },
];

/**
 * 通用动作白名单（internal/admin/shared/helpers.go ValidateRuleAction
 * 去掉 redirect 后的集合，即 ValidateActionWithoutRedirectTarget 可接受的取值）。
 */
export const GENERIC_ACTIONS: LocalizedOption[] = [
  { key: "intercept", label: "intercept", labelKey: "protection.action.intercept" },
  { key: "drop", label: "drop", labelKey: "protection.action.drop" },
  { key: "challenge", label: "challenge", labelKey: "protection.action.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "protection.action.captchaChallenge",
  },
  {
    key: "shield_challenge",
    label: "shield_challenge",
    labelKey: "protection.action.shieldChallenge",
  },
  {
    key: "chain_challenge",
    label: "chain_challenge",
    labelKey: "protection.action.chainChallenge",
  },
  { key: "rate_limit", label: "rate_limit", labelKey: "protection.action.rateLimit" },
  { key: "observe", label: "observe", labelKey: "protection.action.observe" },
];

/** 质询动作（internal/admin/shared/helpers.go ValidateChallengeAction 白名单 + 空串继承） */
export const CHALLENGE_ACTIONS: LocalizedOption[] = [
  { key: "", label: "", labelKey: "protection.action.defaultChallenge" },
  { key: "challenge", label: "challenge", labelKey: "protection.action.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "protection.action.captchaChallenge",
  },
  {
    key: "shield_challenge",
    label: "shield_challenge",
    labelKey: "protection.action.shieldChallenge",
  },
  {
    key: "chain_challenge",
    label: "chain_challenge",
    labelKey: "protection.action.chainChallenge",
  },
];

/** 自动封禁动作：仅拦截与丢弃 */
export const AUTO_BAN_ACTIONS: LocalizedOption[] = [
  { key: "intercept", label: "intercept", labelKey: "protection.action.intercept" },
  { key: "drop", label: "drop", labelKey: "protection.action.drop" },
];

/** 浏览器签名动作（internal/store/protection.go BrowserSignAction 注释：observe / challenge / intercept） */
export const BROWSER_SIGN_ACTIONS: LocalizedOption[] = [
  { key: "observe", label: "observe", labelKey: "protection.action.observe" },
  { key: "challenge", label: "challenge", labelKey: "protection.action.challenge" },
  { key: "intercept", label: "intercept", labelKey: "protection.action.intercept" },
];

/** 验证码类型（internal/waf/challenge/captcha.go L31-34） */
export const CAPTCHA_TYPES: LocalizedOption[] = [
  { key: "math", label: "math", labelKey: "protection.captchaType.math" },
  { key: "click", label: "click", labelKey: "protection.captchaType.click" },
  { key: "slide", label: "slide", labelKey: "protection.captchaType.slide" },
  { key: "rotate", label: "rotate", labelKey: "protection.captchaType.rotate" },
];

/** 连锁步骤类型（internal/waf/challenge/chain.go ChainStepType L24-27） */
export const CHAIN_STEP_TYPES: LocalizedOption<ChainStepType>[] = [
  { key: "env", label: "env", labelKey: "protection.chainStep.env" },
  { key: "pow", label: "pow", labelKey: "protection.chainStep.pow" },
  { key: "captcha", label: "captcha", labelKey: "protection.chainStep.captcha" },
];

/** 连锁步骤条件（internal/admin/protect/chain/chain.go normalizeChainStepCondition 白名单） */
export const CHAIN_CONDITIONS: LocalizedOption[] = [
  { key: "all", label: "all", labelKey: "protection.chainCondition.all" },
  { key: "env_score>30", label: "env_score>30", labelKey: "protection.chainCondition.envAbove" },
  { key: "env_score<30", label: "env_score<30", labelKey: "protection.chainCondition.envBelow" },
  { key: "score>50", label: "score>50", labelKey: "protection.chainCondition.scoreAbove50" },
  { key: "score>80", label: "score>80", labelKey: "protection.chainCondition.scoreAbove80" },
];

/** 反重放 Cookie 模式（internal/admin/shared/helpers.go ValidateAntiReplayCookieMode） */
export const ANTI_REPLAY_MODES: LocalizedOption[] = [
  { key: "standard", label: "standard", labelKey: "protection.antiReplay.standard" },
  { key: "dual", label: "dual", labelKey: "protection.antiReplay.dual" },
];

/** js_protection_mode 白名单：internal/waf/dynamic IsValidJSProtectionMode（all / paths） */
export const JS_PROTECTION_MODES: LocalizedOption[] = [
  { key: "all", label: "all", labelKey: "protection.jsMode.all" },
  { key: "paths", label: "paths", labelKey: "protection.jsMode.paths" },
];

/** 升级动作白名单：internal/admin/protect/escalation/escalation.go L67-70 */
export const ESCALATION_ACTIONS: LocalizedOption[] = [
  { key: "intercept", label: "intercept", labelKey: "protection.action.intercept" },
  { key: "drop", label: "drop", labelKey: "protection.action.drop" },
  { key: "challenge", label: "challenge", labelKey: "protection.action.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "protection.action.captchaChallenge",
  },
  {
    key: "shield_challenge",
    label: "shield_challenge",
    labelKey: "protection.action.shieldChallenge",
  },
  {
    key: "chain_challenge",
    label: "chain_challenge",
    labelKey: "protection.action.chainChallenge",
  },
];

/** Bot 评分风险筛选 */
export const HIGH_RISK_OPTIONS: LocalizedOption[] = [
  { key: "all", label: "all", labelKey: "protection.botScores.filter.all" },
  { key: "true", label: "true", labelKey: "protection.botScores.filter.high" },
  { key: "false", label: "false", labelKey: "protection.botScores.filter.low" },
];

/** Bot 评分分项：字段名 → 语言包键 */
export const SCORE_PARTS: { key: keyof BotScoreLog; labelKey: MessageKey }[] = [
  { key: "total_score", labelKey: "protection.botScores.parts.total" },
  { key: "ua_score", labelKey: "protection.botScores.parts.ua" },
  { key: "geoip_score", labelKey: "protection.botScores.parts.geoip" },
  { key: "fingerprint_score", labelKey: "protection.botScores.parts.fingerprint" },
  { key: "behavior_score", labelKey: "protection.botScores.parts.behavior" },
  { key: "ip_rep_score", labelKey: "protection.botScores.parts.ipRep" },
];

/** 丢弃事件来源 → 语言包键；未知来源原样展示后端值 */
export const DROP_SOURCE_KEYS: Record<string, MessageKey> = {
  bot: "protection.drop.source.bot",
  cve: "protection.drop.source.cve",
  rule: "protection.drop.source.rule",
  ip_reputation: "protection.drop.source.ipRep",
};

/** 页面模板类型元信息 */
export const PAGE_TEMPLATE_META: Record<
  PageTemplateType,
  { labelKey: MessageKey; descriptionKey: MessageKey }
> = {
  captcha: {
    labelKey: "protection.pages.type.captcha",
    descriptionKey: "protection.pages.type.captchaDescription",
  },
  challenge: {
    labelKey: "protection.pages.type.challenge",
    descriptionKey: "protection.pages.type.challengeDescription",
  },
  block: {
    labelKey: "protection.pages.type.block",
    descriptionKey: "protection.pages.type.blockDescription",
  },
};

/** 页面模板编辑字段：模板字段名 → 语言包键 */
export type PageTemplateFieldSpec = {
  key: keyof PageTemplateConfig;
  labelKey: MessageKey;
};

/** 公共品牌字段（pageconfig.PageConfig） */
export const PAGE_TEMPLATE_COMMON_FIELDS: PageTemplateFieldSpec[] = [
  { key: "brand_name", labelKey: "protection.pages.field.brandName" },
  { key: "primary_color", labelKey: "protection.pages.field.primaryColor" },
  { key: "bg_gradient", labelKey: "protection.pages.field.bgGradient" },
  { key: "logo_url", labelKey: "protection.pages.field.logoUrl" },
  { key: "title", labelKey: "protection.pages.field.title" },
  { key: "footer_text", labelKey: "protection.pages.field.footerText" },
];

/** 三类模板各自专属文案字段 */
export const PAGE_TEMPLATE_TYPE_FIELDS: Record<PageTemplateType, PageTemplateFieldSpec[]> = {
  captcha: [
    { key: "subtitle", labelKey: "protection.pages.field.subtitleEn" },
    { key: "subtitle_zh", labelKey: "protection.pages.field.subtitleZh" },
    { key: "submit_text", labelKey: "protection.pages.field.submitText" },
  ],
  challenge: [
    { key: "checking_text", labelKey: "protection.pages.field.checkingEn" },
    { key: "checking_text_zh", labelKey: "protection.pages.field.checkingZh" },
    { key: "wait_text", labelKey: "protection.pages.field.waitEn" },
    { key: "wait_text_zh", labelKey: "protection.pages.field.waitZh" },
  ],
  block: [
    { key: "block_title", labelKey: "protection.pages.field.blockTitle" },
    { key: "block_message", labelKey: "protection.pages.field.blockMessage" },
    { key: "rate_limit_title", labelKey: "protection.pages.field.rateLimitTitle" },
    { key: "rate_limit_message", labelKey: "protection.pages.field.rateLimitMessage" },
  ],
};
