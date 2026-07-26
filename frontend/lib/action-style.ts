/**
 * WAF 动作（action）的统一语义样式。
 *
 * 后端 `internal/core/action/action.go` 定义的终端优先级为
 * drop(90) > intercept(80) > rate_limit(70) > challenges(60) > redirect(50) > observe(10)，
 * 且 `block` 归一化为 `intercept`、`log_only` 归一化为 `observe`。
 * 前端徽章颜色按同一套语义分级，避免各页面各写一份 actionColorMap 导致同一动作显示不同颜色。
 */

/** 归一化后的动作类别，用于选色与分级 */
export type ActionTone =
  | "drop"
  | "intercept"
  | "rateLimit"
  | "challenge"
  | "redirect"
  | "observe"
  | "allow"
  | "unknown";

/** 后端动作名 -> 语义类别。键为后端实际返回的字符串，不做大小写以外的推测。 */
const ACTION_TONE: Record<string, ActionTone> = {
  drop: "drop",
  intercept: "intercept",
  block: "intercept",
  rate_limit: "rateLimit",
  challenge: "challenge",
  captcha_challenge: "challenge",
  shield_challenge: "challenge",
  chain_challenge: "challenge",
  redirect: "redirect",
  observe: "observe",
  log_only: "observe",
  tag: "observe",
  allow: "allow",
};

/** 语义类别 -> 徽章类名（浅/深色双向可读，边框 + 半透明底色） */
const TONE_CLASS: Record<ActionTone, string> = {
  drop: "border-rose-500/30 bg-rose-500/12 text-rose-700 dark:border-rose-400/30 dark:bg-rose-400/15 dark:text-rose-300",
  intercept:
    "border-destructive/30 bg-destructive/10 text-destructive dark:bg-destructive/20",
  rateLimit:
    "border-amber-500/30 bg-amber-500/12 text-amber-700 dark:border-amber-400/30 dark:bg-amber-400/15 dark:text-amber-300",
  challenge:
    "border-sky-500/30 bg-sky-500/12 text-sky-700 dark:border-sky-400/30 dark:bg-sky-400/15 dark:text-sky-300",
  redirect:
    "border-violet-500/30 bg-violet-500/12 text-violet-700 dark:border-violet-400/30 dark:bg-violet-400/15 dark:text-violet-300",
  observe: "border-border bg-muted text-muted-foreground",
  allow:
    "border-emerald-500/30 bg-emerald-500/12 text-emerald-700 dark:border-emerald-400/30 dark:bg-emerald-400/15 dark:text-emerald-300",
  unknown: "border-border bg-muted text-muted-foreground",
};

/** 语义类别 -> 严重度分值，与后端 TerminalPriority 同序，供排序/强调使用 */
const TONE_SEVERITY: Record<ActionTone, number> = {
  drop: 90,
  intercept: 80,
  rateLimit: 70,
  challenge: 60,
  redirect: 50,
  observe: 10,
  allow: 0,
  unknown: 0,
};

/** i18n 中已存在文案的动作名（`securityEvents.action.*`），未列入的直接回显原值 */
const TRANSLATABLE_ACTIONS = new Set([
  "block",
  "intercept",
  "observe",
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
  "allow",
  "drop",
  "log_only",
]);

/**
 * 解析动作字符串为语义类别。
 * @param {string | null | undefined} action 后端返回的动作名
 * @returns {ActionTone} 语义类别；未知动作返回 "unknown"
 */
export function actionTone(action?: string | null): ActionTone {
  if (!action) return "unknown";
  return ACTION_TONE[action.toLowerCase()] ?? "unknown";
}

/**
 * 取动作徽章的语义类名。
 * @param {string | null | undefined} action 后端返回的动作名
 * @returns {string} Tailwind 类名串，需与 Badge variant="outline" 搭配
 */
export function actionBadgeClass(action?: string | null): string {
  return TONE_CLASS[actionTone(action)];
}

/**
 * 取动作严重度，用于需要按危险程度排序或高亮的场景。
 * @param {string | null | undefined} action 后端返回的动作名
 * @returns {number} 与后端 TerminalPriority 同序的分值
 */
export function actionSeverity(action?: string | null): number {
  return TONE_SEVERITY[actionTone(action)];
}

/**
 * 判断动作是否有对应的 i18n 文案。
 * @param {string | null | undefined} action 后端返回的动作名
 * @returns {boolean} true 表示可用 `securityEvents.action.<action>` 取文案
 */
export function hasActionLabel(action?: string | null): boolean {
  return !!action && TRANSLATABLE_ACTIONS.has(action.toLowerCase());
}
