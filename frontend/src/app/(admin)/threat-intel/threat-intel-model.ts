/**
 * 威胁情报模块的数据模型：类型别名、本地化下拉选项、表单状态与格式化辅助。
 *
 * 后端契约（internal/store/threatintel、internal/admin/system/threatintel）：
 * - `kind` 仅接受 `blacklist` / `whitelist`；
 * - `action` 仅接受 `intercept` / `drop`；
 * - `sync_interval` 单位为秒；
 * - 同步日志的 `trigger` 仅接受 `auto` / `manual`。
 */

import type { MessageKey, TranslateFn } from "@/i18n";
import type { LocalizedOption } from "@/i18n/localized-options";
import type { ThreatIntelFeed } from "@/lib/types/ip";

/** 订阅源名单类型 */
export type FeedKind = "blacklist" | "whitelist";

/** 订阅源命中动作 */
export type FeedAction = "intercept" | "drop";

/** 名单类型展示文案；未知后端值由调用方回退原样展示 */
export const KIND_LABELS: Record<string, MessageKey> = {
  blacklist: "threatIntel.kind.blacklist",
  whitelist: "threatIntel.kind.whitelist",
};

/** 命中动作展示文案；未知后端值由调用方回退原样展示 */
export const ACTION_LABELS: Record<string, MessageKey> = {
  intercept: "threatIntel.action.intercept",
  drop: "threatIntel.action.drop",
};

/** 同步日志触发方式展示文案（后端注释：auto | manual） */
export const TRIGGER_LABELS: Record<string, MessageKey> = {
  auto: "threatIntel.logs.scheduled",
  manual: "threatIntel.logs.manual",
};

/** 表单中的名单类型选项 */
export const KIND_FORM_OPTIONS: LocalizedOption<FeedKind>[] = [
  { key: "blacklist", label: "blacklist", labelKey: "threatIntel.kind.blacklist" },
  { key: "whitelist", label: "whitelist", labelKey: "threatIntel.kind.whitelist" },
];

/** 表单中的命中动作选项 */
export const ACTION_FORM_OPTIONS: LocalizedOption<FeedAction>[] = [
  { key: "intercept", label: "intercept", labelKey: "threatIntel.action.intercept" },
  { key: "drop", label: "drop", labelKey: "threatIntel.action.drop" },
];

/** 同步间隔选项（键为秒数字符串，与 SimpleSelect 的字符串键约束一致） */
export const SYNC_INTERVAL_FORM_OPTIONS: LocalizedOption[] = [
  { key: "300", label: "300", labelKey: "threatIntel.interval.every5m" },
  { key: "1800", label: "1800", labelKey: "threatIntel.interval.every30m" },
  { key: "3600", label: "3600", labelKey: "threatIntel.interval.every1h" },
  { key: "21600", label: "21600", labelKey: "threatIntel.interval.every6h" },
  { key: "86400", label: "86400", labelKey: "threatIntel.interval.daily" },
];

/**
 * 同步间隔展示文本：按天 / 小时 / 分钟 / 秒取最大整单位。
 *
 * 与后端 `sync_interval` 的秒级语义一一对应，例如 3600 → 「1 小时」；
 * 数量为 1 时使用单独的单数文案，避免英文出现 "1 hours"。
 */
export function formatInterval(t: TranslateFn, sec: number): string {
  const pick = (one: MessageKey, many: MessageKey, count: number) =>
    count === 1 ? t(one) : t(many, { count });
  if (sec % 86400 === 0) return pick("threatIntel.interval.dayOne", "threatIntel.interval.days", sec / 86400);
  if (sec % 3600 === 0) return pick("threatIntel.interval.hourOne", "threatIntel.interval.hours", sec / 3600);
  if (sec % 60 === 0) return pick("threatIntel.interval.minuteOne", "threatIntel.interval.minutes", sec / 60);
  return pick("threatIntel.interval.secondOne", "threatIntel.interval.seconds", sec);
}

/** 新建 / 编辑弹窗的表单状态 */
export type FeedFormState = {
  name: string;
  url: string;
  kind: FeedKind;
  action: FeedAction;
  auth_header_name: string;
  auth_header_value: string;
  sync_interval: number;
  enabled: boolean;
  /** null = 全局（不绑定站点） */
  site_id: number | null;
};

export const EMPTY_FORM: FeedFormState = {
  name: "",
  url: "",
  kind: "blacklist",
  action: "drop",
  auth_header_name: "",
  auth_header_value: "",
  sync_interval: 3600,
  enabled: true,
  site_id: null,
};

/** 列表项 → 表单状态；非法枚举值回退默认项 */
export function feedToForm(feed: ThreatIntelFeed): FeedFormState {
  return {
    name: feed.name,
    url: feed.url,
    kind: feed.kind === "whitelist" ? "whitelist" : "blacklist",
    action: feed.action === "drop" ? "drop" : "intercept",
    auth_header_name: feed.auth_header_name,
    auth_header_value: feed.auth_header_value,
    sync_interval: feed.sync_interval,
    enabled: feed.enabled,
    site_id: feed.site_id ?? null,
  };
}
