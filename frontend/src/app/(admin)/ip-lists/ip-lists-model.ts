/**
 * IP 名单模块的数据模型：类型别名、本地化下拉选项与空表单。
 *
 * 后端契约（internal/admin/ip_lists）：
 * - `kind` 仅接受 `blacklist` / `whitelist`；
 * - `action` 仅接受 `intercept` / `drop`；
 * - 全局条目的 `site_id` 带 omitempty，必须用宽松判空。
 */

import type { LocalizedOption } from "@/i18n/localized-options";
import type { MessageKey } from "@/i18n";

export type Kind = "blacklist" | "whitelist";
export type Action = "intercept" | "drop";

/** 名单类型展示文案 */
export const KIND_LABELS: Record<Kind, MessageKey> = {
  blacklist: "ipLists.kind.blacklist",
  whitelist: "ipLists.kind.whitelist",
};

/** 命中动作展示文案 */
export const ACTION_LABELS: Record<Action, MessageKey> = {
  intercept: "ipLists.action.intercept",
  drop: "ipLists.action.drop",
};

/** 筛选栏的名单类型选项（含「全部类型」） */
export const KIND_FILTER_OPTIONS: LocalizedOption<"" | Kind>[] = [
  { key: "", label: "all", labelKey: "ipLists.kind.all" },
  { key: "blacklist", label: "blacklist", labelKey: "ipLists.kind.blacklist" },
  { key: "whitelist", label: "whitelist", labelKey: "ipLists.kind.whitelist" },
];

/** 表单中的名单类型选项（带语义说明） */
export const KIND_FORM_OPTIONS: LocalizedOption<Kind>[] = [
  { key: "blacklist", label: "blacklist", labelKey: "ipLists.kind.blacklistLong" },
  { key: "whitelist", label: "whitelist", labelKey: "ipLists.kind.whitelistLong" },
];

/** 表单中的命中动作选项（带副作用说明） */
export const ACTION_FORM_OPTIONS: LocalizedOption<Action>[] = [
  { key: "intercept", label: "intercept", labelKey: "ipLists.action.interceptLong" },
  { key: "drop", label: "drop", labelKey: "ipLists.action.dropLong" },
];

/** 预置爬虫白名单条目 */
export type PresetItem = { value: string; note: string };

/** 新建 / 编辑弹窗的表单状态 */
export type IPFormState = {
  kind: Kind;
  value: string;
  action: Action;
  note: string;
  enabled: boolean;
};

export const EMPTY_FORM: IPFormState = {
  kind: "blacklist",
  value: "",
  action: "intercept",
  note: "",
  enabled: true,
};
