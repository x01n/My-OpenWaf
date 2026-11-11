import type { MessageKey, TranslateFn } from "./index";

/**
 * 下拉选项：`labelKey` 存在时按当前语言渲染，否则直接使用 `label`。
 *
 * `label` 通常保留后端技术原值（如 `tcp4`、`intercept`），便于排查日志与接口；
 * 需要面向用户的语义文案时提供 `labelKey`。泛型 `T` 用于约束选项键，
 * 便于与强类型 `SimpleSelect<T>` 组合。
 */
export type LocalizedOption<T extends string = string> = {
  key: T;
  label: string;
  labelKey?: MessageKey;
};

/** 将选项按当前语言本地化；无 `labelKey` 的技术值原样输出。 */
export function localizeOptions<T extends string>(
  options: readonly LocalizedOption<T>[],
  t: TranslateFn,
): { key: T; label: string }[] {
  return options.map((o) => ({ key: o.key, label: o.labelKey ? t(o.labelKey) : o.label }));
}
