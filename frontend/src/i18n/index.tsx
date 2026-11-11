"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { I18nProvider as HeroI18nProvider } from "@heroui/react";
import zh from "./messages/zh";
import en from "./messages/en";

/** 支持的界面语言。 */
export type Locale = "zh" | "en";

/** 语言包键名（从中文包推导，en 包由 satisfies 保证同集合）。 */
export type MessageKey = keyof typeof zh;

/** `t()` 的插值变量：`{name}` 形式。 */
export type TranslateVars = Record<string, string | number>;

/** 翻译函数签名，供子组件以参数形式接收 `t`。 */
export type TranslateFn = (key: MessageKey, vars?: TranslateVars) => string;

const DICTS: Record<Locale, Record<MessageKey, string>> = { zh, en };

/** localStorage 中持久化界面语言的键名。 */
export const LOCALE_STORAGE_KEY = "owaf_locale";

/** 语言展示名，供切换控件使用。 */
export const LOCALE_LABELS: Record<Locale, string> = {
  zh: "中文",
  en: "English",
};

type I18nValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: TranslateFn;
};

const I18nContext = createContext<I18nValue | null>(null);

/**
 * 全局 i18n Provider。
 *
 * 静态导出场景下 HTML 在构建期预渲染，因此首帧固定使用默认语言（中文），
 * 挂载后再读取 localStorage 恢复用户选择，避免 hydration 不一致。
 */
export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("zh");

  useEffect(() => {
    const saved = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (saved === "zh" || saved === "en") setLocaleState(saved);
  }, []);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en";
  }, [locale]);

  const t = useCallback(
    (key: MessageKey, vars?: TranslateVars) => {
      const template = DICTS[locale][key] ?? zh[key] ?? key;
      if (!vars) return template;
      return template.replace(/\{(\w+)\}/g, (match, name: string) =>
        vars[name] === undefined ? match : String(vars[name]),
      );
    },
    [locale],
  );

  const value = useMemo<I18nValue>(() => ({ locale, setLocale, t }), [locale, setLocale, t]);

  return (
    <I18nContext.Provider value={value}>
      <HeroI18nProvider locale={locale === "zh" ? "zh-CN" : "en-US"}>
        {children}
      </HeroI18nProvider>
    </I18nContext.Provider>
  );
}

/** 读取当前语言与翻译函数；必须在 I18nProvider 内使用。 */
export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}

/** 数字千分位格式化：按当前界面语言选择区域格式。 */
export function useNumberFormat(): (n: number | undefined) => string {
  const { locale } = useI18n();
  return useCallback(
    (n: number | undefined) => (n ?? 0).toLocaleString(locale === "zh" ? "zh-CN" : "en-US"),
    [locale],
  );
}
