"use client";

import { useEffect, useState } from "react";
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import zh from "@/lib/i18n/locales/zh.json";
import en from "@/lib/i18n/locales/en.json";

/**
 * i18n 客户端初始化 Provider
 * 仅在客户端 useEffect 中执行初始化，避免 SSR 环境下 react-i18next 兼容问题
 * 静态导出场景下，SSR 阶段 useTranslation 会 fallback 到返回 key，客户端 hydrate 后正常显示翻译
 */
export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(i18n.isInitialized);

  useEffect(() => {
    if (i18n.isInitialized) {
      setReady(true);
      return;
    }
    i18n
      .use(LanguageDetector)
      .use(initReactI18next)
      .init({
        resources: {
          zh: { translation: zh },
          en: { translation: en },
        },
        fallbackLng: "zh",
        interpolation: { escapeValue: false },
        detection: {
          order: ["localStorage", "navigator"],
          caches: ["localStorage"],
        },
        react: {
          useSuspense: false,
        },
      })
      .then(() => {
        setReady(true);
      });
  }, []);

  if (!ready) return null;
  return <>{children}</>;
}
