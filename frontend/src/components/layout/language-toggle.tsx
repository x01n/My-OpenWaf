"use client";

import { Languages } from "lucide-react";
import { Button } from "@heroui/react";
import { useI18n } from "@/i18n";

/**
 * 中英文切换按钮。
 *
 * 按钮展示的是「点击后将切换到的目标语言」：当前中文显示 `EN`，当前英文显示 `中`。
 * 语言状态由 `I18nProvider` 统一维护，切换后全局文案与 `<html lang>` 同步更新。
 */
export function LanguageToggle() {
  const { locale, setLocale, t } = useI18n();
  return (
    <Button
      variant="ghost"
      size="sm"
      aria-label={t("common.toggleLanguage")}
      onPress={() => setLocale(locale === "zh" ? "en" : "zh")}
    >
      <Languages className="size-4" />
      <span className="text-xs font-medium">{locale === "zh" ? "EN" : "中"}</span>
    </Button>
  );
}
