"use client";

import { ThemeProvider } from "next-themes";
import type { ReactNode } from "react";
import { I18nProvider } from "@/i18n";

/**
 * 全局 Provider。
 *
 * attribute 同时输出 class 与 data-theme：HeroUI 官方样式两套暗色选择器
 * （.dark / [data-theme="dark"]）都认，而项目自定义的 globals.css 变量
 * 写在 .dark 块下——只设 data-theme 会导致自定义暗色变量全部失效，
 * 表单控件失去边框与背景对比（弹窗内容视觉塌陷）。
 *
 * I18nProvider 位于 ThemeProvider 内层：语言切换只影响文案，
 * 与主题解析互不依赖。
 */
export function Providers({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider attribute={["class", "data-theme"]} defaultTheme="dark" enableSystem={false}>
      <I18nProvider>{children}</I18nProvider>
    </ThemeProvider>
  );
}
