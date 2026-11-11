"use client";

import { ShieldHalf } from "lucide-react";
import { LanguageToggle } from "@/components/layout/language-toggle";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { useI18n } from "@/i18n";

/**
 * 登录页顶栏：左侧品牌标识，右侧语言与主题切换。
 *
 * 与业务外壳解耦：未登录状态没有侧边栏，控件直接复用全局切换组件，
 * 保证偏好写入与登录后页面完全一致。
 */
export function LoginHeader() {
  const { t } = useI18n();
  return (
    <header className="login-header">
      <div className="login-header-inner">
        <div className="login-brandmark">
          <span className="login-brandmark-icon" aria-hidden="true">
            <ShieldHalf className="size-4" strokeWidth={2.2} />
          </span>
          <span className="login-brandmark-text">{t("brand.name")}</span>
        </div>
        <div className="login-actions">
          <LanguageToggle />
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

/** 登录页页脚：版权与产品定位说明。 */
export function LoginFooter() {
  const { t } = useI18n();
  return (
    <footer className="login-footer">
      <div className="login-footer-inner">
        <span suppressHydrationWarning>
          {t("login.footer.copyright", { year: new Date().getFullYear() })}
        </span>
        <span>{t("login.footer.note")}</span>
      </div>
    </footer>
  );
}
