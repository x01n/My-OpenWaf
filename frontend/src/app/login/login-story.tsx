"use client";

import { useI18n, type MessageKey } from "@/i18n";

/** 叙事区能力列表：仅存 i18n 键，文案在渲染期解析。 */
const CAPABILITIES: ReadonlyArray<{ titleKey: MessageKey; descKey: MessageKey }> = [
  { titleKey: "login.highlight.realtime.title", descKey: "login.highlight.realtime.desc" },
  { titleKey: "login.highlight.manage.title", descKey: "login.highlight.manage.desc" },
  { titleKey: "login.highlight.audit.title", descKey: "login.highlight.audit.desc" },
];

/**
 * 登录页叙事区：产品定位与三项能力，桌面端显示在表单卡片左侧。
 *
 * 刻意不使用卡片与图标，靠字距、编号和细分隔线建立层次，
 * 让右侧登录卡片成为页面唯一的实体容器。
 */
export function LoginStory() {
  const { t } = useI18n();
  return (
    <section className="login-story" aria-labelledby="login-story-title">
      <p className="login-eyebrow">{t("login.eyebrow")}</p>
      <h2 id="login-story-title" className="login-story-title">
        {t("login.brand.title1")}
        <br />
        <span className="login-story-title-dim">{t("login.brand.title2")}</span>
      </h2>
      <p className="login-story-desc">{t("login.brand.desc")}</p>

      <ol className="login-capabilities">
        {CAPABILITIES.map(({ titleKey, descKey }, index) => (
          <li key={titleKey} className="login-capability">
            <span className="login-capability-index" aria-hidden="true">
              {String(index + 1).padStart(2, "0")}
            </span>
            <div>
              <div className="login-capability-title">{t(titleKey)}</div>
              <p className="login-capability-desc">{t(descKey)}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
