"use client";

/**
 * 站点高级配置：防护覆盖、质询动作与按 phase 跳过路径。
 *
 * 所有覆盖开关遵循三态语义（继承全局 / 覆盖启用 / 覆盖关闭），
 * 与 internal/store/site.go 的 *bool / *string 字段一一对应。
 */

import { SimpleSelect, ToggleSwitch } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";
import {
  localizeOptions,
  type LocalizedOption,
  type SiteAdvancedDraft,
} from "./site-advanced-model";
import {
  ANTI_REPLAY_COOKIE_MODE_OPTIONS,
  CAPTCHA_TYPE_OPTIONS,
  CHALLENGE_ACTION_OPTIONS,
  OWASP_SENSITIVITY_OPTIONS,
  SITE_ACTION_OPTIONS,
} from "./site-advanced-model";
import {
  FieldRow,
  Section,
  TextAreaRow,
  TextRow,
  TriStateBool,
  TriStateText,
} from "./form-primitives";

type SetDraft = (patch: Partial<SiteAdvancedDraft>) => void;

/** anti-replay 允许保留的动作集（internal/admin/shared ValidateAntiReplayAction） */
const ANTI_REPLAY_ACTION_OPTIONS: LocalizedOption[] = [
  { key: "", label: "inherit", labelKey: "siteDetail.advanced.protection.inheritDefault" },
  { key: "intercept", label: "intercept", labelKey: "siteDetail.advanced.action.intercept" },
  { key: "challenge", label: "challenge", labelKey: "siteDetail.advanced.action.challenge" },
  {
    key: "captcha_challenge",
    label: "captcha_challenge",
    labelKey: "siteDetail.advanced.action.captchaChallenge",
  },
  {
    key: "shield_challenge",
    label: "shield_challenge",
    labelKey: "siteDetail.advanced.action.shieldChallenge",
  },
  {
    key: "chain_challenge",
    label: "chain_challenge",
    labelKey: "siteDetail.advanced.action.chainChallenge",
  },
];

/** 防护覆盖区块：Bot / OWASP / CVE / 限速 / 反重放 */
export function ProtectionOverrideSection({
  draft,
  set,
}: {
  draft: SiteAdvancedDraft;
  set: SetDraft;
}) {
  const { t } = useI18n();
  return (
    <Section
      title={t("siteDetail.advanced.protection.title")}
      description={t("siteDetail.advanced.protection.description")}
    >
      <div className="grid gap-4 md:grid-cols-2">
        <div className="flex flex-col gap-2 rounded-lg border border-separator p-3">
          <TriStateBool
            label={t("siteDetail.advanced.protection.bot")}
            value={draft.bot_protection_enabled}
            onChange={(v) => set({ bot_protection_enabled: v })}
          />
          <TextRow
            label={t("siteDetail.advanced.protection.botLevel")}
            value={draft.bot_protection_level}
            onChange={(v) => set({ bot_protection_level: v })}
            placeholder={t("siteDetail.advanced.protection.botLevelPlaceholder")}
          />
        </div>

        <div className="flex flex-col gap-2 rounded-lg border border-separator p-3">
          <TriStateBool
            label={t("siteDetail.advanced.protection.owasp")}
            value={draft.owasp_enabled}
            onChange={(v) => set({ owasp_enabled: v })}
          />
          <TriStateText
            label={t("siteDetail.advanced.protection.owaspSensitivity")}
            value={draft.owasp_sensitivity}
            onChange={(v) => set({ owasp_sensitivity: v })}
            options={localizeOptions(OWASP_SENSITIVITY_OPTIONS.slice(1), t)}
          />
          <TriStateText
            label={t("siteDetail.advanced.protection.owaspAction")}
            value={draft.owasp_action}
            onChange={(v) => set({ owasp_action: v })}
            options={localizeOptions(SITE_ACTION_OPTIONS.slice(1), t)}
          />
        </div>

        <div className="flex flex-col gap-2 rounded-lg border border-separator p-3">
          <TriStateBool
            label={t("siteDetail.advanced.protection.cve")}
            value={draft.cve_enabled}
            onChange={(v) => set({ cve_enabled: v })}
          />
          <TriStateText
            label={t("siteDetail.advanced.protection.cveAction")}
            value={draft.cve_action}
            onChange={(v) => set({ cve_action: v })}
            options={localizeOptions(SITE_ACTION_OPTIONS.slice(1), t)}
          />
        </div>

        <div className="flex flex-col gap-2 rounded-lg border border-separator p-3">
          <TriStateBool
            label={t("siteDetail.advanced.protection.rateLimit")}
            value={draft.rate_limit_enabled}
            onChange={(v) => set({ rate_limit_enabled: v })}
          />
          <TextRow
            label={t("siteDetail.advanced.protection.rateLimitWindow")}
            type="number"
            value={String(draft.rate_limit_window)}
            onChange={(v) => set({ rate_limit_window: Number(v) || 0 })}
          />
          <TextRow
            label={t("siteDetail.advanced.protection.rateLimitMax")}
            type="number"
            value={String(draft.rate_limit_max)}
            onChange={(v) => set({ rate_limit_max: Number(v) || 0 })}
          />
          <TriStateText
            label={t("siteDetail.advanced.protection.rateLimitAction")}
            value={draft.rate_limit_action}
            onChange={(v) => set({ rate_limit_action: v })}
            options={localizeOptions(SITE_ACTION_OPTIONS.slice(1), t)}
          />
        </div>

        <div className="flex flex-col gap-2 rounded-lg border border-separator p-3">
          <TriStateBool
            label={t("siteDetail.advanced.protection.antiReplay")}
            value={draft.anti_replay_enabled}
            onChange={(v) => set({ anti_replay_enabled: v })}
          />
          <TextRow
            label={t("siteDetail.advanced.protection.antiReplayTtl")}
            type="number"
            value={String(draft.anti_replay_ttl)}
            onChange={(v) => set({ anti_replay_ttl: Number(v) || 0 })}
          />
          <FieldRow
            label={t("siteDetail.advanced.protection.antiReplayAction")}
            hint={t("siteDetail.advanced.protection.antiReplayActionHint")}
          >
            <SimpleSelect<string>
              value={draft.anti_replay_action}
              onChange={(v) => set({ anti_replay_action: v })}
              label={t("siteDetail.advanced.protection.antiReplayAction")}
              className="w-full"
              options={localizeOptions(ANTI_REPLAY_ACTION_OPTIONS, t)}
            />
          </FieldRow>
          <TriStateText
            label={t("siteDetail.advanced.protection.antiReplayCookieMode")}
            value={draft.anti_replay_cookie_mode}
            onChange={(v) => set({ anti_replay_cookie_mode: v })}
            options={localizeOptions(ANTI_REPLAY_COOKIE_MODE_OPTIONS, t)}
          />
        </div>

        <div className="flex flex-col gap-2 rounded-lg border border-separator p-3">
          <TriStateText
            label={t("siteDetail.advanced.protection.challengeAction")}
            value={draft.challenge_action}
            onChange={(v) => set({ challenge_action: v })}
            options={localizeOptions(CHALLENGE_ACTION_OPTIONS, t)}
          />
          <TriStateText
            label={t("siteDetail.advanced.protection.captchaType")}
            value={draft.captcha_type}
            onChange={(v) => set({ captcha_type: v })}
            options={localizeOptions(CAPTCHA_TYPE_OPTIONS, t)}
          />
        </div>
      </div>
    </Section>
  );
}

/** 按 phase 跳过路径分区 */
export function SkipPathSection({ draft, set }: { draft: SiteAdvancedDraft; set: SetDraft }) {
  const { t } = useI18n();
  const overridden = draft.skip_path_by_phase !== null;
  return (
    <Section
      title={t("siteDetail.advanced.skipPath.title")}
      description={t("siteDetail.advanced.skipPath.description")}
    >
      <ToggleSwitch
        isSelected={overridden}
        onChange={(v) => set({ skip_path_by_phase: v ? "{}" : null })}
      >
        {t("siteDetail.advanced.skipPath.override")}
      </ToggleSwitch>
      {overridden ? (
        <TextAreaRow
          label={t("siteDetail.advanced.skipPath.json")}
          value={draft.skip_path_by_phase ?? "{}"}
          onChange={(v) => set({ skip_path_by_phase: v })}
          placeholder='{"owasp_default":["/health"],"cve_detection":["/upload"]}'
          hint={t("siteDetail.advanced.skipPath.jsonHint")}
          rows={5}
        />
      ) : (
        <p className="text-muted text-xs">{t("siteDetail.advanced.skipPath.inherited")}</p>
      )}
    </Section>
  );
}
