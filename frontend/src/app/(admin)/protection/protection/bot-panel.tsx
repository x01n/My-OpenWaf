"use client";

/**
 * Bot 防护 Tab：GET /bot-settings 表单 + POST /bot-settings/update
 * + GET /bot-stats 统计卡。
 * 字段逐一取自 internal/admin/shared/helpers.go BotSettingsResponse（L622-646）
 * 与 internal/admin/protect/bot/bot.go BotSettingsUpdate（L18-42）。
 */

import { useCallback, useEffect, useState } from "react";
import { Button } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n, useNumberFormat } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton, StatCard } from "@/components/ui/primitives";
import type { BotSettings, BotStats } from "@/lib/types/protection";
import {
  SectionCard,
  SwitchRow,
  NumberField,
  TextFieldRow,
  SelectRow,
} from "./field-controls";
import {
  ANTI_REPLAY_MODES,
  BROWSER_SIGN_ACTIONS,
  JS_PROTECTION_MODES,
} from "./protection-model";

export function BotPanel() {
  const { t } = useI18n();
  const fmt = useNumberFormat();
  const { data, loading, error, reload } = useApi<BotSettings>(
    useCallback(() => apiGet<BotSettings>("/bot-settings"), []),
  );
  const stats = useApi<BotStats>(
    useCallback(() => apiGet<BotStats>("/bot-stats"), []),
  );
  const [form, setForm] = useState<BotSettings | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  const patch = useCallback(
    <K extends keyof BotSettings>(key: K, value: BotSettings[K]) => {
      setForm((f) => (f ? { ...f, [key]: value } : f));
    },
    [],
  );

  /** 把换行/逗号分隔的文本解析为字符串数组（空条目剔除） */
  const toList = (s: string): string[] =>
    s
      .split(/[\n,]/)
      .map((x) => x.trim())
      .filter(Boolean);

  async function save() {
    if (!form) return;
    setSaving(true);
    try {
      await apiPost("/bot-settings/update", form);
      showSuccess(t("protection.saved"));
      await reload();
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  const antiReplayModes = localizeOptions(ANTI_REPLAY_MODES, t);
  const browserSignActions = localizeOptions(BROWSER_SIGN_ACTIONS, t);
  const jsProtectionModes = localizeOptions(JS_PROTECTION_MODES, t);

  return (
    <div className="flex flex-col gap-4">
      {/* 24h 统计 */}
      {stats.error ? null : (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <StatCard label={t("protection.bot.stats.total")} value={fmt(stats.data?.total_24h)} />
          <StatCard label={t("protection.bot.stats.blocked")} value={fmt(stats.data?.blocked_24h)} tone="danger" />
          <StatCard label={t("protection.bot.stats.highRisk")} value={fmt(stats.data?.high_risk_24h)} tone="warning" />
          <StatCard label={t("protection.bot.stats.avgScore")} value={stats.data ? stats.data.avg_score_24h.toFixed(1) : "0"} tone="info" />
        </div>
      )}

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !form ? (
        <CardSkeleton height="h-96" />
      ) : form ? (
        <>
          <SectionCard title={t("protection.bot.switches.title")}>
            <div className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-2">
              <SwitchRow label={t("protection.bot.switches.enabled")} value={form.enabled} onChange={(v) => patch("enabled", v)} />
              <SwitchRow label={t("protection.bot.switches.captcha")} value={form.captcha_enabled} onChange={(v) => patch("captcha_enabled", v)} />
              <SwitchRow label={t("protection.bot.switches.dynamicProtection")} value={form.dynamic_protection_enabled} onChange={(v) => patch("dynamic_protection_enabled", v)} />
              <SwitchRow label={t("protection.bot.switches.htmlObfuscation")} value={form.html_obfuscation} onChange={(v) => patch("html_obfuscation", v)} />
              <SwitchRow label={t("protection.bot.switches.jsObfuscation")} value={form.js_obfuscation} onChange={(v) => patch("js_obfuscation", v)} />
              <SwitchRow label={t("protection.bot.switches.imageWatermark")} value={form.image_watermark} onChange={(v) => patch("image_watermark", v)} />
              <SwitchRow label={t("protection.bot.switches.htmlToMarkdown")} value={form.html_to_markdown_enabled} onChange={(v) => patch("html_to_markdown_enabled", v)} />
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <NumberField label={t("protection.bot.switches.scoreThreshold")} value={form.score_threshold} onChange={(v) => patch("score_threshold", v)} min={1} hint={t("protection.bot.switches.scoreThresholdHint")} />
              <TextFieldRow label={t("protection.bot.switches.geoipPath")} value={form.geoip_db_path} onChange={(v) => patch("geoip_db_path", v)} placeholder="/path/to/GeoLite2-Country.mmdb" />
            </div>
          </SectionCard>

          <SectionCard
            title={t("protection.bot.lists.title")}
            description={t("protection.bot.lists.description")}
          >
            <TextFieldRow
              label={t("protection.bot.lists.highRiskCountries")}
              value={(form.high_risk_countries ?? []).join(",")}
              onChange={(v) => patch("high_risk_countries", toList(v))}
              placeholder={t("protection.bot.lists.highRiskCountriesPlaceholder")}
            />
            <TextFieldRow
              label={t("protection.bot.lists.datacenterAsns")}
              value={(form.datacenter_asns ?? []).join(",")}
              onChange={(v) =>
                patch(
                  "datacenter_asns",
                  toList(v)
                    .map(Number)
                    .filter((n) => Number.isFinite(n) && n > 0),
                )
              }
              placeholder={t("protection.bot.lists.datacenterAsnsPlaceholder")}
            />
            <TextFieldRow
              label={t("protection.bot.lists.vpnProxyAsns")}
              value={(form.vpn_proxy_asns ?? []).join(",")}
              onChange={(v) =>
                patch(
                  "vpn_proxy_asns",
                  toList(v)
                    .map(Number)
                    .filter((n) => Number.isFinite(n) && n > 0),
                )
              }
            />
            <TextFieldRow
              label={t("protection.bot.lists.jsObfuscationPaths")}
              value={(form.js_obfuscation_paths ?? []).join(",")}
              onChange={(v) => patch("js_obfuscation_paths", toList(v))}
              placeholder="/admin/*,/login"
            />
            <TextFieldRow
              label={t("protection.bot.lists.watermarkPaths")}
              value={(form.image_watermark_paths ?? []).join(",")}
              onChange={(v) => patch("image_watermark_paths", toList(v))}
            />
            <TextFieldRow label={t("protection.bot.lists.watermarkText")} value={form.watermark_text ?? ""} onChange={(v) => patch("watermark_text", v)} />
            <TextFieldRow
              label={t("protection.bot.lists.excludeHeaders")}
              value={(form.exclude_record_headers ?? []).join(",")}
              onChange={(v) => patch("exclude_record_headers", toList(v))}
              hint={t("protection.bot.lists.excludeHeadersHint")}
            />
          </SectionCard>

          <SectionCard
            title={t("protection.bot.antiReplay.title")}
            description={t("protection.bot.antiReplay.description")}
          >
            <SwitchRow label={t("protection.bot.antiReplay.enabled")} value={form.anti_replay_enabled} onChange={(v) => patch("anti_replay_enabled", v)} />
            <SelectRow label={t("protection.bot.antiReplay.cookieMode")} value={form.anti_replay_cookie_mode || "standard"} onChange={(v) => patch("anti_replay_cookie_mode", v)} options={antiReplayModes} />
            <SwitchRow label={t("protection.bot.antiReplay.browserSignEnabled")} value={form.browser_sign_enabled} onChange={(v) => patch("browser_sign_enabled", v)} />
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <NumberField label={t("protection.bot.antiReplay.signTtl")} value={form.browser_sign_ttl} onChange={(v) => patch("browser_sign_ttl", v)} />
              <SelectRow label={t("protection.bot.antiReplay.signAction")} value={form.browser_sign_action || "challenge"} onChange={(v) => patch("browser_sign_action", v)} options={browserSignActions} />
            </div>
          </SectionCard>

          <SectionCard title={t("protection.bot.jsCache.title")}>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <SelectRow label={t("protection.bot.jsCache.mode")} value={form.js_protection_mode ?? "all"} onChange={(v) => patch("js_protection_mode", v)} options={jsProtectionModes} />
              <NumberField label={t("protection.bot.jsCache.decryptTtl")} value={form.decrypt_cache_ttl_seconds ?? 0} onChange={(v) => patch("decrypt_cache_ttl_seconds", v)} min={0} />
            </div>
          </SectionCard>

          <div className="flex justify-end">
            <Button variant="primary" isPending={saving} onPress={save}>
              {t("protection.bot.save")}
            </Button>
          </div>
        </>
      ) : null}
    </div>
  );
}
