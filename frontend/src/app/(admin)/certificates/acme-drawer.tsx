"use client";

/**
 * ACME 设置抽屉：展示并保存 ACME 配置（仅 admin 可保存，接口失败显示后端 error）。
 *
 * 后端契约（internal/admin/system/acme.go）：
 * - GET /certificates/acme/config → ACMEConfig
 * - POST /certificates/acme/config（adminGroup）→ 校验失败/无权限时 {"error": "..."}
 */

import { useCallback, useEffect, useState } from "react";
import { useOverlayState, Button, TextField, Input } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type { ACMEConfig, ACMEStatusItem } from "@/lib/types/site";
import { DetailDrawer } from "@/components/ui/detail-drawer";
import { StatusChip, ToggleSwitch } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils/format";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";

export function AcmeConfigDrawer({
  state,
}: {
  state: ReturnType<typeof useOverlayState>;
}) {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi(
    useCallback(() => apiGet<ACMEConfig>("/certificates/acme/config"), []),
  );

  // ACME 证书状态（GET /certificates/acme/status，仅 admin 可读）
  const status = useApi(
    useCallback(() => apiGet<{ items: ACMEStatusItem[] }>("/certificates/acme/status"), []),
  );
  const statusItems = status.data?.items ?? [];

  const [enabled, setEnabled] = useState(false);
  const [email, setEmail] = useState("");
  const [directoryUrl, setDirectoryUrl] = useState("");
  const [autoRenew, setAutoRenew] = useState(true);
  const [renewBeforeDays, setRenewBeforeDays] = useState("30");
  const [caaCheckEnabled, setCaaCheckEnabled] = useState(false);
  const [caaAllowedIssuers, setCaaAllowedIssuers] = useState("");
  const [caaDnsServer, setCaaDnsServer] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!data) return;
    setEnabled(data.enabled);
    setEmail(data.email ?? "");
    setDirectoryUrl(data.directory_url ?? "");
    setAutoRenew(data.auto_renew);
    setRenewBeforeDays(String(data.renew_before_days ?? 30));
    setCaaCheckEnabled(data.caa_check_enabled);
    setCaaAllowedIssuers(data.caa_allowed_issuers ?? "");
    setCaaDnsServer(data.caa_dns_server ?? "");
  }, [data]);

  async function handleSave() {
    setSaving(true);
    try {
      await apiPost("/certificates/acme/config", {
        enabled,
        email,
        directory_url: directoryUrl,
        auto_renew: autoRenew,
        renew_before_days: Number(renewBeforeDays) > 0 ? Number(renewBeforeDays) : 30,
        caa_check_enabled: caaCheckEnabled,
        caa_allowed_issuers: caaAllowedIssuers,
        caa_dns_server: caaDnsServer,
      });
      showSuccess(t("certificates.acme.saved"));
      void reload();
    } catch (err) {
      showError(t("certificates.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <DetailDrawer
      state={state}
      title={t("certificates.acme.configTitle")}
      description={t("certificates.acme.configDescription")}
      width="w-[520px]"
    >
      {loading && !data ? (
        <div className="text-muted py-6 text-center text-sm">{t("common.loading")}</div>
      ) : error ? (
        <div className="text-danger py-6 text-center text-sm">{error}</div>
      ) : (
        <div className="flex flex-col gap-3">
          <ToggleSwitch isSelected={enabled} onChange={setEnabled}>
            {t("certificates.acme.enabled")}
          </ToggleSwitch>
          <TextField aria-label={t("certificates.acme.email")}>
            <Input
              type="email"
              placeholder={t("certificates.acme.emailConfigPlaceholder")}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </TextField>
          <TextField aria-label={t("certificates.acme.directoryUrl")}>
            <Input
              placeholder={t("certificates.acme.directoryUrlPlaceholder")}
              value={directoryUrl}
              onChange={(e) => setDirectoryUrl(e.target.value)}
            />
          </TextField>
          <ToggleSwitch isSelected={autoRenew} onChange={setAutoRenew}>
            {t("certificates.acme.autoRenew")}
          </ToggleSwitch>
          <TextField aria-label={t("certificates.acme.renewBeforeDays")}>
            <Input
              type="number"
              placeholder={t("certificates.acme.renewBeforeDaysPlaceholder")}
              value={renewBeforeDays}
              onChange={(e) => setRenewBeforeDays(e.target.value)}
            />
          </TextField>
          <ToggleSwitch isSelected={caaCheckEnabled} onChange={setCaaCheckEnabled}>
            {t("certificates.acme.caaCheck")}
          </ToggleSwitch>
          {caaCheckEnabled ? (
            <>
              <TextField aria-label={t("certificates.acme.caaIssuers")}>
                <Input
                  placeholder={t("certificates.acme.caaIssuersPlaceholder")}
                  value={caaAllowedIssuers}
                  onChange={(e) => setCaaAllowedIssuers(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("certificates.acme.caaDnsServer")}>
                <Input
                  placeholder={t("certificates.acme.caaDnsServerPlaceholder")}
                  value={caaDnsServer}
                  onChange={(e) => setCaaDnsServer(e.target.value)}
                />
              </TextField>
            </>
          ) : null}
          <div>
            <Button variant="primary" isPending={saving} onPress={() => void handleSave()}>
              {t("common.save")}
            </Button>
          </div>

          <div className="mt-2 border-t border-separator pt-3">
            <div className="mb-2 text-sm font-medium">{t("certificates.acme.statusTitle")}</div>
            {status.loading && !status.data ? (
              <div className="text-muted text-xs">{t("common.loading")}</div>
            ) : status.error ? (
              <div className="text-muted text-xs">{t("certificates.acme.statusAdminOnly")}</div>
            ) : statusItems.length === 0 ? (
              <div className="text-muted text-xs">{t("certificates.acme.statusEmpty")}</div>
            ) : (
              <div className="bg-surface rounded-xl border border-separator px-3 py-1">
                {statusItems.map((c) => (
                  <div key={c.id} className="border-b border-separator py-2 last:border-0">
                    <div className="flex items-center justify-between gap-2 text-sm">
                      <span className="min-w-0 break-all font-medium">{c.name || c.domain}</span>
                      <StatusChip tone={c.auto_renew ? "success" : "neutral"}>
                        {c.auto_renew
                          ? t("certificates.acme.autoRenewBadge")
                          : t("certificates.acme.manualBadge")}
                      </StatusChip>
                    </div>
                    <div className="text-muted tabular mt-0.5 text-xs">
                      {t("certificates.acme.expiresAt", {
                        domain: c.domain,
                        date: formatDateTime(c.expires_at),
                      })}
                    </div>
                    {c.error ? <div className="text-danger mt-0.5 text-xs">{c.error}</div> : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </DetailDrawer>
  );
}
