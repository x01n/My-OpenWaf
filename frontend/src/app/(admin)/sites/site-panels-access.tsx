"use client";

/**
 * 站点详情「访问控制」面板入口：基本开关 + 认证提供方 + 本地用户 + 路径规则。
 *
 * 基本开关数据源：GET/POST /sites/:id/access
 * shared_password 留空表示不变更现有密码。
 */

import { useCallback, useEffect, useState } from "react";
import { Button, TextField, Input } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type { SiteAccessConfig } from "@/lib/types/site-admin";
import { StatusChip, ToggleSwitch } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";
import { ProvidersPanel } from "./site-panels-auth-providers";
import { UsersPanel } from "./site-panels-access-users";
import { PathRulesPanel } from "./site-panels-path-rules";

/** 访问控制 Tab 总入口。 */
export function AccessPanel({ siteId }: { siteId: number }) {
  return (
    <div className="flex flex-col gap-5 py-2">
      <BasicAccessCard siteId={siteId} />
      <ProvidersPanel siteId={siteId} />
      <UsersPanel siteId={siteId} />
      <PathRulesPanel siteId={siteId} />
    </div>
  );
}

/** 基本开关：共享密码 + 会话有效期。 */
function BasicAccessCard({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const { data, loading, reload } = useApi(
    useCallback(() => apiGet<SiteAccessConfig>(`/sites/${siteId}/access`), [siteId]),
  );

  const [enabled, setEnabled] = useState(false);
  const [password, setPassword] = useState("");
  const [ttl, setTtl] = useState("86400");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!data) return;
    setEnabled(data.enabled);
    setTtl(String(data.session_ttl));
  }, [data]);

  async function handleSave() {
    setSaving(true);
    try {
      await apiPost(`/sites/${siteId}/access`, {
        enabled,
        shared_password: password,
        session_ttl: Number(ttl) > 0 ? Number(ttl) : 86400,
      });
      showSuccess(t("siteDetail.access.saved"));
      setPassword("");
      void reload();
    } catch (err) {
      showError(t("sites.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  if (loading && !data) {
    return <div className="text-muted py-6 text-center text-sm">{t("common.loading")}</div>;
  }

  return (
    <section className="flex flex-col gap-3">
      <h4 className="text-muted border-t border-separator pt-3 text-xs font-semibold">
        {t("siteDetail.access.basicTitle")}
      </h4>
      <div className="text-muted text-xs">
        {t("siteDetail.access.sharedPasswordStatus")}
        <StatusChip tone={data?.shared_password_set ? "success" : "neutral"}>
          {data?.shared_password_set
            ? t("siteDetail.access.passwordSet")
            : t("siteDetail.access.passwordUnset")}
        </StatusChip>
      </div>
      <ToggleSwitch isSelected={enabled} onChange={setEnabled}>
        {t("siteDetail.access.enable")}
      </ToggleSwitch>
      <TextField aria-label={t("login.password")}>
        <Input
          type="password"
          placeholder={
            data?.shared_password_set
              ? t("siteDetail.access.passwordPlaceholder.set")
              : t("siteDetail.access.passwordPlaceholder.unset")
          }
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </TextField>
      <TextField aria-label={t("siteDetail.access.ttlPlaceholder")}>
        <Input
          type="number"
          placeholder={t("siteDetail.access.ttlPlaceholder")}
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
        />
      </TextField>
      <div>
        <Button variant="primary" isPending={saving} onPress={() => void handleSave()}>
          {t("common.save")}
        </Button>
      </div>
    </section>
  );
}
