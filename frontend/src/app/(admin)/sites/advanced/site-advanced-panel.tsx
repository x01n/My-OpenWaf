"use client";

/**
 * 站点高级配置面板（站点详情抽屉 Tab）。
 *
 * 数据源为 GET /sites/:id，保存走 POST /sites/:id/update，仅提交发生变化的字段。
 * 覆盖字段的三态语义与 internal/store/site.go 保持一致。
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@heroui/react";
import { RotateCcw, Save } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { CardSkeleton, ErrorState } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import type { Site } from "@/lib/types/site";
import { useI18n } from "@/i18n";
import {
  buildAdvancedDraft,
  buildAdvancedPatch,
  validateJsonBlobs,
  type SiteAdvancedDraft,
} from "./site-advanced-model";
import { ClientIPSection, TlsSection, UpstreamSection } from "./site-advanced-network";
import { ProtectionOverrideSection, SkipPathSection } from "./site-advanced-protection";
import {
  CCRulesSection,
  CacheSection,
  DynamicProtectionSection,
  MaintenanceSection,
} from "./site-advanced-runtime";

export function SiteAdvancedPanel({
  siteId,
  onChanged,
}: {
  siteId: number;
  onChanged: () => void;
}) {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<Site>(
    useCallback(() => apiGet<Site>(`/sites/${siteId}`), [siteId]),
  );
  const [initial, setInitial] = useState<SiteAdvancedDraft | null>(null);
  const [draft, setDraft] = useState<SiteAdvancedDraft | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!data) return;
    const next = buildAdvancedDraft(data);
    setInitial(next);
    setDraft(next);
  }, [data]);

  const set = useCallback((patch: Partial<SiteAdvancedDraft>) => {
    setDraft((prev) => (prev ? { ...prev, ...patch } : prev));
  }, []);

  const dirty = useMemo(() => {
    if (!draft || !initial) return false;
    return Object.keys(buildAdvancedPatch(draft, initial)).length > 0;
  }, [draft, initial]);

  async function handleSave() {
    if (!draft || !initial) return;
    const invalidField = validateJsonBlobs(draft);
    if (invalidField) {
      showError(
        t("siteDetail.advanced.saveFailed"),
        t("siteDetail.advanced.invalidJson", { field: invalidField }),
      );
      return;
    }
    const patch = buildAdvancedPatch(draft, initial);
    if (Object.keys(patch).length === 0) {
      showSuccess(t("siteDetail.advanced.nothingToSave"));
      return;
    }
    setSaving(true);
    try {
      await apiPost(`/sites/${siteId}/update`, patch);
      showSuccess(t("siteDetail.advanced.saved"));
      onChanged();
      void reload();
    } catch (err) {
      showError(
        t("siteDetail.advanced.saveFailed"),
        err instanceof ApiError ? err.message : undefined,
      );
    } finally {
      setSaving(false);
    }
  }

  if (error) {
    return <ErrorState message={error} onRetry={reload} />;
  }
  if (loading || !draft || !initial) {
    return (
      <div className="flex flex-col gap-3">
        <CardSkeleton height="h-40" />
        <CardSkeleton height="h-40" />
        <CardSkeleton height="h-40" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="bg-surface sticky top-0 z-10 flex items-center justify-between gap-2 rounded-xl border border-separator px-3 py-2">
        <span className="text-muted text-xs">
          {dirty ? t("siteDetail.advanced.dirty") : t("siteDetail.advanced.clean")}
        </span>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="ghost"
            isDisabled={!dirty || saving}
            onPress={() => setDraft(initial)}
          >
            <RotateCcw className="size-3.5" /> {t("siteDetail.advanced.reset")}
          </Button>
          <Button
            size="sm"
            variant="primary"
            isPending={saving}
            isDisabled={!dirty}
            onPress={() => void handleSave()}
          >
            <Save className="size-3.5" /> {t("common.save")}
          </Button>
        </div>
      </div>

      <UpstreamSection draft={draft} set={set} />
      <TlsSection draft={draft} set={set} />
      <ClientIPSection draft={draft} set={set} />
      <ProtectionOverrideSection draft={draft} set={set} />
      <SkipPathSection draft={draft} set={set} />
      <CacheSection draft={draft} set={set} />
      <MaintenanceSection draft={draft} set={set} />
      <DynamicProtectionSection draft={draft} set={set} />
      <CCRulesSection draft={draft} set={set} />
    </div>
  );
}
