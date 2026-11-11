"use client";

/**
 * 灵敏度 Tab：GET/POST /protection/global/sensitivity（:id = "global"）。
 * 响应 {category_sensitivity:{...}}，每个分类一行 + level 下拉。
 * 等级白名单见 internal/store/protection.go normalizeProtectionSensitivityLevel（L206-223）。
 */

import { useCallback, useEffect, useState } from "react";
import { Button } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton, EmptyState, SimpleSelect } from "@/components/ui/primitives";
import type { SensitivityConfig, SensitivityLevel } from "@/lib/types/protection";
import { SectionCard } from "./field-controls";
import { SENSITIVITY_LEVELS } from "./protection-model";

const BASE_PATH = "/protection/global/sensitivity";

export function SensitivityPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<SensitivityConfig>(
    useCallback(() => apiGet<SensitivityConfig>(BASE_PATH), []),
  );
  const [levels, setLevels] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data) setLevels({ ...data.category_sensitivity });
  }, [data]);

  const categories = Object.keys(levels).sort((a, b) => a.localeCompare(b));

  async function save() {
    setSaving(true);
    try {
      await apiPost(BASE_PATH, { category_sensitivity: levels });
      showSuccess(t("protection.sensitivityPanel.saved"));
      await reload();
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  const sensitivityOptions = localizeOptions(SENSITIVITY_LEVELS, t);

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && categories.length === 0 ? (
        <CardSkeleton height="h-80" />
      ) : (
        <SectionCard
          title={t("protection.sensitivityPanel.title")}
          description={t("protection.sensitivityPanel.description")}
        >
          {categories.length === 0 ? (
            <EmptyState message={t("protection.sensitivityPanel.empty")} />
          ) : (
            <div className="flex flex-col divide-y divide-separator">
              {categories.map((category) => (
                <div key={category} className="flex items-center justify-between gap-4 py-2.5">
                  <div className="font-mono text-sm">{category}</div>
                  <SimpleSelect<SensitivityLevel | string>
                    value={levels[category]}
                    onChange={(v) => setLevels((prev) => ({ ...prev, [category]: v }))}
                    options={sensitivityOptions}
                    label={t("protection.sensitivityPanel.aria", { category })}
                    className="w-40"
                  />
                </div>
              ))}
            </div>
          )}
          <div className="flex justify-end">
            <Button variant="primary" isPending={saving} onPress={save} isDisabled={categories.length === 0}>
              {t("protection.sensitivityPanel.save")}
            </Button>
          </div>
        </SectionCard>
      )}
    </div>
  );
}
