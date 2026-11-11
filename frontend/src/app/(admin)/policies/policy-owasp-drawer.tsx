"use client";

/**
 * 策略详情抽屉：基本信息 + OWASP 规则概要统计。
 *
 * 抽屉内容仅在打开时由 HeroUI 挂载，统计请求随挂载发起、随关闭卸载，
 * 无需额外的 enabled 控制。
 */

import { useCallback } from "react";
import { ShieldCheck } from "lucide-react";
import { apiGet } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import type { Policy } from "@/lib/types/rule";
import { formatDateTime } from "@/lib/utils/format";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import type { OwaspRuleStats } from "./policies-model";

export function PolicyOwaspDrawer({
  state,
  policy,
}: {
  state: ReturnType<typeof import("@heroui/react").useOverlayState>;
  policy: Policy | null;
}) {
  const { t } = useI18n();

  return (
    <DetailDrawer
      state={state}
      title={policy?.name ?? t("policies.detail.title")}
      description={policy ? t("policies.detail.subtitle", { id: policy.id }) : undefined}
    >
      {policy && (
        <div>
          <DetailRow label={t("policies.field.description")}>
            {policy.description || "-"}
          </DetailRow>
          <DetailRow label={t("policies.field.isDefault")}>
            {policy.is_default ? t("policies.yes") : t("policies.no")}
          </DetailRow>
          <DetailRow label={t("policies.field.createdAt")}>
            {formatDateTime(policy.created_at)}
          </DetailRow>
          <DetailRow label={t("policies.field.updatedAt")}>
            {formatDateTime(policy.updated_at)}
          </DetailRow>
        </div>
      )}

      {policy && <OwaspStatsSection policyId={policy.id} />}
    </DetailDrawer>
  );
}

/** OWASP 规则概要：三格统计 + 分类占比条形 */
function OwaspStatsSection({ policyId }: { policyId: number }) {
  const { t } = useI18n();
  const stats = useApi<OwaspRuleStats>(
    useCallback(
      () => apiGet<OwaspRuleStats>(`/policies/${policyId}/owasp-rules/stats`),
      [policyId],
    ),
    [policyId],
  );

  const categoryEntries = Object.entries(stats.data?.by_category ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="border-separator mt-2 border-t pt-3">
      <div className="mb-2 flex items-center gap-1.5 text-sm font-medium">
        <ShieldCheck className="size-4" /> {t("policies.owasp.title")}
      </div>
      {stats.error ? (
        <div className="text-danger text-sm">{stats.error}</div>
      ) : stats.loading || !stats.data ? (
        <div className="text-muted py-3 text-sm">{t("common.loading")}</div>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="bg-default rounded-lg p-2.5">
              <div className="tabular text-lg font-semibold">{stats.data.total}</div>
              <div className="text-muted text-xs">{t("policies.owasp.total")}</div>
            </div>
            <div className="bg-default rounded-lg p-2.5">
              <div className="tabular text-success text-lg font-semibold">
                {stats.data.enabled_count}
              </div>
              <div className="text-muted text-xs">{t("policies.owasp.enabled")}</div>
            </div>
            <div className="bg-default rounded-lg p-2.5">
              <div className="tabular text-muted text-lg font-semibold">
                {stats.data.disabled_count}
              </div>
              <div className="text-muted text-xs">{t("policies.owasp.disabled")}</div>
            </div>
          </div>
          {categoryEntries.length === 0 ? (
            <div className="text-muted text-sm">{t("policies.owasp.empty")}</div>
          ) : (
            <div className="flex flex-col gap-2">
              {categoryEntries.map(([category, count]) => (
                <div key={category}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span>{category}</span>
                    <span className="tabular text-muted">{count}</span>
                  </div>
                  <div className="bg-default h-2 w-full overflow-hidden rounded-full">
                    <div
                      className="bg-accent h-full rounded-full"
                      style={{
                        width: `${
                          stats.data && stats.data.total > 0
                            ? Math.max(2, (count / stats.data.total) * 100)
                            : 0
                        }%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
