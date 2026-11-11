"use client";

/**
 * 丢弃策略 Tab：GET /drop-policy 表单 + POST /drop-policy/update
 * + GET /drop-stats 统计卡 + GET /drop-events 简表。
 * 字段取自 internal/admin/protect/drop/drop.go DropPolicyResponse（L20-25）；
 * 统计见 DropStatsSummary（drop_event.go L157-163）；事件见 store.DropEvent（events.go L240-250）。
 */

import { useCallback, useEffect, useState } from "react";
import { Button } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n, useNumberFormat } from "@/i18n";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton, StatCard, Pager } from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { formatDateTime } from "@/lib/utils/format";
import type { DropEvent, DropPolicy, DropStats } from "@/lib/types/protection";
import { SectionCard, SwitchRow, NumberField } from "./field-controls";
import { DROP_SOURCE_KEYS } from "./protection-model";

const PAGE_SIZE = 20;

export function DropPanel() {
  const { t } = useI18n();
  const fmt = useNumberFormat();
  const { data, loading, error, reload } = useApi<DropPolicy>(
    useCallback(() => apiGet<DropPolicy>("/drop-policy"), []),
  );
  const stats = useApi<DropStats>(useCallback(() => apiGet<DropStats>("/drop-stats"), []));
  const [page, setPage] = useState(1);
  const events = useApi<{ items: DropEvent[]; total: number }>(
    useCallback(
      () => apiGet<{ items: DropEvent[]; total: number }>("/drop-events", { page, page_size: PAGE_SIZE }),
      [page],
    ),
    [page],
  );
  const [form, setForm] = useState<DropPolicy | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  async function save() {
    if (!form) return;
    setSaving(true);
    try {
      await apiPost("/drop-policy/update", form);
      showSuccess(t("protection.saved"));
      await Promise.all([reload(), stats.reload()]);
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  const columns: DataTableColumn<DropEvent>[] = [
    { header: t("protection.drop.col.clientIp"), render: (r) => <span className="font-mono text-xs">{r.client_ip}</span> },
    {
      header: t("protection.drop.col.source"),
      render: (r) => {
        const key = DROP_SOURCE_KEYS[r.source];
        return key ? t(key) : r.source;
      },
    },
    { header: t("protection.drop.col.ruleId"), render: (r) => <span className="font-mono text-xs">{r.rule_id || "—"}</span> },
    { header: t("protection.drop.col.host"), render: (r) => <span className="text-xs">{r.host}</span> },
    { header: t("protection.drop.col.path"), render: (r) => <span className="max-w-xs truncate text-xs">{r.path}</span> },
    { header: t("protection.drop.col.time"), render: (r) => <span className="text-xs">{formatDateTime(r.created_at)}</span> },
  ];

  return (
    <div className="flex flex-col gap-4">
      {/* 24h 统计 */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard label={t("protection.drop.stats.total")} value={fmt(stats.data?.total_24h)} tone="danger" />
        <StatCard label={t("protection.drop.stats.bot")} value={fmt(stats.data?.by_bot)} tone="warning" />
        <StatCard label={t("protection.drop.stats.cve")} value={fmt(stats.data?.by_cve)} tone="warning" />
        <StatCard label={t("protection.drop.stats.rule")} value={fmt(stats.data?.by_rule)} tone="warning" />
        <StatCard label={t("protection.drop.stats.ipRep")} value={fmt(stats.data?.by_ip_reputation)} tone="warning" />
      </div>

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !form ? (
        <CardSkeleton height="h-64" />
      ) : form ? (
        <SectionCard
          title={t("protection.drop.title")}
          description={t("protection.drop.description")}
        >
          <SwitchRow label={t("protection.drop.enabled")} value={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} />
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <NumberField label={t("protection.drop.botThreshold")} value={form.bot_score_threshold} onChange={(v) => setForm({ ...form, bot_score_threshold: v })} min={1} hint={t("protection.drop.botThresholdHint")} />
          </div>
          <div className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-2">
            <SwitchRow label={t("protection.drop.cveCritical")} value={form.cve_auto_drop_critical} onChange={(v) => setForm({ ...form, cve_auto_drop_critical: v })} />
            <SwitchRow label={t("protection.drop.cveHigh")} value={form.cve_auto_drop_high} onChange={(v) => setForm({ ...form, cve_auto_drop_high: v })} />
          </div>
          <div className="flex justify-end">
            <Button variant="primary" isPending={saving} onPress={save}>
              {t("protection.drop.save")}
            </Button>
          </div>
        </SectionCard>
      ) : null}

      <div className="bg-surface rounded-xl border border-separator p-4">
        <h3 className="mb-3 text-sm font-medium">{t("protection.drop.events.title")}</h3>
        {events.error ? (
          <ErrorState message={events.error} onRetry={events.reload} />
        ) : (
          <>
            <DataTable ariaLabel={t("protection.drop.listAria")} columns={columns} rows={events.data?.items} loading={events.loading} emptyMessage={t("protection.drop.empty")} />
            <Pager page={page} pageSize={PAGE_SIZE} total={events.data?.total ?? 0} onPageChange={setPage} />
          </>
        )}
      </div>
    </div>
  );
}
