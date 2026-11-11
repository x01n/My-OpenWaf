"use client";

/**
 * 威胁情报同步日志面板：分页展示每次同步的结果与耗时。
 *
 * 后端契约：
 * - 列表 GET /threat-intel-sync-logs → { items: ThreatIntelSyncLog[], total }
 * - 记录结构见 internal/store/threatintel/threat_intel_sync_log.go
 * - `trigger` 仅接受 `auto` / `manual`
 *
 * `refreshKey` 由父组件递增：订阅源保存 / 同步 / 删除后本面板同步刷新。
 */

import { useCallback, useState } from "react";
import { Chip } from "@heroui/react";
import { apiGet, type ListResponse } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n, useNumberFormat } from "@/i18n";
import type { ThreatIntelSyncLog } from "@/lib/types/ip";
import { formatDateTime, truncate } from "@/lib/utils/format";
import { ErrorState, Pager } from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { TRIGGER_LABELS } from "./threat-intel-model";

const PAGE_SIZE = 20;

export function SyncLogsPanel({ refreshKey }: { refreshKey: number }) {
  const { t } = useI18n();
  const fmt = useNumberFormat();
  const [page, setPage] = useState(1);

  const { data, loading, error, reload } = useApi(
    useCallback(
      () =>
        apiGet<ListResponse<ThreatIntelSyncLog>>("/threat-intel-sync-logs", {
          page,
          page_size: PAGE_SIZE,
        }),
      [page, refreshKey],
    ),
    [page, refreshKey],
  );

  const columns: DataTableColumn<ThreatIntelSyncLog>[] = [
    {
      header: t("threatIntel.logs.col.feed"),
      render: (l) => <span className="font-medium">{l.feed_name}</span>,
    },
    {
      header: t("threatIntel.logs.col.startedAt"),
      render: (l) => formatDateTime(l.started_at),
    },
    {
      header: t("threatIntel.logs.col.duration"),
      render: (l) => <span className="tabular">{l.duration_ms} ms</span>,
    },
    {
      header: t("threatIntel.logs.col.result"),
      render: (l) =>
        l.success ? (
          <Chip size="sm" variant="soft" color="success">
            {t("threatIntel.logs.success")}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="danger">
            {t("threatIntel.logs.failed")}
          </Chip>
        ),
    },
    {
      header: t("threatIntel.logs.col.counts"),
      render: (l) => (
        <span className="tabular">
          {fmt(l.entries_added)} / {fmt(l.entries_skipped)} / {fmt(l.lines_read)}
        </span>
      ),
    },
    {
      header: t("threatIntel.logs.col.trigger"),
      render: (l) => {
        const key = TRIGGER_LABELS[l.trigger];
        const label = key ? t(key) : l.trigger;
        return l.trigger === "manual" ? (
          <Chip size="sm" variant="soft" color="accent">
            {label}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="default">
            {label}
          </Chip>
        );
      },
    },
    {
      header: t("threatIntel.logs.col.error"),
      render: (l) =>
        l.error ? (
          <span className="text-danger" title={l.error}>
            {truncate(l.error, 40)}
          </span>
        ) : (
          <span className="text-muted">-</span>
        ),
    },
  ];

  if (error) return <ErrorState message={error} onRetry={reload} />;

  return (
    <div className="flex flex-col gap-3">
      <DataTable
        ariaLabel={t("threatIntel.logsAria")}
        columns={columns}
        rows={data?.items ?? []}
        loading={loading}
        emptyMessage={t("threatIntel.logsEmpty")}
      />
      <Pager
        page={page}
        pageSize={PAGE_SIZE}
        total={data?.total ?? 0}
        onPageChange={setPage}
      />
    </div>
  );
}
