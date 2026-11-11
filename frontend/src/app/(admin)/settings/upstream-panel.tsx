"use client";

/**
 * 上游状态面板：
 * - GET /upstreams/status（非分页）→ { items, total }
 * - 只读展示各上游的健康状态、协议、延迟、失败计数与最近错误。
 */

import { useCallback } from "react";
import { Button } from "@heroui/react";
import { RefreshCw } from "lucide-react";
import { apiGet } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import type { UpstreamStatusItem, UpstreamStatusResponse } from "@/lib/types/access";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { StatusChip } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils/format";
import { PanelCard, PanelError, PanelSkeleton } from "./form-kit";

type UpstreamRow = UpstreamStatusItem & { id: string };

/** 上游状态 Tab 入口 */
export function UpstreamPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<UpstreamStatusResponse>(
    useCallback(() => apiGet<UpstreamStatusResponse>("/upstreams/status"), []),
  );

  const rows: UpstreamRow[] = (data?.items ?? []).map((it) => ({ ...it, id: it.url }));

  const columns: DataTableColumn<UpstreamRow>[] = [
    {
      header: t("settings.upstream.colAddress"),
      render: (r) => <span className="font-mono break-all text-xs">{r.url}</span>,
    },
    {
      header: t("settings.upstream.colHealth"),
      render: (r) => (
        <StatusChip tone={r.healthy ? "success" : "danger"}>
          {r.healthy ? t("settings.upstream.healthy") : t("settings.upstream.unhealthy")}
        </StatusChip>
      ),
    },
    {
      header: t("settings.upstream.colProtocol"),
      render: (r) => {
        const configured = r.configured_protocol || "-";
        const last = r.last_http_protocol;
        return (
          <span className="tabular text-xs">
            {configured}
            {last && last !== configured ? ` → ${last}` : ""}
          </span>
        );
      },
    },
    {
      header: t("settings.upstream.colLatency"),
      render: (r) => (
        <span className="tabular text-xs">
          {r.average_latency_ms}ms / {r.last_latency_ms}ms
        </span>
      ),
    },
    {
      header: t("settings.upstream.colFailCount"),
      render: (r) => <span className="tabular">{r.fail_count}</span>,
    },
    {
      header: t("settings.upstream.colFailureKind"),
      render: (r) => r.last_failure_kind || "-",
    },
    {
      header: t("settings.upstream.colLastError"),
      className: "max-w-56",
      render: (r) =>
        r.last_error ? (
          <span className="text-danger block truncate text-xs" title={r.last_error}>
            {r.last_error}
          </span>
        ) : (
          <span className="text-muted">-</span>
        ),
    },
    {
      header: t("settings.upstream.colLastSuccess"),
      render: (r) => <span className="tabular">{formatDateTime(r.last_success_at)}</span>,
    },
  ];

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading && !data) return <PanelSkeleton />;

  return (
    <PanelCard
      title={t("settings.upstream.title")}
      description={t("settings.upstream.description")}
    >
      <div className="flex items-center justify-between">
        <span className="text-muted text-xs">
          {t("settings.upstream.total", { count: data?.total ?? 0 })}
        </span>
        <Button size="sm" variant="ghost" onPress={() => void reload()}>
          <RefreshCw className="size-3.5" /> {t("common.refresh")}
        </Button>
      </div>
      <DataTable
        ariaLabel={t("settings.upstream.listAria")}
        columns={columns}
        rows={rows}
        loading={loading}
        emptyMessage={t("settings.upstream.empty")}
      />
    </PanelCard>
  );
}
