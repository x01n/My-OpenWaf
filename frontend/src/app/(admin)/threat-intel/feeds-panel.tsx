"use client";

/**
 * 威胁情报订阅源面板：列表、同步、删除与翻页。
 *
 * 后端契约（internal/admin/system/threatintel）：
 * - 列表 GET /threat-intel-feeds → { items: ThreatIntelFeed[], total }
 * - 同步 POST /threat-intel-feeds/:id/sync
 * - 删除 POST /threat-intel-feeds/:id/delete
 *
 * `refreshKey` 由父组件递增，用于跨面板刷新：同步 / 删除后日志面板同步更新。
 */

import { useCallback, useState } from "react";
import { Button, Chip } from "@heroui/react";
import { RefreshCw } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n, useNumberFormat } from "@/i18n";
import type { ThreatIntelFeed } from "@/lib/types/ip";
import { formatDateTime, truncate } from "@/lib/utils/format";
import { ErrorState, Pager } from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ACTION_LABELS, KIND_LABELS, formatInterval } from "./threat-intel-model";

const PAGE_SIZE = 20;

export function FeedsPanel({
  refreshKey,
  onEdit,
  onMutated,
}: {
  /** 递增触发重新加载（保存 / 同步 / 删除后由父组件更新） */
  refreshKey: number;
  onEdit: (feed: ThreatIntelFeed) => void;
  onMutated: () => void;
}) {
  const { t } = useI18n();
  const fmt = useNumberFormat();
  const [page, setPage] = useState(1);
  const [syncingId, setSyncingId] = useState<number | null>(null);

  const { data, loading, error, reload } = useApi(
    useCallback(
      () =>
        apiGet<ListResponse<ThreatIntelFeed>>("/threat-intel-feeds", {
          page,
          page_size: PAGE_SIZE,
        }),
      [page, refreshKey],
    ),
    [page, refreshKey],
  );

  async function handleSync(id: number) {
    setSyncingId(id);
    try {
      await apiPost(`/threat-intel-feeds/${id}/sync`);
      showSuccess(t("threatIntel.syncDone"));
      onMutated();
    } catch (err) {
      showError(t("threatIntel.syncFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSyncingId(null);
    }
  }

  const columns: DataTableColumn<ThreatIntelFeed>[] = [
    {
      header: t("threatIntel.col.name"),
      render: (f) => <span className="font-medium">{f.name}</span>,
    },
    {
      header: t("threatIntel.col.url"),
      render: (f) => (
        <span className="font-mono text-muted text-xs" title={f.url}>
          {truncate(f.url, 48)}
        </span>
      ),
    },
    {
      header: t("threatIntel.col.kind"),
      render: (f) => {
        const key = KIND_LABELS[f.kind];
        const label = key ? t(key) : f.kind;
        return f.kind === "whitelist" ? (
          <Chip size="sm" variant="soft" color="success">
            {label}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="danger">
            {label}
          </Chip>
        );
      },
    },
    {
      header: t("threatIntel.col.action"),
      render: (f) => {
        const key = ACTION_LABELS[f.action];
        return key ? t(key) : f.action;
      },
    },
    {
      header: t("threatIntel.col.status"),
      render: (f) =>
        f.enabled ? (
          <Chip size="sm" variant="soft" color="success">
            {t("common.enabled")}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="default">
            {t("common.disabled")}
          </Chip>
        ),
    },
    {
      header: t("threatIntel.col.syncInterval"),
      render: (f) => <span className="tabular">{formatInterval(t, f.sync_interval)}</span>,
    },
    {
      header: t("threatIntel.col.entryCount"),
      render: (f) => <span className="tabular">{fmt(f.entry_count)}</span>,
    },
    {
      header: t("threatIntel.col.lastSync"),
      render: (f) => formatDateTime(f.last_sync_at),
    },
    {
      header: t("threatIntel.col.lastError"),
      render: (f) =>
        f.last_error ? (
          <span className="text-danger" title={f.last_error}>
            {truncate(f.last_error, 40)}
          </span>
        ) : (
          <span className="text-muted">-</span>
        ),
    },
    {
      header: t("common.actions"),
      render: (f) => (
        <div className="flex items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            isPending={syncingId === f.id}
            onPress={() => void handleSync(f.id)}
          >
            <RefreshCw className="size-3.5" /> {t("threatIntel.sync")}
          </Button>
          <Button size="sm" variant="outline" onPress={() => onEdit(f)}>
            {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("threatIntel.deleteConfirm", { name: f.name })}
            successText={t("threatIntel.deleted")}
            onConfirm={async () => {
              await apiPost(`/threat-intel-feeds/${f.id}/delete`);
              onMutated();
            }}
          >
            {t("common.delete")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  if (error) return <ErrorState message={error} onRetry={reload} />;

  return (
    <div className="flex flex-col gap-3">
      <DataTable
        ariaLabel={t("threatIntel.feedsAria")}
        columns={columns}
        rows={data?.items ?? []}
        loading={loading}
        emptyMessage={t("threatIntel.feedsEmpty")}
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
