"use client";

/**
 * 站点「安全事件」面板：站点级安全事件列表 + 24h 统计 + 时间线。
 *
 * 数据来源（internal/admin/router.go L180-182）：
 * - GET /sites/:id/security-events → { items, total, page }
 * - GET /sites/:id/security-events/stats?hours=24 → SecurityEventStatsSnapshot
 * - GET /sites/:id/security-events/timeline?hours=24 → { buckets, hours }
 * 列表投影不含请求体等大字段，详情按 id 二次拉取 GET /security-events/:id。
 */

import { useCallback, useEffect, useState } from "react";
import { Button, ScrollShadow, useOverlayState } from "@heroui/react";
import { Activity, RefreshCw } from "lucide-react";
import { apiGet, ApiError } from "@/lib/api/client";
import { useApi, useDebounced, useList } from "@/lib/hooks/use-api";
import type {
  SecurityEvent,
  SecurityEventStats,
  TimelineBucket,
} from "@/lib/types/event";
import {
  CardSkeleton,
  ErrorState,
  Pager,
  SearchInput,
  SimpleSelect,
  StatCard,
  StatusChip,
  TableSkeleton,
  Toolbar,
  type StatusTone,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { formatDateTime, truncate } from "@/lib/utils/format";
import { useI18n, useNumberFormat, type MessageKey } from "@/i18n";

/** WAF action → 语言包键与语义色（internal/core/action 常量集）。 */
const ACTION_META: Record<string, { labelKey: MessageKey; tone: StatusTone }> = {
  block: { labelKey: "action.intercept", tone: "danger" },
  intercept: { labelKey: "action.intercept", tone: "danger" },
  drop: { labelKey: "action.drop", tone: "danger" },
  rate_limit: { labelKey: "action.rateLimit", tone: "danger" },
  captcha: { labelKey: "action.captcha", tone: "warning" },
  captcha_challenge: { labelKey: "action.captchaChallenge", tone: "warning" },
  challenge: { labelKey: "action.challenge", tone: "warning" },
  shield_challenge: { labelKey: "action.shieldChallenge", tone: "warning" },
  chain_challenge: { labelKey: "action.chainChallenge", tone: "warning" },
  observe: { labelKey: "action.observe", tone: "info" },
  allow: { labelKey: "action.allow", tone: "success" },
  redirect: { labelKey: "action.redirect", tone: "info" },
};

/** 动作筛选项（值与 ACTION_META 对齐，all 为全部）。 */
const ACTION_FILTERS = [
  "intercept",
  "drop",
  "rate_limit",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
  "observe",
  "allow",
] as const;

function ActionChip({ action }: { action: string }) {
  const { t } = useI18n();
  const meta = ACTION_META[action];
  return (
    <StatusChip tone={meta?.tone ?? "neutral"}>
      {meta ? t(meta.labelKey) : action || "-"}
    </StatusChip>
  );
}

/** 24 小时事件条图：对齐后端 `{ bucket, count }` 结构。 */
function TimelineBars({ buckets }: { buckets: TimelineBucket[] }) {
  const { t } = useI18n();
  if (!buckets || buckets.length === 0) {
    return (
      <div className="text-muted py-6 text-center text-sm">{t("events.timeline.empty")}</div>
    );
  }
  const max = Math.max(...buckets.map((b) => b.count ?? 0), 1);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex h-28 items-end gap-1">
        {buckets.map((b, i) => (
          <div
            key={`${b.bucket}-${i}`}
            className="group relative flex h-full flex-1 items-end"
            title={t("events.timeline.tooltip", {
              time: formatDateTime(b.bucket),
              count: b.count ?? 0,
            })}
          >
            <div
              className="bg-accent w-full rounded-t transition-all group-hover:opacity-80"
              style={{ height: `${Math.max(2, ((b.count ?? 0) / max) * 100)}%` }}
            />
          </div>
        ))}
      </div>
      <div className="text-muted flex items-center justify-between text-xs">
        <span>{formatDateTime(buckets[0]?.bucket)}</span>
        <span>{t("events.timeline.peak", { count: max })}</span>
        <span>{formatDateTime(buckets[buckets.length - 1]?.bucket)}</span>
      </div>
    </div>
  );
}

export function SiteSecurityPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const fmt = useNumberFormat();
  const [qInput, setQInput] = useState("");
  const q = useDebounced(qInput, 350);
  const [action, setAction] = useState("all");

  const list = useList<SecurityEvent>(`/sites/${siteId}/security-events`, {
    q: q || undefined,
    action: action === "all" ? undefined : action,
  });

  /* 防抖筛选变化后回到第一页。 */
  useEffect(() => {
    list.setPage(1);
  }, [q, action, list.setPage]);

  const stats = useApi<SecurityEventStats>(
    useCallback(
      () => apiGet<SecurityEventStats>(`/sites/${siteId}/security-events/stats`, { hours: 24 }),
      [siteId],
    ),
    [siteId],
  );
  const timeline = useApi<{ buckets?: TimelineBucket[] }>(
    useCallback(
      () =>
        apiGet<{ buckets?: TimelineBucket[] }>(`/sites/${siteId}/security-events/timeline`, {
          hours: 24,
        }),
      [siteId],
    ),
    [siteId],
  );

  /* 详情：列表投影不含大字段，按 id 拉取完整行。 */
  const [detail, setDetail] = useState<SecurityEvent | null>(null);
  const detailState = useOverlayState();
  const detailFull = useApi<SecurityEvent>(
    useCallback(() => apiGet<SecurityEvent>(`/security-events/${detail!.id}`), [detail?.id]),
    [detail?.id],
    { enabled: detail !== null },
  );
  const detailData = detailFull.data ?? detail;

  function openDetail(row: SecurityEvent) {
    setDetail(row);
    detailState.open();
  }

  function reloadAll() {
    void stats.reload();
    void timeline.reload();
    void list.reload();
  }

  const actionOptions = [
    { key: "all", label: t("siteDetail.security.action.all") },
    ...ACTION_FILTERS.map((key) => ({ key, label: t(ACTION_META[key].labelKey) })),
  ];

  const columns: DataTableColumn<SecurityEvent>[] = [
    {
      header: t("events.col.time"),
      render: (row) => (
        <span className="text-xs whitespace-nowrap">{formatDateTime(row.created_at)}</span>
      ),
    },
    {
      header: t("events.col.clientIp"),
      render: (row) => <span className="font-mono text-xs">{row.client_ip || "-"}</span>,
    },
    { header: t("common.method"), render: (row) => <span className="text-xs">{row.method || "-"}</span> },
    {
      header: t("common.path"),
      className: "max-w-56",
      render: (row) => {
        const full = row.query_string ? `${row.path}?${row.query_string}` : row.path;
        return (
          <span className="block truncate font-mono text-xs" title={full}>
            {truncate(full || "-", 48)}
          </span>
        );
      },
    },
    { header: t("events.col.action"), render: (row) => <ActionChip action={row.action} /> },
    {
      header: t("events.col.category"),
      render: (row) => <span className="text-xs">{row.category || "-"}</span>,
    },
    {
      header: t("events.col.rule"),
      render: (row) => (
        <span className="font-mono text-xs">
          {String(row.rule_id_str || row.rule_id || "-")}
        </span>
      ),
    },
    {
      header: t("common.actions"),
      render: (row) => (
        <Button size="sm" variant="outline" onPress={() => openDetail(row)}>
          {t("common.detail")}
        </Button>
      ),
    },
  ];

  const detailEntries = detailData ? Object.entries(detailData) : [];

  return (
    <div className="flex flex-col gap-4 py-2">
      {/* 统计（24 小时） */}
      <section>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-muted text-sm font-medium">{t("siteDetail.security.statsTitle")}</h3>
          <Button size="sm" variant="ghost" onPress={reloadAll}>
            <RefreshCw className="size-3.5" /> {t("common.refresh")}
          </Button>
        </div>
        {stats.error ? (
          <ErrorState message={stats.error} onRetry={stats.reload} />
        ) : stats.loading && !stats.data ? (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <CardSkeleton key={i} height="h-24" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4">
            <StatCard label={t("events.stats.total")} value={fmt(stats.data?.total)} />
            <StatCard
              label={t("events.stats.intercepts")}
              value={fmt(stats.data?.intercepts)}
              tone="danger"
            />
            <StatCard
              label={t("events.stats.observes")}
              value={fmt(stats.data?.observes)}
              tone="warning"
            />
            <StatCard
              label={t("events.stats.challenges")}
              value={fmt(stats.data?.challenges)}
              tone="info"
            />
          </div>
        )}
      </section>

      {/* 时间线（24 小时） */}
      <section>
        <h3 className="text-muted mb-2 flex items-center gap-1.5 text-sm font-medium">
          <Activity className="size-4" /> {t("siteDetail.security.timelineTitle")}
        </h3>
        <div className="bg-surface rounded-xl border border-separator p-4">
          {timeline.loading && !timeline.data ? (
            <TableSkeleton rows={3} />
          ) : (
            <TimelineBars buckets={timeline.data?.buckets ?? []} />
          )}
        </div>
      </section>

      {/* 筛选与列表 */}
      <section className="flex flex-col gap-2">
        <Toolbar>
          <SearchInput
            value={qInput}
            onChange={setQInput}
            placeholder={t("siteDetail.security.search")}
          />
          <SimpleSelect<string>
            value={action}
            onChange={setAction}
            options={actionOptions}
            label={t("siteDetail.security.actionFilter")}
            className="w-40"
          />
        </Toolbar>
        {list.error ? (
          <ErrorState message={list.error} onRetry={list.reload} />
        ) : list.loading && list.items.length === 0 ? (
          <TableSkeleton rows={6} />
        ) : (
          <DataTable
            ariaLabel={t("siteDetail.security.listAria")}
            columns={columns}
            rows={list.items}
            emptyMessage={t("siteDetail.security.empty")}
          />
        )}
        <Pager
          page={list.page}
          pageSize={list.pageSize}
          total={list.total}
          onPageChange={list.setPage}
        />
      </section>

      {/* 事件详情 */}
      <DetailDrawer
        state={detailState}
        title={
          detail
            ? t("siteDetail.security.detail.title", { id: detail.id })
            : t("siteDetail.security.detail.fallback")
        }
        description={detail ? `${detail.method} ${detail.host}${detail.path}` : undefined}
        width="w-[640px]"
      >
        {detailFull.loading && !detailFull.data ? (
          <TableSkeleton rows={6} />
        ) : detailFull.error ? (
          <ErrorState message={detailFull.error} onRetry={detailFull.reload} />
        ) : detailData ? (
          <div className="flex flex-col gap-2">
            {detailEntries.map(([key, value]) => (
              <DetailRow key={key} label={key}>
                {value === null || value === undefined || value === "" ? (
                  <span className="text-muted">-</span>
                ) : typeof value === "object" ? (
                  <ScrollShadow className="max-h-48">
                    <pre className="text-xs break-all whitespace-pre-wrap">
                      {JSON.stringify(value, null, 2)}
                    </pre>
                  </ScrollShadow>
                ) : /_at$/.test(key) ? (
                  formatDateTime(String(value))
                ) : (
                  <span className="break-all">{String(value)}</span>
                )}
              </DetailRow>
            ))}
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
