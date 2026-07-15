"use client";

/**
 * 上游服务器状态页面
 *
 * 展示所有配置上游的健康检查结果，每 10 秒自动刷新。
 *
 * 后端契约：GET /api/v1/upstreams/status
 *   参见 internal/admin/system/upstream.go
 */

import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  IconServer,
  IconAlertTriangle,
  IconCircleCheckFilled,
  IconCircleXFilled,
  IconClock,
  IconRefresh,
  IconArrowRight,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useUpstreamStatus } from "@/hooks/use-api";
import { formatRelative } from "@/lib/time-format";
import type { UpstreamStatus } from "@/lib/types";
import { EmptyState } from "@/components/empty-state";

function latencyClass(ms: number): string {
  if (ms <= 0) return "text-muted-foreground";
  if (ms < 100) return "text-emerald-600 dark:text-emerald-400";
  if (ms <= 500) return "text-amber-600 dark:text-amber-400";
  return "text-red-600 dark:text-red-400";
}

/**
 * 状态圆点
 */
function StatusDot({ healthy }: { healthy: boolean }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block h-2.5 w-2.5 rounded-full shrink-0",
        healthy
          ? "bg-teal-500 shadow-[0_0_0_3px_rgba(20,184,166,0.15)]"
          : "bg-red-500 shadow-[0_0_0_3px_rgba(239,68,68,0.15)]"
      )}
    />
  );
}

function ProtocolPair({
  configured,
  actual,
}: {
  configured?: string;
  actual?: string;
}) {
  const cfg = configured || "-";
  const act = actual || "-";
  return (
    <div className="inline-flex items-center gap-1.5 text-xs font-mono">
      <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
        {cfg}
      </span>
      <IconArrowRight className="h-3 w-3 text-muted-foreground" />
      <span
        className={cn(
          "rounded px-1.5 py-0.5",
          actual ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"
        )}
      >
        {act}
      </span>
    </div>
  );
}

function UpstreamRow({ item }: { item: UpstreamStatus }) {
  const { t } = useTranslation();
  const hasFailure = item.fail_count > 0 || !!item.last_failure_kind || !!item.last_error;

  return (
    <Card className="transition-colors hover:border-primary/40">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="flex items-center gap-2">
              <StatusDot healthy={item.healthy} />
              <span className="break-all font-mono text-base font-semibold">
                {item.url}
              </span>
              <Badge
                variant={item.healthy ? "secondary" : "destructive"}
                className="h-5 shrink-0 px-1.5 text-[10px]"
              >
                {item.healthy
                  ? t("upstreamStatus.healthy")
                  : t("upstreamStatus.unhealthy")}
              </Badge>
            </div>
            <ProtocolPair
              configured={item.configured_protocol}
              actual={item.last_http_protocol}
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            {item.fail_count > 0 && (
              <Badge variant="destructive" className="h-5 gap-1 px-1.5 text-[10px]">
                <IconAlertTriangle className="h-3 w-3" />
                {t("upstreamStatus.failCountValue", { count: item.fail_count })}
              </Badge>
            )}
            {item.last_success_at && (
              <span className="inline-flex items-center gap-1 text-muted-foreground">
                <IconCircleCheckFilled className="h-3.5 w-3.5 text-emerald-500" />
                {t("upstreamStatus.lastSuccess")}
                <span className="font-mono">
                  {formatRelative(item.last_success_at)}
                </span>
              </span>
            )}
            {item.checked_at && (
              <span className="inline-flex items-center gap-1 text-muted-foreground">
                <IconClock className="h-3.5 w-3.5" />
                {t("upstreamStatus.checkedAt")}
                <span className="font-mono">
                  {formatRelative(item.checked_at)}
                </span>
              </span>
            )}
          </div>
        </div>

        <div className="grid gap-2 border-t pt-3 sm:grid-cols-2 lg:grid-cols-3">
          <MetricCell
            label={t("upstreamStatus.currentLatency", { value: item.last_latency_ms })}
            hint={t("upstreamStatus.latency")}
            colorClass={latencyClass(item.last_latency_ms)}
          />
          <MetricCell
            label={t("upstreamStatus.averageLatency", { value: item.average_latency_ms })}
            hint={t("upstreamStatus.averageLatencyLabel")}
            colorClass={latencyClass(item.average_latency_ms)}
          />
          <MetricCell
            label={t("upstreamStatus.failCountValue", { count: item.fail_count })}
            hint={t("upstreamStatus.failCount")}
            colorClass={
              item.fail_count > 0
                ? "text-red-600 dark:text-red-400"
                : "text-muted-foreground"
            }
          />
        </div>

        {hasFailure && (
          <div className="flex flex-wrap items-start gap-x-3 gap-y-1 rounded-md border border-red-500/20 bg-red-500/5 px-3 py-2 text-xs">
            <span className="inline-flex items-center gap-1 font-medium text-red-600 dark:text-red-400">
              <IconCircleXFilled className="h-3.5 w-3.5" />
              {t("upstreamStatus.lastFailure")}
            </span>
            {item.last_failure_kind && (
              <span className="text-muted-foreground">
                <span className="mr-1">{t("upstreamStatus.lastFailureKind")}:</span>
                <span className="font-mono text-foreground">{item.last_failure_kind}</span>
              </span>
            )}
            {item.last_error && (
              <TooltipProvider delayDuration={150}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="block max-w-full truncate font-mono text-muted-foreground">
                      <span className="mr-1">{t("upstreamStatus.lastError")}:</span>
                      {item.last_error}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-md whitespace-pre-wrap break-all">
                    {item.last_error}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function MetricCell({
  label,
  hint,
  colorClass,
}: {
  label: string;
  hint: string;
  colorClass?: string;
}) {
  return (
    <div className="rounded-md border bg-muted/20 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
        {hint}
      </div>
      <div className={cn("mt-0.5 text-sm font-semibold", colorClass)}>
        {label}
      </div>
    </div>
  );
}

export default function UpstreamStatusPage() {
  const { t } = useTranslation();
  const { data, error, isLoading } = useUpstreamStatus();

  const items: UpstreamStatus[] = useMemo(() => data?.items || [], [data]);
  const total = data?.total ?? items.length;

  const { healthyCount, unhealthyCount } = useMemo(() => {
    let h = 0;
    let u = 0;
    for (const it of items) {
      if (it.healthy) h += 1;
      else u += 1;
    }
    return { healthyCount: h, unhealthyCount: u };
  }, [items]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <IconServer className="h-6 w-6 text-primary" />
          <h1 className="text-xl font-semibold">{t("upstreamStatus.title")}</h1>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="gap-1 font-mono">
            {t("upstreamStatus.totalCount", { count: total })}
          </Badge>
          <Badge className="gap-1 bg-teal-500/15 text-teal-700 hover:bg-teal-500/20 dark:text-teal-300">
            <IconCircleCheckFilled className="h-3.5 w-3.5" />
            {t("upstreamStatus.healthyCount", { count: healthyCount })}
          </Badge>
          <Badge
            variant={unhealthyCount > 0 ? "destructive" : "outline"}
            className="gap-1"
          >
            <IconCircleXFilled className="h-3.5 w-3.5" />
            {t("upstreamStatus.unhealthyCount", { count: unhealthyCount })}
          </Badge>
          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
            <IconRefresh className="h-3.5 w-3.5" />
            {t("upstreamStatus.refreshInterval")}
          </span>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("upstreamStatus.title")}</CardTitle>
          <p className="text-xs text-muted-foreground">
            {t("upstreamStatus.description")}
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          {error && (
            <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive">
              {(error as Error).message || t("upstreamStatus.loadFailed")}
            </div>
          )}

          {isLoading && items.length === 0 && !error && (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              {t("upstreamStatus.loading")}
            </div>
          )}

          {!isLoading && items.length === 0 && !error && (
            <EmptyState
              icon={IconServer}
              title={t("upstreamStatus.empty")}
              description={t("upstreamStatus.emptyHint")}
            />
          )}

          {items.length > 0 && (
            <div className="space-y-3">
              {items.map((it) => (
                <UpstreamRow key={it.url} item={it} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
