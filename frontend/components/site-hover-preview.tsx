"use client";

import * as React from "react";
import { useTranslation } from "react-i18next";
import useSWR from "swr";
import { format } from "date-fns";

import { cn } from "@/lib/utils";
import type { Site, UpstreamStatus } from "@/lib/types";
import { securityEventApi, upstreamApi } from "@/lib/api";
import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card";
import { Badge } from "@/components/ui/badge";
import {
  IconActivity,
  IconAlertTriangle,
  IconCheck,
  IconServer,
  IconShieldExclamation,
  IconX,
} from "@tabler/icons-react";

/**
 * 从站点 upstream_urls 中提取上游 URL 列表。
 */
function parseUpstreams(site: Site): string[] {
  const raw = (site.upstream_urls || "").trim();
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

interface SiteHoverPreviewProps {
  site: Site;
  children: React.ReactNode;
  align?: "start" | "center" | "end";
  className?: string;
}

/**
 * 站点信息悬停预览：
 * - 上游列表健康状态（健康/失败次数/平均延迟）
 * - 最近 24h 安全事件汇总（总数、拦截数、观察数）
 * 全部使用现有 API：GET /sites/{id}/security-events/stats?hours=24 与 GET /upstreams/status
 * 仅在首次 hover 打开时懒加载。
 */
export function SiteHoverPreview({
  site,
  children,
  align = "start",
  className,
}: SiteHoverPreviewProps) {
  const { t } = useTranslation();
  const [enabled, setEnabled] = React.useState(false);

  const upstreams = React.useMemo(() => parseUpstreams(site), [site]);

  const { data: statsData, isLoading: statsLoading } = useSWR(
    enabled ? ["site-hover-stats", site.id] : null,
    async () => {
      const res = (await securityEventApi.getSiteStats(site.id, {
        hours: 24,
      })) as {
        total: number;
        intercepts: number;
        observes: number;
        challenges: number;
        requests: number;
      };
      return res;
    },
    { revalidateOnFocus: false },
  );

  const { data: upstreamData, isLoading: upstreamLoading } = useSWR(
    enabled ? ["upstream-status-all"] : null,
    async () => upstreamApi.getStatus(),
    { revalidateOnFocus: false, refreshInterval: 15000 },
  );

  const relatedUpstreams: UpstreamStatus[] = React.useMemo(() => {
    if (!upstreamData?.items || upstreams.length === 0) return [];
    return upstreamData.items.filter((it) => upstreams.includes(it.url));
  }, [upstreamData, upstreams]);

  return (
    <HoverCard
      openDelay={250}
      closeDelay={120}
      onOpenChange={(o) => {
        if (o) setEnabled(true);
      }}
    >
      <HoverCardTrigger asChild>
        <span className={cn(className)}>{children}</span>
      </HoverCardTrigger>
      <HoverCardContent align={align} className="w-80 p-3">
        <div className="mb-2 flex items-center justify-between">
          <span className="truncate text-sm font-semibold" title={site.host}>
            {site.host}
          </span>
          <Badge variant="outline" className="h-4 px-1 text-[10px]">
            #{site.id}
          </Badge>
        </div>

        {/* 24h 攻击/事件 汇总 */}
        <div className="mb-3 rounded-md border bg-muted/30 p-2">
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
            <IconShieldExclamation className="h-3.5 w-3.5" />
            {t("sites.hover.recentAttacks", {
              defaultValue: "近 24 小时事件",
            })}
          </div>
          {statsLoading ? (
            <p className="text-center text-xs text-muted-foreground">
              {t("common.loading")}
            </p>
          ) : !statsData ? (
            <p className="text-center text-xs text-muted-foreground">
              {t("common.empty")}
            </p>
          ) : (
            <div className="grid grid-cols-3 gap-1.5 text-center">
              <MetricCell
                value={statsData.total}
                label={t("sites.hover.total", { defaultValue: "总数" })}
              />
              <MetricCell
                value={statsData.intercepts}
                label={t("sites.hover.intercepts", {
                  defaultValue: "拦截",
                })}
                tone="destructive"
              />
              <MetricCell
                value={statsData.observes}
                label={t("sites.hover.observes", { defaultValue: "观察" })}
                tone="warning"
              />
            </div>
          )}
        </div>

        {/* 上游状态 */}
        <div className="rounded-md border bg-muted/30 p-2">
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
            <IconServer className="h-3.5 w-3.5" />
            {t("sites.hover.upstreamStatus", {
              defaultValue: "上游状态",
            })}
          </div>
          {upstreams.length === 0 ? (
            <p className="text-center text-xs text-muted-foreground">
              {t("sites.hover.noUpstream", { defaultValue: "未配置上游" })}
            </p>
          ) : upstreamLoading ? (
            <p className="text-center text-xs text-muted-foreground">
              {t("common.loading")}
            </p>
          ) : (
            <ul className="space-y-1">
              {upstreams.slice(0, 4).map((url) => {
                const found = relatedUpstreams.find((u) => u.url === url);
                return (
                  <li
                    key={url}
                    className="flex items-center gap-1.5 text-[10.5px]"
                  >
                    {found ? (
                      found.healthy ? (
                        <IconCheck className="h-3 w-3 shrink-0 text-emerald-500" />
                      ) : (
                        <IconX className="h-3 w-3 shrink-0 text-destructive" />
                      )
                    ) : (
                      <IconAlertTriangle className="h-3 w-3 shrink-0 text-muted-foreground" />
                    )}
                    <span
                      className="truncate font-mono text-foreground/80"
                      title={url}
                    >
                      {url}
                    </span>
                    {found ? (
                      <span className="ml-auto shrink-0 text-muted-foreground">
                        {found.average_latency_ms > 0
                          ? `${found.average_latency_ms}ms`
                          : found.last_latency_ms > 0
                            ? `${found.last_latency_ms}ms`
                            : "-"}
                      </span>
                    ) : (
                      <span className="ml-auto shrink-0 text-muted-foreground">
                        {t("sites.hover.unknown", {
                          defaultValue: "未探测",
                        })}
                      </span>
                    )}
                  </li>
                );
              })}
              {upstreams.length > 4 ? (
                <li className="pt-0.5 text-center text-[10px] text-muted-foreground">
                  {t("sites.hover.moreUpstreams", {
                    defaultValue: "还有 {{count}} 个未展示",
                    count: upstreams.length - 4,
                  })}
                </li>
              ) : null}
            </ul>
          )}
        </div>

        {/* 底部小字：站点最近更新时间 */}
        <div className="mt-2 flex items-center gap-1 text-[10px] text-muted-foreground">
          <IconActivity className="h-3 w-3" />
          {t("sites.hover.updatedAt", { defaultValue: "更新于" })}{" "}
          {safeFormat(site.updated_at)}
        </div>
      </HoverCardContent>
    </HoverCard>
  );
}

function MetricCell({
  value,
  label,
  tone,
}: {
  value: number;
  label: React.ReactNode;
  tone?: "destructive" | "warning";
}) {
  const color =
    tone === "destructive"
      ? "text-destructive"
      : tone === "warning"
        ? "text-amber-600 dark:text-amber-400"
        : "text-foreground";
  return (
    <div className="rounded-md bg-background/60 py-1">
      <div className={cn("text-sm font-semibold tabular-nums", color)}>
        {value ?? 0}
      </div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  );
}

function safeFormat(iso?: string): string {
  if (!iso) return "-";
  try {
    return format(new Date(iso), "MM-dd HH:mm");
  } catch {
    return iso;
  }
}
