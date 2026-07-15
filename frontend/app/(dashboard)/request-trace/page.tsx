"use client";

/**
 * 请求追踪页面
 *
 * 通过 request_id 查询单次请求的完整链路：
 * - 访问日志 (access_logs)
 * - 安全事件 (security_events)
 *
 * 后端契约见 internal/admin/event/request.go
 *   GET /api/v1/request/:request_id
 *   -> { request_id: string, access_logs: AccessLog[]|null, security_events: SecurityEvent[]|null }
 */

import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useTranslation } from "react-i18next";
import { format } from "date-fns";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { DataTable } from "@/components/data-table";
import { SecurityEventDetailDialog } from "@/components/security-event-detail-dialog";
import { EmptyState } from "@/components/empty-state";
import {
  IconRoute,
  IconSearch,
  IconClock,
  IconHash,
  IconWorld,
  IconShieldExclamation,
  IconFileText,
  IconEye,
  IconMapPin,
} from "@tabler/icons-react";
import { useRequestTrace, useSites } from "@/hooks/use-api";
import type { AccessLog, SecurityEvent, Site } from "@/lib/types";

const actionColorMap: Record<string, string> = {
  block: "destructive",
  intercept: "destructive",
  observe: "secondary",
  challenge: "outline",
  captcha_challenge: "outline",
  shield_challenge: "outline",
  chain_challenge: "outline",
  allow: "ghost",
  drop: "destructive",
  log_only: "secondary",
};

function RequestTraceContent() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();

  const queryId = searchParams.get("id") || "";
  const [inputState, setInputState] = useState({ source: queryId, value: queryId });
  const inputValue = inputState.source === queryId ? inputState.value : queryId;

  const { data, isLoading, error } = useRequestTrace(queryId || undefined);
  const { data: sitesData } = useSites({ page: 1, page_size: 500 });

  const siteMap = useMemo(() => {
    const m = new Map<number, Site>();
    (sitesData?.items || []).forEach((s) => m.set(s.id, s));
    return m;
  }, [sitesData]);

  const accessLogs = useMemo<AccessLog[]>(
    () => data?.access_logs || [],
    [data?.access_logs]
  );
  const securityEvents = useMemo<SecurityEvent[]>(
    () => data?.security_events || [],
    [data?.security_events]
  );
  const hasAny = accessLogs.length > 0 || securityEvents.length > 0;

  const handleSearch = () => {
    const id = inputValue.trim();
    if (!id) return;
    // 同步 URL 便于分享，并由 URL 驱动查询。
    const url = `/request-trace?id=${encodeURIComponent(id)}`;
    router.replace(url);
  };

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") handleSearch();
  };

  // 概要信息：优先取安全事件（更完整），否则取访问日志
  const summary = useMemo(() => {
    const first = securityEvents[0] || accessLogs[0];
    if (!first) return null;
    const site = siteMap.get(first.site_id);
    // 状态码：优先取访问日志
    const statusCode =
      accessLogs[0]?.status_code ?? securityEvents[0]?.status_code ?? 0;
    // WAF 动作：优先取访问日志中的 waf_action，其次取安全事件动作
    const wafAction =
      accessLogs[0]?.waf_action ||
      securityEvents.find((e) => e.action !== "observe" && e.action !== "allow")?.action ||
      securityEvents[0]?.action ||
      "-";
    return {
      requestId: data?.request_id || queryId,
      time: first.created_at,
      siteId: first.site_id,
      siteHost: site?.host,
      clientIp: first.client_ip,
      host: first.host,
      path: first.path,
      method: first.method,
      statusCode,
      wafAction,
    };
  }, [accessLogs, securityEvents, data?.request_id, queryId, siteMap]);

  // 安全事件详情弹窗
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const accessLogColumns = [
    {
      key: "created_at",
      title: t("requestTrace.firstSeen"),
      width: "180px",
      render: (row: AccessLog) =>
        row.created_at ? format(new Date(row.created_at), "yyyy-MM-dd HH:mm:ss") : "-",
    },
    { key: "client_ip", title: "IP", width: "140px" },
    { key: "host", title: "Host", width: "180px" },
    { key: "path", title: "Path" },
    { key: "method", title: "Method", width: "80px" },
    { key: "status_code", title: t("requestTrace.statusCode"), width: "80px" },
    {
      key: "waf_action",
      title: t("requestTrace.wafAction"),
      width: "100px",
      render: (row: AccessLog) =>
        row.waf_action ? (
          <Badge
            variant={(actionColorMap[row.waf_action] || "secondary") as React.ComponentProps<typeof Badge>["variant"]}
            className="h-5 px-1.5 text-[10px]"
          >
            {row.waf_action}
          </Badge>
        ) : (
          "-"
        ),
    },
    {
      key: "upstream_latency_ms",
      title: t("requestTrace.upstreamLatency"),
      width: "120px",
      render: (row: AccessLog) =>
        row.upstream_latency_ms > 0 ? `${row.upstream_latency_ms} ms` : "-",
    },
    {
      key: "response_size",
      title: t("requestTrace.responseSize"),
      width: "120px",
      render: (row: AccessLog) => (row.response_size > 0 ? `${row.response_size} B` : "-"),
    },
    {
      key: "tls_version",
      title: t("requestTrace.tlsVersion"),
      width: "100px",
      render: (row: AccessLog) => row.tls_version || "-",
    },
    {
      key: "upstream",
      title: t("requestTrace.upstream"),
      width: "180px",
      render: (row: AccessLog) => row.upstream || "-",
    },
  ];

  const securityEventColumns = [
    {
      key: "created_at",
      title: t("requestTrace.firstSeen"),
      width: "180px",
      render: (row: SecurityEvent) =>
        row.created_at ? format(new Date(row.created_at), "yyyy-MM-dd HH:mm:ss") : "-",
    },
    { key: "phase", title: t("requestTrace.phase"), width: "120px" },
    {
      key: "action",
      title: t("requestTrace.action"),
      width: "110px",
      render: (row: SecurityEvent) => (
        <Badge
          variant={(actionColorMap[row.action] || "secondary") as React.ComponentProps<typeof Badge>["variant"]}
          className="h-5 px-1.5 text-[10px]"
        >
          {row.action}
        </Badge>
      ),
    },
    { key: "category", title: t("requestTrace.category"), width: "130px" },
    {
      key: "rule_id_str",
      title: t("requestTrace.rule"),
      width: "160px",
      render: (row: SecurityEvent) => row.rule_id_str || String(row.rule_id) || "-",
    },
    {
      key: "match_desc",
      title: t("requestTrace.matchDesc"),
      render: (row: SecurityEvent) => (
        <span className="text-xs text-muted-foreground line-clamp-2">
          {row.match_desc || "-"}
        </span>
      ),
    },
    {
      key: "operations",
      title: t("common.action"),
      width: "80px",
      render: (row: SecurityEvent) => (
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={() => setSelectedEvent(row)}
        >
          <IconEye className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <IconRoute className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-semibold">{t("requestTrace.title")}</h1>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("requestTrace.title")}</CardTitle>
          <p className="text-xs text-muted-foreground">
            {t("requestTrace.description")}
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              value={inputValue}
              placeholder={t("requestTrace.searchPlaceholder")}
              className="h-9 flex-1 font-mono text-xs"
              onChange={(e) => setInputState({ source: queryId, value: e.target.value })}
              onKeyDown={handleKey}
            />
            <Button
              size="sm"
              className="h-9 gap-1.5"
              onClick={handleSearch}
              disabled={!inputValue.trim() || isLoading}
            >
              <IconSearch className="h-4 w-4" />
              {t("requestTrace.search")}
            </Button>
          </div>

          {queryId && !isLoading && !hasAny && !error && (
            <EmptyState
              icon={IconSearch}
              title={t("requestTrace.notFound")}
              className="py-8"
            />
          )}

          {error && (
            <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive">
              {(error as Error).message || t("common.operationFailed")}
            </div>
          )}
        </CardContent>
      </Card>

      {summary && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">
              {t("requestTrace.summary")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <SummaryItem
                icon={<IconHash className="h-4 w-4" />}
                label={t("requestTrace.requestId")}
                value={summary.requestId}
                mono
              />
              <SummaryItem
                icon={<IconClock className="h-4 w-4" />}
                label={t("requestTrace.firstSeen")}
                value={
                  summary.time
                    ? format(new Date(summary.time), "yyyy-MM-dd HH:mm:ss")
                    : "-"
                }
              />
              <SummaryItem
                icon={<IconShieldExclamation className="h-4 w-4" />}
                label={t("requestTrace.site")}
                value={
                  summary.siteHost
                    ? `${summary.siteHost} (#${summary.siteId})`
                    : summary.siteId
                      ? `#${summary.siteId}`
                      : t("requestTrace.noSite")
                }
              />
              <SummaryItem
                icon={<IconMapPin className="h-4 w-4" />}
                label={t("requestTrace.clientIp")}
                value={summary.clientIp || "-"}
                mono
              />
              <SummaryItem
                icon={<IconWorld className="h-4 w-4" />}
                label={t("requestTrace.host")}
                value={summary.host || "-"}
              />
              <SummaryItem
                icon={<IconRoute className="h-4 w-4" />}
                label={t("requestTrace.path")}
                value={summary.path || "-"}
                mono
              />
              <SummaryItem
                label={t("requestTrace.method")}
                value={summary.method || "-"}
              />
              <SummaryItem
                label={t("requestTrace.statusCode")}
                value={String(summary.statusCode || "-")}
              />
              <SummaryItem
                label={t("requestTrace.wafAction")}
                value={
                  <Badge
                    variant={(actionColorMap[summary.wafAction] || "secondary") as React.ComponentProps<typeof Badge>["variant"]}
                    className="h-5 px-1.5 text-[10px]"
                  >
                    {summary.wafAction}
                  </Badge>
                }
              />
            </div>
          </CardContent>
        </Card>
      )}

      {hasAny && (
        <Card>
          <CardContent className="pt-6">
            <Tabs defaultValue="access_logs">
              <TabsList>
                <TabsTrigger value="access_logs" className="gap-1.5">
                  <IconFileText className="h-4 w-4" />
                  {t("requestTrace.accessLogsCount", {
                    count: accessLogs.length,
                  })}
                </TabsTrigger>
                <TabsTrigger value="security_events" className="gap-1.5">
                  <IconShieldExclamation className="h-4 w-4" />
                  {t("requestTrace.securityEventsCount", {
                    count: securityEvents.length,
                  })}
                </TabsTrigger>
              </TabsList>
              <TabsContent value="access_logs" className="mt-4">
                <DataTable
                  columns={accessLogColumns}
                  data={accessLogs}
                  rowKey={(row) => row.id}
                  emptyText={t("requestTrace.emptyAccessLogs")}
                />
              </TabsContent>
              <TabsContent value="security_events" className="mt-4">
                <DataTable
                  columns={securityEventColumns}
                  data={securityEvents}
                  rowKey={(row) => row.id}
                  emptyText={t("requestTrace.emptySecurityEvents")}
                />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}

      <SecurityEventDetailDialog
        event={selectedEvent}
        open={!!selectedEvent}
        onOpenChange={(open) => {
          if (!open) setSelectedEvent(null);
        }}
      />
    </div>
  );
}

/**
 * 概要项：label + value 组合，可选图标与等宽字体
 */
function SummaryItem({
  icon,
  label,
  value,
  mono,
}: {
  icon?: React.ReactNode;
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-md border bg-muted/20 p-3">
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div
        className={
          "text-sm break-all " + (mono ? "font-mono" : "")
        }
      >
        {value}
      </div>
    </div>
  );
}

export default function RequestTracePage() {
  return (
    <Suspense fallback={<div className="p-4 text-sm text-muted-foreground">...</div>}>
      <RequestTraceContent />
    </Suspense>
  );
}
