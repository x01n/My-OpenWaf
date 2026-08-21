"use client"

/**
 * 请求追踪页面
 *
 * 通过 request_id 查询单次请求的完整链路：
 * - 访问日志 (access_logs)
 * - 安全事件 (security_events)
 * - Bot 评分 (bot_scores)
 *
 * 后端契约见 internal/admin/event/request.go
 *   GET /api/v1/request/:request_id
 *   -> { request_id: string, access_logs: AccessLog[]|null, security_events: SecurityEvent[]|null, bot_scores: BotScoreLog[] }
 */

import { Suspense, useCallback, useMemo, useState } from "react"
import dynamic from "next/dynamic"
import { useRouter, useSearchParams } from "next/navigation"
import { useTranslation } from "react-i18next"
import { format } from "date-fns"
import { PageHeader } from "@/components/page-header"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { ActionBadge } from "@/components/action-badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DataTable } from "@/components/data-table"
import { EmptyState } from "@/components/empty-state"
import {
  IconClock,
  IconEye,
  IconFileText,
  IconHash,
  IconMapPin,
  IconRoute,
  IconSearch,
  IconShieldExclamation,
  IconWorld,
} from "@tabler/icons-react"
import { useRequestTrace, useSites } from "@/hooks/use-api"
import type { AccessLog, BotScoreLog, SecurityEvent, Site } from "@/lib/types"
import { formatBytes, formatLatencyMs, cn } from "@/lib/utils"
import { localizeMatchDesc } from "@/lib/match-desc-i18n"
import { categoryLabel, phaseLabel } from "@/lib/attack-category"

const SecurityEventDetailDialog = dynamic(() =>
  import("@/components/security-event-detail-dialog").then(
    (module) => module.SecurityEventDetailDialog
  )
)
const AccessLogDetailDialog = dynamic(() =>
  import("@/components/access-log-detail-dialog").then(
    (module) => module.AccessLogDetailDialog
  )
)

/** 日期格式化失败时保留原始值，避免单条脏数据阻断整页。 */
function formatTraceTime(value?: string): string {
  if (!value) return "-"
  try {
    return format(new Date(value), "yyyy-MM-dd HH:mm:ss")
  } catch {
    return value
  }
}

/** 状态码区间样式，数值本身始终可读。 */
function statusBadgeClass(status: number): string {
  if (status >= 500) {
    return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
  }
  if (status >= 400) {
    return "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
  }
  if (status >= 300) {
    return "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300"
  }
  if (status >= 200) {
    return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
  }
  return ""
}

/** 追踪概要字段，使用平面网格而不是重复卡片。 */
function SummaryItem({
  icon,
  label,
  value,
  mono,
}: {
  icon?: React.ReactNode
  label: string
  value: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="min-w-0 border-b px-3 py-3 last:border-b-0 sm:border-r sm:px-4 lg:border-b-0 lg:last:border-r-0">
      <div className="flex items-center gap-1.5 text-[11px] font-medium tracking-wide text-muted-foreground uppercase">
        {icon}
        {label}
      </div>
      <div
        className={cn(
          "mt-1 min-w-0 text-sm break-all",
          mono && "font-mono text-xs"
        )}
      >
        {value}
      </div>
    </div>
  )
}

function RequestTraceContent() {
  const { t, i18n } = useTranslation()
  const router = useRouter()
  const searchParams = useSearchParams()
  const queryId = searchParams.get("id") || ""
  const [inputState, setInputState] = useState({
    source: queryId,
    value: queryId,
  })
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)
  const [selectedLog, setSelectedLog] = useState<AccessLog | null>(null)
  const inputValue = inputState.source === queryId ? inputState.value : queryId

  const { data, isLoading, error } = useRequestTrace(queryId || undefined)
  const { data: sitesData } = useSites({ page: 1, page_size: 500 })

  const siteMap = useMemo(() => {
    const map = new Map<number, Site>()
    ;(sitesData?.items || []).forEach((site) => map.set(site.id, site))
    return map
  }, [sitesData])

  const accessLogs = useMemo<AccessLog[]>(
    () => data?.access_logs || [],
    [data?.access_logs]
  )
  const securityEvents = useMemo<SecurityEvent[]>(
    () => data?.security_events || [],
    [data?.security_events]
  )
  const botScores = useMemo<BotScoreLog[]>(
    () => data?.bot_scores || [],
    [data?.bot_scores]
  )
  const hasAny =
    accessLogs.length > 0 || securityEvents.length > 0 || botScores.length > 0

  const handleSearch = useCallback(() => {
    const id = inputValue.trim()
    if (!id) return
    router.replace(`/request-trace?id=${encodeURIComponent(id)}`)
  }, [inputValue, router])

  const handleKey = useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "Enter") handleSearch()
    },
    [handleSearch]
  )

  /** 概要优先使用访问日志中的性能与响应字段，再回退到安全事件。 */
  const summary = useMemo(() => {
    const accessLog = accessLogs[0]
    const securityEvent = securityEvents[0]
    const botScore = botScores[0]
    const first = accessLog || securityEvent || botScore
    if (!first) return null
    const site = siteMap.get(first.site_id)
    const statusCode =
      accessLog?.status_code ?? securityEvent?.status_code ?? 0
    const wafAction =
      accessLog?.waf_action ||
      securityEvents.find((event) =>
        event.action !== "observe" && event.action !== "allow"
      )?.action ||
      securityEvent?.action ||
      "-"

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
      upstream: accessLog?.upstream,
      latency: accessLog?.upstream_latency_ms,
      responseSize: accessLog?.response_size,
      tlsVersion:
        accessLog?.tls_version || securityEvent?.tls_version || botScore?.tls_version,
      tlsSni: accessLog?.tls_sni || securityEvent?.tls_sni || botScore?.tls_sni,
      tlsAlpn: accessLog?.tls_alpn || securityEvent?.tls_alpn || botScore?.tls_alpn,
      tlsJa3: accessLog?.tls_ja3 || securityEvent?.tls_ja3,
      tlsJa3Hash:
        accessLog?.tls_ja3_hash || securityEvent?.tls_ja3_hash || botScore?.tls_ja3_hash,
      tlsJa4: accessLog?.tls_ja4 || securityEvent?.tls_ja4 || botScore?.tls_ja4,
    }
  }, [accessLogs, botScores, data?.request_id, queryId, securityEvents, siteMap])

  const accessLogColumns = useMemo(
    () => [
      {
        key: "created_at",
        title: t("requestTrace.firstSeen"),
        width: "168px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <span className="font-mono text-xs whitespace-nowrap">
            {formatTraceTime(row.created_at)}
          </span>
        ),
      },
      {
        key: "request",
        title: t("requestTrace.path"),
        width: "min(34vw, 420px)",
        cellClassName: "align-top whitespace-normal",
        render: (row: AccessLog) => (
          <div className="flex min-w-0 items-start gap-2">
            <Badge
              variant="outline"
              className="h-5 shrink-0 px-1.5 font-mono text-[10px] font-semibold"
            >
              {row.method || "-"}
            </Badge>
            <div className="min-w-0">
              <code
                className="line-clamp-2 block font-mono text-xs leading-relaxed break-all"
                title={row.path || undefined}
              >
                {row.path || "/"}
              </code>
              <span className="mt-1 block truncate text-[11px] text-muted-foreground">
                {row.host || row.client_ip || "-"}
              </span>
            </div>
          </div>
        ),
      },
      {
        key: "status_code",
        title: t("requestTrace.statusCode"),
        width: "90px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <Badge
            variant="outline"
            className={cn("font-mono text-xs", statusBadgeClass(row.status_code))}
          >
            {row.status_code || "-"}
          </Badge>
        ),
      },
      {
        key: "waf_action",
        title: t("requestTrace.wafAction"),
        width: "116px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <ActionBadge action={row.waf_action} className="h-5 px-1.5 text-[10px]" />
        ),
      },
      {
        key: "performance",
        title: t("requestTrace.upstreamLatency"),
        width: "156px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <div className="space-y-1 font-mono text-[11px]">
            <div>{formatLatencyMs(row.upstream_latency_ms)}</div>
            <div className="text-muted-foreground">
              {formatBytes(row.request_size)} → {formatBytes(row.response_size)}
            </div>
          </div>
        ),
      },
      {
        key: "upstream",
        title: t("requestTrace.upstream"),
        width: "210px",
        cellClassName: "align-top whitespace-normal",
        render: (row: AccessLog) => (
          <div className="min-w-0 space-y-1">
            <div className="truncate font-mono text-xs" title={row.upstream || undefined}>
              {row.upstream || "-"}
            </div>
            <div className="text-[10px] text-muted-foreground">
              {row.http_protocol || "-"} → {row.upstream_http_protocol || "-"}
            </div>
          </div>
        ),
      },
      {
        key: "operations",
        title: t("common.action"),
        width: "52px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="cursor-pointer"
            title={t("common.viewDetail")}
            onClick={() => setSelectedLog(row)}
          >
            <IconEye className="h-4 w-4" />
          </Button>
        ),
      },
    ],
    [t]
  )

  const securityEventColumns = useMemo(
    () => [
      {
        key: "created_at",
        title: t("requestTrace.firstSeen"),
        width: "168px",
        cellClassName: "align-top",
        render: (row: SecurityEvent) => (
          <span className="font-mono text-xs whitespace-nowrap">
            {formatTraceTime(row.created_at)}
          </span>
        ),
      },
      {
        key: "action",
        title: t("requestTrace.action"),
        width: "116px",
        cellClassName: "align-top",
        render: (row: SecurityEvent) => (
          <ActionBadge action={row.action} className="h-5 px-1.5 text-[10px]" />
        ),
      },
      {
        key: "category",
        title: t("requestTrace.category"),
        width: "130px",
        cellClassName: "align-top",
        render: (row: SecurityEvent) => categoryLabel(row.category),
      },
      {
        key: "phase",
        title: t("requestTrace.phase"),
        width: "116px",
        cellClassName: "align-top",
        render: (row: SecurityEvent) => (
          <Badge variant="secondary" className="h-5 px-1.5 font-mono text-[10px]">
            {phaseLabel(row.phase)}
          </Badge>
        ),
      },
      {
        key: "rule_id_str",
        title: t("requestTrace.rule"),
        width: "150px",
        cellClassName: "align-top whitespace-normal break-all",
        render: (row: SecurityEvent) => (
          <span className="font-mono text-xs break-all">
            {row.rule_id_str || String(row.rule_id) || "-"}
          </span>
        ),
      },
      {
        key: "match_desc",
        title: t("requestTrace.matchDesc"),
        cellClassName: "align-top whitespace-normal",
        render: (row: SecurityEvent) => (
          <span className="line-clamp-2 block max-w-full text-xs leading-relaxed break-words text-muted-foreground">
            {localizeMatchDesc(
              row.match_desc,
              i18n.resolvedLanguage ?? i18n.language
            ) || "-"}
          </span>
        ),
      },
      {
        key: "operations",
        title: t("common.action"),
        width: "52px",
        cellClassName: "align-top",
        render: (row: SecurityEvent) => (
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="cursor-pointer"
            title={t("common.viewDetail")}
            onClick={() => setSelectedEvent(row)}
          >
            <IconEye className="h-4 w-4" />
          </Button>
        ),
      },
    ],
    [t, i18n.language, i18n.resolvedLanguage]
  )

  const botScoreColumns = useMemo(
    () => [
      {
        key: "created_at",
        title: t("requestTrace.firstSeen"),
        width: "168px",
        cellClassName: "align-top",
        render: (row: BotScoreLog) => (
          <span className="font-mono text-xs whitespace-nowrap">
            {formatTraceTime(row.created_at)}
          </span>
        ),
      },
      {
        key: "score",
        title: t("requestTrace.totalScore"),
        width: "210px",
        cellClassName: "align-top whitespace-normal",
        render: (row: BotScoreLog) => (
          <div className="space-y-1 font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="font-semibold">{row.total_score}</span>
              {row.is_high_risk && (
                <Badge variant="destructive" className="h-5 px-1.5 text-[10px]">
                  {t("requestTrace.highRisk")}
                </Badge>
              )}
            </div>
            <div className="text-[10px] text-muted-foreground break-all">
              {t("requestTrace.geoipScore")}: {row.geoip_score} · {t("requestTrace.fingerprintScore")}: {row.fingerprint_score} · {t("requestTrace.behaviorScore")}: {row.behavior_score} · {t("requestTrace.ipRepScore")}: {row.ip_rep_score}
            </div>
          </div>
        ),
      },
      {
        key: "action",
        title: t("requestTrace.action"),
        width: "116px",
        cellClassName: "align-top",
        render: (row: BotScoreLog) => (
          <ActionBadge action={row.action} className="h-5 px-1.5 text-[10px]" />
        ),
      },
      {
        key: "client",
        title: t("requestTrace.botClient"),
        width: "min(34vw, 420px)",
        cellClassName: "align-top whitespace-normal",
        render: (row: BotScoreLog) => (
          <div className="min-w-0 space-y-1">
            <code className="block font-mono text-xs break-all">{row.client_ip || "-"}</code>
            <code className="block text-[11px] leading-relaxed break-all text-muted-foreground">
              {row.host || "-"}{row.path || "/"}
            </code>
            <span className="line-clamp-2 block text-[10px] break-words text-muted-foreground" title={row.user_agent || undefined}>
              {row.user_agent || "-"}
            </span>
          </div>
        ),
      },
      {
        key: "fingerprint",
        title: t("requestTrace.botFingerprint"),
        width: "min(32vw, 360px)",
        cellClassName: "align-top whitespace-normal",
        render: (row: BotScoreLog) => (
          <div className="space-y-1 text-[10px] leading-relaxed break-all">
            <div>{t("requestTrace.tlsVersion")}: {row.tls_version || "-"}</div>
            <div>{t("requestTrace.tlsSni")}: {row.tls_sni || "-"}</div>
            <div>{t("requestTrace.tlsAlpn")}: {row.tls_alpn || "-"}</div>
            <div className="font-mono">{t("requestTrace.tlsJa4")}: {row.tls_ja4 || "-"}</div>
            <div className="font-mono">{t("requestTrace.tlsJa3Hash")}: {row.tls_ja3_hash || "-"}</div>
          </div>
        ),
      },
      {
        key: "details",
        title: t("requestTrace.details"),
        width: "min(30vw, 320px)",
        cellClassName: "align-top whitespace-normal",
        render: (row: BotScoreLog) => (
          <code className="line-clamp-3 block max-w-full whitespace-pre-wrap break-all text-[10px] text-muted-foreground">
            {row.details || "-"}
          </code>
        ),
      },
    ],
    [t]
  )

  return (
    <div className="max-w-full min-w-0 space-y-4 overflow-x-hidden">
      <PageHeader
        icon={<IconRoute className="h-6 w-6 text-primary" />}
        title={t("requestTrace.title")}
        description={t("requestTrace.description")}
      />

      <div className="rounded-lg border bg-card p-3 sm:p-4">
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            value={inputValue}
            aria-label={t("requestTrace.searchPlaceholder")}
            placeholder={t("requestTrace.searchPlaceholder")}
            className="h-9 w-full font-mono text-xs sm:flex-1"
            onChange={(event) =>
              setInputState({ source: queryId, value: event.target.value })
            }
            onKeyDown={handleKey}
          />
          <Button
            size="sm"
            className="h-9 cursor-pointer gap-1.5"
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
          <div className="mt-3 rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">
            {(error as Error).message || t("common.operationFailed")}
          </div>
        )}
      </div>

      {summary && (
        <section className="overflow-hidden rounded-lg border bg-card" aria-label={t("requestTrace.summary")}>
          <div className="border-b bg-muted/10 px-4 py-3">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <Badge variant="outline" className="font-mono text-xs font-semibold">
                {summary.method || "-"}
              </Badge>
              <Badge
                variant="outline"
                className={cn("font-mono text-xs", statusBadgeClass(summary.statusCode))}
              >
                {summary.statusCode || "-"}
              </Badge>
              <ActionBadge
                action={summary.wafAction}
                className="h-6 px-2 text-xs"
              />
              <code className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={`${summary.host || ""}${summary.path || ""}`}>
                {summary.host || "-"}{summary.path || "/"}
              </code>
            </div>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4">
            <SummaryItem
              icon={<IconHash className="h-3.5 w-3.5" />}
              label={t("requestTrace.requestId")}
              value={summary.requestId}
              mono
            />
            <SummaryItem
              icon={<IconClock className="h-3.5 w-3.5" />}
              label={t("requestTrace.firstSeen")}
              value={formatTraceTime(summary.time)}
              mono
            />
            <SummaryItem
              icon={<IconMapPin className="h-3.5 w-3.5" />}
              label={t("requestTrace.clientIp")}
              value={summary.clientIp || "-"}
              mono
            />
            <SummaryItem
              icon={<IconWorld className="h-3.5 w-3.5" />}
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
              icon={<IconRoute className="h-3.5 w-3.5" />}
              label={t("requestTrace.upstream")}
              value={summary.upstream || "-"}
              mono
            />
            <SummaryItem
              label={t("requestTrace.upstreamLatency")}
              value={
                summary.latency == null
                  ? "-"
                  : formatLatencyMs(summary.latency)
              }
              mono
            />
            <SummaryItem
              label={t("requestTrace.responseSize")}
              value={
                summary.responseSize == null
                  ? "-"
                  : formatBytes(summary.responseSize)
              }
              mono
            />
            <SummaryItem
              label={t("requestTrace.tlsVersion")}
              value={summary.tlsVersion || "-"}
              mono
            />
            <SummaryItem
              label={t("requestTrace.tlsSni")}
              value={summary.tlsSni || "-"}
              mono
            />
            <SummaryItem
              label={t("requestTrace.tlsAlpn")}
              value={summary.tlsAlpn || "-"}
              mono
            />
            <SummaryItem
              label={t("requestTrace.tlsJa3")}
              value={summary.tlsJa3 || "-"}
              mono
            />
            <SummaryItem
              label={t("requestTrace.tlsJa4")}
              value={summary.tlsJa4 || "-"}
              mono
            />
            <SummaryItem
              label={t("requestTrace.tlsJa3Hash")}
              value={summary.tlsJa3Hash || "-"}
              mono
            />
          </div>
        </section>
      )}

      {hasAny && (
        <Card className="min-w-0 overflow-hidden">
          <CardContent className="min-w-0 p-3 sm:p-4">
            <Tabs defaultValue="access_logs">
              <div className="max-w-full min-w-0 overflow-x-auto">
                <TabsList className="w-max">
                  <TabsTrigger value="access_logs" className="cursor-pointer gap-1.5">
                    <IconFileText className="h-4 w-4" />
                    {t("requestTrace.accessLogsCount", { count: accessLogs.length })}
                  </TabsTrigger>
                  <TabsTrigger value="security_events" className="cursor-pointer gap-1.5">
                    <IconShieldExclamation className="h-4 w-4" />
                    {t("requestTrace.securityEventsCount", {
                      count: securityEvents.length,
                    })}
                  </TabsTrigger>
                  <TabsTrigger value="bot_scores" className="cursor-pointer gap-1.5">
                    <IconShieldExclamation className="h-4 w-4" />
                    {t("requestTrace.botScoresCount", { count: botScores.length })}
                  </TabsTrigger>
                </TabsList>
              </div>
              <TabsContent value="access_logs" className="mt-4 min-w-0">
                <DataTable
                  columns={accessLogColumns}
                  data={accessLogs}
                  rowKey={(row) => row.id}
                  emptyText={t("requestTrace.emptyAccessLogs")}
                />
              </TabsContent>
              <TabsContent value="security_events" className="mt-4 min-w-0">
                <DataTable
                  columns={securityEventColumns}
                  data={securityEvents}
                  rowKey={(row) => row.id}
                  emptyText={t("requestTrace.emptySecurityEvents")}
                />
              </TabsContent>
              <TabsContent value="bot_scores" className="mt-4 min-w-0">
                <DataTable
                  columns={botScoreColumns}
                  data={botScores}
                  rowKey={(row) => row.id}
                  emptyText={t("requestTrace.emptyBotScores")}
                />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}

      {selectedLog && (
        <AccessLogDetailDialog
          log={selectedLog}
          open
          onOpenChange={(open) => {
            if (!open) setSelectedLog(null)
          }}
        />
      )}
      {selectedEvent && (
        <SecurityEventDetailDialog
          event={selectedEvent}
          open
          onOpenChange={(open) => {
            if (!open) setSelectedEvent(null)
          }}
        />
      )}
    </div>
  )
}

export default function RequestTracePage() {
  return (
    <Suspense
      fallback={<div className="p-4 text-sm text-muted-foreground">...</div>}
    >
      <RequestTraceContent />
    </Suspense>
  )
}
