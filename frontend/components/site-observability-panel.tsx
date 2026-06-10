"use client"

import Link from "next/link"
import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  CopyableBlock,
  DetailField,
  TruncatedCell,
  WAFActionBadge,
  redactSensitiveText,
} from "@/components/log-presentation"
import { Pagination } from "@/components/pagination"
import { RequestTracePanel } from "@/components/request-trace-panel"
import { deferEffect } from "@/lib/effects"
import {
  Activity,
  BarChart3,
  Eye,
  FileText,
  ListChecks,
  RefreshCcw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldX,
} from "@/lib/icons"
import {
  getAccessLog,
  getRequestTrace,
  getSiteAccessLogs,
  getSiteDropEvents,
  getSiteDropStats,
  getSiteRules,
  getSiteSecurityEvents,
  getSiteSecurityStats,
  getSiteSecurityTimeline,
  getSecurityEvent,
  type AccessLogQuery,
  type AccessLog,
  type DropEvent,
  type DropStats,
  type Rule,
  type RequestTrace,
  type SecurityEvent,
  type SiteDropEventQuery,
  type SiteAccessLogStats,
  type SiteSecurityEventQuery,
  type SiteSecurityStats,
  type TimelineBucket,
} from "@/lib/api"
import { categoryLabels, phaseLabels, wafActionOptions } from "@/lib/console"
import { cn, formatDate } from "@/lib/utils"

const OBSERVABILITY_PAGE_SIZE = 8

const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
]

export function SiteObservabilityPanel({
  siteId,
  siteHost,
  accessStats,
}: {
  siteId: string | number
  siteHost: string
  accessStats: SiteAccessLogStats | null
}) {
  const [loading, setLoading] = useState(true)
  const [accessPage, setAccessPage] = useState(1)
  const [accessLogs, setAccessLogs] = useState<AccessLog[]>([])
  const [accessTotal, setAccessTotal] = useState(0)
  const [accessLogId, setAccessLogId] = useState("")
  const [accessRequestId, setAccessRequestId] = useState("")
  const [accessClientIp, setAccessClientIp] = useState("")
  const [accessHost, setAccessHost] = useState("")
  const [accessPath, setAccessPath] = useState("")
  const [accessStatusGroup, setAccessStatusGroup] = useState("all")
  const [accessMethod, setAccessMethod] = useState("all")
  const [accessWafAction, setAccessWafAction] = useState("all")
  const [accessCacheState, setAccessCacheState] = useState("all")
  const [accessSince, setAccessSince] = useState("")
  const [accessUntil, setAccessUntil] = useState("")
  const [securityPage, setSecurityPage] = useState(1)
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([])
  const [securityTotal, setSecurityTotal] = useState(0)
  const [securityRequestId, setSecurityRequestId] = useState("")
  const [securityClientIp, setSecurityClientIp] = useState("")
  const [securityPath, setSecurityPath] = useState("")
  const [securityAction, setSecurityAction] = useState("all")
  const [securityPhase, setSecurityPhase] = useState("all")
  const [securityCategory, setSecurityCategory] = useState("all")
  const [securityTLSSNI, setSecurityTLSSNI] = useState("")
  const [securityTLSJA3Hash, setSecurityTLSJA3Hash] = useState("")
  const [securityTLSJA4, setSecurityTLSJA4] = useState("")
  const [securityTLSVersion, setSecurityTLSVersion] = useState("")
  const [securityTLSALPN, setSecurityTLSALPN] = useState("")
  const [securityHeaderOrder, setSecurityHeaderOrder] = useState("")
  const [securitySince, setSecuritySince] = useState("")
  const [securityUntil, setSecurityUntil] = useState("")
  const [securityStats, setSecurityStats] = useState<SiteSecurityStats | null>(
    null
  )
  const [securityTimeline, setSecurityTimeline] = useState<TimelineBucket[]>([])
  const [dropPage, setDropPage] = useState(1)
  const [dropEvents, setDropEvents] = useState<DropEvent[]>([])
  const [dropTotal, setDropTotal] = useState(0)
  const [dropClientIp, setDropClientIp] = useState("")
  const [dropSource, setDropSource] = useState("all")
  const [dropStartTime, setDropStartTime] = useState("")
  const [dropEndTime, setDropEndTime] = useState("")
  const [dropStats, setDropStats] = useState<DropStats | null>(null)
  const [siteRules, setSiteRules] = useState<Rule[]>([])
  const [siteRulesTotal, setSiteRulesTotal] = useState(0)
  const [policyId, setPolicyId] = useState<number | null>(null)
  const [selectedAccessLog, setSelectedAccessLog] = useState<AccessLog | null>(
    null
  )
  const [selectedSecurityEvent, setSelectedSecurityEvent] =
    useState<SecurityEvent | null>(null)
  const [selectedDropEvent, setSelectedDropEvent] = useState<DropEvent | null>(
    null
  )
  const [loadingAccessLogId, setLoadingAccessLogId] = useState<number | null>(
    null
  )
  const [loadingSecurityEventId, setLoadingSecurityEventId] = useState<
    number | null
  >(null)
  const [requestTrace, setRequestTrace] = useState<RequestTrace | null>(null)
  const [traceLoading, setTraceLoading] = useState(false)

  const primaryHost = useMemo(
    () => siteHost.split(",").map((item) => item.trim()).find(Boolean) ?? "",
    [siteHost]
  )

  const accessFiltersActive = Boolean(
    accessLogId ||
      accessRequestId ||
      accessClientIp ||
      accessHost ||
      accessPath ||
      accessStatusGroup !== "all" ||
      accessMethod !== "all" ||
      accessWafAction !== "all" ||
      accessCacheState !== "all" ||
      accessSince ||
      accessUntil
  )
  const securityFiltersActive = Boolean(
    securityRequestId ||
      securityClientIp ||
      securityPath ||
      securityAction !== "all" ||
      securityPhase !== "all" ||
      securityCategory !== "all" ||
      securityTLSSNI ||
      securityTLSJA3Hash ||
      securityTLSJA4 ||
      securityTLSVersion ||
      securityTLSALPN ||
      securityHeaderOrder ||
      securitySince ||
      securityUntil
  )
  const dropFiltersActive = Boolean(
    dropClientIp || dropSource !== "all" || dropStartTime || dropEndTime
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const accessParams: AccessLogQuery = {
        page: accessPage,
        page_size: OBSERVABILITY_PAGE_SIZE,
        id: accessLogId || undefined,
        request_id: accessRequestId || undefined,
        client_ip: accessClientIp || undefined,
        host: accessHost || undefined,
        path: accessPath || undefined,
        status_group:
          accessStatusGroup === "all" ? undefined : accessStatusGroup,
        method: accessMethod === "all" ? undefined : accessMethod,
        waf_action: accessWafAction === "all" ? undefined : accessWafAction,
        cache_state:
          accessCacheState === "all" ? undefined : accessCacheState,
        since: accessSince ? new Date(accessSince).toISOString() : undefined,
        until: accessUntil ? new Date(accessUntil).toISOString() : undefined,
      }
      const securityParams: SiteSecurityEventQuery = {
        page: securityPage,
        page_size: OBSERVABILITY_PAGE_SIZE,
        request_id: securityRequestId || undefined,
        client_ip: securityClientIp || undefined,
        path: securityPath || undefined,
        action: securityAction === "all" ? undefined : securityAction,
        phase: securityPhase === "all" ? undefined : securityPhase,
        category:
          securityCategory === "all" ? undefined : securityCategory,
        tls_sni: securityTLSSNI || undefined,
        tls_ja3_hash: securityTLSJA3Hash || undefined,
        tls_ja4: securityTLSJA4 || undefined,
        tls_version: securityTLSVersion || undefined,
        tls_alpn: securityTLSALPN || undefined,
        header_order: securityHeaderOrder || undefined,
        since: securitySince
          ? new Date(securitySince).toISOString()
          : undefined,
        until: securityUntil
          ? new Date(securityUntil).toISOString()
          : undefined,
      }
      const dropParams: SiteDropEventQuery = {
        page: dropPage,
        page_size: OBSERVABILITY_PAGE_SIZE,
        client_ip: dropClientIp || undefined,
        source: dropSource === "all" ? undefined : dropSource,
        start_time: dropStartTime
          ? new Date(dropStartTime).toISOString()
          : undefined,
        end_time: dropEndTime ? new Date(dropEndTime).toISOString() : undefined,
      }
      const [
        accessLogResult,
        securityStatsResult,
        securityTimelineResult,
        securityEventResult,
        dropStatsResult,
        dropEventResult,
        siteRulesResult,
      ] = await Promise.all([
        getSiteAccessLogs(siteId, accessParams),
        getSiteSecurityStats(siteId, 24),
        getSiteSecurityTimeline(siteId, 24),
        getSiteSecurityEvents(siteId, securityParams),
        getSiteDropStats(siteId),
        getSiteDropEvents(siteId, dropParams),
        getSiteRules(siteId),
      ])

      setAccessLogs(accessLogResult.items ?? [])
      setAccessTotal(Number(accessLogResult.total) || 0)
      const nextAccessTotal = Number(accessLogResult.total) || 0
      const nextAccessTotalPages = Math.max(
        1,
        Math.ceil(nextAccessTotal / OBSERVABILITY_PAGE_SIZE)
      )
      if (accessPage > nextAccessTotalPages) {
        setAccessPage(nextAccessTotalPages)
      }
      setSecurityStats(securityStatsResult)
      setSecurityTimeline(securityTimelineResult.buckets ?? [])
      setSecurityEvents(securityEventResult.items ?? [])
      setSecurityTotal(Number(securityEventResult.total) || 0)
      const nextSecurityTotal = Number(securityEventResult.total) || 0
      const nextSecurityTotalPages = Math.max(
        1,
        Math.ceil(nextSecurityTotal / OBSERVABILITY_PAGE_SIZE)
      )
      if (securityPage > nextSecurityTotalPages) {
        setSecurityPage(nextSecurityTotalPages)
      }
      setDropStats(dropStatsResult)
      setDropEvents(dropEventResult.items ?? [])
      setDropTotal(Number(dropEventResult.total) || 0)
      const nextDropTotal = Number(dropEventResult.total) || 0
      const nextDropTotalPages = Math.max(
        1,
        Math.ceil(nextDropTotal / OBSERVABILITY_PAGE_SIZE)
      )
      if (dropPage > nextDropTotalPages) {
        setDropPage(nextDropTotalPages)
      }
      setSiteRules(siteRulesResult.items ?? [])
      setSiteRulesTotal(Number(siteRulesResult.total) || 0)
      setPolicyId(siteRulesResult.policy_id ?? null)
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "加载站点观测数据失败"
      )
      setAccessLogs([])
      setAccessTotal(0)
      setSecurityStats(null)
      setSecurityTimeline([])
      setSecurityEvents([])
      setSecurityTotal(0)
      setDropStats(null)
      setDropEvents([])
      setDropTotal(0)
      setSiteRules([])
      setSiteRulesTotal(0)
      setPolicyId(null)
    } finally {
      setLoading(false)
    }
  }, [
    accessCacheState,
    accessClientIp,
    accessHost,
    accessLogId,
    accessMethod,
    accessPage,
    accessPath,
    accessRequestId,
    accessSince,
    accessStatusGroup,
    accessUntil,
    accessWafAction,
    dropClientIp,
    dropEndTime,
    dropPage,
    dropSource,
    dropStartTime,
    securityAction,
    securityCategory,
    securityClientIp,
    securityHeaderOrder,
    securitySince,
    securityPage,
    securityPath,
    securityPhase,
    securityRequestId,
    securityTLSALPN,
    securityTLSJA3Hash,
    securityTLSJA4,
    securityTLSSNI,
    securityTLSVersion,
    securityUntil,
    siteId,
  ])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  function resetAccessFilters() {
    setAccessLogId("")
    setAccessRequestId("")
    setAccessClientIp("")
    setAccessHost("")
    setAccessPath("")
    setAccessStatusGroup("all")
    setAccessMethod("all")
    setAccessWafAction("all")
    setAccessCacheState("all")
    setAccessSince("")
    setAccessUntil("")
    setAccessPage(1)
  }

  function resetSecurityFilters() {
    setSecurityRequestId("")
    setSecurityClientIp("")
    setSecurityPath("")
    setSecurityAction("all")
    setSecurityPhase("all")
    setSecurityCategory("all")
    setSecurityTLSSNI("")
    setSecurityTLSJA3Hash("")
    setSecurityTLSJA4("")
    setSecurityTLSVersion("")
    setSecurityTLSALPN("")
    setSecurityHeaderOrder("")
    setSecuritySince("")
    setSecurityUntil("")
    setSecurityPage(1)
  }

  function resetDropFilters() {
    setDropClientIp("")
    setDropSource("all")
    setDropStartTime("")
    setDropEndTime("")
    setDropPage(1)
  }

  async function openAccessLogDetail(item: AccessLog) {
    setSelectedAccessLog(item)
    setRequestTrace(null)
    setLoadingAccessLogId(item.id)
    try {
      const detail = await getAccessLog(item.id)
      setSelectedAccessLog((current) =>
        current?.id === item.id ? detail : current
      )
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "加载访问日志详情失败"
      )
    } finally {
      setLoadingAccessLogId(null)
    }
  }

  async function openSecurityEventDetail(item: SecurityEvent) {
    setSelectedSecurityEvent(item)
    setRequestTrace(null)
    setLoadingSecurityEventId(item.id)
    try {
      const detail = await getSecurityEvent(item.id)
      setSelectedSecurityEvent((current) =>
        current?.id === item.id ? detail : current
      )
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "加载安全事件详情失败"
      )
    } finally {
      setLoadingSecurityEventId(null)
    }
  }

  async function loadRequestTrace(requestId: string) {
    if (!requestId) return
    setTraceLoading(true)
    try {
      setRequestTrace(await getRequestTrace(requestId))
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载请求追踪失败")
    } finally {
      setTraceLoading(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">站点观测</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            {primaryHost || "当前站点"} · 最近 24 小时聚合与最新记录
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="rounded-md"
          disabled={loading}
          onClick={() => void load()}
        >
          <RefreshCcw data-icon="inline-start" />
          刷新观测
        </Button>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <ObservabilityMetric
          icon={Activity}
          label="24h 请求"
          value={accessStats?.requests ?? 0}
          subValue={`${
            accessFiltersActive ? "当前筛选记录" : "最新记录"
          } ${accessTotal}`}
          loading={loading}
        />
        <ObservabilityMetric
          icon={ShieldAlert}
          label="安全事件"
          value={securityStats?.total ?? 0}
          subValue={`拦截 ${securityStats?.intercepts ?? 0} · 观察 ${
            securityStats?.observes ?? 0
          }`}
          loading={loading}
        />
        <ObservabilityMetric
          icon={ShieldX}
          label="丢弃连接"
          value={dropStats?.total_24h ?? 0}
          subValue={`Bot ${dropStats?.by_bot ?? 0} · CVE ${
            dropStats?.by_cve ?? 0
          }`}
          loading={loading}
        />
        <ObservabilityMetric
          icon={ListChecks}
          label="策略规则"
          value={siteRulesTotal}
          subValue={
            policyId === null ? "未绑定策略" : `策略 ID ${policyId}`
          }
          loading={loading}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
        <AccessLogSection
          items={accessLogs}
          total={accessTotal}
          page={accessPage}
          loading={loading}
          loadingDetailId={loadingAccessLogId}
          requestId={accessRequestId}
          logId={accessLogId}
          clientIp={accessClientIp}
          host={accessHost}
          path={accessPath}
          statusGroup={accessStatusGroup}
          method={accessMethod}
          wafAction={accessWafAction}
          cacheState={accessCacheState}
          since={accessSince}
          until={accessUntil}
          filtersActive={accessFiltersActive}
          onLogIdChange={setAccessLogId}
          onRequestIdChange={setAccessRequestId}
          onClientIpChange={setAccessClientIp}
          onHostChange={setAccessHost}
          onPathChange={setAccessPath}
          onStatusGroupChange={setAccessStatusGroup}
          onMethodChange={setAccessMethod}
          onWafActionChange={setAccessWafAction}
          onCacheStateChange={setAccessCacheState}
          onSinceChange={setAccessSince}
          onUntilChange={setAccessUntil}
          onPageChange={setAccessPage}
          onResetFilters={resetAccessFilters}
          onOpenDetail={openAccessLogDetail}
        />
        <TimelineSection items={securityTimeline} loading={loading} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <SecurityEventSection
          items={securityEvents}
          total={securityTotal}
          page={securityPage}
          loading={loading}
          loadingDetailId={loadingSecurityEventId}
          requestId={securityRequestId}
          clientIp={securityClientIp}
          path={securityPath}
          action={securityAction}
          phase={securityPhase}
          category={securityCategory}
          tlsSNI={securityTLSSNI}
          tlsJA3Hash={securityTLSJA3Hash}
          tlsJA4={securityTLSJA4}
          tlsVersion={securityTLSVersion}
          tlsALPN={securityTLSALPN}
          headerOrder={securityHeaderOrder}
          since={securitySince}
          until={securityUntil}
          filtersActive={securityFiltersActive}
          onRequestIdChange={setSecurityRequestId}
          onClientIpChange={setSecurityClientIp}
          onPathChange={setSecurityPath}
          onActionChange={setSecurityAction}
          onPhaseChange={setSecurityPhase}
          onCategoryChange={setSecurityCategory}
          onTLSSNIChange={setSecurityTLSSNI}
          onTLSJA3HashChange={setSecurityTLSJA3Hash}
          onTLSJA4Change={setSecurityTLSJA4}
          onTLSVersionChange={setSecurityTLSVersion}
          onTLSALPNChange={setSecurityTLSALPN}
          onHeaderOrderChange={setSecurityHeaderOrder}
          onSinceChange={setSecuritySince}
          onUntilChange={setSecurityUntil}
          onPageChange={setSecurityPage}
          onResetFilters={resetSecurityFilters}
          onOpenDetail={openSecurityEventDetail}
        />
        <DropEventSection
          items={dropEvents}
          total={dropTotal}
          page={dropPage}
          loading={loading}
          clientIp={dropClientIp}
          source={dropSource}
          startTime={dropStartTime}
          endTime={dropEndTime}
          filtersActive={dropFiltersActive}
          onClientIpChange={setDropClientIp}
          onSourceChange={setDropSource}
          onStartTimeChange={setDropStartTime}
          onEndTimeChange={setDropEndTime}
          onPageChange={setDropPage}
          onResetFilters={resetDropFilters}
          onOpenDetail={setSelectedDropEvent}
        />
      </div>

      <RulesSection
        items={siteRules}
        total={siteRulesTotal}
        policyId={policyId}
        loading={loading}
      />

      <AccessLogDetailDialog
        item={selectedAccessLog}
        requestTrace={requestTrace}
        traceLoading={traceLoading}
        onLoadRequestTrace={loadRequestTrace}
        onOpenChange={(open) => {
          if (!open) {
            setSelectedAccessLog(null)
            setRequestTrace(null)
          }
        }}
      />
      <SecurityEventDetailDialog
        item={selectedSecurityEvent}
        requestTrace={requestTrace}
        traceLoading={traceLoading}
        onLoadRequestTrace={loadRequestTrace}
        onOpenChange={(open) => {
          if (!open) {
            setSelectedSecurityEvent(null)
            setRequestTrace(null)
          }
        }}
      />
      <DropEventDetailDialog
        item={selectedDropEvent}
        onOpenChange={(open) => {
          if (!open) setSelectedDropEvent(null)
        }}
      />
    </div>
  )
}

function ObservabilityMetric({
  icon: Icon,
  label,
  value,
  subValue,
  loading,
}: {
  icon: typeof Activity
  label: string
  value: number
  subValue: string
  loading: boolean
}) {
  return (
    <div className="rounded-md border bg-background p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs font-medium text-muted-foreground">{label}</div>
        <div className="flex size-8 items-center justify-center rounded-md bg-muted text-muted-foreground">
          <Icon />
        </div>
      </div>
      {loading ? (
        <div className="mt-3 flex flex-col gap-2">
          <Skeleton className="h-7 w-24" />
          <Skeleton className="h-4 w-32" />
        </div>
      ) : (
        <>
          <div className="mt-3 text-2xl font-semibold">
            {value.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">{subValue}</div>
        </>
      )}
    </div>
  )
}

function AccessLogSection({
  items,
  total,
  page,
  loading,
  loadingDetailId,
  logId,
  requestId,
  clientIp,
  host,
  path,
  statusGroup,
  method,
  wafAction,
  cacheState,
  since,
  until,
  filtersActive,
  onLogIdChange,
  onRequestIdChange,
  onClientIpChange,
  onHostChange,
  onPathChange,
  onStatusGroupChange,
  onMethodChange,
  onWafActionChange,
  onCacheStateChange,
  onSinceChange,
  onUntilChange,
  onPageChange,
  onResetFilters,
  onOpenDetail,
}: {
  items: AccessLog[]
  total: number
  page: number
  loading: boolean
  loadingDetailId: number | null
  logId: string
  requestId: string
  clientIp: string
  host: string
  path: string
  statusGroup: string
  method: string
  wafAction: string
  cacheState: string
  since: string
  until: string
  filtersActive: boolean
  onLogIdChange: (value: string) => void
  onRequestIdChange: (value: string) => void
  onClientIpChange: (value: string) => void
  onHostChange: (value: string) => void
  onPathChange: (value: string) => void
  onStatusGroupChange: (value: string) => void
  onMethodChange: (value: string) => void
  onWafActionChange: (value: string) => void
  onCacheStateChange: (value: string) => void
  onSinceChange: (value: string) => void
  onUntilChange: (value: string) => void
  onPageChange: (page: number) => void
  onResetFilters: () => void
  onOpenDetail: (item: AccessLog) => void
}) {
  const totalPages = Math.max(
    1,
    Math.ceil(total / OBSERVABILITY_PAGE_SIZE)
  )

  return (
    <section className="min-w-0 rounded-md border">
      <SectionHeader
        icon={FileText}
        title={filtersActive ? "当前筛选访问日志" : "最新访问日志"}
        total={total}
        href="/access-logs/"
      />
      <AccessLogFilters
        logId={logId}
        requestId={requestId}
        clientIp={clientIp}
        host={host}
        path={path}
        statusGroup={statusGroup}
        method={method}
        wafAction={wafAction}
        cacheState={cacheState}
        since={since}
        until={until}
        filtersActive={filtersActive}
        onLogIdChange={(value) => {
          onLogIdChange(value)
          onPageChange(1)
        }}
        onRequestIdChange={(value) => {
          onRequestIdChange(value)
          onPageChange(1)
        }}
        onClientIpChange={(value) => {
          onClientIpChange(value)
          onPageChange(1)
        }}
        onHostChange={(value) => {
          onHostChange(value)
          onPageChange(1)
        }}
        onPathChange={(value) => {
          onPathChange(value)
          onPageChange(1)
        }}
        onStatusGroupChange={(value) => {
          onStatusGroupChange(value)
          onPageChange(1)
        }}
        onMethodChange={(value) => {
          onMethodChange(value)
          onPageChange(1)
        }}
        onWafActionChange={(value) => {
          onWafActionChange(value)
          onPageChange(1)
        }}
        onCacheStateChange={(value) => {
          onCacheStateChange(value)
          onPageChange(1)
        }}
        onSinceChange={(value) => {
          onSinceChange(value)
          onPageChange(1)
        }}
        onUntilChange={(value) => {
          onUntilChange(value)
          onPageChange(1)
        }}
        onResetFilters={onResetFilters}
      />
      <div className="overflow-x-auto">
        <Table className="min-w-[900px] text-xs">
          <TableHeader className="bg-muted/35 text-muted-foreground">
            <TableRow>
              <TableHead className="px-2 py-2">时间</TableHead>
              <TableHead className="px-2 py-2">方法</TableHead>
              <TableHead className="px-2 py-2">路径</TableHead>
              <TableHead className="px-2 py-2">状态</TableHead>
              <TableHead className="px-2 py-2">WAF 动作</TableHead>
              <TableHead className="px-2 py-2">客户端</TableHead>
              <TableHead className="px-2 py-2">Request ID</TableHead>
              <TableHead className="px-2 py-2 text-right">详情</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <SkeletonRows columns={8} rows={4} />
            ) : items.length === 0 ? (
              <EmptyRow columns={8} text="暂无访问日志" />
            ) : (
              items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="px-2 py-2 whitespace-nowrap text-muted-foreground">
                    {formatDate(item.created_at)}
                  </TableCell>
                  <TableCell className="px-2 py-2">
                    <MethodBadge method={item.method} />
                  </TableCell>
                  <TableCell className="max-w-[260px] px-2 py-2">
                    <TruncatedCell
                      value={redactSensitiveText(item.path)}
                      mono
                    />
                  </TableCell>
                  <TableCell className="px-2 py-2">
                    <StatusBadge code={item.status_code} />
                  </TableCell>
                  <TableCell className="px-2 py-2">
                    <WAFActionBadge action={item.waf_action} />
                  </TableCell>
                  <TableCell className="max-w-[140px] px-2 py-2">
                    <TruncatedCell value={item.client_ip} mono />
                  </TableCell>
                  <TableCell className="max-w-[180px] px-2 py-2">
                    <TruncatedCell value={item.request_id} mono />
                  </TableCell>
                  <TableCell className="px-2 py-2 text-right">
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      disabled={loadingDetailId === item.id}
                      onClick={() => onOpenDetail(item)}
                      aria-label="查看访问日志详情"
                    >
                      <Eye data-icon="inline-start" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {!loading && total > OBSERVABILITY_PAGE_SIZE ? (
        <>
          <Separator />
          <div className="p-3">
            <Pagination
              page={page}
              totalPages={totalPages}
              total={total}
              pageSize={OBSERVABILITY_PAGE_SIZE}
              onPageChange={onPageChange}
            />
          </div>
        </>
      ) : null}
    </section>
  )
}

function AccessLogFilters({
  logId,
  requestId,
  clientIp,
  host,
  path,
  statusGroup,
  method,
  wafAction,
  cacheState,
  since,
  until,
  filtersActive,
  onLogIdChange,
  onRequestIdChange,
  onClientIpChange,
  onHostChange,
  onPathChange,
  onStatusGroupChange,
  onMethodChange,
  onWafActionChange,
  onCacheStateChange,
  onSinceChange,
  onUntilChange,
  onResetFilters,
}: {
  logId: string
  requestId: string
  clientIp: string
  host: string
  path: string
  statusGroup: string
  method: string
  wafAction: string
  cacheState: string
  since: string
  until: string
  filtersActive: boolean
  onLogIdChange: (value: string) => void
  onRequestIdChange: (value: string) => void
  onClientIpChange: (value: string) => void
  onHostChange: (value: string) => void
  onPathChange: (value: string) => void
  onStatusGroupChange: (value: string) => void
  onMethodChange: (value: string) => void
  onWafActionChange: (value: string) => void
  onCacheStateChange: (value: string) => void
  onSinceChange: (value: string) => void
  onUntilChange: (value: string) => void
  onResetFilters: () => void
}) {
  return (
    <div className="border-b bg-muted/20 px-4 py-3">
      <FieldGroup className="gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <SearchInput
            value={logId}
            onChange={onLogIdChange}
            placeholder="日志 ID"
            ariaLabel="访问日志 ID"
            className="w-[120px]"
          />
          <SearchInput
            value={requestId}
            onChange={onRequestIdChange}
            placeholder="Request ID"
            ariaLabel="访问日志 Request ID"
            className="w-[170px]"
          />
          <SearchInput
            value={clientIp}
            onChange={onClientIpChange}
            placeholder="客户端 IP"
            ariaLabel="访问日志客户端 IP"
            className="w-[150px]"
          />
          <SearchInput
            value={host}
            onChange={onHostChange}
            placeholder="Host"
            ariaLabel="访问日志 Host"
            className="w-[150px]"
          />
          <SearchInput
            value={path}
            onChange={onPathChange}
            placeholder="路径"
            ariaLabel="访问日志路径"
            className="w-[180px]"
          />
          <Select value={statusGroup} onValueChange={onStatusGroupChange}>
            <SelectTrigger className="w-[130px] rounded-lg">
              <SelectValue placeholder="状态码" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部状态码</SelectItem>
                <SelectItem value="2xx">2xx 成功</SelectItem>
                <SelectItem value="3xx">3xx 重定向</SelectItem>
                <SelectItem value="4xx">4xx 客户端错误</SelectItem>
                <SelectItem value="5xx">5xx 服务端错误</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={method} onValueChange={onMethodChange}>
            <SelectTrigger className="w-[110px] rounded-lg">
              <SelectValue placeholder="方法" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部方法</SelectItem>
                {HTTP_METHODS.map((item) => (
                  <SelectItem key={item} value={item}>
                    {item}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={wafAction} onValueChange={onWafActionChange}>
            <SelectTrigger className="w-[140px] rounded-lg">
              <SelectValue placeholder="WAF 动作" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部 WAF</SelectItem>
                {wafActionOptions.map((item) => (
                  <SelectItem key={item.value} value={item.value}>
                    {item.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={cacheState} onValueChange={onCacheStateChange}>
            <SelectTrigger className="w-[120px] rounded-lg">
              <SelectValue placeholder="缓存" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部缓存</SelectItem>
                <SelectItem value="hit">命中</SelectItem>
                <SelectItem value="miss">未命中</SelectItem>
                <SelectItem value="bypass">跳过</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="rounded-lg"
            disabled={!filtersActive}
            onClick={onResetFilters}
          >
            <RotateCcw data-icon="inline-start" />
            重置
          </Button>
        </div>
        <FieldGroup className="flex-row flex-wrap items-center gap-3">
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="site-access-since"
              className="text-xs font-normal text-muted-foreground"
            >
              开始时间
            </FieldLabel>
            <Input
              id="site-access-since"
              type="datetime-local"
              value={since}
              onChange={(event) => onSinceChange(event.target.value)}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="site-access-until"
              className="text-xs font-normal text-muted-foreground"
            >
              结束时间
            </FieldLabel>
            <Input
              id="site-access-until"
              type="datetime-local"
              value={until}
              onChange={(event) => onUntilChange(event.target.value)}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
        </FieldGroup>
      </FieldGroup>
    </div>
  )
}

function TimelineSection({
  items,
  loading,
}: {
  items: TimelineBucket[]
  loading: boolean
}) {
  const latest = items.slice(-12)
  const maxCount = Math.max(1, ...latest.map((item) => Number(item.count) || 0))

  return (
    <section className="min-w-0 rounded-md border p-4">
      <div className="mb-4 flex items-center gap-2">
        <BarChart3 className="text-muted-foreground" />
        <h3 className="text-sm font-semibold">安全事件时间线</h3>
      </div>
      {loading ? (
        <div className="flex flex-col gap-3">
          {Array.from({ length: 6 }).map((_, index) => (
            <Skeleton key={index} className="h-5 w-full" />
          ))}
        </div>
      ) : latest.length === 0 ? (
        <div className="rounded-md border border-dashed bg-muted/35 px-4 py-8 text-center text-sm text-muted-foreground">
          暂无时间线数据
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {latest.map((item) => {
            const count = Number(item.count) || 0
            const width = `${Math.max(4, Math.round((count / maxCount) * 100))}%`

            return (
              <div key={item.bucket} className="grid grid-cols-[96px_1fr_48px] items-center gap-3">
                <div className="truncate text-xs text-muted-foreground">
                  {formatDate(item.bucket)}
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary"
                    style={{ width }}
                  />
                </div>
                <div className="text-right font-mono text-xs">{count}</div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

function SecurityEventSection({
  items,
  total,
  page,
  loading,
  loadingDetailId,
  requestId,
  clientIp,
  path,
  action,
  phase,
  category,
  tlsSNI,
  tlsJA3Hash,
  tlsJA4,
  tlsVersion,
  tlsALPN,
  headerOrder,
  since,
  until,
  filtersActive,
  onRequestIdChange,
  onClientIpChange,
  onPathChange,
  onActionChange,
  onPhaseChange,
  onCategoryChange,
  onTLSSNIChange,
  onTLSJA3HashChange,
  onTLSJA4Change,
  onTLSVersionChange,
  onTLSALPNChange,
  onHeaderOrderChange,
  onSinceChange,
  onUntilChange,
  onPageChange,
  onResetFilters,
  onOpenDetail,
}: {
  items: SecurityEvent[]
  total: number
  page: number
  loading: boolean
  loadingDetailId: number | null
  requestId: string
  clientIp: string
  path: string
  action: string
  phase: string
  category: string
  tlsSNI: string
  tlsJA3Hash: string
  tlsJA4: string
  tlsVersion: string
  tlsALPN: string
  headerOrder: string
  since: string
  until: string
  filtersActive: boolean
  onRequestIdChange: (value: string) => void
  onClientIpChange: (value: string) => void
  onPathChange: (value: string) => void
  onActionChange: (value: string) => void
  onPhaseChange: (value: string) => void
  onCategoryChange: (value: string) => void
  onTLSSNIChange: (value: string) => void
  onTLSJA3HashChange: (value: string) => void
  onTLSJA4Change: (value: string) => void
  onTLSVersionChange: (value: string) => void
  onTLSALPNChange: (value: string) => void
  onHeaderOrderChange: (value: string) => void
  onSinceChange: (value: string) => void
  onUntilChange: (value: string) => void
  onPageChange: (page: number) => void
  onResetFilters: () => void
  onOpenDetail: (item: SecurityEvent) => void
}) {
  const totalPages = Math.max(
    1,
    Math.ceil(total / OBSERVABILITY_PAGE_SIZE)
  )

  return (
    <section className="min-w-0 rounded-md border">
      <SectionHeader
        icon={ShieldAlert}
        title={filtersActive ? "当前筛选安全事件" : "最新安全事件"}
        total={total}
        href="/security-events/"
      />
      <SecurityEventFilters
        requestId={requestId}
        clientIp={clientIp}
        path={path}
        action={action}
        phase={phase}
        category={category}
        tlsSNI={tlsSNI}
        tlsJA3Hash={tlsJA3Hash}
        tlsJA4={tlsJA4}
        tlsVersion={tlsVersion}
        tlsALPN={tlsALPN}
        headerOrder={headerOrder}
        since={since}
        until={until}
        filtersActive={filtersActive}
        onRequestIdChange={(value) => {
          onRequestIdChange(value)
          onPageChange(1)
        }}
        onClientIpChange={(value) => {
          onClientIpChange(value)
          onPageChange(1)
        }}
        onPathChange={(value) => {
          onPathChange(value)
          onPageChange(1)
        }}
        onActionChange={(value) => {
          onActionChange(value)
          onPageChange(1)
        }}
        onPhaseChange={(value) => {
          onPhaseChange(value)
          onPageChange(1)
        }}
        onCategoryChange={(value) => {
          onCategoryChange(value)
          onPageChange(1)
        }}
        onTLSSNIChange={(value) => {
          onTLSSNIChange(value)
          onPageChange(1)
        }}
        onTLSJA3HashChange={(value) => {
          onTLSJA3HashChange(value)
          onPageChange(1)
        }}
        onTLSJA4Change={(value) => {
          onTLSJA4Change(value)
          onPageChange(1)
        }}
        onTLSVersionChange={(value) => {
          onTLSVersionChange(value)
          onPageChange(1)
        }}
        onTLSALPNChange={(value) => {
          onTLSALPNChange(value)
          onPageChange(1)
        }}
        onHeaderOrderChange={(value) => {
          onHeaderOrderChange(value)
          onPageChange(1)
        }}
        onSinceChange={(value) => {
          onSinceChange(value)
          onPageChange(1)
        }}
        onUntilChange={(value) => {
          onUntilChange(value)
          onPageChange(1)
        }}
        onResetFilters={onResetFilters}
      />
      <div className="overflow-x-auto">
        <Table className="min-w-[760px] text-xs">
          <TableHeader className="bg-muted/35 text-muted-foreground">
            <TableRow>
              <TableHead className="px-2 py-2">时间</TableHead>
              <TableHead className="px-2 py-2">动作</TableHead>
              <TableHead className="px-2 py-2">分类</TableHead>
              <TableHead className="px-2 py-2">规则</TableHead>
              <TableHead className="px-2 py-2">路径</TableHead>
              <TableHead className="px-2 py-2">客户端</TableHead>
              <TableHead className="px-2 py-2 text-right">详情</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <SkeletonRows columns={7} rows={4} />
            ) : items.length === 0 ? (
              <EmptyRow columns={7} text="暂无安全事件" />
            ) : (
              items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="px-2 py-2 whitespace-nowrap text-muted-foreground">
                    {formatDate(item.created_at)}
                  </TableCell>
                  <TableCell className="px-2 py-2">
                    <WAFActionBadge action={item.action} />
                  </TableCell>
                  <TableCell className="max-w-[120px] px-2 py-2">
                    <TruncatedCell value={item.category} />
                  </TableCell>
                  <TableCell className="max-w-[140px] px-2 py-2">
                    <TruncatedCell
                      value={
                        item.rule_id_str ||
                        (item.rule_id ? String(item.rule_id) : "-")
                      }
                      mono
                    />
                  </TableCell>
                  <TableCell className="max-w-[220px] px-2 py-2">
                    <TruncatedCell
                      value={redactSensitiveText(item.path)}
                      mono
                    />
                  </TableCell>
                  <TableCell className="max-w-[140px] px-2 py-2">
                    <TruncatedCell value={item.client_ip} mono />
                  </TableCell>
                  <TableCell className="px-2 py-2 text-right">
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      disabled={loadingDetailId === item.id}
                      onClick={() => onOpenDetail(item)}
                      aria-label="查看安全事件详情"
                    >
                      <Eye data-icon="inline-start" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {!loading && total > OBSERVABILITY_PAGE_SIZE ? (
        <>
          <Separator />
          <div className="p-3">
            <Pagination
              page={page}
              totalPages={totalPages}
              total={total}
              pageSize={OBSERVABILITY_PAGE_SIZE}
              onPageChange={onPageChange}
            />
          </div>
        </>
      ) : null}
    </section>
  )
}

function SecurityEventFilters({
  requestId,
  clientIp,
  path,
  action,
  phase,
  category,
  tlsSNI,
  tlsJA3Hash,
  tlsJA4,
  tlsVersion,
  tlsALPN,
  headerOrder,
  since,
  until,
  filtersActive,
  onRequestIdChange,
  onClientIpChange,
  onPathChange,
  onActionChange,
  onPhaseChange,
  onCategoryChange,
  onTLSSNIChange,
  onTLSJA3HashChange,
  onTLSJA4Change,
  onTLSVersionChange,
  onTLSALPNChange,
  onHeaderOrderChange,
  onSinceChange,
  onUntilChange,
  onResetFilters,
}: {
  requestId: string
  clientIp: string
  path: string
  action: string
  phase: string
  category: string
  tlsSNI: string
  tlsJA3Hash: string
  tlsJA4: string
  tlsVersion: string
  tlsALPN: string
  headerOrder: string
  since: string
  until: string
  filtersActive: boolean
  onRequestIdChange: (value: string) => void
  onClientIpChange: (value: string) => void
  onPathChange: (value: string) => void
  onActionChange: (value: string) => void
  onPhaseChange: (value: string) => void
  onCategoryChange: (value: string) => void
  onTLSSNIChange: (value: string) => void
  onTLSJA3HashChange: (value: string) => void
  onTLSJA4Change: (value: string) => void
  onTLSVersionChange: (value: string) => void
  onTLSALPNChange: (value: string) => void
  onHeaderOrderChange: (value: string) => void
  onSinceChange: (value: string) => void
  onUntilChange: (value: string) => void
  onResetFilters: () => void
}) {
  return (
    <div className="border-b bg-muted/20 px-4 py-3">
      <FieldGroup className="gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <SearchInput
            value={requestId}
            onChange={onRequestIdChange}
            placeholder="Request ID"
            ariaLabel="安全事件 Request ID"
            className="w-[170px]"
          />
          <SearchInput
            value={clientIp}
            onChange={onClientIpChange}
            placeholder="客户端 IP"
            ariaLabel="安全事件客户端 IP"
            className="w-[150px]"
          />
          <SearchInput
            value={path}
            onChange={onPathChange}
            placeholder="路径"
            ariaLabel="安全事件路径"
            className="w-[170px]"
          />
          <Select value={action} onValueChange={onActionChange}>
            <SelectTrigger className="w-[140px] rounded-lg">
              <SelectValue placeholder="动作" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部动作</SelectItem>
                {wafActionOptions.map((item) => (
                  <SelectItem key={item.value} value={item.value}>
                    {item.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={phase} onValueChange={onPhaseChange}>
            <SelectTrigger className="w-[160px] rounded-lg">
              <SelectValue placeholder="阶段" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部阶段</SelectItem>
                {Object.entries(phaseLabels).map(([key, label]) => (
                  <SelectItem key={key} value={key}>
                    {label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={category} onValueChange={onCategoryChange}>
            <SelectTrigger className="w-[160px] rounded-lg">
              <SelectValue placeholder="类别" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部类别</SelectItem>
                {Object.entries(categoryLabels).map(([key, label]) => (
                  <SelectItem key={key} value={key}>
                    {label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <SearchInput
            value={tlsSNI}
            onChange={onTLSSNIChange}
            placeholder="TLS SNI"
            ariaLabel="安全事件 TLS SNI"
            className="w-[170px]"
          />
          <SearchInput
            value={tlsJA3Hash}
            onChange={onTLSJA3HashChange}
            placeholder="JA3 Hash"
            ariaLabel="安全事件 JA3 Hash"
            className="w-[190px]"
          />
          <SearchInput
            value={tlsJA4}
            onChange={onTLSJA4Change}
            placeholder="JA4"
            ariaLabel="安全事件 JA4"
            className="w-[170px]"
          />
          <SearchInput
            value={tlsVersion}
            onChange={onTLSVersionChange}
            placeholder="TLS 版本"
            ariaLabel="安全事件 TLS 版本"
            className="w-[130px]"
          />
          <SearchInput
            value={tlsALPN}
            onChange={onTLSALPNChange}
            placeholder="TLS ALPN"
            ariaLabel="安全事件 TLS ALPN"
            className="w-[140px]"
          />
          <SearchInput
            value={headerOrder}
            onChange={onHeaderOrderChange}
            placeholder="Header Order"
            ariaLabel="安全事件 Header Order"
            className="w-[170px]"
          />
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="rounded-lg"
            disabled={!filtersActive}
            onClick={onResetFilters}
          >
            <RotateCcw data-icon="inline-start" />
            重置
          </Button>
        </div>
        <FieldGroup className="flex-row flex-wrap items-center gap-3">
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="site-security-since"
              className="text-xs font-normal text-muted-foreground"
            >
              开始时间
            </FieldLabel>
            <Input
              id="site-security-since"
              type="datetime-local"
              value={since}
              onChange={(event) => onSinceChange(event.target.value)}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="site-security-until"
              className="text-xs font-normal text-muted-foreground"
            >
              结束时间
            </FieldLabel>
            <Input
              id="site-security-until"
              type="datetime-local"
              value={until}
              onChange={(event) => onUntilChange(event.target.value)}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
        </FieldGroup>
      </FieldGroup>
    </div>
  )
}

function DropEventSection({
  items,
  total,
  page,
  loading,
  clientIp,
  source,
  startTime,
  endTime,
  filtersActive,
  onClientIpChange,
  onSourceChange,
  onStartTimeChange,
  onEndTimeChange,
  onPageChange,
  onResetFilters,
  onOpenDetail,
}: {
  items: DropEvent[]
  total: number
  page: number
  loading: boolean
  clientIp: string
  source: string
  startTime: string
  endTime: string
  filtersActive: boolean
  onClientIpChange: (value: string) => void
  onSourceChange: (value: string) => void
  onStartTimeChange: (value: string) => void
  onEndTimeChange: (value: string) => void
  onPageChange: (page: number) => void
  onResetFilters: () => void
  onOpenDetail: (item: DropEvent) => void
}) {
  const totalPages = Math.max(
    1,
    Math.ceil(total / OBSERVABILITY_PAGE_SIZE)
  )

  return (
    <section className="min-w-0 rounded-md border">
      <SectionHeader
        icon={ShieldX}
        title={filtersActive ? "当前筛选丢弃事件" : "最新丢弃事件"}
        total={total}
        href="/drop-policy/"
      />
      <DropEventFilters
        clientIp={clientIp}
        source={source}
        startTime={startTime}
        endTime={endTime}
        filtersActive={filtersActive}
        onClientIpChange={(value) => {
          onClientIpChange(value)
          onPageChange(1)
        }}
        onSourceChange={(value) => {
          onSourceChange(value)
          onPageChange(1)
        }}
        onStartTimeChange={(value) => {
          onStartTimeChange(value)
          onPageChange(1)
        }}
        onEndTimeChange={(value) => {
          onEndTimeChange(value)
          onPageChange(1)
        }}
        onResetFilters={onResetFilters}
      />
      <div className="overflow-x-auto">
        <Table className="min-w-[720px] text-xs">
          <TableHeader className="bg-muted/35 text-muted-foreground">
            <TableRow>
              <TableHead className="px-2 py-2">时间</TableHead>
              <TableHead className="px-2 py-2">来源</TableHead>
              <TableHead className="px-2 py-2">规则</TableHead>
              <TableHead className="px-2 py-2">路径</TableHead>
              <TableHead className="px-2 py-2">客户端</TableHead>
              <TableHead className="px-2 py-2">详情</TableHead>
              <TableHead className="px-2 py-2 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <SkeletonRows columns={7} rows={4} />
            ) : items.length === 0 ? (
              <EmptyRow columns={7} text="暂无丢弃事件" />
            ) : (
              items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="px-2 py-2 whitespace-nowrap text-muted-foreground">
                    {formatDate(item.created_at)}
                  </TableCell>
                  <TableCell className="px-2 py-2">
                    <Badge variant="secondary" className="font-mono">
                      {item.source || "-"}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[120px] px-2 py-2">
                    <TruncatedCell value={item.rule_id} mono />
                  </TableCell>
                  <TableCell className="max-w-[180px] px-2 py-2">
                    <TruncatedCell
                      value={redactSensitiveText(item.path)}
                      mono
                    />
                  </TableCell>
                  <TableCell className="max-w-[140px] px-2 py-2">
                    <TruncatedCell value={item.client_ip} mono />
                  </TableCell>
                  <TableCell className="max-w-[180px] px-2 py-2">
                    <TruncatedCell value={redactSensitiveText(item.detail)} />
                  </TableCell>
                  <TableCell className="px-2 py-2 text-right">
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      onClick={() => onOpenDetail(item)}
                      aria-label="查看丢弃事件详情"
                    >
                      <Eye data-icon="inline-start" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {!loading && total > OBSERVABILITY_PAGE_SIZE ? (
        <>
          <Separator />
          <div className="p-3">
            <Pagination
              page={page}
              totalPages={totalPages}
              total={total}
              pageSize={OBSERVABILITY_PAGE_SIZE}
              onPageChange={onPageChange}
            />
          </div>
        </>
      ) : null}
    </section>
  )
}

function DropEventFilters({
  clientIp,
  source,
  startTime,
  endTime,
  filtersActive,
  onClientIpChange,
  onSourceChange,
  onStartTimeChange,
  onEndTimeChange,
  onResetFilters,
}: {
  clientIp: string
  source: string
  startTime: string
  endTime: string
  filtersActive: boolean
  onClientIpChange: (value: string) => void
  onSourceChange: (value: string) => void
  onStartTimeChange: (value: string) => void
  onEndTimeChange: (value: string) => void
  onResetFilters: () => void
}) {
  return (
    <div className="border-b bg-muted/20 px-4 py-3">
      <FieldGroup className="gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <SearchInput
            value={clientIp}
            onChange={onClientIpChange}
            placeholder="客户端 IP"
            ariaLabel="丢弃事件客户端 IP"
            className="w-[150px]"
          />
          <Select value={source} onValueChange={onSourceChange}>
            <SelectTrigger className="w-[140px] rounded-lg">
              <SelectValue placeholder="来源" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部来源</SelectItem>
                <SelectItem value="bot">Bot</SelectItem>
                <SelectItem value="cve">CVE</SelectItem>
                <SelectItem value="rule">规则</SelectItem>
                <SelectItem value="ip_reputation">IP 信誉</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="rounded-lg"
            disabled={!filtersActive}
            onClick={onResetFilters}
          >
            <RotateCcw data-icon="inline-start" />
            重置
          </Button>
        </div>
        <FieldGroup className="flex-row flex-wrap items-center gap-3">
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="site-drop-start-time"
              className="text-xs font-normal text-muted-foreground"
            >
              开始时间
            </FieldLabel>
            <Input
              id="site-drop-start-time"
              type="datetime-local"
              value={startTime}
              onChange={(event) => onStartTimeChange(event.target.value)}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="site-drop-end-time"
              className="text-xs font-normal text-muted-foreground"
            >
              结束时间
            </FieldLabel>
            <Input
              id="site-drop-end-time"
              type="datetime-local"
              value={endTime}
              onChange={(event) => onEndTimeChange(event.target.value)}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
        </FieldGroup>
      </FieldGroup>
    </div>
  )
}

function SearchInput({
  value,
  onChange,
  placeholder,
  ariaLabel,
  className,
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  ariaLabel: string
  className?: string
}) {
  return (
    <div className={cn("relative", className)}>
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel}
        className="rounded-lg pl-8"
      />
    </div>
  )
}

function AccessLogDetailDialog({
  item,
  requestTrace,
  traceLoading,
  onLoadRequestTrace,
  onOpenChange,
}: {
  item: AccessLog | null
  requestTrace: RequestTrace | null
  traceLoading: boolean
  onLoadRequestTrace: (requestId: string) => void
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Dialog open={!!item} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto rounded-lg">
        <DialogHeader>
          <DialogTitle>访问日志详情</DialogTitle>
          <DialogDescription>
            站点观测中打开的访问日志单条详情。
          </DialogDescription>
        </DialogHeader>
        {item && (
          <div className="grid gap-3 sm:grid-cols-2">
            <DetailField label="时间" value={formatDate(item.created_at)} />
            <DetailField
              label="Request ID"
              value={item.request_id || "-"}
              mono
              copyText={item.request_id}
            />
            <DetailField
              label="客户端 IP"
              value={item.client_ip || "-"}
              mono
              copyText={item.client_ip}
            />
            <DetailField label="Host" value={item.host || "-"} mono />
            <DetailField label="方法" value={<MethodBadge method={item.method} />} />
            <DetailField
              label="状态码"
              value={<StatusBadge code={item.status_code} />}
            />
            <DetailField
              label="WAF 动作"
              value={<WAFActionBadge action={item.waf_action} />}
            />
            <DetailField
              label="缓存状态"
              value={item.cache_state || "-"}
              mono
            />
            <DetailField
              label="上游"
              value={item.upstream || "-"}
              mono
              className="sm:col-span-2"
            />
            <RequestTracePanel
              requestId={item.request_id}
              trace={requestTrace}
              loading={traceLoading}
              onLoad={() => onLoadRequestTrace(item.request_id)}
            />
            <CopyableBlock
              label="路径"
              value={item.path || "-"}
              as="code"
              className="sm:col-span-2"
              redact
            />
            <CopyableBlock
              label="查询参数"
              value={item.query_string || "-"}
              as="code"
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
            <CopyableBlock
              label="User-Agent"
              value={item.user_agent || "-"}
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
            <CopyableBlock
              label="请求头"
              value={item.request_headers || "-"}
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
            <CopyableBlock
              label={
                item.request_body_truncated ? "请求体预览（已截断）" : "请求体预览"
              }
              value={item.request_body_preview || "-"}
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
            <CopyableBlock
              label="响应头"
              value={item.response_headers || "-"}
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function SecurityEventDetailDialog({
  item,
  requestTrace,
  traceLoading,
  onLoadRequestTrace,
  onOpenChange,
}: {
  item: SecurityEvent | null
  requestTrace: RequestTrace | null
  traceLoading: boolean
  onLoadRequestTrace: (requestId: string) => void
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Dialog open={!!item} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto rounded-lg">
        <DialogHeader>
          <DialogTitle>安全事件详情</DialogTitle>
          <DialogDescription>
            站点观测中打开的安全事件单条详情。
          </DialogDescription>
        </DialogHeader>
        {item && (
          <div className="grid gap-3 sm:grid-cols-2">
            <DetailField label="时间" value={formatDate(item.created_at)} />
            <DetailField
              label="Request ID"
              value={item.request_id || "-"}
              mono
              copyText={item.request_id}
            />
            <DetailField
              label="客户端 IP"
              value={item.client_ip || "-"}
              mono
              copyText={item.client_ip}
            />
            <DetailField label="Host" value={item.host || "-"} mono />
            <DetailField label="方法" value={item.method || "-"} mono />
            <DetailField
              label="动作"
              value={<WAFActionBadge action={item.action} />}
            />
            <DetailField label="阶段" value={item.phase || "-"} mono />
            <DetailField label="分类" value={item.category || "-"} mono />
            <DetailField
              label="历史规则 ID"
              value={item.rule_id_str || item.rule_id || "-"}
              mono
            />
            <DetailField
              label="状态码"
              value={item.status_code ? String(item.status_code) : "-"}
              mono
            />
            <DetailField
              label="TLS 版本"
              value={item.tls_version || "-"}
              mono
              copyText={item.tls_version || undefined}
            />
            <DetailField
              label="TLS SNI"
              value={item.tls_sni || "-"}
              mono
              copyText={item.tls_sni || undefined}
            />
            <DetailField
              label="TLS ALPN"
              value={item.tls_alpn || "-"}
              mono
              copyText={item.tls_alpn || undefined}
            />
            <DetailField
              label="JA3 Hash"
              value={item.tls_ja3_hash || "-"}
              mono
              copyText={item.tls_ja3_hash || undefined}
            />
            <DetailField
              label="JA4"
              value={item.tls_ja4 || "-"}
              mono
              copyText={item.tls_ja4 || undefined}
            />
            <RequestTracePanel
              requestId={item.request_id}
              trace={requestTrace}
              loading={traceLoading}
              onLoad={() => onLoadRequestTrace(item.request_id)}
            />
            <CopyableBlock
              label="路径"
              value={item.path || "-"}
              as="code"
              className="sm:col-span-2"
              redact
            />
            <CopyableBlock
              label="查询参数"
              value={item.query_string || "-"}
              as="code"
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
            <CopyableBlock
              label="匹配描述"
              value={item.match_desc || "-"}
              className="sm:col-span-2"
              redact
            />
            <CopyableBlock
              label="JA3"
              value={item.tls_ja3 || "-"}
              as="code"
              className="sm:col-span-2"
              defaultOpen={false}
            />
            <CopyableBlock
              label="Header Order"
              value={item.header_order || "-"}
              as="code"
              className="sm:col-span-2"
              defaultOpen={false}
            />
            <CopyableBlock
              label="User-Agent"
              value={item.user_agent || "-"}
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
            <CopyableBlock
              label="请求头"
              value={item.request_headers || "-"}
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
            <CopyableBlock
              label={
                item.request_body_truncated ? "请求体预览（已截断）" : "请求体预览"
              }
              value={item.request_body_preview || "-"}
              className="sm:col-span-2"
              redact
              defaultOpen={false}
            />
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function DropEventDetailDialog({
  item,
  onOpenChange,
}: {
  item: DropEvent | null
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Dialog open={!!item} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto rounded-lg">
        <DialogHeader>
          <DialogTitle>丢弃事件详情</DialogTitle>
          <DialogDescription>
            站点观测中打开的 drop_events 记录详情。
          </DialogDescription>
        </DialogHeader>
        {item && (
          <div className="grid gap-3 sm:grid-cols-2">
            <DetailField label="时间" value={formatDate(item.created_at)} />
            <DetailField
              label="站点 ID"
              value={item.site_id ? String(item.site_id) : "-"}
              mono
            />
            <DetailField
              label="客户端 IP"
              value={item.client_ip || "-"}
              mono
              copyText={item.client_ip}
            />
            <DetailField label="Host" value={item.host || "-"} mono />
            <DetailField label="来源" value={item.source || "-"} mono />
            <DetailField
              label="历史规则 ID"
              value={item.rule_id || "-"}
              mono
            />
            <CopyableBlock
              label="路径"
              value={item.path || "-"}
              as="code"
              className="sm:col-span-2"
              redact
            />
            <CopyableBlock
              label="详情"
              value={item.detail || "-"}
              className="sm:col-span-2"
              redact
            />
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function RulesSection({
  items,
  total,
  policyId,
  loading,
}: {
  items: Rule[]
  total: number
  policyId: number | null
  loading: boolean
}) {
  return (
    <section className="min-w-0 rounded-md border">
      <SectionHeader
        icon={ListChecks}
        title="当前策略规则"
        total={total}
        href="/rules/"
      />
      <div className="overflow-x-auto">
        <Table className="min-w-[860px] text-xs">
          <TableHeader className="bg-muted/35 text-muted-foreground">
            <TableRow>
              <TableHead className="px-2 py-2">状态</TableHead>
              <TableHead className="px-2 py-2">名称</TableHead>
              <TableHead className="px-2 py-2">阶段</TableHead>
              <TableHead className="px-2 py-2">动作</TableHead>
              <TableHead className="px-2 py-2">优先级</TableHead>
              <TableHead className="px-2 py-2">模式</TableHead>
              <TableHead className="px-2 py-2">策略</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <SkeletonRows columns={7} rows={4} />
            ) : items.length === 0 ? (
              <EmptyRow
                columns={7}
                text={
                  policyId === null ? "当前站点未绑定策略" : "当前策略暂无规则"
                }
              />
            ) : (
              items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="px-2 py-2">
                    <Badge
                      variant={item.enabled ? "secondary" : "outline"}
                      className="font-mono"
                    >
                      {item.enabled ? "启用" : "停用"}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[180px] px-2 py-2">
                    <TruncatedCell value={item.name} />
                  </TableCell>
                  <TableCell className="max-w-[140px] px-2 py-2">
                    <TruncatedCell value={item.phase} mono />
                  </TableCell>
                  <TableCell className="px-2 py-2">
                    <WAFActionBadge action={item.action} />
                  </TableCell>
                  <TableCell className="px-2 py-2 font-mono">
                    {item.priority}
                  </TableCell>
                  <TableCell className="max-w-[260px] px-2 py-2">
                    <TruncatedCell value={item.pattern} mono />
                  </TableCell>
                  <TableCell className="px-2 py-2 font-mono">
                    {item.policy_id}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </section>
  )
}

function SectionHeader({
  icon: Icon,
  title,
  total,
  href,
}: {
  icon: typeof Activity
  title: string
  total: number
  href: string
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3">
      <div className="flex min-w-0 items-center gap-2">
        <Icon className="text-muted-foreground" />
        <h3 className="truncate text-sm font-semibold">{title}</h3>
        <Badge variant="outline" className="font-mono">
          {total.toLocaleString()}
        </Badge>
      </div>
      <Button asChild type="button" variant="ghost" size="xs">
        <Link href={href}>打开全局页</Link>
      </Button>
    </div>
  )
}

function MethodBadge({ method }: { method: string }) {
  const variant =
    method === "DELETE"
      ? "destructive"
      : method === "POST" || method === "PUT" || method === "PATCH"
        ? "secondary"
        : "outline"

  return (
    <Badge
      variant={variant}
      className="font-mono text-[11px]"
    >
      {method || "-"}
    </Badge>
  )
}

function StatusBadge({ code }: { code: number }) {
  const variant =
    code >= 500 ? "destructive" : code >= 400 ? "secondary" : "outline"

  return (
    <Badge variant={variant} className="font-mono">
      {code || "-"}
    </Badge>
  )
}

function SkeletonRows({
  columns,
  rows,
}: {
  columns: number
  rows: number
}) {
  return (
    <>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <TableRow key={rowIndex}>
          {Array.from({ length: columns }).map((__, columnIndex) => (
            <TableCell key={columnIndex} className="px-2 py-3">
              <Skeleton
                className={cn(
                  "h-4",
                  columnIndex === 0 ? "w-24" : "w-full"
                )}
              />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  )
}

function EmptyRow({ columns, text }: { columns: number; text: string }) {
  return (
    <TableRow>
      <TableCell
        colSpan={columns}
        className="px-3 py-8 text-center text-muted-foreground"
      >
        {text}
      </TableCell>
    </TableRow>
  )
}
