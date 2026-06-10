"use client"

import { useCallback, useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import { Download, Eye, RefreshCcw, Search } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Pagination } from "@/components/pagination"
import {
  EmptyState,
  MetricCard,
  MetricGrid,
  PageIntro,
  Surface,
} from "@/components/console-shell"
import { AttackHeatmap } from "@/components/charts/attack-heatmap"
import {
  CopyableBlock,
  DetailField,
  redactSensitiveText,
  TruncatedCell,
  WAFActionBadge,
} from "@/components/log-presentation"
import { RequestTracePanel } from "@/components/request-trace-panel"
import {
  getRequestTrace,
  getSecurityEvent,
  getSecurityEventStats,
  getSecurityEvents,
  getSecurityTimeline,
  type RequestTrace,
  type SecurityEvent,
  type SecurityEventQuery,
  type SecurityStats,
  type TimelineBucket,
} from "@/lib/api"
import { useAdminRealtime } from "@/lib/admin-realtime"
import {
  getWAFActionMeta,
  wafActionOptions,
  phaseLabels,
  categoryLabels,
} from "@/lib/console"
import { downloadCSV, toCSV } from "@/lib/download"
import { formatBytes, formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

function dateTimeLocalFromSearchParams(
  searchParams: URLSearchParams,
  key: string
) {
  const value = searchParams.get(key)
  if (!value) return ""
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ""
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate()
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function exportCSV(events: SecurityEvent[]) {
  const headers = [
    "ID",
    "时间",
    "Request ID",
    "源 IP",
    "Host",
    "方法",
    "路径",
    "动作",
    "阶段",
    "类别",
    "TLS 版本",
    "TLS SNI",
    "JA3 Hash",
    "JA4",
    "历史规则",
    "匹配描述",
  ]
  const rows = events.map((e) => [
    e.id,
    formatDate(e.created_at),
    e.request_id,
    e.client_ip,
    e.host,
    e.method,
    redactSensitiveText(e.path),
    getWAFActionMeta(e.action).label,
    phaseLabels[e.phase] ?? e.phase,
    categoryLabels[e.category] ?? e.category,
    e.tls_version || "",
    e.tls_sni || "",
    e.tls_ja3_hash || "",
    e.tls_ja4 || "",
    e.rule_id_str || e.rule_id,
    redactSensitiveText(e.match_desc),
  ])
  downloadCSV(toCSV(headers, rows), "security-events")
}

export default function SecurityEventsPage() {
  const searchParams = useSearchParams()
  const realtime = useAdminRealtime()
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [stats, setStats] = useState<SecurityStats | null>(null)
  const [timeline, setTimeline] = useState<TimelineBucket[]>([])
  const [selected, setSelected] = useState<SecurityEvent | null>(null)
  const [requestTrace, setRequestTrace] = useState<RequestTrace | null>(null)
  const [traceLoading, setTraceLoading] = useState(false)
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [idSearch, setIdSearch] = useState(() => searchParams.get("id") ?? "")
  const [requestIDSearch, setRequestIDSearch] = useState(
    () => searchParams.get("request_id") ?? ""
  )
  const [action, setAction] = useState(
    () => searchParams.get("action") ?? "all"
  )
  const [phase, setPhase] = useState(
    () => searchParams.get("phase") ?? "all"
  )
  const [category, setCategory] = useState(
    () => searchParams.get("category") ?? "all"
  )
  const [clientIP, setClientIP] = useState(
    () => searchParams.get("client_ip") ?? ""
  )
  const [ruleIdStr, setRuleIdStr] = useState(
    () => searchParams.get("rule_id_str") ?? ""
  )
  const [ruleId, setRuleId] = useState(() => searchParams.get("rule_id") ?? "")
  const [hostSearch, setHostSearch] = useState(
    () => searchParams.get("host") ?? ""
  )
  const [pathSearch, setPathSearch] = useState(
    () => searchParams.get("path") ?? ""
  )
  const [tlsSNI, setTLSSNI] = useState(
    () => searchParams.get("tls_sni") ?? ""
  )
  const [tlsJA3Hash, setTLSJA3Hash] = useState(
    () => searchParams.get("tls_ja3_hash") ?? ""
  )
  const [tlsJA4, setTLSJA4] = useState(
    () => searchParams.get("tls_ja4") ?? ""
  )
  const [tlsVersion, setTLSVersion] = useState(
    () => searchParams.get("tls_version") ?? ""
  )
  const [tlsALPN, setTLSALPN] = useState(
    () => searchParams.get("tls_alpn") ?? ""
  )
  const [headerOrder, setHeaderOrder] = useState(
    () => searchParams.get("header_order") ?? ""
  )
  const [sinceFilter, setSinceFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "since")
  )
  const [untilFilter, setUntilFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "until")
  )
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const query: SecurityEventQuery = {
        page,
        page_size: PAGE_SIZE,
        id: idSearch || undefined,
        request_id: requestIDSearch || undefined,
        action: action === "all" ? undefined : action,
        phase: phase === "all" ? undefined : phase,
        category: category === "all" ? undefined : category,
        client_ip: clientIP || undefined,
        rule_id: ruleId || undefined,
        rule_id_str: ruleIdStr || undefined,
        host: hostSearch || undefined,
        path: pathSearch || undefined,
        tls_sni: tlsSNI || undefined,
        tls_ja3_hash: tlsJA3Hash || undefined,
        tls_ja4: tlsJA4 || undefined,
        tls_version: tlsVersion || undefined,
        tls_alpn: tlsALPN || undefined,
        header_order: headerOrder || undefined,
        since: sinceFilter ? new Date(sinceFilter).toISOString() : undefined,
        until: untilFilter ? new Date(untilFilter).toISOString() : undefined,
      }
      const [eventRes, statsRes, timelineRes] = await Promise.all([
        getSecurityEvents(query),
        getSecurityEventStats(24),
        getSecurityTimeline(24),
      ])
      setEvents(eventRes.items ?? [])
      setTotal(eventRes.total ?? 0)
      setStats(statsRes)
      setTimeline(timelineRes.buckets ?? [])
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败")
      setEvents([])
      setTotal(0)
      setStats(null)
      setTimeline([])
    } finally {
      setLoading(false)
    }
  }, [
    idSearch,
    requestIDSearch,
    action,
    phase,
    category,
    clientIP,
    ruleId,
    ruleIdStr,
    hostSearch,
    pathSearch,
    tlsSNI,
    tlsJA3Hash,
    tlsJA4,
    tlsVersion,
    tlsALPN,
    headerOrder,
    sinceFilter,
    untilFilter,
    page,
  ])

  function resetFilters() {
    setIdSearch("")
    setRequestIDSearch("")
    setAction("all")
    setPhase("all")
    setCategory("all")
    setClientIP("")
    setRuleId("")
    setRuleIdStr("")
    setHostSearch("")
    setPathSearch("")
    setTLSSNI("")
    setTLSJA3Hash("")
    setTLSJA4("")
    setTLSVersion("")
    setTLSALPN("")
    setHeaderOrder("")
    setSinceFilter("")
    setUntilFilter("")
    setPage(1)
  }

  async function openDetail(item: SecurityEvent) {
    setSelected(item)
    setRequestTrace(null)
    try {
      const detail = await getSecurityEvent(item.id)
      setSelected((current) => (current?.id === item.id ? detail : current))
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载事件详情失败")
    }
  }

  function closeDetail(open: boolean) {
    if (open) return
    setSelected(null)
    setRequestTrace(null)
  }

  async function loadRequestTrace() {
    if (!selected?.request_id) return
    setTraceLoading(true)
    try {
      setRequestTrace(await getRequestTrace(selected.request_id))
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载请求追踪失败")
    } finally {
      setTraceLoading(false)
    }
  }

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  const hasFilters = Boolean(
    idSearch ||
      requestIDSearch ||
      action !== "all" ||
      phase !== "all" ||
      category !== "all" ||
      clientIP ||
    ruleId ||
    ruleIdStr ||
    hostSearch ||
    pathSearch ||
    tlsSNI ||
    tlsJA3Hash ||
    tlsJA4 ||
    tlsVersion ||
    tlsALPN ||
    headerOrder ||
    sinceFilter ||
    untilFilter
  )
  const realtimeSecurityEvents =
    page === 1 && !hasFilters ? realtime.securityEvents : null
  const visibleEvents = realtimeSecurityEvents?.items ?? events
  const visibleTotal = realtimeSecurityEvents?.total ?? total
  const visibleLoading = loading && !realtimeSecurityEvents
  const totalPages = Math.max(1, Math.ceil(visibleTotal / PAGE_SIZE))
  const timelineData = timeline.map((item) => ({
    hour: formatDate(item.bucket),
    count: Number(item.count) || 0,
  }))

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Security Events"
        title="安全事件"
        description="检索拦截、验证、限速与观察事件，分析攻击来源和热点。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={load}>
              <RefreshCcw data-icon="inline-start" /> 刷新
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportCSV(visibleEvents)}
              disabled={visibleEvents.length === 0}
            >
              <Download data-icon="inline-start" /> 导出当前页 CSV
            </Button>
          </>
        }
      />

      <MetricGrid>
        <MetricCard
          label="总事件数"
          value={stats ? stats.total.toLocaleString() : "--"}
          hint="近 24 小时"
        />
        <MetricCard
          label="终止事件"
          value={stats ? stats.intercepts.toLocaleString() : "--"}
          tone="danger"
          hint="近 24 小时"
        />
        <MetricCard
          label="验证事件"
          value={stats ? stats.challenges.toLocaleString() : "--"}
          tone="warning"
          hint="近 24 小时 challenge 动作"
        />
        <MetricCard
          label="独立请求"
          value={stats ? stats.requests.toLocaleString() : "--"}
          hint="近 24 小时去重 Request ID"
        />
      </MetricGrid>

      <Surface
        title="近 24 小时安全事件时间线"
        description="来自后端全局时间线聚合接口，不受下方当前筛选条件影响。"
      >
        {loading ? (
          <div className="flex h-[220px] items-center justify-center rounded-lg border border-dashed text-sm text-muted-foreground">
            正在加载时间线
          </div>
        ) : timelineData.length === 0 ? (
          <EmptyState
            title="暂无时间线数据"
            description="近 24 小时没有安全事件聚合记录。"
          />
        ) : (
          <AttackHeatmap data={timelineData} height={220} />
        )}
      </Surface>

      <Surface
        title="筛选条件"
        description="动作、阶段、类别、规则、时间和请求字段会共同参与后端分页查询，导出仅包含当前页结果。"
      >
        <div className="flex flex-col gap-3">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={idSearch}
              onChange={(e) => {
                setIdSearch(e.target.value)
                setPage(1)
              }}
              placeholder="事件 ID"
              className="w-[120px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={requestIDSearch}
              onChange={(e) => {
                setRequestIDSearch(e.target.value)
                setPage(1)
              }}
              placeholder="Request ID"
              className="w-[180px] rounded-lg pl-8"
            />
          </div>
          <Select
            value={action}
            onValueChange={(v) => {
              setAction(v)
              setPage(1)
            }}
          >
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
          <Select
            value={category}
            onValueChange={(v) => {
              setCategory(v)
              setPage(1)
            }}
          >
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
          <Select
            value={phase}
            onValueChange={(v) => {
              setPhase(v)
              setPage(1)
            }}
          >
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
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={clientIP}
              onChange={(e) => {
                setClientIP(e.target.value)
                setPage(1)
              }}
              placeholder="搜索 IP"
              className="w-[160px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={ruleId}
              onChange={(e) => {
                setRuleId(e.target.value)
                setPage(1)
              }}
              placeholder="规则 ID"
              className="w-[120px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={hostSearch}
              onChange={(e) => {
                setHostSearch(e.target.value)
                setPage(1)
              }}
              placeholder="搜索 Host（支持站点首个 Host 跳转）"
              className="w-[160px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={pathSearch}
              onChange={(e) => {
                setPathSearch(e.target.value)
                setPage(1)
              }}
              placeholder="搜索路径"
              className="w-[160px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={ruleIdStr}
              onChange={(e) => {
                setRuleIdStr(e.target.value)
                setPage(1)
              }}
              placeholder="历史规则 ID"
              className="w-[140px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={tlsSNI}
              onChange={(e) => {
                setTLSSNI(e.target.value)
                setPage(1)
              }}
              placeholder="TLS SNI"
              className="w-[170px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={tlsJA3Hash}
              onChange={(e) => {
                setTLSJA3Hash(e.target.value)
                setPage(1)
              }}
              placeholder="JA3 Hash"
              className="w-[190px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={tlsJA4}
              onChange={(e) => {
                setTLSJA4(e.target.value)
                setPage(1)
              }}
              placeholder="JA4"
              className="w-[170px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={tlsVersion}
              onChange={(e) => {
                setTLSVersion(e.target.value)
                setPage(1)
              }}
              placeholder="TLS 版本"
              className="w-[130px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={tlsALPN}
              onChange={(e) => {
                setTLSALPN(e.target.value)
                setPage(1)
              }}
              placeholder="TLS ALPN"
              className="w-[140px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={headerOrder}
              onChange={(e) => {
                setHeaderOrder(e.target.value)
                setPage(1)
              }}
              placeholder="Header Order"
              className="w-[170px] rounded-lg pl-8"
            />
          </div>
        </div>
        <FieldGroup className="flex-row flex-wrap items-center gap-3">
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="security-events-since"
              className="text-xs font-normal text-muted-foreground"
            >
              开始时间
            </FieldLabel>
            <Input
              id="security-events-since"
              type="datetime-local"
              value={sinceFilter}
              onChange={(e) => {
                setSinceFilter(e.target.value)
                setPage(1)
              }}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="security-events-until"
              className="text-xs font-normal text-muted-foreground"
            >
              结束时间
            </FieldLabel>
            <Input
              id="security-events-until"
              type="datetime-local"
              value={untilFilter}
              onChange={(e) => {
                setUntilFilter(e.target.value)
                setPage(1)
              }}
              className="w-[190px] rounded-lg text-xs"
            />
          </Field>
          <Button variant="ghost" size="sm" onClick={resetFilters}>
            重置筛选
          </Button>
        </FieldGroup>
      </Surface>

      {/* Events table */}
      <Surface
        title="安全事件列表"
        description={`当前筛选命中 ${visibleTotal} 条，详情中的请求头和请求体按脱敏与截断策略展示。${realtimeSecurityEvents ? " 当前显示实时快照第一页。" : ""}`}
      >
        {visibleLoading ? (
          <div className="p-16 text-center text-sm text-muted-foreground">
            加载中...
          </div>
        ) : visibleEvents.length === 0 ? (
          <EmptyState
            title="当前筛选条件下本页没有安全事件"
            description="调整动作、阶段、类别、规则、时间、Host、路径、源 IP 或历史规则 ID 后重新查看。"
          />
        ) : (
          <>
            <div className="overscroll-x-contain">
              <Table className="min-w-[1180px] table-fixed">
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground hover:bg-muted/45">
                    <TableHead className="w-[150px] px-4 py-3 text-muted-foreground">
                      时间
                    </TableHead>
                    <TableHead className="w-[90px] px-4 py-3 text-muted-foreground">
                      动作
                    </TableHead>
                    <TableHead className="w-[130px] px-4 py-3 text-muted-foreground">
                      类别
                    </TableHead>
                    <TableHead className="w-[80px] px-4 py-3 text-muted-foreground">
                      方法
                    </TableHead>
                    <TableHead className="w-[160px] px-4 py-3 text-muted-foreground">
                      Host
                    </TableHead>
                    <TableHead className="w-[90px] px-4 py-3 text-muted-foreground">
                      状态码
                    </TableHead>
                    <TableHead className="w-[150px] px-4 py-3 text-muted-foreground">
                      源 IP
                    </TableHead>
                    <TableHead className="w-[260px] px-4 py-3 text-muted-foreground">
                      请求路径
                    </TableHead>
                    <TableHead className="w-[210px] px-4 py-3 text-muted-foreground">
                      匹配描述
                    </TableHead>
                    <TableHead className="w-[80px] px-4 py-3 text-right text-muted-foreground">
                      详情
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleEvents.map((evt) => (
                    <TableRow key={evt.id}>
                      <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(evt.created_at)}
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <WAFActionBadge action={evt.action} />
                      </TableCell>
                      <TableCell className="px-4 py-3 text-xs text-foreground">
                        {categoryLabels[evt.category] ?? evt.category}
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-[11px] text-muted-foreground">
                        {evt.method || "-"}
                      </TableCell>
                      <TableCell className="min-w-0 px-4 py-3 text-xs text-muted-foreground">
                        <TruncatedCell value={evt.host} />
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-xs text-foreground">
                        {evt.action === "drop" || evt.status_code === 0
                          ? "DROP"
                          : evt.status_code || "—"}
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-xs text-foreground">
                        {evt.client_ip}
                      </TableCell>
                      <TableCell className="min-w-0 px-4 py-3 text-xs text-muted-foreground">
                        <TruncatedCell value={redactSensitiveText(evt.path)} mono />
                      </TableCell>
                      <TableCell className="min-w-0 px-4 py-3 text-xs text-muted-foreground">
                        <TruncatedCell
                          value={redactSensitiveText(evt.match_desc)}
                        />
                      </TableCell>
                      <TableCell className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openDetail(evt)}
                        >
                          <Eye data-icon="inline-start" /> 详情
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Separator />
            <div className="p-3">
              <Pagination
                page={page}
                totalPages={totalPages}
                total={visibleTotal}
                pageSize={PAGE_SIZE}
                onPageChange={setPage}
              />
            </div>
          </>
        )}
      </Surface>

      {/* Detail Dialog */}
      <Dialog open={!!selected} onOpenChange={closeDetail}>
        <DialogContent className="max-h-[86vh] max-w-3xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>事件详情</DialogTitle>
            <DialogDescription>
              完整的安全事件信息；规则字段为事件产生时记录的历史命中值，关联规则可能已被修改或删除。
            </DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["Request ID", selected.request_id || "-", true, true],
                ["时间", formatDate(selected.created_at), false, false],
                ["客户端 IP", selected.client_ip, true, true],
                ["Host", selected.host || "-", true, true],
                ["方法", selected.method, true, true],
                [
                  "阶段",
                  phaseLabels[selected.phase] ?? selected.phase,
                  false,
                  false,
                ],
                [
                  "类别",
                  categoryLabels[selected.category] ?? selected.category,
                  false,
                  false,
                ],
                ["动作", getWAFActionMeta(selected.action).label, false, false],
                [
                  "历史规则",
                  selected.rule_id_str || String(selected.rule_id),
                  true,
                  true,
                ],
                ["状态码", String(selected.status_code), true, true],
                ["TLS 版本", selected.tls_version || "-", true, true],
                ["TLS SNI", selected.tls_sni || "-", true, true],
                ["TLS ALPN", selected.tls_alpn || "-", true, true],
                ["JA3 Hash", selected.tls_ja3_hash || "-", true, true],
                ["JA4", selected.tls_ja4 || "-", true, true],
                ["Header Order", selected.header_order || "-", true, true],
                [
                  "请求大小",
                  formatBytes(selected.request_size ?? 0),
                  true,
                  false,
                ],
                ["国家", selected.geo_country || "-", false, false],
                ["城市", selected.geo_city || "-", false, false],
              ].map(([label, value, mono, copyable]) => (
                <DetailField
                  key={String(label)}
                  label={String(label)}
                  value={String(value)}
                  mono={Boolean(mono)}
                  copyText={copyable ? String(value) : undefined}
                />
              ))}
              <RequestTracePanel
                requestId={selected.request_id}
                trace={requestTrace}
                loading={traceLoading}
                onLoad={loadRequestTrace}
              />
              <CopyableBlock
                label="路径"
                value={selected.path}
                as="code"
                className="sm:col-span-2"
                contentClassName="max-h-32 overflow-auto text-xs break-all text-foreground"
                redact
              />
              <CopyableBlock
                label="匹配描述"
                value={selected.match_desc || "-"}
                as="div"
                className="sm:col-span-2"
                contentClassName="text-sm break-all text-foreground"
                redact
              />
              {selected.query_string && (
                <CopyableBlock
                  label="查询参数"
                  value={selected.query_string}
                  as="code"
                  className="sm:col-span-2"
                  contentClassName="max-h-32 overflow-auto text-xs break-all text-foreground"
                  redact
                />
              )}
              <CopyableBlock
                label="Request Headers"
                value={selected.request_headers || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <div className="rounded-lg border bg-muted/35 p-3 sm:col-span-2">
                <CopyableBlock
                  label="Request Body Preview"
                  value={selected.request_body_preview || "-"}
                  className="border-0 bg-transparent p-0"
                  contentClassName="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-background p-2 text-xs text-foreground"
                  redact
                  defaultOpen={false}
                />
                {selected.request_body_truncated && (
                  <div className="mt-2 text-xs text-muted-foreground">
                    请求体已截断显示
                  </div>
                )}
              </div>
              <CopyableBlock
                label="JA3"
                value={selected.tls_ja3 || "-"}
                as="code"
                className="sm:col-span-2"
                contentClassName="max-h-32 overflow-auto text-xs break-all text-foreground"
              />
              <CopyableBlock
                label="User-Agent"
                value={selected.user_agent || "-"}
                as="div"
                className="sm:col-span-2"
                contentClassName="text-xs break-all text-muted-foreground"
                redact
              />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
