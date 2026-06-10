"use client"

import { useCallback, useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import { Download, Eye, RefreshCcw, Search } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
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
import { Pagination } from "@/components/pagination"
import { EmptyState, PageIntro, Surface } from "@/components/console-shell"
import {
  CopyableBlock,
  DetailField,
  redactSensitiveText,
  TruncatedCell,
  WAFActionBadge,
} from "@/components/log-presentation"
import { RequestTracePanel } from "@/components/request-trace-panel"
import {
  getAccessLog,
  getAccessLogs,
  getRequestTrace,
  type AccessLog,
  type AccessLogQuery,
  type RequestTrace,
} from "@/lib/api"
import { useAdminRealtime } from "@/lib/admin-realtime"
import { getWAFActionMeta, wafActionOptions } from "@/lib/console"
import { downloadCSV, toCSV } from "@/lib/download"
import { formatBytes, formatDate, formatLatency } from "@/lib/utils"

const PAGE_SIZE = 20

const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
]

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

function StatusBadge({ code }: { code: number }) {
  let variant: "outline" | "secondary" | "destructive" = "outline"
  if (code >= 500) variant = "destructive"
  else if (code >= 400) variant = "secondary"

  return (
    <Badge variant={variant} className="font-mono">
      {code}
    </Badge>
  )
}

function MethodBadge({ method }: { method: string }) {
  let variant: "outline" | "secondary" | "destructive" = "outline"
  if (method === "DELETE") variant = "destructive"
  else if (method === "POST" || method === "PUT" || method === "PATCH")
    variant = "secondary"

  return (
    <Badge variant={variant} className="font-mono text-[11px]">
      {method}
    </Badge>
  )
}

function exportCSV(items: AccessLog[]) {
  const headers = [
    "ID",
    "站点 ID",
    "时间",
    "Request ID",
    "Host",
    "源 IP",
    "方法",
    "路径",
    "查询参数",
    "状态码",
    "当时 WAF 动作",
    "缓存状态",
    "上游",
    "HTTP协议",
    "TLS版本",
    "TLS SNI",
    "TLS ALPN",
    "JA3",
    "JA3 Hash",
    "JA4",
    "Header Order",
    "上游耗时(ms)",
    "响应大小",
    "User-Agent",
  ]
  const rows = items.map((i) => [
    i.id,
    i.site_id,
    formatDate(i.created_at),
    i.request_id,
    i.host,
    i.client_ip,
    i.method,
    redactSensitiveText(i.path),
    redactSensitiveText(i.query_string),
    i.status_code,
    i.waf_action,
    i.cache_state,
    i.upstream,
    i.http_protocol,
    i.tls_version,
    i.tls_sni,
    i.tls_alpn,
    i.tls_ja3,
    i.tls_ja3_hash,
    i.tls_ja4,
    i.header_order,
    i.upstream_latency_ms,
    i.response_size,
    redactSensitiveText(i.user_agent),
  ])
  downloadCSV(toCSV(headers, rows), "access-logs")
}

export default function AccessLogsPage() {
  const searchParams = useSearchParams()
  const realtime = useAdminRealtime()
  const [items, setItems] = useState<AccessLog[]>([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState<AccessLog | null>(null)
  const [requestTrace, setRequestTrace] = useState<RequestTrace | null>(null)
  const [traceLoading, setTraceLoading] = useState(false)

  // Filters
  const [idSearch, setIdSearch] = useState(() => searchParams.get("id") ?? "")
  const [siteIDSearch, setSiteIDSearch] = useState(
    () => searchParams.get("site_id") ?? ""
  )
  const [requestIDSearch, setRequestIDSearch] = useState(
    () => searchParams.get("request_id") ?? ""
  )
  const [pathSearch, setPathSearch] = useState(
    () => searchParams.get("path") ?? ""
  )
  const [hostSearch, setHostSearch] = useState(
    () => searchParams.get("host") ?? ""
  )
  const [clientIP, setClientIP] = useState(
    () => searchParams.get("client_ip") ?? ""
  )
  const [statusFilter, setStatusFilter] = useState(
    () => searchParams.get("status_group") ?? "all"
  )
  const [methodFilter, setMethodFilter] = useState(
    () => searchParams.get("method") ?? "all"
  )
  const [wafActionFilter, setWafActionFilter] = useState(
    () => searchParams.get("waf_action") ?? "all"
  )
  const [cacheFilter, setCacheFilter] = useState(
    () => searchParams.get("cache_state") ?? "all"
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
  const [sinceFilter, setSinceFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "since")
  )
  const [untilFilter, setUntilFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "until")
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: AccessLogQuery = {
        page,
        page_size: PAGE_SIZE,
      }
      if (idSearch) params.id = idSearch
      if (siteIDSearch) params.site_id = siteIDSearch
      if (requestIDSearch) params.request_id = requestIDSearch
      if (pathSearch) params.path = pathSearch
      if (hostSearch) params.host = hostSearch
      if (clientIP) params.client_ip = clientIP
      if (statusFilter !== "all") params.status_group = statusFilter
      if (methodFilter !== "all") params.method = methodFilter
      if (wafActionFilter !== "all") params.waf_action = wafActionFilter
      if (cacheFilter !== "all") params.cache_state = cacheFilter
      if (tlsSNI) params.tls_sni = tlsSNI
      if (tlsJA3Hash) params.tls_ja3_hash = tlsJA3Hash
      if (tlsJA4) params.tls_ja4 = tlsJA4
      if (tlsVersion) params.tls_version = tlsVersion
      if (tlsALPN) params.tls_alpn = tlsALPN
      if (sinceFilter) params.since = new Date(sinceFilter).toISOString()
      if (untilFilter) params.until = new Date(untilFilter).toISOString()
      const res = await getAccessLogs(params)
      setItems(res.items ?? [])
      setTotal(res.total ?? 0)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败")
      setItems([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [
    page,
    idSearch,
    siteIDSearch,
    requestIDSearch,
    pathSearch,
    hostSearch,
    clientIP,
    statusFilter,
    methodFilter,
    wafActionFilter,
    cacheFilter,
    tlsSNI,
    tlsJA3Hash,
    tlsJA4,
    tlsVersion,
    tlsALPN,
    sinceFilter,
    untilFilter,
  ])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  const hasFilters = Boolean(
    idSearch ||
      siteIDSearch ||
      requestIDSearch ||
      pathSearch ||
      hostSearch ||
      clientIP ||
      statusFilter !== "all" ||
      methodFilter !== "all" ||
      wafActionFilter !== "all" ||
      cacheFilter !== "all" ||
      tlsSNI ||
      tlsJA3Hash ||
      tlsJA4 ||
      tlsVersion ||
      tlsALPN ||
      sinceFilter ||
      untilFilter
  )
  const realtimeAccessLogs =
    page === 1 && !hasFilters ? realtime.accessLogs : null
  const visibleItems = realtimeAccessLogs?.items ?? items
  const visibleTotal = realtimeAccessLogs?.total ?? total
  const visibleLoading = loading && !realtimeAccessLogs
  const totalPages = Math.max(1, Math.ceil(visibleTotal / PAGE_SIZE))

  function resetFilters() {
    setIdSearch("")
    setSiteIDSearch("")
    setRequestIDSearch("")
    setPathSearch("")
    setHostSearch("")
    setClientIP("")
    setStatusFilter("all")
    setMethodFilter("all")
    setWafActionFilter("all")
    setCacheFilter("all")
    setTLSSNI("")
    setTLSJA3Hash("")
    setTLSJA4("")
    setTLSVersion("")
    setTLSALPN("")
    setSinceFilter("")
    setUntilFilter("")
    setPage(1)
  }

  async function openDetail(item: AccessLog) {
    setSelected(item)
    setRequestTrace(null)
    try {
      const detail = await getAccessLog(item.id)
      setSelected((current) => (current?.id === item.id ? detail : current))
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载请求详情失败")
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

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Access Logs"
        title="请求日志"
        description="查看请求结果、状态码、上游响应耗时与当时 WAF 动作，用于排障与审计。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={load}>
              <RefreshCcw data-icon="inline-start" /> 刷新
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportCSV(visibleItems)}
              disabled={visibleItems.length === 0}
            >
              <Download data-icon="inline-start" /> 导出当前页 CSV
            </Button>
          </>
        }
      />

      <Surface
        title="筛选条件"
        description="所有条件参与后端分页查询，导出仅包含当前页结果。"
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
              placeholder="日志 ID"
              className="w-[120px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={siteIDSearch}
              onChange={(e) => {
                setSiteIDSearch(e.target.value)
                setPage(1)
              }}
              placeholder="站点 ID"
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
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={pathSearch}
              onChange={(e) => {
                setPathSearch(e.target.value)
                setPage(1)
              }}
              placeholder="搜索路径"
              className="w-[180px] rounded-lg pl-8"
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
              value={clientIP}
              onChange={(e) => {
                setClientIP(e.target.value)
                setPage(1)
              }}
              placeholder="搜索源 IP"
              className="w-[160px] rounded-lg pl-8"
            />
          </div>
          <Select
            value={statusFilter}
            onValueChange={(v) => {
              setStatusFilter(v)
              setPage(1)
            }}
          >
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
          <Select
            value={methodFilter}
            onValueChange={(v) => {
              setMethodFilter(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[110px] rounded-lg">
              <SelectValue placeholder="方法" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部方法</SelectItem>
                {HTTP_METHODS.map((m) => (
                  <SelectItem key={m} value={m}>
                    {m}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select
            value={wafActionFilter}
            onValueChange={(v) => {
              setWafActionFilter(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[130px] rounded-lg">
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
          <Select
            value={cacheFilter}
            onValueChange={(v) => {
              setCacheFilter(v)
              setPage(1)
            }}
          >
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
        </div>
        <FieldGroup className="flex-row flex-wrap items-center gap-3">
          <Field orientation="horizontal" className="w-auto gap-1.5">
            <FieldLabel
              htmlFor="access-log-since"
              className="text-xs font-normal text-muted-foreground"
            >
              开始时间
            </FieldLabel>
            <Input
              id="access-log-since"
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
              htmlFor="access-log-until"
              className="text-xs font-normal text-muted-foreground"
            >
              结束时间
            </FieldLabel>
            <Input
              id="access-log-until"
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

      {/* Table */}
      <Surface
        title="请求日志列表"
        description={`当前筛选命中 ${visibleTotal} 条，请求体和请求头详情按脱敏与截断策略展示。${realtimeAccessLogs ? " 当前显示实时快照第一页。" : ""}`}
      >
        {visibleLoading ? (
          <div className="p-16 text-center text-sm text-muted-foreground">
            加载中...
          </div>
        ) : visibleItems.length === 0 ? (
          <EmptyState
            title="当前筛选条件下本页暂无请求日志"
            description="调整站点 ID、时间范围、Host、路径、源 IP、状态码或 WAF 动作后重新查看。"
          />
        ) : (
          <>
            <div className="overscroll-x-contain">
              <Table className="min-w-[1200px] table-fixed">
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground hover:bg-muted/45">
                    <TableHead className="w-[82px] px-4 py-3 text-muted-foreground">
                      站点
                    </TableHead>
                    <TableHead className="w-[150px] px-4 py-3 text-muted-foreground">
                      时间
                    </TableHead>
                    <TableHead className="w-[86px] px-4 py-3 text-muted-foreground">
                      方法
                    </TableHead>
                    <TableHead className="w-[170px] px-4 py-3 text-muted-foreground">
                      Host
                    </TableHead>
                    <TableHead className="w-[280px] px-4 py-3 text-muted-foreground">
                      路径
                    </TableHead>
                    <TableHead className="w-[90px] px-4 py-3 text-muted-foreground">
                      状态码
                    </TableHead>
                    <TableHead className="w-[150px] px-4 py-3 text-muted-foreground">
                      源 IP
                    </TableHead>
                    <TableHead className="w-[104px] px-4 py-3 text-muted-foreground">
                      当时 WAF
                    </TableHead>
                    <TableHead className="w-[110px] px-4 py-3 text-muted-foreground">
                      上游耗时
                    </TableHead>
                    <TableHead className="w-[110px] px-4 py-3 text-muted-foreground">
                      响应大小
                    </TableHead>
                    <TableHead className="w-[84px] px-4 py-3 text-right text-muted-foreground">
                      详情
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleItems.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell className="px-4 py-3 font-mono text-xs text-muted-foreground">
                        {item.site_id}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(item.created_at)}
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <MethodBadge method={item.method} />
                      </TableCell>
                      <TableCell className="min-w-0 px-4 py-3 text-xs text-muted-foreground">
                        <TruncatedCell value={item.host} />
                      </TableCell>
                      <TableCell className="min-w-0 px-4 py-3 text-xs text-muted-foreground">
                        <TruncatedCell value={redactSensitiveText(item.path)} mono />
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <StatusBadge code={item.status_code} />
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-xs text-foreground">
                        {item.client_ip}
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <WAFActionBadge action={item.waf_action} />
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-xs whitespace-nowrap text-muted-foreground">
                        {formatLatency(item.upstream_latency_ms)}
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-xs whitespace-nowrap text-muted-foreground">
                        {formatBytes(item.response_size)}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openDetail(item)}
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
            <DialogTitle>请求详情</DialogTitle>
            <DialogDescription>完整的请求日志信息</DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {(
                [
                  ["Request ID", selected.request_id || "-", true, true],
                  ["时间", formatDate(selected.created_at), false, false],
                  ["客户端 IP", selected.client_ip, true, true],
                  ["Host", selected.host || "-", true, true],
                  ["方法", selected.method, true, true],
                  ["状态码", String(selected.status_code), true, true],
                  [
                    "当时 WAF 动作",
                    selected.waf_action
                      ? getWAFActionMeta(selected.waf_action).label
                      : "-",
                    false,
                    false,
                  ],
                  ["缓存状态", selected.cache_state || "-", true, true],
                  ["上游服务器", selected.upstream || "-", true, true],
                  [
                    "上游耗时",
                    formatLatency(selected.upstream_latency_ms),
                    true,
                    false,
                  ],
                  [
                    "响应大小",
                    formatBytes(selected.response_size),
                    true,
                    false,
                  ],
                  [
                    "请求大小",
                    formatBytes(selected.request_size ?? 0),
                    true,
                    false,
                  ],
                  ["HTTP 协议", selected.http_protocol || "-", true, true],
                  ["TLS 版本", selected.tls_version || "-", true, true],
                  ["TLS SNI", selected.tls_sni || "-", true, true],
                  ["TLS ALPN", selected.tls_alpn || "-", true, true],
                  ["JA3 Hash", selected.tls_ja3_hash || "-", true, true],
                  ["JA4", selected.tls_ja4 || "-", true, true],
                  ["站点 ID", String(selected.site_id), true, true],
                ] as [string, string, boolean, boolean][]
              ).map(([label, value, mono, copyable]) => (
                <DetailField
                  key={label}
                  label={label}
                  value={value}
                  mono={mono}
                  copyText={copyable ? value : undefined}
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
                label="JA3"
                value={selected.tls_ja3 || "-"}
                as="code"
                className="sm:col-span-2"
                contentClassName="text-xs break-all text-foreground"
              />
              <CopyableBlock
                label="Request Headers"
                value={selected.request_headers || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="Response Headers"
                value={selected.response_headers || "-"}
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
                label="Header Order"
                value={selected.header_order || "-"}
                as="code"
                className="sm:col-span-2"
                contentClassName="text-xs break-all text-foreground"
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
