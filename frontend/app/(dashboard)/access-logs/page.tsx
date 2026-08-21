"use client"

import { Suspense, useCallback, useMemo, useState } from "react"
import dynamic from "next/dynamic"
import Link from "next/link"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { format } from "date-fns"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
  PaginationEllipsis,
} from "@/components/ui/pagination"
import { Badge } from "@/components/ui/badge"
import { ActionBadge } from "@/components/action-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { DataTable } from "@/components/data-table"
import { Skeleton } from "@/components/ui/skeleton"
import { IconEye, IconFilter, IconRoute } from "@tabler/icons-react"
import { useAccessLogs } from "@/hooks/use-api"
import type { AccessLog } from "@/lib/types"
import { cn, formatBytes, formatLatencyMs } from "@/lib/utils"

const AccessLogDetailDialog = dynamic(() =>
  import("@/components/access-log-detail-dialog").then(
    (module) => module.AccessLogDetailDialog
  )
)

const FILTER_ALL = "__all__"
const PAGE_SIZE = 20

interface AccessLogFilters {
  waf_action: string
  status_group: string
  client_ip: string
  host: string
  path: string
  site_id: string
}

type AccessLogQueryUpdates = Partial<AccessLogFilters> & {
  page?: string
}

interface FilterDraftState {
  source: string
  value: AccessLogFilters
}

type PaginationToken = number | "start-ellipsis" | "end-ellipsis"

/** URL 页码只接受大于等于 1 的整数。 */
function parsePositivePage(raw: string | null): number {
  const value = Number(raw)
  return Number.isFinite(value) && Number.isInteger(value) && value >= 1
    ? value
    : 1
}

/** 从只读查询字符串提取访问日志筛选条件。 */
function readFilters(queryString: string): AccessLogFilters {
  const params = new URLSearchParams(queryString)
  return {
    waf_action: params.get("waf_action") || "",
    status_group: params.get("status_group") || "",
    client_ip: params.get("client_ip") || "",
    host: params.get("host") || "",
    path: params.get("path") || "",
    site_id: params.get("site_id") || "",
  }
}

/** 生成围绕当前页的紧凑分页窗口，避免深页码时失去当前位置。 */
function buildPaginationTokens(
  totalPages: number,
  currentPage: number
): PaginationToken[] {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, index) => index + 1)
  }

  const pages = new Set([1, totalPages, currentPage - 1, currentPage, currentPage + 1])
  const visible = Array.from(pages)
    .filter((page) => page >= 1 && page <= totalPages)
    .sort((left, right) => left - right)
  const tokens: PaginationToken[] = []

  visible.forEach((page, index) => {
    const previous = visible[index - 1]
    if (previous && page - previous > 1) {
      tokens.push(previous === 1 ? "start-ellipsis" : "end-ellipsis")
    }
    tokens.push(page)
  })
  return tokens
}

/** 日期格式化失败时保留后端原值。 */
function formatLogTime(value: string): string {
  try {
    return format(new Date(value), "yyyy-MM-dd HH:mm:ss")
  } catch {
    return value || "-"
  }
}

/** 状态码区间样式，文字数值同时承载语义。 */
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

/** DataTable 使用稳定函数，避免每次页面状态变化都创建 rowKey。 */
function accessLogRowKey(row: AccessLog): number {
  return row.id
}

function AccessLogsContent() {
  const { t } = useTranslation()
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const queryString = searchParams.toString()
  const page = parsePositivePage(searchParams.get("page"))
  const filters = useMemo(() => readFilters(queryString), [queryString])
  const activeFilterParams = useMemo(
    () =>
      Object.fromEntries(
        Object.entries(filters).filter(([, value]) => value !== "")
      ),
    [filters]
  )
  const activeFilterCount = Object.keys(activeFilterParams).length
  const [showFilters, setShowFilters] = useState(activeFilterCount > 0)
  const [selectedLog, setSelectedLog] = useState<AccessLog | null>(null)
  const [draftState, setDraftState] = useState<FilterDraftState>({
    source: queryString,
    value: filters,
  })
  const draft = draftState.source === queryString ? draftState.value : filters

  const queryParams = useMemo(
    () => ({
      page,
      page_size: PAGE_SIZE,
      ...activeFilterParams,
    }),
    [activeFilterParams, page]
  )
  const { data, isLoading, error } = useAccessLogs(queryParams)
  const items = useMemo<AccessLog[]>(() => data?.items || [], [data?.items])
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE) || 1
  const paginationTokens = useMemo(
    () => buildPaginationTokens(totalPages, page),
    [page, totalPages]
  )

  const updateQuery = useCallback(
    (updates: AccessLogQueryUpdates) => {
      const params = new URLSearchParams(queryString)
      params.delete("status_code")
      for (const [key, value] of Object.entries(updates)) {
        if (value) params.set(key, value)
        else params.delete(key)
      }
      if (!("page" in updates)) params.set("page", "1")
      const nextQuery = params.toString()
      router.replace(nextQuery ? `${pathname}?${nextQuery}` : pathname)
    },
    [pathname, queryString, router]
  )

  const updateDraft = useCallback(
    (key: keyof AccessLogFilters, value: string) => {
      setDraftState((current) => ({
        source: queryString,
        value: {
          ...(current.source === queryString ? current.value : filters),
          [key]: value,
        },
      }))
    },
    [filters, queryString]
  )

  const applyFilters = useCallback(() => {
    updateQuery(draft)
  }, [draft, updateQuery])

  const clearFilters = useCallback(() => {
    const emptyFilters: AccessLogFilters = {
      waf_action: "",
      status_group: "",
      client_ip: "",
      host: "",
      path: "",
      site_id: "",
    }
    setDraftState({ source: queryString, value: emptyFilters })
    updateQuery(emptyFilters)
  }, [queryString, updateQuery])

  const columns = useMemo(
    () => [
      {
        key: "created_at",
        title: t("accessLogs.time"),
        width: "168px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <div className="space-y-1">
            <div className="font-mono text-xs whitespace-nowrap">
              {formatLogTime(row.created_at)}
            </div>
            <div
              className="max-w-40 truncate font-mono text-[10px] text-muted-foreground"
              title={row.request_id || undefined}
            >
              {row.request_id || `#${row.id}`}
            </div>
          </div>
        ),
      },
      {
        key: "client",
        title: t("accessLogs.ip"),
        width: "190px",
        cellClassName: "align-top whitespace-normal",
        render: (row: AccessLog) => (
          <div className="min-w-0 space-y-1">
            <div className="font-mono text-xs font-medium break-all">
              {row.client_ip || "-"}
            </div>
            <div className="truncate text-xs text-muted-foreground" title={row.host}>
              {row.host || "-"}
            </div>
          </div>
        ),
      },
      {
        key: "request",
        title: t("accessLogs.path"),
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
            <code
              className="line-clamp-2 min-w-0 font-mono text-xs leading-relaxed break-all"
              title={row.path || undefined}
            >
              {row.path || "/"}
            </code>
          </div>
        ),
      },
      {
        key: "verdict",
        title: t("accessLogs.wafAction"),
        width: "148px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge
              variant="outline"
              className={cn(
                "h-5 px-1.5 font-mono text-[10px]",
                statusBadgeClass(row.status_code)
              )}
            >
              {row.status_code || "-"}
            </Badge>
            <ActionBadge
              action={row.waf_action}
              className="h-5 px-1.5 text-[10px]"
            />
          </div>
        ),
      },
      {
        key: "performance",
        title: t("requestTrace.upstreamLatency"),
        width: "150px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <div className="space-y-1 font-mono text-[11px]">
            <div className="font-semibold">
              {formatLatencyMs(row.upstream_latency_ms)}
            </div>
            <div className="text-muted-foreground">
              req {formatBytes(row.request_size)} · res {formatBytes(row.response_size)}
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
            <div
              className="truncate font-mono text-xs"
              title={row.upstream || undefined}
            >
              {row.upstream || "-"}
            </div>
            <div className="flex flex-wrap gap-1 text-[10px] text-muted-foreground">
              {row.upstream_http_protocol || row.http_protocol ? (
                <span>
                  {row.http_protocol || "-"} → {row.upstream_http_protocol || "-"}
                </span>
              ) : null}
              {row.cache_state ? <span>· {row.cache_state}</span> : null}
            </div>
          </div>
        ),
      },
      {
        key: "operations",
        title: t("common.action"),
        width: "84px",
        cellClassName: "align-top",
        render: (row: AccessLog) => (
          <div className="flex items-center gap-0.5">
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
            {row.request_id ? (
              <Button
                asChild
                variant="ghost"
                size="icon-sm"
                className="cursor-pointer"
                title={t("requestTrace.trackThisRequest")}
              >
                <Link
                  href={`/request-trace?id=${encodeURIComponent(row.request_id)}`}
                >
                  <IconRoute className="h-4 w-4" />
                </Link>
              </Button>
            ) : null}
          </div>
        ),
      },
    ],
    [t]
  )

  return (
    <div className="max-w-full min-w-0 space-y-4 overflow-x-hidden">
      <PageHeader
        title={t("accessLogs.title")}
        description={t("accessLogs.description")}
        actions={
          <Badge variant="secondary" className="h-6 px-2.5 font-mono text-xs">
            {t("accessLogs.total", { count: total })}
          </Badge>
        }
      />

      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {error.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}

      <Card className="min-w-0 overflow-hidden">
        <CardHeader className="border-b bg-muted/10 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <CardTitle className="text-base">
                {t("accessLogs.listTitle")}
              </CardTitle>
              {activeFilterCount > 0 && (
                <Badge variant="outline" className="h-5 px-1.5 font-mono text-[10px]">
                  {activeFilterCount}
                </Badge>
              )}
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-8 cursor-pointer gap-1.5 text-xs"
              aria-expanded={showFilters}
              onClick={() => setShowFilters((visible) => !visible)}
            >
              <IconFilter className="h-3.5 w-3.5" />
              {showFilters
                ? t("common.collapseFilter")
                : t("common.advancedFilter")}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="min-w-0 space-y-4 p-3 sm:p-4">
          {showFilters && (
            <form
              className="grid gap-3 rounded-lg border bg-muted/20 p-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6"
              onSubmit={(event) => {
                event.preventDefault()
                applyFilters()
              }}
            >
              <div className="space-y-1.5">
                <Label className="text-xs">{t("accessLogs.wafAction")}</Label>
                <Select
                  value={draft.waf_action || FILTER_ALL}
                  onValueChange={(value) =>
                    updateDraft(
                      "waf_action",
                      value === FILTER_ALL ? "" : value
                    )
                  }
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t("common.all")} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FILTER_ALL}>{t("common.all")}</SelectItem>
                    <SelectItem value="allow">
                      {t("securityEvents.action.allow")}
                    </SelectItem>
                    <SelectItem value="block">
                      {t("securityEvents.action.block")}
                    </SelectItem>
                    <SelectItem value="intercept">
                      {t("securityEvents.action.intercept")}
                    </SelectItem>
                    <SelectItem value="challenge">
                      {t("securityEvents.action.challenge")}
                    </SelectItem>
                    <SelectItem value="observe">
                      {t("securityEvents.action.observe")}
                    </SelectItem>
                    <SelectItem value="log_only">
                      {t("securityEvents.action.log_only")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("accessLogs.status")}</Label>
                <Select
                  value={draft.status_group || FILTER_ALL}
                  onValueChange={(value) =>
                    updateDraft(
                      "status_group",
                      value === FILTER_ALL ? "" : value
                    )
                  }
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t("common.all")} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FILTER_ALL}>{t("common.all")}</SelectItem>
                    <SelectItem value="2xx">2xx</SelectItem>
                    <SelectItem value="3xx">3xx</SelectItem>
                    <SelectItem value="4xx">4xx</SelectItem>
                    <SelectItem value="5xx">5xx</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="access-log-ip" className="text-xs">
                  {t("accessLogs.ip")}
                </Label>
                <Input
                  id="access-log-ip"
                  className="h-8 font-mono text-xs"
                  placeholder={t("accessLogs.ipPlaceholder")}
                  value={draft.client_ip}
                  onChange={(event) =>
                    updateDraft("client_ip", event.target.value)
                  }
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="access-log-host" className="text-xs">
                  {t("accessLogs.host")}
                </Label>
                <Input
                  id="access-log-host"
                  className="h-8 text-xs"
                  placeholder={t("accessLogs.domainPlaceholder")}
                  value={draft.host}
                  onChange={(event) => updateDraft("host", event.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="access-log-path" className="text-xs">
                  {t("accessLogs.path")}
                </Label>
                <Input
                  id="access-log-path"
                  className="h-8 font-mono text-xs"
                  placeholder="/api/"
                  value={draft.path}
                  onChange={(event) => updateDraft("path", event.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="access-log-site" className="text-xs">
                  {t("requestTrace.site")} ID
                </Label>
                <Input
                  id="access-log-site"
                  inputMode="numeric"
                  className="h-8 font-mono text-xs"
                  placeholder="#"
                  value={draft.site_id}
                  onChange={(event) => updateDraft("site_id", event.target.value)}
                />
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2 sm:col-span-2 lg:col-span-3 xl:col-span-6">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 cursor-pointer text-xs"
                  onClick={clearFilters}
                >
                  {t("common.clearFilters")}
                </Button>
                <Button type="submit" size="sm" className="h-8 cursor-pointer text-xs">
                  {t("timeRange.apply")}
                </Button>
              </div>
            </form>
          )}

          <DataTable
            columns={columns}
            data={items}
            loading={isLoading}
            rowKey={accessLogRowKey}
            emptyText={t("accessLogs.empty")}
          />

          {totalPages > 1 && (
            <div className="max-w-full overflow-x-auto pb-1">
              <Pagination className="w-max min-w-full">
                <PaginationContent>
                  <PaginationItem>
                    <PaginationPrevious
                      aria-disabled={page <= 1}
                      tabIndex={page <= 1 ? -1 : 0}
                      disabled={page <= 1}
                      onClick={() =>
                        updateQuery({ page: String(Math.max(1, page - 1)) })
                      }
                      className={
                        page <= 1 ? "pointer-events-none opacity-50" : "cursor-pointer"
                      }
                    />
                  </PaginationItem>
                  {paginationTokens.map((token) =>
                    typeof token === "number" ? (
                      <PaginationItem key={token}>
                        <PaginationLink
                          isActive={page === token}
                          className="cursor-pointer"
                          onClick={() => updateQuery({ page: String(token) })}
                        >
                          {token}
                        </PaginationLink>
                      </PaginationItem>
                    ) : (
                      <PaginationItem key={token}>
                        <PaginationEllipsis />
                      </PaginationItem>
                    )
                  )}
                  <PaginationItem>
                    <PaginationNext
                      aria-disabled={page >= totalPages}
                      tabIndex={page >= totalPages ? -1 : 0}
                      disabled={page >= totalPages}
                      onClick={() =>
                        updateQuery({
                          page: String(Math.min(totalPages, page + 1)),
                        })
                      }
                      className={
                        page >= totalPages
                          ? "pointer-events-none opacity-50"
                          : "cursor-pointer"
                      }
                    />
                  </PaginationItem>
                </PaginationContent>
              </Pagination>
            </div>
          )}
        </CardContent>
      </Card>

      {selectedLog && (
        <AccessLogDetailDialog
          log={selectedLog}
          open
          onOpenChange={(open) => {
            if (!open) setSelectedLog(null)
          }}
        />
      )}
    </div>
  )
}

/** 静态导出时为 useSearchParams 提供明确的 Suspense 边界。 */
function AccessLogsFallback() {
  return (
    <div className="space-y-4" aria-busy="true">
      <div className="space-y-2">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-4 w-72 max-w-full" />
      </div>
      <Card>
        <CardContent className="space-y-3 p-4">
          <Skeleton className="h-9 w-full" />
          {Array.from({ length: 6 }, (_, index) => (
            <Skeleton key={index} className="h-12 w-full" />
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

export default function AccessLogsPage() {
  return (
    <Suspense fallback={<AccessLogsFallback />}>
      <AccessLogsContent />
    </Suspense>
  )
}
