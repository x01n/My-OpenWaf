"use client"

import { useMemo, useState } from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import { toast } from "sonner"
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
import { Checkbox } from "@/components/ui/checkbox"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DataTable } from "@/components/data-table"
import { SecurityEventDetailDialog } from "@/components/security-event-detail-dialog"
import { DateRangePicker } from "@/components/date-range-picker"
import { IpHoverPreview } from "@/components/ip-hover-preview"
import { EmptyState } from "@/components/empty-state"
import { RequestAggregateView } from "./components/request-aggregate-view"
import Link from "next/link"
import {
  IconFilter,
  IconEye,
  IconChevronDown,
  IconDownload,
  IconShieldLock,
  IconX,
  IconRoute,
  IconShieldOff,
} from "@tabler/icons-react"
import {
  invalidateIPListCaches,
  useSecurityEvents,
} from "@/hooks/use-api"
import { ipListApi } from "@/lib/api"
import type { SecurityEvent } from "@/lib/types"
import { categoryLabel } from "@/lib/attack-category"
import { localizeMatchDesc } from "@/lib/match-desc-i18n"
import { format } from "date-fns"

const FILTER_ALL = "__all__"
type SelectionState = { scope: string; ids: Set<number> }

/** 列表视图维度：事件级逐条展示，请求级按 request_id 聚合。 */
const VIEW_EVENTS = "events"
const VIEW_REQUESTS = "requests"
type ViewMode = typeof VIEW_EVENTS | typeof VIEW_REQUESTS

function parsePositivePage(raw: string | null): number {
  const value = Number(raw)
  return Number.isFinite(value) && Number.isInteger(value) && value >= 1
    ? value
    : 1
}

/** 视图参数只接受两个已知值，其余一律回落到事件级，避免 URL 被改写后渲染空白。 */
function parseViewMode(raw: string | null): ViewMode {
  return raw === VIEW_REQUESTS ? VIEW_REQUESTS : VIEW_EVENTS
}

export default function SecurityEventsPage() {
  const { t, i18n } = useTranslation()

  const actionLabelMap: Record<string, string> = {
    block: t("securityEvents.action.block"),
    intercept: t("securityEvents.action.intercept"),
    observe: t("securityEvents.action.observe"),
    challenge: t("securityEvents.action.challenge"),
    captcha_challenge: t("securityEvents.action.captcha_challenge"),
    shield_challenge: t("securityEvents.action.shield_challenge"),
    chain_challenge: t("securityEvents.action.chain_challenge"),
    allow: t("securityEvents.action.allow"),
    drop: t("securityEvents.action.drop"),
    log_only: t("securityEvents.action.log_only"),
    rate_limit: t("securityEvents.action.rate_limit"),
    redirect: t("securityEvents.action.redirect"),
    tag: t("securityEvents.action.tag"),
  }

  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const [pageSize] = useState(20)
  const [showFilters, setShowFilters] = useState(false)
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)
  const [selection, setSelection] = useState<SelectionState>({
    scope: "",
    ids: new Set(),
  })
  const [batchLoading, setBatchLoading] = useState(false)
  const page = parsePositivePage(searchParams.get("page"))
  const view = parseViewMode(searchParams.get("view"))
  const filters = {
    action: searchParams.get("action") || "",
    category: searchParams.get("category") || "",
    client_ip: searchParams.get("client_ip") || "",
    host: searchParams.get("host") || "",
    path: searchParams.get("path") || "",
    site_id: searchParams.get("site_id") || "",
    since: searchParams.get("since") || "",
    until: searchParams.get("until") || "",
  }
  /** 两个视图共用同一组筛选值，请求级视图直接透传，不再造第二套筛选状态。 */
  const activeFilterParams = Object.fromEntries(
    Object.entries(filters).filter(([, v]) => v !== "")
  ) as Record<string, string>

  const updateQuery = (updates: Record<string, string | undefined>) => {
    const params = new URLSearchParams(searchParams.toString())
    for (const [key, value] of Object.entries(updates)) {
      if (value) params.set(key, value)
      else params.delete(key)
    }
    if (!("page" in updates)) params.set("page", "1")
    router.replace(`${pathname}?${params.toString()}`)
  }

  const { data, isLoading, error } = useSecurityEvents({
    page,
    page_size: pageSize,
    ...activeFilterParams,
  })

  const items = useMemo(() => data?.items || [], [data?.items])
  const total = data?.total || 0
  const totalPages = Math.ceil(total / pageSize) || 1
  const selectionScope = `${page}:${JSON.stringify(filters)}`
  const scopedSelectedIds =
    selection.scope === selectionScope ? selection.ids : new Set<number>()
  const selectedCurrentPageCount = items.reduce(
    (count, item) => count + (scopedSelectedIds.has(item.id) ? 1 : 0),
    0
  )
  const allCurrentPageSelected =
    items.length > 0 && selectedCurrentPageCount === items.length

  const handleFilterChange = (key: string, value: string) => {
    updateQuery({ [key]: value })
  }

  const clearFilters = () => {
    updateQuery({
      action: undefined,
      category: undefined,
      client_ip: undefined,
      host: undefined,
      path: undefined,
      site_id: undefined,
      since: undefined,
      until: undefined,
    })
  }

  const toggleSelect = (id: number) => {
    setSelection((prev) => {
      const next = new Set(prev.scope === selectionScope ? prev.ids : [])
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return { scope: selectionScope, ids: next }
    })
  }

  const toggleSelectAll = () => {
    setSelection({
      scope: selectionScope,
      ids: allCurrentPageSelected
        ? new Set()
        : new Set(items.map((item) => item.id)),
    })
  }

  const clearSelection = () =>
    setSelection({ scope: selectionScope, ids: new Set() })

  const exportCSV = () => {
    if (items.length === 0) return
    const headers = [
      "ID",
      t("securityEvents.csv.time", { defaultValue: "时间" }),
      t("securityEvents.csv.clientIp", { defaultValue: "客户端IP" }),
      t("securityEvents.csv.host", { defaultValue: "域名" }),
      t("securityEvents.csv.path", { defaultValue: "路径" }),
      t("securityEvents.csv.method", { defaultValue: "方法" }),
      t("securityEvents.csv.action", { defaultValue: "动作" }),
      t("securityEvents.csv.category", { defaultValue: "分类" }),
      t("securityEvents.csv.rule", { defaultValue: "规则" }),
      t("securityEvents.csv.statusCode", { defaultValue: "状态码" }),
      t("securityEvents.csv.matchDesc", { defaultValue: "匹配描述" }),
    ]
    const rows = items.map((ev) => [
      ev.id,
      ev.created_at,
      ev.client_ip,
      ev.host,
      ev.path,
      ev.method,
      ev.action ? actionLabelMap[ev.action] || ev.action : "",
      categoryLabel(ev.category),
      ev.rule_id_str || ev.rule_id,
      ev.status_code,
      localizeMatchDesc(
        ev.match_desc,
        i18n.resolvedLanguage ?? i18n.language
      ).replace(/"/g, '""'),
    ])
    const csv = [
      headers.join(","),
      ...rows.map((r) => r.map((v) => `"${v}"`).join(",")),
    ].join("\n")
    const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8;" })
    downloadBlob(blob, `security-events-${formatFileDate()}.csv`)
    toast.success(
      t("securityEvents.export.csvSuccess", { defaultValue: "CSV 导出成功" })
    )
  }

  const exportJSON = () => {
    if (items.length === 0) return
    const json = JSON.stringify(items, null, 2)
    const blob = new Blob([json], { type: "application/json;charset=utf-8;" })
    downloadBlob(blob, `security-events-${formatFileDate()}.json`)
    toast.success(
      t("securityEvents.export.jsonSuccess", { defaultValue: "JSON 导出成功" })
    )
  }

  const formatFileDate = () => {
    return format(new Date(), "yyyyMMdd-HHmmss")
  }

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const batchAddToBlocklist = async () => {
    const selectedItems = items.filter((item) => scopedSelectedIds.has(item.id))
    const uniqueIPs = [...new Set(selectedItems.map((item) => item.client_ip))]
    if (uniqueIPs.length === 0) return

    setBatchLoading(true)
    let success = 0
    let failed = 0
    for (const ip of uniqueIPs) {
      try {
        await ipListApi.create({
          value: ip,
          kind: "blacklist",
          action: "intercept",
          note: t("securityEvents.batch.blocklistNote", {
            defaultValue: "批量加入黑名单 - 安全事件",
          }),
        })
        success++
      } catch {
        failed++
      }
    }
    if (success > 0) {
      await invalidateIPListCaches().catch(() => undefined)
    }
    setBatchLoading(false)
    clearSelection()
    if (failed === 0) {
      toast.success(
        t("securityEvents.batch.blocklistSuccess", {
          defaultValue: `已将 ${success} 个 IP 加入黑名单`,
          success,
        })
      )
    } else {
      toast.warning(
        t("securityEvents.batch.blocklistPartial", {
          defaultValue: `${success} 个成功，${failed} 个失败`,
          success,
          failed,
        })
      )
    }
  }

  const columns = [
    {
      key: "select",
      title: (
        <Checkbox
          checked={allCurrentPageSelected}
          onCheckedChange={toggleSelectAll}
          aria-label={t("common.selectAll", { defaultValue: "全选" })}
        />
      ),
      width: "40px",
      render: (row: SecurityEvent) => (
        <Checkbox
          checked={scopedSelectedIds.has(row.id)}
          onCheckedChange={() => toggleSelect(row.id)}
          aria-label={`选择事件 ${row.id}`}
        />
      ),
    },
    { key: "created_at", title: t("securityEvents.time"), width: "180px" },
    {
      key: "client_ip",
      title: t("securityEvents.clientIp"),
      width: "140px",
      render: (row: SecurityEvent) =>
        row.client_ip ? (
          <IpHoverPreview ip={row.client_ip} />
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      key: "host",
      title: t("securityEvents.host"),
      width: "180px",
      cellClassName: "whitespace-normal break-all align-top",
    },
    {
      key: "path",
      title: t("securityEvents.path"),
      width: "200px",
      cellClassName: "whitespace-normal break-all align-top",
    },
    { key: "method", title: t("securityEvents.method"), width: "80px" },
    {
      key: "action",
      title: t("securityEvents.actionLabel"),
      width: "100px",
      render: (row: SecurityEvent) => (
        <ActionBadge action={row.action} className="h-5 px-1.5 text-[10px]" />
      ),
    },
    {
      key: "category",
      title: t("securityEvents.category", { defaultValue: "类别" }),
      width: "120px",
      render: (row: SecurityEvent) => categoryLabel(row.category),
    },
    {
      key: "rule_id_str",
      title: t("securityEvents.rule", { defaultValue: "规则" }),
      width: "120px",
      cellClassName: "whitespace-normal break-all align-top",
    },
    {
      key: "operations",
      title: t("common.action"),
      width: "110px",
      render: (row: SecurityEvent) => (
        <div className="flex items-center gap-0.5">
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => setSelectedEvent(row)}
            title={t("common.viewDetail")}
          >
            <IconEye className="h-4 w-4" />
          </Button>
          {row.request_id && (
            <Button
              asChild
              variant="ghost"
              size="icon-sm"
              title={t("requestTrace.trackThisRequest")}
            >
              <Link
                href={`/request-trace?id=${encodeURIComponent(row.request_id)}`}
              >
                <IconRoute className="h-4 w-4" />
              </Link>
            </Button>
          )}
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("securityEvents.title")}
        description={t("securityEvents.description")}
        actions={
          view === VIEW_EVENTS ? (
            <Badge variant="secondary" className="h-5 px-2 text-xs">
              {t("securityEvents.total", { count: total })}
            </Badge>
          ) : null
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

      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-3">
              <CardTitle className="text-base">
                {view === VIEW_EVENTS
                  ? t("securityEvents.eventList")
                  : t("securityEvents.requests.listTitle")}
              </CardTitle>
              <Tabs
                value={view}
                onValueChange={(v) =>
                  updateQuery({ view: v === VIEW_EVENTS ? undefined : v })
                }
              >
                <TabsList className="h-8">
                  <TabsTrigger
                    value={VIEW_EVENTS}
                    className="cursor-pointer text-xs"
                  >
                    {t("securityEvents.view.events")}
                  </TabsTrigger>
                  <TabsTrigger
                    value={VIEW_REQUESTS}
                    className="cursor-pointer text-xs"
                  >
                    {t("securityEvents.view.requests")}
                  </TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
            <div className="flex items-center gap-2">
              {view === VIEW_EVENTS && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-8 cursor-pointer gap-1 text-xs"
                      disabled={items.length === 0}
                    >
                      <IconDownload className="h-3.5 w-3.5" />
                      {t("securityEvents.export.title", {
                        defaultValue: "导出",
                      })}
                      <IconChevronDown className="h-3 w-3" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={exportCSV}>
                      {t("securityEvents.export.csv", {
                        defaultValue: "导出 CSV",
                      })}
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={exportJSON}>
                      {t("securityEvents.export.json", {
                        defaultValue: "导出 JSON",
                      })}
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
              <Button
                variant="outline"
                size="sm"
                className="h-8 cursor-pointer gap-1 text-xs"
                onClick={() => setShowFilters(!showFilters)}
              >
                <IconFilter className="h-3.5 w-3.5" />
                {showFilters
                  ? t("common.collapseFilter")
                  : t("common.advancedFilter")}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {showFilters && (
            <div className="grid gap-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-2 lg:grid-cols-3">
              <div className="space-y-1.5">
                <Label className="text-xs">
                  {t("securityEvents.actionLabel")}
                </Label>
                <Select
                  value={filters.action || FILTER_ALL}
                  onValueChange={(v) =>
                    handleFilterChange("action", v === FILTER_ALL ? "" : v)
                  }
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t("securityEvents.allActions")} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FILTER_ALL}>
                      {t("common.all")}
                    </SelectItem>
                    {Object.entries(actionLabelMap).map(([key, label]) => (
                      <SelectItem key={key} value={key}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">
                  {t("securityEvents.category", { defaultValue: "类别" })}
                </Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("securityEvents.categoryPlaceholder")}
                  value={filters.category}
                  onChange={(e) =>
                    handleFilterChange("category", e.target.value)
                  }
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">
                  {t("securityEvents.clientIp")}
                </Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("securityEvents.ipPlaceholder")}
                  value={filters.client_ip}
                  onChange={(e) =>
                    handleFilterChange("client_ip", e.target.value)
                  }
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Host</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("securityEvents.domainPlaceholder")}
                  value={filters.host}
                  onChange={(e) => handleFilterChange("host", e.target.value)}
                />
              </div>
              <div className="space-y-1.5 sm:col-span-2 lg:col-span-2">
                <Label className="text-xs">
                  {t("securityEvents.timeRange", {
                    defaultValue: "时间范围",
                  })}
                </Label>
                <DateRangePicker
                  value={{ since: filters.since, until: filters.until }}
                  onChange={(v) =>
                    updateQuery({ since: v.since, until: v.until })
                  }
                />
              </div>
              <div className="flex items-end sm:col-span-2 lg:col-span-3">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 cursor-pointer text-xs"
                  onClick={clearFilters}
                >
                  {t("common.clearFilters")}
                </Button>
              </div>
            </div>
          )}

          {view === VIEW_REQUESTS && (
            <RequestAggregateView
              filterParams={activeFilterParams}
              page={page}
              pageSize={pageSize}
              onPageChange={(next) => updateQuery({ page: String(next) })}
            />
          )}

          {view === VIEW_EVENTS && (
            <DataTable
              columns={columns}
              data={items}
              loading={isLoading}
              rowKey={(row) => row.id}
              emptyText={t("securityEvents.empty")}
              emptyContent={
                <EmptyState
                  icon={IconShieldOff}
                  title={t("securityEvents.empty")}
                  description={t(
                    "securityEvents.emptyHint",
                    "暂未检测到安全事件，当 WAF 拦截或观察到可疑请求时将在此展示"
                  )}
                  className="py-16"
                />
              }
            />
          )}

          {view === VIEW_EVENTS && totalPages > 1 && (
            <Pagination>
              <PaginationContent>
                <PaginationItem>
                  <PaginationPrevious
                    onClick={() =>
                      updateQuery({ page: String(Math.max(1, page - 1)) })
                    }
                    disabled={page <= 1}
                    className={
                      page <= 1 ? "pointer-events-none opacity-50" : ""
                    }
                  />
                </PaginationItem>
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  const pageNum = i + 1
                  return (
                    <PaginationItem key={pageNum}>
                      <PaginationLink
                        isActive={page === pageNum}
                        onClick={() => updateQuery({ page: String(pageNum) })}
                      >
                        {pageNum}
                      </PaginationLink>
                    </PaginationItem>
                  )
                })}
                {totalPages > 5 && (
                  <PaginationItem>
                    <PaginationEllipsis />
                  </PaginationItem>
                )}
                <PaginationItem>
                  <PaginationNext
                    onClick={() =>
                      updateQuery({
                        page: String(Math.min(totalPages, page + 1)),
                      })
                    }
                    disabled={page >= totalPages}
                    className={
                      page >= totalPages ? "pointer-events-none opacity-50" : ""
                    }
                  />
                </PaginationItem>
              </PaginationContent>
            </Pagination>
          )}
        </CardContent>
      </Card>

      {view === VIEW_EVENTS && selectedCurrentPageCount > 0 && (
        <div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2">
          <div className="flex items-center gap-3 rounded-xl border bg-background/95 px-5 py-3 shadow-lg backdrop-blur-sm">
            <span className="text-sm font-medium text-muted-foreground">
              {t("securityEvents.batch.selected", {
                defaultValue: `已选择 ${selectedCurrentPageCount} 条`,
                count: selectedCurrentPageCount,
              })}
            </span>
            <Button
              variant="default"
              size="sm"
              className="h-8 gap-1.5 text-xs"
              disabled={batchLoading}
              onClick={batchAddToBlocklist}
            >
              <IconShieldLock className="h-3.5 w-3.5" />
              {t("securityEvents.batch.addToBlocklist", {
                defaultValue: "批量加入黑名单",
              })}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1 text-xs"
              onClick={clearSelection}
            >
              <IconX className="h-3.5 w-3.5" />
              {t("common.cancel", { defaultValue: "取消" })}
            </Button>
          </div>
        </div>
      )}

      <SecurityEventDetailDialog
        event={selectedEvent}
        open={!!selectedEvent}
        onOpenChange={(open) => {
          if (!open) setSelectedEvent(null)
        }}
      />
    </div>
  )
}
