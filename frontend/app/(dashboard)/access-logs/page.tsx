"use client"

import { useState } from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
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
import Link from "next/link"
import { IconFilter, IconRoute } from "@tabler/icons-react"
import { useAccessLogs } from "@/hooks/use-api"
import type { AccessLog } from "@/lib/types"

const FILTER_ALL = "__all__"

function parsePositivePage(raw: string | null): number {
  const value = Number(raw)
  return Number.isFinite(value) && Number.isInteger(value) && value >= 1
    ? value
    : 1
}

export default function AccessLogsPage() {
  const { t } = useTranslation()
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const [pageSize] = useState(20)
  const [showFilters, setShowFilters] = useState(false)
  const page = parsePositivePage(searchParams.get("page"))
  const filters = {
    waf_action: searchParams.get("waf_action") || "",
    status_group: searchParams.get("status_group") || "",
    client_ip: searchParams.get("client_ip") || "",
    host: searchParams.get("host") || "",
    path: searchParams.get("path") || "",
    site_id: searchParams.get("site_id") || "",
  }

  const updateQuery = (updates: Record<string, string | undefined>) => {
    const params = new URLSearchParams(searchParams.toString())
    params.delete("status_code")
    for (const [key, value] of Object.entries(updates)) {
      if (value) params.set(key, value)
      else params.delete(key)
    }
    if (!("page" in updates)) params.set("page", "1")
    router.replace(`${pathname}?${params.toString()}`)
  }

  const { data, isLoading, error } = useAccessLogs({
    page,
    page_size: pageSize,
    ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== "")),
  })

  const items = data?.items || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / pageSize) || 1

  const handleFilterChange = (key: string, value: string) => {
    updateQuery({ [key]: value })
  }

  const clearFilters = () => {
    updateQuery({
      waf_action: undefined,
      status_group: undefined,
      client_ip: undefined,
      host: undefined,
      path: undefined,
      site_id: undefined,
    })
  }

  const columns = [
    { key: "created_at", title: t("accessLogs.time"), width: "180px" },
    { key: "client_ip", title: t("accessLogs.ip"), width: "140px" },
    {
      key: "host",
      title: t("accessLogs.host"),
      width: "180px",
      cellClassName: "whitespace-normal break-words align-top",
      render: (row: AccessLog) => (
        <span className="block max-w-full break-words">{row.host || "-"}</span>
      ),
    },
    {
      key: "path",
      title: t("accessLogs.path"),
      width: "220px",
      cellClassName: "whitespace-normal break-all align-top",
      render: (row: AccessLog) => (
        <span className="block max-w-full font-mono text-xs break-all">
          {row.path || "-"}
        </span>
      ),
    },
    {
      key: "upstream",
      title: t("requestTrace.upstream"),
      width: "190px",
      cellClassName: "whitespace-normal break-all align-top",
      render: (row: AccessLog) => (
        <span className="block max-w-full font-mono text-xs break-all">
          {row.upstream || "-"}
        </span>
      ),
    },
    { key: "method", title: t("accessLogs.method"), width: "80px" },
    { key: "status_code", title: t("accessLogs.status"), width: "80px" },
    {
      key: "waf_action",
      title: t("accessLogs.wafAction"),
      width: "100px",
      render: (row: AccessLog) =>
        row.waf_action ? (
          <ActionBadge
            action={row.waf_action}
            className="h-5 px-1.5 text-[10px]"
          />
        ) : (
          "-"
        ),
    },
    {
      key: "tls_ja3",
      title: "tls_ja3",
      width: "180px",
      cellClassName: "whitespace-normal break-all align-top",
      render: (row: AccessLog) => (
        <span className="block max-w-full font-mono text-xs break-all">
          {row.tls_ja3 || "-"}
        </span>
      ),
    },
    {
      key: "tls_ja3_hash",
      title: "tls_ja3_hash",
      width: "180px",
      cellClassName: "whitespace-normal break-all align-top",
      render: (row: AccessLog) => (
        <span className="block max-w-full font-mono text-xs break-all">
          {row.tls_ja3_hash || "-"}
        </span>
      ),
    },
    {
      key: "tls_ja4",
      title: "tls_ja4",
      width: "150px",
      cellClassName: "whitespace-normal break-all align-top",
      render: (row: AccessLog) => (
        <span className="block max-w-full font-mono text-xs break-all">
          {row.tls_ja4 || "-"}
        </span>
      ),
    },
    {
      key: "operations",
      title: t("common.action"),
      width: "80px",
      render: (row: AccessLog) =>
        row.request_id ? (
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
        ) : (
          "-"
        ),
    },
  ]

  return (
    <div className="max-w-full min-w-0 space-y-4 overflow-x-hidden">
      <PageHeader
        title={t("accessLogs.title")}
        description={t("accessLogs.description")}
        actions={
          <Badge variant="secondary" className="h-5 px-2 text-xs">
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
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">
              {t("accessLogs.listTitle")}
            </CardTitle>
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1 text-xs"
              onClick={() => setShowFilters(!showFilters)}
            >
              <IconFilter className="h-3.5 w-3.5" />
              {showFilters
                ? t("common.collapseFilter")
                : t("common.advancedFilter")}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="min-w-0 space-y-4">
          {showFilters && (
            <div className="grid gap-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-2 lg:grid-cols-4">
              <div className="space-y-1.5">
                <Label className="text-xs">WAF Action</Label>
                <Select
                  value={filters.waf_action || FILTER_ALL}
                  onValueChange={(v) =>
                    handleFilterChange("waf_action", v === FILTER_ALL ? "" : v)
                  }
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t("common.all")} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FILTER_ALL}>
                      {t("common.all")}
                    </SelectItem>
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
                <Label className="text-xs">Status</Label>
                <Select
                  value={filters.status_group || FILTER_ALL}
                  onValueChange={(v) =>
                    handleFilterChange(
                      "status_group",
                      v === FILTER_ALL ? "" : v
                    )
                  }
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={t("common.all")} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FILTER_ALL}>
                      {t("common.all")}
                    </SelectItem>
                    <SelectItem value="2xx">2xx</SelectItem>
                    <SelectItem value="3xx">3xx</SelectItem>
                    <SelectItem value="4xx">4xx</SelectItem>
                    <SelectItem value="5xx">5xx</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">IP</Label>
                <Input
                  className="h-8 text-xs"
                  placeholder={t("accessLogs.ipPlaceholder")}
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
                  placeholder={t("accessLogs.domainPlaceholder")}
                  value={filters.host}
                  onChange={(e) => handleFilterChange("host", e.target.value)}
                />
              </div>
              <div className="flex items-end sm:col-span-2 lg:col-span-4">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 text-xs"
                  onClick={clearFilters}
                >
                  {t("common.clearFilters")}
                </Button>
              </div>
            </div>
          )}

          <DataTable
            columns={columns}
            data={items}
            loading={isLoading}
            rowKey={(row) => row.id}
            emptyText={t("accessLogs.empty")}
          />

          {totalPages > 1 && (
            <Pagination>
              <PaginationContent>
                <PaginationItem>
                  <PaginationPrevious
                    onClick={() =>
                      updateQuery({ page: String(Math.max(1, page - 1)) })
                    }
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
    </div>
  )
}
