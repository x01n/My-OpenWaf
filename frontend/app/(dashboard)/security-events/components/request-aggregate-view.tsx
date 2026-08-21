"use client"

/**
 * 请求级安全事件聚合视图
 *
 * 后端契约：GET /api/v1/security-events/requests
 *   -> { items: SecurityEventRequest[], total: number, page: number }
 * items 元素只有 request_id / event_count / last_seen 三个字段；
 * total 是按 request_id 去重后的请求数，不是事件条数。
 * 筛选参数与 GET /api/v1/security-events 完全一致，故由父页面注入。
 */

import { useMemo } from "react"
import { useRouter } from "next/navigation"
import { useTranslation } from "react-i18next"
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { DataTable } from "@/components/data-table"
import { EmptyState } from "@/components/empty-state"
import { IconRoute, IconShieldOff } from "@tabler/icons-react"
import { useSecurityEventRequests } from "@/hooks/use-api"
import type { SecurityEventRequest } from "@/lib/types"
import { format } from "date-fns"

/** 单个 request_id 的追踪详情路由，与安全事件表格内的跳转形式保持一致。 */
function traceHref(requestId: string): string {
  return `/request-trace?id=${encodeURIComponent(requestId)}`
}

/** last_seen 为 RFC3339 串，非法值退化为 "-"，不让表格出现 Invalid Date。 */
function formatLastSeen(iso: string): string {
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return "-"
  return format(new Date(parsed), "yyyy-MM-dd HH:mm:ss")
}

export interface RequestAggregateViewProps {
  /** 与事件级列表共用的筛选参数（已剔除空值） */
  filterParams: Record<string, string>
  page: number
  pageSize: number
  onPageChange: (page: number) => void
}

export function RequestAggregateView({
  filterParams,
  page,
  pageSize,
  onPageChange,
}: RequestAggregateViewProps) {
  const { t } = useTranslation()
  const router = useRouter()

  const { data, isLoading } = useSecurityEventRequests({
    page,
    page_size: pageSize,
    ...filterParams,
  })

  const items = useMemo<SecurityEventRequest[]>(
    () => data?.items || [],
    [data?.items]
  )
  const total = data?.total || 0
  const totalPages = Math.ceil(total / pageSize) || 1

  const openTrace = (requestId: string) => {
    router.push(traceHref(requestId))
  }

  const columns = [
    {
      key: "request_id",
      title: t("securityEvents.requests.requestId"),
      // TableCell 默认 whitespace-nowrap，长 request_id 会撑宽表格触发横向滚动，
      // 故显式换行；align-top 让多行 ID 与右侧单行列顶部对齐。
      cellClassName: "whitespace-normal break-all align-top",
      render: (row: SecurityEventRequest) => (
        <button
          type="button"
          onClick={() => openTrace(row.request_id)}
          title={t("securityEvents.requests.openTrace")}
          className="block max-w-full cursor-pointer text-left font-mono text-xs break-all text-foreground transition-colors hover:text-primary"
        >
          {row.request_id}
        </button>
      ),
    },
    {
      key: "event_count",
      title: t("securityEvents.requests.eventCount"),
      width: "120px",
      cellClassName: "align-top",
      render: (row: SecurityEventRequest) => (
        <Badge variant="secondary" className="h-5 px-2 font-mono text-xs">
          {row.event_count}
        </Badge>
      ),
    },
    {
      key: "last_seen",
      title: t("securityEvents.requests.lastSeen"),
      width: "190px",
      cellClassName: "align-top",
      render: (row: SecurityEventRequest) => (
        <span className="text-xs whitespace-nowrap text-muted-foreground">
          {formatLastSeen(row.last_seen)}
        </span>
      ),
    },
    {
      key: "operations",
      title: t("common.action"),
      width: "80px",
      cellClassName: "align-top",
      render: (row: SecurityEventRequest) => (
        <Button
          variant="ghost"
          size="icon-sm"
          className="cursor-pointer"
          title={t("securityEvents.requests.openTrace")}
          onClick={() => openTrace(row.request_id)}
        >
          <IconRoute className="h-4 w-4" />
        </Button>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary" className="h-5 px-2 text-xs">
          {t("securityEvents.requests.total", { count: total })}
        </Badge>
        <span className="text-xs text-muted-foreground">
          {t("securityEvents.requests.totalScope")}
        </span>
      </div>

      <DataTable
        columns={columns}
        data={items}
        loading={isLoading}
        rowKey={(row) => row.request_id}
        emptyText={t("securityEvents.requests.empty")}
        emptyContent={
          <EmptyState
            icon={IconShieldOff}
            title={t("securityEvents.requests.empty")}
            description={t("securityEvents.requests.emptyHint")}
            className="py-16"
          />
        }
      />

      {totalPages > 1 && (
        <Pagination>
          <PaginationContent>
            <PaginationItem>
              <PaginationPrevious
                onClick={() => onPageChange(Math.max(1, page - 1))}
                className={page <= 1 ? "pointer-events-none opacity-50" : ""}
              />
            </PaginationItem>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const pageNum = i + 1
              return (
                <PaginationItem key={pageNum}>
                  <PaginationLink
                    isActive={page === pageNum}
                    onClick={() => onPageChange(pageNum)}
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
                onClick={() => onPageChange(Math.min(totalPages, page + 1))}
                className={
                  page >= totalPages ? "pointer-events-none opacity-50" : ""
                }
              />
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      )}
    </div>
  )
}
