"use client"

import { useMemo } from "react"
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

type PageToken = number | "start-ellipsis" | "end-ellipsis"

interface TablePaginationProps {
  page: number
  pageSize: number
  total: number
  disabled?: boolean
  onPageChange: (page: number) => void
}

/**
 * 构造包含首尾页和当前页邻居的紧凑分页序列。
 *
 * @param page 当前页码
 * @param totalPages 总页数
 * @returns 可直接渲染的页码与省略号序列
 */
function buildPageTokens(page: number, totalPages: number): PageToken[] {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, index) => index + 1)
  }

  const pages = new Set([1, totalPages, page - 1, page, page + 1])
  const visible = Array.from(pages)
    .filter((value) => value >= 1 && value <= totalPages)
    .sort((a, b) => a - b)
  const tokens: PageToken[] = []

  visible.forEach((value, index) => {
    const previous = visible[index - 1]
    if (previous !== undefined && value - previous > 1) {
      tokens.push(previous === 1 ? "start-ellipsis" : "end-ellipsis")
    }
    tokens.push(value)
  })

  return tokens
}

/**
 * 数据表通用分页条，只负责展示服务端 total 与切换页码。
 */
export function TablePagination({
  page,
  pageSize,
  total,
  disabled = false,
  onPageChange,
}: TablePaginationProps) {
  const { t } = useTranslation()
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const tokens = useMemo(
    () => buildPageTokens(page, totalPages),
    [page, totalPages]
  )

  if (totalPages <= 1) return null

  return (
    <div className="flex max-w-full min-w-0 flex-wrap items-center justify-between gap-3">
      <p className="text-xs text-muted-foreground">
        {t("common.pageSummary", {
          page,
          totalPages,
          total,
        })}
      </p>
      <Pagination
        className="mx-0 w-full min-w-0 justify-start overflow-x-auto sm:w-auto sm:justify-end"
        aria-label={t("common.pagination")}
      >
        <PaginationContent className="w-max shrink-0">
          <PaginationItem>
            <PaginationPrevious
              text={t("common.previous")}
              aria-label={t("common.previousPage")}
              disabled={disabled || page <= 1}
              onClick={() => onPageChange(Math.max(1, page - 1))}
            />
          </PaginationItem>
          {tokens.map((token) =>
            typeof token === "number" ? (
              <PaginationItem key={token}>
                <PaginationLink
                  isActive={page === token}
                  disabled={disabled}
                  aria-label={t("common.goToPage", { page: token })}
                  onClick={() => onPageChange(token)}
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
              text={t("common.next")}
              aria-label={t("common.nextPage")}
              disabled={disabled || page >= totalPages}
              onClick={() => onPageChange(Math.min(totalPages, page + 1))}
            />
          </PaginationItem>
        </PaginationContent>
      </Pagination>
    </div>
  )
}
