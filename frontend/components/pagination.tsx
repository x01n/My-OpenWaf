"use client"

import { ChevronLeft, ChevronRight } from "@/lib/icons"
import { Button } from "@/components/ui/button"

interface PaginationProps {
  page: number
  totalPages: number
  total: number
  pageSize: number
  onPageChange: (page: number) => void
}

export function Pagination({
  page,
  totalPages,
  total,
  pageSize,
  onPageChange,
}: PaginationProps) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-muted/35 px-4 py-3 text-sm text-muted-foreground md:flex-row md:items-center md:justify-between">
      <span>
        每页 {pageSize} 条，共 {total} 条
      </span>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="icon-sm"
          className="rounded-md"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          aria-label="上一页"
        >
          <ChevronLeft data-icon="inline-start" />
        </Button>
        <span className="px-2 text-foreground">
          {page} / {totalPages}
        </span>
        <Button
          variant="outline"
          size="icon-sm"
          className="rounded-md"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
          aria-label="下一页"
        >
          <ChevronRight data-icon="inline-start" />
        </Button>
      </div>
    </div>
  )
}
