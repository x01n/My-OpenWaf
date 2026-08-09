"use client"

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Skeleton } from "@/components/ui/skeleton"
import { EmptyState } from "@/components/empty-state"
import { cn } from "@/lib/utils"
import { ReactNode } from "react"
import { useTranslation } from "react-i18next"
import { IconInbox } from "@tabler/icons-react"

/** 骨架屏行数：与列表页默认 pageSize 无关，仅用于占位，避免过长的空白区 */
const SKELETON_ROWS = 6

/** 骨架单元格宽度循环，制造参差感，避免整片等宽色块 */
const SKELETON_WIDTHS = ["w-4/5", "w-3/5", "w-full", "w-2/5", "w-3/4"]

interface Column<T> {
  key: string
  title: string | ReactNode
  width?: string
  cellClassName?: string
  render?: (row: T, index: number) => ReactNode
}

interface DataTableProps<T = unknown> {
  columns: Column<T>[]
  data: T[]
  loading?: boolean
  rowKey?: (row: T) => string | number
  emptyText?: string
  emptyContent?: ReactNode
  className?: string
}

export function DataTable<T = unknown>({
  columns,
  data,
  loading,
  rowKey,
  emptyText = "",
  emptyContent,
  className,
}: DataTableProps<T>) {
  const { t } = useTranslation()

  if (loading) {
    return (
      <div
        className={cn(
          "max-w-full min-w-0 overflow-hidden rounded-md border",
          className
        )}
      >
        <Table>
          {/* 加载态保留真实表头文本：列宽提前确定，数据到达时不再抖动 */}
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              {columns.map((col) => (
                <TableHead key={col.key} style={{ width: col.width }}>
                  {col.title}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {Array.from({ length: SKELETON_ROWS }).map((_, rowIdx) => (
              <TableRow key={rowIdx} className="hover:bg-transparent">
                {columns.map((col, colIdx) => (
                  <TableCell key={col.key} className={col.cellClassName}>
                    <Skeleton
                      className={cn(
                        "h-4",
                        SKELETON_WIDTHS[
                          (rowIdx + colIdx) % SKELETON_WIDTHS.length
                        ]
                      )}
                    />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    )
  }

  if (!data || data.length === 0) {
    if (emptyContent) {
      return <>{emptyContent}</>
    }
    return (
      <EmptyState
        icon={IconInbox}
        title={emptyText || t("common.empty")}
        className={cn("py-12", className)}
      />
    )
  }

  return (
    <div
      className={cn(
        "max-w-full min-w-0 overflow-hidden rounded-md border",
        className
      )}
    >
      <Table>
        <TableHeader className="bg-muted/40">
          <TableRow className="hover:bg-transparent">
            {columns.map((col) => (
              <TableHead
                key={col.key}
                style={{ width: col.width }}
                className="text-xs font-semibold text-muted-foreground"
              >
                {col.title}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((row, index) => (
            <TableRow
              key={rowKey ? rowKey(row) : index}
              className="hover:bg-primary/[0.06] dark:hover:bg-primary/[0.12]"
            >
              {columns.map((col) => (
                <TableCell key={col.key} className={col.cellClassName}>
                  {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                  {col.render ? col.render(row, index) : (row as any)[col.key]}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
