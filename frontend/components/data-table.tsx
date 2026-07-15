"use client";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { ReactNode } from "react";
import { useTranslation } from "react-i18next";

interface Column<T> {
  key: string;
  title: string | ReactNode;
  width?: string;
  render?: (row: T, index: number) => ReactNode;
}

interface DataTableProps<T = unknown> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  rowKey?: (row: T) => string | number;
  emptyText?: string;
  emptyContent?: ReactNode;
  className?: string;
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
  const { t } = useTranslation();
  if (loading) {
    return (
      <div className={cn("rounded-md border", className)}>
        <Table>
          <TableHeader>
            <TableRow>
              {columns.map((col) => (
                <TableHead key={col.key} style={{ width: col.width }}>
                  <Skeleton className="h-4 w-20" />
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {Array.from({ length: 5 }).map((_, i) => (
              <TableRow key={i}>
                {columns.map((col) => (
                  <TableCell key={col.key}>
                    <Skeleton className="h-4 w-full" />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    );
  }

  if (!data || data.length === 0) {
    if (emptyContent) {
      return <>{emptyContent}</>;
    }
    return (
      <div className={cn("flex h-40 items-center justify-center rounded-md border text-sm text-muted-foreground", className)}>
        {emptyText || t("common.empty")}
      </div>
    );
  }

  return (
    <div className={cn("rounded-md border", className)}>
      <Table>
        <TableHeader>
          <TableRow>
            {columns.map((col) => (
              <TableHead key={col.key} style={{ width: col.width }}>
                {col.title}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((row, index) => (
            <TableRow key={rowKey ? rowKey(row) : index}>
              {columns.map((col) => (
                <TableCell key={col.key}>
                  {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                  {col.render ? col.render(row, index) : (row as any)[col.key]}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
