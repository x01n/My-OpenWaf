"use client";

import { Skeleton } from "@heroui/react";

/** 表格加载骨架：固定行高的条状占位。 */
export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2.5 p-1">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full rounded-lg" />
      ))}
    </div>
  );
}

/** 卡片加载骨架：高度可配置的圆角占位。 */
export function CardSkeleton({ height = "h-32" }: { height?: string }) {
  return <Skeleton className={`w-full rounded-xl ${height}`} />;
}
