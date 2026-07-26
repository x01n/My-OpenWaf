"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, formatNumber } from "@/lib/utils";
import { ReactNode } from "react";

/** 排行项。`label` 必须是后端原样返回的标识，不做任何改写。 */
export interface RankedItem {
  label: string;
  count: number;
}

interface RankedBarListProps {
  title: string;
  /** 标题右侧插槽，通常放统计口径徽章 */
  action?: ReactNode;
  /** 排行数据，需已按 count 降序；组件不再重排以保持与后端口径一致 */
  items: RankedItem[];
  /** 最多展示的条目数，超出部分折叠为一条汇总项 */
  maxItems?: number;
  /** 折叠项的文案生成器，入参为被折叠的类别数 */
  restLabel?: (restCount: number) => string;
  /** 空数据文案 */
  emptyText: string;
  /** 条形色调 */
  tone?: "danger" | "accent";
  /** 标签是否用等宽字体（规则 ID、类别名等标识符建议开启） */
  mono?: boolean;
  className?: string;
}

/**
 * 排行条形列表。
 *
 * 相比饼图，条形长度是比较数量的正确编码方式：类别多于 6 个时饼图不可读，
 * 且颜色循环会让两个不相邻的类别撞色。此处所有条形共用一个色调 ——
 * 类别之间没有天然顺序，长度已经表达了数量，颜色不应重复编码同一信息。
 * 每条均直接标注数值与占比，因此无需依赖 tooltip 才能读数。
 */
export function RankedBarList({
  title,
  action,
  items,
  maxItems = 8,
  restLabel,
  emptyText,
  tone = "danger",
  mono = true,
  className,
}: RankedBarListProps) {
  const total = items.reduce((sum, it) => sum + it.count, 0);
  const head = items.slice(0, maxItems);
  const rest = items.slice(maxItems);
  const restSum = rest.reduce((sum, it) => sum + it.count, 0);

  // 条形长度相对「最大值」而非总量，避免长尾类别全部塌缩成看不见的一条
  const peak = head.length > 0 ? head[0].count : 0;

  const barClass =
    tone === "danger"
      ? "bg-rose-500/70 dark:bg-rose-400/70"
      : "bg-primary/70";

  const rows: Array<RankedItem & { faded?: boolean }> = [...head];
  if (rest.length > 0 && restSum > 0 && restLabel) {
    rows.push({ label: restLabel(rest.length), count: restSum, faded: true });
  }

  return (
    <Card className={cn("py-0", className)}>
      <CardHeader className="flex-row items-center justify-between gap-2 px-4 py-2.5">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {action}
      </CardHeader>
      <CardContent className="px-4 pb-3.5 pt-0">
        {rows.length === 0 ? (
          <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
            {emptyText}
          </div>
        ) : (
          <ul className="space-y-1.5">
            {rows.map((row) => {
              const share = total > 0 ? (row.count / total) * 100 : 0;
              const width = peak > 0 ? Math.max(1.5, (row.count / peak) * 100) : 0;
              return (
                <li key={row.label} className="group">
                  <div className="flex items-baseline justify-between gap-3">
                    <span
                      className={cn(
                        "min-w-0 flex-1 truncate text-xs",
                        mono && "font-mono",
                        row.faded ? "text-muted-foreground" : "text-foreground"
                      )}
                      title={row.label}
                    >
                      {row.label}
                    </span>
                    <span className="shrink-0 text-xs font-semibold tabular-nums text-foreground">
                      {formatNumber(row.count)}
                    </span>
                    <span className="w-12 shrink-0 text-right text-[11px] tabular-nums text-muted-foreground">
                      {share.toFixed(1)}%
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className={cn(
                        "h-full rounded-full transition-[width] duration-500",
                        row.faded ? "bg-muted-foreground/35" : barClass
                      )}
                      style={{ width: `${width}%` }}
                    />
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
