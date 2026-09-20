"use client"

import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { ReactNode } from "react"

/** 单个次要指标 */
export interface MetricStripItem {
  /** 指标名 */
  label: string
  /** 已格式化的展示值 */
  value: string
  /**
   * 原始数值，仅用于「零值降级」判断。
   * 为 0 时该项以低对比度渲染，让有数据的指标先被看到。
   */
  rawValue?: number
  /** 悬停提示，用于说明统计口径 */
  hint?: string
}

interface MetricStripProps {
  /** 分组标题，用于声明这一组指标的统计口径 */
  title: string
  /** 口径补充说明（例如「自进程启动累计，重启后归零」） */
  caption?: string
  /** 标题右侧插槽，通常放徽章 */
  action?: ReactNode
  items: MetricStripItem[]
  className?: string
}

/**
 * 次要指标条。
 *
 * 用一张卡片承载多个低优先级指标，去掉每项的卡片外壳，
 * 以「标签在上、数值在下」的紧凑网格排布，在同等高度内容纳数倍信息量。
 * 适合放置 4xx/5xx 这类经常为 0、但仍需可见的运行时计数。
 */
export function MetricStrip({
  title,
  caption,
  action,
  items,
  className,
}: MetricStripProps) {
  return (
    <Card className={cn("py-0", className)}>
      <CardContent className="px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-xs font-semibold text-foreground">{title}</h3>
            {caption && (
              <p className="mt-0.5 text-[11px] leading-tight text-muted-foreground">
                {caption}
              </p>
            )}
          </div>
          {action}
        </div>

        <dl className="mt-3 grid grid-cols-3 gap-x-4 gap-y-3 border-t border-border/60 pt-3 sm:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8">
          {items.map((item) => {
            const isZero = item.rawValue === 0
            return (
              <div key={item.label} className="min-w-0" title={item.hint}>
                <dt className="truncate text-[11px] leading-none text-muted-foreground">
                  {item.label}
                </dt>
                <dd
                  className={cn(
                    "mt-1.5 text-base leading-none font-semibold tabular-nums",
                    isZero ? "text-muted-foreground/45" : "text-foreground"
                  )}
                >
                  {item.value}
                </dd>
              </div>
            )
          })}
        </dl>
      </CardContent>
    </Card>
  )
}
