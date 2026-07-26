"use client";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { ReactNode } from "react";

/**
 * 指标的语义色调。
 *
 * 与 `lib/action-style.ts` 的动作分级同源：风险类指标用 danger/warning，
 * 健康类用 success，其余为 accent（跟随主题强调色）或 neutral。
 */
export type MetricTone = "accent" | "danger" | "warning" | "success" | "neutral";

/** 色调 -> 数值文字色 */
const TONE_VALUE: Record<MetricTone, string> = {
  accent: "text-foreground",
  danger: "text-rose-600 dark:text-rose-400",
  warning: "text-amber-600 dark:text-amber-400",
  success: "text-emerald-600 dark:text-emerald-400",
  neutral: "text-foreground",
};

/** 色调 -> 图标底片（半透明底 + 同色图标，浅/深色双向可读） */
const TONE_CHIP: Record<MetricTone, string> = {
  accent: "bg-primary/10 text-primary",
  danger: "bg-rose-500/12 text-rose-600 dark:bg-rose-400/15 dark:text-rose-400",
  warning: "bg-amber-500/12 text-amber-600 dark:bg-amber-400/15 dark:text-amber-400",
  success:
    "bg-emerald-500/12 text-emerald-600 dark:bg-emerald-400/15 dark:text-emerald-400",
  neutral: "bg-muted text-muted-foreground",
};

/** 色调 -> 左侧语义竖条 */
const TONE_RAIL: Record<MetricTone, string> = {
  accent: "bg-primary",
  danger: "bg-rose-500",
  warning: "bg-amber-500",
  success: "bg-emerald-500",
  neutral: "bg-border",
};

/** 色调 -> 迷你折线颜色 */
const TONE_SPARK: Record<MetricTone, string> = {
  accent: "text-primary",
  danger: "text-rose-500",
  warning: "text-amber-500",
  success: "text-emerald-500",
  neutral: "text-muted-foreground",
};

/**
 * 迷你趋势折线（内联 SVG，无额外依赖）。
 * 仅在调用方提供真实序列时渲染，不生成任何占位数据。
 */
function Sparkline({ points, label }: { points: number[]; label?: string }) {
  const max = Math.max(...points);
  const min = Math.min(...points);
  const span = max - min || 1;
  const width = 100;
  const height = 22;
  const stepX = width / (points.length - 1);
  const coords = points.map((p, i) => {
    const x = i * stepX;
    const y = height - ((p - min) / span) * (height - 2) - 1;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : "true"}
      className="h-5 w-full"
    >
      {label && <title>{label}</title>}
      <polyline
        points={`0,${height} ${coords.join(" ")} ${width},${height}`}
        fill="currentColor"
        fillOpacity="0.14"
        stroke="none"
      />
      <polyline
        points={coords.join(" ")}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

interface MetricTileProps {
  /** 指标名 */
  title: string;
  /** 已格式化的展示值 */
  value: string;
  /**
   * 原始数值，仅用于「零值降级」判断。
   * 传入 0 时整张卡降为 neutral 且降低对比度，避免空指标与有数据的指标抢注意力。
   */
  rawValue?: number;
  /** 补充说明，置于数值下方 */
  description?: string;
  icon?: ReactNode;
  tone?: MetricTone;
  /** 右上角徽章，通常用于标注统计口径（如 24h） */
  badge?: ReactNode;
  /** 迷你折线的真实序列，必须来自后端聚合，不足 2 点则不渲染 */
  sparkline?: number[];
  /** 折线含义说明；当折线口径与主数值不同时必须传入 */
  sparklineLabel?: string;
  className?: string;
}

/**
 * 主指标卡片。
 *
 * 相比 {@link StatCard}，本组件强调**语义分层**：通过左侧色条、图标底片与数值配色
 * 区分风险指标与健康指标，并在指标为 0 时主动降级，让有数据的指标占据视觉重心。
 */
export function MetricTile({
  title,
  value,
  rawValue,
  description,
  icon,
  tone = "neutral",
  badge,
  sparkline,
  sparklineLabel,
  className,
}: MetricTileProps) {
  const isZero = rawValue === 0;
  const effectiveTone: MetricTone = isZero ? "neutral" : tone;
  const points = sparkline && sparkline.length >= 2 ? sparkline : null;

  return (
    <Card
      className={cn(
        "group relative overflow-hidden py-0 transition-[border-color,box-shadow] duration-200",
        isZero ? "border-dashed bg-muted/25" : "hover:border-primary/35 hover:shadow-sm",
        className
      )}
    >
      {/* 左侧语义竖条：零值时不渲染，避免空指标被着色强调 */}
      {!isZero && (
        <span
          aria-hidden="true"
          className={cn(
            "pointer-events-none absolute inset-y-0 left-0 w-[3px]",
            TONE_RAIL[effectiveTone]
          )}
        />
      )}
      <CardContent className="px-3.5 py-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            {icon && (
              <span
                className={cn(
                  "flex size-6 shrink-0 items-center justify-center rounded-md",
                  isZero ? "bg-muted text-muted-foreground/70" : TONE_CHIP[effectiveTone]
                )}
              >
                {icon}
              </span>
            )}
            <span className="truncate text-xs font-medium text-muted-foreground">
              {title}
            </span>
          </div>
          {badge}
        </div>

        {/* 大号数值使用比例数字（非 tabular-nums）：等宽数字在展示字号下会显得松散 */}
        <div
          className={cn(
            "mt-2 text-2xl font-semibold leading-none tracking-tight",
            isZero ? "text-muted-foreground/60" : TONE_VALUE[effectiveTone]
          )}
        >
          {value}
        </div>

        {description && (
          <p className="mt-1.5 truncate text-[11px] leading-none text-muted-foreground">
            {description}
          </p>
        )}

        {points && (
          <div className={cn("mt-2 -mb-0.5", TONE_SPARK[effectiveTone])}>
            <Sparkline points={points} label={sparklineLabel} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
