"use client";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { ReactNode, useEffect, useRef, useState } from "react";

/** 数值过渡时长（毫秒） */
const COUNT_DURATION = 520;

/** 从已格式化的展示值中拆出「前导数字 + 后缀」，例如 "12.5k" -> [12.5, "k"]、"3.45%" -> [3.45, "%"] */
const NUMERIC_PREFIX = /^(-?\d+(?:\.\d+)?)([\s\S]*)$/;

/** 是否偏好减少动效 */
function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * 数值平滑过渡。
 *
 * 首屏直接渲染最终值（静态导出无 hydration 偏差，也不产生 CLS）；
 * 仅当 SWR 轮询带来新值时，从旧值插值到新值，避免数字硬跳。
 * @param {string | number} value 目标展示值（可能已被 formatNumber 格式化）
 * @returns {string} 当前应渲染的文本
 */
function useAnimatedValue(value: string | number): string {
  const target = String(value);
  const [display, setDisplay] = useState(target);
  const prevRef = useRef(target);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    const from = prevRef.current;
    prevRef.current = target;
    if (from === target) return;

    const fromMatch = NUMERIC_PREFIX.exec(from);
    const toMatch = NUMERIC_PREFIX.exec(target);
    // 非数值型（如 "-"）或单位不一致（"999" -> "1.2k"）时不插值，直接切换
    if (!fromMatch || !toMatch || fromMatch[2] !== toMatch[2] || prefersReducedMotion()) {
      setDisplay(target);
      return;
    }

    const fromNum = Number(fromMatch[1]);
    const toNum = Number(toMatch[1]);
    const suffix = toMatch[2];
    // 小数位跟随目标值，保证过渡结束前后格式一致
    const decimals = (toMatch[1].split(".")[1] ?? "").length;
    const start = performance.now();

    const step = (now: number) => {
      const progress = Math.min(1, (now - start) / COUNT_DURATION);
      if (progress >= 1) {
        setDisplay(target);
        frameRef.current = null;
        return;
      }
      // easeOutCubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = fromNum + (toNum - fromNum) * eased;
      setDisplay(current.toFixed(decimals) + suffix);
      frameRef.current = requestAnimationFrame(step);
    };

    frameRef.current = requestAnimationFrame(step);
    return () => {
      if (frameRef.current !== null) {
        cancelAnimationFrame(frameRef.current);
        frameRef.current = null;
      }
    };
  }, [target]);

  return display;
}

/**
 * 迷你趋势折线（内联 SVG，无额外依赖）。
 * 仅在调用方提供真实序列数据时渲染，不生成任何占位数据。
 */
function Sparkline({
  points,
  label,
  className,
}: {
  points: number[];
  /** 折线含义说明（时间范围等），作为原生 tooltip 与无障碍标签 */
  label?: string;
  className?: string;
}) {
  if (points.length < 2) return null;

  const max = Math.max(...points);
  const min = Math.min(...points);
  const span = max - min || 1;
  const width = 100;
  const height = 24;
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
      className={cn("h-6 w-full", className)}
    >
      {label && <title>{label}</title>}
      <polyline
        points={`0,${height} ${coords.join(" ")} ${width},${height}`}
        fill="currentColor"
        fillOpacity="0.12"
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

interface StatCardProps {
  title: string;
  value: string | number;
  description?: string;
  icon?: ReactNode;
  /**
   * description 的语义着色意图（非趋势判断）：
   * up=正向/绿、down=风险/红、neutral=中性。不会渲染任何趋势箭头，
   * 以免在没有真实同比数据时暗示涨跌。
   */
  trend?: "up" | "down" | "neutral";
  className?: string;
  /** 紧凑模式：减少内边距，缩小文字 */
  compact?: boolean;
  /**
   * 迷你趋势折线的真实数据序列。必须来自后端聚合结果，
   * 不传则不渲染折线区域（不占位、不产生高度差）。
   */
  sparkline?: number[];
  /** 折线的语义色调，默认跟随 primary */
  sparklineTone?: "primary" | "danger";
  /**
   * 折线的含义说明。当折线的统计范围与主数值不同（例如主数值为累计、折线为近 N 小时）时
   * 必须传入，避免读者误认为两者同源。
   */
  sparklineLabel?: string;
}

export function StatCard({
  title,
  value,
  description,
  icon,
  trend,
  className,
  compact,
  sparkline,
  sparklineTone = "primary",
  sparklineLabel,
}: StatCardProps) {
  const display = useAnimatedValue(value);
  const sparklineColor =
    sparklineTone === "danger" ? "text-destructive" : "text-primary";
  const sparklinePoints = sparkline && sparkline.length >= 2 ? sparkline : null;

  if (compact) {
    return (
      <Card
        className={cn(
          "group relative overflow-hidden transition-[border-color,box-shadow] duration-200",
          "hover:border-primary/35 hover:shadow-sm",
          className
        )}
      >
        {/* 悬停时浮现的顶部语义高亮条 */}
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-px scale-x-0 bg-gradient-to-r from-transparent via-primary to-transparent opacity-0 transition-[transform,opacity] duration-300 group-hover:scale-x-100 group-hover:opacity-100"
        />
        <CardContent className="px-3 py-2.5">
          <div className="flex items-start justify-between">
            <span className="text-xs font-medium text-muted-foreground leading-none">
              {title}
            </span>
            {icon && (
              <div className="shrink-0 text-muted-foreground/60 transition-colors duration-200 group-hover:text-primary">
                {icon}
              </div>
            )}
          </div>
          <div className="mt-1.5 text-xl font-bold leading-none tracking-tight tabular-nums">
            {display}
          </div>
          {description && (
            <p
              className={cn(
                "text-[11px] mt-1 leading-none",
                trend === "up" && "text-emerald-600 dark:text-emerald-400",
                trend === "down" && "text-red-600 dark:text-red-400",
                !trend && "text-muted-foreground"
              )}
            >
              {description}
            </p>
          )}
          {sparklinePoints && (
            <div className={cn("mt-2 -mb-0.5", sparklineColor)}>
              <Sparkline points={sparklinePoints} label={sparklineLabel} />
            </div>
          )}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card
      className={cn(
        "group transition-[border-color,box-shadow] duration-200 hover:border-primary/35 hover:shadow-sm",
        className
      )}
    >
      <CardContent className="px-4 py-3">
        <div className="flex items-center justify-between space-y-0 pb-1.5">
          <span className="text-sm font-medium text-muted-foreground">
            {title}
          </span>
          {icon && (
            <div className="text-muted-foreground transition-colors duration-200 group-hover:text-primary">
              {icon}
            </div>
          )}
        </div>
        <div className="text-2xl font-bold tracking-tight tabular-nums">
          {display}
        </div>
        {description && (
          <p
            className={cn(
              "text-xs mt-1",
              trend === "up" && "text-emerald-600 dark:text-emerald-400",
              trend === "down" && "text-red-600 dark:text-red-400",
              trend === "neutral" && "text-muted-foreground"
            )}
          >
            {description}
          </p>
        )}
        {sparklinePoints && (
          <div className={cn("mt-2.5", sparklineColor)}>
            <Sparkline points={sparklinePoints} label={sparklineLabel} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
