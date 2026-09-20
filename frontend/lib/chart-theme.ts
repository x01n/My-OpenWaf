/**
 * Recharts 图表的主题 token。
 *
 * 注意：`app/globals.css` 的设计变量是 **oklch()** 形式（例如 `--primary: oklch(0.527 0.154 178.0)`），
 * 因此不能写成 `hsl(var(--primary))` —— 嵌套后是无效颜色值，浏览器会丢弃，
 * 图表会回落到 recharts 默认色。变量必须直接使用 `var(--primary)`。
 */

import type { CSSProperties } from "react"
import type { TextProps } from "recharts"

/** Tooltip 容器样式，跟随浅/深色主题 */
export const chartTooltipStyle: CSSProperties = {
  backgroundColor: "var(--popover)",
  color: "var(--popover-foreground)",
  border: "1px solid var(--border)",
  borderRadius: "10px",
  fontSize: "12px",
  padding: "8px 10px",
  boxShadow: "0 8px 24px -8px rgb(0 0 0 / 0.28)",
}

/** Tooltip 文字/标签样式 */
export const chartTooltipLabelStyle: CSSProperties = {
  color: "var(--muted-foreground)",
  fontSize: "11px",
  marginBottom: "2px",
}

/**
 * 主色系列（跟随 accent 主题切换）。
 *
 * 指向 `--chart-accent` 而非 `--primary`：深色模式下 `--primary` 对卡片背景仅 2.64:1，
 * 低于图表标记要求的 3:1，折线会暗到看不清。`--chart-accent` 是按卡面校验过的等价色。
 */
export const CHART_ACCENT = "var(--chart-accent)"

/** @deprecated 保留旧名以兼容既有引用，语义同 {@link CHART_ACCENT} */
export const CHART_PRIMARY = CHART_ACCENT

/** 危险色：用于拦截/攻击类序列，固定红色以保持语义，不随 accent 变化 */
export const CHART_DANGER = "var(--chart-danger)"

/** 危险色的浅填充（渐变不可用时的兜底纯色填充） */
export const CHART_DANGER_FILL = "rgba(239, 68, 68, 0.12)"

/** 网格线：实心发丝线。虚线网格会读作「阈值/预测」，是明确的反模式。 */
export const CHART_GRID_STROKE = "var(--border)"

/**
 * 坐标轴刻度文字样式。
 * 类型必须是 recharts 的 `TextProps`（`tick` 属性的联合分支之一），
 * 用 `CSSProperties` 会让 `tick` 的联合类型推断失败。
 */
export const CHART_AXIS_TICK: TextProps = {
  fill: "var(--muted-foreground)",
  fontSize: 10,
}

/** 面积图渐变填充的通用停靠点（配合 <defs><linearGradient> 使用） */
export const CHART_AREA_GRADIENT_STOPS = [
  { offset: "0%", opacity: 0.28 },
  { offset: "100%", opacity: 0.02 },
] as const
