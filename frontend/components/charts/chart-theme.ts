import type { CSSProperties } from "react"

export const chartGridColor = "var(--border)"
export const chartAxisColor = "var(--muted-foreground)"

export const chartTooltipContentStyle = {
  backgroundColor: "var(--popover)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--popover-foreground)",
  fontSize: 12,
  boxShadow: "var(--shadow-sm)",
} satisfies CSSProperties

export const chartTooltipLabelStyle = {
  color: "var(--popover-foreground)",
  fontWeight: 600,
} satisfies CSSProperties

export const categoricalChartColors = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--primary)",
  "var(--destructive)",
  "var(--accent)",
  "color-mix(in oklch, var(--chart-1) 76%, var(--foreground))",
  "color-mix(in oklch, var(--chart-2) 76%, var(--foreground))",
  "color-mix(in oklch, var(--chart-3) 76%, var(--foreground))",
  "color-mix(in oklch, var(--chart-4) 76%, var(--foreground))",
  "color-mix(in oklch, var(--chart-5) 76%, var(--foreground))",
  "color-mix(in oklch, var(--primary) 68%, var(--foreground))",
  "color-mix(in oklch, var(--destructive) 68%, var(--foreground))",
  "color-mix(in oklch, var(--accent) 68%, var(--foreground))",
]

export const attackIntensityColors = [
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--destructive)",
  "color-mix(in oklch, var(--destructive) 86%, var(--foreground))",
]
