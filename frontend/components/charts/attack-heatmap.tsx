"use client"

import { useMemo } from "react"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts"
import {
  attackIntensityColors,
  chartAxisColor,
  chartGridColor,
  chartTooltipContentStyle,
  chartTooltipLabelStyle,
} from "@/components/charts/chart-theme"

interface TimelinePoint {
  hour: string
  count: number
}

interface AttackHeatmapProps {
  data: TimelinePoint[]
  height?: number
}

export function AttackHeatmap({ data, height = 280 }: AttackHeatmapProps) {
  const { maxCount, colorScale } = useMemo(() => {
    if (data.length === 0) return { maxCount: 100, colorScale: [] }
    const max = Math.max(...data.map((d) => d.count))
    const scale = data.map((d) => {
      const intensity = max > 0 ? d.count / max : 0
      if (intensity > 0.8) return attackIntensityColors[4]
      if (intensity > 0.6) return attackIntensityColors[3]
      if (intensity > 0.4) return attackIntensityColors[2]
      if (intensity > 0.2) return attackIntensityColors[1]
      return attackIntensityColors[0]
    })
    return { maxCount: max, colorScale: scale }
  }, [data])

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
        <CartesianGrid
          strokeDasharray="3 3"
          stroke={chartGridColor}
          opacity={0.5}
        />
        <XAxis
          dataKey="hour"
          stroke={chartAxisColor}
          fontSize={12}
          tickLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          stroke={chartAxisColor}
          fontSize={12}
          tickLine={false}
          domain={[0, maxCount * 1.1]}
        />
        <Tooltip
          contentStyle={chartTooltipContentStyle}
          labelStyle={chartTooltipLabelStyle}
          formatter={(value) => [`${value ?? 0} 次`, "攻击"]}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} animationDuration={500}>
          {data.map((_, index) => (
            <Cell key={`cell-${index}`} fill={colorScale[index]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
