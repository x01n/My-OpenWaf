"use client"

import { useMemo } from "react"
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import {
  chartAxisColor,
  chartGridColor,
  chartTooltipContentStyle,
  chartTooltipLabelStyle,
} from "@/components/charts/chart-theme"

interface QPSPoint {
  time: string
  qps: number
}

interface RealtimeQPSChartProps {
  data: QPSPoint[]
  height?: number
}

export function RealtimeQPSChart({
  data,
  height = 280,
}: RealtimeQPSChartProps) {
  const maxQPS = useMemo(() => {
    if (data.length === 0) return 100
    const max = Math.max(...data.map((d) => d.qps))
    return Math.ceil(max * 1.2)
  }, [data])

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart
        data={data}
        margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
      >
        <defs>
          <linearGradient id="qpsGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="var(--chart-1)" stopOpacity={0.3} />
            <stop offset="95%" stopColor="var(--chart-1)" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid
          strokeDasharray="3 3"
          stroke={chartGridColor}
          opacity={0.5}
        />
        <XAxis
          dataKey="time"
          stroke={chartAxisColor}
          fontSize={12}
          tickLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          stroke={chartAxisColor}
          fontSize={12}
          tickLine={false}
          domain={[0, maxQPS]}
          tickFormatter={(value) => `${value}`}
        />
        <Tooltip
          contentStyle={chartTooltipContentStyle}
          labelStyle={chartTooltipLabelStyle}
          formatter={(value) => [`${value ?? 0} req/s`, "QPS"]}
        />
        <Area
          type="monotone"
          dataKey="qps"
          stroke="var(--chart-1)"
          strokeWidth={2}
          fill="url(#qpsGradient)"
          animationDuration={300}
          isAnimationActive={true}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
