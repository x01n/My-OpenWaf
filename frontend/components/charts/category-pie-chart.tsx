"use client"

import { useMemo } from "react"
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts"
import {
  categoricalChartColors,
  chartTooltipContentStyle,
} from "@/components/charts/chart-theme"

interface CategoryData {
  name: string
  value: number
}

interface CategoryPieChartProps {
  data: CategoryData[]
  height?: number
}

export function CategoryPieChart({
  data,
  height = 300,
}: CategoryPieChartProps) {
  const total = useMemo(() => {
    return data.reduce((sum, item) => sum + item.value, 0)
  }, [data])

  const renderCustomLabel = ({
    cx,
    cy,
    midAngle,
    innerRadius,
    outerRadius,
    percent,
  }: {
    cx?: number
    cy?: number
    midAngle?: number
    innerRadius?: number
    outerRadius?: number
    percent?: number
  }) => {
    if (
      !percent ||
      percent < 0.05 ||
      !cx ||
      !cy ||
      !midAngle ||
      !innerRadius ||
      !outerRadius
    )
      return null
    const RADIAN = Math.PI / 180
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5
    const x = cx + radius * Math.cos(-midAngle * RADIAN)
    const y = cy + radius * Math.sin(-midAngle * RADIAN)

    return (
      <text
        x={x}
        y={y}
        fill="white"
        textAnchor={x > cx ? "start" : "end"}
        dominantBaseline="central"
        fontSize={12}
        fontWeight={600}
      >
        {`${(percent * 100).toFixed(0)}%`}
      </text>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          labelLine={false}
          label={renderCustomLabel}
          outerRadius={100}
          fill="var(--chart-1)"
          dataKey="value"
          animationDuration={800}
          animationBegin={0}
        >
          {data.map((_, index) => (
            <Cell
              key={`cell-${index}`}
              fill={
                categoricalChartColors[index % categoricalChartColors.length]
              }
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={chartTooltipContentStyle}
          formatter={(value) => [
            `${value ?? 0} 次 (${((Number(value ?? 0) / total) * 100).toFixed(1)}%)`,
            "攻击",
          ]}
        />
        <Legend
          verticalAlign="bottom"
          height={36}
          iconType="circle"
          wrapperStyle={{ fontSize: "12px" }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
