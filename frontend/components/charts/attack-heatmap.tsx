"use client";

import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface TimelinePoint {
  hour: string;
  count: number;
}

interface AttackHeatmapProps {
  data: TimelinePoint[];
  height?: number;
}

export function AttackHeatmap({ data, height = 280 }: AttackHeatmapProps) {
  const { maxCount, colorScale } = useMemo(() => {
    if (data.length === 0) return { maxCount: 100, colorScale: [] };
    const max = Math.max(...data.map((d) => d.count));
    const scale = data.map((d) => {
      const intensity = max > 0 ? d.count / max : 0;
      if (intensity > 0.8) return "#dc2626"; // red-600
      if (intensity > 0.6) return "#ea580c"; // orange-600
      if (intensity > 0.4) return "#f59e0b"; // amber-500
      if (intensity > 0.2) return "#eab308"; // yellow-500
      return "#22c55e"; // green-500
    });
    return { maxCount: max, colorScale: scale };
  }, [data]);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart
        data={data}
        margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" opacity={0.5} />
        <XAxis
          dataKey="hour"
          stroke="#6b7280"
          fontSize={12}
          tickLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          stroke="#6b7280"
          fontSize={12}
          tickLine={false}
          domain={[0, maxCount * 1.1]}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "rgba(255, 255, 255, 0.95)",
            border: "1px solid #e5e7eb",
            borderRadius: "8px",
            boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
          }}
          labelStyle={{ color: "#374151", fontWeight: 600 }}
          formatter={(value) => [`${value ?? 0} 次`, "攻击"]}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} animationDuration={500}>
          {data.map((_, index) => (
            <Cell key={`cell-${index}`} fill={colorScale[index]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
