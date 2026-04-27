"use client";

import { useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface QPSPoint {
  time: string;
  qps: number;
}

interface RealtimeQPSChartProps {
  data: QPSPoint[];
  height?: number;
}

export function RealtimeQPSChart({ data, height = 280 }: RealtimeQPSChartProps) {
  const maxQPS = useMemo(() => {
    if (data.length === 0) return 100;
    const max = Math.max(...data.map((d) => d.qps));
    return Math.ceil(max * 1.2);
  }, [data]);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart
        data={data}
        margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
      >
        <defs>
          <linearGradient id="qpsGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" opacity={0.5} />
        <XAxis
          dataKey="time"
          stroke="#6b7280"
          fontSize={12}
          tickLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          stroke="#6b7280"
          fontSize={12}
          tickLine={false}
          domain={[0, maxQPS]}
          tickFormatter={(value) => `${value}`}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "rgba(255, 255, 255, 0.95)",
            border: "1px solid #e5e7eb",
            borderRadius: "8px",
            boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
          }}
          labelStyle={{ color: "#374151", fontWeight: 600 }}
          formatter={(value) => [`${value ?? 0} req/s`, "QPS"]}
        />
        <Area
          type="monotone"
          dataKey="qps"
          stroke="#3b82f6"
          strokeWidth={2}
          fill="url(#qpsGradient)"
          animationDuration={300}
          isAnimationActive={true}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
