"use client";

import { useEffect, useState } from "react";
import { getFingerprints, type FingerprintStats } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
  type PieLabelRenderProps,
} from "recharts";
import { AlertTriangle } from "lucide-react";

const PIE_COLORS = ["#14b8a6", "#f59e0b", "#6366f1", "#ef4444", "#8b5cf6", "#ec4899", "#06b6d4", "#84cc16"];

function formatDate(s: string) {
  if (!s) return "-";
  return new Date(s).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function FingerprintsPage() {
  const [data, setData] = useState<FingerprintStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getFingerprints()
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="space-y-5">
        <div>
          <h1 className="text-xl font-semibold text-gray-800">指纹分析</h1>
          <p className="text-gray-500 text-sm mt-0.5">TLS指纹统计与异常分析</p>
        </div>
        <div className="py-12 text-center text-gray-400">加载中...</div>
      </div>
    );
  }

  const ja3Top = data?.ja3_top ?? [];
  const ja4Top = data?.ja4_top ?? [];
  const browserDist = data?.browser_distribution ?? [];
  const anomalies = data?.anomalies ?? [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-gray-800">指纹分析</h1>
        <p className="text-gray-500 text-sm mt-0.5">TLS指纹统计与异常分析</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* JA3 Top */}
        <div className="bg-white border border-gray-200 rounded-lg p-5">
          <h3 className="text-sm font-medium text-gray-700 mb-3">JA3 Top 指纹</h3>
          {ja3Top.length === 0 ? (
            <div className="py-8 text-center text-sm text-gray-400">暂无数据</div>
          ) : (
            <div className="space-y-2">
              {ja3Top.map((item, i) => (
                <div key={item.hash} className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 w-5">{i + 1}</span>
                  <code className="text-xs font-mono text-gray-600 truncate flex-1">{item.hash}</code>
                  <Badge variant="secondary" className="text-xs tabular-nums">{item.count}</Badge>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* JA4 Top */}
        <div className="bg-white border border-gray-200 rounded-lg p-5">
          <h3 className="text-sm font-medium text-gray-700 mb-3">JA4 Top 指纹</h3>
          {ja4Top.length === 0 ? (
            <div className="py-8 text-center text-sm text-gray-400">暂无数据</div>
          ) : (
            <div className="space-y-2">
              {ja4Top.map((item, i) => (
                <div key={item.hash} className="flex items-center gap-3">
                  <span className="text-xs text-gray-400 w-5">{i + 1}</span>
                  <code className="text-xs font-mono text-gray-600 truncate flex-1">{item.hash}</code>
                  <Badge variant="secondary" className="text-xs tabular-nums">{item.count}</Badge>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Browser Distribution */}
      <div className="bg-white border border-gray-200 rounded-lg p-5">
        <h3 className="text-sm font-medium text-gray-700 mb-3">浏览器分布</h3>
        {browserDist.length === 0 ? (
          <div className="py-8 text-center text-sm text-gray-400">暂无数据</div>
        ) : (
          <div className="flex flex-col lg:flex-row items-center gap-6">
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={browserDist}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  label={(props: PieLabelRenderProps) => `${props.name ?? ""} ${((props.percent ?? 0) * 100).toFixed(0)}%`}
                >
                  {browserDist.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Anomalies */}
      <div className="bg-white border border-gray-200 rounded-lg p-5">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="h-4 w-4 text-amber-500" />
          <h3 className="text-sm font-medium text-gray-700">异常指纹告警</h3>
        </div>
        {anomalies.length === 0 ? (
          <div className="py-8 text-center text-sm text-gray-400">暂无异常指纹</div>
        ) : (
          <div className="rounded-lg border border-gray-200 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-gray-50">
                  <TableHead className="text-gray-600 font-medium">指纹Hash</TableHead>
                  <TableHead className="text-gray-600 font-medium">异常原因</TableHead>
                  <TableHead className="text-gray-600 font-medium w-[80px]">次数</TableHead>
                  <TableHead className="text-gray-600 font-medium w-[130px]">最后出现</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anomalies.map((a) => (
                  <TableRow key={a.hash} className="hover:bg-gray-50">
                    <TableCell className="font-mono text-xs">{a.hash}</TableCell>
                    <TableCell className="text-sm text-gray-600">{a.reason}</TableCell>
                    <TableCell>
                      <Badge variant="destructive" className="text-xs">{a.count}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-gray-500">{formatDate(a.last_seen)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}
