"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Eye,
  RefreshCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Button } from "@/components/ui/button";
import {
  getDashboardSummary,
  getSecurityEvents,
  getSecurityEventStats,
  getSecurityTimeline,
  type DashboardSummary,
  type SecurityEvent,
  type SecurityStats,
  type TimelineBucket,
} from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { toast } from "sonner";

const PIE_COLORS = ["#0ea5e9", "#94a3b8", "#f59e0b", "#ef4444", "#14b8a6", "#64748b"];

function fmt(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return value.toLocaleString();
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);
  const [stats, setStats] = useState<SecurityStats | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const [dashRes, tlRes, statsRes, eventsRes] = await Promise.all([
        getDashboardSummary(),
        getSecurityTimeline(24),
        getSecurityEventStats(24),
        getSecurityEvents({ limit: 5, page_size: 5 }),
      ]);
      setSummary(dashRes);
      setTimeline(tlRes.buckets ?? []);
      setStats(statsRes);
      setEvents(eventsRes.items ?? []);
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") load();
    }, 15000);
    return () => clearInterval(timer);
  }, []);

  const timelineData = useMemo(
    () =>
      timeline.map((b) => ({
        time: b.bucket.includes(" ") ? b.bucket.split(" ").pop() : b.bucket,
        count: b.count,
      })),
    [timeline],
  );

  const categoryData = useMemo(() => (stats?.categories ?? []).filter((c) => c.count > 0), [stats]);

  const statCards = summary
    ? [
        { label: "PV 总量", value: fmt(summary.requests_total), icon: Eye, change: `${fmt(summary.status_2xx)} 成功`, up: true },
        { label: "拦截数", value: fmt(summary.waf_blocks), icon: ShieldAlert, change: `${fmt(summary.waf_observes)} 观察`, up: summary.waf_blocks > 0 },
        { label: "独立访客 (UV)", value: fmt(summary.bot_total_24h), icon: Users, change: "近 24 小时", up: true },
        { label: "活跃规则数", value: fmt(summary.builtin_hits), icon: ShieldCheck, change: `修订版本 ${summary.revision}`, up: true },
      ]
    : [];

  const actionLabel = (action: string) => {
    const map: Record<string, { text: string; cls: string }> = {
      intercept: { text: "拦截", cls: "bg-red-50 text-red-700" },
      block: { text: "阻断", cls: "bg-red-50 text-red-700" },
      observe: { text: "观察", cls: "bg-amber-50 text-amber-700" },
      drop: { text: "丢弃", cls: "bg-rose-50 text-rose-700" },
      challenge: { text: "质询", cls: "bg-cyan-50 text-cyan-700" },
    };
    return map[action] ?? { text: action, cls: "bg-gray-100 text-gray-700" };
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-950 dark:text-slate-50">总览仪表板</h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">实时安全态势与流量统计</p>
        </div>
        <Button onClick={load} disabled={loading} className="rounded-md bg-slate-950 text-white hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-950 dark:hover:bg-slate-200">
          <RefreshCcw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          刷新
        </Button>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {loading && !summary
          ? Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-[120px] animate-pulse rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900" />)
          : statCards.map((card) => (
              <div key={card.label} className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-500 dark:text-slate-400">{card.label}</span>
                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-slate-100 dark:bg-slate-800">
                    <card.icon className="h-4.5 w-4.5 text-slate-600 dark:text-slate-300" />
                  </div>
                </div>
                <div className="mt-2 text-2xl font-semibold text-slate-950 dark:text-slate-50">{card.value}</div>
                <div className="mt-1 flex items-center text-xs text-slate-500 dark:text-slate-400">
                  {card.up ? <ArrowUpRight className="mr-1 h-3.5 w-3.5 text-emerald-500" /> : <ArrowDownRight className="mr-1 h-3.5 w-3.5 text-red-500" />}
                  {card.change}
                </div>
              </div>
            ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="col-span-1 rounded-lg border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900 xl:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-slate-950 dark:text-slate-50">流量趋势</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">近 24 小时安全事件时间线</p>
            </div>
            <Activity className="h-5 w-5 text-slate-400" />
          </div>
          <div className="h-[300px]">
            {timelineData.length === 0 ? (
              <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50 text-sm text-slate-400 dark:border-slate-800 dark:bg-slate-950">
                暂无时间线数据
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={timelineData} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: "#64748b" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: "#64748b" }} axisLine={false} tickLine={false} width={40} />
                  <Tooltip
                    contentStyle={{
                      borderRadius: 8,
                      border: "1px solid #e2e8f0",
                      boxShadow: "0 2px 8px rgba(15,23,42,0.08)",
                    }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#0ea5e9" strokeWidth={2} fill="url(#colorCount)" name="事件数" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="mb-4">
            <h3 className="text-base font-semibold text-slate-950 dark:text-slate-50">安全事件分类</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">按攻击类型分布</p>
          </div>
          {categoryData.length === 0 ? (
            <div className="flex h-[300px] items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50 text-sm text-slate-400 dark:border-slate-800 dark:bg-slate-950">
              暂无分类数据
            </div>
          ) : (
            <>
              <div className="flex justify-center">
                <ResponsiveContainer width={220} height={220}>
                  <PieChart>
                    <Pie data={categoryData} dataKey="count" nameKey="category" innerRadius={55} outerRadius={90} paddingAngle={3} strokeWidth={0}>
                      {categoryData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-3 space-y-2">
                {categoryData.slice(0, 5).map((c, i) => (
                  <div key={c.category} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }} />
                      <span className="text-slate-600 dark:text-slate-400">{c.category}</span>
                    </div>
                    <span className="font-medium text-slate-950 dark:text-slate-50">{fmt(c.count)}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div>
            <h3 className="text-base font-semibold text-slate-950 dark:text-slate-50">最近安全事件</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">最近 5 条安全事件记录</p>
          </div>
          <Shield className="h-5 w-5 text-slate-400" />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/80 dark:border-slate-800 dark:bg-slate-950">
                <th className="px-5 py-3 font-medium text-slate-500 dark:text-slate-400">时间</th>
                <th className="px-5 py-3 font-medium text-slate-500 dark:text-slate-400">类型</th>
                <th className="px-5 py-3 font-medium text-slate-500 dark:text-slate-400">客户端 IP</th>
                <th className="px-5 py-3 font-medium text-slate-500 dark:text-slate-400">动作</th>
                <th className="px-5 py-3 font-medium text-slate-500 dark:text-slate-400">描述</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-10 text-center text-slate-400">
                    暂无安全事件
                  </td>
                </tr>
              ) : (
                events.map((ev) => {
                  const a = actionLabel(ev.action);
                  return (
                    <tr key={ev.id} className="border-b border-slate-100 hover:bg-slate-50/50 dark:border-slate-800 dark:hover:bg-slate-800/40">
                      <td className="whitespace-nowrap px-5 py-3 text-slate-600 dark:text-slate-400">{formatDate(ev.created_at)}</td>
                      <td className="px-5 py-3">
                        <span className="rounded-md border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium text-slate-700 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300">
                          {ev.category || "-"}
                        </span>
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-slate-700 dark:text-slate-300">{ev.client_ip}</td>
                      <td className="px-5 py-3">
                        <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${a.cls}`}>{a.text}</span>
                      </td>
                      <td className="max-w-[300px] truncate px-5 py-3 text-slate-500 dark:text-slate-400">{ev.match_desc || ev.path || "-"}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
