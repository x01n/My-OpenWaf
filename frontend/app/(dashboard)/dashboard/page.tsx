"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Globe,
  MonitorSmartphone,
  RefreshCcw,
  Shield,
  ShieldAlert,
  Users,
  Wifi,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
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
import { cn } from "@/lib/utils";

const PIE_COLORS = ["#14b8a6", "#0ea5e9", "#f59e0b", "#ef4444", "#8b5cf6", "#64748b"];

function fmt(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return value.toLocaleString();
}

type TabKey = "traffic" | "overview" | "threats";

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("traffic");
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

  const tabs = [
    { key: "traffic" as const, label: "流量分析" },
    { key: "overview" as const, label: "安全态势" },
    { key: "threats" as const, label: "防护报告" },
  ];

  const actionLabel = (action: string) => {
    const map: Record<string, { text: string; cls: string }> = {
      intercept: { text: "拦截", cls: "bg-red-50 text-red-600 border border-red-200" },
      block: { text: "阻断", cls: "bg-red-50 text-red-600 border border-red-200" },
      observe: { text: "观察", cls: "bg-amber-50 text-amber-600 border border-amber-200" },
      drop: { text: "丢弃", cls: "bg-rose-50 text-rose-600 border border-rose-200" },
      challenge: { text: "质询", cls: "bg-teal-50 text-teal-600 border border-teal-200" },
    };
    return map[action] ?? { text: action, cls: "bg-gray-100 text-gray-600 border border-gray-200" };
  };

  return (
    <div className="space-y-5">
      {/* Tab bar */}
      <div className="flex items-center gap-1 rounded-lg bg-white p-1 shadow-sm border border-slate-200/80">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={cn(
              "rounded-md px-4 py-1.5 text-[13px] font-medium transition-all",
              activeTab === tab.key
                ? "bg-teal-500 text-white shadow-sm"
                : "text-slate-500 hover:bg-slate-50 hover:text-slate-700",
            )}
          >
            {tab.label}
          </button>
        ))}
        <div className="flex-1" />
        <Button
          onClick={load}
          disabled={loading}
          variant="ghost"
          size="sm"
          className="h-8 gap-1.5 text-xs text-slate-500 hover:text-teal-600"
        >
          <RefreshCcw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          刷新
        </Button>
      </div>

      {/* Stats row 1: main metrics */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        {[
          { label: "请求次数", value: summary ? fmt(summary.requests_total) : "—", icon: Activity, color: "text-teal-500", iconBg: "bg-teal-50" },
          { label: "访问次数 (PV)", value: summary ? fmt(summary.status_2xx) : "—", icon: Globe, color: "text-blue-500", iconBg: "bg-blue-50" },
          { label: "独立访客 (UV)", value: summary ? fmt(summary.bot_total_24h) : "—", icon: Users, color: "text-teal-500", iconBg: "bg-teal-50" },
          { label: "QPS (5s)", value: summary ? summary.qps_5s.toFixed(1) : "—", icon: MonitorSmartphone, color: "text-violet-500", iconBg: "bg-violet-50" },
          { label: "拦截次数", value: summary ? fmt(summary.waf_blocks) : "—", icon: ShieldAlert, color: "text-orange-500", iconBg: "bg-orange-50", warning: true },
          { label: "攻击 IP", value: summary ? fmt(summary.waf_observes) : "—", icon: Shield, color: "text-red-500", iconBg: "bg-red-50", warning: true },
        ].map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200/80 bg-white p-4 shadow-sm">
            <div className="flex items-center gap-2 text-[12px] text-slate-500">
              <span>{card.label}</span>
              <div className={cn("flex h-4.5 w-4.5 items-center justify-center rounded", card.iconBg)}>
                <card.icon className={cn("h-3 w-3", card.color)} />
              </div>
            </div>
            <div className={cn("mt-2 text-2xl font-bold", card.warning && (summary?.waf_blocks ?? 0) > 0 ? "text-orange-600" : "text-slate-900")}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      {/* Stats row 2: error metrics */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        {[
          { label: "4xx 错误数", value: summary ? fmt(summary.errors_upstream_4xx) : "—", warning: true },
          { label: "4xx 错误率", value: summary && summary.requests_total > 0 ? `${((summary.errors_upstream_4xx / summary.requests_total) * 100).toFixed(2)}%` : "0%", warning: false },
          { label: "4xx 拦截数", value: summary ? fmt(summary.waf_blocks) : "—", warning: true },
          { label: "4xx 拦截率", value: summary && summary.requests_total > 0 ? `${((summary.waf_blocks / summary.requests_total) * 100).toFixed(2)}%` : "0%", warning: false },
          { label: "5xx 错误数", value: summary ? fmt(summary.errors_upstream_5xx) : "—", warning: true },
          { label: "5xx 错误率", value: summary && summary.requests_total > 0 ? `${((summary.errors_upstream_5xx / summary.requests_total) * 100).toFixed(2)}%` : "0%", warning: false },
        ].map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200/80 bg-white px-4 py-3 shadow-sm">
            <div className="flex items-center gap-1.5 text-[12px] text-slate-500">
              <span>{card.label}</span>
              {card.warning && <span className="text-red-400">▲</span>}
            </div>
            <div className={cn("mt-1.5 text-xl font-bold", card.warning && card.value !== "0" && card.value !== "—" ? "text-red-600" : "text-slate-900")}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      {/* Charts area */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        {/* QPS & Timeline */}
        <div className="col-span-1 space-y-4 xl:col-span-3">
          {/* Real-time QPS */}
          <div className="rounded-xl border border-slate-200/80 bg-white p-5 shadow-sm">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-[15px] font-semibold text-slate-800">实时 QPS</h3>
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <Wifi className="h-3.5 w-3.5 text-teal-400" />
                <span>{summary ? fmt(summary.requests_total) : "—"}</span>
              </div>
            </div>
            <div className="h-[180px]">
              {timelineData.length === 0 ? (
                <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-slate-200 text-sm text-slate-400">暂无数据</div>
              ) : (
                <ResponsiveContainer width="100%" height={180}>
                  <BarChart data={timelineData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                    <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} width={36} />
                    <Tooltip contentStyle={{ borderRadius: 8, border: "1px solid #e2e8f0", fontSize: 12 }} />
                    <Bar dataKey="count" fill="#14b8a6" radius={[2, 2, 0, 0]} name="事件数" />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Security events table */}
          <div className="rounded-xl border border-slate-200/80 bg-white shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-100 px-5 py-3.5">
              <h3 className="text-[15px] font-semibold text-slate-800">最近安全事件</h3>
              <Shield className="h-4 w-4 text-teal-400" />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[13px]">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/60">
                    <th className="px-5 py-2.5 font-medium text-slate-500">时间</th>
                    <th className="px-5 py-2.5 font-medium text-slate-500">类型</th>
                    <th className="px-5 py-2.5 font-medium text-slate-500">客户端 IP</th>
                    <th className="px-5 py-2.5 font-medium text-slate-500">动作</th>
                    <th className="px-5 py-2.5 font-medium text-slate-500">描述</th>
                  </tr>
                </thead>
                <tbody>
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-5 py-10 text-center text-slate-400">暂无安全事件</td>
                    </tr>
                  ) : (
                    events.map((ev) => {
                      const a = actionLabel(ev.action);
                      return (
                        <tr key={ev.id} className="border-b border-slate-50 hover:bg-slate-50/50">
                          <td className="whitespace-nowrap px-5 py-2.5 text-slate-500">{formatDate(ev.created_at)}</td>
                          <td className="px-5 py-2.5">
                            <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[11px] font-medium text-slate-600">{ev.category || "-"}</span>
                          </td>
                          <td className="px-5 py-2.5 font-mono text-[12px] text-slate-600">{ev.client_ip}</td>
                          <td className="px-5 py-2.5">
                            <span className={cn("rounded px-1.5 py-0.5 text-[11px] font-medium", a.cls)}>{a.text}</span>
                          </td>
                          <td className="max-w-[280px] truncate px-5 py-2.5 text-slate-500">{ev.match_desc || ev.path || "-"}</td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right sidebar charts */}
        <div className="space-y-4">
          {/* Access trend */}
          <div className="rounded-xl border border-slate-200/80 bg-white p-5 shadow-sm">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-[14px] font-semibold text-slate-800">访问情况</h3>
              <span className="text-xs text-slate-400">峰值 {timelineData.length > 0 ? fmt(Math.max(...timelineData.map((d) => d.count))) : "0"}</span>
            </div>
            <div className="h-[120px]">
              {timelineData.length === 0 ? (
                <div className="flex h-full items-center justify-center text-xs text-slate-400">暂无</div>
              ) : (
                <ResponsiveContainer width="100%" height={120}>
                  <AreaChart data={timelineData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="tealGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#14b8a6" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#14b8a6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Area type="monotone" dataKey="count" stroke="#14b8a6" strokeWidth={1.5} fill="url(#tealGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Block trend */}
          <div className="rounded-xl border border-slate-200/80 bg-white p-5 shadow-sm">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-[14px] font-semibold text-slate-800">拦截情况</h3>
              <span className="text-xs text-slate-400">峰值 {stats?.total ? fmt(stats.total) : "0"}</span>
            </div>
            <div className="h-[120px]">
              {categoryData.length === 0 ? (
                <div className="flex h-full items-center justify-center text-xs text-slate-400">暂无</div>
              ) : (
                <ResponsiveContainer width="100%" height={120}>
                  <AreaChart data={timelineData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f87171" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Area type="monotone" dataKey="count" stroke="#f87171" strokeWidth={1.5} fill="url(#redGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Category distribution */}
          <div className="rounded-xl border border-slate-200/80 bg-white p-5 shadow-sm">
            <h3 className="mb-3 text-[14px] font-semibold text-slate-800">攻击类型分布</h3>
            {categoryData.length === 0 ? (
              <div className="flex h-[140px] items-center justify-center text-xs text-slate-400">暂无</div>
            ) : (
              <>
                <div className="flex justify-center">
                  <ResponsiveContainer width={140} height={140}>
                    <PieChart>
                      <Pie data={categoryData} dataKey="count" nameKey="category" innerRadius={38} outerRadius={60} paddingAngle={3} strokeWidth={0}>
                        {categoryData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="mt-2 space-y-1.5">
                  {categoryData.slice(0, 5).map((c, i) => (
                    <div key={c.category} className="flex items-center justify-between text-[12px]">
                      <div className="flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }} />
                        <span className="text-slate-500">{c.category}</span>
                      </div>
                      <span className="font-medium text-slate-700">{fmt(c.count)}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
