"use client";

import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface DashboardData {
  qps_1s: number;
  qps_5s: number;
  requests_total: number;
  status_2xx: number;
  errors_upstream_4xx: number;
  errors_upstream_5xx: number;
  waf_blocks: number;
  waf_observes: number;
  builtin_hits: number;
  uptime_sec: number;
  bot_stats?: { detected_24h: number; blocked_24h: number };
  cve_stats?: { hits_24h: number };
  drop_stats?: { dropped_24h: number };
  fingerprint_stats?: { unique_ja3: number };
}

interface QPSPoint {
  time: string;
  qps: number;
}

interface VisitPoint {
  time: string;
  visits: number;
}

interface BlockPoint {
  time: string;
  blocks: number;
}

const TABS = ["流量分析", "安全态势", "防护报告", "防护大屏"] as const;
const TIME_RANGES = ["近24小时", "近7天", "近30天"] as const;
const TEAL = "#14b8a6";
const TEAL_LIGHT = "#5eead4";

interface TimelineBucket {
  bucket: string;
  count: number;
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [activeTab, setActiveTab] = useState<string>("流量分析");
  const [timeRange, setTimeRange] = useState<string>("近24小时");
  const [showTimeDropdown, setShowTimeDropdown] = useState(false);
  const [showSiteDropdown, setShowSiteDropdown] = useState(false);
  const [qpsHistory, setQpsHistory] = useState<QPSPoint[]>([]);
  const [visitHistory, setVisitHistory] = useState<VisitPoint[]>([]);
  const [blockHistory, setBlockHistory] = useState<BlockPoint[]>([]);
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);

  const loadTimeline = useCallback(async (hours: number) => {
    try {
      const res = await api<{ buckets: TimelineBucket[] }>(`/api/v1/security-events/timeline?hours=${hours}`);
      setTimeline(res.buckets || []);
    } catch {
      // silent
    }
  }, []);

  const load = useCallback(async () => {
    try {
      const d = await api<DashboardData>("/api/v1/dashboard/summary");
      setData(d);
      const now = new Date().toLocaleTimeString("zh-CN", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
      setQpsHistory((prev) => {
        const next = [...prev, { time: now, qps: d.qps_5s }];
        return next.length > 30 ? next.slice(-30) : next;
      });
      setVisitHistory((prev) => {
        const next = [...prev, { time: now, visits: d.requests_total }];
        return next.length > 30 ? next.slice(-30) : next;
      });
      setBlockHistory((prev) => {
        const next = [...prev, { time: now, blocks: d.waf_blocks }];
        return next.length > 30 ? next.slice(-30) : next;
      });
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(() => {
      if (document.visibilityState === "visible") {
        load();
      }
    }, 5000);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    const hours = timeRange === "近7天" ? 168 : timeRange === "近30天" ? 720 : 24;
    loadTimeline(hours);
  }, [timeRange, loadTimeline]);

  const d = data;
  const totalRequests = d?.requests_total ?? 0;
  const pv = d?.status_2xx ?? 0;
  const blocks = d?.waf_blocks ?? 0;
  const err4xx = d?.errors_upstream_4xx ?? 0;
  const err5xx = d?.errors_upstream_5xx ?? 0;
  const err4xxRate = totalRequests > 0 ? ((err4xx / totalRequests) * 100).toFixed(2) + "%" : "0%";
  const err5xxRate = totalRequests > 0 ? ((err5xx / totalRequests) * 100).toFixed(2) + "%" : "0%";
  const block4xx = Math.min(blocks, err4xx);
  const block4xxRate = err4xx > 0 ? ((block4xx / err4xx) * 100).toFixed(2) + "%" : "0%";

  // Country data not available from backend API
  const countryData: { name: string; count: number }[] = [];

  const statsRow1 = [
    { label: "请求次数", value: fmt(totalRequests) },
    { label: "访问次数(PV)", value: fmt(pv) },
    { label: "独立访客(UV)", value: "暂无数据" },
    { label: "独立IP", value: "暂无数据" },
    { label: "拦截次数", value: fmt(blocks) },
    { label: "攻击IP", value: "暂无数据" },
  ];

  const statsRow2 = [
    { label: "4xx错误数", value: fmt(err4xx) },
    { label: "4xx错误率", value: err4xxRate },
    { label: "4xx拦截数", value: fmt(block4xx) },
    { label: "4xx拦截率", value: block4xxRate },
    { label: "5xx错误数", value: fmt(err5xx) },
    { label: "5xx错误率", value: err5xxRate },
  ];

  return (
    <div className="min-h-full bg-gray-50 text-gray-900 p-6 space-y-5">
      {/* Top bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1">
          {TABS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm transition-colors ${
                activeTab === tab
                  ? "text-teal-600 border-b-2 border-teal-500 font-medium"
                  : "text-gray-500 hover:text-gray-700"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3">
          {/* Time range selector */}
          <div className="relative">
            <button
              onClick={() => { setShowTimeDropdown(!showTimeDropdown); setShowSiteDropdown(false); }}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-white border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50"
            >
              {timeRange}
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
            </button>
            {showTimeDropdown && (
              <div className="absolute right-0 mt-1 bg-white border border-gray-200 rounded-md shadow-lg z-50">
                {TIME_RANGES.map((r) => (
                  <button key={r} onClick={() => { setTimeRange(r); setShowTimeDropdown(false); }} className="block w-full px-4 py-2 text-sm text-left text-gray-700 hover:bg-gray-50 whitespace-nowrap">
                    {r}
                  </button>
                ))}
              </div>
            )}
          </div>
          {/* Site filter */}
          <div className="relative">
            <button
              onClick={() => { setShowSiteDropdown(!showSiteDropdown); setShowTimeDropdown(false); }}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-white border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50"
            >
              全部应用
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
            </button>
            {showSiteDropdown && (
              <div className="absolute right-0 mt-1 bg-white border border-gray-200 rounded-md shadow-lg z-50">
                <button onClick={() => setShowSiteDropdown(false)} className="block w-full px-4 py-2 text-sm text-left text-gray-700 hover:bg-gray-50 whitespace-nowrap">
                  全部应用
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Main layout: left stats + right charts */}
      {activeTab === "安全态势" ? (
        <div className="space-y-5">
          <div className="bg-white border border-gray-200 rounded-lg p-5">
            <h3 className="text-sm font-medium text-gray-700 mb-4">攻击事件趋势（按小时）</h3>
            {timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={timeline} margin={{ left: 0, right: 10, top: 5, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                  <XAxis dataKey="bucket" tick={{ fill: "#9ca3af", fontSize: 10 }} angle={-45} textAnchor="end" interval="preserveStartEnd" />
                  <YAxis tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: "#ffffff", border: "1px solid #e5e7eb", borderRadius: 6, color: "#111827", fontSize: 12 }} />
                  <Bar dataKey="count" fill="#f87171" radius={[2, 2, 0, 0]} name="攻击事件" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[280px] items-center justify-center text-sm text-gray-400">暂无攻击数据</div>
            )}
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">总拦截次数</div>
              <div className="text-2xl font-bold text-rose-500">{fmt(blocks)}</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">观察事件数</div>
              <div className="text-2xl font-bold text-amber-500">{fmt(d?.waf_observes ?? 0)}</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">规则命中数</div>
              <div className="text-2xl font-bold text-teal-600">{fmt(d?.builtin_hits ?? 0)}</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">上游错误数</div>
              <div className="text-2xl font-bold text-gray-700">{fmt((d?.errors_upstream_4xx ?? 0) + (d?.errors_upstream_5xx ?? 0))}</div>
            </div>
          </div>
        </div>
      ) : activeTab === "防护报告" ? (
        <div className="bg-white border border-gray-200 rounded-lg p-8 flex flex-col items-center justify-center min-h-[320px] text-gray-400">
          <p className="text-sm">防护报告功能开发中</p>
        </div>
      ) : activeTab === "防护大屏" ? (
        <div className="bg-white border border-gray-200 rounded-lg p-8 flex flex-col items-center justify-center min-h-[320px] text-gray-400">
          <p className="text-sm">防护大屏功能开发中</p>
        </div>
      ) : (
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Left: Stats cards */}
        <div className="xl:col-span-2 space-y-4">
          {/* Row 1 */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {statsRow1.map((s) => (
              <div key={s.label} className="bg-white border border-gray-200 rounded-lg p-4">
                <div className="text-xs text-gray-500 mb-2">{s.label}</div>
                <div className="text-2xl font-bold text-gray-900 tabular-nums">{s.value}</div>
              </div>
            ))}
          </div>
          {/* Row 2 */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {statsRow2.map((s) => (
              <div key={s.label} className="bg-white border border-gray-200 rounded-lg p-4">
                <div className="text-xs text-gray-500 mb-2">{s.label}</div>
                <div className="text-2xl font-bold text-gray-900 tabular-nums">{s.value}</div>
              </div>
            ))}
          </div>

          {/* Row 3: Security Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">Bot检测(24h)</div>
              <div className="text-2xl font-bold text-orange-500 tabular-nums">{fmt(d?.bot_stats?.detected_24h ?? 0)}</div>
              <div className="text-xs text-gray-400 mt-1">拦截 {fmt(d?.bot_stats?.blocked_24h ?? 0)}</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">CVE命中(24h)</div>
              <div className="text-2xl font-bold text-red-500 tabular-nums">{fmt(d?.cve_stats?.hits_24h ?? 0)}</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">阻断数(24h)</div>
              <div className="text-2xl font-bold text-rose-600 tabular-nums">{fmt(d?.drop_stats?.dropped_24h ?? 0)}</div>
            </div>
            <div className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="text-xs text-gray-500 mb-2">独立JA3指纹</div>
              <div className="text-2xl font-bold text-indigo-500 tabular-nums">{fmt(d?.fingerprint_stats?.unique_ja3 ?? 0)}</div>
            </div>
          </div>

          {/* Bottom: Top countries */}
          <div className="bg-white border border-gray-200 rounded-lg p-5">
            <h3 className="text-sm font-medium text-gray-700 mb-4">Top 访问来源</h3>
            {countryData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={countryData} layout="vertical" margin={{ left: 50, right: 20, top: 5, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#9ca3af", fontSize: 12 }} axisLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: "#374151", fontSize: 12 }} axisLine={false} width={50} />
                  <Tooltip contentStyle={{ backgroundColor: "#ffffff", border: "1px solid #e5e7eb", borderRadius: 6, color: "#111827" }} />
                  <Bar dataKey="count" fill={TEAL} radius={[0, 4, 4, 0]} barSize={18} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[260px] items-center justify-center text-sm text-gray-400">暂无数据</div>
            )}
          </div>
        </div>

        {/* Right: Charts panel */}
        <div className="space-y-4">
          {/* Real-time QPS */}
          <div className="bg-white border border-gray-200 rounded-lg p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-gray-700">实时QPS</h3>
              <span className="text-xs text-teal-600 font-mono">{d?.qps_5s?.toFixed(1) ?? "0"} req/s</span>
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={qpsHistory} margin={{ left: -10, right: 5, top: 5, bottom: 0 }}>
                <XAxis dataKey="time" tick={false} axisLine={false} />
                <YAxis tick={{ fill: "#9ca3af", fontSize: 10 }} axisLine={false} tickLine={false} width={35} />
                <Tooltip contentStyle={{ backgroundColor: "#ffffff", border: "1px solid #e5e7eb", borderRadius: 6, color: "#111827", fontSize: 12 }} />
                <Bar dataKey="qps" fill={TEAL} radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Visit trend */}
          <div className="bg-white border border-gray-200 rounded-lg p-5">
            <h3 className="text-sm font-medium text-gray-700 mb-3">访问情况</h3>
            <ResponsiveContainer width="100%" height={140}>
              <LineChart data={visitHistory} margin={{ left: -10, right: 5, top: 5, bottom: 0 }}>
                <XAxis dataKey="time" tick={false} axisLine={false} />
                <YAxis tick={{ fill: "#9ca3af", fontSize: 10 }} axisLine={false} tickLine={false} width={35} />
                <Tooltip contentStyle={{ backgroundColor: "#ffffff", border: "1px solid #e5e7eb", borderRadius: 6, color: "#111827", fontSize: 12 }} />
                <Line type="monotone" dataKey="visits" stroke={TEAL} strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Block trend */}
          <div className="bg-white border border-gray-200 rounded-lg p-5">
            <h3 className="text-sm font-medium text-gray-700 mb-3">拦截情况</h3>
            <ResponsiveContainer width="100%" height={140}>
              <LineChart data={blockHistory} margin={{ left: -10, right: 5, top: 5, bottom: 0 }}>
                <XAxis dataKey="time" tick={false} axisLine={false} />
                <YAxis tick={{ fill: "#9ca3af", fontSize: 10 }} axisLine={false} tickLine={false} width={35} />
                <Tooltip contentStyle={{ backgroundColor: "#ffffff", border: "1px solid #e5e7eb", borderRadius: 6, color: "#111827", fontSize: 12 }} />
                <Line type="monotone" dataKey="blocks" stroke="#f87171" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
      )}

      {/* Footer uptime */}
      {d && (
        <div className="text-xs text-gray-400 text-right">
          运行时间: {formatUptime(d.uptime_sec)}
        </div>
      )}
    </div>
  );
}

function fmt(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toLocaleString();
}

function formatUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  return `${h}h ${m}m ${s}s`;
}
