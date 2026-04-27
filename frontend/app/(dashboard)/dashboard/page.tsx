"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Ban,
  Bot,
  Gauge,
  RefreshCcw,
  ShieldAlert,
  TimerReset,
} from "lucide-react";
import {
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
import { PageIntro, MetricCard, MetricGrid, Surface, InlineMeta, statusToneClass } from "@/components/console-shell";
import { dashboardTabs } from "@/lib/console";
import { getDashboardSummary, getSecurityTimeline, type DashboardSummary, type TimelineBucket } from "@/lib/api";

const chartColors = ["#06b6d4", "#22c55e", "#f59e0b", "#fb7185", "#8b5cf6", "#64748b"];

function fmt(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return value.toLocaleString();
}

function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  return `${hours}h ${minutes}m`;
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);
  const [tab, setTab] = useState<(typeof dashboardTabs)[number]["key"]>("overview");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const [dashboard, timelineResponse] = await Promise.all([
        getDashboardSummary(),
        getSecurityTimeline(24),
      ]);
      setSummary(dashboard);
      setTimeline(timelineResponse.buckets ?? []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") {
        load();
      }
    }, 15000);
    return () => clearInterval(timer);
  }, []);

  const dropPie = useMemo(() => {
    if (!summary) return [];
    return Object.entries(summary.drop_by_source_24h || {})
      .map(([key, value]) => ({ key, value }))
      .filter((item) => item.value > 0);
  }, [summary]);

  const cvePhasePie = useMemo(() => summary?.cve_by_type_24h ?? [], [summary]);

  const metricCards = summary
    ? [
        {
          label: "实时 QPS",
          value: summary.qps_5s.toFixed(1),
          hint: `1 秒窗口 ${summary.qps_1s.toFixed(1)}`,
          tone: "default" as const,
        },
        {
          label: "请求总数",
          value: fmt(summary.requests_total),
          hint: `2xx ${fmt(summary.status_2xx)} · 版本修订 ${summary.revision}`,
          tone: "default" as const,
        },
        {
          label: "WAF 拦截",
          value: fmt(summary.waf_blocks),
          hint: `观察事件 ${fmt(summary.waf_observes)} · 内建命中 ${fmt(summary.builtin_hits)}`,
          tone: "danger" as const,
        },
        {
          label: "上游错误",
          value: fmt(summary.errors_upstream_4xx + summary.errors_upstream_5xx),
          hint: `4xx ${fmt(summary.errors_upstream_4xx)} · 5xx ${fmt(summary.errors_upstream_5xx)}`,
          tone: "warning" as const,
        },
      ]
    : [];

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Runtime Overview"
        title="安全态势总览"
        description="基于当前真实 API 汇总请求吞吐、WAF 命中、Bot 评分、CVE 事件、阻断来源与运行修订。页面会在窗口可见时自动刷新。"
        actions={
          <>
            <div className="inline-flex rounded-full border border-white/10 bg-white/5 p-1">
              {dashboardTabs.map((item) => (
                <button
                  key={item.key}
                  onClick={() => setTab(item.key)}
                  className={
                    tab === item.key
                      ? "rounded-full bg-white px-4 py-2 text-xs font-medium text-slate-950"
                      : "rounded-full px-4 py-2 text-xs font-medium text-white/70"
                  }
                >
                  {item.label}
                </button>
              ))}
            </div>
            <Button variant="secondary" className="rounded-2xl bg-white text-slate-950 hover:bg-slate-100" onClick={load}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              刷新
            </Button>
          </>
        }
      />

      <MetricGrid>
        {loading && !summary
          ? Array.from({ length: 4 }).map((_, index) => (
              <MetricCard key={index} label="加载中" value="--" hint="等待后端响应" />
            ))
          : metricCards.map((item) => (
              <MetricCard key={item.label} {...item} />
            ))}
      </MetricGrid>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_0.9fr]">
        <Surface
          title={tab === "overview" ? "24 小时安全事件时间线" : tab === "traffic" ? "请求与阻断概览" : "威胁来源聚合"}
          description={
            tab === "overview"
              ? "安全事件时间桶来自 /api/v1/security-events/timeline，帮助识别攻击峰值。"
              : tab === "traffic"
                ? "从总览接口展示当前吞吐与关键运行指标。"
                : "聚合展示 Bot、CVE、指纹异常与阻断来源。"
          }
        >
          {tab === "overview" ? (
            <div className="min-w-0 h-[340px]">
              <ResponsiveContainer width="100%" height={340} minWidth={0}>
                <BarChart data={timeline} margin={{ top: 8, right: 12, left: -20, bottom: 18 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="bucket" tick={{ fontSize: 11, fill: "#64748b" }} minTickGap={24} />
                  <YAxis tick={{ fontSize: 11, fill: "#64748b" }} width={36} />
                  <Tooltip />
                  <Bar dataKey="count" radius={[8, 8, 0, 0]} fill="#0891b2" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : tab === "traffic" ? (
            <div className="grid gap-4 md:grid-cols-2">
              <InlineMeta label="运行时长" value={summary ? formatUptime(summary.uptime_sec) : "--"} />
              <InlineMeta label="配置修订" value={summary ? `rev-${summary.revision}` : "--"} />
              <InlineMeta label="Bot 高风险（24h）" value={summary ? fmt(summary.bot_high_risk_24h) : "--"} />
              <InlineMeta label="阻断事件（24h）" value={summary ? fmt(summary.drop_total_24h) : "--"} />
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              <InlineMeta label="Bot 检测总数" value={summary ? fmt(summary.bot_total_24h) : "--"} />
              <InlineMeta label="Bot 已阻断" value={summary ? fmt(summary.bot_blocked_24h) : "--"} />
              <InlineMeta label="CVE 命中总数" value={summary ? fmt(summary.cve_total_24h) : "--"} />
              <InlineMeta label="指纹异常" value={summary ? fmt(summary.fingerprint_anomaly_24h) : "--"} />
            </div>
          )}
        </Surface>

        <Surface title="运行状态" description="面向值班与排障的关键观测数据。">
          <div className="space-y-3">
            <StatusRow icon={Gauge} label="请求速率" value={summary ? `${summary.qps_5s.toFixed(1)} req/s` : "--"} status="running" />
            <StatusRow icon={ShieldAlert} label="拦截动作" value={summary ? fmt(summary.waf_blocks) : "--"} status="block" />
            <StatusRow icon={Bot} label="Bot 风险" value={summary ? fmt(summary.bot_high_risk_24h) : "--"} status="warning" />
            <StatusRow icon={Ban} label="主动阻断" value={summary ? fmt(summary.drop_total_24h) : "--"} status="error" />
            <StatusRow icon={TimerReset} label="运行时间" value={summary ? formatUptime(summary.uptime_sec) : "--"} status="success" />
          </div>
        </Surface>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Surface title="阻断来源分布" description="drop_by_source_24h 按来源聚合。">
          <div className="grid gap-5 lg:grid-cols-[320px_1fr] lg:items-center">
            <div className="min-w-0 h-[260px]">
              <ResponsiveContainer width="100%" height={260} minWidth={0}>
                <PieChart>
                  <Pie data={dropPie} dataKey="value" nameKey="key" innerRadius={55} outerRadius={92} paddingAngle={4}>
                    {dropPie.map((entry, index) => (
                      <Cell key={entry.key} fill={chartColors[index % chartColors.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-3">
              {dropPie.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">24 小时内暂无主动阻断事件。</div>
              ) : (
                dropPie.map((entry, index) => (
                  <div key={entry.key} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                    <div className="flex items-center gap-3 text-slate-700">
                      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: chartColors[index % chartColors.length] }} />
                      <span>{entry.key}</span>
                    </div>
                    <span className="font-medium text-slate-950">{fmt(entry.value)}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </Surface>

        <Surface title="CVE 阶段分布" description="cve_by_type_24h 使用 phase 聚合，帮助判断规则命中位置。">
          <div className="grid gap-3">
            {cvePhasePie.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">24 小时内暂无 CVE 事件。</div>
            ) : (
              cvePhasePie.map((entry, index) => (
                <div key={`${entry.category}-${index}`} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <div className="flex items-center gap-3 text-slate-700">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: chartColors[index % chartColors.length] }} />
                    <span>{entry.category}</span>
                  </div>
                  <span className="font-medium text-slate-950">{fmt(entry.count)}</span>
                </div>
              ))
            )}
          </div>
        </Surface>
      </div>
    </div>
  );
}

function StatusRow({
  icon: Icon,
  label,
  value,
  status,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  status: string;
}) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-900 text-white">
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <div className="text-sm font-medium text-slate-900">{label}</div>
          <div className="text-xs text-slate-500">实时读取当前运行状态</div>
        </div>
      </div>
      <div className={`console-badge ${statusToneClass(status)}`}>{value}</div>
    </div>
  );
}
