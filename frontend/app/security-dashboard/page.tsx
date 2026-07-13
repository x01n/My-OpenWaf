"use client";

/**
 * 安全防护监控大屏
 *
 * 独立全屏页面，无侧边栏与顶栏，深色主题 + teal 装饰色。
 * 4x3 CSS Grid 布局，涵盖：
 *   - 顶部：标题、实时时间、全屏按钮、返回链接
 *   - 左列：3 张统计大数字卡（UV / 请求数 / 拦截数）+ 攻击 IP Top 5 排行
 *   - 中列：地理攻击分布 + 实时 QPS 迷你柱状图
 *   - 右列：实时攻击流（IP + 国家 + 时间 + 次数）
 *
 * 数据源全部复用 dashboard 现有 hook，30 秒轮询由 SWR 自动完成。
 */

import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import Link from "next/link";
import {
  IconArrowLeft,
  IconMaximize,
  IconMinimize,
  IconShieldHalfFilled,
  IconUsers,
  IconChartBar,
  IconBan,
  IconTrophy,
  IconTrophyFilled,
  IconActivity,
  IconAlertTriangle,
} from "@tabler/icons-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useTranslation } from "react-i18next";
import {
  useDashboard,
  useDashboardStats,
  useSecurityEvents,
} from "@/hooks/use-api";
import { GeoAttackDistribution } from "@/components/geo-attack-distribution";
import { formatNumber } from "@/lib/utils";
import { countryFlag, countryName } from "@/lib/country-names";
import type { SecurityEvent, SecurityEventStats } from "@/lib/types";

const MAX_QPS_POINTS = 30;
const LIVE_ATTACK_LIMIT = 12;

interface QPSPoint {
  time: string;
  qps: number;
}

/**
 * 将 SecurityEvent 里的时间戳格式化为 HH:mm:ss。
 */
function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "--:--:--";
    return d.toTimeString().slice(0, 8);
  } catch {
    return "--:--:--";
  }
}

/**
 * Top IP 排行奖牌颜色。
 */
function medalClass(idx: number): string {
  switch (idx) {
    case 0:
      return "text-yellow-400";
    case 1:
      return "text-slate-300";
    case 2:
      return "text-amber-600";
    default:
      return "text-slate-500";
  }
}

/**
 * 大屏面板容器（无边框、半透明背景、teal 描边）。
 */
function Panel({
  title,
  icon,
  children,
  className = "",
}: {
  title?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`flex flex-col overflow-hidden rounded-xl border border-teal-500/20 bg-slate-900/50 shadow-[0_0_24px_-12px_rgba(20,184,166,0.4)] backdrop-blur ${className}`}
    >
      {title && (
        <div className="flex items-center gap-2 border-b border-teal-500/15 px-4 py-2.5 text-sm font-medium text-teal-300">
          {icon}
          <span>{title}</span>
        </div>
      )}
      <div className="flex-1 overflow-hidden p-4">{children}</div>
    </div>
  );
}

/**
 * 大数字统计卡。
 */
function BigStat({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
  accent: string;
}) {
  return (
    <div className="relative flex flex-col justify-between overflow-hidden rounded-xl border border-teal-500/20 bg-gradient-to-br from-slate-900/70 to-slate-950/70 p-4 shadow-[0_0_24px_-12px_rgba(20,184,166,0.4)] backdrop-blur">
      <div className="flex items-center justify-between text-xs uppercase tracking-wider text-slate-400">
        <span>{label}</span>
        <span className={accent}>{icon}</span>
      </div>
      <div
        className={`mt-2 font-mono text-4xl font-bold tabular-nums ${accent} drop-shadow-[0_0_8px_currentColor]`}
        style={{ letterSpacing: "0.02em" }}
      >
        {value}
      </div>
    </div>
  );
}

export default function SecurityDashboardPage() {
  const { t } = useTranslation();
  const HOURS = 24;

  const { data: dashboard } = useDashboard();
  const { data: stats } = useDashboardStats({ hours: HOURS }) as {
    data?: SecurityEventStats;
  };
  const { data: eventsResp } = useSecurityEvents({
    page: 1,
    page_size: LIVE_ATTACK_LIMIT,
  }) as { data?: { items: SecurityEvent[]; total: number } };

  // 实时时间
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    setNow(new Date());
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // 全屏切换
  const [isFullscreen, setIsFullscreen] = useState(false);
  useEffect(() => {
    const handler = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener("fullscreenchange", handler);
    return () => document.removeEventListener("fullscreenchange", handler);
  }, []);
  const toggleFullscreen = useCallback(() => {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    } else {
      document.documentElement.requestFullscreen().catch(() => {});
    }
  }, []);

  // 实时 QPS 采样
  const qpsRef = useRef<QPSPoint[]>([]);
  const [qpsHistory, setQpsHistory] = useState<QPSPoint[]>([]);
  useEffect(() => {
    if (!dashboard) return;
    const d = new Date();
    const timeStr = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
    const point: QPSPoint = {
      time: timeStr,
      qps: dashboard.qps_5s ?? dashboard.qps_1s ?? 0,
    };
    const next = [...qpsRef.current, point];
    if (next.length > MAX_QPS_POINTS) {
      next.splice(0, next.length - MAX_QPS_POINTS);
    }
    qpsRef.current = next;
    setQpsHistory([...next]);
  }, [dashboard]);

  // 攻击 IP -> 国家映射（利用最近事件补充地理信息）
  const ipCountryMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const ev of eventsResp?.items ?? []) {
      if (ev.client_ip && ev.geo_country && !map.has(ev.client_ip)) {
        map.set(ev.client_ip, ev.geo_country);
      }
    }
    return map;
  }, [eventsResp]);

  const topIps = (stats?.top_ips ?? []).slice(0, 5);
  const uniqueVisitors = stats?.top_ips?.length ?? 0;
  const totalRequests = stats?.requests ?? 0;
  const totalIntercepts = stats?.intercepts ?? 0;

  const liveAttacks = (eventsResp?.items ?? []).slice(0, LIVE_ATTACK_LIMIT);

  const dateStr = now
    ? `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`
    : "----/--/--";
  const timeStr = now ? now.toTimeString().slice(0, 8) : "--:--:--";

  return (
    <div className="relative flex min-h-svh flex-col overflow-hidden bg-slate-950 text-slate-100">
      {/* 背景光晕 */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-40"
        style={{
          backgroundImage:
            "radial-gradient(circle at 20% 20%, rgba(20,184,166,0.18) 0%, transparent 40%), radial-gradient(circle at 80% 80%, rgba(6,182,212,0.14) 0%, transparent 45%)",
        }}
      />

      {/* 顶部标题栏 */}
      <header className="relative z-10 flex items-center justify-between border-b border-teal-500/20 bg-slate-950/70 px-6 py-3 backdrop-blur">
        <div className="flex items-center gap-3">
          <Link
            href="/dashboard"
            className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-teal-500/10 hover:text-teal-300"
            title={t("securityDashboard.back")}
          >
            <IconArrowLeft className="h-5 w-5" />
          </Link>
          <IconShieldHalfFilled className="h-7 w-7 text-teal-400 drop-shadow-[0_0_8px_rgba(20,184,166,0.6)]" />
          <h1 className="bg-gradient-to-r from-teal-300 to-cyan-200 bg-clip-text text-xl font-bold tracking-wide text-transparent md:text-2xl">
            {t("securityDashboard.title")}
          </h1>
        </div>
        <div className="flex items-center gap-6">
          <div className="hidden text-right md:block">
            <div className="font-mono text-xs text-slate-400">{dateStr}</div>
            <div className="font-mono text-lg font-semibold tabular-nums text-teal-300">
              {timeStr}
            </div>
          </div>
          <button
            onClick={toggleFullscreen}
            className="flex items-center gap-1.5 rounded-md border border-teal-500/30 bg-slate-900/60 px-3 py-1.5 text-xs text-teal-300 transition-colors hover:bg-teal-500/10"
            title={
              isFullscreen
                ? t("securityDashboard.exitFullscreen")
                : t("securityDashboard.enterFullscreen")
            }
          >
            {isFullscreen ? (
              <IconMinimize className="h-4 w-4" />
            ) : (
              <IconMaximize className="h-4 w-4" />
            )}
            <span className="hidden sm:inline">
              {isFullscreen
                ? t("securityDashboard.exitFullscreen")
                : t("securityDashboard.enterFullscreen")}
            </span>
          </button>
        </div>
      </header>

      {/* 主体网格 */}
      <main className="relative z-10 flex-1 overflow-auto p-4 lg:p-6">
        <div className="grid h-full min-h-[720px] grid-cols-1 gap-4 lg:grid-cols-12 lg:grid-rows-[auto_1fr_auto]">
          {/* 上一行：3 张大数字卡（12 列 / 每张 4 列） */}
          <div className="lg:col-span-4">
            <BigStat
              label={t("securityDashboard.uniqueVisitors")}
              value={formatNumber(uniqueVisitors)}
              icon={<IconUsers className="h-5 w-5" />}
              accent="text-cyan-300"
            />
          </div>
          <div className="lg:col-span-4">
            <BigStat
              label={t("securityDashboard.requests")}
              value={formatNumber(totalRequests)}
              icon={<IconChartBar className="h-5 w-5" />}
              accent="text-teal-300"
            />
          </div>
          <div className="lg:col-span-4">
            <BigStat
              label={t("securityDashboard.intercepts")}
              value={formatNumber(totalIntercepts)}
              icon={<IconBan className="h-5 w-5" />}
              accent="text-rose-400"
            />
          </div>

          {/* 中间行：左（Top IP 排行 4 列） / 中（地理分布 4 列） / 右（实时攻击 4 列） */}
          <div className="lg:col-span-4 lg:row-span-1">
            <Panel
              title={t("securityDashboard.attackIPs")}
              icon={<IconTrophy className="h-4 w-4" />}
              className="h-full"
            >
              {topIps.length > 0 ? (
                <ul className="space-y-2.5">
                  {topIps.map((ip, idx) => {
                    const cc = ipCountryMap.get(ip.client_ip);
                    return (
                      <li
                        key={ip.client_ip}
                        className="flex items-center gap-3 rounded-lg border border-teal-500/10 bg-slate-950/50 px-3 py-2"
                      >
                        <span
                          className={`flex h-7 w-7 items-center justify-center ${medalClass(idx)}`}
                        >
                          {idx < 3 ? (
                            <IconTrophyFilled className="h-5 w-5" />
                          ) : (
                            <span className="font-mono text-sm font-bold">
                              {idx + 1}
                            </span>
                          )}
                        </span>
                        <span className="font-mono text-sm text-slate-200">
                          {ip.client_ip}
                        </span>
                        {cc && (
                          <span className="flex items-center gap-1 text-xs text-slate-400">
                            <span aria-hidden>{countryFlag(cc)}</span>
                            <span>{countryName(cc)}</span>
                          </span>
                        )}
                        <span className="ml-auto font-mono text-sm font-semibold tabular-nums text-rose-400">
                          {formatNumber(ip.count)}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <div className="flex h-full min-h-[240px] items-center justify-center text-sm text-slate-500">
                  {t("securityDashboard.noData")}
                </div>
              )}
            </Panel>
          </div>

          <div className="lg:col-span-4 lg:row-span-1">
            {/* 复用 GeoAttackDistribution；layout 已注入 dark class，Card 自动使用暗色变量 */}
            <div className="h-full [&>div]:h-full [&>div]:border-teal-500/20 [&>div]:bg-slate-900/50 [&>div]:shadow-[0_0_24px_-12px_rgba(20,184,166,0.4)] [&>div]:backdrop-blur">
              <GeoAttackDistribution
                data={stats?.top_countries}
                hours={HOURS}
              />
            </div>
          </div>

          <div className="lg:col-span-4 lg:row-span-1">
            <Panel
              title={t("securityDashboard.liveAttacks")}
              icon={<IconAlertTriangle className="h-4 w-4" />}
              className="h-full"
            >
              {liveAttacks.length > 0 ? (
                <ul className="max-h-[420px] space-y-1.5 overflow-y-auto pr-1">
                  {liveAttacks.map((ev) => (
                    <li
                      key={ev.id}
                      className="flex items-center gap-3 rounded-md border border-rose-500/10 bg-slate-950/40 px-2.5 py-1.5 text-xs"
                    >
                      <span
                        aria-hidden
                        className="h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-rose-400"
                      />
                      <span className="font-mono text-slate-200">
                        {ev.client_ip}
                      </span>
                      {ev.geo_country && (
                        <span className="flex items-center gap-1 text-slate-400">
                          <span aria-hidden>{countryFlag(ev.geo_country)}</span>
                          <span className="hidden md:inline">
                            {countryName(ev.geo_country)}
                          </span>
                        </span>
                      )}
                      <span className="ml-auto flex items-center gap-2">
                        <span className="rounded bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-medium text-rose-300">
                          {ev.category || ev.action}
                        </span>
                        <span className="font-mono tabular-nums text-slate-400">
                          {formatTime(ev.created_at)}
                        </span>
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="flex h-full min-h-[240px] items-center justify-center text-sm text-slate-500">
                  {t("securityDashboard.noData")}
                </div>
              )}
            </Panel>
          </div>

          {/* 底部行：实时 QPS 迷你柱状图（全宽） */}
          <div className="lg:col-span-12">
            <Panel
              title={t("securityDashboard.realtimeQps")}
              icon={<IconActivity className="h-4 w-4" />}
            >
              <div className="flex items-center gap-6">
                <div className="hidden shrink-0 flex-col md:flex">
                  <span className="text-xs uppercase tracking-wider text-slate-400">
                    QPS
                  </span>
                  <span className="font-mono text-3xl font-bold tabular-nums text-teal-300 drop-shadow-[0_0_8px_currentColor]">
                    {dashboard?.qps_5s ?? dashboard?.qps_1s ?? 0}
                  </span>
                </div>
                <div className="h-32 w-full min-w-0">
                  {qpsHistory.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={qpsHistory}
                        margin={{ top: 4, right: 4, left: 4, bottom: 4 }}
                      >
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke="rgba(148,163,184,0.12)"
                          vertical={false}
                        />
                        <XAxis
                          dataKey="time"
                          fontSize={10}
                          stroke="rgba(148,163,184,0.6)"
                          tickLine={false}
                          axisLine={false}
                          interval="preserveStartEnd"
                        />
                        <YAxis
                          fontSize={10}
                          stroke="rgba(148,163,184,0.6)"
                          tickLine={false}
                          axisLine={false}
                          allowDecimals={false}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "rgba(15,23,42,0.95)",
                            border: "1px solid rgba(20,184,166,0.4)",
                            borderRadius: "6px",
                            fontSize: "11px",
                            color: "#e2e8f0",
                          }}
                          cursor={{ fill: "rgba(20,184,166,0.08)" }}
                        />
                        <Bar
                          dataKey="qps"
                          fill="url(#qpsGradient)"
                          radius={[3, 3, 0, 0]}
                        />
                        <defs>
                          <linearGradient
                            id="qpsGradient"
                            x1="0"
                            y1="0"
                            x2="0"
                            y2="1"
                          >
                            <stop offset="0%" stopColor="#5eead4" />
                            <stop offset="100%" stopColor="#0d9488" />
                          </linearGradient>
                        </defs>
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-slate-500">
                      {t("securityDashboard.waitingData")}
                    </div>
                  )}
                </div>
              </div>
            </Panel>
          </div>
        </div>
      </main>
    </div>
  );
}
