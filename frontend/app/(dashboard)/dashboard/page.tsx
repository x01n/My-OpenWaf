"use client";

import { useRef, useEffect, useState, useCallback } from "react";
import { useDashboard, useSecurityEventTimeline, useDashboardStats } from "@/hooks/use-api";
import { MetricTile } from "@/components/metric-tile";
import { MetricStrip, type MetricStripItem } from "@/components/metric-strip";
import { RankedBarList, type RankedItem } from "@/components/ranked-bar-list";
import { GeoAttackDistribution } from "@/components/geo-attack-distribution";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatNumber } from "@/lib/utils";
import {
  chartTooltipStyle,
  chartTooltipLabelStyle,
  CHART_ACCENT,
  CHART_DANGER,
  CHART_GRID_STROKE,
  CHART_AXIS_TICK,
} from "@/lib/chart-theme";
import {
  IconChartBar,
  IconShield,
  IconBan,
  IconBolt,
  IconTrendingUp,
  IconClock,
  IconActivity,
  IconMaximize,
  IconCategory2,
  IconTargetArrow,
  IconListNumbers,
} from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import {
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  AreaChart,
  Area,
  Legend,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import Link from "next/link";

const MAX_QPS_POINTS = 60;

interface QPSPoint {
  time: string;
  qps: number;
}

/**
 * `/api/v1/security-events/stats` 的返回结构。
 *
 * 字段名取自 `internal/admin/event/security.go` 的 `SecurityEventStats`，
 * 其中 `categories` 为完整 GROUP BY，`top_*` 系列均被后端限制为 10 条。
 */
interface SecurityEventStats {
  total: number;
  hours: number;
  intercepts: number;
  observes: number;
  challenges: number;
  requests: number;
  categories: Array<{ category: string; count: number }> | null;
  top_ips: Array<{ client_ip: string; count: number }> | null;
  top_paths: Array<{ path: string; count: number }> | null;
  top_rules: Array<{ rule_id_str: string; count: number }> | null;
  top_countries: Array<{ country: string; count: number }> | null;
}

/**
 * 带渐变填充的面积图。
 *
 * 网格使用实心发丝线：虚线网格会被读作「阈值」或「预测区间」，而这里只是刻度参考。
 */
function GradientArea({
  data,
  dataKey,
  color,
  gradientId,
  name,
}: {
  data: object[];
  dataKey: string;
  color: string;
  gradientId: string;
  name?: string;
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 6, right: 10, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.28} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid
          vertical={false}
          stroke={CHART_GRID_STROKE}
          strokeOpacity={0.7}
        />
        <XAxis
          dataKey="time"
          tick={CHART_AXIS_TICK}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
          minTickGap={24}
        />
        {/* 刻度缩写为 20k/15k，避免五位数被轴宽截断成 "000"、"500" */}
        <YAxis
          tick={CHART_AXIS_TICK}
          tickLine={false}
          axisLine={false}
          width={38}
          allowDecimals={false}
          tickFormatter={(v: number) => formatNumber(v)}
        />
        <Tooltip
          contentStyle={chartTooltipStyle}
          labelStyle={chartTooltipLabelStyle}
          cursor={{ stroke: CHART_GRID_STROKE, strokeWidth: 1 }}
        />
        <Area
          type="monotone"
          dataKey={dataKey}
          stroke={color}
          strokeWidth={2}
          fill={`url(#${gradientId})`}
          name={name}
          activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--card)" }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-3">
      <Skeleton className="h-9 w-80" />
      <div className="grid gap-2.5 grid-cols-2 md:grid-cols-4">
        {Array.from({ length: 12 }).map((_, i) => (
          <Skeleton key={i} className="h-20" />
        ))}
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Skeleton className="h-72" />
        <Skeleton className="h-72" />
      </div>
    </div>
  );
}

const PIE_COLORS = ["#14b8a6", "#6366f1", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

export default function DashboardPage() {
  const { t } = useTranslation();
  const [timeRange, setTimeRange] = useState("24");
  const hours = timeRange === "168" ? 168 : Number(timeRange);
  const { data, isLoading, error } = useDashboard();
  const { data: timelineData } = useSecurityEventTimeline({ hours });
  const { data: statsData } = useDashboardStats({ hours });

  const qpsHistoryRef = useRef<QPSPoint[]>([]);
  const [qpsHistory, setQpsHistory] = useState<QPSPoint[]>([]);

  const updateQpsHistory = useCallback(() => {
    if (!data) return;
    const now = new Date();
    const timeStr = `${now.getHours().toString().padStart(2, "0")}:${now.getMinutes().toString().padStart(2, "0")}:${now.getSeconds().toString().padStart(2, "0")}`;
    const point: QPSPoint = { time: timeStr, qps: data.qps_5s ?? data.qps_1s ?? 0 };
    const history = [...qpsHistoryRef.current, point];
    if (history.length > MAX_QPS_POINTS) {
      history.splice(0, history.length - MAX_QPS_POINTS);
    }
    qpsHistoryRef.current = history;
    setQpsHistory([...history]);
  }, [data]);

  useEffect(() => {
    updateQpsHistory();
  }, [data, updateQpsHistory]);

  if (isLoading) {
    return <DashboardSkeleton />;
  }

  if (error || !data) {
    return (
      <div className="space-y-6 p-6">
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>{(error as Error)?.message || t("error.unexpectedError")}</AlertDescription>
        </Alert>
      </div>
    );
  }

  const d = data;

  // 后端 /security-events/timeline 返回 { buckets: [{ bucket: "2026-07-26 06:00", count }] }，
  // 字段名是 bucket 而非 time，格式为空格分隔而非 ISO。取末尾的 HH:mm 作为轴标签。
  const blockTimeline: Array<{ time: string; count: number }> =
    timelineData?.buckets?.map((b: unknown) => {
      const raw = (b as { bucket?: unknown }).bucket;
      const label =
        typeof raw === "string"
          ? (raw.split(" ")[1] ?? raw).slice(0, 5) || raw
          : "";
      return {
        time: label,
        count: ((b as { count?: unknown }).count as number | undefined) ?? 0,
      };
    }) || [];

  const cveByType = d.cve_by_type_24h || [];
  const dropBySource = d.drop_by_source_24h || {};
  const dropPieData = Object.entries(dropBySource)
    .filter(([, v]) => (v as number) > 0)
    .map(([k, v]) => ({ name: k, value: v as number }));

  // 拦截趋势的真实序列，用于统计卡的迷你折线（与「访问/拦截趋势」图同源）
  const blockSparkline = blockTimeline.map((b) => b.count);

  // ---- 窗口口径指标：来自 /security-events/stats，随上方时间范围变化 ----
  // 注意与 /dashboard/summary 的区别：后者是进程内 atomic 计数（重启归零、不随时间范围变化），
  // 两者口径不同，必须分区展示，否则时间范围切换后数字不动会让人以为页面坏了。
  const s = statsData as SecurityEventStats | undefined;
  const eventsTotal = s?.total ?? 0;
  const intercepts = s?.intercepts ?? 0;
  const categories = s?.categories ?? [];
  // categories 是完整 GROUP BY（后端未截断），因此类别数可作为真实聚合值使用；
  // top_ips / top_paths / top_rules 均被后端限制为 10 条，其长度不能当作总数。
  const attackTypeCount = categories.length;
  const interceptShare = eventsTotal > 0 ? (intercepts / eventsTotal) * 100 : 0;

  const categoryItems: RankedItem[] = categories.map((c) => ({
    label: c.category,
    count: c.count,
  }));
  const ruleItems: RankedItem[] = (s?.top_rules ?? []).map((r) => ({
    label: r.rule_id_str,
    count: r.count,
  }));

  const uptimeText = `${Math.floor(d.uptime_sec / 86400)}d ${Math.floor(
    (d.uptime_sec % 86400) / 3600
  )}h ${Math.floor((d.uptime_sec % 3600) / 60)}m`;

  const pct = (part: number, whole: number) =>
    whole > 0 ? ((part / whole) * 100).toFixed(2) + "%" : "0%";

  /** 运行时累计计数：全部来自 /dashboard/summary 的进程内计数器 */
  const runtimeItems: MetricStripItem[] = [
    { label: t("dashboard.requests"), value: formatNumber(d.requests_total), rawValue: d.requests_total },
    { label: t("dashboard.pv"), value: formatNumber(d.status_2xx), rawValue: d.status_2xx },
    { label: t("dashboard.uniqueIp"), value: formatNumber(d.unique_ips), rawValue: d.unique_ips },
    { label: t("dashboard.attackIp"), value: formatNumber(d.attack_ips), rawValue: d.attack_ips },
    { label: t("dashboard.blocks"), value: formatNumber(d.waf_blocks), rawValue: d.waf_blocks },
    { label: t("dashboard.uv"), value: formatNumber(d.waf_observes), rawValue: d.waf_observes },
    {
      label: t("dashboard.blocks4xxRate"),
      value: formatNumber(d.builtin_hits),
      rawValue: d.builtin_hits,
    },
    {
      label: t("dashboard.blocks4xx"),
      value: pct(d.waf_blocks, d.requests_total),
      rawValue: d.waf_blocks,
    },
    { label: t("dashboard.errors4xx"), value: formatNumber(d.errors_upstream_4xx), rawValue: d.errors_upstream_4xx },
    {
      label: t("dashboard.errors4xxRate"),
      value: pct(d.errors_upstream_4xx, d.requests_total),
      rawValue: d.errors_upstream_4xx,
    },
    { label: t("dashboard.errors5xx"), value: formatNumber(d.errors_upstream_5xx), rawValue: d.errors_upstream_5xx },
    {
      label: t("dashboard.errors5xxRate"),
      value: pct(d.errors_upstream_5xx, d.requests_total),
      rawValue: d.errors_upstream_5xx,
    },
  ];

  return (
    <div className="space-y-3">
      <Tabs defaultValue="traffic">
        {/* 顶部导航：Tabs + 时间筛选 */}
        <div className="flex items-center justify-between gap-4">
          <TabsList>
            <TabsTrigger value="traffic">{t("dashboard.tabTraffic")}</TabsTrigger>
            <TabsTrigger value="security">{t("dashboard.tabSecurity")}</TabsTrigger>
            <TabsTrigger value="report">{t("dashboard.tabReport")}</TabsTrigger>
            <TabsTrigger value="fullscreen" asChild>
              <Link
                href="/security-dashboard"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1"
              >
                <IconMaximize className="h-3.5 w-3.5" />
                {t("dashboard.tabFullscreen")}
              </Link>
            </TabsTrigger>
          </TabsList>
          <div className="flex items-center gap-2">
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="h-8 w-36 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">{t("dashboard.timeRange1h")}</SelectItem>
                <SelectItem value="6">{t("dashboard.timeRange6h")}</SelectItem>
                <SelectItem value="24">{t("dashboard.timeRange24h")}</SelectItem>
                <SelectItem value="168">{t("dashboard.timeRange7d")}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Tab: 流量分析 */}
        <TabsContent value="traffic" className="space-y-3">
          {/* 第一层：窗口口径的攻击拦截主指标（随时间范围变化的真实聚合） */}
          <div className="grid gap-2.5 grid-cols-2 lg:grid-cols-4">
            <MetricTile
              title={t("dashboard.securityEvents")}
              value={formatNumber(eventsTotal)}
              rawValue={eventsTotal}
              tone="accent"
              icon={<IconChartBar className="h-3.5 w-3.5" />}
              description={t("dashboard.securityEventsDesc")}
              badge={
                <Badge variant="outline" className="h-5 shrink-0 text-[10px]">
                  {hours}h
                </Badge>
              }
              sparkline={blockSparkline}
              sparklineLabel={t("dashboard.eventSparklineHint", { hours })}
            />
            {/*
              「已拦截」不挂折线：/security-events/timeline 是对全部安全事件做 COUNT(*)，
              并未按 action 过滤，挂在拦截指标下会被误读成「拦截数随时间的变化」。
            */}
            <MetricTile
              title={t("dashboard.intercepted")}
              value={formatNumber(intercepts)}
              rawValue={intercepts}
              tone="danger"
              icon={<IconBan className="h-3.5 w-3.5" />}
              description={t("dashboard.interceptedDesc")}
            />
            <MetricTile
              title={t("dashboard.attackTypes")}
              value={formatNumber(attackTypeCount)}
              rawValue={attackTypeCount}
              tone="warning"
              icon={<IconCategory2 className="h-3.5 w-3.5" />}
              description={t("dashboard.attackTypesDesc")}
            />
            <MetricTile
              title={t("dashboard.interceptShare")}
              value={eventsTotal > 0 ? interceptShare.toFixed(1) + "%" : "0%"}
              rawValue={eventsTotal}
              tone="success"
              icon={<IconTargetArrow className="h-3.5 w-3.5" />}
              description={t("dashboard.interceptShareDesc")}
            />
          </div>

          {/* 第二层：进程内运行时计数，口径与上方不同，折叠成紧凑指标条 */}
          <MetricStrip
            title={t("dashboard.runtimeCounters")}
            caption={t("dashboard.runtimeCountersCaption")}
            action={
              <Badge variant="secondary" className="h-5 shrink-0 gap-1 text-[10px]">
                <IconClock className="h-3 w-3" />
                {uptimeText}
              </Badge>
            }
            items={runtimeItems}
          />

          {/* 第三层：趋势图 */}
          <div className="grid gap-3 lg:grid-cols-2">
            <Card className="py-0">
              <CardHeader className="flex-row items-center justify-between px-4 py-2.5">
                <CardTitle className="text-sm font-medium">
                  {t("dashboard.visitBlockTrend")}
                </CardTitle>
                <Badge variant="outline" className="h-5 text-[10px]">{hours}h</Badge>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="h-52">
                  {blockTimeline.length > 0 ? (
                    <GradientArea
                      data={blockTimeline}
                      dataKey="count"
                      color={CHART_DANGER}
                      gradientId="dashBlockTrend"
                      name={t("dashboard.blocks")}
                    />
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                      {t("dashboard.noData")}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card className="py-0">
              <CardHeader className="flex-row items-center justify-between px-4 py-2.5">
                <CardTitle className="text-sm font-medium">
                  {t("dashboard.realtimeQps")}
                </CardTitle>
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <IconActivity className="h-3.5 w-3.5" />
                  <span className="tabular-nums">{d.qps_5s ?? 0}</span>
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="h-52">
                  {qpsHistory.length > 0 ? (
                    <GradientArea
                      data={qpsHistory}
                      dataKey="qps"
                      color={CHART_ACCENT}
                      gradientId="dashQps"
                      name="QPS"
                    />
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                      {t("dashboard.waitingData")}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* 第四层：攻击构成 —— 类别分布与规则命中排行，均为窗口口径真实聚合 */}
          <div className="grid gap-3 lg:grid-cols-2">
            <RankedBarList
              title={t("dashboard.attackCategoryDist")}
              action={
                <Badge variant="outline" className="h-5 text-[10px]">{hours}h</Badge>
              }
              items={categoryItems}
              restLabel={(n) => t("dashboard.otherCategories", { count: n })}
              emptyText={t("dashboard.noData")}
              tone="danger"
            />
            <RankedBarList
              title={t("dashboard.topRuleHits")}
              action={
                <Badge variant="outline" className="h-5 gap-1 text-[10px]">
                  <IconListNumbers className="h-3 w-3" />
                  {hours}h
                </Badge>
              }
              items={ruleItems}
              maxItems={8}
              emptyText={t("dashboard.noData")}
              tone="accent"
            />
          </div>
        </TabsContent>

        {/* Tab: 安全态势 */}
        <TabsContent value="security" className="space-y-3">
          {/* Bot / CVE / Drop 统计 */}
          <div className="grid gap-3 lg:grid-cols-3">
            <Card>
              <CardHeader className="px-4 py-2.5">
                <CardTitle className="text-sm font-medium">{t("dashboard.botDetect24h")}</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="space-y-2.5">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t("dashboard.totalDetect")}</span>
                    <span className="font-semibold">{formatNumber(d.bot_total_24h)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t("dashboard.blocked")}</span>
                    <span className="font-semibold text-red-600">{formatNumber(d.bot_blocked_24h)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t("dashboard.highRisk")}</span>
                    <span className="font-semibold text-amber-600">{formatNumber(d.bot_high_risk_24h)}</span>
                  </div>
                  {d.bot_total_24h > 0 && (
                    <div className="pt-1">
                      <div className="h-2 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full bg-red-500 transition-all"
                          style={{ width: `${Math.min(100, (d.bot_blocked_24h / d.bot_total_24h) * 100)}%` }}
                        />
                      </div>
                      <p className="mt-1 text-[10px] text-muted-foreground">
                        {((d.bot_blocked_24h / d.bot_total_24h) * 100).toFixed(1)}% {t("dashboard.blockRate")}
                      </p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="px-4 py-2.5">
                <CardTitle className="text-sm font-medium">{t("dashboard.cveDetect24h")}</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="space-y-2.5">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t("dashboard.totalDetect")}</span>
                    <span className="font-semibold">{formatNumber(d.cve_total_24h)}</span>
                  </div>
                  {cveByType.length > 0 ? (
                    <div className="h-36">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={cveByType.map((c: { category: string; count: number }) => ({ name: c.category, value: c.count }))}
                            cx="50%"
                            cy="50%"
                            innerRadius={28}
                            outerRadius={50}
                            paddingAngle={2}
                            dataKey="value"
                          >
                            {cveByType.map((_: unknown, i: number) => (
                              <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend layout="vertical" align="right" verticalAlign="middle" wrapperStyle={{ fontSize: 10 }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    cveByType.map((item: { category: string; count: number }) => (
                      <div key={item.category} className="flex justify-between text-sm">
                        <span className="text-muted-foreground">{item.category}</span>
                        <span className="font-medium">{formatNumber(item.count)}</span>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="px-4 py-2.5">
                <CardTitle className="text-sm font-medium">{t("dashboard.dropEvents24h")}</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="space-y-2.5">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t("dashboard.total")}</span>
                    <span className="font-semibold">{formatNumber(d.drop_total_24h)}</span>
                  </div>
                  {dropPieData.length > 0 ? (
                    <div className="h-36">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={dropPieData}
                            cx="50%"
                            cy="50%"
                            innerRadius={28}
                            outerRadius={50}
                            paddingAngle={2}
                            dataKey="value"
                          >
                            {dropPieData.map((_, i) => (
                              <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend layout="vertical" align="right" verticalAlign="middle" wrapperStyle={{ fontSize: 10 }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    Object.entries(dropBySource).map(([source, count]) => (
                      <div key={source} className="flex justify-between text-sm">
                        <span className="text-muted-foreground">{source}</span>
                        <span className="font-medium">{formatNumber(count as number)}</span>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Top 攻击 IP + Top 攻击路径 + 地理分布 */}
          <div className="grid gap-3 lg:grid-cols-3">
            <Card>
              <CardHeader className="flex-row items-center justify-between px-4 py-2.5">
                <CardTitle className="text-sm font-medium">
                  {t("dashboard.topIps")}
                </CardTitle>
                <Badge variant="outline" className="h-5 text-[10px]">{hours}h</Badge>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                {statsData?.top_ips && statsData.top_ips.length > 0 ? (
                  <div className="space-y-1.5">
                    {statsData.top_ips.map((item: { client_ip: string; count: number }, idx: number) => (
                      <Link
                        key={item.client_ip}
                        href={`/security-events?client_ip=${encodeURIComponent(item.client_ip)}`}
                        className="flex items-center gap-2.5 rounded-md px-2 py-1 text-sm transition-colors hover:bg-muted"
                      >
                        <span className="w-4 text-center text-xs font-medium text-muted-foreground">
                          {idx + 1}
                        </span>
                        <span className="flex-1 truncate font-mono text-xs">
                          {item.client_ip}
                        </span>
                        <Badge variant="secondary" className="text-[10px]">
                          {formatNumber(item.count)}
                        </Badge>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="flex h-36 items-center justify-center text-sm text-muted-foreground">
                    {t("dashboard.noData")}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex-row items-center justify-between px-4 py-2.5">
                <CardTitle className="text-sm font-medium">
                  {t("dashboard.topUrls")}
                </CardTitle>
                <Badge variant="outline" className="h-5 text-[10px]">{hours}h</Badge>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                {statsData?.top_paths && statsData.top_paths.length > 0 ? (
                  <div className="space-y-1.5">
                    {statsData.top_paths.map((item: { path: string; count: number }, idx: number) => (
                      <Link
                        key={item.path}
                        href={`/security-events?path=${encodeURIComponent(item.path)}`}
                        className="flex items-center gap-2.5 rounded-md px-2 py-1 text-sm transition-colors hover:bg-muted"
                      >
                        <span className="w-4 text-center text-xs font-medium text-muted-foreground">
                          {idx + 1}
                        </span>
                        <span className="flex-1 truncate font-mono text-xs">
                          {item.path}
                        </span>
                        <Badge variant="secondary" className="text-[10px]">
                          {formatNumber(item.count)}
                        </Badge>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="flex h-36 items-center justify-center text-sm text-muted-foreground">
                    {t("dashboard.noData")}
                  </div>
                )}
              </CardContent>
            </Card>

            <GeoAttackDistribution data={statsData?.top_countries} hours={hours} />
          </div>
        </TabsContent>

        {/* Tab: 防护报告 */}
        <TabsContent value="report" className="space-y-3">
          {/*
            核心指标概览。与「流量分析」同口径：用 /security-events/stats 的窗口聚合，
            而非 /dashboard/summary 的进程内计数 —— 防护报告按时间范围出具，
            用重启即归零的累计值会让报告在每次重启后失真。
          */}
          <div className="grid gap-2.5 grid-cols-2 lg:grid-cols-4">
            <MetricTile
              title={t("dashboard.securityEvents")}
              value={formatNumber(eventsTotal)}
              rawValue={eventsTotal}
              tone="accent"
              icon={<IconChartBar className="h-3.5 w-3.5" />}
              description={t("dashboard.securityEventsDesc")}
              badge={
                <Badge variant="outline" className="h-5 shrink-0 text-[10px]">
                  {hours}h
                </Badge>
              }
              sparkline={blockSparkline}
              sparklineLabel={t("dashboard.eventSparklineHint", { hours })}
            />
            <MetricTile
              title={t("dashboard.intercepted")}
              value={formatNumber(intercepts)}
              rawValue={intercepts}
              tone="danger"
              icon={<IconBan className="h-3.5 w-3.5" />}
              description={t("dashboard.interceptedDesc")}
            />
            <MetricTile
              title={t("dashboard.attackTypes")}
              value={formatNumber(attackTypeCount)}
              rawValue={attackTypeCount}
              tone="warning"
              icon={<IconCategory2 className="h-3.5 w-3.5" />}
              description={t("dashboard.attackTypesDesc")}
            />
            <MetricTile
              title={t("dashboard.errors5xx")}
              value={formatNumber(d.errors_upstream_5xx)}
              rawValue={d.errors_upstream_5xx}
              tone="warning"
              icon={<IconTrendingUp className="h-3.5 w-3.5" />}
              description={t("dashboard.upstream5xx")}
            />
          </div>

          {/* 拦截趋势 */}
          <Card>
            <CardHeader className="flex-row items-center justify-between px-4 py-2.5">
              <CardTitle className="text-sm font-medium">
                {t("dashboard.visitBlockTrend")}
              </CardTitle>
              <Badge variant="outline" className="h-5 text-[10px]">{hours}h</Badge>
            </CardHeader>
            <CardContent className="px-4 pb-3 pt-0">
              <div className="h-56">
                {blockTimeline.length > 0 ? (
                  <GradientArea
                    data={blockTimeline}
                    dataKey="count"
                    color={CHART_DANGER}
                    gradientId="reportBlockTrend"
                    name={t("dashboard.blocks")}
                  />
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                    {t("dashboard.noData")}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Bot / CVE / Drop 摘要 + 地理分布 */}
          <div className="grid gap-3 lg:grid-cols-2">
            <Card>
              <CardHeader className="px-4 py-2.5">
                <CardTitle className="text-sm font-medium">{t("dashboard.botDetect24h")}</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center">
                    <div className="text-lg font-bold">{formatNumber(d.bot_total_24h)}</div>
                    <div className="text-xs text-muted-foreground">{t("dashboard.totalDetect")}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-red-600">{formatNumber(d.bot_blocked_24h)}</div>
                    <div className="text-xs text-muted-foreground">{t("dashboard.blocked")}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-amber-600">{formatNumber(d.bot_high_risk_24h)}</div>
                    <div className="text-xs text-muted-foreground">{t("dashboard.highRisk")}</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <GeoAttackDistribution data={statsData?.top_countries} hours={hours} />
          </div>
        </TabsContent>
      </Tabs>

      {/* 运行时信息 - 始终显示 */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-5 py-3 px-4">
          <div className="flex items-center gap-2 text-sm">
            <IconClock className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">{t("dashboard.uptime")}:</span>
            <span className="font-medium">
              {Math.floor(d.uptime_sec / 86400)}d {Math.floor((d.uptime_sec % 86400) / 3600)}h {Math.floor((d.uptime_sec % 3600) / 60)}m
            </span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <IconBolt className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">QPS:</span>
            <span className="font-medium">{d.qps_1s}/{d.qps_5s}</span>
            <span className="text-xs text-muted-foreground">(1s/5s)</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <IconShield className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">{t("dashboard.observe")}:</span>
            <span className="font-medium">{formatNumber(d.waf_observes)}</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <IconActivity className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">{t("dashboard.revision")}:</span>
            <span className="font-medium">{d.revision}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
