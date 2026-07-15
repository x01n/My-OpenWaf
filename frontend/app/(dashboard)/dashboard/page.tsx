"use client";

import { useRef, useEffect, useState, useCallback } from "react";
import { useDashboard, useSecurityEventTimeline, useDashboardStats } from "@/hooks/use-api";
import { StatCard } from "@/components/stat-card";
import { GeoAttackDistribution } from "@/components/geo-attack-distribution";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatNumber } from "@/lib/utils";
import {
  IconChartBar,
  IconShield,
  IconEye,
  IconUsers,
  IconMapPin,
  IconBan,
  IconAlertTriangle,
  IconBolt,
  IconTrendingUp,
  IconTrendingDown,
  IconClock,
  IconActivity,
  IconMaximize,
  IconPercentage,
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
  const { data, isLoading } = useDashboard();
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

  if (isLoading || !data) {
    return <DashboardSkeleton />;
  }

  const d = data;

  const blockTimeline: Array<{ time: string; count: number }> =
    timelineData?.buckets?.map((b: unknown) => ({
      time: typeof (b as { time: unknown }).time === "string"
        ? ((b as { time: string }).time).slice(11, 16)
        : String((b as { time: unknown }).time),
      count: ((b as { count: unknown }).count as number | undefined) ?? 0,
    })) || [];

  const cveByType = d.cve_by_type_24h || [];
  const dropBySource = d.drop_by_source_24h || {};
  const dropPieData = Object.entries(dropBySource)
    .filter(([, v]) => (v as number) > 0)
    .map(([k, v]) => ({ name: k, value: v as number }));

  const tooltipStyle = {
    backgroundColor: "hsl(var(--card))",
    border: "1px solid hsl(var(--border))",
    borderRadius: "8px",
    fontSize: "12px",
  };

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
          {/* 统计卡片 3 行 x 4 列 */}
          <div className="grid gap-2.5 grid-cols-2 md:grid-cols-4">
            <StatCard
              compact
              title={t("dashboard.requests")}
              value={formatNumber(d.requests_total)}
              icon={<IconChartBar className="h-3.5 w-3.5" />}
              description={t("dashboard.requestsDesc")}
            />
            <StatCard
              compact
              title={t("dashboard.pv")}
              value={formatNumber(d.status_2xx)}
              icon={<IconEye className="h-3.5 w-3.5" />}
              description={t("dashboard.pvDesc")}
            />
            <StatCard
              compact
              title={t("dashboard.uv")}
              value={formatNumber(d.unique_ips)}
              icon={<IconUsers className="h-3.5 w-3.5" />}
              description={t("dashboard.uvDesc")}
            />
            <StatCard
              compact
              title={t("dashboard.uniqueIp")}
              value={formatNumber(d.unique_ips)}
              icon={<IconMapPin className="h-3.5 w-3.5" />}
              description={t("dashboard.uniqueIpDesc")}
            />
          </div>

          <div className="grid gap-2.5 grid-cols-2 md:grid-cols-4">
            <StatCard
              compact
              title={t("dashboard.blocks")}
              value={formatNumber(d.waf_blocks)}
              icon={<IconBan className="h-3.5 w-3.5" />}
              description={t("dashboard.blocksDesc")}
              trend="down"
            />
            <StatCard
              compact
              title={t("dashboard.attackIp")}
              value={formatNumber(d.attack_ips)}
              icon={<IconAlertTriangle className="h-3.5 w-3.5" />}
              description={t("dashboard.attackIpDesc")}
              trend="down"
            />
            <StatCard
              compact
              title={t("dashboard.errors4xx")}
              value={formatNumber(d.errors_upstream_4xx)}
              icon={<IconTrendingDown className="h-3.5 w-3.5" />}
              description={t("dashboard.upstream4xx")}
            />
            <StatCard
              compact
              title={t("dashboard.errors4xxRate")}
              value={d.requests_total > 0 ? ((d.errors_upstream_4xx / d.requests_total) * 100).toFixed(2) + "%" : "0%"}
              icon={<IconPercentage className="h-3.5 w-3.5" />}
              description={t("dashboard.upstream4xxDesc")}
            />
          </div>

          <div className="grid gap-2.5 grid-cols-2 md:grid-cols-4">
            <StatCard
              compact
              title={t("dashboard.blocks4xx")}
              value={formatNumber(d.waf_blocks)}
              icon={<IconShield className="h-3.5 w-3.5" />}
              description={t("dashboard.blocksDesc")}
            />
            <StatCard
              compact
              title={t("dashboard.blocks4xxRate")}
              value={d.errors_upstream_4xx > 0 ? ((d.waf_blocks / d.errors_upstream_4xx) * 100).toFixed(2) + "%" : "0%"}
              icon={<IconShield className="h-3.5 w-3.5" />}
              description={t("dashboard.blockRate")}
            />
            <StatCard
              compact
              title={t("dashboard.errors5xx")}
              value={formatNumber(d.errors_upstream_5xx)}
              icon={<IconTrendingUp className="h-3.5 w-3.5" />}
              description={t("dashboard.upstream5xx")}
            />
            <StatCard
              compact
              title={t("dashboard.errors5xxRate")}
              value={d.requests_total > 0 ? ((d.errors_upstream_5xx / d.requests_total) * 100).toFixed(2) + "%" : "0%"}
              icon={<IconPercentage className="h-3.5 w-3.5" />}
              description={t("dashboard.upstream5xxDesc")}
            />
          </div>

          {/* 实时 QPS + 拦截趋势 */}
          <div className="grid gap-3 lg:grid-cols-2">
            <Card>
              <CardHeader className="flex-row items-center justify-between px-4 py-2.5">
                <CardTitle className="text-sm font-medium">
                  {t("dashboard.realtimeQps")}
                </CardTitle>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <IconActivity className="h-3.5 w-3.5" />
                  <span>{d.qps_5s ?? 0}</span>
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-3 pt-0">
                <div className="h-56">
                  {qpsHistory.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={qpsHistory}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                        <XAxis dataKey="time" fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                        <YAxis fontSize={11} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={tooltipStyle} />
                        <Area type="monotone" dataKey="qps" stroke="hsl(var(--primary))" fill="hsl(var(--primary)/0.15)" strokeWidth={2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                      {t("dashboard.waitingData")}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

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
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={blockTimeline}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                        <XAxis dataKey="time" fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                        <YAxis fontSize={11} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={tooltipStyle} />
                        <Area type="monotone" dataKey="count" stroke="#ef4444" fill="rgba(239,68,68,0.12)" strokeWidth={2} name={t("dashboard.blocks")} />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                      {t("dashboard.noData")}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
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
          {/* 核心指标概览（紧凑卡片） */}
          <div className="grid gap-2.5 grid-cols-2 md:grid-cols-4">
            <StatCard
              compact
              title={t("dashboard.requests")}
              value={formatNumber(d.requests_total)}
              icon={<IconChartBar className="h-3.5 w-3.5" />}
              description={t("dashboard.requestsDesc")}
            />
            <StatCard
              compact
              title={t("dashboard.blocks")}
              value={formatNumber(d.waf_blocks)}
              icon={<IconBan className="h-3.5 w-3.5" />}
              description={t("dashboard.blocksDesc")}
              trend="down"
            />
            <StatCard
              compact
              title={t("dashboard.attackIp")}
              value={formatNumber(d.attack_ips)}
              icon={<IconAlertTriangle className="h-3.5 w-3.5" />}
              description={t("dashboard.attackIpDesc")}
              trend="down"
            />
            <StatCard
              compact
              title={t("dashboard.errors5xx")}
              value={formatNumber(d.errors_upstream_5xx)}
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
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={blockTimeline}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                      <XAxis dataKey="time" fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                      <YAxis fontSize={11} tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Area type="monotone" dataKey="count" stroke="#ef4444" fill="rgba(239,68,68,0.12)" strokeWidth={2} name={t("dashboard.blocks")} />
                    </AreaChart>
                  </ResponsiveContainer>
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
