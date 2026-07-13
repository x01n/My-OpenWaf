"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { StatCard } from "@/components/stat-card";
import { GeoAttackDistribution } from "@/components/geo-attack-distribution";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  IconChartBar,
  IconBan,
  IconEye,
  IconPuzzle,
} from "@tabler/icons-react";
import { useSiteStats, useSiteTimeline } from "@/hooks/use-api";
import { formatNumber } from "@/lib/utils";
import type { Site } from "@/lib/types";

/**
 * 站点级实时监控 Tab 属性。
 * @property site 当前站点对象，仅使用 id 触发接口
 */
interface MonitorTabProps {
  site: Site;
}

/** 时间线桶结构（后端 GET /security-events/timeline 返回） */
interface TimelineBucket {
  bucket?: string;
  time?: string;
  count?: number;
}

/** stats 接口返回结构（仅使用需要的字段） */
interface SiteStatsResp {
  total?: number;
  hours?: number;
  requests?: number;
  intercepts?: number;
  observes?: number;
  challenges?: number;
  categories?: Array<{ category: string; count: number }>;
  top_ips?: Array<{ client_ip: string; count: number }>;
  top_paths?: Array<{ path: string; count: number }>;
  top_countries?: Array<{ country: string; count: number }>;
}

interface SiteTimelineResp {
  buckets?: TimelineBucket[];
  hours?: number;
}

/** 饼图配色，与 dashboard 保持一致 */
const PIE_COLORS = [
  "#14b8a6",
  "#6366f1",
  "#f59e0b",
  "#ef4444",
  "#8b5cf6",
  "#ec4899",
];

/** 30 秒自动刷新间隔（毫秒） */
const REFRESH_INTERVAL_MS = 30_000;

/**
 * 站点级实时监控 Tab。
 * 使用站点级 stats/timeline 接口，30s 轮询刷新，展示核心指标、
 * 趋势、类别、Top IP/路径与国家分布。
 */
export function MonitorTab({ site }: MonitorTabProps) {
  const { t } = useTranslation();
  const [timeRange, setTimeRange] = useState("24");
  const hours = timeRange === "168" ? 168 : Number(timeRange);

  const { data: statsData } = useSiteStats(
    site.id,
    { hours },
    { refreshInterval: REFRESH_INTERVAL_MS }
  ) as { data: SiteStatsResp | undefined };
  const { data: timelineData } = useSiteTimeline(
    site.id,
    { hours },
    { refreshInterval: REFRESH_INTERVAL_MS }
  ) as { data: SiteTimelineResp | undefined };

  /**
   * 时间线数据归一化：兼容 bucket / time 两种字段，仅取时分段。
   */
  const trendData = useMemo(() => {
    const rows = timelineData?.buckets || [];
    return rows.map((b) => {
      const raw = b.bucket || b.time || "";
      const label = raw.length >= 16 ? raw.slice(11, 16) : raw;
      return { time: label, count: Number(b.count ?? 0) };
    });
  }, [timelineData]);

  const categories = statsData?.categories || [];
  const topIps = statsData?.top_ips || [];
  const topPaths = statsData?.top_paths || [];
  const topCountries = statsData?.top_countries || [];

  const pieData = categories
    .filter((c) => c.count > 0)
    .map((c) => ({ name: c.category, value: c.count }));

  return (
    <div className="space-y-4">
      {/* 顶部：时间范围与刷新提示 */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="outline" className="h-5 text-[10px]">
            {t("sites.detail.monitor.autoRefresh")}
          </Badge>
          <span>{t("sites.detail.monitor.autoRefreshHint")}</span>
        </div>
        <Select value={timeRange} onValueChange={setTimeRange}>
          <SelectTrigger className="w-40">
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

      {/* 关键指标 */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title={t("sites.detail.monitor.requests")}
          value={formatNumber(statsData?.requests ?? 0)}
          icon={<IconChartBar className="h-4 w-4" />}
          description={t("sites.detail.monitor.requestsDesc")}
        />
        <StatCard
          title={t("sites.detail.monitor.intercepts")}
          value={formatNumber(statsData?.intercepts ?? 0)}
          icon={<IconBan className="h-4 w-4" />}
          description={t("sites.detail.monitor.interceptsDesc")}
          trend="down"
        />
        <StatCard
          title={t("sites.detail.monitor.observes")}
          value={formatNumber(statsData?.observes ?? 0)}
          icon={<IconEye className="h-4 w-4" />}
          description={t("sites.detail.monitor.observesDesc")}
        />
        <StatCard
          title={t("sites.detail.monitor.challenges")}
          value={formatNumber(statsData?.challenges ?? 0)}
          icon={<IconPuzzle className="h-4 w-4" />}
          description={t("sites.detail.monitor.challengesDesc")}
        />
      </div>

      {/* 攻击趋势 + 类别分布 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              {t("sites.detail.monitor.attackTrend")}
            </CardTitle>
            <Badge variant="outline" className="h-5 text-[10px]">
              {hours}h
            </Badge>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              {trendData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData}>
                    <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                    <XAxis
                      dataKey="time"
                      fontSize={10}
                      tickLine={false}
                      axisLine={false}
                      interval="preserveStartEnd"
                    />
                    <YAxis fontSize={12} tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "hsl(var(--card))",
                        border: "1px solid hsl(var(--border))",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="#ef4444"
                      fill="rgba(239,68,68,0.12)"
                      strokeWidth={2}
                      name={t("sites.detail.monitor.attackTrend")}
                    />
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

        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              {t("sites.detail.monitor.attackCategory")}
            </CardTitle>
            <Badge variant="outline" className="h-5 text-[10px]">
              {hours}h
            </Badge>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={90}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {pieData.map((_, i) => (
                        <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend
                      layout="vertical"
                      align="right"
                      verticalAlign="middle"
                      wrapperStyle={{ fontSize: 11 }}
                    />
                  </PieChart>
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

      {/* Top IP / Top 路径 / 国家分布 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              {t("sites.detail.monitor.topAttackIPs")}
            </CardTitle>
            <Badge variant="outline" className="h-5 text-[10px]">
              {hours}h
            </Badge>
          </CardHeader>
          <CardContent>
            {topIps.length > 0 ? (
              <div className="space-y-2">
                {topIps.slice(0, 5).map((item, idx) => (
                  <Link
                    key={item.client_ip}
                    href={`/security-events?site_id=${site.id}&client_ip=${encodeURIComponent(item.client_ip)}`}
                    className="flex items-center gap-3 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted"
                  >
                    <span className="w-5 text-center text-xs font-medium text-muted-foreground">
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
              <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
                {t("dashboard.noData")}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              {t("sites.detail.monitor.topAttackPaths")}
            </CardTitle>
            <Badge variant="outline" className="h-5 text-[10px]">
              {hours}h
            </Badge>
          </CardHeader>
          <CardContent>
            {topPaths.length > 0 ? (
              <div className="space-y-2">
                {topPaths.slice(0, 5).map((item, idx) => (
                  <Link
                    key={item.path}
                    href={`/security-events?site_id=${site.id}&path=${encodeURIComponent(item.path)}`}
                    className="flex items-center gap-3 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted"
                  >
                    <span className="w-5 text-center text-xs font-medium text-muted-foreground">
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
              <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
                {t("dashboard.noData")}
              </div>
            )}
          </CardContent>
        </Card>

        <GeoAttackDistribution data={topCountries} hours={hours} />
      </div>
    </div>
  );
}
