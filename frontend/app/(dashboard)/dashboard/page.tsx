"use client";

import { useRef, useEffect, useState, useCallback } from "react";
import { useDashboard, useSecurityEventTimeline } from "@/hooks/use-api";
import { StatCard } from "@/components/stat-card";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
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
} from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  AreaChart,
  Area,
  Legend,
  PieChart,
  Pie,
  Cell,
} from "recharts";

const MAX_QPS_POINTS = 60;

interface QPSPoint {
  time: string;
  qps: number;
}

function DashboardSkeleton() {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-28" />
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Skeleton className="h-80" />
        <Skeleton className="h-80" />
      </div>
    </div>
  );
}

const PIE_COLORS = ["#14b8a6", "#6366f1", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

export default function DashboardPage() {
  const { t } = useTranslation();
  const { data, isLoading } = useDashboard();
  const { data: timelineData } = useSecurityEventTimeline({ hours: 24 });

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
    timelineData?.buckets?.map((b: any) => ({
      time: typeof b.time === "string" ? b.time.slice(11, 16) : String(b.time),
      count: b.count ?? 0,
    })) || [];

  const cveByType = d.cve_by_type_24h || [];
  const dropBySource = d.drop_by_source_24h || {};
  const dropPieData = Object.entries(dropBySource)
    .filter(([, v]) => (v as number) > 0)
    .map(([k, v]) => ({ name: k, value: v as number }));

  return (
    <div className="space-y-4">
      {/* 核心指标 */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard
          title={t("dashboard.requests")}
          value={formatNumber(d.requests_total)}
          icon={<IconChartBar className="h-4 w-4" />}
          description={t("dashboard.requestsDesc")}
        />
        <StatCard
          title={t("dashboard.pv")}
          value={formatNumber(d.status_2xx)}
          icon={<IconEye className="h-4 w-4" />}
          description={t("dashboard.pvDesc")}
        />
        <StatCard
          title={t("dashboard.uv")}
          value={formatNumber(d.unique_ips)}
          icon={<IconUsers className="h-4 w-4" />}
          description={t("dashboard.uvDesc")}
        />
        <StatCard
          title={t("dashboard.uniqueIp")}
          value={formatNumber(d.unique_ips)}
          icon={<IconMapPin className="h-4 w-4" />}
          description={t("dashboard.uniqueIpDesc")}
        />
        <StatCard
          title={t("dashboard.blocks")}
          value={formatNumber(d.waf_blocks)}
          icon={<IconBan className="h-4 w-4" />}
          description={t("dashboard.blocksDesc")}
          trend="down"
        />
        <StatCard
          title={t("dashboard.attackIp")}
          value={formatNumber(d.attack_ips)}
          icon={<IconAlertTriangle className="h-4 w-4" />}
          description={t("dashboard.attackIpDesc")}
          trend="down"
        />
      </div>

      {/* 错误统计 */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard
          title={t("dashboard.errors4xx")}
          value={formatNumber(d.errors_upstream_4xx)}
          icon={<IconTrendingDown className="h-4 w-4" />}
          description={t("dashboard.upstream4xx")}
        />
        <StatCard
          title={t("dashboard.errors4xxRate")}
          value={d.requests_total > 0 ? ((d.errors_upstream_4xx / d.requests_total) * 100).toFixed(2) + "%" : "0%"}
          icon={<IconTrendingDown className="h-4 w-4" />}
          description={t("dashboard.upstream4xxDesc")}
        />
        <StatCard
          title={t("dashboard.blocks4xx")}
          value={formatNumber(d.waf_blocks)}
          icon={<IconShield className="h-4 w-4" />}
          description={t("dashboard.blocksDesc")}
        />
        <StatCard
          title={t("dashboard.blocks4xxRate")}
          value={d.errors_upstream_4xx > 0 ? ((d.waf_blocks / d.errors_upstream_4xx) * 100).toFixed(2) + "%" : "0%"}
          icon={<IconShield className="h-4 w-4" />}
          description={t("dashboard.blockRate")}
        />
        <StatCard
          title={t("dashboard.errors5xx")}
          value={formatNumber(d.errors_upstream_5xx)}
          icon={<IconTrendingUp className="h-4 w-4" />}
          description={t("dashboard.upstream5xx")}
        />
        <StatCard
          title={t("dashboard.errors5xxRate")}
          value={d.requests_total > 0 ? ((d.errors_upstream_5xx / d.requests_total) * 100).toFixed(2) + "%" : "0%"}
          icon={<IconTrendingUp className="h-4 w-4" />}
          description={t("dashboard.upstream5xxDesc")}
        />
      </div>

      {/* 实时 QPS + 拦截趋势 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              {t("dashboard.realtimeQps")}
            </CardTitle>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <IconActivity className="h-3.5 w-3.5" />
              <span>{d.qps_5s ?? 0}</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              {qpsHistory.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={qpsHistory}>
                    <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                    <XAxis dataKey="time" fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                    <YAxis fontSize={12} tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "hsl(var(--card))",
                        border: "1px solid hsl(var(--border))",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
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
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              {t("dashboard.visitBlockTrend")}
            </CardTitle>
            <Badge variant="outline" className="h-5 text-[10px]">24h</Badge>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              {blockTimeline.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={blockTimeline}>
                    <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                    <XAxis dataKey="time" fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                    <YAxis fontSize={12} tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "hsl(var(--card))",
                        border: "1px solid hsl(var(--border))",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
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

      {/* Bot / CVE / Drop 统计 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t("dashboard.botDetect24h")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
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
                <div className="pt-2">
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
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t("dashboard.cveDetect24h")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">{t("dashboard.totalDetect")}</span>
                <span className="font-semibold">{formatNumber(d.cve_total_24h)}</span>
              </div>
              {cveByType.length > 0 ? (
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={cveByType.map((c: any) => ({ name: c.category, value: c.count }))}
                        cx="50%"
                        cy="50%"
                        innerRadius={30}
                        outerRadius={55}
                        paddingAngle={2}
                        dataKey="value"
                      >
                        {cveByType.map((_: any, i: number) => (
                          <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend
                        layout="vertical"
                        align="right"
                        verticalAlign="middle"
                        wrapperStyle={{ fontSize: 10 }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                cveByType.map((item: any) => (
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
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t("dashboard.dropEvents24h")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">{t("dashboard.total")}</span>
                <span className="font-semibold">{formatNumber(d.drop_total_24h)}</span>
              </div>
              {dropPieData.length > 0 ? (
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={dropPieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={30}
                        outerRadius={55}
                        paddingAngle={2}
                        dataKey="value"
                      >
                        {dropPieData.map((_, i) => (
                          <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend
                        layout="vertical"
                        align="right"
                        verticalAlign="middle"
                        wrapperStyle={{ fontSize: 10 }}
                      />
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

      {/* 运行时信息 */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-6 py-4">
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
