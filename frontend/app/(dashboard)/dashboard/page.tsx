"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { api } from "@/lib/api";
import {
  RefreshCw,
  Shield,
  Activity,
  AlertTriangle,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend,
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
  revision: number;
}

interface StatsData {
  total: number;
  hours: number;
  categories: { category: string; count: number }[] | null;
  top_ips: { client_ip: string; count: number }[] | null;
  top_paths: { path: string; count: number }[] | null;
  top_rules: { rule_id_str: string; count: number }[] | null;
}

interface TimelinePoint {
  hour: string;
  count: number;
}

interface QPSPoint {
  time: string;
  qps: number;
}

const PIE_COLORS = [
  "#ef4444", "#f97316", "#eab308", "#22c55e",
  "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899",
];

const CATEGORY_LABELS: Record<string, string> = {
  sqli: "SQL 注入",
  xss: "XSS",
  path_traversal: "路径遍历",
  webshell: "Webshell",
  revshell: "反弹 Shell",
  ssrf: "SSRF",
  cmd_injection: "命令注入",
  xxe: "XXE",
  ldap_injection: "LDAP 注入",
  nosql_injection: "NoSQL 注入",
  template_injection: "模板注入",
  file_upload: "文件上传",
  protocol_violation: "协议违规",
  bot_malicious: "恶意 Bot",
  bot_suspicious: "可疑 Bot",
  rate_limit: "速率限制",
  blacklist: "黑名单",
  auto_ban: "自动封禁",
};

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [stats, setStats] = useState<StatsData | null>(null);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [qpsHistory, setQpsHistory] = useState<QPSPoint[]>([]);
  const [error, setError] = useState("");
  const [reloading, setReloading] = useState(false);

  const load = useCallback(async () => {
    try {
      const d = await api<DashboardData>("/api/v1/dashboard/summary");
      setData(d);
      setError("");
      setQpsHistory((prev) => {
        const now = new Date().toLocaleTimeString("zh-CN", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
        const next = [...prev, { time: now, qps: d.qps_5s }];
        return next.length > 60 ? next.slice(-60) : next;
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "加载失败");
    }
  }, []);

  const loadStats = useCallback(async () => {
    try {
      const [s, t] = await Promise.all([
        api<StatsData>("/api/v1/security-events/stats?hours=24"),
        api<{ items: TimelinePoint[] | null }>("/api/v1/security-events/timeline?hours=24"),
      ]);
      setStats(s);
      setTimeline(t.items || []);
    } catch {
      // non-critical
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    loadStats();
    const id = setInterval(loadStats, 30000);
    return () => clearInterval(id);
  }, [loadStats]);

  async function handleReload() {
    setReloading(true);
    try {
      await api("/api/v1/reload", { method: "POST" });
      toast.success("配置已重载");
      load();
    } catch {
      toast.error("重载失败");
    } finally {
      setReloading(false);
    }
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  const pieData = (stats?.categories || []).map((c) => ({
    name: CATEGORY_LABELS[c.category] || c.category,
    value: c.count,
  }));

  const timelineData = timeline.map((t) => ({
    hour: t.hour.slice(11, 16),
    count: t.count,
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">概览</h1>
          <p className="text-sm text-muted-foreground">
            数据面流量与安全态势（近实时）
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && (
            <Badge variant="outline">配置版本 #{data.revision}</Badge>
          )}
          <Button
            size="sm"
            variant="outline"
            onClick={handleReload}
            disabled={reloading}
          >
            <RefreshCw className={`mr-1 h-3.5 w-3.5 ${reloading ? "animate-spin" : ""}`} />
            重载配置
          </Button>
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="总请求数"
          icon={<Activity className="h-4 w-4 text-blue-500" />}
          primary={data?.requests_total ?? 0}
          secondary={`2xx: ${data?.status_2xx ?? 0}`}
        />
        <MetricCard
          title="实时 QPS"
          icon={<Zap className="h-4 w-4 text-yellow-500" />}
          primary={Number(data?.qps_5s?.toFixed(1) ?? 0)}
          secondary={`瞬时 QPS: ${data?.qps_1s?.toFixed(1) ?? 0}`}
        />
        <MetricCard
          title="WAF 拦截"
          icon={<Shield className="h-4 w-4 text-red-500" />}
          primary={data?.waf_blocks ?? 0}
          secondary={`观察: ${data?.waf_observes ?? 0}`}
        />
        <MetricCard
          title="上游错误"
          icon={<AlertTriangle className="h-4 w-4 text-orange-500" />}
          primary={(data?.errors_upstream_4xx ?? 0) + (data?.errors_upstream_5xx ?? 0)}
          secondary={`4xx: ${data?.errors_upstream_4xx ?? 0} / 5xx: ${data?.errors_upstream_5xx ?? 0}`}
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* QPS trend */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">QPS 趋势</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={qpsHistory}>
                  <defs>
                    <linearGradient id="qpsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="time" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 10 }} />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="qps"
                    stroke="#3b82f6"
                    fill="url(#qpsGradient)"
                    strokeWidth={2}
                    name="QPS"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Attack type distribution */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">24h 攻击类型分布</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[240px]">
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
                      {pieData.map((_, index) => (
                        <Cell key={index} fill={PIE_COLORS[index % PIE_COLORS.length]} />
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
                  暂无攻击数据
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Timeline chart */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">24h 安全事件时间线</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[200px]">
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="hour" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 10 }} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#ef4444" radius={[2, 2, 0, 0]} name="事件数" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                暂无时间线数据
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Top rankings */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        <RankingCard
          title="Top 10 攻击 IP"
          items={(stats?.top_ips || []).map((ip) => ({
            label: ip.client_ip,
            count: ip.count,
          }))}
        />
        <RankingCard
          title="Top 10 攻击路径"
          items={(stats?.top_paths || []).map((p) => ({
            label: p.path,
            count: p.count,
          }))}
        />
        <RankingCard
          title="Top 10 触发规则"
          items={(stats?.top_rules || []).map((r) => ({
            label: r.rule_id_str,
            count: r.count,
          }))}
        />
      </div>

      {data && (
        <div className="text-xs text-muted-foreground">
          运行时间: {formatUptime(data.uptime_sec)}
        </div>
      )}
    </div>
  );
}

function MetricCard({
  title,
  icon,
  primary,
  secondary,
}: {
  title: string;
  icon: React.ReactNode;
  primary: number;
  secondary: string;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold tabular-nums">{primary.toLocaleString()}</div>
        <p className="mt-1 text-xs text-muted-foreground">{secondary}</p>
      </CardContent>
    </Card>
  );
}

function RankingCard({
  title,
  items,
}: {
  title: string;
  items: { label: string; count: number }[];
}) {
  const maxCount = items.length > 0 ? items[0].count : 1;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <div className="py-4 text-center text-sm text-muted-foreground">
            暂无数据
          </div>
        ) : (
          <div className="space-y-2">
            {items.slice(0, 10).map((item, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="w-5 text-right text-xs font-medium text-muted-foreground">
                  {i + 1}
                </span>
                <div className="relative flex-1">
                  <div
                    className="absolute inset-y-0 left-0 rounded bg-muted"
                    style={{ width: `${(item.count / maxCount) * 100}%` }}
                  />
                  <span className="relative truncate px-1.5 text-xs font-mono">
                    {item.label}
                  </span>
                </div>
                <span className="text-xs tabular-nums text-muted-foreground">
                  {item.count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function formatUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  return `${h}h ${m}m ${s}s`;
}
