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
  Globe,
  CheckCircle2,
  XCircle,
  Target,
  TrendingUp,
} from "lucide-react";
import { toast } from "sonner";
import { RealtimeQPSChart } from "@/components/charts/realtime-qps-chart";
import { AttackHeatmap } from "@/components/charts/attack-heatmap";
import { CategoryPieChart } from "@/components/charts/category-pie-chart";
import { TopListCard } from "@/components/charts/top-list-card";

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
  const [sites, setSites] = useState<{ id: number; name: string; enabled: boolean }[]>([]);
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
      const [s, t, siteList] = await Promise.all([
        api<StatsData>("/api/v1/security-events/stats?hours=24"),
        api<{ items: TimelinePoint[] | null }>("/api/v1/security-events/timeline?hours=24"),
        api<{ items: { id: number; name: string; enabled: boolean }[] }>("/api/v1/sites"),
      ]);
      setStats(s);
      setTimeline(t.items || []);
      setSites(siteList.items || []);
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

  async function handleAddToBlacklist(value: string) {
    // Create a new ACL rule to block this IP
    await api("/api/v1/rules", {
      method: "POST",
      body: JSON.stringify({
        name: `Auto-block ${value}`,
        enabled: true,
        priority: 100,
        pattern: `block_ip:${value}`,
        action: "block",
        description: `Automatically added from dashboard`,
      }),
    });
    await api("/api/v1/reload", { method: "POST" });
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

      {/* Site Status Overview */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Globe className="h-4 w-4 text-green-500" />
            站点状态概览
          </CardTitle>
        </CardHeader>
        <CardContent>
          {sites.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {sites.map((site) => (
                <div
                  key={site.id}
                  className="flex items-center justify-between p-3 rounded-lg border bg-card hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {site.enabled ? (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-gray-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium">{site.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {site.enabled ? "运行中" : "已停用"}
                      </p>
                    </div>
                  </div>
                  <Badge variant={site.enabled ? "default" : "secondary"}>
                    {site.enabled ? "启用" : "禁用"}
                  </Badge>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex h-[100px] items-center justify-center text-sm text-muted-foreground">
              暂无站点配置
            </div>
          )}
        </CardContent>
      </Card>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* QPS trend */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-500" />
              实时 QPS 趋势
            </CardTitle>
          </CardHeader>
          <CardContent>
            <RealtimeQPSChart data={qpsHistory} height={280} />
          </CardContent>
        </Card>

        {/* Attack type distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-4 w-4 text-red-500" />
              24h 攻击类型分布
            </CardTitle>
          </CardHeader>
          <CardContent>
            {pieData.length > 0 ? (
              <CategoryPieChart data={pieData} height={280} />
            ) : (
              <div className="flex h-[280px] items-center justify-center text-sm text-muted-foreground">
                暂无攻击数据
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Timeline chart */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-500" />
            24h 攻击时间线热力图
          </CardTitle>
        </CardHeader>
        <CardContent>
          {timelineData.length > 0 ? (
            <AttackHeatmap data={timelineData} height={280} />
          ) : (
            <div className="flex h-[280px] items-center justify-center text-sm text-muted-foreground">
              暂无时间线数据
            </div>
          )}
        </CardContent>
      </Card>

      {/* Top rankings */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        <TopListCard
          title="Top 10 攻击 IP"
          icon={<Shield className="h-4 w-4 text-red-500" />}
          items={(stats?.top_ips || []).map((ip) => ({
            label: ip.client_ip,
            value: ip.client_ip,
            count: ip.count,
            actionable: true,
          }))}
          onAddToBlacklist={handleAddToBlacklist}
        />
        <TopListCard
          title="Top 10 攻击路径"
          icon={<Globe className="h-4 w-4 text-blue-500" />}
          items={(stats?.top_paths || []).map((p) => ({
            label: p.path.length > 30 ? p.path.slice(0, 30) + "..." : p.path,
            value: p.path,
            count: p.count,
          }))}
        />
        <TopListCard
          title="Top 10 触发规则"
          icon={<Zap className="h-4 w-4 text-yellow-500" />}
          items={(stats?.top_rules || []).map((r) => ({
            label: r.rule_id_str,
            value: r.rule_id_str,
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
    <Card className="hover:shadow-md transition-shadow">
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

function formatUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  return `${h}h ${m}m ${s}s`;
}
