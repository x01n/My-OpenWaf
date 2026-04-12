"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { api } from "@/lib/api";
import { RefreshCw } from "lucide-react";
import { toast } from "sonner";

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

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");
  const [reloading, setReloading] = useState(false);

  async function load() {
    try {
      const d = await api<DashboardData>("/api/v1/dashboard/summary");
      setData(d);
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "加载失败");
    }
  }

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

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

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="请求概览"
          primary={data?.requests_total ?? 0}
          primaryLabel="总请求数"
          secondary={`2xx: ${data?.status_2xx ?? 0}`}
        />
        <MetricCard
          title="错误概览"
          primary={(data?.errors_upstream_4xx ?? 0) + (data?.errors_upstream_5xx ?? 0)}
          primaryLabel="错误总数"
          secondary={`4xx: ${data?.errors_upstream_4xx ?? 0} / 5xx: ${data?.errors_upstream_5xx ?? 0}`}
        />
        <MetricCard
          title="系统 QPS"
          primary={Number(data?.qps_5s?.toFixed(1) ?? 0)}
          primaryLabel="QPS (5s)"
          secondary={`瞬时: ${data?.qps_1s?.toFixed(1) ?? 0}`}
        />
        <MetricCard
          title="WAF 拦截"
          primary={data?.waf_blocks ?? 0}
          primaryLabel="拦截次数"
          secondary={`观察: ${data?.waf_observes ?? 0} / 内置命中: ${data?.builtin_hits ?? 0}`}
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
  primary,
  primaryLabel,
  secondary,
}: {
  title: string;
  primary: number;
  primaryLabel: string;
  secondary: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-bold tabular-nums">{primary.toLocaleString()}</div>
        <p className="text-xs text-muted-foreground">{primaryLabel}</p>
        <p className="mt-1 text-xs text-muted-foreground">{secondary}</p>
      </CardContent>
    </Card>
  );
}

function formatUptime(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${h}h ${m}m ${s}s`;
}
