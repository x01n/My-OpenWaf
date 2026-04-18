"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { SiteStatusBadge } from "@/components/site-status-badge";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Plus, Pencil, Trash2, Play, Square, TrendingUp } from "lucide-react";

interface Site {
  id: number;
  host: string;
  listener_id: number;
  upstream_urls: string;
  cert_id?: number;
  policy_id?: number;
  maintenance_enabled: boolean;
  created_at: string;
  updated_at: string;
}

interface SiteStats {
  qps: number;
  blocked: number;
  status: "running" | "stopped" | "error";
}

export default function SitesPage() {
  const router = useRouter();
  const [sites, setSites] = useState<Site[]>([]);
  const [stats, setStats] = useState<Record<number, SiteStats>>({});
  const [loading, setLoading] = useState(true);
  const [deleteTarget, setDeleteTarget] = useState<Site | null>(null);
  const [actionLoading, setActionLoading] = useState<Record<number, boolean>>({});

  const loadSites = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api<{ items: Site[] }>("/api/v1/sites");
      setSites(data.items || []);
    } catch (err) {
      toast.error("加载站点失败: " + String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadStats = useCallback(async () => {
    // Mock stats for now - replace with actual API call
    const mockStats: Record<number, SiteStats> = {};
    sites.forEach((site) => {
      mockStats[site.id] = {
        qps: Math.floor(Math.random() * 1000),
        blocked: Math.floor(Math.random() * 50),
        status: site.maintenance_enabled ? "stopped" : "running",
      };
    });
    setStats(mockStats);
  }, [sites]);

  useEffect(() => {
    loadSites();
  }, [loadSites]);

  useEffect(() => {
    if (sites.length > 0) {
      loadStats();
      const interval = setInterval(loadStats, 5000);
      return () => clearInterval(interval);
    }
  }, [sites, loadStats]);

  const handleToggleStatus = async (site: Site) => {
    try {
      setActionLoading((prev) => ({ ...prev, [site.id]: true }));
      await api(`/api/v1/sites/${site.id}/update`, {
        method: "POST",
        body: JSON.stringify({
          ...site,
          maintenance_enabled: !site.maintenance_enabled,
        }),
      });
      toast.success(site.maintenance_enabled ? "站点已启动" : "站点已停止");
      await loadSites();
    } catch (err) {
      toast.error("操作失败: " + String(err));
    } finally {
      setActionLoading((prev) => ({ ...prev, [site.id]: false }));
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await api(`/api/v1/sites/${deleteTarget.id}/delete`, { method: "POST" });
      toast.success("站点已删除");
      setDeleteTarget(null);
      await loadSites();
    } catch (err) {
      toast.error("删除失败: " + String(err));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">站点管理</h1>
          <p className="text-muted-foreground mt-2">
            管理虚拟主机配置，每个站点绑定 Host 到上游服务
          </p>
        </div>
        <Button onClick={() => router.push("/sites/new/edit")}>
          <Plus className="mr-2 size-4" />
          新建站点
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>站点列表</CardTitle>
          <CardDescription>共 {sites.length} 个站点</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-3">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          ) : sites.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              暂无站点，点击右上角新建
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>上游地址</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead className="text-right">QPS</TableHead>
                  <TableHead className="text-right">拦截数</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sites.map((site) => {
                  const siteStats = stats[site.id] || { qps: 0, blocked: 0, status: "stopped" as const };
                  return (
                    <TableRow key={site.id}>
                      <TableCell className="font-medium">{site.host}</TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {site.upstream_urls.split(",")[0]}
                        {site.upstream_urls.split(",").length > 1 && (
                          <span className="ml-1 text-xs">+{site.upstream_urls.split(",").length - 1}</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <SiteStatusBadge status={siteStats.status} />
                      </TableCell>
                      <TableCell className="text-right font-mono text-sm">
                        {siteStats.qps}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <TrendingUp className="size-3 text-red-500" />
                          <span className="font-mono text-sm">{siteStats.blocked}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleToggleStatus(site)}
                            disabled={actionLoading[site.id]}
                          >
                            {site.maintenance_enabled ? (
                              <Play className="size-4" />
                            ) : (
                              <Square className="size-4" />
                            )}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => router.push(`/sites/${site.id}/edit`)}
                          >
                            <Pencil className="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setDeleteTarget(site)}
                          >
                            <Trash2 className="size-4 text-destructive" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              确定要删除站点 <strong>{deleteTarget?.host}</strong> 吗？此操作无法撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete}>删除</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
