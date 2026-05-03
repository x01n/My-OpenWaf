"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ExternalLink,
  Globe,
  Loader2,
  Plus,
  Power,
  Shield,
  Trash2,
} from "lucide-react";
import { AddSiteDialog } from "@/components/add-site-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { deleteSite, listSites, startSite, stopSite, type Site } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { toast } from "sonner";

function parseUpstreams(raw: string) {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as string[];
  } catch {}
  return raw
    ? raw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];
}

export default function SitesPage() {
  const router = useRouter();
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Site | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await listSites();
      setSites(res.items ?? []);
    } catch (err) {
      toast.error(String(err));
      setSites([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function toggleSite(site: Site) {
    setBusyId(site.id);
    try {
      if (site.enabled) {
        await stopSite(site.id);
      } else {
        await startSite(site.id);
      }
      toast.success(site.enabled ? "站点已停用" : "站点已启用");
      load();
    } catch (err) {
      toast.error(String(err));
    } finally {
      setBusyId(null);
    }
  }

  async function removeSite() {
    if (!deleteTarget) return;
    setDeleting(true);
    setBusyId(deleteTarget.id);
    try {
      await deleteSite(deleteTarget.id);
      toast.success("站点已删除");
      setDeleteTarget(null);
      load();
    } catch (err) {
      toast.error(String(err));
    } finally {
      setDeleting(false);
      setBusyId(null);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">防护应用</h1>
          <p className="mt-1 text-sm text-gray-500">管理站点接入、上游转发和防护状态</p>
        </div>
        <Button
          onClick={() => setDialogOpen(true)}
          className="rounded-md bg-cyan-500 text-white hover:bg-cyan-600"
        >
          <Plus className="mr-2 h-4 w-4" />
          添加站点
        </Button>
      </div>

      {/* Loading */}
      {loading ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-[220px] animate-pulse rounded-lg bg-white shadow-sm" />
          ))}
        </div>
      ) : sites.length === 0 ? (
        <div className="flex min-h-[320px] flex-col items-center justify-center rounded-lg border border-dashed border-gray-300 bg-white">
          <Globe className="mb-4 h-12 w-12 text-gray-300" />
          <h3 className="text-lg font-semibold text-gray-700">还没有防护应用</h3>
          <p className="mt-2 max-w-sm text-center text-sm text-gray-500">
            创建站点后即可绑定域名、监听地址与上游目标
          </p>
          <Button
            onClick={() => setDialogOpen(true)}
            className="mt-5 rounded-md bg-cyan-500 text-white hover:bg-cyan-600"
          >
            <Plus className="mr-2 h-4 w-4" />
            新建站点
          </Button>
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {sites.map((site) => {
            const upstreams = parseUpstreams(site.upstream_urls);
            const isBusy = busyId === site.id;

            return (
              <div
                key={site.id}
                className="rounded-lg border border-gray-200 bg-white shadow-sm transition-shadow hover:shadow-md"
              >
                {/* Card Header */}
                <div className="flex items-start justify-between border-b border-gray-100 p-5">
                  <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-50">
                      <Globe className="h-5 w-5 text-cyan-600" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-lg font-semibold text-gray-900">{site.host}</h2>
                        <span
                          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                            site.enabled
                              ? "bg-emerald-50 text-emerald-700"
                              : "bg-gray-100 text-gray-500"
                          }`}
                        >
                          {site.enabled ? "运行中" : "已停止"}
                        </span>
                      </div>
                      <p className="mt-1 text-sm text-gray-500">
                        {site.tls_enabled ? "HTTPS" : "HTTP"} · 监听{" "}
                        <span className="font-mono">{site.bind}</span> · 网络 {site.network}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      className="rounded-md text-xs"
                      onClick={() => router.push(`/sites/${site.id}/`)}
                    >
                      <ExternalLink className="mr-1.5 h-3.5 w-3.5" />
                      详情
                    </Button>
                    <Button
                      variant="outline"
                      size="icon"
                      className="h-8 w-8 rounded-md"
                      disabled={isBusy}
                      onClick={() => toggleSite(site)}
                      title={site.enabled ? "停用" : "启用"}
                    >
                      {isBusy ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Power
                          className={`h-4 w-4 ${site.enabled ? "text-emerald-600" : "text-gray-400"}`}
                        />
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 rounded-md text-red-500 hover:bg-red-50 hover:text-red-600"
                      disabled={isBusy}
                      onClick={() => setDeleteTarget(site)}
                      title="删除"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Card Stats */}
                <div className="grid grid-cols-4 divide-x divide-gray-100 border-b border-gray-100">
                  <StatCell label="TLS" value={site.tls_enabled ? "已启用" : "关闭"} />
                  <StatCell
                    label="策略 ID"
                    value={site.policy_id ? `#${site.policy_id}` : "未绑定"}
                  />
                  <StatCell label="Bot 防护" value={site.bot_protection_enabled ? "开启" : "关闭"} />
                  <StatCell label="最近更新" value={formatDate(site.updated_at)} small />
                </div>

                {/* Upstreams */}
                <div className="p-5">
                  <div className="mb-2 flex items-center gap-2 text-xs font-medium text-gray-500">
                    <Shield className="h-3.5 w-3.5" />
                    上游目标
                  </div>
                  {upstreams.length === 0 ? (
                    <p className="text-sm text-gray-400">未配置上游地址</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {upstreams.map((u, i) => (
                        <span
                          key={`${site.id}-${i}`}
                          className="rounded-md border border-gray-200 bg-gray-50 px-2.5 py-1 font-mono text-xs text-gray-600"
                        >
                          {u}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <AddSiteDialog open={dialogOpen} onOpenChange={setDialogOpen} onSuccess={load} />

      {/* Delete Confirmation */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>确认删除站点</DialogTitle>
            <DialogDescription>
              删除后该站点入口、监听配置与运行时状态都会移除，此操作不可撤销。
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            目标站点：<strong>{deleteTarget?.host || "-"}</strong>
          </div>
          <DialogFooter>
            <Button variant="outline" className="rounded-md" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button
              className="rounded-md bg-red-600 text-white hover:bg-red-500"
              disabled={deleting}
              onClick={removeSite}
            >
              {deleting ? "删除中..." : "确认删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function StatCell({
  label,
  value,
  small,
}: {
  label: string;
  value: string;
  small?: boolean;
}) {
  return (
    <div className="px-4 py-3">
      <div className="text-[11px] font-medium text-gray-400 uppercase">{label}</div>
      <div className={`mt-0.5 font-medium text-gray-800 ${small ? "text-xs" : "text-sm"}`}>
        {value}
      </div>
    </div>
  );
}
