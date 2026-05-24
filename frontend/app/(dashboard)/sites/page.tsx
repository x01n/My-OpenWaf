"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ExternalLink, Globe, Loader2, Plus, Power, Shield, Trash2 } from "lucide-react";
import { AddSiteDialog } from "@/components/add-site-dialog";
import { Pagination } from "@/components/pagination";
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
import { parseSiteUpstreams } from "@/lib/site-upstreams";
import { formatDate, cn } from "@/lib/utils";
import { toast } from "sonner";

export default function SitesPage() {
  const router = useRouter();
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Site | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const pageSize = 20;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  async function load(targetPage = page) {
    setLoading(true);
    try {
      const res = await listSites({ page: targetPage, page_size: pageSize });
      const nextItems = res.items ?? [];
      const nextTotal = res.total ?? 0;
      if (targetPage > 1 && nextItems.length === 0 && nextTotal > 0) {
        const previousPage = targetPage - 1;
        setPage(previousPage);
        await load(previousPage);
        return;
      }
      setSites(nextItems);
      setTotal(nextTotal);
    } catch (err) {
      toast.error(String(err));
      setSites([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(page); }, [page]);

  async function toggleSite(site: Site) {
    setBusyId(site.id);
    try {
      if (site.enabled) { await stopSite(site.id); } else { await startSite(site.id); }
      toast.success(site.enabled ? "站点已停用" : "站点已启用");
      load(page);
    } catch (err) { toast.error(String(err)); } finally { setBusyId(null); }
  }

  async function removeSite() {
    if (!deleteTarget) return;
    setDeleting(true);
    setBusyId(deleteTarget.id);
    try {
      await deleteSite(deleteTarget.id);
      toast.success("站点已删除");
      setDeleteTarget(null);
      load(page);
    } catch (err) { toast.error(String(err)); } finally { setDeleting(false); setBusyId(null); }
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-500">共 {total} 个应用</span>
          <span className="text-sm text-slate-400">|</span>
          <span className="text-sm text-slate-500">应用</span>
        </div>
        <Button onClick={() => setDialogOpen(true)} className="rounded-lg bg-teal-500 text-white hover:bg-teal-600 shadow-sm">
          <Plus className="mr-1.5 h-4 w-4" />
          添加应用
        </Button>
      </div>

      {/* Site cards */}
      {loading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-[140px] animate-pulse rounded-xl border border-slate-200/80 bg-white shadow-sm" />
          ))}
        </div>
      ) : sites.length === 0 ? (
        <div className="flex min-h-[320px] flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white">
          <Globe className="mb-4 h-12 w-12 text-slate-300" />
          <h3 className="text-lg font-semibold text-slate-600">还没有防护应用</h3>
          <p className="mt-2 max-w-sm text-center text-sm text-slate-400">创建站点后即可绑定域名、监听地址与上游目标</p>
          <Button onClick={() => setDialogOpen(true)} className="mt-5 rounded-lg bg-teal-500 text-white hover:bg-teal-600">
            <Plus className="mr-1.5 h-4 w-4" />
            新建站点
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {sites.map((site) => {
            const upstreams = parseSiteUpstreams(site.upstream_urls);
            const isBusy = busyId === site.id;
            const bindPort = site.bind?.replace(/^.*:/, "") || "80";
            const protocol = site.tls_enabled ? "HTTPS" : "HTTP";
            const siteHosts = site.host ? site.host.split(",").map((h) => h.trim()).filter(Boolean) : [];
            const primaryHost = siteHosts[0] || site.host;

            return (
              <div key={site.id} className="rounded-xl border border-slate-200/80 bg-white shadow-sm transition-shadow hover:shadow-md">
                <div className="flex items-center gap-4 px-5 py-4">
                  {/* Icon */}
                  <div className={cn(
                    "flex h-10 w-10 shrink-0 items-center justify-center rounded-full",
                    site.enabled ? "bg-teal-50 text-teal-500" : "bg-slate-100 text-slate-400",
                  )}>
                    <Globe className="h-5 w-5" />
                  </div>

                  {/* Info */}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <h2 className="truncate text-[15px] font-semibold text-slate-800">{primaryHost}</h2>
                      {siteHosts.length > 1 && (
                        <span className="rounded-full bg-cyan-50 px-2 py-0.5 text-[11px] font-medium text-cyan-600 border border-cyan-200">
                          +{siteHosts.length - 1} 域名
                        </span>
                      )}
                      {site.enabled && <span className="text-teal-400">⊕</span>}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[13px] text-slate-500">
                      {siteHosts.slice(0, 3).map((h) => (
                        <span key={h} className="flex items-center gap-1">
                          <Globe className="h-3 w-3" />
                          {h}
                        </span>
                      ))}
                      {siteHosts.length > 3 && <span className="text-slate-400">+{siteHosts.length - 3}</span>}
                      <span className="flex items-center gap-1 ml-1">
                        <Shield className="h-3 w-3" />
                        {bindPort}/{protocol}
                      </span>
                    </div>
                  </div>

                  {/* Protection mode button */}
                  <button className="rounded-lg border border-teal-200 bg-teal-50 px-3 py-1.5 text-[13px] font-medium text-teal-700 hover:bg-teal-100 transition-colors">
                    防护模式 ≡
                  </button>

                  {/* Actions */}
                  <div className="flex items-center gap-1.5">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 gap-1 text-xs text-teal-600 hover:bg-teal-50 hover:text-teal-700"
                      onClick={() => router.push(`/sites/_/?id=${site.id}`)}
                    >
                      详情
                      <ExternalLink className="h-3 w-3" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      disabled={isBusy}
                      onClick={() => toggleSite(site)}
                      title={site.enabled ? "停用" : "启用"}
                    >
                      {isBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Power className={cn("h-4 w-4", site.enabled ? "text-teal-500" : "text-slate-400")} />}
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-red-400 hover:bg-red-50 hover:text-red-600"
                      disabled={isBusy}
                      onClick={() => setDeleteTarget(site)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Stats row */}
                <div className="flex items-center border-t border-slate-100 px-5 py-2.5 text-[12px]">
                  <div className="flex items-center gap-4">
                    <span className="text-slate-500">今日请求 <strong className="text-slate-700">{0}</strong></span>
                    <span className="text-slate-500">今日拦截 <strong className="text-slate-700">{0}</strong></span>
                  </div>
                  <div className="ml-auto flex items-center gap-2">
                    {upstreams.slice(0, 2).map((u, i) => (
                      <span key={i} className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[11px] text-slate-500">
                        {u}
                        {site.enabled && <span className="ml-1 text-green-500">●</span>}
                      </span>
                    ))}
                    {upstreams.length > 2 && <span className="text-slate-400">+{upstreams.length - 2}</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {!loading && total > 0 ? (
        <Pagination page={page} totalPages={totalPages} total={total} pageSize={pageSize} onPageChange={setPage} />
      ) : null}

      <AddSiteDialog open={dialogOpen} onOpenChange={setDialogOpen} onSuccess={() => load(page)} />

      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="max-w-md rounded-xl">
          <DialogHeader>
            <DialogTitle>确认删除站点</DialogTitle>
            <DialogDescription>删除后该站点入口、监听配置与运行时状态都会移除，此操作不可撤销。</DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            目标站点：<strong>{deleteTarget?.host?.split(",").map(h => h.trim()).join(", ") || "-"}</strong>
          </div>
          <DialogFooter>
            <Button variant="outline" className="rounded-lg" onClick={() => setDeleteTarget(null)}>取消</Button>
            <Button className="rounded-lg bg-red-600 text-white hover:bg-red-500" disabled={deleting} onClick={removeSite}>
              {deleting ? "删除中..." : "确认删除"} 
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
