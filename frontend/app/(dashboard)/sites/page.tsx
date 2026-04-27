"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Globe, Plus, Power, ShieldAlert, Trash2 } from "lucide-react";
import { AddSiteDialog } from "@/components/add-site-dialog";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { EmptyState, InlineMeta, PageIntro, Surface, statusToneClass } from "@/components/console-shell";
import { deleteSite, listSites, startSite, stopSite, type Site, updateSite } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { toast } from "sonner";

function parseUpstreams(raw: string) {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as string[];
  } catch {}
  return raw ? raw.split(",").map((item) => item.trim()).filter(Boolean) : [];
}

function siteMode(site: Site) {
  if (site.maintenance_enabled) return { key: "maintenance", label: "维护模式" };
  if (site.attack_protection_level === "observe") return { key: "observe", label: "观察模式" };
  return { key: "protect", label: "防护模式" };
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
      const result = await listSites();
      setSites(result.items ?? []);
    } catch (error) {
      toast.error(String(error));
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
      await updateSite(site.id, { ...site, enabled: !site.enabled });
      toast.success(site.enabled ? "站点已停用" : "站点已启用");
      load();
    } catch (error) {
      toast.error(String(error));
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
    } catch (error) {
      toast.error(String(error));
    } finally {
      setDeleting(false);
      setBusyId(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Sites & Runtime"
        title="防护应用"
        description="管理当前系统中实际运行的站点入口、上游转发、TLS 接入和站点级防护状态。所有数据直接来自 /api/v1/sites。"
        actions={
          <Button className="rounded-2xl bg-white text-slate-950 hover:bg-slate-100" onClick={() => setDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            添加应用
          </Button>
        }
      />

      {loading ? (
        <div className="grid gap-4 xl:grid-cols-2">
          {Array.from({ length: 4 }).map((_, index) => (
            <Surface key={index} className="min-h-[220px] animate-pulse">
              <div className="h-full" />
            </Surface>
          ))}
        </div>
      ) : sites.length === 0 ? (
        <EmptyState
          title="还没有接入的防护应用"
          description="创建站点后即可绑定 Host、监听地址与上游转发目标，并在后续页面中继续配置保护策略。"
          action={
            <Button onClick={() => setDialogOpen(true)} className="rounded-2xl bg-slate-950 text-white hover:bg-slate-800">
              <Plus className="mr-2 h-4 w-4" />
              新建站点
            </Button>
          }
        />
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {sites.map((site) => {
            const upstreams = parseUpstreams(site.upstream_urls);
            const mode = siteMode(site);
            const trafficStatus = site.enabled ? "running" : "stopped";

            return (
              <Surface key={site.id} className="overflow-hidden">
                <div className="space-y-5">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-4">
                      <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyan-50 text-cyan-700">
                        <Globe className="h-5 w-5" />
                      </div>
                      <div className="space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <h2 className="text-lg font-semibold text-slate-950">{site.host}</h2>
                          <span className={`console-badge ${statusToneClass(trafficStatus)}`}>
                            {site.enabled ? "运行中" : "已停用"}
                          </span>
                          <span className={`console-badge ${statusToneClass(mode.key)}`}>{mode.label}</span>
                        </div>
                        <p className="text-sm text-slate-500">
                          {site.tls_enabled ? "HTTPS" : "HTTP"} · 监听 {site.bind} · 网络 {site.network}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="rounded-xl"
                        onClick={() => router.push(`/sites/${site.id}/`)}
                      >
                        查看详情
                      </Button>
                      <Button
                        variant="outline"
                        size="icon-sm"
                        className="rounded-xl"
                        disabled={busyId === site.id}
                        onClick={() => toggleSite(site)}
                        title={site.enabled ? "停用站点" : "启用站点"}
                      >
                        <Power className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        className="rounded-xl text-rose-600 hover:bg-rose-50 hover:text-rose-700"
                        disabled={busyId === site.id}
                        onClick={() => setDeleteTarget(site)}
                        title="删除站点"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                    <InlineMeta label="TLS" value={site.tls_enabled ? "已启用" : "未启用"} />
                    <InlineMeta label="策略 ID" value={site.policy_id ? `#${site.policy_id}` : "未绑定"} />
                    <InlineMeta label="Bot 防护" value={site.bot_protection_enabled ? "开启" : "关闭"} />
                    <InlineMeta label="最近更新" value={formatDate(site.updated_at)} />
                  </div>

                  <div className="rounded-[22px] border border-slate-200 bg-slate-50/80 p-4">
                    <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-900">
                      <ShieldAlert className="h-4 w-4 text-cyan-700" />
                      上游目标
                    </div>
                    <div className="space-y-2">
                      {upstreams.length === 0 ? (
                        <div className="text-sm text-slate-500">未配置上游地址</div>
                      ) : (
                        upstreams.map((upstream, index) => (
                          <div key={`${site.id}-${index}`} className="rounded-2xl border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-slate-700">
                            {upstream}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </Surface>
            );
          })}
        </div>
      )}

      <AddSiteDialog open={dialogOpen} onOpenChange={setDialogOpen} onSuccess={load} />

      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="max-w-md rounded-[28px]">
          <DialogHeader>
            <DialogTitle>确认删除站点</DialogTitle>
            <DialogDescription>删除后该站点入口、监听配置与关联运行时状态都会从当前环境移除。</DialogDescription>
          </DialogHeader>
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-900">
            目标站点：{deleteTarget?.host || "-"}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>取消</Button>
            <Button className="bg-rose-600 hover:bg-rose-500" disabled={deleting} onClick={removeSite}>
              {deleting ? "删除中..." : "删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
