"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import {
  ExternalLink,
  Globe,
  Loader2,
  Plus,
  Power,
  Shield,
  Trash2,
} from "lucide-react"
import { AddSiteDialog } from "@/components/add-site-dialog"
import { Pagination } from "@/components/pagination"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import {
  deleteSite,
  listSites,
  startSite,
  stopSite,
  updateSite,
  type Site,
} from "@/lib/api"
import { parseSiteUpstreams } from "@/lib/site-upstreams"
import {
  getProtectionMode,
  ProtectionModeDialog,
  protectionModeLabel,
  type ProtectionMode,
} from "@/components/protection-mode-dialog"
import { formatDate, cn } from "@/lib/utils"
import { toast } from "sonner"

export default function SitesPage() {
  const router = useRouter()
  const [sites, setSites] = useState<Site[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Site | null>(null)
  const [modeTarget, setModeTarget] = useState<Site | null>(null)
  const [modeSaving, setModeSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const pageSize = 20
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  const load = useCallback(async (targetPage: number) => {
    setLoading(true)
    try {
      const res = await listSites({ page: targetPage, page_size: pageSize })
      const nextItems = res.items ?? []
      const nextTotal = res.total ?? 0
      if (targetPage > 1 && nextItems.length === 0 && nextTotal > 0) {
        setPage(targetPage - 1)
        return
      }
      setSites(nextItems)
      setTotal(nextTotal)
    } catch (err) {
      toast.error(String(err))
      setSites([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(page)
  }, [load, page])

  async function toggleSite(site: Site) {
    setBusyId(site.id)
    try {
      if (site.enabled) {
        await stopSite(site.id)
      } else {
        await startSite(site.id)
      }
      toast.success(site.enabled ? "站点已停用" : "站点已启用")
      load(page)
    } catch (err) {
      toast.error(String(err))
    } finally {
      setBusyId(null)
    }
  }

  async function removeSite() {
    if (!deleteTarget) return
    setDeleting(true)
    setBusyId(deleteTarget.id)
    try {
      await deleteSite(deleteTarget.id)
      toast.success("站点已删除")
      setDeleteTarget(null)
      load(page)
    } catch (err) {
      toast.error(String(err))
    } finally {
      setDeleting(false)
      setBusyId(null)
    }
  }

  async function updateProtectionMode(mode: ProtectionMode) {
    if (!modeTarget) return
    setModeSaving(true)
    setBusyId(modeTarget.id)
    try {
      await updateSite(modeTarget.id, {
        attack_protection_level: mode === "observe" ? "observe" : "protect",
        maintenance_enabled: mode === "maintenance",
      })
      toast.success("防护模式已更新")
      setModeTarget(null)
      load(page)
    } catch (err) {
      toast.error(String(err))
    } finally {
      setModeSaving(false)
      setBusyId(null)
    }
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="text-xs font-semibold tracking-[0.22em] text-teal-600 uppercase">
            Applications
          </div>
          <h1 className="mt-1 text-2xl font-semibold text-slate-950">
            站点管理
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            共 {total} 个防护应用，统一管理域名、监听地址、上游与防护模式。
          </p>
        </div>
        <Button
          onClick={() => setDialogOpen(true)}
          className="w-full rounded-lg bg-teal-500 text-white shadow-sm hover:bg-teal-600 sm:w-auto"
        >
          <Plus className="mr-1.5 h-4 w-4" />
          添加应用
        </Button>
      </div>

      {/* Site cards */}
      {loading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-[140px] animate-pulse rounded-xl border border-slate-200/80 bg-white shadow-sm"
            />
          ))}
        </div>
      ) : sites.length === 0 ? (
        <div className="flex min-h-[320px] flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white">
          <Globe className="mb-4 h-12 w-12 text-slate-300" />
          <h3 className="text-lg font-semibold text-slate-600">
            还没有防护应用
          </h3>
          <p className="mt-2 max-w-sm text-center text-sm text-slate-400">
            创建站点后即可绑定域名、监听地址与上游目标
          </p>
          <Button
            onClick={() => setDialogOpen(true)}
            className="mt-5 rounded-lg bg-teal-500 text-white hover:bg-teal-600"
          >
            <Plus className="mr-1.5 h-4 w-4" />
            新建站点
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {sites.map((site) => {
            const upstreams = parseSiteUpstreams(site.upstream_urls)
            const isBusy = busyId === site.id
            const bindPort = site.bind?.replace(/^.*:/, "") || "80"
            const protocol = site.tls_enabled ? "HTTPS" : "HTTP"
            const siteHosts = site.host
              ? site.host
                  .split(",")
                  .map((h) => h.trim())
                  .filter(Boolean)
              : []
            const primaryHost = siteHosts[0] || site.host
            const protectionMode = getProtectionMode(site)

            return (
              <div
                key={site.id}
                className="rounded-xl border border-slate-200/80 bg-white shadow-sm transition-shadow hover:shadow-md"
              >
                <div className="flex flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center">
                  {/* Icon */}
                  <div
                    className={cn(
                      "flex h-10 w-10 shrink-0 items-center justify-center rounded-full",
                      site.enabled
                        ? "bg-teal-50 text-teal-500"
                        : "bg-slate-100 text-slate-400"
                    )}
                  >
                    <Globe className="h-5 w-5" />
                  </div>

                  {/* Info */}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <h2 className="truncate text-[15px] font-semibold text-slate-800">
                        {primaryHost}
                      </h2>
                      {siteHosts.length > 1 && (
                        <span className="rounded-full border border-cyan-200 bg-cyan-50 px-2 py-0.5 text-[11px] font-medium text-cyan-600">
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
                      {siteHosts.length > 3 && (
                        <span className="text-slate-400">
                          +{siteHosts.length - 3}
                        </span>
                      )}
                      <span className="ml-1 flex items-center gap-1">
                        <Shield className="h-3 w-3" />
                        {bindPort}/{protocol}
                      </span>
                    </div>
                  </div>

                  {/* Protection mode button */}
                  <button
                    className="rounded-lg border border-teal-200 bg-teal-50 px-3 py-1.5 text-[13px] font-medium text-teal-700 transition-colors hover:bg-teal-100 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={isBusy}
                    onClick={() => setModeTarget(site)}
                  >
                    {protectionModeLabel(protectionMode)} ≡
                  </button>

                  {/* Actions */}
                  <div className="flex w-full flex-wrap items-center justify-end gap-1.5 lg:w-auto lg:flex-nowrap">
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
                      {isBusy ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Power
                          className={cn(
                            "h-4 w-4",
                            site.enabled ? "text-teal-500" : "text-slate-400"
                          )}
                        />
                      )}
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
                <div className="flex flex-col gap-3 border-t border-slate-100 px-5 py-3 text-[12px] sm:flex-row sm:items-center">
                  <div className="flex flex-wrap items-center gap-3 text-slate-500">
                    <span>请求统计请到站点详情查看</span>
                    <span className="text-slate-300">•</span>
                    <span>创建于 {formatDate(site.created_at)}</span>
                  </div>
                  <div className="flex min-w-0 flex-wrap items-center gap-2 sm:ml-auto sm:justify-end">
                    {upstreams.slice(0, 2).map((u, i) => (
                      <span
                        key={i}
                        className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[11px] text-slate-500"
                      >
                        {u}
                        {site.enabled && (
                          <span className="ml-1 text-green-500">●</span>
                        )}
                      </span>
                    ))}
                    {upstreams.length > 2 && (
                      <span className="text-slate-400">
                        +{upstreams.length - 2}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {!loading && total > 0 ? (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={total}
          pageSize={pageSize}
          onPageChange={setPage}
        />
      ) : null}

      <AddSiteDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        onSuccess={() => load(page)}
      />

      {modeTarget && (
        <ProtectionModeDialog
          open={!!modeTarget}
          onOpenChange={(open) => !open && setModeTarget(null)}
          currentMode={getProtectionMode(modeTarget)}
          onConfirm={updateProtectionMode}
          loading={modeSaving}
        />
      )}

      <Dialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <DialogContent className="max-w-md rounded-xl">
          <DialogHeader>
            <DialogTitle>确认删除站点</DialogTitle>
            <DialogDescription>
              删除后该站点入口、监听配置与运行时状态都会移除，此操作不可撤销。
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            目标站点：
            <strong>
              {deleteTarget?.host
                ?.split(",")
                .map((h) => h.trim())
                .join(", ") || "-"}
            </strong>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="rounded-lg"
              onClick={() => setDeleteTarget(null)}
            >
              取消
            </Button>
            <Button
              className="rounded-lg bg-red-600 text-white hover:bg-red-500"
              disabled={deleting}
              onClick={removeSite}
            >
              {deleting ? "删除中..." : "确认删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
