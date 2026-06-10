"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import {
  ExternalLink,
  Globe,
  AlertTriangle,
  Loader2,
  Plus,
  Power,
  Shield,
  Trash2,
} from "@/lib/icons"
import { deferEffect } from "@/lib/effects"
import { AddSiteDialog } from "@/components/add-site-dialog"
import { EmptyState, PageIntro } from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"
import { Pagination } from "@/components/pagination"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  deleteSite,
  getConfigAppliedReloadFailureDetails,
  getConfigAppliedReloadFailureItem,
  getSiteStatus,
  isConfigAppliedReloadFailureError,
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

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

export default function SitesPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [sites, setSites] = useState<Site[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Site | null>(null)
  const [modeTarget, setModeTarget] = useState<Site | null>(null)
  const [modeSaving, setModeSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [siteStatuses, setSiteStatuses] = useState<Record<number, string>>({})
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)
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
      setSiteStatuses((prev) => {
        const next: Record<number, string> = {}
        for (const item of nextItems) {
          next[item.id] =
            prev[item.id] || (item.enabled ? "running" : "stopped")
        }
        return next
      })
      let statusLoadFailed = false
      const statusEntries = await Promise.all(
        nextItems.map(async (item) => {
          try {
            const status = await getSiteStatus(item.id)
            return [item.id, status.status] as const
          } catch {
            statusLoadFailed = true
            return [item.id, item.enabled ? "running" : "stopped"] as const
          }
        })
      )
      setSiteStatuses(Object.fromEntries(statusEntries))
      if (statusLoadFailed) {
        toast.error("部分站点运行状态加载失败，已使用启停配置兜底显示")
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "加载站点列表失败")
      setSites([])
      setTotal(0)
      setSiteStatuses({})
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    return deferEffect(() => load(page))
  }, [load, page])

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  function rememberSiteReloadFailureOperation(
    error: unknown,
    operation: string,
    site: Site,
    payload?: Record<string, unknown>
  ) {
    const item = getConfigAppliedReloadFailureItem<Site>(error)
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    setOperationDetails({
      operation,
      site_id: site.id,
      host: site.host,
      payload: payload ?? null,
      response: {
        site: item,
        reload_failed: true,
        reload_error: error instanceof Error ? error.message : null,
        reload_failure: details,
      },
    })
  }

  function openAddSiteDialog() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setDialogOpen(true)
  }

  async function toggleSite(site: Site) {
    const payload = { enabled: !site.enabled }
    setBusyId(site.id)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      let response
      if (site.enabled) {
        response = await stopSite(site.id)
      } else {
        response = await startSite(site.id)
      }
      setOperationDetails({
        operation: site.enabled ? "stop" : "start",
        site_id: site.id,
        host: site.host,
        payload,
        response,
      })
      setSiteStatuses((prev) => ({
        ...prev,
        [site.id]: site.enabled ? "stopped" : "running",
      }))
      toast.success(site.enabled ? "站点已停用" : "站点已启用")
      load(page)
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        rememberSiteReloadFailureOperation(
          err,
          site.enabled ? "stop" : "start",
          site,
          payload
        )
        await load(page)
      }
      toast.error(err instanceof Error ? err.message : "更新站点状态失败")
    } finally {
      setBusyId(null)
    }
  }

  async function removeSite() {
    if (!deleteTarget) return
    const target = deleteTarget
    setDeleting(true)
    setBusyId(target.id)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      await deleteSite(target.id)
      setOperationDetails({
        operation: "delete",
        site_id: target.id,
        host: target.host,
        payload: {
          id: target.id,
          host: target.host,
        },
        status_code: 204,
        response: null,
      })
      toast.success("站点已删除")
      setDeleteTarget(null)
      load(page)
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(err)
        if (details) {
          setOperationDetails({
            operation: "delete",
            site_id: target.id,
            host: target.host,
            payload: {
              id: target.id,
              host: target.host,
            },
            response: details,
          })
        }
        setDeleteTarget(null)
        await load(page)
      }
      toast.error(err instanceof Error ? err.message : "删除站点失败")
    } finally {
      setDeleting(false)
      setBusyId(null)
    }
  }

  async function updateProtectionMode(mode: ProtectionMode) {
    if (!modeTarget) return
    setModeSaving(true)
    setBusyId(modeTarget.id)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const payload = {
      attack_protection_level: mode === "observe" ? "observe" : "protect",
      maintenance_enabled: mode === "maintenance",
    }
    try {
      const result = await updateSite(modeTarget.id, payload)
      setOperationDetails({
        operation: "update_protection_mode",
        site_id: modeTarget.id,
        host: modeTarget.host,
        mode,
        payload,
        response: result,
      })
      toast.success("防护模式已更新")
      setModeTarget(null)
      load(page)
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        rememberSiteReloadFailureOperation(
          err,
          "update_protection_mode",
          modeTarget,
          {
            mode,
            ...payload,
          }
        )
        setModeTarget(null)
        await load(page)
      }
      toast.error(err instanceof Error ? err.message : "更新防护模式失败")
    } finally {
      setModeSaving(false)
      setBusyId(null)
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <PageIntro
        eyebrow="Applications"
        title="站点管理"
        description={`共 ${total} 个防护应用，统一管理域名、监听地址、上游与防护模式。`}
        actions={
          <Button
            onClick={openAddSiteDialog}
            className="w-full rounded-lg shadow-sm sm:w-auto"
          >
            <Plus data-icon="inline-start" />
            添加应用
          </Button>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回站点操作响应体；请核对 item 或 error 字段。
          </AlertDescription>
          <CopyableBlock
            label="reload 失败响应体"
            value={JSON.stringify(reloadFailureDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {operationDetails ? (
        <Alert className="gap-3">
          <Shield />
          <AlertTitle>最近站点操作响应</AlertTitle>
          <AlertDescription>
            后端已返回站点操作响应；请核对 operation、site_id 与响应字段。
          </AlertDescription>
          <CopyableBlock
            label="站点操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {/* Site cards */}
      {loading ? (
        <div className="flex flex-col gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton
              key={i}
              className="h-[140px] rounded-lg border border-border shadow-sm"
            />
          ))}
        </div>
      ) : sites.length === 0 ? (
        <EmptyState
          title="还没有防护应用"
          description="创建站点后即可绑定域名、监听地址与上游目标。"
          action={
            <Button onClick={openAddSiteDialog} className="rounded-lg">
              <Plus data-icon="inline-start" />
              新建站点
            </Button>
          }
        />
      ) : (
        <div className="flex flex-col gap-3">
          {sites.map((site) => {
            const upstreams = parseSiteUpstreams(site.upstream_urls)
            const isBusy = busyId === site.id
            const listenerSummary =
              site.listener_summary || site.bind?.replace(/^.*:/, "") || "80"
            const tlsSummary =
              site.tls_summary || (site.tls_enabled ? "HTTPS" : "HTTP")
            const siteHosts = site.host
              ? site.host
                  .split(",")
                  .map((h) => h.trim())
                  .filter(Boolean)
              : []
            const primaryHost = siteHosts[0] || site.host
            const protectionMode = getProtectionMode(site)
            const runtimeStatus =
              siteStatuses[site.id] || (site.enabled ? "running" : "stopped")
            const isRunning = runtimeStatus === "running"

            return (
              <div
                key={site.id}
                className="console-panel overflow-hidden transition-shadow hover:shadow-md"
              >
                <div className="flex flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center">
                  {/* Icon */}
                  <div
                    className={cn(
                      "flex size-10 shrink-0 items-center justify-center rounded-full",
                      site.enabled
                        ? "bg-primary/10 text-primary"
                        : "bg-muted text-muted-foreground"
                    )}
                  >
                    <Globe className="size-5" aria-hidden="true" />
                  </div>

                  {/* Info */}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <h2 className="truncate text-[15px] font-semibold text-foreground">
                        {primaryHost}
                      </h2>
                      {siteHosts.length > 1 && (
                        <Badge variant="secondary" className="rounded-md">
                          +{siteHosts.length - 1} 域名
                        </Badge>
                      )}
                      <Badge
                        variant={isRunning ? "outline" : "secondary"}
                        className="rounded-md"
                      >
                        {isRunning ? "运行中" : "已停止"}
                      </Badge>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[13px] text-muted-foreground">
                      {siteHosts.slice(0, 3).map((h) => (
                        <span key={h} className="flex items-center gap-1">
                          <Globe className="size-3" aria-hidden="true" />
                          {h}
                        </span>
                      ))}
                      {siteHosts.length > 3 && (
                        <span className="text-muted-foreground">
                          +{siteHosts.length - 3}
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <Shield className="size-3" aria-hidden="true" />
                        {listenerSummary}/{tlsSummary}
                      </span>
                    </div>
                  </div>

                  {/* Protection mode button */}
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="rounded-lg text-[13px]"
                    disabled={isBusy}
                    onClick={() => setModeTarget(site)}
                  >
                    <Shield data-icon="inline-start" />
                    {protectionModeLabel(protectionMode)}
                  </Button>

                  {/* Actions */}
                  <div className="flex w-full flex-wrap items-center justify-end gap-1.5 lg:w-auto lg:flex-nowrap">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-xs"
                      onClick={() => router.push(`/sites/_/?id=${site.id}`)}
                    >
                      详情
                      <ExternalLink data-icon="inline-end" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="rounded-md"
                      disabled={isBusy}
                      onClick={() => toggleSite(site)}
                      aria-label={site.enabled ? "停用站点" : "启用站点"}
                      title={site.enabled ? "停用" : "启用"}
                    >
                      {isBusy ? (
                        <Loader2
                          data-icon="inline-start"
                          className="animate-spin"
                        />
                      ) : (
                        <Power
                          data-icon="inline-start"
                          className={cn(
                            site.enabled
                              ? "text-primary"
                              : "text-muted-foreground"
                          )}
                        />
                      )}
                    </Button>
                    <Button
                      variant="destructive"
                      size="icon"
                      className="rounded-md"
                      disabled={isBusy}
                      onClick={() => setDeleteTarget(site)}
                      aria-label="删除站点"
                    >
                      <Trash2 data-icon="inline-start" />
                    </Button>
                  </div>
                </div>

                {/* Stats row */}
                <Separator />
                <div className="flex flex-col gap-3 px-5 py-3 text-[12px] sm:flex-row sm:items-center">
                  <div className="flex flex-wrap items-center gap-3 text-muted-foreground">
                    <span>请求统计请到站点详情查看</span>
                    <span className="text-muted-foreground/45">•</span>
                    <span>创建于 {formatDate(site.created_at)}</span>
                  </div>
                  <div className="flex min-w-0 flex-wrap items-center gap-2 sm:ml-auto sm:justify-end">
                    {upstreams.slice(0, 2).map((u, i) => (
                      <span
                        key={i}
                        className="inline-flex items-center gap-1 rounded border border-border bg-muted/35 px-2 py-0.5 font-mono text-[11px] text-muted-foreground"
                      >
                        {u}
                        {isRunning && (
                          <span className="text-primary">●</span>
                        )}
                      </span>
                    ))}
                    {upstreams.length > 2 && (
                      <span className="text-muted-foreground">
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
        onReloadFailureDetails={(details) => setReloadFailureDetails(details)}
        onOperationDetails={(details) => setOperationDetails(details)}
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

      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open && !deleting) setDeleteTarget(null)
        }}
      >
        <AlertDialogContent className="max-w-md rounded-xl">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除站点</AlertDialogTitle>
            <AlertDialogDescription>
              删除后该站点入口、监听配置与运行时状态都会移除，此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Alert variant="destructive">
            <AlertDescription>
              目标站点：
              <strong>
                {deleteTarget?.host
                  ?.split(",")
                  .map((h) => h.trim())
                  .join(", ") || "-"}
              </strong>
            </AlertDescription>
          </Alert>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault()
                removeSite()
              }}
            >
              {deleting ? "删除中..." : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
