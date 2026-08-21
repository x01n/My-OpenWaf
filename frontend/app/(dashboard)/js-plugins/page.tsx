"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  useJSPluginDelete,
  useJSPluginStats,
  useJSPluginToggle,
  useJSPlugins,
  useAllSites,
} from "@/hooks/use-api"
import {
  IconAlertTriangle,
  IconBraces,
  IconEdit,
  IconInfoCircle,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react"
import type { JSPlugin, JSPluginStage } from "@/lib/types"
import { JSPluginEditorDialog } from "./components/plugin-editor-dialog"

const STAGE_CLASS: Record<JSPluginStage, string> = {
  request:
    "border-sky-500/30 bg-sky-500/12 text-sky-700 dark:border-sky-400/30 dark:bg-sky-400/15 dark:text-sky-300",
  response:
    "border-violet-500/30 bg-violet-500/12 text-violet-700 dark:border-violet-400/30 dark:bg-violet-400/15 dark:text-violet-300",
}

/**
 * JavaScript 边缘脚本管理页。
 */
export default function JSPluginsPage() {
  const { t } = useTranslation()
  const { data, isLoading, error, mutate: refresh } = useJSPlugins()
  const { data: stats, error: statsError } = useJSPluginStats()
  const { data: sitesData } = useAllSites()
  const sites = useMemo(() => sitesData?.items ?? [], [sitesData])
  const siteNames = useMemo(
    () => new Map(sites.map((site) => [site.id, site.host])),
    [sites]
  )
  const statsByID = useMemo(
    () => new Map((stats?.items ?? []).map((item) => [item.id, item])),
    [stats]
  )
  const { execute: deletePlugin, loading: deleteLoading } = useJSPluginDelete()
  const { execute: togglePlugin } = useJSPluginToggle()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [dialogSeq, setDialogSeq] = useState(0)
  const [editing, setEditing] = useState<JSPlugin | null>(null)
  const [deleteId, setDeleteId] = useState<number | null>(null)

  const openCreate = () => {
    setEditing(null)
    setDialogSeq((value) => value + 1)
    setDialogOpen(true)
  }

  const openEdit = (plugin: JSPlugin) => {
    setEditing(plugin)
    setDialogSeq((value) => value + 1)
    setDialogOpen(true)
  }

  const handleToggle = async (plugin: JSPlugin, enabled: boolean) => {
    if (plugin.stage === "response" && enabled) {
      toast.error(t("jsPlugins.responseStageUnavailable"))
      return
    }
    try {
      await togglePlugin({ id: plugin.id, enabled })
      refresh()
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : t("common.updateFailed")
      )
    }
  }

  const confirmDelete = async () => {
    if (deleteId === null) return
    try {
      await deletePlugin(deleteId)
      toast.success(t("common.deleteSuccess"))
      setDeleteId(null)
      refresh()
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : t("common.deleteFailed")
      )
    }
  }

  const plugins = data?.items ?? []
  const compileFailures = plugins.filter(
    (plugin) => plugin.stage === "request" && plugin.compile_error
  )
  const columns = [
    {
      key: "name",
      title: t("jsPlugins.name"),
      render: (row: JSPlugin) => (
        <span className="font-medium">{row.name}</span>
      ),
    },
    {
      key: "stage",
      title: t("jsPlugins.stage"),
      width: "130px",
      render: (row: JSPlugin) => (
        <Badge variant="outline" className={STAGE_CLASS[row.stage]}>
          {row.stage === "request"
            ? t("jsPlugins.stageRequest")
            : t("jsPlugins.stageResponse")}
        </Badge>
      ),
    },
    {
      key: "failure_mode",
      title: t("jsPlugins.failureMode"),
      width: "130px",
      render: (row: JSPlugin) => (
        <Badge variant="secondary">
          {row.failure_mode === "fail_open"
            ? t("jsPlugins.failOpen")
            : t("jsPlugins.failClosed")}
        </Badge>
      ),
    },
    {
      key: "priority",
      title: t("jsPlugins.priority"),
      width: "80px",
      render: (row: JSPlugin) => (
        <span className="font-mono text-sm">{row.priority}</span>
      ),
    },
    {
      key: "scope",
      title: t("jsPlugins.scope"),
      width: "150px",
      render: (row: JSPlugin) =>
        row.site_id == null ? (
          <Badge variant="secondary">{t("jsPlugins.scopeGlobal")}</Badge>
        ) : (
          <Badge variant="outline">
            {siteNames.get(row.site_id) || `#${row.site_id}`}
          </Badge>
        ),
    },
    {
      key: "timeout_ms",
      title: t("jsPlugins.timeout"),
      width: "100px",
      render: (row: JSPlugin) => (
        <span className="font-mono text-sm text-muted-foreground">
          {row.timeout_ms > 0
            ? `${row.timeout_ms}ms`
            : t("jsPlugins.timeoutDefault")}
        </span>
      ),
    },
    {
      key: "stats",
      title: t("jsPlugins.stats"),
      width: "220px",
      render: (row: JSPlugin) => {
        const item = statsByID.get(row.id)
        if (!item) {
          return (
            <span className="text-xs text-muted-foreground">
              {t("jsPlugins.statsNotLoaded")}
            </span>
          )
        }
        return (
          <div className="space-y-0.5 text-xs text-muted-foreground">
            <div>
              {t("jsPlugins.statsRuns")}: {item.runs} ·{" "}
              {t("jsPlugins.statsFailures")}: {item.failures}
            </div>
            <div>
              {t("jsPlugins.statsTimeouts")}: {item.timeouts} ·{" "}
              {t("jsPlugins.statsAvgMS", { value: item.avg_ms.toFixed(2) })}
            </div>
          </div>
        )
      },
    },
    {
      key: "description",
      title: t("common.description"),
      render: (row: JSPlugin) =>
        row.description ? (
          <TooltipProvider delayDuration={200}>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="block max-w-[220px] truncate text-sm text-muted-foreground">
                  {row.description}
                </span>
              </TooltipTrigger>
              <TooltipContent className="max-w-md break-all whitespace-pre-wrap">
                {row.description}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      key: "compile_error",
      title: t("common.status"),
      width: "150px",
      render: (row: JSPlugin) =>
        row.stage === "response" ? (
          <Badge variant="destructive" className="gap-1">
            <IconAlertTriangle className="h-3.5 w-3.5" />
            {t("jsPlugins.stageResponseUnavailable")}
          </Badge>
        ) : row.compile_error ? (
          <TooltipProvider delayDuration={200}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge
                  variant="destructive"
                  className="max-w-[140px] cursor-help gap-1"
                >
                  <IconAlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate">
                    {t("luaPlugins.compileError")}
                  </span>
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="max-w-lg break-all whitespace-pre-wrap">
                {row.compile_error}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      key: "enabled",
      title: t("jsPlugins.enabled"),
      width: "80px",
      render: (row: JSPlugin) => (
        <Switch
          checked={row.enabled}
          disabled={row.stage === "response" && !row.enabled}
          onCheckedChange={(value) => handleToggle(row, value)}
        />
      ),
    },
    {
      key: "actions",
      title: t("common.action"),
      width: "100px",
      render: (row: JSPlugin) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => openEdit(row)}
            title={t("common.edit")}
          >
            <IconEdit className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => setDeleteId(row.id)}
            title={t("common.delete")}
          >
            <IconTrash className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        icon={<IconBraces className="h-6 w-6" />}
        title={t("jsPlugins.title")}
        description={t("jsPlugins.description")}
        actions={
          <Button onClick={openCreate}>
            <IconPlus className="h-4 w-4" />
            {t("jsPlugins.add")}
          </Button>
        }
      />

      <Alert>
        <IconInfoCircle className="h-4 w-4" />
        <AlertTitle>{t("jsPlugins.runtimeTitle")}</AlertTitle>
        <AlertDescription>{t("jsPlugins.runtimeDescription")}</AlertDescription>
      </Alert>

      {error && (
        <Alert variant="destructive">
          <IconAlertTriangle className="h-4 w-4" />
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {error instanceof Error ? error.message : String(error)}
          </AlertDescription>
        </Alert>
      )}

      {compileFailures.length > 0 && (
        <Alert variant="destructive">
          <IconAlertTriangle className="h-4 w-4" />
          <AlertTitle>{t("luaPlugins.compileError")}</AlertTitle>
          <AlertDescription>
            <div className="space-y-2">
              {compileFailures.map((plugin) => (
                <div
                  key={plugin.id}
                  className="rounded-md border border-destructive/20 bg-destructive/5 p-2"
                >
                  <div className="font-medium">{plugin.name}</div>
                  <code className="mt-1 block text-xs break-all whitespace-pre-wrap">
                    {plugin.compile_error}
                  </code>
                </div>
              ))}
            </div>
          </AlertDescription>
        </Alert>
      )}

      {statsError && (
        <Alert variant="destructive">
          <IconAlertTriangle className="h-4 w-4" />
          <AlertTitle>{t("jsPlugins.statsLoadFailed")}</AlertTitle>
          <AlertDescription>
            {statsError instanceof Error
              ? statsError.message
              : String(statsError)}
          </AlertDescription>
        </Alert>
      )}
      {stats && !statsError && stats.total === 0 && (
        <p className="rounded-md border bg-muted/20 p-3 text-sm text-muted-foreground">
          {t("jsPlugins.statsEmpty")}
        </p>
      )}
      {stats && !statsError && stats.total > 0 && (
        <p className="rounded-md border bg-muted/20 p-3 text-sm text-muted-foreground">
          {t("jsPlugins.statsSummary", { total: stats.total })}
        </p>
      )}

      <DataTable<JSPlugin>
        columns={columns}
        data={plugins}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("jsPlugins.empty")}
      />

      <JSPluginEditorDialog
        key={dialogSeq}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        editing={editing}
        sites={sites}
        onSaved={refresh}
      />

      <ConfirmDialog
        open={deleteId !== null}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("jsPlugins.deleteTitle")}
        description={t("jsPlugins.deleteConfirm")}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  )
}
