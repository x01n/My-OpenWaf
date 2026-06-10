"use client"

import { useCallback, useEffect, useId, useMemo, useState } from "react"
import { toast } from "sonner"

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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldTitle,
} from "@/components/ui/field"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { CopyableBlock } from "@/components/log-presentation"
import {
  AlertTriangle,
  Eye,
  FileWarning,
  RefreshCcw,
  Save,
  Trash2,
} from "@/lib/icons"
import { deferEffect } from "@/lib/effects"
import {
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
} from "@/lib/api"
import {
  getDefaultErrorPages,
  getSiteErrorPages,
  previewErrorPage,
  updateSiteErrorPages,
  type ErrorPageConfig,
} from "@/lib/rules-api"

const orderedStatusCodes = ["403", "404", "429", "500", "502", "503"]

export function SiteErrorPagesPanel({
  siteId,
  siteHost,
}: {
  siteId: number
  siteHost: string
}) {
  const htmlEditorId = useId()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [previewing, setPreviewing] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [clearOpen, setClearOpen] = useState(false)
  const [activeCode, setActiveCode] = useState("403")
  const [defaults, setDefaults] = useState<Record<string, ErrorPageConfig>>({})
  const [sitePages, setSitePages] = useState<Record<string, ErrorPageConfig>>(
    {}
  )
  const [previewHtml, setPreviewHtml] = useState("")
  const [previewMessage, setPreviewMessage] = useState("")
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  const primaryHost = useMemo(
    () => siteHost.split(",").map((item) => item.trim()).find(Boolean) ?? "",
    [siteHost]
  )

  const statusCodes = useMemo(() => {
    const merged = new Set([
      ...orderedStatusCodes,
      ...Object.keys(defaults),
      ...Object.keys(sitePages),
    ])
    return Array.from(merged).sort((a, b) => Number(a) - Number(b))
  }, [defaults, sitePages])

  const currentPage = sitePages[activeCode]
  const defaultPage = defaults[activeCode]
  const currentHtml = currentPage?.html ?? defaultPage?.html ?? ""
  const hasOverride = Object.prototype.hasOwnProperty.call(
    sitePages,
    activeCode
  )
  const overrideCount = Object.keys(sitePages).length

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [defaultResult, siteResult] = await Promise.all([
        getDefaultErrorPages(),
        getSiteErrorPages(siteId),
      ])
      setDefaults(defaultResult.defaults ?? {})
      setSitePages(siteResult.error_pages ?? {})
      setPreviewHtml("")
      setPreviewMessage("")
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "加载站点错误页面失败"
      )
      setDefaults({})
      setSitePages({})
    } finally {
      setLoading(false)
    }
  }, [siteId])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  function patchCurrentPage(patch: Partial<ErrorPageConfig>) {
    setSitePages((prev) => {
      const base = prev[activeCode] ?? defaults[activeCode] ?? {
        status_code: Number(activeCode),
        title: statusLabel(activeCode),
        html: "",
        content_type: "text/html",
      }

      return {
        ...prev,
        [activeCode]: {
          status_code: Number(activeCode),
          title: base.title || statusLabel(activeCode),
          html: base.html || "",
          content_type: base.content_type || "text/html",
          ...patch,
        },
      }
    })
  }

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  async function handlePreview() {
    if (!currentHtml.trim()) {
      toast.error("HTML 内容为空")
      return
    }

    setPreviewing(true)
    setPreviewMessage("")
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      const result = await previewErrorPage(currentHtml, Number(activeCode))
      setPreviewHtml(result.rendered)
      setOperationDetails({
        operation: "preview",
        site_id: siteId,
        payload: {
          status_code: Number(activeCode),
          html: currentHtml,
        },
        response: result,
      })
      if (result.parse_error) {
        setPreviewMessage(result.parse_error)
      } else if (result.execute_error) {
        setPreviewMessage(result.execute_error)
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "预览失败")
    } finally {
      setPreviewing(false)
    }
  }

  async function handleSave() {
    const payload = {
      error_pages: sitePages,
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    try {
      const result = await updateSiteErrorPages(siteId, sitePages)
      setSitePages(result.error_pages ?? {})
      setOperationDetails({
        operation: "update",
        site_id: result.site_id,
        payload,
        response: result,
      })
      toast.success("站点错误页面已保存")
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
        if (details) {
          setOperationDetails({
            operation: "update",
            site_id: siteId,
            payload,
            response: details,
          })
        }
        toast.error(error.message)
        await load()
      } else {
        toast.error(error instanceof Error ? error.message : "保存失败")
      }
    } finally {
      setSaving(false)
    }
  }

  async function handleRemoveCurrentOverride() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSitePages((prev) => {
      const next = { ...prev }
      delete next[activeCode]
      return next
    })
    setPreviewHtml("")
    setPreviewMessage("")
  }

  async function handleClearAllOverrides() {
    const payload = {
      error_pages: {},
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setClearing(true)
    try {
      const result = await updateSiteErrorPages(siteId, {})
      setSitePages(result.error_pages ?? {})
      setOperationDetails({
        operation: "clear",
        site_id: result.site_id,
        payload,
        response: result,
      })
      setPreviewHtml("")
      setPreviewMessage("")
      setClearOpen(false)
      toast.success("站点错误页面覆盖已清空")
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
        if (details) {
          setOperationDetails({
            operation: "clear",
            site_id: siteId,
            payload,
            response: details,
          })
        }
        toast.error(error.message)
        setClearOpen(false)
        await load()
      } else {
        toast.error(error instanceof Error ? error.message : "清空失败")
      }
    } finally {
      setClearing(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">站点错误页面</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            {primaryHost || `站点 ${siteId}`} · 已覆盖 {overrideCount} 个状态码
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="rounded-md"
            disabled={loading}
            onClick={() => void load()}
          >
            <RefreshCcw data-icon="inline-start" />
            刷新
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="rounded-md"
            disabled={loading || previewing}
            onClick={() => void handlePreview()}
          >
            <Eye data-icon="inline-start" />
            {previewing ? "预览中..." : "预览"}
          </Button>
          <Button
            type="button"
            size="sm"
            className="rounded-md"
            disabled={loading || saving}
            onClick={() => void handleSave()}
          >
            <Save data-icon="inline-start" />
            {saving ? "保存中..." : "保存覆盖"}
          </Button>
        </div>
      </div>

      <Alert>
        <AlertTriangle />
        <AlertTitle>覆盖语义</AlertTitle>
        <AlertDescription>
          保存会提交完整 `error_pages` 对象；删除当前状态码覆盖后保存才会恢复默认模板。提交空对象会清空本站点全部覆盖。
        </AlertDescription>
      </Alert>

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回站点错误页面操作响应体；请核对 error 字段。
          </AlertDescription>
          <CopyableBlock
            label="reload 失败响应体"
            value={JSON.stringify(reloadFailureDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {operationDetails ? (
        <Alert className="gap-3">
          <Save />
          <AlertTitle>最近站点错误页面操作响应</AlertTitle>
          <AlertDescription>
            后端已返回站点错误页面操作响应体；请核对 operation、site_id、
            payload 或 response 字段。
          </AlertDescription>
          <CopyableBlock
            label="站点错误页面操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
        <div className="rounded-md border bg-background p-4">
          <div className="mb-3 flex items-center gap-2">
            <FileWarning className="text-muted-foreground" />
            <h4 className="text-sm font-semibold">状态码</h4>
          </div>
          {loading ? (
            <div className="flex flex-col gap-2">
              {Array.from({ length: 6 }).map((_, index) => (
                <Skeleton key={index} className="h-9 w-full" />
              ))}
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {statusCodes.map((code) => (
                <Button
                  key={code}
                  type="button"
                  variant={activeCode === code ? "secondary" : "outline"}
                  className="justify-between rounded-md"
                  onClick={() => {
                    setActiveCode(code)
                    setPreviewHtml("")
                    setPreviewMessage("")
                  }}
                >
                  <span className="truncate">{statusLabel(code)}</span>
                  {Object.prototype.hasOwnProperty.call(sitePages, code) ? (
                    <Badge variant="secondary">覆盖</Badge>
                  ) : (
                    <Badge variant="outline">默认</Badge>
                  )}
                </Button>
              ))}
            </div>
          )}
          <Button
            type="button"
            variant="destructive"
            size="sm"
            className="mt-4 w-full rounded-md"
            disabled={loading || overrideCount === 0}
            onClick={() => {
              setReloadFailureDetails(null)
              setClearOpen(true)
            }}
          >
            <Trash2 data-icon="inline-start" />
            清空全部覆盖
          </Button>
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor={`${htmlEditorId}-title`}>标题</FieldLabel>
              <Textarea
                id={`${htmlEditorId}-title`}
                value={currentPage?.title ?? defaultPage?.title ?? ""}
                rows={2}
                className="rounded-md"
                disabled={loading}
                onChange={(event) =>
                  patchCurrentPage({ title: event.target.value })
                }
              />
              <FieldDescription>
                标题会随本站点覆盖保存，未覆盖时读取默认模板标题。
              </FieldDescription>
            </Field>

            <Field>
              <FieldLabel>内容类型</FieldLabel>
              <Select
                value={
                  currentPage?.content_type ??
                  defaultPage?.content_type ??
                  "text/html"
                }
                disabled={loading}
                onValueChange={(value) =>
                  patchCurrentPage({ content_type: value })
                }
              >
                <SelectTrigger className="rounded-md">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="text/html">text/html</SelectItem>
                    <SelectItem value="text/plain">text/plain</SelectItem>
                    <SelectItem value="application/json">
                      application/json
                    </SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>

            <Field>
              <FieldLabel htmlFor={`${htmlEditorId}-html`}>
                HTML 模板
              </FieldLabel>
              <Textarea
                id={`${htmlEditorId}-html`}
                value={currentHtml}
                rows={18}
                className="rounded-md font-mono text-xs"
                disabled={loading}
                onChange={(event) => patchCurrentPage({ html: event.target.value })}
              />
              <FieldDescription>
                支持 {"{{.StatusCode}}"}、{"{{.Message}}"}、{"{{.ClientIP}}"}、
                {"{{.RequestID}}"} 模板变量。
              </FieldDescription>
            </Field>

            <div className="flex flex-wrap justify-between gap-2">
              <Badge variant={hasOverride ? "secondary" : "outline"}>
                {hasOverride ? "本站点覆盖" : "使用默认模板"}
              </Badge>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="rounded-md"
                disabled={loading || !hasOverride}
                onClick={() => void handleRemoveCurrentOverride()}
              >
                删除当前覆盖
              </Button>
            </div>
          </FieldGroup>

          <Field>
            <FieldTitle>预览</FieldTitle>
            {previewMessage && (
              <Alert>
                <AlertTriangle />
                <AlertDescription>{previewMessage}</AlertDescription>
              </Alert>
            )}
            <div className="min-h-[520px] overflow-hidden rounded-md border bg-background">
              {loading ? (
                <div className="flex h-[520px] flex-col gap-3 p-4">
                  <Skeleton className="h-8 w-40" />
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-32 w-full" />
                </div>
              ) : previewHtml ? (
                <iframe
                  srcDoc={previewHtml}
                  className="h-[520px] w-full border-0"
                  sandbox="allow-same-origin"
                  title="站点错误页面预览"
                />
              ) : (
                <div className="flex h-[520px] items-center justify-center text-sm text-muted-foreground">
                  <div className="flex flex-col items-center gap-2 text-center">
                    <Eye />
                    <p>点击预览查看模板渲染结果</p>
                  </div>
                </div>
              )}
            </div>
          </Field>
        </div>
      </div>

      <AlertDialog
        open={clearOpen}
        onOpenChange={(open) => {
          if (!open && !clearing) setClearOpen(false)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认清空站点错误页面覆盖</AlertDialogTitle>
            <AlertDialogDescription>
              确定清空站点「{primaryHost || siteId}」的全部自定义错误页面？保存后本站点会回到系统默认模板。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={clearing}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={clearing}
              onClick={(event) => {
                event.preventDefault()
                void handleClearAllOverrides()
              }}
            >
              {clearing ? "清空中..." : "清空"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function statusLabel(code: string) {
  switch (code) {
    case "403":
      return "403 Forbidden"
    case "404":
      return "404 Not Found"
    case "429":
      return "429 Too Many Requests"
    case "500":
      return "500 Internal Server Error"
    case "502":
      return "502 Bad Gateway"
    case "503":
      return "503 Service Unavailable"
    default:
      return code
  }
}
