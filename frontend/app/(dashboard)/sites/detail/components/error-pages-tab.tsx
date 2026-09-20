"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  IconAlertTriangle,
  IconDeviceFloppy,
  IconEye,
  IconPlus,
  IconRefresh,
  IconTrash,
} from "@tabler/icons-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import {
  useDefaultErrorPages,
  useErrorPagesUpdate,
  useSiteErrorPages,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import { errorPageApi } from "@/lib/api"
import type { ErrorPageConfig, Site, SiteErrorPages } from "@/lib/types"

interface ErrorPagesTabProps {
  site: Site
}

type ErrorPageMap = Record<string, ErrorPageConfig>

const FALLBACK_STATUS_CODES = [
  "403",
  "404",
  "429",
  "431",
  "500",
  "502",
  "503",
  "504",
]

const MAX_ERROR_PAGES = 32
const MAX_ERROR_PAGE_HTML_BYTES = 256 * 1024
const MAX_ERROR_PAGE_TITLE_BYTES = 256
const MAX_ERROR_PAGE_CONTENT_TYPE_BYTES = 128

function clonePages(pages: ErrorPageMap | undefined): ErrorPageMap {
  if (!pages) return {}
  return Object.fromEntries(
    Object.entries(pages).map(([code, page]) => [code, { ...page }])
  )
}

function statusSort(left: string, right: string): number {
  const leftCode = Number(left)
  const rightCode = Number(right)
  if (Number.isFinite(leftCode) && Number.isFinite(rightCode)) {
    return leftCode - rightCode
  }
  return left.localeCompare(right)
}

function pageForStatus(
  status: string,
  current: ErrorPageMap,
  defaults: ErrorPageMap
): ErrorPageConfig {
  const page = current[status] ?? defaults[status]
  return {
    status_code: page?.status_code || Number(status) || 500,
    title: page?.title || "",
    html: page?.html || "",
    content_type: page?.content_type || "text/html",
  }
}

function normalizeResponse(response: SiteErrorPages | undefined): {
  pages: ErrorPageMap
  error: string | null
} {
  const source = response?.error_pages
  if (!source) return { pages: {}, error: null }
  const entries = Object.entries(source)
  if (entries.length > MAX_ERROR_PAGES) {
    return { pages: {}, error: "sites.detail.errorPages.invalidStored" }
  }
  const encoder = new TextEncoder()
  const normalized: ErrorPageMap = {}
  for (const [key, page] of entries) {
    const code = Number(key)
    const rawPage = page as unknown as Record<string, unknown>
    const statusCode = rawPage.status_code ?? code
    const title = rawPage.title ?? ""
    const html = rawPage.html ?? ""
    const contentType = rawPage.content_type ?? "text/html"
    if (
      !Number.isInteger(code) ||
      code < 400 ||
      code > 599 ||
      !page ||
      (statusCode !== 0 && statusCode !== code) ||
      typeof title !== "string" ||
      typeof html !== "string" ||
      typeof contentType !== "string" ||
      encoder.encode(title).length > MAX_ERROR_PAGE_TITLE_BYTES ||
      encoder.encode(html).length > MAX_ERROR_PAGE_HTML_BYTES ||
      encoder.encode(contentType).length > MAX_ERROR_PAGE_CONTENT_TYPE_BYTES ||
      /[\r\n]/.test(contentType)
    ) {
      return { pages: {}, error: "sites.detail.errorPages.invalidStored" }
    }
    const normalizedKey = String(code)
    if (Object.prototype.hasOwnProperty.call(normalized, normalizedKey)) {
      return { pages: {}, error: "sites.detail.errorPages.invalidStored" }
    }
    normalized[normalizedKey] = {
      status_code: code,
      title,
      html,
      content_type: contentType.trim() || "text/html",
    }
  }
  return { pages: normalized, error: null }
}

/**
 * 站点自定义错误页编辑器。
 * 仅提交 error_pages 字段，避免覆盖站点的其他配置；预览使用 sandbox iframe，
 * 不把用户编辑的 HTML 直接插入管理端 DOM。
 */
export function ErrorPagesTab({ site }: ErrorPagesTabProps) {
  const { t } = useTranslation()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const currentQuery = useSiteErrorPages(site.id)
  const defaultsQuery = useDefaultErrorPages()
  const updatePages = useErrorPagesUpdate()
  const [draftPages, setDraftPages] = useState<ErrorPageMap | null>(null)
  const [selectedStatus, setSelectedStatus] = useState("403")
  const [previewHTML, setPreviewHTML] = useState("")
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [newStatusCode, setNewStatusCode] = useState("")

  const previewDocument = useMemo(() => {
    if (!previewHTML) return ""
    // sandbox 禁止脚本和同源访问；CSP 进一步阻止 HTML 中的图片、样式或
    // 链接标签向内网/外部地址发起请求，避免管理员预览时产生副作用。
    return `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; font-src data:;"></head><body>${previewHTML}</body></html>`
  }, [previewHTML])

  const currentResult = useMemo(
    () => normalizeResponse(currentQuery.data),
    [currentQuery.data]
  )
  const currentPages = currentResult.pages
  const storedError = currentResult.error
  const defaultPages = useMemo(
    () => defaultsQuery.data?.defaults ?? {},
    [defaultsQuery.data]
  )
  const pages = draftPages ?? currentPages
  const statusCodes = useMemo(() => {
    const codes = new Set([
      ...FALLBACK_STATUS_CODES,
      ...Object.keys(defaultPages),
      ...Object.keys(pages),
    ])
    return Array.from(codes).sort(statusSort)
  }, [defaultPages, pages])

  const activeStatus = statusCodes.includes(selectedStatus)
    ? selectedStatus
    : (statusCodes[0] ?? "403")
  const selectedPage = pageForStatus(activeStatus, pages, defaultPages)
  const hasOverride = Object.prototype.hasOwnProperty.call(pages, activeStatus)
  const defaultPage = defaultPages[activeStatus]

  const updateSelectedPage = (patch: Partial<ErrorPageConfig>) => {
    if (!canManage) return
    setDraftPages((currentDraft) => {
      const current = currentDraft ?? pages
      return {
        ...current,
        [activeStatus]: {
          ...pageForStatus(activeStatus, current, defaultPages),
          ...patch,
          status_code:
            patch.status_code ??
            pageForStatus(activeStatus, current, defaultPages).status_code,
        },
      }
    })
  }

  const handleResetToDefault = () => {
    if (!canManage) return
    setDraftPages((currentDraft) => {
      const next = { ...(currentDraft ?? pages) }
      delete next[activeStatus]
      return next
    })
    setPreviewHTML("")
    setPreviewError(null)
  }

  const handleAddStatusCode = () => {
    if (!canManage) return
    const code = Number(newStatusCode.trim())
    if (!Number.isInteger(code) || code < 400 || code > 599) {
      toast.error(t("sites.detail.errorPages.statusCodeInvalid"))
      return
    }
    const key = String(code)
    if (
      !Object.prototype.hasOwnProperty.call(pages, key) &&
      Object.keys(pages).length >= MAX_ERROR_PAGES
    ) {
      toast.error(t("sites.detail.errorPages.tooMany"))
      return
    }
    setDraftPages((currentDraft) => {
      const current = currentDraft ?? pages
      if (Object.prototype.hasOwnProperty.call(current, key)) return current
      return { ...current, [key]: pageForStatus(key, current, defaultPages) }
    })
    setSelectedStatus(key)
    setNewStatusCode("")
  }

  const handleSave = async () => {
    if (!canManage) return
    const validation = normalizeResponse({
      site_id: site.id,
      error_pages: pages,
    }).error
    if (validation) {
      toast.error(t(validation))
      return
    }
    try {
      await updatePages.execute({
        siteId: site.id,
        data: { error_pages: clonePages(pages) },
      })
      setDraftPages(null)
      toast.success(t("common.saveSuccess"))
    } catch (error: unknown) {
      toast.error(
        error instanceof Error ? error.message : t("common.operationFailed")
      )
    }
  }

  const handlePreview = async () => {
    if (!canManage) return
    if (!selectedPage.html.trim()) {
      toast.error(t("sites.detail.errorPages.htmlRequired"))
      return
    }
    setPreviewLoading(true)
    setPreviewError(null)
    try {
      const response = await errorPageApi.preview({
        html: selectedPage.html,
        status_code: selectedPage.status_code,
      })
      setPreviewHTML(response.rendered || selectedPage.html)
      setPreviewError(response.parse_error || response.execute_error || null)
    } catch (error: unknown) {
      setPreviewError(
        error instanceof Error ? error.message : t("common.operationFailed")
      )
      setPreviewHTML("")
    } finally {
      setPreviewLoading(false)
    }
  }

  if (currentQuery.isLoading || defaultsQuery.isLoading) {
    return (
      <div className="min-w-0 space-y-4">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    )
  }

  if (currentQuery.error || defaultsQuery.error || storedError) {
    return (
      <Alert variant="destructive">
        <IconAlertTriangle />
        <AlertTitle>{t("sites.detail.errorPages.loadFailedTitle")}</AlertTitle>
        <AlertDescription>
          {storedError
            ? t(storedError)
            : t("sites.detail.errorPages.loadFailed")}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className="min-w-0 space-y-4">
      {!authLoading && !canManage && (
        <Alert>
          <IconAlertTriangle />
          <AlertDescription>{t("common.readOnlyHint")}</AlertDescription>
        </Alert>
      )}
      <fieldset
        disabled={!canManage}
        className="m-0 min-w-0 space-y-4 border-0 p-0"
      >
        <Card>
          <CardHeader className="gap-3 pb-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <CardTitle className="text-base">
                {t("sites.detail.errorPages.title")}
              </CardTitle>
              <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
                {t("sites.detail.errorPages.description")}
              </p>
            </div>
            <Badge variant="outline" className="w-fit shrink-0">
              {t("sites.detail.errorPages.overrideCount", {
                count: Object.keys(pages).length,
              })}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid min-w-0 gap-4 lg:grid-cols-[minmax(10rem,15rem)_minmax(0,1fr)]">
              <div className="min-w-0 space-y-2">
                <Label htmlFor="error-page-status">
                  {t("sites.detail.errorPages.statusCode")}
                </Label>
                <Select value={activeStatus} onValueChange={setSelectedStatus}>
                  <SelectTrigger
                    id="error-page-status"
                    className="w-full min-w-0"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {statusCodes.map((status) => (
                      <SelectItem key={status} value={status}>
                        {status}
                        {defaultPages[status]?.title
                          ? ` - ${defaultPages[status].title}`
                          : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <div className="flex min-w-0 gap-2">
                  <Input
                    type="number"
                    min={400}
                    max={599}
                    value={newStatusCode}
                    onChange={(event) => setNewStatusCode(event.target.value)}
                    placeholder="418"
                    aria-label={t("sites.detail.errorPages.addStatusCode")}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    className="shrink-0"
                    onClick={handleAddStatusCode}
                    disabled={
                      !newStatusCode.trim() ||
                      Object.keys(pages).length >= MAX_ERROR_PAGES
                    }
                  >
                    <IconPlus className="size-4" />
                    {t("sites.detail.errorPages.addStatusCode")}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.errorPages.statusHint")}
                </p>
                <div className="rounded-lg border bg-muted/30 p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">
                      {t("sites.detail.errorPages.source")}
                    </span>
                    <Badge variant={hasOverride ? "default" : "secondary"}>
                      {hasOverride
                        ? t("sites.detail.errorPages.custom")
                        : t("sites.detail.errorPages.builtin")}
                    </Badge>
                  </div>
                  <p className="mt-2 break-words text-muted-foreground">
                    {hasOverride
                      ? t("sites.detail.errorPages.customHint")
                      : t("sites.detail.errorPages.builtinHint")}
                  </p>
                </div>
              </div>

              <div className="min-w-0 space-y-4">
                <div className="grid min-w-0 gap-4 sm:grid-cols-2">
                  <div className="min-w-0 space-y-2">
                    <Label htmlFor="error-page-title">
                      {t("sites.detail.errorPages.pageTitle")}
                    </Label>
                    <Input
                      id="error-page-title"
                      className="min-w-0"
                      maxLength={MAX_ERROR_PAGE_TITLE_BYTES}
                      value={selectedPage.title}
                      onChange={(event) =>
                        updateSelectedPage({ title: event.target.value })
                      }
                    />
                  </div>
                  <div className="min-w-0 space-y-2">
                    <Label htmlFor="error-page-content-type">
                      {t("sites.detail.errorPages.contentType")}
                    </Label>
                    <Input
                      id="error-page-content-type"
                      className="min-w-0 font-mono text-xs"
                      maxLength={MAX_ERROR_PAGE_CONTENT_TYPE_BYTES}
                      value={selectedPage.content_type}
                      onChange={(event) =>
                        updateSelectedPage({ content_type: event.target.value })
                      }
                    />
                  </div>
                </div>

                <div className="min-w-0 space-y-2">
                  <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                    <Label htmlFor="error-page-html">
                      {t("sites.detail.errorPages.html")}
                    </Label>
                    <span className="text-xs text-muted-foreground">
                      {t("sites.detail.errorPages.htmlHint")}
                    </span>
                  </div>
                  <Textarea
                    id="error-page-html"
                    className="max-h-[55vh] min-h-64 resize-y overflow-auto font-mono text-xs leading-5"
                    maxLength={MAX_ERROR_PAGE_HTML_BYTES}
                    value={selectedPage.html}
                    onChange={(event) =>
                      updateSelectedPage({ html: event.target.value })
                    }
                    spellCheck={false}
                  />
                </div>

                <div className="flex min-w-0 flex-wrap justify-end gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => updateSelectedPage(defaultPage || {})}
                    disabled={!defaultPage}
                  >
                    <IconRefresh className="size-4" />
                    {t("sites.detail.errorPages.useBuiltin")}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    className="text-destructive hover:text-destructive"
                    onClick={handleResetToDefault}
                    disabled={!hasOverride}
                  >
                    <IconTrash className="size-4" />
                    {t("sites.detail.errorPages.clearOverride")}
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={handlePreview}
                    disabled={previewLoading || !selectedPage.html.trim()}
                  >
                    <IconEye className="size-4" />
                    {previewLoading
                      ? t("sites.detail.errorPages.previewing")
                      : t("sites.detail.errorPages.preview")}
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {(previewHTML || previewError) && (
          <Card className="min-w-0 overflow-hidden">
            <CardHeader className="pb-3">
              <CardTitle className="text-base">
                {t("sites.detail.errorPages.previewTitle")}
              </CardTitle>
            </CardHeader>
            <CardContent className="min-w-0 space-y-3">
              {previewError && (
                <Alert variant="destructive">
                  <IconAlertTriangle />
                  <AlertDescription className="break-words">
                    {previewError}
                  </AlertDescription>
                </Alert>
              )}
              {previewHTML && (
                <iframe
                  title={t("sites.detail.errorPages.previewFrameTitle")}
                  sandbox=""
                  referrerPolicy="no-referrer"
                  srcDoc={previewDocument}
                  className="h-72 w-full max-w-full rounded-lg border bg-white"
                />
              )}
            </CardContent>
          </Card>
        )}

        <div className="flex min-w-0 flex-wrap items-center justify-between gap-3">
          <p className="max-w-2xl min-w-0 text-xs text-muted-foreground">
            {t("sites.detail.errorPages.saveHint")}
          </p>
          <Button
            type="button"
            onClick={handleSave}
            disabled={updatePages.loading || !!storedError}
            className="shrink-0"
          >
            <IconDeviceFloppy className="size-4" />
            {updatePages.loading ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </fieldset>
    </div>
  )
}
