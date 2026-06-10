"use client"

import { useCallback, useEffect, useId, useMemo, useState } from "react"
import { FileWarning, Eye, Save, AlertTriangle } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldLabel,
  FieldTitle,
} from "@/components/ui/field"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { PageIntro, Surface, EmptyState } from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"
import {
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
  listAllSites,
  type Site,
} from "@/lib/api"
import {
  getDefaultErrorPages,
  getSiteErrorPages,
  updateSiteErrorPages,
  previewErrorPage,
  type ErrorPageConfig,
} from "@/lib/rules-api"

const orderedStatusCodes = ["403", "404", "429", "500", "502", "503"] as const
const statusLabels: Record<string, string> = {
  "403": "403 Forbidden",
  "404": "404 Not Found",
  "429": "429 Too Many Requests",
  "500": "500 Internal Server Error",
  "502": "502 Bad Gateway",
  "503": "503 Service Unavailable",
  "504": "504 Gateway Timeout",
}

const statusColors: Record<string, string> = {
  "403": "border-destructive/25 bg-destructive/10 text-destructive",
  "404": "border-chart-2/25 bg-chart-2/10 text-chart-2",
  "429": "border-chart-4/25 bg-chart-4/10 text-chart-4",
  "500": "border-chart-3/25 bg-chart-3/10 text-chart-3",
  "502": "border-chart-5/25 bg-chart-5/10 text-chart-5",
  "503": "border-chart-1/25 bg-chart-1/10 text-chart-1",
  "504": "border-border bg-muted/35 text-muted-foreground",
}

export default function ErrorPagesPage() {
  const selectedSiteId = useId()
  const htmlEditorId = useId()
  const [defaults, setDefaults] = useState<Record<string, ErrorPageConfig>>({})
  const [sites, setSites] = useState<Site[]>([])
  const [selectedSite, setSelectedSite] = useState<string>("")
  const [activeCode, setActiveCode] = useState("403")
  const [sitePages, setSitePages] = useState<Record<string, ErrorPageConfig>>(
    {}
  )
  const [previewHtml, setPreviewHtml] = useState("")
  const [saving, setSaving] = useState(false)
  const [previewing, setPreviewing] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const statusCodes = useMemo(() => {
    const merged = new Set([
      ...orderedStatusCodes,
      ...Object.keys(defaults),
      ...Object.keys(sitePages),
    ])
    return Array.from(merged).sort((a, b) => Number(a) - Number(b))
  }, [defaults, sitePages])
  const selectedStatusCode = statusCodes.includes(activeCode)
    ? activeCode
    : statusCodes[0]

  useEffect(() => {
    getDefaultErrorPages()
      .then((res) => setDefaults(res.defaults ?? {}))
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载默认错误页失败")
      )
    listAllSites()
      .then((res) => {
        const list = res.items ?? []
        setSites(list)
        if (list.length > 0) setSelectedSite(String(list[0].id))
      })
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载站点列表失败")
      )
  }, [])

  const loadSiteErrorPages = useCallback(async (siteId: number) => {
    setPreviewHtml("")
    try {
      const res = await getSiteErrorPages(siteId)
      setSitePages(res.error_pages ?? {})
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载站点错误页失败")
      setSitePages({})
    }
  }, [])

  useEffect(() => {
    if (!selectedSite) return
    return deferEffect(() => loadSiteErrorPages(Number(selectedSite)))
  }, [selectedSite, loadSiteErrorPages])

  function getCurrentHtml(): string {
    return (
      sitePages[selectedStatusCode]?.html ??
      defaults[selectedStatusCode]?.html ??
      ""
    )
  }

  function setCurrentHtml(html: string) {
    setSitePages((prev) => ({
      ...prev,
      [selectedStatusCode]: {
        status_code: Number(selectedStatusCode),
        title: statusLabels[selectedStatusCode] ?? selectedStatusCode,
        html,
        content_type: "text/html",
      },
    }))
  }

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  async function handleSave() {
    if (!selectedSite) return
    const siteId = Number(selectedSite)
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
      toast.success("错误页面已保存")
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "update",
            site_id: siteId,
            payload,
            response: details,
          })
        }
        toast.error(e.message)
        await loadSiteErrorPages(siteId)
      } else {
        toast.error(e instanceof Error ? e.message : "保存错误页面失败")
      }
    } finally {
      setSaving(false)
    }
  }

  async function handlePreview() {
    const html = getCurrentHtml()
    if (!html) {
      toast.error("HTML 内容为空")
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setPreviewing(true)
    try {
      const res = await previewErrorPage(html, Number(selectedStatusCode))
      setPreviewHtml(res.rendered)
      setOperationDetails({
        operation: "preview",
        site_id: Number(selectedSite),
        payload: {
          status_code: Number(selectedStatusCode),
          html,
        },
        response: res,
      })
      if (res.parse_error) toast.warning("模板解析警告: " + res.parse_error)
      if (res.execute_error) toast.warning("模板执行警告: " + res.execute_error)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "预览错误页面失败")
    } finally {
      setPreviewing(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Error Pages"
        title="错误页面管理"
        description="管理系统默认和站点自定义的错误页面模板，支持 Go Template 变量和实时预览。"
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回错误页面操作响应体；请核对 error 字段。
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
          <AlertTitle>最近错误页面操作响应</AlertTitle>
          <AlertDescription>
            后端已返回错误页面操作响应体；请核对 operation、site_id、
            payload 或 response 字段。
          </AlertDescription>
          <CopyableBlock
            label="错误页面操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {/* 默认模板 */}
      <Surface
        title="默认错误页面模板"
        description="系统内置模板，当站点未自定义时使用。"
      >
        {Object.keys(defaults).length === 0 ? (
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5">
            {statusCodes.map((code) => (
              <div
                key={code}
                className={`rounded-lg border p-4 ${statusColors[code] ?? "border-border bg-muted/35"}`}
              >
                <div className="mb-2 flex items-center gap-2">
                  <FileWarning className="size-4" />
                  <span className="text-sm font-semibold">
                    {statusLabels[code]}
                  </span>
                </div>
                <div className="text-xs opacity-60">默认模板</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5">
            {statusCodes.map((code) => {
              const cfg = defaults[code]
              return (
                <div
                  key={code}
                  className={`rounded-xl border p-4 ${statusColors[code] ?? "border-border bg-muted/35"}`}
                >
                  <div className="mb-2 flex items-center gap-2">
                    <FileWarning className="size-4" />
                    <span className="text-sm font-semibold">
                      {cfg?.title ?? statusLabels[code]}
                    </span>
                  </div>
                  <div className="max-h-[100px] overflow-y-auto rounded-md border border-border bg-background p-2 font-mono text-xs text-foreground">
                    {cfg?.html?.slice(0, 200) ?? "无模板"}
                    {(cfg?.html?.length ?? 0) > 200 ? "..." : ""}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Surface>

      {/* 站点自定义编辑 */}
      <Surface
        title="站点自定义错误页面"
        description="选择站点后为各状态码编辑自定义 HTML，支持 Go template 变量。"
        action={
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={handlePreview}
              disabled={previewing || !selectedSite}
            >
              <Eye data-icon="inline-start" />
              {previewing ? "预览中..." : "预览"}
            </Button>
            <Button onClick={handleSave} disabled={saving || !selectedSite}>
              <Save data-icon="inline-start" />
              {saving ? "保存中..." : "保存"}
            </Button>
          </div>
        }
      >
        <Field className="mb-4">
          <FieldLabel htmlFor={selectedSiteId}>站点</FieldLabel>
          <Select value={selectedSite} onValueChange={setSelectedSite}>
            <SelectTrigger id={selectedSiteId} className="w-[300px] rounded-md">
              <SelectValue placeholder="选择站点..." />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {sites.map((s) => (
                  <SelectItem key={s.id} value={String(s.id)}>
                    {s.host} (ID: {s.id})
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <FieldDescription>
            选择站点以编辑该站点覆盖默认模板的错误页面。
          </FieldDescription>
        </Field>

        {!selectedSite ? (
          <EmptyState
            title="请先选择站点"
            description="选择一个站点以编辑其自定义错误页面。"
          />
        ) : (
          <Tabs
            value={selectedStatusCode}
            onValueChange={(v) => {
              setActiveCode(v)
              setPreviewHtml("")
            }}
          >
            <TabsList className="mb-4 rounded-xl border border-border bg-muted/35 p-1 shadow-sm backdrop-blur">
              {statusCodes.map((code) => (
                <TabsTrigger key={code} value={code}>
                  {code}
                </TabsTrigger>
              ))}
            </TabsList>

            {statusCodes.map((code) => (
              <TabsContent key={code} value={code}>
                <div className="grid gap-4 lg:grid-cols-2">
                  <Field>
                    <FieldLabel htmlFor={`${htmlEditorId}-${code}`}>
                      HTML 编辑器 — {statusLabels[code]}
                    </FieldLabel>
                    <Textarea
                      id={`${htmlEditorId}-${code}`}
                      value={code === selectedStatusCode ? getCurrentHtml() : ""}
                      onChange={(e) => setCurrentHtml(e.target.value)}
                      rows={18}
                      className="rounded-md font-mono text-xs"
                      placeholder={`输入 ${code} 错误页面的 HTML 内容...`}
                    />
                    <Alert>
                      <AlertTriangle />
                      <AlertDescription>
                        支持 Go template 变量：{"{{.StatusCode}}"}{" "}
                        {"{{.Message}}"} {"{{.ClientIP}}"} {"{{.RequestID}}"}
                      </AlertDescription>
                    </Alert>
                  </Field>
                  <Field>
                    <FieldTitle>实时预览</FieldTitle>
                    <div className="min-h-[400px] overflow-hidden rounded-xl border border-border bg-background">
                      {previewHtml ? (
                        <iframe
                          srcDoc={previewHtml}
                          className="h-[400px] w-full border-0"
                          sandbox="allow-same-origin"
                          title="错误页面预览"
                        />
                      ) : (
                        <div className="flex h-[400px] items-center justify-center text-sm text-muted-foreground">
                          <div className="flex flex-col items-center gap-2 text-center">
                            <Eye className="size-8 text-muted-foreground/60" />
                            <p>点击「预览」按钮查看渲染效果</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </Field>
                </div>
              </TabsContent>
            ))}
          </Tabs>
        )}
      </Surface>
    </div>
  )
}
