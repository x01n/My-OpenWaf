"use client"

import { useEffect, useState } from "react"
import { FileWarning, Eye, Save, AlertTriangle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { PageIntro, Surface, EmptyState } from "@/components/console-shell"
import { listSites, type Site } from "@/lib/api"
import {
  getDefaultErrorPages,
  getSiteErrorPages,
  updateSiteErrorPages,
  previewErrorPage,
  type ErrorPageConfig,
} from "@/lib/rules-api"

const statusCodes = ["403", "429", "502", "503", "504"] as const
const statusLabels: Record<string, string> = {
  "403": "403 Forbidden",
  "429": "429 Too Many Requests",
  "502": "502 Bad Gateway",
  "503": "503 Service Unavailable",
  "504": "504 Gateway Timeout",
}

const statusColors: Record<string, string> = {
  "403": "border-rose-200 bg-rose-50 text-rose-700",
  "429": "border-amber-200 bg-amber-50 text-amber-700",
  "502": "border-orange-200 bg-orange-50 text-orange-700",
  "503": "border-purple-200 bg-purple-50 text-purple-700",
  "504": "border-slate-200 bg-slate-50 text-slate-700",
}

export default function ErrorPagesPage() {
  const [defaults, setDefaults] = useState<Record<string, ErrorPageConfig>>({})
  const [sites, setSites] = useState<Site[]>([])
  const [selectedSite, setSelectedSite] = useState<string>("")
  const [activeCode, setActiveCode] = useState("403")
  const [sitePages, setSitePages] = useState<Record<string, ErrorPageConfig>>(
    {}
  )
  const [previewHtml, setPreviewHtml] = useState("")
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getDefaultErrorPages()
      .then((res) => setDefaults(res.defaults ?? {}))
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载默认错误页失败")
      )
    listSites()
      .then((res) => {
        const list = res.items ?? []
        setSites(list)
        if (list.length > 0) setSelectedSite(String(list[0].id))
      })
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载站点列表失败")
      )
  }, [])

  useEffect(() => {
    if (!selectedSite) return
    setPreviewHtml("")
    getSiteErrorPages(Number(selectedSite))
      .then((res) => setSitePages(res.error_pages ?? {}))
      .catch((e) => {
        toast.error(e instanceof Error ? e.message : "加载站点错误页失败")
        setSitePages({})
      })
  }, [selectedSite])

  function getCurrentHtml(): string {
    return sitePages[activeCode]?.html ?? defaults[activeCode]?.html ?? ""
  }

  function setCurrentHtml(html: string) {
    setSitePages((prev) => ({
      ...prev,
      [activeCode]: {
        status_code: Number(activeCode),
        title: statusLabels[activeCode] ?? activeCode,
        html,
        content_type: "text/html",
      },
    }))
  }

  async function handleSave() {
    if (!selectedSite) return
    setSaving(true)
    try {
      await updateSiteErrorPages(Number(selectedSite), sitePages)
      toast.success("错误页面已保存")
    } catch (e) {
      toast.error(String(e))
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
    try {
      const res = await previewErrorPage(html, Number(activeCode))
      setPreviewHtml(res.rendered)
      if (res.parse_error) toast.warning("模板解析警告: " + res.parse_error)
      if (res.execute_error) toast.warning("模板执行警告: " + res.execute_error)
    } catch (e) {
      toast.error(String(e))
    }
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Error Pages"
        title="错误页面管理"
        description="管理系统默认和站点自定义的错误页面模板，支持 Go Template 变量和实时预览。"
      />

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
                className={`rounded-lg border p-4 ${statusColors[code] ?? "border-slate-200 bg-slate-50"}`}
              >
                <div className="mb-2 flex items-center gap-2">
                  <FileWarning className="h-4 w-4" />
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
                  className={`rounded-xl border p-4 ${statusColors[code] ?? "border-slate-200 bg-slate-50"}`}
                >
                  <div className="mb-2 flex items-center gap-2">
                    <FileWarning className="h-4 w-4" />
                    <span className="text-sm font-semibold">
                      {cfg?.title ?? statusLabels[code]}
                    </span>
                  </div>
                  <div className="max-h-[100px] overflow-y-auto rounded-md border border-slate-200 bg-white p-2 font-mono text-xs">
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
              className="gap-2 rounded-md"
            >
              <Eye className="h-4 w-4" />
              预览
            </Button>
            <Button
              onClick={handleSave}
              disabled={saving || !selectedSite}
              className="gap-2"
            >
              <Save className="h-4 w-4" />
              {saving ? "保存中..." : "保存"}
            </Button>
          </div>
        }
      >
        <div className="mb-4">
          <Select value={selectedSite} onValueChange={setSelectedSite}>
            <SelectTrigger className="w-[300px] rounded-md">
              <SelectValue placeholder="选择站点..." />
            </SelectTrigger>
            <SelectContent>
              {sites.map((s) => (
                <SelectItem key={s.id} value={String(s.id)}>
                  {s.host} (ID: {s.id})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {!selectedSite ? (
          <EmptyState
            title="请先选择站点"
            description="选择一个站点以编辑其自定义错误页面。"
          />
        ) : (
          <Tabs
            value={activeCode}
            onValueChange={(v) => {
              setActiveCode(v)
              setPreviewHtml("")
            }}
          >
            <TabsList className="mb-4 rounded-xl border border-slate-200/80 bg-white/90 p-1 shadow-sm backdrop-blur">
              {statusCodes.map((code) => (
                <TabsTrigger key={code} value={code}>
                  {code}
                </TabsTrigger>
              ))}
            </TabsList>

            {statusCodes.map((code) => (
              <TabsContent key={code} value={code}>
                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700">
                      HTML 编辑器 — {statusLabels[code]}
                    </label>
                    <Textarea
                      value={code === activeCode ? getCurrentHtml() : ""}
                      onChange={(e) => setCurrentHtml(e.target.value)}
                      rows={18}
                      className="rounded-md font-mono text-xs"
                      placeholder={`输入 ${code} 错误页面的 HTML 内容...`}
                    />
                    <div className="flex items-start gap-2 rounded-xl border border-slate-200/80 bg-slate-50/80 px-3 py-2 text-xs text-slate-700">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>
                        支持 Go template 变量：{"{{.StatusCode}}"}{" "}
                        {"{{.Message}}"} {"{{.ClientIP}}"} {"{{.RequestID}}"}
                      </span>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700">
                      实时预览
                    </label>
                    <div className="min-h-[400px] overflow-hidden rounded-xl border border-slate-200/80 bg-white/95">
                      {previewHtml ? (
                        <iframe
                          srcDoc={previewHtml}
                          className="h-[400px] w-full border-0"
                          sandbox="allow-same-origin"
                          title="错误页面预览"
                        />
                      ) : (
                        <div className="flex h-[400px] items-center justify-center text-sm text-slate-400">
                          <div className="space-y-2 text-center">
                            <Eye className="mx-auto h-8 w-8 text-slate-300" />
                            <p>点击「预览」按钮查看渲染效果</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </TabsContent>
            ))}
          </Tabs>
        )}
      </Surface>
    </div>
  )
}
