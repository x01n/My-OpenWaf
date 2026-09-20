"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Skeleton } from "@/components/ui/skeleton"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { toast } from "sonner"
import { IconDeviceFloppy, IconRefresh, IconEye } from "@tabler/icons-react"
import { pageTemplateApi } from "@/lib/api"
import {
  usePageTemplate,
  usePageTemplateUpdate,
  usePageTemplateReset,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"

const TEMPLATE_TYPES = ["captcha", "challenge", "block"] as const
type TemplateType = (typeof TEMPLATE_TYPES)[number]

function TemplateEditor({ type }: { type: TemplateType }) {
  const { t } = useTranslation()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const { data, isLoading, error, mutate } = usePageTemplate(type)
  const updateTemplate = usePageTemplateUpdate()
  const resetTemplate = usePageTemplateReset()

  // 草稿为空时直接使用 SWR 数据，避免通过 effect 同步状态造成级联渲染。
  // 一旦用户编辑才创建独立副本，后台重验证不会覆盖草稿。
  const [draft, setDraft] = useState<Record<string, string> | null>(null)
  const form = draft ?? (data as Record<string, string> | undefined) ?? {}
  const dirty = draft !== null
  const [showPreview, setShowPreview] = useState(false)
  const [previewHtml, setPreviewHtml] = useState("")
  const [previewLoading, setPreviewLoading] = useState(false)

  const previewDocument = useMemo(() => {
    if (!previewHtml) return ""
    return `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:;"></head><body>${previewHtml}</body></html>`
  }, [previewHtml])

  const setField = (key: string, value: string) => {
    if (!canManage) return
    setDraft((prev) => ({ ...(prev ?? form), [key]: value }))
  }

  const handleSave = async () => {
    if (!canManage) return
    try {
      await updateTemplate.execute({ type, data: form })
      setDraft(null)
      toast.success(t("pageTemplates.saved"))
      await mutate().catch(() => {
        toast.error(t("pageTemplates.refreshFailed"))
      })
    } catch {
      toast.error(t("pageTemplates.saveFailed"))
    }
  }

  const handleReset = async () => {
    if (!canManage) return
    try {
      await resetTemplate.execute(type)
      setDraft(null)
      toast.success(t("pageTemplates.resetSuccess"))
      await mutate().catch(() => {
        toast.error(t("pageTemplates.refreshFailed"))
      })
    } catch {
      toast.error(t("pageTemplates.resetFailed"))
    }
  }

  const handlePreview = async () => {
    if (!canManage) return
    const next = !showPreview
    setShowPreview(next)
    if (!next) return
    setPreviewLoading(true)
    try {
      const html = await pageTemplateApi.previewDraft(type, form)
      setPreviewHtml(typeof html === "string" ? html : String(html ?? ""))
    } catch {
      setPreviewHtml("")
      toast.error(t("pageTemplates.previewFailed"))
    } finally {
      setPreviewLoading(false)
    }
  }

  const extraFields: { key: string; label: string }[] = []
  if (type === "captcha") {
    extraFields.push(
      { key: "subtitle", label: t("pageTemplates.subtitle") },
      { key: "subtitle_zh", label: t("pageTemplates.subtitleZh") },
      { key: "submit_text", label: t("pageTemplates.submitText") }
    )
  } else if (type === "challenge") {
    extraFields.push(
      { key: "checking_text", label: t("pageTemplates.checkingText") },
      { key: "checking_text_zh", label: t("pageTemplates.checkingTextZh") },
      { key: "wait_text", label: t("pageTemplates.waitText") },
      { key: "wait_text_zh", label: t("pageTemplates.waitTextZh") }
    )
  } else if (type === "block") {
    extraFields.push(
      { key: "block_title", label: t("pageTemplates.blockTitle") },
      { key: "block_message", label: t("pageTemplates.blockMessage") },
      { key: "rate_limit_title", label: t("pageTemplates.rateLimitTitle") },
      { key: "rate_limit_message", label: t("pageTemplates.rateLimitMsg") }
    )
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    )
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
        <AlertDescription>
          {(error as Error)?.message || t("error.unexpectedError")}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className="min-w-0 space-y-6">
      {!authLoading && !canManage && (
        <Alert>
          <AlertTitle>{t("common.readOnlyHint")}</AlertTitle>
          <AlertDescription>{t("pageTemplates.readOnlyHint")}</AlertDescription>
        </Alert>
      )}
      <fieldset
        disabled={!canManage}
        className="m-0 min-w-0 space-y-6 border-0 p-0"
      >
        <div className="grid min-w-0 gap-4 md:grid-cols-2">
          <div className="min-w-0 space-y-1">
            <Label>{t("pageTemplates.brandName")}</Label>
            <Input
              className="min-w-0"
              value={form.brand_name || ""}
              onChange={(e) => setField("brand_name", e.target.value)}
            />
          </div>
          <div className="min-w-0 space-y-1">
            <Label>{t("pageTemplates.primaryColor")}</Label>
            <div className="flex gap-2">
              <Input
                className="min-w-0"
                value={form.primary_color || ""}
                onChange={(e) => setField("primary_color", e.target.value)}
              />
              <input
                aria-label={t("pageTemplates.primaryColor")}
                type="color"
                value={form.primary_color || "#14b8a6"}
                onChange={(e) => setField("primary_color", e.target.value)}
                className="h-9 w-9 cursor-pointer rounded border"
              />
            </div>
          </div>
          <div className="min-w-0 space-y-1">
            <Label>{t("pageTemplates.bgGradient")}</Label>
            <Input
              className="min-w-0"
              value={form.bg_gradient || ""}
              onChange={(e) => setField("bg_gradient", e.target.value)}
            />
          </div>
          <div className="min-w-0 space-y-1">
            <Label>{t("pageTemplates.logoUrl")}</Label>
            <Input
              className="min-w-0"
              value={form.logo_url || ""}
              onChange={(e) => setField("logo_url", e.target.value)}
            />
          </div>
          <div className="min-w-0 space-y-1">
            <Label>{t("pageTemplates.pageTitle")}</Label>
            <Input
              className="min-w-0"
              value={form.title || ""}
              onChange={(e) => setField("title", e.target.value)}
            />
          </div>
          <div className="min-w-0 space-y-1">
            <Label>{t("pageTemplates.footerText")}</Label>
            <Input
              className="min-w-0"
              value={form.footer_text || ""}
              onChange={(e) => setField("footer_text", e.target.value)}
            />
          </div>
          {extraFields.map((f) => (
            <div key={f.key} className="min-w-0 space-y-1">
              <Label>{f.label}</Label>
              <Input
                className="min-w-0"
                value={form[f.key] || ""}
                onChange={(e) => setField(f.key, e.target.value)}
              />
            </div>
          ))}
          <div className="min-w-0 space-y-1 md:col-span-2">
            <Label>{t("pageTemplates.customCss")}</Label>
            <Textarea
              rows={6}
              wrap="soft"
              value={form.custom_css || ""}
              onChange={(e) => setField("custom_css", e.target.value)}
              className="min-h-32 max-w-full min-w-0 font-mono text-sm"
            />
          </div>
        </div>

        <div className="flex min-w-0 flex-wrap gap-2">
          <Button
            onClick={handleSave}
            disabled={updateTemplate.loading || !dirty}
          >
            <IconDeviceFloppy className="mr-1 h-4 w-4" />
            {t("pageTemplates.save")}
          </Button>
          <Button
            variant="outline"
            onClick={handlePreview}
            disabled={previewLoading}
          >
            <IconEye className="mr-1 h-4 w-4" />
            {t("pageTemplates.preview")}
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive">
                <IconRefresh className="mr-1 h-4 w-4" />
                {t("pageTemplates.reset")}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  {t("pageTemplates.resetConfirm")}
                </AlertDialogTitle>
                <AlertDialogDescription>
                  {t("pageTemplates.resetConfirmDesc")}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
                <AlertDialogAction onClick={handleReset}>
                  {t("common.confirm")}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>

        {showPreview && (
          <div className="mt-4 overflow-hidden rounded-lg border">
            {previewLoading ? (
              <Skeleton className="h-[500px] w-full" />
            ) : (
              <iframe
                srcDoc={previewDocument}
                className="block h-[500px] w-full max-w-full"
                sandbox=""
                referrerPolicy="no-referrer"
                title="Template Preview"
              />
            )}
          </div>
        )}
      </fieldset>
    </div>
  )
}

export default function PageTemplatesPage() {
  const { t } = useTranslation()

  return (
    <div className="min-w-0 space-y-6">
      <PageHeader
        title={t("pageTemplates.title")}
        description={t("pageTemplates.description")}
      />

      <Tabs defaultValue="captcha" className="min-w-0">
        <TabsList className="max-w-full justify-start overflow-x-auto">
          {TEMPLATE_TYPES.map((type) => (
            <TabsTrigger key={type} value={type} className="shrink-0">
              {t(`pageTemplates.${type}`)}
            </TabsTrigger>
          ))}
        </TabsList>
        {TEMPLATE_TYPES.map((type) => (
          <TabsContent key={type} value={type} className="min-w-0">
            <Card className="min-w-0">
              <CardHeader>
                <CardTitle>{t(`pageTemplates.${type}`)}</CardTitle>
                <CardDescription>
                  {t("pageTemplates.description")}
                </CardDescription>
              </CardHeader>
              <CardContent className="min-w-0">
                <TemplateEditor type={type} />
              </CardContent>
            </Card>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  )
}
