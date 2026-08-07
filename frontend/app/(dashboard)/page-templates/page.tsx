"use client"

import { useState } from "react"
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

const TEMPLATE_TYPES = ["captcha", "challenge", "block"] as const
type TemplateType = (typeof TEMPLATE_TYPES)[number]

function TemplateEditor({ type }: { type: TemplateType }) {
  const { t } = useTranslation()
  const { data, isLoading, error, mutate } = usePageTemplate(type)
  const updateTemplate = usePageTemplateUpdate()
  const resetTemplate = usePageTemplateReset()

  const [prevData, setPrevData] = useState(data)
  const [form, setForm] = useState<Record<string, string>>(
    data ? (data as Record<string, string>) : {}
  )
  const [showPreview, setShowPreview] = useState(false)
  const [previewHtml, setPreviewHtml] = useState("")
  const [previewLoading, setPreviewLoading] = useState(false)

  if (data !== prevData) {
    setPrevData(data)
    if (data) setForm(data as Record<string, string>)
  }

  const setField = (key: string, value: string) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const handleSave = async () => {
    try {
      await updateTemplate.execute({ type, data: form })
      await mutate()
      toast.success(t("pageTemplates.saved"))
    } catch {
      toast.error(t("pageTemplates.saveFailed"))
    }
  }

  const handleReset = async () => {
    try {
      await resetTemplate.execute(type)
      await mutate()
      toast.success(t("pageTemplates.resetSuccess"))
    } catch {
      toast.error(t("pageTemplates.resetFailed"))
    }
  }

  const handlePreview = async () => {
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
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-1">
          <Label>{t("pageTemplates.brandName")}</Label>
          <Input
            value={form.brand_name || ""}
            onChange={(e) => setField("brand_name", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.primaryColor")}</Label>
          <div className="flex gap-2">
            <Input
              value={form.primary_color || ""}
              onChange={(e) => setField("primary_color", e.target.value)}
            />
            <input
              type="color"
              value={form.primary_color || "#14b8a6"}
              onChange={(e) => setField("primary_color", e.target.value)}
              className="h-9 w-9 cursor-pointer rounded border"
            />
          </div>
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.bgGradient")}</Label>
          <Input
            value={form.bg_gradient || ""}
            onChange={(e) => setField("bg_gradient", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.logoUrl")}</Label>
          <Input
            value={form.logo_url || ""}
            onChange={(e) => setField("logo_url", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.pageTitle")}</Label>
          <Input
            value={form.title || ""}
            onChange={(e) => setField("title", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.footerText")}</Label>
          <Input
            value={form.footer_text || ""}
            onChange={(e) => setField("footer_text", e.target.value)}
          />
        </div>
        {extraFields.map((f) => (
          <div key={f.key} className="space-y-1">
            <Label>{f.label}</Label>
            <Input
              value={form[f.key] || ""}
              onChange={(e) => setField(f.key, e.target.value)}
            />
          </div>
        ))}
        <div className="space-y-1 md:col-span-2">
          <Label>{t("pageTemplates.customCss")}</Label>
          <Textarea
            rows={4}
            value={form.custom_css || ""}
            onChange={(e) => setField("custom_css", e.target.value)}
            className="font-mono text-sm"
          />
        </div>
      </div>

      <div className="flex gap-2">
        <Button onClick={handleSave} disabled={updateTemplate.loading}>
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
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={handleReset}>
                Confirm
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
              srcDoc={previewHtml}
              className="h-[500px] w-full"
              sandbox="allow-same-origin"
              title="Template Preview"
            />
          )}
        </div>
      )}
    </div>
  )
}

export default function PageTemplatesPage() {
  const { t } = useTranslation()

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("pageTemplates.title")}
        description={t("pageTemplates.description")}
      />

      <Tabs defaultValue="captcha">
        <TabsList>
          {TEMPLATE_TYPES.map((type) => (
            <TabsTrigger key={type} value={type}>
              {t(`pageTemplates.${type}`)}
            </TabsTrigger>
          ))}
        </TabsList>
        {TEMPLATE_TYPES.map((type) => (
          <TabsContent key={type} value={type}>
            <Card>
              <CardHeader>
                <CardTitle>{t(`pageTemplates.${type}`)}</CardTitle>
                <CardDescription>
                  {t("pageTemplates.description")}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <TemplateEditor type={type} />
              </CardContent>
            </Card>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  )
}
