"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import {
  useImageTransformConfig,
  useImageTransformConfigUpdate,
} from "@/hooks/use-api"
import type { ImageTransformConfig } from "@/lib/types"

/**
 * 图像转换全局配置卡片。
 *
 * 对应后端 GET/POST `/api/v1/image-transform`，配置写在 system_settings 的
 * `image_transform` 键下，并在数据面按 URL 查询参数 `image_process=...`
 * 逐请求触发。本组件只负责全局开关与限额；站点级覆盖留待后续。
 *
 * 保存遵循「局部合并」：只提交被改动过的字段（draft 中存在的键），
 * 未展示的字段不会被打成零值。
 *
 * @param props.canManage 是否具备写权限（admin）。
 */
export function ImageTransformCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation()
  const { data, isLoading, error } = useImageTransformConfig(true)
  const update = useImageTransformConfigUpdate()
  const [draft, setDraft] = useState<Partial<ImageTransformConfig>>({})

  const value = <K extends keyof ImageTransformConfig>(key: K) =>
    (draft[key] ?? data?.[key]) as ImageTransformConfig[K] | undefined

  const setValue = <K extends keyof ImageTransformConfig>(
    key: K,
    next: ImageTransformConfig[K]
  ) => {
    setDraft((prev) => ({ ...prev, [key]: next }))
  }

  const dirty = Object.keys(draft).length > 0

  const save = async () => {
    if (!canManage || !dirty) return
    try {
      await update.execute(draft)
      setDraft({})
      toast.success(t("captcha.imageTransform.saveSuccess"))
    } catch {
      toast.error(t("captcha.imageTransform.saveFailed"))
    }
  }

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t("captcha.imageTransform.title")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {t("common.loading")}
          </p>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t("captcha.imageTransform.title")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-destructive">
            {(error as Error).message || t("error.unexpectedError")}
          </p>
        </CardContent>
      </Card>
    )
  }

  const enabled = Boolean(value("enabled"))
  const numericFields = [
    {
      key: "max_pixels" as const,
      label: t("captcha.imageTransform.maxPixels"),
      hint: t("captcha.imageTransform.maxPixelsHint"),
      min: 1,
    },
    {
      key: "max_side" as const,
      label: t("captcha.imageTransform.maxSide"),
      hint: t("captcha.imageTransform.maxSideHint"),
      min: 1,
    },
    {
      key: "max_bytes" as const,
      label: t("captcha.imageTransform.maxBytes"),
      hint: t("captcha.imageTransform.maxBytesHint"),
      min: 1024,
    },
    {
      key: "timeout_ms" as const,
      label: t("captcha.imageTransform.timeoutMs"),
      hint: t("captcha.imageTransform.timeoutMsHint"),
      min: 50,
    },
    {
      key: "concurrency" as const,
      label: t("captcha.imageTransform.concurrency"),
      hint: t("captcha.imageTransform.concurrencyHint"),
      min: 0,
    },
    {
      key: "default_quality" as const,
      label: t("captcha.imageTransform.defaultQuality"),
      hint: t("captcha.imageTransform.defaultQualityHint"),
      min: 0,
    },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t("captcha.imageTransform.title")}
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          {t("captcha.imageTransform.description")}
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-start justify-between gap-4 rounded-xl border border-border/70 bg-muted/20 p-4">
          <div className="min-w-0 space-y-1">
            <Label htmlFor="image_transform_enabled" className="text-sm font-medium">
              {t("captcha.imageTransform.enabled")}
            </Label>
            <p className="text-xs leading-5 text-muted-foreground">
              {t("captcha.imageTransform.enabledHint")}
            </p>
          </div>
          <Switch
            id="image_transform_enabled"
            checked={enabled}
            disabled={!canManage}
            onCheckedChange={(checked) => setValue("enabled", checked)}
          />
        </div>

        <div
          className={
            enabled ? "space-y-4" : "space-y-4 opacity-50 pointer-events-none"
          }
        >
          <div className="flex items-start justify-between gap-4 rounded-xl border border-border/70 bg-muted/20 p-4">
            <div className="min-w-0 space-y-1">
              <Label
                htmlFor="adaptive_webp"
                className="text-sm font-medium"
              >
                {t("captcha.imageTransform.adaptiveWebp")}
              </Label>
              <p className="text-xs leading-5 text-muted-foreground">
                {t("captcha.imageTransform.adaptiveWebpHint")}
              </p>
            </div>
            <Switch
              id="adaptive_webp"
              checked={Boolean(value("adaptive_webp"))}
              disabled={!canManage || !enabled}
              onCheckedChange={(checked) => setValue("adaptive_webp", checked)}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            {numericFields.map((field) => (
              <div key={field.key} className="space-y-2">
                <Label htmlFor={`image_transform_${field.key}`}>
                  {field.label}
                </Label>
                <Input
                  id={`image_transform_${field.key}`}
                  type="number"
                  min={field.min}
                  disabled={!canManage || !enabled}
                  value={String(value(field.key) ?? 0)}
                  onChange={(event) => {
                    const parsed = Number.parseInt(event.target.value, 10)
                    setValue(field.key, Number.isNaN(parsed) ? 0 : parsed)
                  }}
                />
                <p className="text-xs leading-5 text-muted-foreground">
                  {field.hint}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-end gap-2">
          <Button
            type="button"
            variant="ghost"
            disabled={!canManage || !dirty}
            onClick={() => setDraft({})}
          >
            {t("common.cancel")}
          </Button>
          <Button
            type="button"
            disabled={!canManage || !dirty || update.loading}
            onClick={save}
          >
            {update.loading ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}