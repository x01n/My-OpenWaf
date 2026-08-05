"use client"

import { useState, useMemo, useCallback } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { toast } from "sonner"
import { IconShield, IconRefresh, IconHelpCircle } from "@tabler/icons-react"
import { useBotSettings, useBotSettingsUpdate } from "@/hooks/use-api"
import { cn } from "@/lib/utils"

/**
 * 动态防护子选项
 */
interface DynamicOption {
  key: string
  label: string
  description?: string
  recommended?: boolean
}

export default function CaptchaPage() {
  const { t } = useTranslation()
  const { data: botSettings, isLoading, error, mutate } = useBotSettings()
  const updateBot = useBotSettingsUpdate()

  const [localSettings, setLocalSettings] = useState<Record<string, unknown>>(
    {}
  )

  const getValue = useCallback(
    (key: string, defaultValue: unknown = false) => {
      return localSettings[key] !== undefined
        ? localSettings[key]
        : (botSettings?.[key] ?? defaultValue)
    },
    [localSettings, botSettings]
  )

  const handleToggle = useCallback(
    (key: string) => {
      setLocalSettings((prev) => ({ ...prev, [key]: !getValue(key) }))
    },
    [getValue]
  )

  const handleSubToggle = useCallback(
    (key: string) => {
      setLocalSettings((prev) => ({ ...prev, [key]: !getValue(key) }))
    },
    [getValue]
  )

  const handleValue = useCallback((key: string, value: string | number) => {
    setLocalSettings((prev) => ({ ...prev, [key]: value }))
  }, [])

  const hasChanges = useMemo(() => {
    return Object.keys(localSettings).length > 0
  }, [localSettings])

  const handleSave = useCallback(async () => {
    try {
      await updateBot.execute({ ...botSettings, ...localSettings })
      toast.success(t("captcha.saveSuccess"))
      setLocalSettings({})
      mutate()
    } catch {
      toast.error(t("captcha.saveFailed"))
    }
  }, [botSettings, localSettings, updateBot, mutate, t])

  const handleCancel = useCallback(() => {
    setLocalSettings({})
    toast.info(t("attacks.cancelled"))
  }, [t])

  const dynamicProtectionEnabled = getValue("dynamic_protection_enabled", false)

  const dynamicOptions: DynamicOption[] = [
    {
      key: "html_obfuscation",
      label: t("captcha.htmlObfuscation"),
      description: t("captcha.htmlObfuscationDesc"),
      recommended: true,
    },
    {
      key: "js_obfuscation",
      label: t("captcha.jsObfuscation"),
      description: t("captcha.performanceWarning"),
    },
    {
      key: "image_watermark",
      label: t("captcha.imageWatermark"),
      description: t("captcha.performanceWarning"),
    },
  ]

  if (isLoading) {
    return (
      <div className="mx-auto max-w-5xl space-y-6">
        <PageHeader
          title={t("captcha.botProtection")}
          description={t("captcha.description")}
        />
        <Skeleton className="h-96 w-full" />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      {/* 页面标题 */}
      <PageHeader
        title={t("captcha.botProtection")}
        description={t("captcha.description")}
      />

      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {error.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}

      <Card className="overflow-hidden">
        <CardContent className="space-y-8 p-6">
          {/* 人机验证 */}
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-5 w-1 rounded-full bg-primary" />
              <span className="text-sm font-medium">
                {t("captcha.section.captcha")}
              </span>
              <Switch
                checked={getValue("captcha_enabled", false)}
                onCheckedChange={() => handleToggle("captcha_enabled")}
                id="captcha_enabled"
              />
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <IconHelpCircle className="h-3.5 w-3.5" />
                <span>{t("captcha.enableCaptchaDesc")}</span>
                <span className="cursor-pointer text-primary hover:underline">
                  {t("captcha.link")}
                </span>
              </div>
            </div>
          </div>

          {/* 动态防护 */}
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-5 w-1 rounded-full bg-primary" />
              <span className="text-sm font-medium">
                {t("captcha.section.dynamicProtection")}
              </span>
              <Switch
                checked={dynamicProtectionEnabled}
                onCheckedChange={() =>
                  handleToggle("dynamic_protection_enabled")
                }
                id="dynamic_protection_enabled"
              />
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <IconHelpCircle className="h-3.5 w-3.5" />
                <span>{t("captcha.enableDynamicProtectionDesc")}</span>
                <span className="cursor-pointer text-primary hover:underline">
                  {t("captcha.link")}
                </span>
              </div>
            </div>

            {/* 动态防护子选项 */}
            <div
              className={cn(
                "ml-4 space-y-3 rounded-lg border p-4 transition-all",
                dynamicProtectionEnabled
                  ? "opacity-100"
                  : "pointer-events-none opacity-40"
              )}
            >
              {dynamicOptions.map((option) => (
                <div key={option.key} className="flex items-start gap-3">
                  <Checkbox
                    id={option.key}
                    checked={getValue(option.key, false)}
                    onCheckedChange={() => handleSubToggle(option.key)}
                    disabled={!dynamicProtectionEnabled}
                  />
                  <div className="flex flex-col gap-0.5">
                    <div className="flex items-center gap-2">
                      <Label
                        htmlFor={option.key}
                        className={cn(
                          "cursor-pointer text-sm font-normal",
                          !dynamicProtectionEnabled && "cursor-not-allowed"
                        )}
                      >
                        {option.label}
                      </Label>
                      {option.recommended && (
                        <span className="inline-flex items-center rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                          {t("captcha.recommended")}
                        </span>
                      )}
                    </div>
                    {option.description && (
                      <p className="text-xs text-muted-foreground">
                        {option.description}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* 请求防重放 */}
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-5 w-1 rounded-full bg-primary" />
              <span className="text-sm font-medium">
                {t("captcha.section.antiReplay")}
              </span>
              <Switch
                checked={getValue("anti_replay_enabled", false)}
                onCheckedChange={() => handleToggle("anti_replay_enabled")}
                id="anti_replay_enabled"
              />
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <IconHelpCircle className="h-3.5 w-3.5" />
                <span>{t("captcha.enableAntiReplayDesc")}</span>
                <span className="cursor-pointer text-primary hover:underline">
                  {t("captcha.link")}
                </span>
              </div>
            </div>
          </div>

          {/* 浏览器签名校验 */}
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-5 w-1 rounded-full bg-primary" />
              <span className="text-sm font-medium">
                {t("captcha.section.browserSign")}
              </span>
              <Switch
                checked={getValue("browser_sign_enabled", false)}
                onCheckedChange={() => handleToggle("browser_sign_enabled")}
                id="browser_sign_enabled"
              />
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <IconHelpCircle className="h-3.5 w-3.5" />
                <span>{t("captcha.enableBrowserSignDesc")}</span>
                <span className="cursor-pointer text-primary hover:underline">
                  {t("captcha.link")}
                </span>
              </div>
            </div>

            <div
              className={cn(
                "ml-4 grid gap-4 rounded-lg border p-4 transition-all sm:grid-cols-2",
                getValue("browser_sign_enabled", false)
                  ? "opacity-100"
                  : "pointer-events-none opacity-40"
              )}
            >
              <div className="space-y-1.5">
                <Label htmlFor="browser_sign_ttl">
                  {t("captcha.browserSignTtl")}
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="browser_sign_ttl"
                    type="number"
                    min={30}
                    max={3600}
                    disabled={!getValue("browser_sign_enabled", false)}
                    value={getValue("browser_sign_ttl", 300)}
                    onChange={(e) => {
                      const n = Number(e.target.value)
                      handleValue(
                        "browser_sign_ttl",
                        Number.isFinite(n) && n > 0 ? n : 300
                      )
                    }}
                  />
                  <span className="text-sm text-muted-foreground">
                    {t("captcha.browserSignTtlUnit")}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t("captcha.browserSignTtlDesc")}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="browser_sign_action">
                  {t("captcha.browserSignAction")}
                </Label>
                <Select
                  value={getValue("browser_sign_action", "challenge")}
                  onValueChange={(v) => handleValue("browser_sign_action", v)}
                  disabled={!getValue("browser_sign_enabled", false)}
                >
                  <SelectTrigger id="browser_sign_action">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="observe">
                      {t("captcha.browserSignActionObserve")}
                    </SelectItem>
                    <SelectItem value="challenge">
                      {t("captcha.browserSignActionChallenge")}
                    </SelectItem>
                    <SelectItem value="intercept">
                      {t("captcha.browserSignActionIntercept")}
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {t("captcha.browserSignActionDesc")}
                </p>
              </div>
            </div>
          </div>
        </CardContent>

        {/* 底部操作栏 */}
        <div className="flex items-center justify-end gap-3 border-t px-6 py-4">
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={!hasChanges || updateBot.loading}
          >
            {t("captcha.cancel")}
          </Button>
          <Button
            onClick={handleSave}
            disabled={!hasChanges || updateBot.loading}
          >
            {updateBot.loading ? (
              <>
                <IconRefresh className="mr-2 h-4 w-4 animate-spin" />
                {t("common.saving")}
              </>
            ) : (
              <>
                <IconShield className="mr-2 h-4 w-4" />
                {t("captcha.save")}
              </>
            )}
          </Button>
        </div>
      </Card>
    </div>
  )
}
