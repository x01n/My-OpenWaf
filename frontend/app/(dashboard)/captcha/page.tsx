"use client"

import { useCallback, useMemo, useState, type ReactNode } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { toast } from "sonner"
import { IconHelpCircle, IconRefresh, IconShield } from "@tabler/icons-react"
import {
  useBotSettings,
  useBotSettingsUpdate,
  useCaptchaConfig,
  useCaptchaConfigUpdate,
  useCaptchaTest,
} from "@/hooks/use-api"
import type {
  BotSettings,
  CaptchaConfig,
  CaptchaConfigPatch,
  CaptchaTestResponse,
} from "@/lib/types"
import { cn } from "@/lib/utils"

/** BotSettings 中由本页维护的局部字段。 */
type BotEditableKey =
  | "dynamic_protection_enabled"
  | "html_obfuscation"
  | "js_obfuscation"
  | "image_watermark"
  | "anti_replay_enabled"
  | "browser_sign_enabled"
  | "browser_sign_ttl"
  | "browser_sign_action"

type BotLocalSettings = Partial<Pick<BotSettings, BotEditableKey>>

type NumberFieldProps = {
  id: string
  label: string
  description: string
  value: number
  onChange: (value: number) => void
  min?: number
  max?: number
  step?: number
  unit?: string
  disabled?: boolean
}

function NumberField({
  id,
  label,
  description,
  value,
  onChange,
  min,
  max,
  step = 1,
  unit,
  disabled = false,
}: NumberFieldProps) {
  const descriptionId = `${id}-description`
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex items-center gap-2">
        <Input
          id={id}
          type="number"
          value={value}
          min={min}
          max={max}
          step={step}
          disabled={disabled}
          aria-describedby={descriptionId}
          onChange={(event) => {
            const next = Number(event.target.value)
            if (Number.isFinite(next)) onChange(next)
          }}
        />
        {unit ? (
          <span className="shrink-0 text-sm text-muted-foreground">{unit}</span>
        ) : null}
      </div>
      <p id={descriptionId} className="text-xs leading-5 text-muted-foreground">
        {description}
      </p>
    </div>
  )
}

type SettingSwitchProps = {
  id: string
  label: string
  description: string
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  disabled?: boolean
  badge?: string
}

function SettingSwitch({
  id,
  label,
  description,
  checked,
  onCheckedChange,
  disabled = false,
  badge,
}: SettingSwitchProps) {
  const descriptionId = `${id}-description`
  return (
    <div className="flex items-start justify-between gap-4 rounded-xl border border-border/70 bg-muted/20 p-4">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <Label
            htmlFor={id}
            className={cn(
              "cursor-pointer text-sm font-medium",
              disabled && "cursor-not-allowed"
            )}
          >
            {label}
          </Label>
          {badge ? <Badge variant="secondary">{badge}</Badge> : null}
        </div>
        <p
          id={descriptionId}
          className="text-xs leading-5 text-muted-foreground"
        >
          {description}
        </p>
      </div>
      <Switch
        id={id}
        checked={checked}
        disabled={disabled}
        aria-describedby={descriptionId}
        onCheckedChange={onCheckedChange}
      />
    </div>
  )
}

type SectionHeadingProps = {
  title: string
  description: string
  help: string
}

function SectionHeading({ title, description, help }: SectionHeadingProps) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="space-y-1">
        <h2 className="text-base font-semibold tracking-tight">{title}</h2>
        <p className="text-sm leading-6 text-muted-foreground">{description}</p>
      </div>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            className="inline-flex size-8 shrink-0 cursor-pointer items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/40 focus-visible:outline-none"
            aria-label={help}
          >
            <IconHelpCircle className="size-4" aria-hidden="true" />
          </button>
        </TooltipTrigger>
        <TooltipContent>{help}</TooltipContent>
      </Tooltip>
    </div>
  )
}

function PreviewValue({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-lg border border-border/60 bg-muted/20 p-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 text-sm font-medium break-words text-foreground">
        {value}
      </dd>
    </div>
  )
}

export default function CaptchaPage() {
  const { t } = useTranslation()
  const {
    data: botSettings,
    isLoading: botIsLoading,
    error: botError,
    mutate: mutateBot,
  } = useBotSettings()
  const updateBot = useBotSettingsUpdate()
  const {
    data: captchaConfig,
    isLoading: captchaIsLoading,
    error: captchaError,
    mutate: mutateCaptcha,
  } = useCaptchaConfig()
  const updateCaptcha = useCaptchaConfigUpdate()
  const captchaTest = useCaptchaTest()

  const [botLocalSettings, setBotLocalSettings] = useState<BotLocalSettings>({})
  const [captchaLocalSettings, setCaptchaLocalSettings] =
    useState<CaptchaConfigPatch>({})
  const [preview, setPreview] = useState<CaptchaTestResponse | null>(null)

  const getBotValue = useCallback(
    <K extends BotEditableKey>(
      key: K,
      defaultValue: NonNullable<BotSettings[K]>
    ): NonNullable<BotSettings[K]> => {
      const localValue = botLocalSettings[key]
      if (localValue !== undefined)
        return localValue as NonNullable<BotSettings[K]>
      const serverValue = botSettings?.[key]
      return (serverValue ?? defaultValue) as NonNullable<BotSettings[K]>
    },
    [botLocalSettings, botSettings]
  )

  const getCaptchaValue = useCallback(
    <K extends keyof CaptchaConfig>(
      key: K,
      defaultValue: CaptchaConfig[K]
    ): CaptchaConfig[K] => {
      const localValue = captchaLocalSettings[key]
      if (localValue !== undefined) return localValue as CaptchaConfig[K]
      return (captchaConfig?.[key] ?? defaultValue) as CaptchaConfig[K]
    },
    [captchaConfig, captchaLocalSettings]
  )

  const setBotValue = useCallback(
    <K extends BotEditableKey>(key: K, value: BotSettings[K]) => {
      setBotLocalSettings((previous) => ({ ...previous, [key]: value }))
    },
    []
  )

  const setCaptchaValue = useCallback(
    <K extends keyof CaptchaConfig>(key: K, value: CaptchaConfig[K]) => {
      setCaptchaLocalSettings(
        (previous: CaptchaConfigPatch) => ({ ...previous, [key]: value })
      )
    },
    []
  )

  const hasBotChanges = useMemo(
    () => Object.keys(botLocalSettings).length > 0,
    [botLocalSettings]
  )
  const hasCaptchaChanges = useMemo(
    () => Object.keys(captchaLocalSettings).length > 0,
    [captchaLocalSettings]
  )
  const dynamicProtectionEnabled = getBotValue(
    "dynamic_protection_enabled",
    false
  )
  const browserSignEnabled = getBotValue("browser_sign_enabled", false)
  const shieldEnabled = getCaptchaValue("shield_enabled", false)
  const isLoading = botIsLoading || captchaIsLoading

  const saveBotSettings = useCallback(async () => {
    if (!botSettings) return
    try {
      // 保留 BotSettings 的既有局部合并语义；CAPTCHA/Shield 不从此处写入。
      await updateBot.execute({ ...botSettings, ...botLocalSettings })
      setBotLocalSettings({})
      await mutateBot()
      toast.success(t("captcha.botSaveSuccess"))
    } catch {
      toast.error(t("captcha.botSaveFailed"))
    }
  }, [botLocalSettings, botSettings, mutateBot, t, updateBot])

  const saveCaptchaSettings = useCallback(async () => {
    try {
      await updateCaptcha.execute(captchaLocalSettings)
      setCaptchaLocalSettings({})
      await mutateCaptcha()
      toast.success(t("captcha.captchaSaveSuccess"))
    } catch {
      toast.error(t("captcha.captchaSaveFailed"))
    }
  }, [captchaLocalSettings, mutateCaptcha, t, updateCaptcha])

  const runCaptchaTest = useCallback(async () => {
    try {
      const result = await captchaTest.execute(undefined)
      setPreview(result)
      toast.success(t("captcha.testSuccess"))
    } catch {
      toast.error(t("captcha.testFailed"))
    }
  }, [captchaTest, t])

  if (isLoading) {
    return (
      <div className="mx-auto max-w-6xl space-y-6">
        <PageHeader
          title={t("captcha.title")}
          description={t("captcha.description")}
        />
        <Skeleton className="h-[720px] w-full rounded-3xl" />
      </div>
    )
  }

  return (
    <TooltipProvider>
      <div className="mx-auto max-w-6xl space-y-6 pb-8">
        <PageHeader
          title={t("captcha.title")}
          description={t("captcha.description")}
          icon={
            <IconShield className="size-6 text-primary" aria-hidden="true" />
          }
          titleExtra={
            <Badge variant="outline">{t("captcha.globalConfig")}</Badge>
          }
        />

        {botError || captchaError ? (
          <Alert variant="destructive">
            <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
            <AlertDescription>
              {botError?.message ||
                captchaError?.message ||
                t("error.unexpectedError")}
            </AlertDescription>
          </Alert>
        ) : null}

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <SectionHeading
                  title={t("captcha.section.captcha")}
                  description={t("captcha.captchaDescription")}
                  help={t("captcha.captchaHelp")}
                />
              </CardHeader>
              <CardContent className="space-y-6">
                <SettingSwitch
                  id="captcha_enabled"
                  label={t("captcha.enableCaptcha")}
                  description={t("captcha.enableCaptchaDesc")}
                  checked={getCaptchaValue("captcha_enabled", false)}
                  onCheckedChange={(checked) =>
                    setCaptchaValue("captcha_enabled", checked)
                  }
                />

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="captcha_type">
                      {t("captcha.captchaType")}
                    </Label>
                    <Select
                      value={getCaptchaValue("captcha_type", "math")}
                      onValueChange={(value) =>
                        setCaptchaValue(
                          "captcha_type",
                          value as CaptchaConfig["captcha_type"]
                        )
                      }
                    >
                      <SelectTrigger
                        id="captcha_type"
                        aria-describedby="captcha_type-description"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="math">
                          {t("captcha.typeMath")}
                        </SelectItem>
                        <SelectItem value="click">
                          {t("captcha.typeClick")}
                        </SelectItem>
                        <SelectItem value="slide">
                          {t("captcha.typeSlide")}
                        </SelectItem>
                        <SelectItem value="rotate">
                          {t("captcha.typeRotate")}
                        </SelectItem>
                      </SelectContent>
                    </Select>
                    <p
                      id="captcha_type-description"
                      className="text-xs leading-5 text-muted-foreground"
                    >
                      {t("captcha.captchaTypeDesc")}
                    </p>
                  </div>
                  <NumberField
                    id="captcha_timeout"
                    label={t("captcha.captchaTimeout")}
                    description={t("captcha.captchaTimeoutDesc")}
                    value={getCaptchaValue("captcha_timeout", 120)}
                    min={1}
                    unit={t("common.seconds")}
                    onChange={(value) =>
                      setCaptchaValue("captcha_timeout", value)
                    }
                  />
                  <NumberField
                    id="captcha_pass_ttl"
                    label={t("captcha.captchaPassTtl")}
                    description={t("captcha.captchaPassTtlDesc")}
                    value={getCaptchaValue("captcha_pass_ttl", 120)}
                    min={1}
                    unit={t("common.seconds")}
                    onChange={(value) =>
                      setCaptchaValue("captcha_pass_ttl", value)
                    }
                  />
                </div>
              </CardContent>
              <CardFooter className="justify-end border-t">
                <Button
                  onClick={saveCaptchaSettings}
                  disabled={!hasCaptchaChanges || updateCaptcha.loading}
                >
                  {updateCaptcha.loading ? (
                    <IconRefresh
                      className="mr-2 size-4 animate-spin"
                      aria-hidden="true"
                    />
                  ) : null}
                  {updateCaptcha.loading
                    ? t("common.saving")
                    : t("captcha.saveCaptcha")}
                </Button>
              </CardFooter>
            </Card>

            <Card>
              <CardHeader>
                <SectionHeading
                  title={t("captcha.section.shield")}
                  description={t("captcha.shieldDescription")}
                  help={t("captcha.shieldHelp")}
                />
              </CardHeader>
              <CardContent className="space-y-6">
                <SettingSwitch
                  id="shield_enabled"
                  label={t("captcha.enableShield")}
                  description={t("captcha.enableShieldDesc")}
                  checked={shieldEnabled}
                  onCheckedChange={(checked) =>
                    setCaptchaValue("shield_enabled", checked)
                  }
                />
                <div
                  className={cn(
                    "space-y-6 rounded-2xl border border-border/70 bg-muted/10 p-4",
                    !shieldEnabled && "opacity-60"
                  )}
                >
                  <div className="grid gap-4 sm:grid-cols-2">
                    <NumberField
                      id="shield_difficulty"
                      label={t("captcha.shieldDifficulty")}
                      description={t("captcha.shieldDifficultyDesc")}
                      value={getCaptchaValue("shield_difficulty", 4)}
                      min={1}
                      disabled={!shieldEnabled}
                      onChange={(value) =>
                        setCaptchaValue("shield_difficulty", value)
                      }
                    />
                    <NumberField
                      id="shield_timeout_secs"
                      label={t("captcha.shieldTimeout")}
                      description={t("captcha.shieldTimeoutDesc")}
                      value={getCaptchaValue("shield_timeout_secs", 30)}
                      min={1}
                      unit={t("common.seconds")}
                      disabled={!shieldEnabled}
                      onChange={(value) =>
                        setCaptchaValue("shield_timeout_secs", value)
                      }
                    />
                    <NumberField
                      id="shield_auto_start_delay"
                      label={t("captcha.shieldAutoStartDelay")}
                      description={t("captcha.shieldAutoStartDelayDesc")}
                      value={getCaptchaValue("shield_auto_start_delay", 800)}
                      min={0}
                      unit={t("captcha.milliseconds")}
                      disabled={!shieldEnabled}
                      onChange={(value) =>
                        setCaptchaValue("shield_auto_start_delay", value)
                      }
                    />
                    <NumberField
                      id="shield_max_retries"
                      label={t("captcha.shieldMaxRetries")}
                      description={t("captcha.shieldMaxRetriesDesc")}
                      value={getCaptchaValue("shield_max_retries", 3)}
                      min={1}
                      disabled={!shieldEnabled}
                      onChange={(value) =>
                        setCaptchaValue("shield_max_retries", value)
                      }
                    />
                    <NumberField
                      id="shield_env_strictness"
                      label={t("captcha.shieldEnvStrictness")}
                      description={t("captcha.shieldEnvStrictnessDesc")}
                      value={getCaptchaValue("shield_env_strictness", 1)}
                      min={0}
                      max={2}
                      disabled={!shieldEnabled}
                      onChange={(value) =>
                        setCaptchaValue(
                          "shield_env_strictness",
                          value as CaptchaConfig["shield_env_strictness"]
                        )
                      }
                    />
                  </div>
                  <Separator />
                  <div className="grid gap-3 sm:grid-cols-2">
                    <SettingSwitch
                      id="shield_require_http2"
                      label={t("captcha.shieldRequireHttp2")}
                      description={t("captcha.shieldRequireHttp2Desc")}
                      checked={getCaptchaValue("shield_require_http2", false)}
                      disabled={!shieldEnabled}
                      onCheckedChange={(checked) =>
                        setCaptchaValue("shield_require_http2", checked)
                      }
                    />
                    <SettingSwitch
                      id="shield_require_http3"
                      label={t("captcha.shieldRequireHttp3")}
                      description={t("captcha.shieldRequireHttp3Desc")}
                      checked={getCaptchaValue("shield_require_http3", false)}
                      disabled={!shieldEnabled}
                      onCheckedChange={(checked) =>
                        setCaptchaValue("shield_require_http3", checked)
                      }
                    />
                    <SettingSwitch
                      id="shield_allow_http1"
                      label={t("captcha.shieldAllowHttp1")}
                      description={t("captcha.shieldAllowHttp1Desc")}
                      checked={getCaptchaValue("shield_allow_http1", true)}
                      disabled={!shieldEnabled}
                      onCheckedChange={(checked) =>
                        setCaptchaValue("shield_allow_http1", checked)
                      }
                    />
                    <SettingSwitch
                      id="shield_enable_js_challenge"
                      label={t("captcha.shieldEnableJsChallenge")}
                      description={t("captcha.shieldEnableJsChallengeDesc")}
                      checked={getCaptchaValue(
                        "shield_enable_js_challenge",
                        true
                      )}
                      disabled={!shieldEnabled}
                      onCheckedChange={(checked) =>
                        setCaptchaValue("shield_enable_js_challenge", checked)
                      }
                    />
                    <SettingSwitch
                      id="shield_enable_env_check"
                      label={t("captcha.shieldEnableEnvCheck")}
                      description={t("captcha.shieldEnableEnvCheckDesc")}
                      checked={getCaptchaValue("shield_enable_env_check", true)}
                      disabled={!shieldEnabled}
                      onCheckedChange={(checked) =>
                        setCaptchaValue("shield_enable_env_check", checked)
                      }
                    />
                    <SettingSwitch
                      id="shield_enable_devtools"
                      label={t("captcha.shieldEnableDevtools")}
                      description={t("captcha.shieldEnableDevtoolsDesc")}
                      checked={getCaptchaValue("shield_enable_devtools", true)}
                      disabled={!shieldEnabled}
                      onCheckedChange={(checked) =>
                        setCaptchaValue("shield_enable_devtools", checked)
                      }
                    />
                  </div>
                </div>
              </CardContent>
              <CardFooter className="justify-end border-t">
                <Button
                  onClick={saveCaptchaSettings}
                  disabled={!hasCaptchaChanges || updateCaptcha.loading}
                >
                  {updateCaptcha.loading ? (
                    <IconRefresh
                      className="mr-2 size-4 animate-spin"
                      aria-hidden="true"
                    />
                  ) : null}
                  {updateCaptcha.loading
                    ? t("common.saving")
                    : t("captcha.saveShield")}
                </Button>
              </CardFooter>
            </Card>

            <Card>
              <CardHeader>
                <SectionHeading
                  title={t("captcha.section.dynamicProtection")}
                  description={t("captcha.dynamicProtectionDescription")}
                  help={t("captcha.dynamicProtectionHelp")}
                />
              </CardHeader>
              <CardContent className="space-y-3">
                <SettingSwitch
                  id="dynamic_protection_enabled"
                  label={t("captcha.enableDynamicProtection")}
                  description={t("captcha.enableDynamicProtectionDesc")}
                  checked={dynamicProtectionEnabled}
                  onCheckedChange={(checked) =>
                    setBotValue("dynamic_protection_enabled", checked)
                  }
                />
                <div
                  className={cn(
                    "ml-0 space-y-3 rounded-2xl border border-border/70 bg-muted/10 p-4 sm:ml-4",
                    !dynamicProtectionEnabled &&
                      "pointer-events-none opacity-50"
                  )}
                >
                  <SettingSwitch
                    id="html_obfuscation"
                    label={t("captcha.htmlObfuscation")}
                    description={t("captcha.htmlObfuscationDesc")}
                    badge={t("captcha.recommended")}
                    checked={getBotValue("html_obfuscation", false)}
                    disabled={!dynamicProtectionEnabled}
                    onCheckedChange={(checked) =>
                      setBotValue("html_obfuscation", checked)
                    }
                  />
                  <SettingSwitch
                    id="js_obfuscation"
                    label={t("captcha.jsObfuscation")}
                    description={t("captcha.performanceWarning")}
                    checked={getBotValue("js_obfuscation", false)}
                    disabled={!dynamicProtectionEnabled}
                    onCheckedChange={(checked) =>
                      setBotValue("js_obfuscation", checked)
                    }
                  />
                  <SettingSwitch
                    id="image_watermark"
                    label={t("captcha.imageWatermark")}
                    description={t("captcha.performanceWarning")}
                    checked={getBotValue("image_watermark", false)}
                    disabled={!dynamicProtectionEnabled}
                    onCheckedChange={(checked) =>
                      setBotValue("image_watermark", checked)
                    }
                  />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <SectionHeading
                  title={t("captcha.section.antiReplay")}
                  description={t("captcha.antiReplayDescription")}
                  help={t("captcha.antiReplayHelp")}
                />
              </CardHeader>
              <CardContent>
                <SettingSwitch
                  id="anti_replay_enabled"
                  label={t("captcha.enableAntiReplay")}
                  description={t("captcha.enableAntiReplayDesc")}
                  checked={getBotValue("anti_replay_enabled", false)}
                  onCheckedChange={(checked) =>
                    setBotValue("anti_replay_enabled", checked)
                  }
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <SectionHeading
                  title={t("captcha.section.browserSign")}
                  description={t("captcha.browserSignDescription")}
                  help={t("captcha.browserSignHelp")}
                />
              </CardHeader>
              <CardContent className="space-y-4">
                <SettingSwitch
                  id="browser_sign_enabled"
                  label={t("captcha.enableBrowserSign")}
                  description={t("captcha.enableBrowserSignDesc")}
                  checked={browserSignEnabled}
                  onCheckedChange={(checked) =>
                    setBotValue("browser_sign_enabled", checked)
                  }
                />
                <div
                  className={cn(
                    "grid gap-4 rounded-2xl border border-border/70 bg-muted/10 p-4 sm:grid-cols-2",
                    !browserSignEnabled && "pointer-events-none opacity-50"
                  )}
                >
                  <NumberField
                    id="browser_sign_ttl"
                    label={t("captcha.browserSignTtl")}
                    description={t("captcha.browserSignTtlDesc")}
                    value={getBotValue("browser_sign_ttl", 300)}
                    min={1}
                    unit={t("common.seconds")}
                    disabled={!browserSignEnabled}
                    onChange={(value) => setBotValue("browser_sign_ttl", value)}
                  />
                  <div className="space-y-2">
                    <Label htmlFor="browser_sign_action">
                      {t("captcha.browserSignAction")}
                    </Label>
                    <Select
                      value={getBotValue("browser_sign_action", "challenge")}
                      disabled={!browserSignEnabled}
                      onValueChange={(value) =>
                        setBotValue("browser_sign_action", value)
                      }
                    >
                      <SelectTrigger
                        id="browser_sign_action"
                        aria-describedby="browser_sign_action-description"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="observe">
                          {t("captcha.browserSignActionObserve")}
                        </SelectItem>
                        <SelectItem value="challenge">
                          {t("captcha.browserSignActionChallenge")}
                        </SelectItem>
                        <SelectItem value="captcha_challenge">
                          {t("ccProtection.action_captcha_challenge")}
                        </SelectItem>
                        <SelectItem value="intercept">
                          {t("captcha.browserSignActionIntercept")}
                        </SelectItem>
                      </SelectContent>
                    </Select>
                    <p
                      id="browser_sign_action-description"
                      className="text-xs leading-5 text-muted-foreground"
                    >
                      {t("captcha.browserSignActionDesc")}
                    </p>
                  </div>
                </div>
              </CardContent>
              <CardFooter className="justify-end border-t">
                <div className="flex flex-wrap justify-end gap-2">
                  <Button
                    variant="outline"
                    onClick={() => setBotLocalSettings({})}
                    disabled={!hasBotChanges || updateBot.loading}
                  >
                    {t("captcha.cancel")}
                  </Button>
                  <Button
                    onClick={saveBotSettings}
                    disabled={!hasBotChanges || updateBot.loading}
                  >
                    {updateBot.loading ? (
                      <IconRefresh
                        className="mr-2 size-4 animate-spin"
                        aria-hidden="true"
                      />
                    ) : null}
                    {updateBot.loading
                      ? t("common.saving")
                      : t("captcha.saveBot")}
                  </Button>
                </div>
              </CardFooter>
            </Card>
          </div>

          <div className="space-y-6 xl:sticky xl:top-6 xl:self-start">
            <Card>
              <CardHeader>
                <CardTitle>{t("captcha.testTitle")}</CardTitle>
                <CardDescription>
                  {t("captcha.testDescription")}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Button
                  className="w-full"
                  onClick={runCaptchaTest}
                  disabled={captchaTest.loading}
                >
                  {captchaTest.loading ? (
                    <IconRefresh
                      className="mr-2 size-4 animate-spin"
                      aria-hidden="true"
                    />
                  ) : null}
                  {captchaTest.loading
                    ? t("captcha.testing")
                    : t("captcha.runTest")}
                </Button>
                {preview ? (
                  <div className="space-y-4" aria-live="polite">
                    <div className="overflow-hidden rounded-2xl border border-border bg-muted/20 p-3">
                      {preview.master_img ? (
                        <img
                          src={preview.master_img}
                          alt={t("captcha.masterImageAlt")}
                          className="mx-auto h-auto max-h-72 max-w-full rounded-lg object-contain"
                        />
                      ) : (
                        <p className="py-12 text-center text-sm text-muted-foreground">
                          {t("captcha.noMasterImage")}
                        </p>
                      )}
                    </div>
                    {preview.thumb_img ? (
                      <div className="overflow-hidden rounded-2xl border border-border bg-muted/20 p-3">
                        <p className="mb-2 text-xs font-medium text-muted-foreground">
                          {t("captcha.thumbImage")}
                        </p>
                        <img
                          src={preview.thumb_img}
                          alt={t("captcha.thumbImageAlt")}
                          className="mx-auto h-auto max-h-24 max-w-full rounded-lg object-contain"
                        />
                      </div>
                    ) : null}
                    <p className="rounded-xl bg-primary/10 p-3 text-sm font-medium text-primary">
                      {preview.prompt}
                    </p>
                    <dl className="grid grid-cols-2 gap-2">
                      <PreviewValue
                        label={t("captcha.previewType")}
                        value={preview.type}
                      />
                      <PreviewValue
                        label={t("captcha.previewRequestedType")}
                        value={preview.captcha_type}
                      />
                      <PreviewValue
                        label={t("captcha.previewSize")}
                        value={`${preview.width} × ${preview.height}`}
                      />
                      <PreviewValue
                        label={t("captcha.previewTimeout")}
                        value={`${preview.timeout} ${t("common.seconds")}`}
                      />
                      <PreviewValue
                        label={t("captcha.previewPassTtl")}
                        value={`${preview.pass_ttl} ${t("common.seconds")}`}
                      />
                      <PreviewValue
                        label={t("captcha.previewFallback")}
                        value={
                          preview.fallback ? (
                            <Badge variant="secondary">{t("common.yes")}</Badge>
                          ) : (
                            <Badge variant="outline">{t("common.no")}</Badge>
                          )
                        }
                      />
                      <PreviewValue
                        label={t("captcha.previewSession")}
                        value={
                          <code className="text-xs">{preview.session_id}</code>
                        }
                      />
                    </dl>
                  </div>
                ) : (
                  <div className="rounded-2xl border border-dashed border-border p-8 text-center text-sm leading-6 text-muted-foreground">
                    {t("captcha.testEmpty")}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-primary/20 bg-primary/5">
              <CardHeader>
                <CardTitle className="text-base">
                  {t("captcha.saveHintTitle")}
                </CardTitle>
                <CardDescription>
                  {t("captcha.saveHintDescription")}
                </CardDescription>
              </CardHeader>
            </Card>
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}
