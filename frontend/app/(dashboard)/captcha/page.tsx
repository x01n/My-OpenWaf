"use client"

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react"
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
import {
  IconHelpCircle,
  IconPlus,
  IconRefresh,
  IconShield,
  IconTrash,
} from "@tabler/icons-react"
import {
  useBotSettings,
  useBotSettingsUpdate,
  useCaptchaConfig,
  useCaptchaConfigUpdate,
  useCaptchaTest,
  useChainConfig,
  useChainConfigUpdate,
  useChainSessions,
  useChainSessionDelete,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import { ConfirmDialog } from "@/components/confirm-dialog"
import type {
  BotSettings,
  ChainConfig,
  ChainSessionInfo,
  ChainStepCondition,
  ChainStepConfig,
  ChainStepType,
  CaptchaConfig,
  CaptchaConfigPatch,
  CaptchaTestResponse,
} from "@/lib/types"
import { cn } from "@/lib/utils"
import { BotObservationCard } from "./components/bot-observation-card"

const CHAIN_CAPTCHA_TYPES: Array<CaptchaConfig["captcha_type"] | ""> = [
  "",
  "math",
  "click",
  "slide",
  "rotate",
]

const CHAIN_STEP_TYPES: ChainStepType[] = ["env", "pow", "captcha"]

const CHAIN_STEP_CONDITIONS: ChainStepCondition[] = [
  "all",
  "env_score>30",
  "env_score<30",
  "score>50",
  "score>80",
]

function normalizeChainSteps(raw: unknown): ChainStepConfig[] {
  if (!Array.isArray(raw)) return []
  const steps: ChainStepConfig[] = []
  for (const value of raw) {
    if (!value || typeof value !== "object" || Array.isArray(value)) continue
    const item = value as Record<string, unknown>
    const type = item.type
    if (
      typeof type !== "string" ||
      !CHAIN_STEP_TYPES.includes(type as ChainStepType)
    ) {
      continue
    }
    const condition =
      typeof item.condition === "string" &&
      CHAIN_STEP_CONDITIONS.includes(item.condition as ChainStepCondition)
        ? (item.condition as ChainStepCondition)
        : "all"
    const captchaType =
      typeof item.captcha_type === "string" &&
      CHAIN_CAPTCHA_TYPES.includes(
        item.captcha_type as CaptchaConfig["captcha_type"]
      )
        ? (item.captcha_type as CaptchaConfig["captcha_type"])
        : ""
    steps.push(
      type === "captcha"
        ? { type: "captcha", condition: "all", captcha_type: captchaType }
        : { type: type as Exclude<ChainStepType, "captcha">, condition }
    )
  }
  return steps
}

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

/**
 * GeoIP 数据源运行模式：
 * - "env":    geoip_db_path 为空，运行时沿用环境变量 MY_OPENWAF_GEOIP_DB 配置的库；
 * - "custom": 使用显式配置的 MaxMind GeoIP2 数据库文件路径。
 * 后端 loadBotGeoConfig（internal/app/server.go）对空路径保留环境变量 fallback。
 */
type GeoIPMode = "env" | "custom"

/**
 * 宽松读取高风险国家代码列表：
 * 后端字段为字符串数组（ISO 3166-1 alpha-2 大写）。
 * 原始数据为空或非法时返回空数组，避免破坏保存载荷。
 */
function parseCountries(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  return raw.filter(
    (value): value is string => typeof value === "string" && value.length > 0
  )
}

/**
 * 宽松读取 ASN 列表：兼容数组、逗号/分号/空白分隔数字文本，
 * 只保留非负安全整数。
 */
function parseAsns(raw: unknown, maxLen = 200): number[] {
  if (raw == null) return []
  const text = Array.isArray(raw)
    ? raw.map(String).join(",")
    : typeof raw === "string"
      ? raw
      : ""
  const parts = text.split(/[\s,;]+/).filter((value) => value.length > 0)
  const result: number[] = []
  for (const part of parts) {
    if (!/^\d+$/.test(part)) continue
    const parsed = Number(part)
    if (Number.isSafeInteger(parsed) && parsed >= 0) result.push(parsed)
  }
  return result.slice(0, maxLen)
}

/** ASN 数字数组转逗号分隔回显文本。 */
function formatAsns(asns: number[] | undefined): string {
  return (asns ?? []).join(", ")
}

/**
 * ASN 输入文本序列化，非法内容返回 null 供 UI 显示校验错误。
 */
function serializeAsnText(text: string): number[] | null {
  const trimmed = text.trim()
  if (trimmed === "") return []
  if (!/^[\d\s,;]+$/.test(trimmed)) {
    return null
  }
  const parts = trimmed.split(/[\s,;]+/).filter((value) => value.length > 0)
  const values = parts.map(Number)
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    return null
  }
  return values.slice(0, 200)
}

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

/**
 * 链式验证配置卡：步骤顺序与 CAPTCHA 步骤的具体类型直接映射到
 * `chain/config` 后端契约，避免管理端只能修改全局验证码而无法控制链式质询。
 */
function ChainConfigCard({
  config,
  canManage,
}: {
  config: ChainConfig
  canManage: boolean
}) {
  const { t } = useTranslation()
  const updateChain = useChainConfigUpdate()
  const [enabled, setEnabled] = useState(config.chain_enabled)
  const [steps, setSteps] = useState<ChainStepConfig[]>(() =>
    normalizeChainSteps(config.chain_steps)
  )
  const savedSignature = JSON.stringify({
    chain_enabled: config.chain_enabled,
    chain_steps: normalizeChainSteps(config.chain_steps),
  })
  const draftSignature = JSON.stringify({
    chain_enabled: enabled,
    chain_steps: steps,
  })
  const dirty = savedSignature !== draftSignature

  const updateStep = (index: number, patch: Partial<ChainStepConfig>) => {
    if (!canManage) return
    setSteps((previous) =>
      previous.map((step, stepIndex) =>
        stepIndex === index ? { ...step, ...patch } : step
      )
    )
  }

  const changeStepType = (index: number, value: string) => {
    const type = value as ChainStepType
    if (!CHAIN_STEP_TYPES.includes(type)) return
    if (type === "captcha") {
      updateStep(index, { type, condition: "all", captcha_type: "" })
      return
    }
    updateStep(index, { type, condition: "all", captcha_type: "" })
  }

  const handleSave = async () => {
    if (!canManage || updateChain.loading) return
    if (enabled && steps.length === 0) {
      toast.error(t("captcha.chain.emptyEnabled"))
      return
    }
    const payload = steps.map((step) =>
      step.type === "captcha"
        ? {
            type: "captcha" as const,
            condition: "all" as const,
            ...(step.captcha_type ? { captcha_type: step.captcha_type } : {}),
          }
        : {
            type: step.type,
            condition: step.condition || "all",
          }
    )
    try {
      await updateChain.execute({
        chain_enabled: enabled,
        chain_steps: payload,
      })
      toast.success(t("captcha.chain.saveSuccess"))
    } catch (error: unknown) {
      toast.error(
        error instanceof Error ? error.message : t("captcha.chain.saveFailed")
      )
    }
  }

  return (
    <Card>
      <CardHeader>
        <SectionHeading
          title={t("captcha.chain.title")}
          description={t("captcha.chain.description")}
          help={t("captcha.chain.help")}
        />
      </CardHeader>
      <CardContent className="space-y-4">
        <SettingSwitch
          id="chain_enabled"
          label={t("captcha.chain.enabled")}
          description={t("captcha.chain.enabledDesc")}
          checked={enabled}
          disabled={!canManage}
          onCheckedChange={setEnabled}
        />
        <div className="space-y-3 rounded-2xl border border-border/70 bg-muted/10 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-sm font-medium">{t("captcha.chain.steps")}</p>
              <p className="text-xs leading-5 text-muted-foreground">
                {t("captcha.chain.stepsDesc")}
              </p>
            </div>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() =>
                canManage &&
                setSteps((previous) => [
                  ...previous,
                  { type: "captcha", condition: "all", captcha_type: "" },
                ])
              }
              disabled={!canManage || updateChain.loading}
            >
              <IconPlus className="mr-1 size-4" aria-hidden="true" />
              {t("captcha.chain.addStep")}
            </Button>
          </div>

          {steps.length === 0 ? (
            <p className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">
              {t("captcha.chain.noSteps")}
            </p>
          ) : (
            <div className="space-y-2">
              {steps.map((step, index) => (
                <div
                  key={`${index}-${step.type}`}
                  className="grid min-w-0 gap-2 rounded-xl border bg-background/70 p-3 sm:grid-cols-[auto_minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-center"
                >
                  <Badge variant="secondary" className="w-fit">
                    {index + 1}
                  </Badge>
                  <select
                    value={step.type}
                    disabled={!canManage || updateChain.loading}
                    onChange={(event) =>
                      changeStepType(index, event.target.value)
                    }
                    className="h-9 min-w-0 rounded-md border border-input bg-background px-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                    aria-label={t("captcha.chain.stepTypeLabel", {
                      index: index + 1,
                    })}
                  >
                    {CHAIN_STEP_TYPES.map((type) => (
                      <option key={type} value={type}>
                        {t(`captcha.chain.stepType.${type}`)}
                      </option>
                    ))}
                  </select>
                  {step.type === "captcha" ? (
                    <select
                      value={step.captcha_type ?? ""}
                      disabled={!canManage || updateChain.loading}
                      onChange={(event) =>
                        updateStep(index, {
                          captcha_type: event.target.value as
                            CaptchaConfig["captcha_type"] | "",
                        })
                      }
                      className="h-9 min-w-0 rounded-md border border-input bg-background px-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                      aria-label={t("captcha.chain.captchaTypeLabel", {
                        index: index + 1,
                      })}
                    >
                      {CHAIN_CAPTCHA_TYPES.map((type) => (
                        <option key={type || "inherit"} value={type}>
                          {t(`captcha.chain.captchaType.${type || "inherit"}`)}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <select
                      value={step.condition || "all"}
                      disabled={!canManage || updateChain.loading}
                      onChange={(event) =>
                        updateStep(index, {
                          condition: event.target.value as ChainStepCondition,
                        })
                      }
                      className="h-9 min-w-0 rounded-md border border-input bg-background px-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                      aria-label={t("captcha.chain.conditionLabel", {
                        index: index + 1,
                      })}
                    >
                      {CHAIN_STEP_CONDITIONS.map((condition) => (
                        <option key={condition} value={condition}>
                          {t(`captcha.chain.condition.${condition || "all"}`)}
                        </option>
                      ))}
                    </select>
                  )}
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    className="text-destructive"
                    aria-label={t("captcha.chain.removeStep", {
                      index: index + 1,
                    })}
                    onClick={() =>
                      canManage &&
                      setSteps((previous) =>
                        previous.filter((_, stepIndex) => stepIndex !== index)
                      )
                    }
                    disabled={!canManage || updateChain.loading}
                  >
                    <IconTrash className="size-4" aria-hidden="true" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
      <CardFooter className="justify-end border-t">
        <Button
          type="button"
          onClick={handleSave}
          disabled={!canManage || !dirty || updateChain.loading}
        >
          {updateChain.loading ? (
            <IconRefresh
              className="mr-2 size-4 animate-spin"
              aria-hidden="true"
            />
          ) : null}
          {updateChain.loading ? t("common.saving") : t("captcha.chain.save")}
        </Button>
      </CardFooter>
    </Card>
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

/**
 * 链式验证进行中会话列表：契约来自 GET /api/v1/chain/sessions 与
 * POST /api/v1/chain/sessions/:id/delete，删除后清除该访客的半途挑战状态。
 */
function ChainSessionsCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation()
  const { data, isLoading, error, mutate } = useChainSessions()
  const deleteSession = useChainSessionDelete()
  const [pendingId, setPendingId] = useState<string | null>(null)

  const sessions = data?.items ?? []
  const deleting = deleteSession.loading && pendingId !== null

  const handleDelete = async () => {
    if (!canManage || !pendingId) return
    try {
      await deleteSession.execute(pendingId)
      toast.success(t("captcha.chain.sessionDeleteSuccess"))
      await mutate().catch(() => {
        toast.error(t("captcha.refreshFailed"))
      })
    } catch {
      toast.error(t("captcha.chain.sessionDeleteFailed"))
    } finally {
      setPendingId(null)
    }
  }

  return (
    <Card>
      <CardHeader>
        <SectionHeading
          title={t("captcha.chain.sessions")}
          description={t("captcha.chain.sessionsDesc")}
          help={t("captcha.chain.sessionsDesc")}
        />
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading ? (
          <Skeleton className="h-24 w-full rounded-2xl" />
        ) : error ? (
          <Alert variant="destructive">
            <AlertTitle>{t("captcha.chain.sessionLoadFailed")}</AlertTitle>
          </Alert>
        ) : sessions.length === 0 ? (
          <p className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">
            {t("captcha.chain.noSessions")}
          </p>
        ) : (
          <div className="divide-y rounded-2xl border border-border/70 bg-muted/10">
            {sessions.map((session: ChainSessionInfo) => (
              <div
                key={session.id}
                className="flex flex-wrap items-center justify-between gap-2 px-4 py-3"
              >
                <div className="min-w-0">
                  <p className="truncate font-mono text-xs text-foreground">
                    {session.id}
                  </p>
                  <p className="truncate text-xs text-muted-foreground">
                    {session.original_url &&
                      decodeURIComponent(session.original_url)}
                    {session.original_url ? " · " : ""}
                    {t("captcha.chain.sessionStep", {
                      current: session.current_step,
                      total: session.step_count,
                    })}
                  </p>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="text-destructive"
                  disabled={!canManage || deleteSession.loading}
                  onClick={() => setPendingId(session.id)}
                >
                  <IconTrash className="mr-1 size-4" aria-hidden="true" />
                  {deleteSession.loading && pendingId === session.id
                    ? t("common.processing")
                    : t("common.delete")}
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
      <ConfirmDialog
        open={pendingId !== null}
        onOpenChange={(open) => !open && setPendingId(null)}
        title={t("captcha.chain.sessionDeleteTitle")}
        description={t("captcha.chain.sessionDeleteDesc")}
        confirmText={t("common.delete")}
        loading={deleting}
        onConfirm={handleDelete}
      />
    </Card>
  )
}

export default function CaptchaPage() {
  const { t } = useTranslation()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
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
  const {
    data: chainConfig,
    isLoading: chainIsLoading,
    error: chainError,
  } = useChainConfig()

  const [botLocalSettings, setBotLocalSettings] = useState<BotLocalSettings>({})
  const [captchaLocalSettings, setCaptchaLocalSettings] =
    useState<CaptchaConfigPatch>({})
  const [preview, setPreview] = useState<CaptchaTestResponse | null>(null)

  /** GeoIP 局部草稿：服务器值未返回前用「环境变量」语义兜底。 */
  const [geoipLocal, setGeoipLocal] = useState<{
    mode: GeoIPMode
    path: string
    countries: string[]
    datacenterText: string
    vpnProxyText: string
    asnTextError: string | null
  }>({
    mode: "env",
    path: "",
    countries: [],
    datacenterText: "",
    vpnProxyText: "",
    asnTextError: null,
  })

  const geoipChangedFromServer = useMemo(() => {
    if (!botSettings) return false
    const savedCountries = parseCountries(botSettings.high_risk_countries)
    const savedDatacenter = formatAsns(parseAsns(botSettings.datacenter_asns))
    const savedVpnProxy = formatAsns(parseAsns(botSettings.vpn_proxy_asns))
    const savedMode: GeoIPMode = botSettings.geoip_db_path ? "custom" : "env"
    const savedPath = botSettings.geoip_db_path || ""
    return (
      geoipLocal.mode !== savedMode ||
      geoipLocal.path !== savedPath ||
      geoipLocal.countries.join(",") !== savedCountries.join(",") ||
      geoipLocal.datacenterText !== savedDatacenter ||
      geoipLocal.vpnProxyText !== savedVpnProxy
    )
  }, [
    botSettings,
    geoipLocal.mode,
    geoipLocal.path,
    geoipLocal.countries,
    geoipLocal.datacenterText,
    geoipLocal.vpnProxyText,
  ])

  /** 服务器 GeoIP 配置返回后，把值装入局部草稿（仅一次，避免覆盖用户输入）。 */
  const geoipHydrated = useRef(false)
  useEffect(() => {
    if (!botSettings || geoipHydrated.current) return
    geoipHydrated.current = true
    setGeoipLocal({
      mode: botSettings.geoip_db_path ? "custom" : "env",
      path: botSettings.geoip_db_path || "",
      countries: parseCountries(botSettings.high_risk_countries),
      datacenterText: formatAsns(parseAsns(botSettings.datacenter_asns)),
      vpnProxyText: formatAsns(parseAsns(botSettings.vpn_proxy_asns)),
      asnTextError: null,
    })
  }, [botSettings])

  const setGeoipMode = useCallback(
    (mode: GeoIPMode) => {
      if (!canManage) return
      setGeoipLocal((previous) => ({
        ...previous,
        mode,
        path: mode === "env" ? "" : previous.path,
      }))
    },
    [canManage]
  )

  const setGeoipPath = useCallback(
    (path: string) => {
      if (!canManage) return
      setGeoipLocal((previous) => ({ ...previous, path }))
    },
    [canManage]
  )

  /** 国家代码列表就地编辑：仅保留规范的两位大写字母代码，重复项只保留一次。 */
  const setGeoipCountries = useCallback(
    (value: string) => {
      if (!canManage) return
      const codes = value
        .split(/[\s,;]+/)
        .map((part) => part.trim().toUpperCase())
        .filter((part) => /^[A-Z]{2}$/.test(part))
      setGeoipLocal((previous) => ({
        ...previous,
        countries: [...new Set(codes)].slice(0, 200),
      }))
    },
    [canManage]
  )

  /** 数据中心 ASN 文本编辑；非法字符时保留原值并标记错误，合法时替换。 */
  const setDatacenterText = useCallback(
    (value: string) => {
      if (!canManage) return
      const parsed = serializeAsnText(value)
      if (parsed === null) {
        setGeoipLocal((previous) => ({
          ...previous,
          datacenterText: value,
          asnTextError: "datacenter",
        }))
        return
      }
      setGeoipLocal((previous) => ({
        ...previous,
        datacenterText: value.trim(),
        asnTextError:
          previous.asnTextError === "datacenter" ? null : previous.asnTextError,
      }))
    },
    [canManage]
  )

  /** VPN/代理 ASN 文本编辑；非法字符时保留原值并标记错误，合法时替换。 */
  const setVpnProxyText = useCallback(
    (value: string) => {
      if (!canManage) return
      const parsed = serializeAsnText(value)
      if (parsed === null) {
        setGeoipLocal((previous) => ({
          ...previous,
          vpnProxyText: value,
          asnTextError: "vpn_proxy",
        }))
        return
      }
      setGeoipLocal((previous) => ({
        ...previous,
        vpnProxyText: value.trim(),
        asnTextError:
          previous.asnTextError === "vpn_proxy" ? null : previous.asnTextError,
      }))
    },
    [canManage]
  )

  const geoipDirty = geoipChangedFromServer || geoipLocal.asnTextError !== null

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
      setCaptchaLocalSettings((previous: CaptchaConfigPatch) => ({
        ...previous,
        [key]: value,
      }))
    },
    []
  )

  const hasBotChanges = useMemo(
    () => Object.keys(botLocalSettings).length > 0 || geoipDirty,
    [botLocalSettings, geoipDirty]
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
    if (!botSettings || !canManage) return
    if (geoipLocal.asnTextError !== null) {
      toast.error(t("captcha.geoAsnInvalid"))
      return
    }
    try {
      // 保留 BotSettings 的既有局部合并语义；CAPTCHA/Shield 不从此处写入。
      await updateBot.execute({
        ...botSettings,
        ...botLocalSettings,
        // GeoIP 字段来自独立草稿编辑区，保存时一并提交。
        high_risk_countries: geoipLocal.countries,
        datacenter_asns: serializeAsnText(geoipLocal.datacenterText) ?? [],
        vpn_proxy_asns: serializeAsnText(geoipLocal.vpnProxyText) ?? [],
        geoip_db_path: geoipLocal.mode === "custom" ? geoipLocal.path : "",
      })
      setBotLocalSettings({})
      toast.success(t("captcha.botSaveSuccess"))
      await mutateBot().catch(() => {
        toast.error(t("captcha.refreshFailed"))
      })
    } catch {
      toast.error(t("captcha.botSaveFailed"))
    }
  }, [
    botLocalSettings,
    botSettings,
    canManage,
    mutateBot,
    t,
    updateBot,
    geoipLocal.asnTextError,
    geoipLocal.countries,
    geoipLocal.datacenterText,
    geoipLocal.mode,
    geoipLocal.path,
    geoipLocal.vpnProxyText,
  ])

  const saveCaptchaSettings = useCallback(async () => {
    if (!canManage) return
    try {
      await updateCaptcha.execute(captchaLocalSettings)
      setCaptchaLocalSettings({})
      toast.success(t("captcha.captchaSaveSuccess"))
      await mutateCaptcha().catch(() => {
        toast.error(t("captcha.refreshFailed"))
      })
    } catch {
      toast.error(t("captcha.captchaSaveFailed"))
    }
  }, [canManage, captchaLocalSettings, mutateCaptcha, t, updateCaptcha])

  const runCaptchaTest = useCallback(async () => {
    if (!canManage) return
    try {
      const result = await captchaTest.execute(
        getCaptchaValue("captcha_type", "math")
      )
      setPreview(result)
      toast.success(t("captcha.testSuccess"))
    } catch {
      toast.error(t("captcha.testFailed"))
    }
  }, [canManage, captchaTest, getCaptchaValue, t])

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

        {!authLoading && !canManage && (
          <Alert>
            <AlertTitle>{t("common.readOnlyHint")}</AlertTitle>
            <AlertDescription>{t("captcha.readOnlyHint")}</AlertDescription>
          </Alert>
        )}

        <fieldset disabled={!canManage} className="m-0 min-w-0 border-0 p-0">
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

              {chainIsLoading ? (
                <Skeleton className="h-72 w-full rounded-3xl" />
              ) : chainConfig ? (
                <>
                  <ChainConfigCard
                    key={JSON.stringify(chainConfig)}
                    config={chainConfig}
                    canManage={canManage}
                  />
                  <ChainSessionsCard canManage={canManage} />
                </>
              ) : (
                <Alert variant="destructive">
                  <AlertTitle>{t("captcha.chain.loadFailed")}</AlertTitle>
                  <AlertDescription>
                    {chainError instanceof Error
                      ? chainError.message
                      : t("error.unexpectedError")}
                  </AlertDescription>
                </Alert>
              )}

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
                        min={1}
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
                        checked={getCaptchaValue(
                          "shield_enable_env_check",
                          true
                        )}
                        disabled={!shieldEnabled}
                        onCheckedChange={(checked) =>
                          setCaptchaValue("shield_enable_env_check", checked)
                        }
                      />
                      <SettingSwitch
                        id="shield_enable_devtools"
                        label={t("captcha.shieldEnableDevtools")}
                        description={t("captcha.shieldEnableDevtoolsDesc")}
                        checked={getCaptchaValue(
                          "shield_enable_devtools",
                          true
                        )}
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
                      onChange={(value) =>
                        setBotValue("browser_sign_ttl", value)
                      }
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

              <Card>
                <CardHeader>
                  <SectionHeading
                    title={t("captcha.section.geoip")}
                    description={t("captcha.geoipDescription")}
                    help={t("captcha.geoipHelp")}
                  />
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="geoip_db_path_mode">
                      {t("captcha.geoipMode")}
                    </Label>
                    <Select
                      value={geoipLocal.mode}
                      disabled={!canManage}
                      onValueChange={(value) =>
                        setGeoipMode(value as GeoIPMode)
                      }
                    >
                      <SelectTrigger
                        id="geoip_db_path_mode"
                        aria-describedby="geoip_db_path_mode-description"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="env">
                          {t("captcha.geoipModeEnv")}
                        </SelectItem>
                        <SelectItem value="custom">
                          {t("captcha.geoipModeCustom")}
                        </SelectItem>
                      </SelectContent>
                    </Select>
                    <p
                      id="geoip_db_path_mode-description"
                      className="text-xs leading-5 text-muted-foreground"
                    >
                      {t("captcha.geoipModeDesc")}
                    </p>
                  </div>

                  {geoipLocal.mode === "custom" && (
                    <div className="space-y-2">
                      <Label htmlFor="geoip_db_path">
                        {t("captcha.geoipDbPath")}
                      </Label>
                      <Input
                        id="geoip_db_path"
                        className="font-mono text-xs"
                        placeholder={t("captcha.geoipDbPathPlaceholder")}
                        value={geoipLocal.path}
                        onChange={(event) => setGeoipPath(event.target.value)}
                      />
                      <p
                        id="geoip_db_path-description"
                        className="text-xs leading-5 text-muted-foreground"
                      >
                        {t("captcha.geoipDbPathDesc")}
                      </p>
                    </div>
                  )}

                  <Separator />

                  <div className="space-y-2">
                    <Label htmlFor="high_risk_countries">
                      {t("captcha.highRiskCountries")}
                    </Label>
                    <textarea
                      id="high_risk_countries"
                      className="min-h-[72px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs ring-offset-background placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-none"
                      placeholder={t("captcha.highRiskCountriesPlaceholder")}
                      value={geoipLocal.countries.join(", ")}
                      onChange={(event) =>
                        setGeoipCountries(event.target.value)
                      }
                    />
                    <p
                      id="high_risk_countries-description"
                      className="text-xs leading-5 text-muted-foreground"
                    >
                      {t("captcha.highRiskCountriesDesc")}
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="datacenter_asns">
                      {t("captcha.datacenterAsns")}
                    </Label>
                    <textarea
                      id="datacenter_asns"
                      className="min-h-[72px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs ring-offset-background placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-none"
                      placeholder={t("captcha.datacenterAsnsPlaceholder")}
                      value={geoipLocal.datacenterText}
                      onChange={(event) =>
                        setDatacenterText(event.target.value)
                      }
                      aria-invalid={geoipLocal.asnTextError === "datacenter"}
                    />
                    <p
                      id="datacenter_asns-description"
                      className="text-xs leading-5 text-muted-foreground"
                    >
                      {t("captcha.datacenterAsnsDesc")}
                    </p>
                    {geoipLocal.asnTextError === "datacenter" && (
                      <p
                        className="text-xs leading-5 text-destructive"
                        id="datacenter_asns-error"
                      >
                        {t("captcha.geoAsnInvalid")}
                      </p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="vpn_proxy_asns">
                      {t("captcha.vpnProxyAsns")}
                    </Label>
                    <textarea
                      id="vpn_proxy_asns"
                      className="min-h-[72px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs ring-offset-background placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-none"
                      placeholder={t("captcha.vpnProxyAsnsPlaceholder")}
                      value={geoipLocal.vpnProxyText}
                      onChange={(event) => setVpnProxyText(event.target.value)}
                      aria-invalid={geoipLocal.asnTextError === "vpn_proxy"}
                    />
                    <p
                      id="vpn_proxy_asns-description"
                      className="text-xs leading-5 text-muted-foreground"
                    >
                      {t("captcha.vpnProxyAsnsDesc")}
                    </p>
                    {geoipLocal.asnTextError === "vpn_proxy" && (
                      <p
                        className="text-xs leading-5 text-destructive"
                        id="vpn_proxy_asns-error"
                      >
                        {t("captcha.geoAsnInvalid")}
                      </p>
                    )}
                  </div>
                </CardContent>
                <CardFooter className="justify-end border-t">
                  <div className="flex flex-wrap justify-end gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        geoipHydrated.current = false
                        setGeoipLocal({
                          mode: botSettings?.geoip_db_path ? "custom" : "env",
                          path: botSettings?.geoip_db_path || "",
                          countries: parseCountries(
                            botSettings?.high_risk_countries
                          ),
                          datacenterText: formatAsns(
                            parseAsns(botSettings?.datacenter_asns)
                          ),
                          vpnProxyText: formatAsns(
                            parseAsns(botSettings?.vpn_proxy_asns)
                          ),
                          asnTextError: null,
                        })
                      }}
                      disabled={!geoipDirty || updateBot.loading}
                    >
                      {t("captcha.cancel")}
                    </Button>
                    <Button
                      type="button"
                      onClick={saveBotSettings}
                      disabled={!geoipDirty || updateBot.loading}
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

              <BotObservationCard />
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
                              <Badge variant="secondary">
                                {t("common.yes")}
                              </Badge>
                            ) : (
                              <Badge variant="outline">{t("common.no")}</Badge>
                            )
                          }
                        />
                        <PreviewValue
                          label={t("captcha.previewSession")}
                          value={
                            <code className="text-xs">
                              {preview.session_id}
                            </code>
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
        </fieldset>
      </div>
    </TooltipProvider>
  )
}
