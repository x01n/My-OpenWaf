"use client"

import { useState, useMemo, useCallback, useEffect } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import {
  useOwaspRules,
  useOwaspBatchUpdate,
  useProtectionSettings,
  useProtectionSettingsUpdate,
  useProtectionSensitivity,
  useProtectionSensitivityUpdate,
  useProtectionEscalation,
  useProtectionEscalationUpdate,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
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
import {
  IconSettings,
  IconCopy,
  IconCheck,
  IconAlertTriangle,
  IconRefresh,
  IconDatabase,
  IconCode,
  IconUpload,
  IconFolder,
  IconTerminal2,
  IconCoffee,
  IconPackages,
  IconBug,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react"
import { SkipPathByPhaseEditor } from "@/components/skip-path-by-phase-editor"
import {
  findEmptySkipPaths,
  parseSkipPathByPhase,
  toSkipPathByPhasePayload,
} from "@/lib/skip-path-by-phase"
import { cn } from "@/lib/utils"
import type {
  EscalationStepDef,
  ProtectionSettings,
  SensitivityLevel,
  SkipPathByPhase,
} from "@/lib/types"

/**
 * OWASP 规则视图
 */
interface OwaspRule {
  id: string
  category: string
  name: string
  description: string
  enabled: boolean
  action?: string
  sensitivity?: string
}

/**
 * OWASP 规则列表响应
 */
interface OwaspRulesResponse {
  items: OwaspRule[]
  grouped: Record<string, OwaspRule[]>
  total: number
  policy_id: number
}

/**
 * 模块防护模式
 */
type ModuleMode = "disabled" | "observe" | "balanced" | "strict"

/**
 * 配置模式：跟随全局 / 自定义
 */
type ConfigMode = "global" | "custom"

/**
 * 攻击模块定义
 */
interface AttackModule {
  key: string
  nameKey: string
  category: string
  descKey: string
  icon: React.ElementType
}

/** 模块列表 */
const MODULES: AttackModule[] = [
  {
    key: "sqli",
    nameKey: "attacks.sqli",
    category: "sqli",
    descKey: "attacks.moduleDesc.sqli",
    icon: IconDatabase,
  },
  {
    key: "xss",
    nameKey: "attacks.xss",
    category: "xss",
    descKey: "attacks.moduleDesc.xss",
    icon: IconCode,
  },
  {
    key: "file_upload",
    nameKey: "attacks.fileUpload",
    category: "file_upload",
    descKey: "attacks.moduleDesc.fileUpload",
    icon: IconUpload,
  },
  {
    key: "path_traversal",
    nameKey: "attacks.pathTraversal",
    category: "path_traversal",
    descKey: "attacks.moduleDesc.pathTraversal",
    icon: IconFolder,
  },
  {
    key: "cmd_injection",
    nameKey: "attacks.cmdInjection",
    category: "cmd_injection",
    descKey: "attacks.moduleDesc.cmdInjection",
    icon: IconTerminal2,
  },
  {
    key: "template_injection",
    nameKey: "attacks.templateInjection",
    category: "template_injection",
    descKey: "attacks.moduleDesc.templateInjection",
    icon: IconCode,
  },
  {
    key: "jndi_injection",
    nameKey: "attacks.jndiInjection",
    category: "jndi_injection",
    descKey: "attacks.moduleDesc.jndiInjection",
    icon: IconCoffee,
  },
  {
    key: "expression_language",
    nameKey: "attacks.expressionLanguage",
    category: "expression_language",
    descKey: "attacks.moduleDesc.expressionLanguage",
    icon: IconCode,
  },
  {
    key: "deserialization",
    nameKey: "attacks.deserialization",
    category: "deserialization",
    descKey: "attacks.moduleDesc.deserialization",
    icon: IconPackages,
  },
  {
    key: "webshell",
    nameKey: "attacks.webshell",
    category: "webshell",
    descKey: "attacks.moduleDesc.webshell",
    icon: IconBug,
  },
]

/** 模式选项 */
const MODE_OPTIONS: { value: ModuleMode; labelKey: string }[] = [
  { value: "disabled", labelKey: "attacks.disabled" },
  { value: "observe", labelKey: "attacks.observe" },
  { value: "balanced", labelKey: "attacks.balanced" },
  { value: "strict", labelKey: "attacks.strict" },
]

/** 全局默认模式（平衡防护） */
const GLOBAL_DEFAULT_MODE: ModuleMode = "balanced"

/**
 * 根据规则列表推断当前模块模式
 * @param rules - 该模块对应的所有规则
 * @returns 推断出的模式
 */
function inferMode(rules: OwaspRule[] | undefined): ModuleMode {
  if (!rules || rules.length === 0) return GLOBAL_DEFAULT_MODE

  const allDisabled = rules.every((r) => !r.enabled)
  if (allDisabled) return "disabled"

  const allObserve = rules.every((r) => r.enabled && r.action === "observe")
  if (allObserve) return "observe"

  const allStrict = rules.every(
    (r) =>
      r.enabled &&
      (r.action === "intercept" || !r.action) &&
      (r.sensitivity === "high" || r.sensitivity === "strict")
  )
  if (allStrict) return "strict"

  return "balanced"
}

/**
 * 将模式转换为规则覆盖配置
 * @param mode - 选择的模式
 * @returns 对应的后端字段值
 */
function modeToOverride(mode: ModuleMode): {
  enabled: boolean
  action: string
  sensitivity: string
} {
  switch (mode) {
    case "disabled":
      return { enabled: false, action: "", sensitivity: "" }
    case "observe":
      return { enabled: true, action: "observe", sensitivity: "" }
    case "balanced":
      return { enabled: true, action: "intercept", sensitivity: "medium" }
    case "strict":
      return { enabled: true, action: "intercept", sensitivity: "high" }
  }
}

/**
 * 获取模式对应的状态标签变体
 * @param mode - 模块模式
 * @returns Badge 变体名称
 */
function getModeBadgeVariant(
  mode: ModuleMode
): "default" | "secondary" | "destructive" | "outline" {
  switch (mode) {
    case "disabled":
      return "secondary"
    case "observe":
      return "outline"
    case "balanced":
      return "default"
    case "strict":
      return "destructive"
  }
}

interface GlobalSkipPathByPhaseCardProps {
  settings: ProtectionSettings
  canManage: boolean
}

/**
 * 全局内置 OWASP 开关配置。
 */

/**
 * 升级阶梯允许的动作白名单；与后端
 * POST /protection/:id/escalation 的校验（internal/admin/protect/escalation.go）
 * 保持一致。
 */
const ESCALATION_ACTION_OPTIONS = [
  "intercept",
  "drop",
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
] as const

/**
 * 全局按类别灵敏度配置（POST /protection/:id/sensitivity）。
 *
 * 类别清单与后端 OWASP 检测类别一致（internal/waf/owasp/owasp.go 的
 * OWASPCategory 常量全集）。
 */
const SENSITIVITY_CATEGORIES: {
  category: string
  nameKey: string
  descKey: string
}[] = [
  { category: "sqli", nameKey: "globalSensitivity.categories.sqli", descKey: "globalSensitivity.categories.sqliDesc" },
  { category: "xss", nameKey: "globalSensitivity.categories.xss", descKey: "globalSensitivity.categories.xssDesc" },
  { category: "cmd_injection", nameKey: "globalSensitivity.categories.cmdInjection", descKey: "globalSensitivity.categories.cmdInjectionDesc" },
  { category: "webshell", nameKey: "globalSensitivity.categories.webshell", descKey: "globalSensitivity.categories.webshellDesc" },
  { category: "revshell", nameKey: "globalSensitivity.categories.revshell", descKey: "globalSensitivity.categories.revshellDesc" },
  { category: "path_traversal", nameKey: "globalSensitivity.categories.pathTraversal", descKey: "globalSensitivity.categories.pathTraversalDesc" },
  { category: "ssrf", nameKey: "globalSensitivity.categories.ssrf", descKey: "globalSensitivity.categories.ssrfDesc" },
  { category: "xxe", nameKey: "globalSensitivity.categories.xxe", descKey: "globalSensitivity.categories.xxeDesc" },
  { category: "ldap_injection", nameKey: "globalSensitivity.categories.ldapInjection", descKey: "globalSensitivity.categories.ldapInjectionDesc" },
  { category: "file_upload", nameKey: "globalSensitivity.categories.fileUpload", descKey: "globalSensitivity.categories.fileUploadDesc" },
  { category: "protocol_violation", nameKey: "globalSensitivity.categories.protocolViolation", descKey: "globalSensitivity.categories.protocolViolationDesc" },
  { category: "nosql_injection", nameKey: "globalSensitivity.categories.nosqlInjection", descKey: "globalSensitivity.categories.nosqlInjectionDesc" },
  { category: "template_injection", nameKey: "globalSensitivity.categories.templateInjection", descKey: "globalSensitivity.categories.templateInjectionDesc" },
  { category: "jndi_injection", nameKey: "globalSensitivity.categories.jndiInjection", descKey: "globalSensitivity.categories.jndiInjectionDesc" },
  { category: "crlf_injection", nameKey: "globalSensitivity.categories.crlfInjection", descKey: "globalSensitivity.categories.crlfInjectionDesc" },
  { category: "expression_language", nameKey: "globalSensitivity.categories.expressionLanguage", descKey: "globalSensitivity.categories.expressionLanguageDesc" },
  { category: "deserialization", nameKey: "globalSensitivity.categories.deserialization", descKey: "globalSensitivity.categories.deserializationDesc" },
  { category: "graphql_injection", nameKey: "globalSensitivity.categories.graphqlInjection", descKey: "globalSensitivity.categories.graphqlInjectionDesc" },
]

/**
 * 等级 -> i18n 展示键；value 与后端归一化值一致。
 */
const SENSITIVITY_LEVEL_OPTIONS: { value: SensitivityLevel; labelKey: string }[] = [
  { value: "low", labelKey: "globalSensitivity.levels.low" },
  { value: "mid", labelKey: "globalSensitivity.levels.mid" },
  { value: "high", labelKey: "globalSensitivity.levels.high" },
  { value: "very_high", labelKey: "globalSensitivity.levels.very_high" },
  { value: "strict", labelKey: "globalSensitivity.levels.strict" },
  { value: "off", labelKey: "globalSensitivity.levels.off" },
]

function GlobalOwaspToggleCard({
  settings,
  canManage,
}: {
  settings: ProtectionSettings
  canManage: boolean
}) {
  const { t, i18n } = useTranslation()
  const useChinese = (i18n.resolvedLanguage ?? i18n.language).startsWith("zh")
  const fallback = (zh: string, en: string) => (useChinese ? zh : en)
  const updateSettings = useProtectionSettingsUpdate()
  const [enabled, setEnabled] = useState(
    Boolean(settings.builtin_owasp_enabled)
  )
  const [sensitivity, setSensitivity] = useState<string>(
    settings.builtin_owasp_sensitivity || "mid"
  )
  const [dirty, setDirty] = useState(false)

  const handleToggle = (next: boolean) => {
    if (!canManage) return
    setEnabled(next)
    setDirty(true)
  }

  const handleSensitivityChange = (next: string) => {
    if (!canManage) return
    setSensitivity(next)
    setDirty(true)
  }

  const handleSave = async () => {
    if (!canManage) return
    try {
      await updateSettings.execute({
        builtin_owasp_enabled: enabled,
        builtin_owasp_sensitivity: sensitivity,
      })
      setDirty(false)
      toast.success(
        t("attacks.globalOwaspSaveSuccess", {
          defaultValue: fallback(
            "全局内置 OWASP 已保存。",
            "Global built-in OWASP saved."
          ),
        })
      )
    } catch {
      toast.error(
        t("attacks.globalOwaspSaveFailed", {
          defaultValue: fallback(
            "全局内置 OWASP 保存失败。",
            "Failed to save global built-in OWASP."
          ),
        })
      )
    }
  }

  const handleReset = () => {
    setEnabled(Boolean(settings.builtin_owasp_enabled))
    setSensitivity(settings.builtin_owasp_sensitivity || "mid")
    setDirty(false)
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <IconBug className="h-5 w-5 text-primary" />
          {t("attacks.globalOwaspTitle", {
            defaultValue: fallback("全局内置 OWASP", "Global built-in OWASP"),
          })}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0 space-y-1">
            <p className="text-sm font-medium">
              {t("attacks.globalOwaspEnabled", {
                defaultValue: fallback(
                  "启用内置 OWASP 引擎阶段",
                  "Enable built-in OWASP engine phase"
                ),
              })}
            </p>
            <p className="text-xs text-muted-foreground">
              {t("attacks.globalOwaspHint", {
                defaultValue: fallback(
                  "关闭后任何站点都不会装配 OWASP 阶段；站点级开关保持独立显示。",
                  "When off, no site assembles the OWASP phase; site-level switches stay independent."
                ),
              })}
            </p>
          </div>
          <Switch
            checked={enabled}
            onCheckedChange={handleToggle}
            disabled={!canManage || updateSettings.loading}
            aria-label={t("attacks.globalOwaspEnabled")}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="global-owasp-sensitivity">
            {t("attacks.globalOwaspSensitivity", {
              defaultValue: fallback("全局敏感度", "Global sensitivity"),
            })}
          </Label>
          <select
            id="global-owasp-sensitivity"
            value={sensitivity}
            disabled={!canManage}
            onChange={(e) => handleSensitivityChange(e.target.value)}
            className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="off">{t("attacks.sensitivityValues.off")}</option>
            <option value="low">{t("attacks.sensitivityValues.low")}</option>
            <option value="mid">{t("attacks.sensitivityValues.medium")}</option>
            <option value="high">{t("attacks.sensitivityValues.high")}</option>
            <option value="very_high">
              {t("attacks.sensitivityValues.very_high")}
            </option>
            <option value="strict">
              {t("attacks.sensitivityValues.strict")}
            </option>
          </select>
        </div>
        <div className="flex flex-col-reverse gap-2 border-t pt-4 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="outline"
            disabled={!canManage || !dirty || updateSettings.loading}
            onClick={handleReset}
          >
            {t("common.cancel", {
              defaultValue: fallback("取消", "Cancel"),
            })}
          </Button>
          <Button
            type="button"
            disabled={!canManage || !dirty || updateSettings.loading}
            onClick={handleSave}
          >
            {updateSettings.loading
              ? t("common.saving", {
                  defaultValue: fallback("保存中...", "Saving..."),
                })
              : t("common.save", {
                  defaultValue: fallback("保存", "Save"),
                })}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/**
 * 全局按类别灵敏度配置（后端 POST /protection/:id/sensitivity）。
 *
 * id 依据后端 handler 校验规则（internal/admin/protect/sensitivity.go），
 * "global" 为全局保护配置；类别灵敏度是 UI 的规范来源，保存时后端会清空旧字段
 * owasp_modules。
 */
function GlobalSensitivityCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation()
  const mutation = useProtectionSensitivityUpdate("global")
  const { data, isLoading, error } = useProtectionSensitivity("global")
  const [draft, setDraft] = useState<Record<string, string> | null>(null)
  const categories = useMemo(
    () =>
      Object.fromEntries(
        SENSITIVITY_CATEGORIES.map((entry) => [
          entry.category,
          data?.category_sensitivity?.[entry.category] ?? "mid",
        ])
      ),
    [data]
  )

  const handleReset = () => {
    setDraft(null)
  }

  const handleSave = async () => {
    if (!canManage || !draft) return
    try {
      await mutation.execute({
        category_sensitivity: {
          ...Object.fromEntries(
            SENSITIVITY_CATEGORIES.map((entry) => [entry.category, categories[entry.category]])
          ),
          ...draft,
        },
      })
      setDraft(null)
      toast.success(t("globalSensitivity.saveSuccess"))
    } catch {
      toast.error(t("globalSensitivity.saveFailed"))
    }
  }

  if (isLoading) {
    return <Skeleton className="h-48 w-full" />
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <IconSettings className="h-5 w-5 text-primary" />
          {t("globalSensitivity.title")}
        </CardTitle>
        <p className="mt-1 text-xs text-muted-foreground">
          {t("globalSensitivity.hint")}
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>
              {error instanceof Error
                ? error.message
                : t("globalSensitivity.loadFailed")}
            </AlertDescription>
          </Alert>
        )}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {SENSITIVITY_CATEGORIES.map((entry) => {
            const level = draft?.[entry.category] ?? categories[entry.category] ?? "mid"
            return (
              <div key={entry.category} className="space-y-1.5">
                <Label htmlFor={`global-sensitivity-${entry.category}`}>
                  {t(entry.nameKey)}
                </Label>
                <Select
                  value={level}
                  disabled={!canManage || mutation.loading}
                  onValueChange={(value) =>
                    setDraft((current) => ({
                      ...(current ?? {}),
                      [entry.category]: value,
                    }))
                  }
                >
                  <SelectTrigger id={`global-sensitivity-${entry.category}`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SENSITIVITY_LEVEL_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {t(option.labelKey)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {t(entry.descKey)}
                </p>
              </div>
            )
          })}
        </div>
        <div className="flex flex-col-reverse gap-2 border-t pt-4 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="outline"
            disabled={!canManage || !draft || mutation.loading}
            onClick={handleReset}
          >
            {t("common.cancel")}
          </Button>
          <Button
            type="button"
            disabled={!canManage || !draft || mutation.loading}
            onClick={handleSave}
          >
            {mutation.loading ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/**
 * 全局升级（escalation）配置（后端 POST /protection/:id/escalation）。
 */
function GlobalEscalationCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation()
  const { data, isLoading, error } = useProtectionEscalation("global")

  if (isLoading) {
    return <Skeleton className="h-48 w-full" />
  }

  if (error || !data) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconAlertTriangle className="h-5 w-5 text-primary" />
            {t("globalEscalation.title")}
          </CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            {t("globalEscalation.hint")}
          </p>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive">
            <AlertDescription>
              {error instanceof Error
                ? error.message
                : t("globalEscalation.loadFailed")}
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    )
  }

  return (
    <GlobalEscalationForm
      key={JSON.stringify(data)}
      initial={{
        enabled: Boolean(data.escalation_enabled),
        windowSecs: data.escalation_window_secs || 60,
        steps: data.escalation_steps ?? [],
      }}
      canManage={canManage}
    />
  )
}

/**
 * 升级表单子组件：挂载时以服务端初值懒初始化，取消/重载由父级 key 重挂载还原。
 */
function GlobalEscalationForm({
  initial,
  canManage,
}: {
  initial: {
    enabled: boolean
    windowSecs: number
    steps: EscalationStepDef[]
  }
  canManage: boolean
}) {
  const { t } = useTranslation()
  const mutation = useProtectionEscalationUpdate("global")
  const [enabled, setEnabled] = useState(initial.enabled)
  const [windowSecs, setWindowSecs] = useState(initial.windowSecs)
  const [steps, setSteps] = useState<EscalationStepDef[]>(initial.steps)

  const updateStep = (index: number, patch: Partial<EscalationStepDef>) => {
    setSteps((current) =>
      current.map((step, stepIndex) =>
        stepIndex === index ? { ...step, ...patch } : step
      )
    )
  }

  const addStep = () => {
    const lastThreshold =
      steps.length > 0 ? steps[steps.length - 1].threshold : 0
    setSteps((current) => [
      ...current,
      { threshold: lastThreshold + 5, action: "intercept" },
    ])
  }

  const removeStep = (index: number) => {
    setSteps((current) => current.filter((_, stepIndex) => stepIndex !== index))
  }

  const handleReset = () => {
    setEnabled(initial.enabled)
    setWindowSecs(initial.windowSecs)
    setSteps(initial.steps)
  }

  const handleSave = async () => {
    if (!canManage) return
    if (windowSecs <= 0) {
      toast.error(t("globalEscalation.windowInvalid"))
      return
    }
    let previous = 0
    for (const step of steps) {
      if (step.threshold <= 0) {
        toast.error(t("globalEscalation.thresholdInvalid"))
        return
      }
      if (step.threshold <= previous) {
        toast.error(t("globalEscalation.orderingInvalid"))
        return
      }
      previous = step.threshold
    }
    try {
      await mutation.execute({
        escalation_enabled: enabled,
        escalation_window_secs: windowSecs,
        escalation_steps: steps,
      })
      toast.success(t("globalEscalation.saveSuccess"))
    } catch {
      toast.error(t("globalEscalation.saveFailed"))
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <IconAlertTriangle className="h-5 w-5 text-primary" />
          {t("globalEscalation.title")}
        </CardTitle>
        <p className="mt-1 text-xs text-muted-foreground">
          {t("globalEscalation.hint")}
        </p>
      </CardHeader>
      <CardContent className="space-y-4">

        <div className="flex items-center justify-between gap-3 rounded-lg border p-3">
          <div className="min-w-0 space-y-0.5">
            <Label className="text-sm font-medium">
              {t("globalEscalation.enabled")}
            </Label>
            <p className="text-xs text-muted-foreground">
              {t("globalEscalation.enabledHint")}
            </p>
          </div>
          <Switch
            checked={enabled}
            disabled={!canManage || mutation.loading}
            onCheckedChange={(checked) => {
              if (canManage) setEnabled(checked)
            }}
          />
        </div>

        {enabled && (
          <div className="space-y-4">
            <div className="max-w-xs space-y-1.5">
              <Label htmlFor="global-escalation-window">
                {t("globalEscalation.window")}
              </Label>
              <div className="flex items-center gap-2">
                <Input
                  id="global-escalation-window"
                  type="number"
                  min={1}
                  value={windowSecs}
                  disabled={!canManage || mutation.loading}
                  onChange={(event) =>
                    setWindowSecs(Math.max(0, Number(event.target.value) || 0))
                  }
                />
                <span className="shrink-0 text-sm text-muted-foreground">
                  {t("common.seconds")}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                {t("globalEscalation.windowHint")}
              </p>
            </div>

            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Label>{t("globalEscalation.steps")}</Label>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={!canManage || mutation.loading}
                  onClick={() => {
                    if (canManage) addStep()
                  }}
                >
                  <IconPlus className="size-4" />
                  {t("globalEscalation.addStep")}
                </Button>
              </div>
              {steps.length === 0 ? (
                <div className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">
                  {t("globalEscalation.noSteps")}
                </div>
              ) : (
                <div className="space-y-2">
                  {steps.map((step, index) => (
                    <div
                      key={index}
                      className="flex flex-wrap items-center gap-3 rounded-lg border p-3"
                    >
                      <div className="flex min-w-0 flex-1 items-center gap-3">
                        <span className="shrink-0 text-xs text-muted-foreground">
                          {t("globalEscalation.stepNumber", {
                            number: index + 1,
                          })}
                        </span>
                        <Input
                          type="number"
                          min={1}
                          className="w-28 shrink-0 font-mono"
                          value={step.threshold}
                          disabled={!canManage || mutation.loading}
                          onChange={(event) =>
                            updateStep(index, {
                              threshold: Math.max(
                                0,
                                Number(event.target.value) || 0
                              ),
                            })
                          }
                          aria-label={t("globalEscalation.threshold")}
                        />
                        <Select
                          value={step.action}
                          disabled={!canManage || mutation.loading}
                          onValueChange={(value) =>
                            updateStep(index, { action: value })
                          }
                        >
                          <SelectTrigger className="min-w-0 flex-1">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {ESCALATION_ACTION_OPTIONS.map((action) => (
                              <SelectItem key={action} value={action}>
                                {t(
                                  `securityEvents.action.${action}`
                                )}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <Button
                        type="button"
                        size="icon-sm"
                        variant="ghost"
                        className="shrink-0 text-muted-foreground hover:text-destructive"
                        aria-label={t("common.delete")}
                        disabled={!canManage || mutation.loading}
                        onClick={() => {
                          if (canManage) removeStep(index)
                        }}
                      >
                        <IconTrash />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        <div className="flex flex-col-reverse gap-2 border-t pt-4 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="outline"
            disabled={!canManage || mutation.loading}
            onClick={handleReset}
          >
            {t("common.cancel")}
          </Button>
          <Button
            type="button"
            disabled={!canManage || mutation.loading}
            onClick={handleSave}
          >
            {mutation.loading ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

/**
 * 全局按阶段跳过路径配置。
 */
function GlobalSkipPathByPhaseCard({
  settings,
  canManage,
}: GlobalSkipPathByPhaseCardProps) {
  const { t, i18n } = useTranslation()
  const useChinese = (i18n.resolvedLanguage ?? i18n.language).startsWith("zh")
  const fallback = (zh: string, en: string) => (useChinese ? zh : en)
  const updateSettings = useProtectionSettingsUpdate()
  const [skipPaths, setSkipPaths] = useState<SkipPathByPhase>(() =>
    parseSkipPathByPhase(settings.skip_path_by_phase)
  )
  const [dirty, setDirty] = useState(false)

  const handleChange = (value: SkipPathByPhase) => {
    if (!canManage) return
    setSkipPaths(value)
    setDirty(true)
  }

  const handleSave = async () => {
    if (!canManage) return
    if (findEmptySkipPaths(skipPaths).length > 0) {
      toast.error(
        t("skipPathByPhase.validationFailed", {
          defaultValue: fallback(
            "请删除空路径，或为每一项输入非空路径。",
            "Remove empty paths or enter a non-empty path for every item."
          ),
        })
      )
      return
    }
    try {
      await updateSettings.execute({
        skip_path_by_phase: toSkipPathByPhasePayload(skipPaths),
      })
      setDirty(false)
      toast.success(
        t("skipPathByPhase.globalSaveSuccess", {
          defaultValue: fallback(
            "全局跳过路径已保存。",
            "Global skipped paths saved."
          ),
        })
      )
    } catch {
      toast.error(
        t("skipPathByPhase.saveFailed", {
          defaultValue: fallback(
            "跳过路径保存失败。",
            "Failed to save skipped paths."
          ),
        })
      )
    }
  }

  const handleReset = () => {
    setSkipPaths(parseSkipPathByPhase(settings.skip_path_by_phase))
    setDirty(false)
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <IconSettings className="h-5 w-5 text-primary" />
          {t("skipPathByPhase.globalTitle", {
            defaultValue: fallback("按阶段跳过路径", "Skip paths by phase"),
          })}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <SkipPathByPhaseEditor
          value={skipPaths}
          onChange={handleChange}
          disabled={!canManage || updateSettings.loading}
          idPrefix="global-skip-path"
        />
        <div className="flex flex-col-reverse gap-2 border-t pt-4 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="outline"
            disabled={!canManage || !dirty || updateSettings.loading}
            onClick={handleReset}
          >
            {t("common.cancel", {
              defaultValue: fallback("取消", "Cancel"),
            })}
          </Button>
          <Button
            type="button"
            disabled={!canManage || !dirty || updateSettings.loading}
            onClick={handleSave}
          >
            {updateSettings.loading
              ? t("common.saving", {
                  defaultValue: fallback("保存中...", "Saving..."),
                })
              : t("common.save", {
                  defaultValue: fallback("保存", "Save"),
                })}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export default function AttacksPage() {
  const { t, i18n } = useTranslation()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const useChinese = (i18n.resolvedLanguage ?? i18n.language).startsWith("zh")
  const fallback = (zh: string, en: string) => (useChinese ? zh : en)
  const { data, isLoading, error, mutate } = useOwaspRules({
    page_size: 500,
  }) as {
    data: OwaspRulesResponse | undefined
    isLoading: boolean
    error: unknown
    mutate: () => void
  }
  const { execute: batchUpdate, loading: isSaving } = useOwaspBatchUpdate()
  const {
    data: protectionSettings,
    isLoading: skipPathsLoading,
    error: skipPathsError,
    mutate: mutateProtectionSettings,
  } = useProtectionSettings()

  const [configMode, setConfigMode] = useState<ConfigMode>("custom")
  const [batchMode, setBatchMode] = useState<ModuleMode>("balanced")
  const [moduleModes, setModuleModes] = useState<Record<string, ModuleMode>>({})
  const [hasChanges, setHasChanges] = useState(false)
  const [initialized, setInitialized] = useState(false)

  // 数据加载后根据实际配置推断初始配置模式
  useEffect(() => {
    if (data?.grouped && !initialized) {
      let hasCustom = false
      for (const mod of MODULES) {
        const rules = data.grouped[mod.category]
        if (rules && rules.length > 0) {
          const mode = inferMode(rules)
          if (mode !== GLOBAL_DEFAULT_MODE) {
            hasCustom = true
            break
          }
        }
      }
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setConfigMode(hasCustom ? "custom" : "global")
      setInitialized(true)
    }
  }, [data, initialized])

  // 从数据推断每个模块的初始模式
  const inferredModes = useMemo(() => {
    if (!data?.grouped) return {}
    const modes: Record<string, ModuleMode> = {}
    for (const mod of MODULES) {
      const rules = data.grouped[mod.category]
      modes[mod.key] = inferMode(rules)
    }
    return modes
  }, [data])

  // 当前显示的模式（跟随全局时统一显示全局默认值）
  const currentModes = useMemo(() => {
    const result: Record<string, ModuleMode> = {}
    for (const mod of MODULES) {
      if (configMode === "global") {
        result[mod.key] = GLOBAL_DEFAULT_MODE
      } else {
        result[mod.key] =
          moduleModes[mod.key] ?? inferredModes[mod.key] ?? GLOBAL_DEFAULT_MODE
      }
    }
    return result
  }, [inferredModes, moduleModes, configMode])

  /**
   * 切换单个模块模式
   */
  const handleModeChange = useCallback(
    (key: string, mode: ModuleMode) => {
      if (!canManage) return
      setModuleModes((prev) => ({ ...prev, [key]: mode }))
      setHasChanges(true)
    },
    [canManage]
  )

  /**
   * 切换全局配置模式
   */
  const handleConfigModeChange = useCallback(
    (mode: ConfigMode) => {
      if (!canManage) return
      setConfigMode(mode)
      setHasChanges(true)
    },
    [canManage]
  )

  /**
   * 批量应用模式到所有模块
   */
  const handleBatchApply = useCallback(() => {
    if (!canManage) return
    const updates: Record<string, ModuleMode> = {}
    for (const mod of MODULES) {
      const rules = data?.grouped?.[mod.category]
      if (rules && rules.length > 0) {
        updates[mod.key] = batchMode
      }
    }
    setModuleModes(updates)
    setHasChanges(true)
    toast.success(t("attacks.batchApplied"))
  }, [batchMode, canManage, data, t])

  /**
   * 保存配置
   */
  const handleSave = useCallback(async () => {
    if (!canManage) return
    if (!data?.grouped) {
      toast.error(t("attacks.dataNotLoaded"))
      return
    }

    if (configMode === "global") {
      try {
        await batchUpdate({ policy_id: data.policy_id, reset_all: true })
        toast.success(t("attacks.followGlobal"))
        setModuleModes({})
        setHasChanges(false)
      } catch (err) {
        toast.error(
          t("attacks.saveFailed", {
            message: err instanceof Error ? err.message : String(err),
          })
        )
      }
      return
    }

    const updates: {
      id: string
      enabled: boolean
      action: string
      sensitivity: string
    }[] = []

    for (const mod of MODULES) {
      const rules = data.grouped[mod.category]
      if (!rules || rules.length === 0) continue

      const mode = currentModes[mod.key]
      const override = modeToOverride(mode)

      for (const rule of rules) {
        updates.push({
          id: rule.id,
          enabled: override.enabled,
          action: override.action,
          sensitivity: override.sensitivity,
        })
      }
    }

    if (updates.length === 0) {
      toast.error(t("attacks.noModules"))
      return
    }

    try {
      await batchUpdate({ policy_id: data.policy_id, rules: updates })
      toast.success(t("attacks.saveSuccess"))
      setHasChanges(false)
    } catch (err) {
      toast.error(
        t("attacks.saveFailed", {
          message: err instanceof Error ? err.message : String(err),
        })
      )
    }
  }, [canManage, data, currentModes, configMode, batchUpdate, t])

  /**
   * 取消修改，重置状态
   */
  const handleCancel = useCallback(() => {
    setModuleModes({})
    setHasChanges(false)
    if (data?.grouped) {
      let hasCustom = false
      for (const mod of MODULES) {
        const rules = data.grouped[mod.category]
        if (rules && rules.length > 0) {
          const mode = inferMode(rules)
          if (mode !== GLOBAL_DEFAULT_MODE) {
            hasCustom = true
            break
          }
        }
      }
      setConfigMode(hasCustom ? "custom" : "global")
    }
    toast.info(t("attacks.cancelled"))
  }, [data, t])

  // 加载错误处理
  if (error) {
    const errMsg = error instanceof Error ? error.message : String(error)
    return (
      <div className="space-y-6">
        <PageHeader
          title={t("attacks.title")}
          description={t("attacks.description")}
        />
        <div className="flex h-40 items-center justify-center gap-2 rounded-lg border border-destructive/20 bg-destructive/5 text-destructive">
          <IconAlertTriangle className="h-5 w-5" />
          <span>
            {t("attacks.loadFailed", {
              message: errMsg || t("common.unknownError"),
            })}
          </span>
          <Button variant="outline" size="sm" onClick={() => mutate()}>
            <IconRefresh className="mr-1 h-4 w-4" />
            {t("common.retry")}
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("attacks.title")}
        description={t("attacks.description")}
      />

      {!authLoading && !canManage && (
        <Alert>
          <AlertDescription>{t("common.readOnlyHint")}</AlertDescription>
        </Alert>
      )}

      {/* 防护模式配置 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconSettings className="h-5 w-5 text-primary" />
            {t("attacks.protectionMode")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            {/* 配置模式切换 */}
            <RadioGroup
              value={configMode}
              disabled={!canManage}
              onValueChange={(v) => handleConfigModeChange(v as ConfigMode)}
              className="flex items-center gap-0 rounded-lg border p-1"
            >
              <div className="flex items-center">
                <RadioGroupItem
                  value="global"
                  id="mode-global"
                  className="sr-only"
                />
                <Label
                  htmlFor="mode-global"
                  className={cn(
                    "cursor-pointer rounded-md px-4 py-1.5 text-sm font-medium transition-colors",
                    configMode === "global"
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  {t("attacks.followGlobalConfig")}
                </Label>
              </div>
              <div className="flex items-center">
                <RadioGroupItem
                  value="custom"
                  id="mode-custom"
                  className="sr-only"
                />
                <Label
                  htmlFor="mode-custom"
                  className={cn(
                    "cursor-pointer rounded-md px-4 py-1.5 text-sm font-medium transition-colors",
                    configMode === "custom"
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  {t("attacks.useCustomConfig")}
                </Label>
              </div>
            </RadioGroup>

            {/* 批量配置 */}
            {configMode === "custom" && (
              <div className="flex items-center gap-2 rounded-lg border bg-muted/30 p-2">
                <span className="text-sm text-muted-foreground">
                  {t("attacks.batchConfig")}
                </span>
                <select
                  value={batchMode}
                  disabled={!canManage}
                  onChange={(e) => setBatchMode(e.target.value as ModuleMode)}
                  className="h-8 rounded-md border border-input bg-background px-2 text-xs outline-none focus:ring-2 focus:ring-ring"
                >
                  {MODE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {t(opt.labelKey)}
                    </option>
                  ))}
                </select>
                <Button
                  variant="default"
                  size="sm"
                  onClick={handleBatchApply}
                  disabled={!canManage}
                  className="h-8"
                >
                  <IconCopy className="mr-1 h-3.5 w-3.5" />
                  {t("attacks.apply")}
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {skipPathsLoading ? (
        <Skeleton className="h-56 w-full" />
      ) : protectionSettings ? (
        <>
          <GlobalOwaspToggleCard
            settings={protectionSettings}
            canManage={canManage}
          />
          <GlobalSensitivityCard canManage={canManage} />
          <GlobalEscalationCard canManage={canManage} />
          <GlobalSkipPathByPhaseCard
            key={JSON.stringify(protectionSettings.skip_path_by_phase)}
            settings={protectionSettings}
            canManage={canManage}
          />
        </>
      ) : (
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 py-5 text-sm text-destructive">
            <IconAlertTriangle className="h-4 w-4" />
            <span>
              {t("skipPathByPhase.loadFailed", {
                defaultValue: fallback(
                  "无法加载按阶段跳过路径配置。",
                  "Unable to load skipped-path configuration."
                ),
              })}
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => mutateProtectionSettings()}
            >
              {t("common.retry", {
                defaultValue: fallback("重试", "Retry"),
              })}
            </Button>
            {skipPathsError instanceof Error && (
              <span className="text-xs text-muted-foreground">
                {skipPathsError.message}
              </span>
            )}
          </CardContent>
        </Card>
      )}

      {/* 模块列表 */}
      <Card>
        <CardHeader className="border-b px-6 py-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">
              {t("attacks.moduleName")}
            </CardTitle>
            <Badge variant="secondary" className="text-xs">
              {t("common.total", { count: MODULES.length })}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="divide-y p-0">
          {isLoading
            ? Array.from({ length: MODULES.length }).map((_, i) => (
                <div key={i} className="flex items-center gap-4 px-6 py-4">
                  <Skeleton className="h-10 w-10 rounded-lg" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-full" />
                    <Skeleton className="h-4 w-full" />
                  </div>
                  <Skeleton className="h-4 w-full max-w-[260px]" />
                </div>
              ))
            : MODULES.map((mod) => {
                const mode = currentModes[mod.key]
                const rules = data?.grouped?.[mod.category]
                const hasRules = rules && rules.length > 0
                const isDisabled =
                  !canManage || configMode === "global" || !hasRules || isSaving
                const ModIcon = mod.icon
                const modeLabel =
                  MODE_OPTIONS.find((o) => o.value === mode)?.labelKey || ""

                return (
                  <div
                    key={mod.key}
                    className={cn(
                      "flex flex-col gap-4 px-6 py-4 transition-colors sm:flex-row sm:items-center sm:justify-between",
                      hasChanges &&
                        configMode === "custom" &&
                        moduleModes[mod.key] !== undefined
                        ? "bg-primary/[0.02]"
                        : ""
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                        <ModIcon className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{t(mod.nameKey)}</span>
                          {!hasRules && (
                            <span className="text-xs text-muted-foreground">
                              ({t("attacks.noRules")})
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground">
                          {t(mod.descKey)}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <Badge
                        variant={getModeBadgeVariant(mode)}
                        className="shrink-0 text-xs"
                      >
                        {t(modeLabel)}
                      </Badge>
                      <div className="flex items-center gap-1 rounded-lg border bg-muted/30 p-1">
                        {MODE_OPTIONS.map((opt) => (
                          <button
                            key={opt.value}
                            type="button"
                            disabled={isDisabled}
                            onClick={() => handleModeChange(mod.key, opt.value)}
                            className={cn(
                              "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                              mode === opt.value
                                ? "bg-primary text-primary-foreground shadow-sm"
                                : "text-muted-foreground hover:bg-muted",
                              isDisabled && "cursor-not-allowed opacity-50"
                            )}
                          >
                            {t(opt.labelKey)}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )
              })}
        </CardContent>

        {/* 底部操作栏 */}
        <div className="flex items-center justify-end gap-3 border-t px-6 py-4">
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={!canManage || !hasChanges || isSaving || isLoading}
          >
            {t("common.cancel")}
          </Button>
          <Button
            onClick={handleSave}
            disabled={!canManage || isLoading || isSaving}
          >
            {isSaving ? (
              <>
                <IconSettings className="mr-2 h-4 w-4 animate-spin" />
                {t("common.saving")}
              </>
            ) : (
              <>
                <IconCheck className="mr-2 h-4 w-4" />
                {t("common.save")}
              </>
            )}
          </Button>
        </div>
      </Card>
    </div>
  )
}
