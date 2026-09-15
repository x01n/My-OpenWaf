"use client"

import { useState, useMemo, useCallback } from "react"
import { useTranslation } from "react-i18next"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
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
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { SkipPathByPhaseEditor } from "@/components/skip-path-by-phase-editor"

import { Skeleton } from "@/components/ui/skeleton"
import { toast } from "sonner"
import {
  IconCopy,
  IconRefresh,
  IconDatabase,
  IconCode,
  IconUpload,
  IconFolder,
  IconTerminal2,
  IconCoffee,
  IconPackages,
  IconBug,
  IconDeviceFloppy,
} from "@tabler/icons-react"
import {
  useDefaultPolicy,
  useOwaspRules,
  useOwaspBatchUpdate,
  useSiteProtectionMutation,
} from "@/hooks/use-api"
import {
  findEmptySkipPaths,
  parseSkipPathByPhase,
  toSkipPathByPhasePayload,
} from "@/lib/skip-path-by-phase"
import { cn } from "@/lib/utils"
import type { Site, SiteUpdate, SkipPathByPhase } from "@/lib/types"

interface OwaspRule {
  id: string
  category: string
  name: string
  description: string
  enabled: boolean
  action?: string
  sensitivity?: string
}

interface OwaspRulesResponse {
  items: OwaspRule[]
  grouped: Record<string, OwaspRule[]>
  total: number
  policy_id: number
}

type ModuleMode = "disabled" | "observe" | "balanced" | "strict"

interface AttackModule {
  key: string
  nameKey: string
  category: string
  icon: React.ElementType
}

const MODULES: AttackModule[] = [
  {
    key: "sqli",
    nameKey: "attacks.sqli",
    category: "sqli",
    icon: IconDatabase,
  },
  { key: "xss", nameKey: "attacks.xss", category: "xss", icon: IconCode },
  {
    key: "file_upload",
    nameKey: "attacks.fileUpload",
    category: "file_upload",
    icon: IconUpload,
  },
  {
    key: "path_traversal",
    nameKey: "attacks.pathTraversal",
    category: "path_traversal",
    icon: IconFolder,
  },
  {
    key: "cmd_injection",
    nameKey: "attacks.cmdInjection",
    category: "cmd_injection",
    icon: IconTerminal2,
  },
  {
    key: "template_injection",
    nameKey: "attacks.templateInjection",
    category: "template_injection",
    icon: IconCode,
  },
  {
    key: "jndi_injection",
    nameKey: "attacks.jndiInjection",
    category: "jndi_injection",
    icon: IconCoffee,
  },
  {
    key: "expression_language",
    nameKey: "attacks.expressionLanguage",
    category: "expression_language",
    icon: IconCode,
  },
  {
    key: "deserialization",
    nameKey: "attacks.deserialization",
    category: "deserialization",
    icon: IconPackages,
  },
  {
    key: "webshell",
    nameKey: "attacks.webshell",
    category: "webshell",
    icon: IconBug,
  },
]

const MODE_OPTIONS: { value: ModuleMode; labelKey: string }[] = [
  { value: "disabled", labelKey: "attacks.disabled" },
  { value: "observe", labelKey: "attacks.observe" },
  { value: "balanced", labelKey: "attacks.balanced" },
  { value: "strict", labelKey: "attacks.strict" },
]

const GLOBAL_DEFAULT_MODE: ModuleMode = "balanced"

type TriState = "inherit" | "on" | "off"
type SkipPathOverrideMode = "inherit" | "override"

/**
 * 站点防护动作可选集合。
 * 与后端 internal/admin/shared.ValidateRuleAction 的白名单一致
 * （IsValid 减去 allow/tag），并排除 redirect。
 * `rl_`/`ow_`/`cv_`（rate_limit_action / owasp_action / cve_action）
 * 共用同一集合：后端均为 ValidateActionWithoutRedirectTarget 校验。
 * challenge 会转换为全局配置的质询类型渲染，可选。
 */
const ACTION_OPTIONS = [
  "intercept",
  "observe",
  "drop",
  "challenge",
  "rate_limit",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
] as const

/**
 * OWASP 灵敏度可选集合。
 * 与后端 owasp.normalizeSensitivityLevel 的合法值一致（mid 与 medium 等价），
 * 前端统一提交 `mid`。
 */
const SENSITIVITY_OPTIONS = [
  "low",
  "mid",
  "high",
  "very_high",
  "strict",
  "off",
] as const

/** 攻击保护级别。与后端 store.SiteProtectionModeProtect / Observe 常量一致。 */
const PROTECTION_LEVEL_OPTIONS = ["protect", "observe"] as const

const ACTION_LABEL_KEYS: Record<string, string> = {
  intercept: "securityEvents.action.intercept",
  observe: "securityEvents.action.observe",
  drop: "securityEvents.action.drop",
  challenge: "securityEvents.action.challenge",
  rate_limit: "securityEvents.action.rate_limit",
  captcha_challenge: "securityEvents.action.captcha_challenge",
  shield_challenge: "securityEvents.action.shield_challenge",
  chain_challenge: "securityEvents.action.chain_challenge",
}

/** 站点动作空串/缺失 = 继承全局，等价于「继承全局」选项。 */
function actionToOption(value: string | undefined): string {
  return value && ACTION_OPTIONS.includes(value as never) ? value : "inherit"
}

function optionToAction(option: string): string {
  return option === "inherit" ? "" : option
}

/** 后端 OWASPSensitivity 历史值可能是 medium；两档归一化显示为 mid。 */
function sensitivityToOption(value: string | undefined): string {
  const normalized =
    value === "medium" ? "mid" : (value ?? "")
  return (SENSITIVITY_OPTIONS as readonly string[]).includes(normalized)
    ? normalized
    : "mid"
}

function toTriState(v: boolean | null | undefined): TriState {
  if (v === true) return "on"
  if (v === false) return "off"
  return "inherit"
}

function fromTriState(v: TriState): boolean | null {
  if (v === "on") return true
  if (v === "off") return false
  return null
}

function TriStateToggle({
  value,
  onChange,
  idPrefix,
}: {
  value: TriState
  onChange: (v: TriState) => void
  idPrefix: string
}) {
  const { t } = useTranslation()
  const opts: { v: TriState; k: string }[] = [
    { v: "inherit", k: "sites.detail.dynOverride.inherit" },
    { v: "on", k: "sites.detail.dynOverride.on" },
    { v: "off", k: "sites.detail.dynOverride.off" },
  ]
  return (
    <div className="inline-flex items-center gap-1 rounded-md border p-0.5">
      {opts.map((opt) => (
        <button
          key={opt.v}
          type="button"
          id={`${idPrefix}-${opt.v}`}
          onClick={() => onChange(opt.v)}
          className={cn(
            "rounded px-2.5 py-1 text-xs transition-colors",
            value === opt.v
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:bg-muted"
          )}
        >
          {t(opt.k)}
        </button>
      ))}
    </div>
  )
}

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

interface ProtectionTabProps {
  site: Site
  canManage: boolean
}

export function ProtectionTab({ site, canManage }: ProtectionTabProps) {
  const { t, i18n } = useTranslation()
  const useChinese = (i18n.resolvedLanguage ?? i18n.language).startsWith("zh")
  const fallback = (zh: string, en: string) => (useChinese ? zh : en)
  const { data: defaultPolicy } = useDefaultPolicy()
  const effectivePolicyId = site.policy_id ?? defaultPolicy?.id
  const { data, isLoading } = useOwaspRules(
    effectivePolicyId ? { policy_id: effectivePolicyId, page_size: 500 } : null
  ) as {
    data: OwaspRulesResponse | undefined
    isLoading: boolean
  }
  const { execute: batchUpdate, loading: isSaving } = useOwaspBatchUpdate()
  const updateSite = useSiteProtectionMutation()

  const [owaspState, setOwaspState] = useState<TriState>(() =>
    toTriState(site.owasp_enabled)
  )
  const [cveState, setCveState] = useState<TriState>(() =>
    toTriState(site.cve_enabled)
  )
  const [botState, setBotState] = useState<TriState>(() =>
    toTriState(site.bot_protection_enabled)
  )
  // 攻击保护级别只有 protect / observe 两档是合法输入；
  // default:medium 是历史遗留默认值，不进入下拉选项时回退显示 protect。
  const [protectionMode, setProtectionMode] = useState<string>(() =>
    site.attack_protection_level === "observe" ? "observe" : "protect"
  )
  // OWASP 灵敏度的合法展示值；inherit 仅在 owasp_enabled 为 null 且值为空时出现。
  const [owaspSensitivity, setOwaspSensitivity] = useState<string>(() =>
    site.owasp_sensitivity ? sensitivityToOption(site.owasp_sensitivity) : "inherit"
  )
  // 动作下拉的 inherit 表示「留空、继承全局」。
  const [owaspAction, setOwaspAction] = useState<string>(() =>
    actionToOption(site.owasp_action)
  )
  const [cveAction, setCveAction] = useState<string>(() =>
    actionToOption(site.cve_action)
  )
  const [rateState, setRateState] = useState<TriState>(() =>
    toTriState(site.rate_limit_enabled)
  )
  const [rateWindow, setRateWindow] = useState<number>(() =>
    site.rate_limit_window > 0 ? site.rate_limit_window : 60
  )
  const [rateWindowValid, setRateWindowValid] = useState<boolean>(() =>
    site.rate_limit_window > 0
  )
  const [rateMax, setRateMax] = useState<number>(() =>
    site.rate_limit_max > 0 ? site.rate_limit_max : 300
  )
  const [rateMaxValid, setRateMaxValid] = useState<boolean>(() =>
    site.rate_limit_max > 0
  )
  const [rateAction, setRateAction] = useState<string>(() =>
    actionToOption(site.rate_limit_action)
  )
  const [owaspDirty, setOwaspDirty] = useState(false)
  const [cveDirty, setCveDirty] = useState(false)
  const [rateDirty, setRateDirty] = useState(false)
  const [moduleModes, setModuleModes] = useState<Record<string, ModuleMode>>({})
  const [hasChanges, setHasChanges] = useState(false)
  const [batchMode, setBatchMode] = useState<ModuleMode>("balanced")
  const [skipPathMode, setSkipPathMode] = useState<SkipPathOverrideMode>(() =>
    site.skip_path_by_phase == null ? "inherit" : "override"
  )
  const [skipPaths, setSkipPaths] = useState<SkipPathByPhase>(() =>
    parseSkipPathByPhase(site.skip_path_by_phase)
  )
  const [skipPathsDirty, setSkipPathsDirty] = useState(false)

  const inferredModes = useMemo(() => {
    if (!data?.grouped) return {}
    const modes: Record<string, ModuleMode> = {}
    for (const mod of MODULES) {
      modes[mod.key] = inferMode(data.grouped[mod.category])
    }
    return modes
  }, [data])

  const currentModes = useMemo(() => {
    const result: Record<string, ModuleMode> = {}
    for (const mod of MODULES) {
      result[mod.key] =
        moduleModes[mod.key] ?? inferredModes[mod.key] ?? GLOBAL_DEFAULT_MODE
    }
    return result
  }, [inferredModes, moduleModes])

  const handleModeChange = useCallback(
    (key: string, mode: ModuleMode) => {
      if (!canManage) return
      setModuleModes((prev) => ({ ...prev, [key]: mode }))
      setHasChanges(true)
    },
    [canManage]
  )

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

  const handleTriStateChange = (
    key: "owasp" | "cve" | "bot" | "rate",
    value: TriState
  ) => {
    if (!canManage) return
    const payload: SiteUpdate = {}
    if (key === "owasp") {
      const opt = owaspSensitivity === "inherit" ? "" : owaspSensitivity
      const action = optionToAction(owaspAction)
      setOwaspState(value)
      payload.owasp_enabled = fromTriState(value)
      // 与后端 clearInheritedProtectionOverrides 对齐：
      // 继承(null)时从属字段一并清空，启用时提交当前面板值。
      payload.owasp_sensitivity = value === "on" ? opt : ""
      payload.owasp_action = value === "on" ? action : ""
      if (value === "on") {
        setOwaspSensitivity("")
        setOwaspDirty(false)
      }
    } else if (key === "cve") {
      const action = optionToAction(cveAction)
      setCveState(value)
      payload.cve_enabled = fromTriState(value)
      payload.cve_action = value === "on" ? action : ""
      if (value === "on") {
        setCveAction("")
        setCveDirty(false)
      }
    } else if (key === "bot") {
      setBotState(value)
      payload.bot_protection_enabled = fromTriState(value)
    } else if (key === "rate") {
      setRateState(value)
      payload.rate_limit_enabled = fromTriState(value)
      // 继承(null)时后端清零 window/max/action，前端同样不携带赋值字段。
      if (value === "on") {
        payload.rate_limit_window = rateWindow
        payload.rate_limit_max = rateMax
        payload.rate_limit_action = optionToAction(rateAction)
        setRateDirty(false)
      }
    }
    updateSite
      .execute({ id: site.id, data: payload })
      .then(() => toast.success(t("common.saveSuccess")))
      .catch(() => toast.error(t("common.operationFailed")))
  }

  /** OWASP 灵敏度 + 动作局部保存：owasp_enabled 为 null（继承）时后端会清空两者。 */
  const handleSaveOwaspDetail = async () => {
    if (!canManage || owaspState === "off") return
    try {
      await updateSite.execute({
        id: site.id,
        data: {
          owasp_sensitivity:
            owaspSensitivity === "inherit" ? "" : owaspSensitivity,
          owasp_action: optionToAction(owaspAction),
        },
      })
      setOwaspDirty(false)
      toast.success(t("common.saveSuccess"))
    } catch {
      toast.error(t("common.operationFailed"))
    }
  }

  /** CVE 动作局部保存：cve_enabled 为 null（继承）时后端会清空 cve_action。 */
  const handleSaveCveDetail = async () => {
    if (!canManage || cveState === "off") return
    try {
      await updateSite.execute({
        id: site.id,
        data: { cve_action: optionToAction(cveAction) },
      })
      setCveDirty(false)
      toast.success(t("common.saveSuccess"))
    } catch {
      toast.error(t("common.operationFailed"))
    }
  }

  /** 限流窗口/最大值/动作局部保存；enabled 为继承时后端自动清空三个字段。 */
  const handleSaveRateDetail = async () => {
    if (!canManage || rateState === "off" || !rateWindowValid || !rateMaxValid)
      return
    try {
      await updateSite.execute({
        id: site.id,
        data: {
          rate_limit_window: rateWindow,
          rate_limit_max: rateMax,
          rate_limit_action: optionToAction(rateAction),
        },
      })
      setRateDirty(false)
      toast.success(t("common.saveSuccess"))
    } catch {
      toast.error(t("common.operationFailed"))
    }
  }

  /** 攻击保护级别切换：携带字段保存 + 前端四组开关即时回落。 */
  const handleProtectionModeChange = (value: string) => {
    if (!canManage) return
    setProtectionMode(value)
    updateSite
      .execute({ id: site.id, data: { attack_protection_level: value } })
      .then(() => {
        setOwaspState("on")
        if (value === "observe") setOwaspAction("observe")
        setCveState("on")
        if (value === "observe") setCveAction("observe")
        setRateState("on")
        setRateAction(value === "observe" ? "observe" : "rate_limit")
        setBotState(value === "observe" ? "off" : "on")
        setOwaspDirty(false)
        setCveDirty(false)
        setRateDirty(false)
        toast.success(t("common.saveSuccess"))
      })
      .catch(() => toast.error(t("common.operationFailed")))
  }

  const handleSkipPathModeChange = (value: SkipPathOverrideMode) => {
    if (!canManage) return
    setSkipPathMode(value)
    setSkipPathsDirty(true)
  }

  const handleSkipPathsChange = (value: SkipPathByPhase) => {
    if (!canManage) return
    setSkipPaths(value)
    setSkipPathsDirty(true)
  }

  const handleResetSkipPaths = () => {
    setSkipPathMode(site.skip_path_by_phase == null ? "inherit" : "override")
    setSkipPaths(parseSkipPathByPhase(site.skip_path_by_phase))
    setSkipPathsDirty(false)
  }

  const handleSaveSkipPaths = async () => {
    if (!canManage) return
    if (
      skipPathMode === "override" &&
      findEmptySkipPaths(skipPaths).length > 0
    ) {
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
      await updateSite.execute({
        id: site.id,
        data: {
          skip_path_by_phase:
            skipPathMode === "inherit"
              ? null
              : toSkipPathByPhasePayload(skipPaths),
        },
      })
      setSkipPathsDirty(false)
      toast.success(
        t("skipPathByPhase.siteSaveSuccess", {
          defaultValue: fallback(
            "本站跳过路径配置已保存。",
            "Site skipped-path configuration saved."
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

  const handleSaveModules = async () => {
    if (!canManage || !effectivePolicyId || !data?.grouped) return

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

    if (updates.length === 0) return

    try {
      await batchUpdate({ policy_id: effectivePolicyId, rules: updates })
      toast.success(t("attacks.saveSuccess"))
      setHasChanges(false)
    } catch (err) {
      toast.error(
        t("attacks.saveFailed", {
          message: err instanceof Error ? err.message : String(err),
        })
      )
    }
  }

  return (
    <fieldset
      disabled={!canManage}
      className="m-0 min-w-0 space-y-4 border-0 p-0"
    >
      {/* 全局防护开关 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {t("sites.detail.protectionSwitches")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="min-w-0 space-y-0.5">
              <Label className="text-sm font-medium">
                {t("sites.detail.attackLevel")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.attackLevelDesc")}
              </p>
            </div>
            <Select
              value={protectionMode}
              onValueChange={handleProtectionModeChange}
              disabled={!canManage}
            >
              <SelectTrigger className="h-7 w-28 shrink-0 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PROTECTION_LEVEL_OPTIONS.map((level) => (
                  <SelectItem key={level} value={level}>
                    {t(
                      level === "protect"
                        ? "sites.detail.attackLevelProtect"
                        : "sites.detail.attackLevelObserve"
                    )}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="min-w-0 space-y-0.5">
              <Label className="text-sm font-medium">
                OWASP {t("sites.detail.protection")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.owaspDesc")}
              </p>
            </div>
            <TriStateToggle
              value={owaspState}
              onChange={(v) => handleTriStateChange("owasp", v)}
              idPrefix="prot-owasp"
            />
          </div>

          {owaspState !== "off" && (
            <div className="grid items-center gap-4 rounded-lg border p-3 sm:grid-cols-[minmax(0,1fr)_auto_auto]">
              <div className="min-w-0 space-y-0.5">
                <Label className="text-sm font-medium">
                  {t("sites.detail.owaspSensitivity")}{" "}
                  <span className="text-xs font-normal text-muted-foreground">
                    ({t("attacks.sensitivityValues.medium")})
                  </span>
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.owaspSensitivityDesc")}
                </p>
              </div>
              <Select
                value={owaspSensitivity}
                onValueChange={(v) => setOwaspSensitivity(v)}
                disabled={owaspState === "inherit"}
              >
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {owaspState === "inherit" && (
                    <SelectItem value="inherit">
                      {t("sites.detail.owaspSensitivityInherit")}
                    </SelectItem>
                  )}
                  {SENSITIVITY_OPTIONS.map((s) => (
                    <SelectItem key={s} value={s}>
                      {t(`attacks.sensitivityValues.${s}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={
                  owaspState === "inherit" || !owaspDirty || updateSite.loading
                }
                onClick={handleSaveOwaspDetail}
              >
                {t("common.save")}
              </Button>
            </div>
          )}

          {owaspState !== "off" && (
            <div className="grid items-center gap-4 rounded-lg border p-3 sm:grid-cols-[minmax(0,1fr)_auto_auto]">
              <div className="min-w-0 space-y-0.5">
                <Label className="text-sm font-medium">
                  OWASP {t("sites.detail.actionLabel")}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.owaspActionDesc")}
                </p>
              </div>
              <Select
                value={owaspAction}
                onValueChange={(v) => setOwaspAction(v)}
                disabled={owaspState === "inherit"}
              >
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {owaspState === "inherit" && (
                    <SelectItem value="inherit">
                      {t("sites.detail.actionInherit")}
                    </SelectItem>
                  )}
                  {ACTION_OPTIONS.map((action) => (
                    <SelectItem key={action} value={action}>
                      {t(ACTION_LABEL_KEYS[action])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={
                  owaspState === "inherit" || !owaspDirty || updateSite.loading
                }
                onClick={handleSaveOwaspDetail}
              >
                {t("common.save")}
              </Button>
            </div>
          )}

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="min-w-0 space-y-0.5">
              <Label className="text-sm font-medium">
                CVE {t("sites.detail.protection")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.cveDesc")}
              </p>
            </div>
            <TriStateToggle
              value={cveState}
              onChange={(v) => handleTriStateChange("cve", v)}
              idPrefix="prot-cve"
            />
          </div>

          {cveState !== "off" && (
            <div className="grid items-center gap-4 rounded-lg border p-3 sm:grid-cols-[minmax(0,1fr)_auto_auto]">
              <div className="min-w-0 space-y-0.5">
                <Label className="text-sm font-medium">
                  CVE {t("sites.detail.actionLabel")}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.cveActionDesc")}
                </p>
              </div>
              <Select
                value={cveAction}
                onValueChange={(v) => setCveAction(v)}
                disabled={cveState === "inherit"}
              >
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {cveState === "inherit" && (
                    <SelectItem value="inherit">
                      {t("sites.detail.actionInherit")}
                    </SelectItem>
                  )}
                  {ACTION_OPTIONS.map((action) => (
                    <SelectItem key={action} value={action}>
                      {t(ACTION_LABEL_KEYS[action])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={
                  cveState === "inherit" || !cveDirty || updateSite.loading
                }
                onClick={handleSaveCveDetail}
              >
                {t("common.save")}
              </Button>
            </div>
          )}

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="min-w-0 space-y-0.5">
              <Label className="text-sm font-medium">
                Bot {t("sites.detail.protection")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.botDesc")}
              </p>
            </div>
            <TriStateToggle
              value={botState}
              onChange={(v) => handleTriStateChange("bot", v)}
              idPrefix="prot-bot"
            />
          </div>
        </CardContent>
      </Card>

      {/* 站点级请求频率限制 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {t("sites.detail.rateLimitTitle")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="min-w-0 space-y-0.5">
              <Label className="text-sm font-medium">
                {t("sites.detail.rateLimitEnabled")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.rateLimitDesc")}
              </p>
            </div>
            <TriStateToggle
              value={rateState}
              onChange={(v) => handleTriStateChange("rate", v)}
              idPrefix="prot-rate"
            />
          </div>

          <div
            className={cn(
              "space-y-4 rounded-lg border p-3",
              rateState === "inherit"
                ? "pointer-events-none opacity-60"
                : rateState === "off"
                  ? "pointer-events-none opacity-40"
                  : ""
            )}
          >
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-[auto_auto_auto_minmax(0,1fr)]">
              <div className="space-y-1.5">
                <Label>{t("sites.detail.rateLimitWindow")}</Label>
                <div className="flex items-center gap-2">
                  <Input
                    type="number"
                    min={1}
                    className="w-24"
                    inputMode="numeric"
                    value={
                      Number.isFinite(rateWindow) ? rateWindow.toString() : ""
                    }
                    onChange={(e) => {
                      const raw = e.target.value.trim()
                      const parsed = raw === "" ? NaN : Number(raw)
                      setRateWindow(parsed)
                      setRateWindowValid(Number.isInteger(parsed) && parsed > 0)
                      setRateDirty(true)
                    }}
                  />
                  <span className="text-sm text-muted-foreground">
                    {t("ccProtection.seconds")}
                  </span>
                </div>
              </div>
              <div className="space-y-1.5">
                <Label>{t("sites.detail.rateLimitMax")}</Label>
                <Input
                  type="number"
                  min={1}
                  className="w-24"
                  inputMode="numeric"
                  value={Number.isFinite(rateMax) ? rateMax.toString() : ""}
                  onChange={(e) => {
                    const raw = e.target.value.trim()
                    const parsed = raw === "" ? NaN : Number(raw)
                    setRateMax(parsed)
                    setRateMaxValid(Number.isInteger(parsed) && parsed > 0)
                    setRateDirty(true)
                  }}
                />
              </div>
              <div className="space-y-1.5">
                <Label>{t("sites.detail.actionLabel")}</Label>
                <Select
                  value={rateAction}
                  onValueChange={(v) => {
                    setRateAction(v)
                    setRateDirty(true)
                  }}
                >
                  <SelectTrigger className="w-36">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {rateState === "inherit" && (
                      <SelectItem value="inherit">
                        {t("sites.detail.actionInherit")}
                      </SelectItem>
                    )}
                    {ACTION_OPTIONS.map((action) => (
                      <SelectItem key={action} value={action}>
                        {t(ACTION_LABEL_KEYS[action])}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {rateState === "inherit" && (
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.rateLimitInheritHint")}
              </p>
            )}
            {!rateWindowValid && (
              <p className="text-xs text-destructive">
                {t("sites.detail.rateLimitWindowInvalid")}
              </p>
            )}
            {!rateMaxValid && (
              <p className="text-xs text-destructive">
                {t("sites.detail.rateLimitMaxInvalid")}
              </p>
            )}
            {rateState === "on" && rateDirty && (
              <div className="flex justify-end border-t pt-3">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!rateWindowValid || !rateMaxValid || updateSite.loading}
                  onClick={handleSaveRateDetail}
                >
                  {t("common.save")}
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {t("skipPathByPhase.siteTitle", {
              defaultValue: fallback(
                "本站按阶段跳过路径",
                "Site skip paths by phase"
              ),
            })}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <RadioGroup
            value={skipPathMode}
            onValueChange={(value) =>
              handleSkipPathModeChange(value as SkipPathOverrideMode)
            }
            aria-label={t("skipPathByPhase.overrideMode", {
              defaultValue: fallback("覆盖模式", "Override mode"),
            })}
            className="grid gap-2 sm:grid-cols-2"
          >
            <div className="flex items-start gap-3 rounded-lg border p-3">
              <RadioGroupItem value="inherit" id="skip-path-inherit" />
              <div className="space-y-1">
                <Label
                  htmlFor="skip-path-inherit"
                  className="cursor-pointer font-medium"
                >
                  {t("skipPathByPhase.inherit", {
                    defaultValue: fallback("继承全局", "Inherit global"),
                  })}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t("skipPathByPhase.inheritHint", {
                    defaultValue: fallback(
                      "保持 null，由本站继承全局映射。",
                      "Keep null so this site inherits the global mapping."
                    ),
                  })}
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3 rounded-lg border p-3">
              <RadioGroupItem value="override" id="skip-path-override" />
              <div className="space-y-1">
                <Label
                  htmlFor="skip-path-override"
                  className="cursor-pointer font-medium"
                >
                  {t("skipPathByPhase.override", {
                    defaultValue: fallback("整体覆盖", "Override all"),
                  })}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t("skipPathByPhase.overrideHint", {
                    defaultValue: fallback(
                      "空映射表示本站明确不跳过任何阶段；非空映射整体替代全局配置。",
                      "An empty map explicitly skips nothing; a non-empty map replaces the global configuration."
                    ),
                  })}
                </p>
              </div>
            </div>
          </RadioGroup>

          {skipPathMode === "override" && (
            <SkipPathByPhaseEditor
              value={skipPaths}
              onChange={handleSkipPathsChange}
              disabled={!canManage || updateSite.loading}
              idPrefix={`site-${site.id}-skip-path`}
            />
          )}

          <div className="flex flex-col-reverse gap-2 border-t pt-4 sm:flex-row sm:justify-end">
            <Button
              type="button"
              variant="outline"
              disabled={!skipPathsDirty || updateSite.loading}
              onClick={handleResetSkipPaths}
            >
              {t("common.cancel", {
                defaultValue: fallback("取消", "Cancel"),
              })}
            </Button>
            <Button
              type="button"
              disabled={!skipPathsDirty || updateSite.loading}
              onClick={handleSaveSkipPaths}
            >
              {updateSite.loading
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

      {/* OWASP 模块详细配置 */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t("attacks.title")}</CardTitle>
            <div className="flex items-center gap-2">
              <select
                value={batchMode}
                onChange={(e) => setBatchMode(e.target.value as ModuleMode)}
                className="h-7 rounded-md border border-input bg-background px-2 text-xs outline-none focus:ring-2 focus:ring-ring"
              >
                {MODE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {t(opt.labelKey)}
                  </option>
                ))}
              </select>
              <Button
                size="sm"
                className="h-7 text-xs"
                onClick={handleBatchApply}
              >
                <IconCopy className="mr-1 h-3 w-3" />
                {t("attacks.apply")}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-hidden rounded-lg border">
            <div className="flex items-center bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
              <span className="flex-1">{t("attacks.moduleName")}</span>
              <span className="w-80 text-right">{t("common.actions")}</span>
            </div>

            <div className="divide-y">
              {isLoading
                ? Array.from({ length: MODULES.length }).map((_, i) => (
                    <div key={i} className="flex items-center gap-4 px-4 py-3">
                      <Skeleton className="h-8 w-8 rounded-lg" />
                      <div className="flex-1 space-y-2">
                        <Skeleton className="h-3 w-24" />
                      </div>
                      <Skeleton className="h-6 w-64" />
                    </div>
                  ))
                : MODULES.map((mod) => {
                    const mode = currentModes[mod.key]
                    const rules = data?.grouped?.[mod.category]
                    const hasRules = rules && rules.length > 0
                    const isDisabled = !hasRules || isSaving
                    const ModIcon = mod.icon
                    const modeLabel =
                      MODE_OPTIONS.find((o) => o.value === mode)?.labelKey || ""

                    return (
                      <div
                        key={mod.key}
                        className={cn(
                          "flex items-center justify-between px-4 py-3 transition-colors",
                          moduleModes[mod.key] !== undefined
                            ? "bg-primary/[0.02]"
                            : ""
                        )}
                      >
                        <div className="flex min-w-0 flex-1 items-center gap-3">
                          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                            <ModIcon className="h-4 w-4 text-primary" />
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">
                                {t(mod.nameKey)}
                              </span>
                              {!hasRules && (
                                <span className="text-xs text-muted-foreground">
                                  ({t("attacks.noRules")})
                                </span>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          <Badge
                            variant={getModeBadgeVariant(mode)}
                            className="h-5 shrink-0 text-[10px]"
                          >
                            {t(modeLabel)}
                          </Badge>
                          <div className="flex items-center gap-1">
                            {MODE_OPTIONS.map((opt) => (
                              <button
                                key={opt.value}
                                type="button"
                                disabled={isDisabled}
                                onClick={() =>
                                  handleModeChange(mod.key, opt.value)
                                }
                                className={cn(
                                  "flex items-center gap-1 rounded-md px-2 py-1 text-xs transition-colors",
                                  mode === opt.value
                                    ? "bg-primary text-primary-foreground"
                                    : "text-muted-foreground hover:bg-muted",
                                  isDisabled && "cursor-not-allowed opacity-50"
                                )}
                              >
                                <span
                                  className={cn(
                                    "h-3 w-3 rounded-full border",
                                    mode === opt.value
                                      ? "border-primary-foreground bg-primary-foreground"
                                      : "border-muted-foreground"
                                  )}
                                >
                                  {mode === opt.value && (
                                    <span className="flex h-full w-full items-center justify-center">
                                      <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                                    </span>
                                  )}
                                </span>
                                {t(opt.labelKey)}
                              </button>
                            ))}
                          </div>
                        </div>
                      </div>
                    )
                  })}
            </div>
          </div>

          {hasChanges && (
            <div className="mt-4 flex justify-end">
              <Button onClick={handleSaveModules} disabled={isSaving}>
                {isSaving ? (
                  <>
                    <IconRefresh className="mr-1 h-4 w-4 animate-spin" />
                    {t("common.saving")}
                  </>
                ) : (
                  <>
                    <IconDeviceFloppy className="mr-1 h-4 w-4" />
                    {t("common.save")}
                  </>
                )}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </fieldset>
  )
}
