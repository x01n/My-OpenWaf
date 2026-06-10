"use client"

import { useEffect, useId, useMemo, useState } from "react"
import {
  AlertTriangle,
  Bot,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Wrench,
  Zap,
  Save,
  ChevronDown,
} from "@/lib/icons"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { PageIntro, Surface } from "@/components/console-shell"
import {
  getDropPolicy,
  getProtectionSettings,
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
  updateProtectionSettings,
  type ProtectionSettings,
} from "@/lib/api"
import { CopyableBlock } from "@/components/log-presentation"
import { assignChangedProtectionField } from "@/lib/protection-settings"
import { getSensitivityConfig } from "@/lib/rules-api"
import { CAPTCHA_TYPE_OPTIONS, type CaptchaType } from "@/lib/security-api"
import {
  getWAFActionMeta,
  nonRedirectWAFActionOptions,
  type WAFActionValue,
} from "@/lib/console"
import { cn } from "@/lib/utils"

const protectionModes = [
  {
    id: "protection",
    label: "防护模式",
    desc: "标准防护，拦截已知攻击",
    icon: ShieldCheck,
    sensitivity: "mid",
  },
  {
    id: "observe",
    label: "观察模式",
    desc: "仅记录不拦截，用于调试",
    icon: Eye,
    sensitivity: "low",
  },
  {
    id: "maintenance",
    label: "维护模式",
    desc: "暂停防护，返回维护页面",
    icon: Wrench,
    sensitivity: "off",
  },
  {
    id: "strict",
    label: "高强度模式",
    desc: "最严格检测，可能误报",
    icon: Zap,
    sensitivity: "strict",
  },
] as const

const sensitivityLevels = [
  { value: "off", label: "无" },
  { value: "low", label: "低" },
  { value: "mid", label: "中" },
  { value: "high", label: "高" },
  { value: "very_high", label: "极高" },
  { value: "strict", label: "严格" },
] as const

const categories = [
  { key: "sqli", label: "SQL 注入" },
  { key: "xss", label: "XSS 跨站脚本" },
  { key: "cmd_injection", label: "命令注入" },
  { key: "ssrf", label: "SSRF 服务端请求伪造" },
  { key: "xxe", label: "XXE 外部实体" },
  { key: "ldap_injection", label: "LDAP 注入" },
  { key: "nosql_injection", label: "NoSQL 注入" },
  { key: "template_injection", label: "模板注入 (SSTI)" },
  { key: "jndi_injection", label: "JNDI 注入" },
  { key: "crlf_injection", label: "CRLF 注入" },
  { key: "expression_language", label: "EL 表达式" },
  { key: "deserialization", label: "反序列化" },
  { key: "graphql_injection", label: "GraphQL" },
  { key: "webshell", label: "Webshell" },
  { key: "revshell", label: "反向 Shell" },
  { key: "path_traversal", label: "路径遍历" },
] as const

const DEFAULT_CVE_AUTO_DROP = true
type CVEAutoDropField = "cve_auto_drop_critical" | "cve_auto_drop_high"
type ProtectionActionField =
  | "builtin_owasp_on_hit"
  | "cve_action"
  | "request_ratelimit_action"
  | "error_ratelimit_action"
  | "auto_ban_action"
type BuiltinDetectionToggleField =
  | "builtin_owasp_enabled"
  | "cve_enabled"
  | "bot_detection_enabled"
type ProtectionToggleField =
  | "captcha_enabled"
  | "shield_enabled"
  | "chain_enabled"
  | "escalation_enabled"
type ProtectionActionBadgeVariant = "outline" | "secondary" | "destructive"

const protectionActionBadgeVariants: Record<
  WAFActionValue,
  ProtectionActionBadgeVariant
> = {
  allow: "outline",
  observe: "outline",
  redirect: "outline",
  rate_limit: "secondary",
  challenge: "secondary",
  captcha_challenge: "secondary",
  shield_challenge: "secondary",
  chain_challenge: "secondary",
  intercept: "destructive",
  drop: "destructive",
}

const protectionPageFields: Array<keyof ProtectionSettings> = [
  "builtin_owasp_enabled",
  "builtin_owasp_sensitivity",
  "builtin_owasp_on_hit",
  "cve_enabled",
  "bot_detection_enabled",
  "maintenance_global_enabled",
  "maintenance_global_html",
  "maintenance_global_status",
  "cve_action",
  "request_ratelimit_action",
  "error_ratelimit_action",
  "auto_ban_action",
  "cve_auto_drop_critical",
  "cve_auto_drop_high",
  "captcha_enabled",
  "shield_enabled",
  "chain_enabled",
  "escalation_enabled",
  "captcha_type",
]

const protectionActionFields: Array<{
  field: ProtectionActionField
  label: string
  fallback: WAFActionValue
}> = [
  { field: "builtin_owasp_on_hit", label: "OWASP 命中", fallback: "intercept" },
  { field: "cve_action", label: "CVE 命中", fallback: "intercept" },
  {
    field: "request_ratelimit_action",
    label: "请求限速",
    fallback: "rate_limit",
  },
  {
    field: "error_ratelimit_action",
    label: "错误限速",
    fallback: "rate_limit",
  },
  { field: "auto_ban_action", label: "自动封禁", fallback: "intercept" },
]

const builtinDetectionToggleFields: Array<{
  field: BuiltinDetectionToggleField
  label: string
  description: string
  hint: string
  icon: typeof ShieldAlert
}> = [
  {
    field: "builtin_owasp_enabled",
    label: "OWASP 内置规则",
    description: "启用 SQL 注入、XSS、命令注入等内置攻击检测。",
    hint: "builtin_owasp_enabled",
    icon: ShieldAlert,
  },
  {
    field: "cve_enabled",
    label: "CVE 检测",
    description: "启用已知漏洞指纹检测，并按 CVE 命中动作处理请求。",
    hint: "cve_enabled",
    icon: Zap,
  },
  {
    field: "bot_detection_enabled",
    label: "Bot 检测",
    description: "启用全局 Bot 评分；保存后同步 Bot 防护页开关。",
    hint: "bot_detection_enabled",
    icon: Bot,
  },
]

const protectionToggleFields: Array<{
  field: ProtectionToggleField
  label: string
  hint: string
}> = [
  { field: "captcha_enabled", label: "验证码", hint: "captcha_challenge" },
  { field: "shield_enabled", label: "5 秒盾", hint: "shield_challenge" },
  { field: "chain_enabled", label: "连锁验证", hint: "chain_challenge" },
  {
    field: "escalation_enabled",
    label: "后续动作升级",
    hint: "challenge → rate_limit → drop",
  },
]

function sameStringRecord(
  a: Record<string, string> = {},
  b: Record<string, string> = {}
) {
  const aKeys = Object.keys(a)
  const bKeys = Object.keys(b)
  return (
    aKeys.length === bKeys.length && aKeys.every((key) => a[key] === b[key])
  )
}

function buildProtectionPagePatch(
  current: ProtectionSettings,
  baseline: ProtectionSettings,
  currentSensitivity: Record<string, string>,
  baselineSensitivity: Record<string, string>
): Partial<ProtectionSettings> {
  const patch: Partial<ProtectionSettings> = {}
  for (const field of protectionPageFields) {
    assignChangedProtectionField(patch, current, baseline, field)
  }
  if (!sameStringRecord(currentSensitivity, baselineSensitivity)) {
    patch.category_sensitivity = currentSensitivity
  }
  return patch
}

function resolveCVEAutoDrop(
  value: boolean | null | undefined,
  fallback = DEFAULT_CVE_AUTO_DROP
) {
  return value ?? fallback
}

function readReloadFailureDetails(error: unknown) {
  return getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
}

function deriveMode(settings: ProtectionSettings): string {
  if (settings.maintenance_global_enabled) return "maintenance"
  if (settings.builtin_owasp_on_hit === "observe") return "observe"
  if (
    settings.builtin_owasp_sensitivity === "high" ||
    settings.builtin_owasp_sensitivity === "strict"
  )
    return "strict"
  return "protection"
}

export default function ProtectionPage() {
  const captchaTypeId = useId()
  const maintenanceStatusId = useId()
  const maintenanceHtmlId = useId()
  const [settings, setSettings] = useState<ProtectionSettings | null>(null)
  const [baselineSettings, setBaselineSettings] =
    useState<ProtectionSettings | null>(null)
  const [sensitivity, setSensitivity] = useState<Record<string, string>>({})
  const [baselineSensitivity, setBaselineSensitivity] = useState<
    Record<string, string>
  >({})
  const [saving, setSaving] = useState(false)
  const [activeMode, setActiveMode] = useState("protection")
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  function updateSetting<K extends keyof ProtectionSettings>(
    field: K,
    value: ProtectionSettings[K]
  ) {
    setSettings((current) => (current ? { ...current, [field]: value } : current))
  }

  function applyLoadedProtectionState(
    data: ProtectionSettings,
    dropPolicy: Awaited<ReturnType<typeof getDropPolicy>>,
    loadedSensitivity: Record<string, string>
  ) {
    const merged = {
      ...data,
      cve_auto_drop_critical: resolveCVEAutoDrop(
        data.cve_auto_drop_critical,
        dropPolicy.cve_auto_drop_critical
      ),
      cve_auto_drop_high: resolveCVEAutoDrop(
        data.cve_auto_drop_high,
        dropPolicy.cve_auto_drop_high
      ),
    }
    const nextSensitivity =
      loadedSensitivity ?? merged.category_sensitivity ?? {}
    setSettings(merged)
    setBaselineSettings(merged)
    setSensitivity(nextSensitivity)
    setBaselineSensitivity(nextSensitivity)
    setActiveMode(deriveMode(merged))
  }

  async function reloadProtectionState() {
    const [data, dropPolicy, sensitivityConfig] = await Promise.all([
      getProtectionSettings(),
      getDropPolicy(),
      getSensitivityConfig("global"),
    ])
    applyLoadedProtectionState(
      data,
      dropPolicy,
      sensitivityConfig.category_sensitivity ?? data.category_sensitivity ?? {}
    )
  }

  useEffect(() => {
    Promise.all([
      getProtectionSettings(),
      getDropPolicy(),
      getSensitivityConfig("global"),
    ])
      .then(([data, dropPolicy, sensitivityConfig]) => {
        applyLoadedProtectionState(
          data,
          dropPolicy,
          sensitivityConfig.category_sensitivity ??
            data.category_sensitivity ??
            {}
        )
      })
      .catch((err) =>
        toast.error(err instanceof Error ? err.message : "加载防护配置失败")
      )
  }, [])

  const modules = useMemo(() => {
    return sensitivity
  }, [sensitivity])

  function setModuleSensitivity(key: string, value: string) {
    setSensitivity({ ...modules, [key]: value })
  }

  function batchSetSensitivity(value: string) {
    const newModules: Record<string, string> = {}
    for (const cat of categories) {
      newModules[cat.key] = value
    }
    setSensitivity(newModules)
  }

  function applyMode(modeId: string) {
    if (!settings) return
    setActiveMode(modeId)
    const mode = protectionModes.find((m) => m.id === modeId)
    if (!mode) return

    const next = { ...settings }
    switch (modeId) {
      case "protection":
        next.builtin_owasp_enabled = true
        next.builtin_owasp_on_hit = "intercept"
        next.builtin_owasp_sensitivity = "mid"
        next.maintenance_global_enabled = false
        break
      case "observe":
        next.builtin_owasp_enabled = true
        next.builtin_owasp_on_hit = "observe"
        next.builtin_owasp_sensitivity = "mid"
        next.maintenance_global_enabled = false
        break
      case "maintenance":
        next.maintenance_global_enabled = true
        break
      case "strict":
        next.builtin_owasp_enabled = true
        next.builtin_owasp_on_hit = "intercept"
        next.builtin_owasp_sensitivity = "high"
        next.maintenance_global_enabled = false
        break
    }
    setSettings(next)
  }

  async function save() {
    if (!settings) return
    let submittedPayload: Partial<ProtectionSettings> | null = null
    setSaving(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      const latest = await getProtectionSettings()
      const patch = buildProtectionPagePatch(
        settings,
        baselineSettings ?? latest,
        sensitivity,
        baselineSensitivity
      )
      if (Object.keys(patch).length === 0) {
        setSettings(latest)
        setBaselineSettings(latest)
        setSensitivity(latest.category_sensitivity ?? sensitivity)
        setBaselineSensitivity(latest.category_sensitivity ?? sensitivity)
        setOperationDetails({
          operation: "noop",
          payload: null,
          response: latest,
          sensitivity: latest.category_sensitivity ?? sensitivity,
        })
        toast.success("防护配置已是最新")
        return
      }
      const payload = { ...patch }
      delete payload.owasp_modules
      submittedPayload = payload
      const result = await updateProtectionSettings(payload)
      const dropPolicy = await getDropPolicy()
      const savedSettings = {
        ...result,
        cve_auto_drop_critical: resolveCVEAutoDrop(
          result.cve_auto_drop_critical,
          dropPolicy.cve_auto_drop_critical
        ),
        cve_auto_drop_high: resolveCVEAutoDrop(
          result.cve_auto_drop_high,
          dropPolicy.cve_auto_drop_high
        ),
      }
      const savedSensitivity = result.category_sensitivity ?? sensitivity
      setOperationDetails({
        operation: "update",
        payload,
        response: result,
        drop_policy: {
          cve_auto_drop_critical: dropPolicy.cve_auto_drop_critical,
          cve_auto_drop_high: dropPolicy.cve_auto_drop_high,
        },
      })
      setSettings(savedSettings)
      setBaselineSettings(savedSettings)
      setSensitivity(savedSensitivity)
      setBaselineSensitivity(savedSensitivity)
      toast.success("防护配置已保存")
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        const details = readReloadFailureDetails(err)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "update",
            payload: submittedPayload,
            response: details,
            sensitivity,
          })
        }
        await reloadProtectionState()
      }
      toast.error(err instanceof Error ? err.message : "保存防护配置失败")
    } finally {
      setSaving(false)
    }
  }

  if (!settings) {
    return (
      <div className="flex flex-col gap-6 p-6">
        <Skeleton className="h-24 rounded-lg" />
        <Skeleton className="h-96 rounded-lg" />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Protection Policy"
        title="攻击防护"
        description="配置全局防护模式、动作状态码、黑白名单优先级、挑战策略和检测类别敏感度。"
        actions={
          <Button onClick={save} disabled={saving}>
            <Save data-icon="inline-start" />
            {saving ? "保存中..." : "保存配置"}
          </Button>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回攻击防护配置响应体；请核对 error 字段。
          </AlertDescription>
          <CopyableBlock
            label="reload 失败响应体"
            value={JSON.stringify(reloadFailureDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {operationDetails ? (
        <Alert className="gap-3">
          <ShieldAlert />
          <AlertTitle>最近攻击防护操作响应</AlertTitle>
          <AlertDescription>
            后端已返回攻击防护操作响应体；请核对 operation、payload、response
            字段；包含 drop_policy 时表示已同步读取阻断策略；operation 为 noop
            时表示后端最新配置与本地表单一致。
          </AlertDescription>
          <CopyableBlock
            label="攻击防护操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <Surface
        title="策略执行顺序"
        description="数据面按优先级短路执行，规则级动作可覆盖全局默认动作。"
      >
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[
            {
              idx: "01",
              title: "白名单",
              desc: "最高优先级，命中后跳过后续检测",
              variant: "outline" as const,
            },
            {
              idx: "02",
              title: "黑名单",
              desc: "在基础检测前拦截、限速或阻断",
              variant: "destructive" as const,
            },
            {
              idx: "03",
              title: "基础检测",
              desc: "OWASP/CVE、Bot、限速、签名和自定义规则",
              variant: "secondary" as const,
            },
            {
              idx: "04",
              title: "后续动作",
              desc: "验证码、5 秒盾、连锁验证或阶梯升级",
              variant: "default" as const,
            },
          ].map(({ idx, title, desc, variant }) => (
            <div key={idx} className="rounded-lg border bg-card p-4 shadow-sm">
              <Badge variant={variant} className="rounded-md text-[11px]">
                {idx}
              </Badge>
              <div className="mt-3 text-sm font-semibold text-foreground">
                {title}
              </div>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                {desc}
              </p>
            </div>
          ))}
        </div>
      </Surface>

      <Surface
        title="防护模式"
        description="快速切换全局防护姿态，保存后写入当前 protection 配置。"
      >
        <ToggleGroup
          type="single"
          value={activeMode}
          onValueChange={(value) => {
            if (
              value === "protection" ||
              value === "observe" ||
              value === "maintenance" ||
              value === "strict"
            ) {
              applyMode(value)
            }
          }}
          className="grid w-full gap-3 sm:grid-cols-2 xl:grid-cols-4"
        >
          {protectionModes.map((mode) => {
            const Icon = mode.icon
            const isActive = activeMode === mode.id
            return (
              <ToggleGroupItem
                key={mode.id}
                value={mode.id}
                className={cn(
                  "h-auto w-full flex-col items-start justify-start gap-2 rounded-lg border bg-card p-4 text-left shadow-sm transition-all hover:border-primary/40 hover:bg-muted/35 hover:shadow-md",
                  isActive
                    ? "border-primary bg-primary/5 ring-1 ring-primary/20"
                    : "border-border"
                )}
              >
                <div
                  className={cn(
                    "flex size-9 items-center justify-center rounded-lg",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "bg-muted text-muted-foreground"
                  )}
                >
                  <Icon data-icon="inline-start" />
                </div>
                <div>
                  <div
                    className={cn(
                      "text-sm font-semibold",
                      isActive ? "text-primary" : "text-foreground"
                    )}
                  >
                    {mode.label}
                  </div>
                  <div className="mt-0.5 text-xs text-muted-foreground">
                    {mode.desc}
                  </div>
                </div>
                {isActive && (
                  <div className="mt-auto self-end">
                    <Badge className="rounded-md text-[10px]">当前</Badge>
                  </div>
                )}
              </ToggleGroupItem>
            )
          })}
        </ToggleGroup>
      </Surface>

      <Surface
        title="全局维护页面"
        description="维护模式启用后，全局维护页面用于未配置站点级维护页面的站点。"
      >
        <FieldGroup className="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
          <Field className="rounded-lg border bg-muted/35 p-4">
            <FieldLabel htmlFor={maintenanceStatusId}>维护状态码</FieldLabel>
            <Input
              id={maintenanceStatusId}
              type="number"
              value={settings.maintenance_global_status ?? 503}
              onChange={(e) =>
                updateSetting(
                  "maintenance_global_status",
                  Number(e.target.value)
                )
              }
              className="rounded-md"
            />
            <FieldDescription>
              默认值来自后端 protection 配置：503。全局自定义 HTML
              非空时，运行时会使用该状态码。
            </FieldDescription>
            <div className="rounded-md border bg-background px-3 py-2 text-xs text-muted-foreground">
              当前状态：
              <Badge
                variant={
                  settings.maintenance_global_enabled ? "secondary" : "outline"
                }
                className="ms-2 rounded-md"
              >
                {settings.maintenance_global_enabled ? "维护模式" : "未启用"}
              </Badge>
            </div>
          </Field>
          <Field className="rounded-lg border bg-card p-4">
            <FieldLabel htmlFor={maintenanceHtmlId}>维护页面 HTML</FieldLabel>
            <Textarea
              id={maintenanceHtmlId}
              value={settings.maintenance_global_html || ""}
              onChange={(e) =>
                updateSetting("maintenance_global_html", e.target.value)
              }
              rows={8}
              className="rounded-md font-mono text-xs"
              placeholder="<h1>维护中</h1>"
            />
            <FieldDescription>
              为空时使用内置维护页面；站点级维护页面存在时优先于全局模板。
            </FieldDescription>
          </Field>
        </FieldGroup>
      </Surface>

      <Surface
        title="内置检测开关"
        description="直接控制全局内置检测能力；Bot 开关会与 Bot 防护页保持同步。"
      >
        <div className="grid gap-3 md:grid-cols-3">
          {builtinDetectionToggleFields.map(
            ({ field, label, description, hint, icon: Icon }) => (
              <div
                key={field}
                className="flex min-h-36 flex-col justify-between gap-4 rounded-lg border bg-muted/35 p-4"
              >
                <div className="flex items-start gap-3">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-background text-muted-foreground">
                    <Icon data-icon="inline-start" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-foreground">
                      {label}
                    </div>
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">
                      {description}
                    </p>
                  </div>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {hint}
                  </span>
                  <Switch
                    checked={Boolean(settings[field])}
                    onCheckedChange={(v) => updateSetting(field, v)}
                    aria-label={label}
                  />
                </div>
              </div>
            )
          )}
        </div>
      </Surface>

      <Surface
        title="全局动作策略"
        description="统一控制 OWASP、CVE、请求限速、错误限速和自动封禁的命中动作；规则级动作会覆盖这里的默认值。"
      >
        <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-5">
          {protectionActionFields.map(({ field, label, fallback }) => {
            const value = String(settings[field] ?? fallback)
            const meta = getWAFActionMeta(value)
            return (
              <div key={field} className="rounded-xl border bg-muted/35 p-3">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-muted-foreground">
                    {label}
                  </span>
                  <Badge
                    variant={protectionActionBadgeVariants[meta.value]}
                    className="rounded-md text-[10px]"
                  >
                    {meta.defaultStatus}
                  </Badge>
                </div>
                <Select
                  value={value}
                  onValueChange={(v) => updateSetting(field, v)}
                >
                  <SelectTrigger className="h-8 rounded-md text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {nonRedirectWAFActionOptions.map((item) => (
                        <SelectItem key={item.value} value={item.value}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
                <p className="mt-2 min-h-8 text-[11px] leading-4 text-muted-foreground">
                  {meta.description}
                </p>
              </div>
            )
          })}
        </div>
      </Surface>

      <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
        <Surface
          title="高危资源耗尽与 CVE 自动阻断"
          description="Critical/High CVE 可自动升级为 Drop；规则级动作优先于自动阻断。"
        >
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              [
                "cve_auto_drop_critical",
                "Critical 自动阻断",
                "命中 Critical CVE 且规则未单独配置动作时返回 RST",
              ],
              [
                "cve_auto_drop_high",
                "High 自动阻断",
                "命中 High CVE 且规则未单独配置动作时返回 RST",
              ],
            ].map(([field, label, desc]) => {
              const key = field as CVEAutoDropField
              const checked = resolveCVEAutoDrop(settings[key])
              return (
                <div key={field} className="rounded-lg border bg-muted/35 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold text-foreground">
                        {label}
                      </div>
                      <p className="mt-1 text-xs leading-5 text-muted-foreground">
                        {desc}
                      </p>
                    </div>
                    <Switch
                      checked={checked}
                      onCheckedChange={(v) => updateSetting(key, v)}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </Surface>

        <Surface
          title="人机验证与后续动作"
          description="配置验证码、5 秒盾、连锁验证和命中后的阶梯升级。"
        >
          <div className="grid gap-3 sm:grid-cols-2">
            {protectionToggleFields.map(({ field, label, hint }) => {
              const checked = Boolean(settings[field])
              return (
                <div
                  key={field}
                  className="flex items-center justify-between gap-3 rounded-lg border bg-muted/35 px-4 py-3"
                >
                  <div>
                    <div className="text-sm font-semibold text-foreground">
                      {label}
                    </div>
                    <div className="font-mono text-[11px] text-muted-foreground">
                      {hint}
                    </div>
                  </div>
                  <Switch
                    checked={checked}
                    onCheckedChange={(v) => updateSetting(field, v)}
                  />
                </div>
              )
            })}
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <Field className="rounded-lg border bg-card p-4">
              <FieldLabel htmlFor={captchaTypeId}>验证码类型</FieldLabel>
              <Select
                value={(settings.captcha_type || "math") as CaptchaType}
                onValueChange={(v: CaptchaType) =>
                  setSettings({ ...settings, captcha_type: v })
                }
              >
                <SelectTrigger id={captchaTypeId}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {CAPTCHA_TYPE_OPTIONS.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
              <FieldDescription>
                {CAPTCHA_TYPE_OPTIONS.find(
                  (item) => item.value === settings.captcha_type
                )?.description || "选择 CAPTCHA 验证方式。"}
              </FieldDescription>
            </Field>
            <Alert>
              <AlertTitle>动作说明</AlertTitle>
              <AlertDescription>
                选择挑战类动作时，请同时启用对应能力：验证码、5 秒盾或连锁验证。
                验证码类型仅影响 captcha_challenge；连锁验证的 CAPTCHA
                步骤在连锁策略中单独配置。
              </AlertDescription>
            </Alert>
          </div>
        </Surface>
      </div>

      <Surface
        title="检测类别敏感度矩阵"
        description="为每个检测类别设置敏感度级别，级别越高检测越严格但可能增加误报。"
        action={
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="shrink-0 rounded-md text-xs">
                批量配置为
                <ChevronDown data-icon="inline-end" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="min-w-[140px]">
              <DropdownMenuGroup>
                {[
                  { label: "禁用", value: "off" },
                  { label: "仅观察", value: "low" },
                  { label: "平衡防护", value: "mid" },
                  { label: "高强度防护", value: "high" },
                ].map((opt) => (
                  <DropdownMenuItem
                    key={opt.value}
                    onClick={() => batchSetSensitivity(opt.value)}
                  >
                    {opt.label}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        }
      >
        <Table className="min-w-[760px]">
          <TableHeader>
            <TableRow>
              <TableHead className="px-5 text-xs tracking-wider text-muted-foreground uppercase">
                类别名称
              </TableHead>
              {sensitivityLevels.map((level) => (
                <TableHead
                  key={level.value}
                  className="px-3 text-center text-xs tracking-wider text-muted-foreground uppercase"
                >
                  {level.label}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {categories.map((cat) => {
              const currentValue = modules[cat.key] || "off"
              return (
                <TableRow key={cat.key}>
                  <TableCell className="px-5">
                    <div className="flex items-center gap-2">
                      <ShieldAlert
                        data-icon="inline-start"
                        className="text-muted-foreground"
                      />
                      <span className="font-medium text-foreground">
                        {cat.label}
                      </span>
                    </div>
                  </TableCell>
                  {sensitivityLevels.map((level) => {
                    const isSelected = currentValue === level.value
                    return (
                      <TableCell key={level.value} className="px-3 text-center">
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon-xs"
                          onClick={() =>
                            setModuleSensitivity(cat.key, level.value)
                          }
                          className={cn(
                            "rounded-full border-2 p-0 transition-all",
                            isSelected
                              ? "border-primary bg-primary shadow-sm"
                              : "border-border bg-background hover:border-primary/45"
                          )}
                          aria-label={`${cat.label} 设置为 ${level.label}`}
                        >
                          {isSelected && (
                            <span className="block size-2 rounded-full bg-primary-foreground" />
                          )}
                        </Button>
                      </TableCell>
                    )
                  })}
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </Surface>

      {/* Bottom Save */}
      <div className="flex justify-end pb-4">
        <Button onClick={save} disabled={saving}>
          <Save data-icon="inline-start" />
          {saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </div>
  )
}
