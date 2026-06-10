"use client"

import { useEffect, useState, useCallback } from "react"
import {
  Clock,
  Shield,
  Zap,
  AlertTriangle,
  Ban,
  Plus,
  Pencil,
  Trash2,
  Info,
  Save,
  ChevronDown,
  ChevronUp,
} from "@/lib/icons"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldTitle,
} from "@/components/ui/field"
import { Skeleton } from "@/components/ui/skeleton"
import { Separator } from "@/components/ui/separator"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  getConfigAppliedReloadFailureDetails,
  getProtectionSettings,
  isConfigAppliedReloadFailureError,
  updateProtectionSettings,
  type ProtectionSettings,
} from "@/lib/api"
import { assignChangedProtectionField } from "@/lib/protection-settings"
import { getWAFActionMeta, nonRedirectWAFActionOptions } from "@/lib/console"
import { cn } from "@/lib/utils"
import { PageIntro, Surface } from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"

/* ───── types ───── */
interface CCCondition {
  target: string
  operator: string
  value: string
}
interface CCRule {
  name: string
  enabled?: boolean
  conditions: CCCondition[]
  window: number
  threshold: number
  action: string
  duration: number
  captcha?: boolean
}

const emptyCondition: CCCondition = {
  target: "url_path",
  operator: "equals",
  value: "",
}
const emptyRule: CCRule = {
  name: "",
  enabled: true,
  conditions: [{ ...emptyCondition }],
  window: 60,
  threshold: 100,
  action: "challenge",
  duration: 5,
  captcha: false,
}

const targetOptions = [
  { value: "url_path", label: "URL 路径" },
  { value: "header", label: "请求头" },
  { value: "method", label: "请求方法" },
]
const operatorOptions = [
  { value: "equals", label: "等于" },
  { value: "contains", label: "包含" },
  { value: "prefix", label: "前缀关键字" },
]

const actionLabelMap: Record<string, string> = {
  challenge: "人机验证",
  captcha_challenge: "验证码验证",
  shield_challenge: "5秒盾验证",
  chain_challenge: "混合验证",
  intercept: "直接封禁",
  rate_limit: "限速",
  drop: "阻断连接",
  block: "直接封禁",
  observe: "仅记录",
}

function actionLabel(action: string): string {
  return actionLabelMap[action] || getWAFActionMeta(action).shortLabel
}

function actionBadgeVariant(
  action: string
): "default" | "secondary" | "destructive" | "outline" {
  if (
    action === "drop" ||
    action === "block" ||
    action === "intercept" ||
    action === "captcha_challenge" ||
    action === "shield_challenge" ||
    action === "chain_challenge"
  ) {
    return "destructive"
  }
  if (action === "challenge" || action === "rate_limit") return "secondary"
  if (action === "observe") return "outline"
  return "outline"
}

const ccProtectionFields: Array<keyof ProtectionSettings> = [
  "waiting_room_enabled",
  "cc_use_custom",
  "request_ratelimit_enabled",
  "request_ratelimit_window",
  "request_ratelimit_max",
  "request_ratelimit_action",
  "auto_ban_enabled",
  "auto_ban_threshold",
  "auto_ban_window",
  "auto_ban_duration",
  "auto_ban_action",
  "error_ratelimit_enabled",
  "error_ratelimit_window",
  "error_ratelimit_max",
  "error_ratelimit_count_4xx",
  "error_ratelimit_count_5xx",
  "error_ratelimit_count_block",
  "error_ratelimit_action",
]

function sameCCRules(left: CCRule[], right: CCRule[]) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function buildCCProtectionPatch(
  current: ProtectionSettings,
  baseline: ProtectionSettings,
  currentRules: CCRule[],
  baselineRules: CCRule[]
): Partial<ProtectionSettings> {
  const patch: Partial<ProtectionSettings> = {}
  for (const field of ccProtectionFields) {
    assignChangedProtectionField(patch, current, baseline, field)
  }
  if (!sameCCRules(currentRules, baselineRules)) {
    patch.cc_rules = currentRules
  }
  return patch
}

function readReloadFailureDetails(error: unknown) {
  return getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
}

/* ───── main ───── */
export default function CCProtectionPage() {
  const [localSettings, setLocalSettings] = useState<ProtectionSettings | null>(
    null
  )
  const [baselineSettings, setBaselineSettings] =
    useState<ProtectionSettings | null>(null)
  const [rules, setRules] = useState<CCRule[]>([])
  const [baselineRules, setBaselineRules] = useState<CCRule[]>([])
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  // built-in rule edit dialogs
  const [editRequestRateOpen, setEditRequestRateOpen] = useState(false)
  const [editAttackRateOpen, setEditAttackRateOpen] = useState(false)
  const [editErrorRateOpen, setEditErrorRateOpen] = useState(false)

  // custom rule dialog
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false)
  const [editIndex, setEditIndex] = useState<number | null>(null)
  const [draft, setDraft] = useState<CCRule>({ ...emptyRule })

  // collapsible sections
  const [customRulesExpanded, setCustomRulesExpanded] = useState(true)

  const load = useCallback(() => {
    getProtectionSettings()
      .then((data) => {
        setLocalSettings({ ...data })
        setBaselineSettings({ ...data })
        const loadedRules = Array.isArray(data.cc_rules)
          ? (data.cc_rules as CCRule[])
          : []
        setRules(loadedRules)
        setBaselineRules(loadedRules)
        setDirty(false)
      })
      .catch((err) =>
        toast.error(err instanceof Error ? err.message : "加载 CC 防护配置失败")
      )
  }, [])

  async function reloadCCState() {
    const data = await getProtectionSettings()
    setLocalSettings({ ...data })
    setBaselineSettings({ ...data })
    const loadedRules = Array.isArray(data.cc_rules)
      ? (data.cc_rules as CCRule[])
      : []
    setRules(loadedRules)
    setBaselineRules(loadedRules)
    setDirty(false)
  }

  useEffect(() => {
    load()
  }, [load])

  function updateLocal(patch: Partial<ProtectionSettings>) {
    setLocalSettings((prev) => (prev ? { ...prev, ...patch } : prev))
    setDirty(true)
  }

  function updateRules(nextRules: CCRule[]) {
    setRules(nextRules)
    setDirty(true)
  }

  async function saveAll() {
    if (!localSettings) return
    let submittedPayload: Partial<ProtectionSettings> | null = null
    setSaving(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      const latest = await getProtectionSettings()
      const patch = buildCCProtectionPatch(
        localSettings,
        baselineSettings ?? latest,
        rules,
        baselineRules
      )
      if (Object.keys(patch).length === 0) {
        setLocalSettings({ ...latest })
        setBaselineSettings({ ...latest })
        const latestRules = Array.isArray(latest.cc_rules)
          ? (latest.cc_rules as CCRule[])
          : []
        setRules(latestRules)
        setBaselineRules(latestRules)
        setOperationDetails({
          operation: "noop",
          payload: null,
          response: latest,
          cc_rules: latestRules,
        })
        setDirty(false)
        toast.success("CC 防护配置已是最新")
        return
      }
      submittedPayload = patch
      const result = await updateProtectionSettings(patch)
      setLocalSettings({ ...result })
      setBaselineSettings({ ...result })
      const savedRules = Array.isArray(result.cc_rules)
        ? (result.cc_rules as CCRule[])
        : []
      setOperationDetails({
        operation: "update",
        payload: patch,
        response: result,
        cc_rules: savedRules,
      })
      setRules(savedRules)
      setBaselineRules(savedRules)
      setDirty(false)
      toast.success("CC 防护配置已保存")
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        const details = readReloadFailureDetails(err)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "update",
            payload: submittedPayload,
            response: details,
            cc_rules: rules,
          })
        }
        await reloadCCState()
      }
      toast.error(err instanceof Error ? err.message : "保存 CC 防护配置失败")
    } finally {
      setSaving(false)
    }
  }

  /* ── custom rule CRUD ── */
  function openAddRule() {
    setEditIndex(null)
    setDraft({ ...emptyRule, conditions: [{ ...emptyCondition }] })
    setRuleDialogOpen(true)
  }
  function openEditRule(idx: number) {
    setEditIndex(idx)
    setDraft({
      ...rules[idx],
      conditions: rules[idx].conditions.map((c) => ({ ...c })),
    })
    setRuleDialogOpen(true)
  }
  function confirmRule() {
    if (!draft.name.trim()) {
      toast.error("请输入规则名称")
      return
    }
    const nextRules = [...rules]
    if (editIndex !== null) {
      nextRules[editIndex] = draft
    } else {
      nextRules.push(draft)
    }
    updateRules(nextRules)
    setRuleDialogOpen(false)
    toast.success(
      editIndex !== null
        ? "规则已更新（请点击保存生效）"
        : "规则已添加（请点击保存生效）"
    )
  }
  function deleteRule(idx: number) {
    const next = rules.filter((_, i) => i !== idx)
    updateRules(next)
    toast.success("规则已移除（请点击保存生效）")
  }
  function toggleRule(idx: number) {
    const next = [...rules]
    next[idx] = { ...next[idx], enabled: !next[idx].enabled }
    updateRules(next)
  }

  /* ── condition helpers ── */
  function updateCondition(ci: number, patch: Partial<CCCondition>) {
    setDraft((d) => ({
      ...d,
      conditions: d.conditions.map((c, i) =>
        i === ci ? { ...c, ...patch } : c
      ),
    }))
  }
  function addCondition() {
    setDraft((d) => ({
      ...d,
      conditions: [...d.conditions, { ...emptyCondition }],
    }))
  }
  function removeCondition(ci: number) {
    setDraft((d) => ({
      ...d,
      conditions: d.conditions.filter((_, i) => i !== ci),
    }))
  }

  function closeBuiltinDialog(kind: "request" | "attack" | "error") {
    if (kind === "request") setEditRequestRateOpen(false)
    if (kind === "attack") setEditAttackRateOpen(false)
    if (kind === "error") setEditErrorRateOpen(false)
    setDirty(true)
    toast.success("已更新（请点击保存生效）")
  }

  if (!localSettings) {
    return (
      <div className="flex flex-col gap-6 p-6">
        <Skeleton className="h-24 rounded-lg" />
        <Skeleton className="h-64 rounded-lg" />
      </div>
    )
  }

  const s = localSettings

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="CC Protection"
        title="CC 防护"
        description="保存等候室预留开关，配置频率限制和自定义 CC 规则，防止恶意高频访问。"
        actions={
          <Button onClick={saveAll} disabled={saving || !dirty}>
            <Save data-icon="inline-start" />
            {saving ? "保存中..." : "保存"}
          </Button>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回 CC 防护配置响应体；请核对 error 字段。
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
          <Shield />
          <AlertTitle>最近 CC 防护操作响应</AlertTitle>
          <AlertDescription>
            后端已返回 CC 防护操作响应体；请核对 operation、payload、
            response 与 cc_rules 字段；operation 为 noop 时表示后端最新配置与本地表单一致。
          </AlertDescription>
          <CopyableBlock
            label="CC 防护操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {/* ══════════════════════════════════════════════════════════
         Section 1: 等候室
         ══════════════════════════════════════════════════════════ */}
      <Surface>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg bg-muted text-primary">
              <Clock className="size-4" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-semibold text-foreground">
                  等候室
                </h2>
                <Badge variant="outline">仅保存状态</Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                当前只写入配置状态，不触发数据面排队削峰
              </p>
            </div>
          </div>
          <Switch
            checked={s.waiting_room_enabled || false}
            onCheckedChange={(val) =>
              updateLocal({ waiting_room_enabled: val })
            }
          />
        </div>
        <div className="mt-4 flex flex-col gap-4">
          <Separator />
          <Alert>
            <Info />
            <AlertDescription>
              该开关会保存到 waiting_room_enabled，但当前运行时不会按该字段执行排队。需要即时生效的 CC 防护请使用下方频率限制或自定义 CC 规则。
            </AlertDescription>
          </Alert>
        </div>
      </Surface>

      {/* ══════════════════════════════════════════════════════════
         Section 2: 频率限制配置模式
         ══════════════════════════════════════════════════════════ */}
      <div className="console-panel overflow-hidden shadow-sm">
        <div className="flex items-center justify-between px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg bg-muted text-primary">
              <Zap className="size-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-foreground">
                频率限制
              </h2>
              <p className="text-xs text-muted-foreground">
                对高频访问、高频攻击和高频错误进行限制
              </p>
            </div>
          </div>
          <ToggleGroup
            type="single"
            value={s.cc_use_custom ? "custom" : "global"}
            onValueChange={(value) => {
              if (value === "global") updateLocal({ cc_use_custom: false })
              if (value === "custom") updateLocal({ cc_use_custom: true })
            }}
            variant="outline"
            size="sm"
          >
            <ToggleGroupItem value="global">跟随全局配置</ToggleGroupItem>
            <ToggleGroupItem value="custom">使用自定义配置</ToggleGroupItem>
          </ToggleGroup>
        </div>
        <Separator />

        <div className="divide-y divide-border">
          {/* ── 高频访问限制 ── */}
          <BuiltinRuleRow
            icon={<Zap className="size-4" />}
            tone="primary"
            title="高频访问限制"
            enabled={s.request_ratelimit_enabled}
            onToggle={(val) => updateLocal({ request_ratelimit_enabled: val })}
            onEdit={() => setEditRequestRateOpen(true)}
            description={
              s.request_ratelimit_enabled
                ? `某 IP 在 ${s.request_ratelimit_window} 秒内请求达到 ${s.request_ratelimit_max} 次，触发${actionLabel(s.request_ratelimit_action)}`
                : "未启用高频访问限制"
            }
          />

          {/* ── 高频攻击限制 ── */}
          <BuiltinRuleRow
            icon={<AlertTriangle className="size-4" />}
            tone="warning"
            title="高频攻击限制"
            enabled={s.auto_ban_enabled}
            onToggle={(val) => updateLocal({ auto_ban_enabled: val })}
            onEdit={() => setEditAttackRateOpen(true)}
            description={
              s.auto_ban_enabled
                ? `某 IP 在 ${s.auto_ban_window} 秒内触发攻击拦截次数达到 ${s.auto_ban_threshold} 次，${Math.floor(s.auto_ban_duration / 60)} 分钟内${actionLabel(s.auto_ban_action || "intercept")}`
                : "未启用高频攻击限制"
            }
          />

          {/* ── 高频错误限制 ── */}
          <BuiltinRuleRow
            icon={<Ban className="size-4" />}
            tone="danger"
            title="高频错误限制"
            enabled={s.error_ratelimit_enabled}
            onToggle={(val) => updateLocal({ error_ratelimit_enabled: val })}
            onEdit={() => setEditErrorRateOpen(true)}
            description={
              s.error_ratelimit_enabled
                ? `某 IP 在 ${s.error_ratelimit_window} 秒内触发${[
                    s.error_ratelimit_count_4xx ? "4xx" : "",
                    s.error_ratelimit_count_5xx ? "5xx" : "",
                    s.error_ratelimit_count_block ? "拦截" : "",
                  ]
                    .filter(Boolean)
                    .join(
                      "/"
                    )}错误达到 ${s.error_ratelimit_max} 次，触发${actionLabel(s.error_ratelimit_action)}`
                : "未启用高频错误限制"
            }
          />
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════
         Section 3: 自定义 CC 规则
         ══════════════════════════════════════════════════════════ */}
      <div className="console-panel overflow-hidden shadow-sm">
        <div
          className="flex cursor-pointer items-center justify-between px-5 py-4"
          onClick={() => setCustomRulesExpanded(!customRulesExpanded)}
        >
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg bg-muted text-primary">
              <Shield className="size-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-foreground">
                自定义规则
              </h2>
              <p className="text-xs text-muted-foreground">
                基于 URL、Header、Method 定义细粒度频率阈值与动作
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={(e) => {
                e.stopPropagation()
                openAddRule()
              }}
              size="sm"
            >
              <Plus data-icon="inline-start" /> 添加规则
            </Button>
            {customRulesExpanded ? (
              <ChevronUp className="size-4 text-muted-foreground" />
            ) : (
              <ChevronDown className="size-4 text-muted-foreground" />
            )}
          </div>
        </div>

        {customRulesExpanded && (
          <>
            <Separator />
            {rules.length === 0 ? (
              <div className="flex min-h-[160px] flex-col items-center justify-center p-8 text-center">
                <Shield className="mb-3 size-10 text-muted-foreground/60" />
                <p className="text-sm font-medium text-muted-foreground">
                  还没有自定义规则
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  点击「添加规则」创建第一条 CC 自定义规则
                </p>
              </div>
            ) : (
              <div>
                <Table>
                  <TableHeader>
                    <TableRow className="bg-muted/45 text-xs text-muted-foreground">
                      <TableHead className="px-5 py-3">状态</TableHead>
                      <TableHead className="px-4 py-3">名称</TableHead>
                      <TableHead className="px-4 py-3">匹配条件</TableHead>
                      <TableHead className="px-4 py-3">频率规则</TableHead>
                      <TableHead className="px-4 py-3">动作</TableHead>
                      <TableHead className="px-4 py-3 text-right">
                        操作
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule, idx) => (
                      <TableRow
                        key={`${rule.name}-${idx}`}
                        className="hover:bg-muted/35"
                      >
                        <TableCell className="px-5 py-3">
                          <Switch
                            checked={rule.enabled !== false}
                            onCheckedChange={() => toggleRule(idx)}
                          />
                        </TableCell>
                        <TableCell className="px-4 py-3 font-medium text-foreground">
                          {rule.name || `规则 ${idx + 1}`}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-muted-foreground">
                          {rule.conditions.map((c, ci) => (
                            <Badge key={ci} variant="outline" className="me-1">
                              {targetOptions.find((t) => t.value === c.target)
                                ?.label || c.target}{" "}
                              {operatorOptions.find(
                                (o) => o.value === c.operator
                              )?.label || c.operator}{" "}
                              {c.value || "..."}
                            </Badge>
                          ))}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-xs text-muted-foreground">
                          {rule.window}秒 / {rule.threshold}次 / {rule.duration}
                          分钟
                        </TableCell>
                        <TableCell className="px-4 py-3">
                          <Badge variant={actionBadgeVariant(rule.action)}>
                            {getWAFActionMeta(rule.action).shortLabel}
                          </Badge>
                        </TableCell>
                        <TableCell className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              onClick={() => openEditRule(idx)}
                              aria-label="编辑 CC 自定义规则"
                            >
                              <Pencil data-icon="inline-start" />
                            </Button>
                            <Button
                              variant="destructive"
                              size="icon-sm"
                              onClick={() => deleteRule(idx)}
                              aria-label="删除 CC 自定义规则"
                            >
                              <Trash2 data-icon="inline-start" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </>
        )}
      </div>

      {/* ══════ Bottom Save Bar ══════ */}
      {dirty && (
        <div className="sticky bottom-0 z-10 flex items-center justify-between rounded-lg border border-border bg-card/95 px-5 py-3 shadow-lg backdrop-blur-sm">
          <div className="flex items-center gap-2 text-sm text-foreground">
            <Info className="size-4 text-primary" />
            <span>配置已修改，请点击保存使更改生效</span>
          </div>
          <Button onClick={saveAll} disabled={saving}>
            <Save data-icon="inline-start" />
            {saving ? "保存中..." : "保存配置"}
          </Button>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════
         Dialog: 编辑高频访问限制
         ══════════════════════════════════════════════════════════ */}
      <Dialog open={editRequestRateOpen} onOpenChange={setEditRequestRateOpen}>
        <DialogContent className="max-w-lg rounded-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Zap className="size-4 text-primary" />
              编辑高频访问限制
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-5">
            <div className="rounded-md border border-border bg-muted/35 p-4">
              <p className="mb-3 text-sm text-muted-foreground">
                某 IP 在
                <InlineNumberInput
                  value={s.request_ratelimit_window}
                  onChange={(v) => updateLocal({ request_ratelimit_window: v })}
                  unit="秒"
                />
                内请求达到
                <InlineNumberInput
                  value={s.request_ratelimit_max}
                  onChange={(v) => updateLocal({ request_ratelimit_max: v })}
                  unit="次"
                />
                ，触发以下动作：
              </p>
              <Field>
                <FieldLabel>限制结果</FieldLabel>
                <Select
                  value={s.request_ratelimit_action}
                  onValueChange={(v) =>
                    updateLocal({ request_ratelimit_action: v })
                  }
                >
                  <SelectTrigger className="rounded-md bg-background">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="challenge">人机验证</SelectItem>
                      <SelectItem value="captcha_challenge">
                        验证码验证
                      </SelectItem>
                      <SelectItem value="shield_challenge">
                        5秒盾验证
                      </SelectItem>
                      <SelectItem value="chain_challenge">
                        混合验证
                      </SelectItem>
                      <SelectItem value="rate_limit">限速 (429)</SelectItem>
                      <SelectItem value="intercept">直接封禁</SelectItem>
                      <SelectItem value="drop">阻断连接</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setEditRequestRateOpen(false)}
            >
              取消
            </Button>
            <Button onClick={() => closeBuiltinDialog("request")}>确定</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ══════════════════════════════════════════════════════════
         Dialog: 编辑高频攻击限制
         ══════════════════════════════════════════════════════════ */}
      <Dialog open={editAttackRateOpen} onOpenChange={setEditAttackRateOpen}>
        <DialogContent className="max-w-lg rounded-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="size-4 text-chart-3" />
              编辑高频攻击限制
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-5">
            <div className="rounded-md border border-border bg-muted/35 p-4">
              <p className="mb-3 text-sm text-muted-foreground">
                某 IP 在
                <InlineNumberInput
                  value={s.auto_ban_window}
                  onChange={(v) => updateLocal({ auto_ban_window: v })}
                  unit="秒"
                />
                内触发攻击拦截次数达到
                <InlineNumberInput
                  value={s.auto_ban_threshold}
                  onChange={(v) => updateLocal({ auto_ban_threshold: v })}
                  unit="次"
                />
                ，
                <InlineNumberInput
                  value={Math.floor(s.auto_ban_duration / 60)}
                  onChange={(v) => updateLocal({ auto_ban_duration: v * 60 })}
                  unit="分钟"
                />
                内触发以下动作：
              </p>
              <Field>
                <FieldLabel>限制结果</FieldLabel>
                <Select
                  value={s.auto_ban_action || "intercept"}
                  onValueChange={(v) => updateLocal({ auto_ban_action: v })}
                >
                  <SelectTrigger className="rounded-md bg-background">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="challenge">人机验证</SelectItem>
                      <SelectItem value="captcha_challenge">
                        验证码验证
                      </SelectItem>
                      <SelectItem value="shield_challenge">
                        5秒盾验证
                      </SelectItem>
                      <SelectItem value="chain_challenge">
                        混合验证
                      </SelectItem>
                      <SelectItem value="intercept">直接封禁</SelectItem>
                      <SelectItem value="drop">阻断连接</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setEditAttackRateOpen(false)}
            >
              取消
            </Button>
            <Button onClick={() => closeBuiltinDialog("attack")}>确定</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ══════════════════════════════════════════════════════════
         Dialog: 编辑高频错误限制
         ══════════════════════════════════════════════════════════ */}
      <Dialog open={editErrorRateOpen} onOpenChange={setEditErrorRateOpen}>
        <DialogContent className="max-w-lg rounded-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Ban className="size-4 text-destructive" />
              编辑高频错误限制
            </DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-5">
            <div className="rounded-md border border-border bg-muted/35 p-4">
              <p className="mb-3 text-sm text-muted-foreground">
                某 IP 在
                <InlineNumberInput
                  value={s.error_ratelimit_window}
                  onChange={(v) => updateLocal({ error_ratelimit_window: v })}
                  unit="秒"
                />
                内触发错误达到
                <InlineNumberInput
                  value={s.error_ratelimit_max}
                  onChange={(v) => updateLocal({ error_ratelimit_max: v })}
                  unit="次"
                />
                ，触发以下动作：
              </p>

              <FieldGroup className="mb-3 gap-2">
                <FieldTitle>计入错误类型</FieldTitle>
                <div className="flex flex-wrap gap-3">
                  <Field
                    orientation="horizontal"
                    className="w-auto items-center gap-2"
                  >
                    <Checkbox
                      id="cc-error-count-4xx"
                      checked={s.error_ratelimit_count_4xx}
                      onCheckedChange={(checked) =>
                        updateLocal({
                          error_ratelimit_count_4xx: checked === true,
                        })
                      }
                    />
                    <FieldLabel
                      htmlFor="cc-error-count-4xx"
                      className="cursor-pointer text-sm font-normal text-muted-foreground"
                    >
                      4xx 错误 (400,401,403,404,405,429)
                    </FieldLabel>
                  </Field>
                  <Field
                    orientation="horizontal"
                    className="w-auto items-center gap-2"
                  >
                    <Checkbox
                      id="cc-error-count-5xx"
                      checked={s.error_ratelimit_count_5xx}
                      onCheckedChange={(checked) =>
                        updateLocal({
                          error_ratelimit_count_5xx: checked === true,
                        })
                      }
                    />
                    <FieldLabel
                      htmlFor="cc-error-count-5xx"
                      className="cursor-pointer text-sm font-normal text-muted-foreground"
                    >
                      5xx 错误
                    </FieldLabel>
                  </Field>
                  <Field
                    orientation="horizontal"
                    className="w-auto items-center gap-2"
                  >
                    <Checkbox
                      id="cc-error-count-block"
                      checked={s.error_ratelimit_count_block}
                      onCheckedChange={(checked) =>
                        updateLocal({
                          error_ratelimit_count_block: checked === true,
                        })
                      }
                    />
                    <FieldLabel
                      htmlFor="cc-error-count-block"
                      className="cursor-pointer text-sm font-normal text-muted-foreground"
                    >
                      WAF 拦截
                    </FieldLabel>
                  </Field>
                </div>
              </FieldGroup>

              <Field>
                <FieldLabel>限制结果</FieldLabel>
                <Select
                  value={s.error_ratelimit_action}
                  onValueChange={(v) =>
                    updateLocal({ error_ratelimit_action: v })
                  }
                >
                  <SelectTrigger className="rounded-md bg-background">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="challenge">人机验证</SelectItem>
                      <SelectItem value="captcha_challenge">
                        验证码验证
                      </SelectItem>
                      <SelectItem value="shield_challenge">
                        5秒盾验证
                      </SelectItem>
                      <SelectItem value="chain_challenge">
                        混合验证
                      </SelectItem>
                      <SelectItem value="rate_limit">限速 (429)</SelectItem>
                      <SelectItem value="intercept">直接封禁</SelectItem>
                      <SelectItem value="drop">阻断连接</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setEditErrorRateOpen(false)}
            >
              取消
            </Button>
            <Button onClick={() => closeBuiltinDialog("error")}>确定</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ══════════════════════════════════════════════════════════
         Dialog: 添加/编辑自定义规则
         ══════════════════════════════════════════════════════════ */}
      <Dialog open={ruleDialogOpen} onOpenChange={setRuleDialogOpen}>
        <DialogContent className="max-w-2xl rounded-lg">
          <DialogHeader>
            <DialogTitle>
              {editIndex !== null ? "编辑规则" : "添加规则"}
            </DialogTitle>
          </DialogHeader>
          <FieldGroup className="flex flex-col gap-4">
            {/* Name */}
            <Field>
              <FieldLabel>
                名称 <span className="text-destructive">*</span>
              </FieldLabel>
              <Input
                className="rounded-md"
                placeholder="规则名称"
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </Field>

            {/* Conditions */}
            <div className="flex flex-col gap-3 rounded-lg border border-border bg-muted/35 p-4">
              <FieldTitle className="text-xs text-muted-foreground">
                匹配条件
              </FieldTitle>
              {draft.conditions.map((cond, ci) => (
                <div key={ci} className="flex items-start gap-2">
                  <div className="grid flex-1 gap-2 md:grid-cols-3">
                    <Field className="gap-1">
                      <FieldLabel className="text-xs text-muted-foreground">
                        匹配目标
                      </FieldLabel>
                      <Select
                        value={cond.target}
                        onValueChange={(v) =>
                          updateCondition(ci, { target: v })
                        }
                      >
                        <SelectTrigger className="rounded-md bg-background">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {targetOptions.map((t) => (
                              <SelectItem key={t.value} value={t.value}>
                                {t.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field className="gap-1">
                      <FieldLabel className="text-xs text-muted-foreground">
                        匹配方式 <span className="text-destructive">*</span>
                      </FieldLabel>
                      <Select
                        value={cond.operator}
                        onValueChange={(v) =>
                          updateCondition(ci, { operator: v })
                        }
                      >
                        <SelectTrigger className="rounded-md bg-background">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {operatorOptions.map((o) => (
                              <SelectItem key={o.value} value={o.value}>
                                {o.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field className="gap-1">
                      <FieldLabel className="text-xs text-muted-foreground">
                        匹配内容 <span className="text-destructive">*</span>
                      </FieldLabel>
                      <Input
                        className="rounded-md bg-background"
                        placeholder="例如: /api/login"
                        value={cond.value}
                        onChange={(e) =>
                          updateCondition(ci, { value: e.target.value })
                        }
                      />
                    </Field>
                  </div>
                  {draft.conditions.length > 1 && (
                    <Button
                      type="button"
                      variant="destructive"
                      size="icon-sm"
                      onClick={() => removeCondition(ci)}
                      className="mt-6"
                      aria-label="删除匹配条件"
                    >
                      <Trash2 data-icon="inline-start" />
                    </Button>
                  )}
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addCondition}
                className="w-fit border-dashed"
              >
                <Plus data-icon="inline-start" />
                添加一个 AND 条件
              </Button>
            </div>

            {/* Params */}
            <div className="grid gap-3 md:grid-cols-4">
              <Field>
                <FieldLabel>
                  经过时间 <span className="text-destructive">*</span>
                </FieldLabel>
                <div className="flex items-center gap-1">
                  <Input
                    type="number"
                    className="rounded-md"
                    value={draft.window}
                    onChange={(e) =>
                      setDraft({ ...draft, window: Number(e.target.value) })
                    }
                  />
                  <span className="text-xs text-muted-foreground">秒</span>
                </div>
              </Field>
              <Field>
                <FieldLabel>
                  请求次数达到 <span className="text-destructive">*</span>
                </FieldLabel>
                <div className="flex items-center gap-1">
                  <Input
                    type="number"
                    className="rounded-md"
                    value={draft.threshold}
                    onChange={(e) =>
                      setDraft({ ...draft, threshold: Number(e.target.value) })
                    }
                  />
                  <span className="text-xs text-muted-foreground">次</span>
                </div>
              </Field>
              <Field>
                <FieldLabel>限制结果</FieldLabel>
                <Select
                  value={draft.action}
                  onValueChange={(v) => setDraft({ ...draft, action: v })}
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {nonRedirectWAFActionOptions.map((a) => (
                        <SelectItem key={a.value} value={a.value}>
                          {a.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel>
                  持续时间 <span className="text-destructive">*</span>
                </FieldLabel>
                <div className="flex items-center gap-1">
                  <Input
                    type="number"
                    className="rounded-md"
                    value={draft.duration}
                    onChange={(e) =>
                      setDraft({ ...draft, duration: Number(e.target.value) })
                    }
                  />
                  <span className="text-xs text-muted-foreground">分钟</span>
                </div>
              </Field>
            </div>
          </FieldGroup>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRuleDialogOpen(false)}>
              取消
            </Button>
            <Button onClick={confirmRule} disabled={saving}>
              确定
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   Sub-components
   ═══════════════════════════════════════════════════════════════ */

/** Inline built-in rule row with toggle, description, and edit button */
function BuiltinRuleRow({
  icon,
  tone,
  title,
  description,
  enabled,
  onToggle,
  onEdit,
}: {
  icon: React.ReactNode
  tone: "primary" | "warning" | "danger"
  title: string
  description: string
  enabled: boolean
  onToggle: (val: boolean) => void
  onEdit: () => void
}) {
  const iconClassName = {
    primary: "bg-primary/10 text-primary",
    warning: "bg-chart-3/10 text-chart-3",
    danger: "bg-destructive/10 text-destructive",
  }[tone]

  return (
    <div className="flex items-center justify-between px-5 py-4">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <div
          className={cn(
            "flex size-8 shrink-0 items-center justify-center rounded-lg",
            iconClassName
          )}
        >
          {icon}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-foreground">
              {title}
            </span>
            {enabled ? (
              <Badge variant="secondary">已启用</Badge>
            ) : (
              <Badge variant="outline">未启用</Badge>
            )}
          </div>
          <p
            className={cn(
              "mt-0.5 truncate text-xs",
              enabled ? "text-muted-foreground" : "text-muted-foreground/70"
            )}
          >
            {description}
          </p>
        </div>
      </div>
      <div className="ms-4 flex shrink-0 items-center gap-3">
        <Button type="button" variant="outline" size="sm" onClick={onEdit}>
          <Pencil data-icon="inline-start" />
          编辑
        </Button>
        <Switch checked={enabled} onCheckedChange={onToggle} />
      </div>
    </div>
  )
}

/** Inline number input rendered inside a sentence */
function InlineNumberInput({
  value,
  onChange,
  unit,
}: {
  value: number
  onChange: (v: number) => void
  unit: string
}) {
  return (
    <span className="mx-1 inline-flex items-center gap-1">
      <Input
        type="number"
        className="inline-block h-auto w-16 rounded-md px-2 py-1 text-center text-sm font-medium"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      <span className="text-xs text-muted-foreground">{unit}</span>
    </span>
  )
}
