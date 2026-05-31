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
} from "lucide-react"
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  getProtectionSettings,
  updateProtectionSettings,
  type ProtectionSettings,
} from "@/lib/api"
import { getWAFActionMeta, terminalWAFActionOptions } from "@/lib/console"
import { cn } from "@/lib/utils"

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

/* ───── main ───── */
export default function CCProtectionPage() {
  const [localSettings, setLocalSettings] = useState<ProtectionSettings | null>(
    null
  )
  const [rules, setRules] = useState<CCRule[]>([])
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)

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
        setRules(
          Array.isArray(data.cc_rules) ? (data.cc_rules as CCRule[]) : []
        )
        setDirty(false)
      })
      .catch((err) => toast.error(String(err)))
  }, [])

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
    const payload = {
      ...localSettings,
      cc_rules: rules,
    } as ProtectionSettings
    setSaving(true)
    try {
      const result = await updateProtectionSettings(payload)
      setLocalSettings({ ...result })
      setRules(
        Array.isArray(result.cc_rules) ? (result.cc_rules as CCRule[]) : []
      )
      setDirty(false)
      toast.success("CC 防护配置已保存")
    } catch (err) {
      toast.error(String(err))
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
      <div className="space-y-6 p-6">
        <div className="h-24 animate-pulse rounded-lg bg-slate-100" />
        <div className="h-64 animate-pulse rounded-lg bg-slate-100" />
      </div>
    )
  }

  const s = localSettings

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">CC 防护</h1>
          <p className="mt-1 text-sm text-slate-500">
            配置等候室、频率限制和自定义 CC 规则，防止恶意高频访问
          </p>
        </div>
        <Button
          onClick={saveAll}
          disabled={saving || !dirty}
          className={cn(
            "rounded-md px-5 text-white transition-all",
            dirty
              ? "bg-teal-600 shadow-md shadow-teal-200 hover:bg-teal-700"
              : "cursor-not-allowed bg-slate-300"
          )}
        >
          <Save className="mr-1.5 h-4 w-4" />
          {saving ? "保存中..." : "保存"}
        </Button>
      </div>

      {/* ══════════════════════════════════════════════════════════
         Section 1: 等候室
         ══════════════════════════════════════════════════════════ */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-teal-50 text-teal-600">
              <Clock className="h-4.5 w-4.5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900">等候室</h2>
              <p className="text-xs text-slate-500">
                当流量超过承载能力时，将多余请求放入等候队列中排队等待
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
        {s.waiting_room_enabled && (
          <div className="border-t border-slate-100 px-5 py-3">
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                当前后端仅保存等候室开关状态，数据面排队削峰执行链路尚在开发中。
              </span>
            </div>
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════
         Section 2: 频率限制配置模式
         ══════════════════════════════════════════════════════════ */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-teal-50 text-teal-600">
              <Zap className="h-4.5 w-4.5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900">频率限制</h2>
              <p className="text-xs text-slate-500">
                对高频访问、高频攻击和高频错误进行限制
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => updateLocal({ cc_use_custom: false })}
              className={cn(
                "rounded-md px-3 py-1.5 text-xs font-medium transition-all",
                !s.cc_use_custom
                  ? "bg-teal-600 text-white shadow-sm"
                  : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              )}
            >
              跟随全局配置
            </button>
            <button
              onClick={() => updateLocal({ cc_use_custom: true })}
              className={cn(
                "rounded-md px-3 py-1.5 text-xs font-medium transition-all",
                s.cc_use_custom
                  ? "bg-teal-600 text-white shadow-sm"
                  : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              )}
            >
              使用自定义配置
            </button>
          </div>
        </div>

        <div className="divide-y divide-slate-100">
          {/* ── 高频访问限制 ── */}
          <BuiltinRuleRow
            icon={<Zap className="h-4 w-4" />}
            iconBg="bg-cyan-50 text-cyan-600"
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
            icon={<AlertTriangle className="h-4 w-4" />}
            iconBg="bg-amber-50 text-amber-600"
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
            icon={<Ban className="h-4 w-4" />}
            iconBg="bg-rose-50 text-rose-600"
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
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div
          className="flex cursor-pointer items-center justify-between px-5 py-4"
          onClick={() => setCustomRulesExpanded(!customRulesExpanded)}
        >
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-50 text-violet-600">
              <Shield className="h-4.5 w-4.5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900">
                自定义规则
              </h2>
              <p className="text-xs text-slate-500">
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
              className="rounded-md bg-teal-600 text-white hover:bg-teal-700"
              size="sm"
            >
              <Plus className="mr-1.5 h-3.5 w-3.5" /> 添加规则
            </Button>
            {customRulesExpanded ? (
              <ChevronUp className="h-4 w-4 text-slate-400" />
            ) : (
              <ChevronDown className="h-4 w-4 text-slate-400" />
            )}
          </div>
        </div>

        {customRulesExpanded && (
          <>
            {rules.length === 0 ? (
              <div className="flex min-h-[160px] flex-col items-center justify-center border-t border-slate-100 p-8 text-center">
                <Shield className="mb-3 h-10 w-10 text-slate-300" />
                <p className="text-sm font-medium text-slate-600">
                  还没有自定义规则
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  点击「添加规则」创建第一条 CC 自定义规则
                </p>
              </div>
            ) : (
              <div className="border-t border-slate-100">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-100 bg-slate-50/80">
                        <th className="px-5 py-3 text-left text-xs font-semibold text-slate-600">
                          状态
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">
                          名称
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">
                          匹配条件
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">
                          频率规则
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">
                          动作
                        </th>
                        <th className="px-4 py-3 text-right text-xs font-semibold text-slate-600">
                          操作
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {rules.map((rule, idx) => (
                        <tr
                          key={`${rule.name}-${idx}`}
                          className="border-b border-slate-50 hover:bg-slate-50/50"
                        >
                          <td className="px-5 py-3">
                            <Switch
                              checked={rule.enabled !== false}
                              onCheckedChange={() => toggleRule(idx)}
                            />
                          </td>
                          <td className="px-4 py-3 font-medium text-slate-800">
                            {rule.name || `规则 ${idx + 1}`}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            {rule.conditions.map((c, ci) => (
                              <span
                                key={ci}
                                className="mr-1 inline-block rounded bg-slate-100 px-1.5 py-0.5 text-xs"
                              >
                                {targetOptions.find((t) => t.value === c.target)
                                  ?.label || c.target}{" "}
                                {operatorOptions.find(
                                  (o) => o.value === c.operator
                                )?.label || c.operator}{" "}
                                {c.value || "..."}
                              </span>
                            ))}
                          </td>
                          <td className="px-4 py-3 text-xs text-slate-600">
                            {rule.window}秒 / {rule.threshold}次 /{" "}
                            {rule.duration}分钟
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={cn(
                                "inline-flex rounded-md border px-2 py-0.5 text-xs font-medium",
                                getWAFActionMeta(rule.action).className
                              )}
                            >
                              {getWAFActionMeta(rule.action).shortLabel}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button
                                onClick={() => openEditRule(idx)}
                                className="rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-teal-600"
                                title="编辑"
                              >
                                <Pencil className="h-3.5 w-3.5" />
                              </button>
                              <button
                                onClick={() => deleteRule(idx)}
                                className="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600"
                                title="删除"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* ══════ Bottom Save Bar ══════ */}
      {dirty && (
        <div className="sticky bottom-0 z-10 flex items-center justify-between rounded-lg border border-teal-200 bg-teal-50/90 px-5 py-3 shadow-lg backdrop-blur-sm">
          <p className="text-sm text-teal-800">
            <Info className="mr-1.5 inline h-4 w-4" />
            配置已修改，请点击保存使更改生效
          </p>
          <Button
            onClick={saveAll}
            disabled={saving}
            className="rounded-md bg-teal-600 px-6 text-white hover:bg-teal-700"
          >
            <Save className="mr-1.5 h-4 w-4" />
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
              <Zap className="h-4 w-4 text-cyan-600" />
              编辑高频访问限制
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-5">
            <div className="rounded-md border border-slate-200 bg-slate-50 p-4">
              <p className="mb-3 text-sm text-slate-700">
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
              <label className="block text-sm">
                <span className="font-medium text-slate-700">限制结果</span>
                <Select
                  value={s.request_ratelimit_action}
                  onValueChange={(v) =>
                    updateLocal({ request_ratelimit_action: v })
                  }
                >
                  <SelectTrigger className="mt-1 rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="challenge">人机验证</SelectItem>
                    <SelectItem value="captcha_challenge">
                      验证码验证
                    </SelectItem>
                    <SelectItem value="shield_challenge">5秒盾验证</SelectItem>
                    <SelectItem value="rate_limit">限速 (429)</SelectItem>
                    <SelectItem value="intercept">直接封禁</SelectItem>
                    <SelectItem value="drop">阻断连接</SelectItem>
                  </SelectContent>
                </Select>
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setEditRequestRateOpen(false)}
            >
              取消
            </Button>
            <Button
              className="bg-teal-600 text-white hover:bg-teal-700"
              onClick={() => closeBuiltinDialog("request")}
            >
              确定
            </Button>
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
              <AlertTriangle className="h-4 w-4 text-amber-600" />
              编辑高频攻击限制
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-5">
            <div className="rounded-md border border-slate-200 bg-slate-50 p-4">
              <p className="mb-3 text-sm text-slate-700">
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
              <label className="block text-sm">
                <span className="font-medium text-slate-700">限制结果</span>
                <Select
                  value={s.auto_ban_action || "intercept"}
                  onValueChange={(v) => updateLocal({ auto_ban_action: v })}
                >
                  <SelectTrigger className="mt-1 rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="challenge">人机验证</SelectItem>
                    <SelectItem value="captcha_challenge">
                      验证码验证
                    </SelectItem>
                    <SelectItem value="shield_challenge">5秒盾验证</SelectItem>
                    <SelectItem value="intercept">直接封禁</SelectItem>
                    <SelectItem value="drop">阻断连接</SelectItem>
                  </SelectContent>
                </Select>
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setEditAttackRateOpen(false)}
            >
              取消
            </Button>
            <Button
              className="bg-teal-600 text-white hover:bg-teal-700"
              onClick={() => closeBuiltinDialog("attack")}
            >
              确定
            </Button>
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
              <Ban className="h-4 w-4 text-rose-600" />
              编辑高频错误限制
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-5">
            <div className="rounded-md border border-slate-200 bg-slate-50 p-4">
              <p className="mb-3 text-sm text-slate-700">
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

              <div className="mb-3 space-y-2">
                <span className="text-sm font-medium text-slate-700">
                  计入错误类型
                </span>
                <div className="flex flex-wrap gap-3">
                  <label className="flex items-center gap-2 text-sm text-slate-600">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-300 text-teal-600 focus:ring-teal-500"
                      checked={s.error_ratelimit_count_4xx}
                      onChange={(e) =>
                        updateLocal({
                          error_ratelimit_count_4xx: e.target.checked,
                        })
                      }
                    />
                    4xx 错误 (400,401,403,404,405,429)
                  </label>
                  <label className="flex items-center gap-2 text-sm text-slate-600">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-300 text-teal-600 focus:ring-teal-500"
                      checked={s.error_ratelimit_count_5xx}
                      onChange={(e) =>
                        updateLocal({
                          error_ratelimit_count_5xx: e.target.checked,
                        })
                      }
                    />
                    5xx 错误
                  </label>
                  <label className="flex items-center gap-2 text-sm text-slate-600">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-slate-300 text-teal-600 focus:ring-teal-500"
                      checked={s.error_ratelimit_count_block}
                      onChange={(e) =>
                        updateLocal({
                          error_ratelimit_count_block: e.target.checked,
                        })
                      }
                    />
                    WAF 拦截
                  </label>
                </div>
              </div>

              <label className="block text-sm">
                <span className="font-medium text-slate-700">限制结果</span>
                <Select
                  value={s.error_ratelimit_action}
                  onValueChange={(v) =>
                    updateLocal({ error_ratelimit_action: v })
                  }
                >
                  <SelectTrigger className="mt-1 rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="challenge">人机验证</SelectItem>
                    <SelectItem value="captcha_challenge">
                      验证码验证
                    </SelectItem>
                    <SelectItem value="shield_challenge">5秒盾验证</SelectItem>
                    <SelectItem value="rate_limit">限速 (429)</SelectItem>
                    <SelectItem value="intercept">直接封禁</SelectItem>
                    <SelectItem value="drop">阻断连接</SelectItem>
                  </SelectContent>
                </Select>
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setEditErrorRateOpen(false)}
            >
              取消
            </Button>
            <Button
              className="bg-teal-600 text-white hover:bg-teal-700"
              onClick={() => closeBuiltinDialog("error")}
            >
              确定
            </Button>
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
          <div className="space-y-4">
            {/* Name */}
            <label className="block text-sm">
              <span className="font-medium text-slate-700">
                名称 <span className="text-rose-500">*</span>
              </span>
              <Input
                className="mt-1 rounded-md"
                placeholder="规则名称"
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </label>

            {/* Conditions */}
            <div className="rounded-lg border border-slate-200 bg-slate-50/50 p-4">
              <span className="mb-2 block text-xs font-semibold text-slate-600">
                匹配条件
              </span>
              {draft.conditions.map((cond, ci) => (
                <div key={ci} className="mb-3 flex items-start gap-2">
                  <div className="grid flex-1 grid-cols-3 gap-2">
                    <div>
                      <span className="mb-1 block text-xs font-medium text-slate-500">
                        匹配目标
                      </span>
                      <Select
                        value={cond.target}
                        onValueChange={(v) =>
                          updateCondition(ci, { target: v })
                        }
                      >
                        <SelectTrigger className="rounded-md bg-white">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {targetOptions.map((t) => (
                            <SelectItem key={t.value} value={t.value}>
                              {t.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <span className="mb-1 block text-xs font-medium text-slate-500">
                        匹配方式 <span className="text-rose-500">*</span>
                      </span>
                      <Select
                        value={cond.operator}
                        onValueChange={(v) =>
                          updateCondition(ci, { operator: v })
                        }
                      >
                        <SelectTrigger className="rounded-md bg-white">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {operatorOptions.map((o) => (
                            <SelectItem key={o.value} value={o.value}>
                              {o.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <span className="mb-1 block text-xs font-medium text-slate-500">
                        匹配内容 <span className="text-rose-500">*</span>
                      </span>
                      <Input
                        className="rounded-md bg-white"
                        placeholder="例如: /api/login"
                        value={cond.value}
                        onChange={(e) =>
                          updateCondition(ci, { value: e.target.value })
                        }
                      />
                    </div>
                  </div>
                  {draft.conditions.length > 1 && (
                    <button
                      onClick={() => removeCondition(ci)}
                      className="mt-6 rounded p-1 text-slate-400 hover:bg-slate-200 hover:text-slate-600"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
              ))}
              <button
                onClick={addCondition}
                className="mt-1 rounded-md border border-dashed border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100"
              >
                + 添加一个 AND 条件
              </button>
            </div>

            {/* Params */}
            <div className="grid grid-cols-4 gap-3">
              <label className="block text-sm">
                <span className="font-medium text-slate-700">
                  经过时间 <span className="text-rose-500">*</span>
                </span>
                <div className="mt-1 flex items-center gap-1">
                  <Input
                    type="number"
                    className="rounded-md"
                    value={draft.window}
                    onChange={(e) =>
                      setDraft({ ...draft, window: Number(e.target.value) })
                    }
                  />
                  <span className="text-xs text-slate-500">秒</span>
                </div>
              </label>
              <label className="block text-sm">
                <span className="font-medium text-slate-700">
                  请求次数达到 <span className="text-rose-500">*</span>
                </span>
                <div className="mt-1 flex items-center gap-1">
                  <Input
                    type="number"
                    className="rounded-md"
                    value={draft.threshold}
                    onChange={(e) =>
                      setDraft({ ...draft, threshold: Number(e.target.value) })
                    }
                  />
                  <span className="text-xs text-slate-500">次</span>
                </div>
              </label>
              <label className="block text-sm">
                <span className="font-medium text-slate-700">限制结果</span>
                <Select
                  value={draft.action}
                  onValueChange={(v) => setDraft({ ...draft, action: v })}
                >
                  <SelectTrigger className="mt-1 rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {terminalWAFActionOptions.map((a) => (
                      <SelectItem key={a.value} value={a.value}>
                        {a.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </label>
              <label className="block text-sm">
                <span className="font-medium text-slate-700">
                  持续时间 <span className="text-rose-500">*</span>
                </span>
                <div className="mt-1 flex items-center gap-1">
                  <Input
                    type="number"
                    className="rounded-md"
                    value={draft.duration}
                    onChange={(e) =>
                      setDraft({ ...draft, duration: Number(e.target.value) })
                    }
                  />
                  <span className="text-xs text-slate-500">分钟</span>
                </div>
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRuleDialogOpen(false)}>
              取消
            </Button>
            <Button
              className="bg-teal-600 text-white hover:bg-teal-700"
              onClick={confirmRule}
              disabled={saving}
            >
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
  iconBg,
  title,
  description,
  enabled,
  onToggle,
  onEdit,
}: {
  icon: React.ReactNode
  iconBg: string
  title: string
  description: string
  enabled: boolean
  onToggle: (val: boolean) => void
  onEdit: () => void
}) {
  return (
    <div className="flex items-center justify-between px-5 py-4">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <div
          className={cn(
            "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg",
            iconBg
          )}
        >
          {icon}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-slate-900">
              {title}
            </span>
            {enabled ? (
              <span className="inline-flex items-center rounded-full bg-teal-50 px-2 py-0.5 text-[10px] font-medium text-teal-700 ring-1 ring-teal-200">
                已启用
              </span>
            ) : (
              <span className="inline-flex items-center rounded-full bg-slate-50 px-2 py-0.5 text-[10px] font-medium text-slate-500 ring-1 ring-slate-200">
                未启用
              </span>
            )}
          </div>
          <p
            className={cn(
              "mt-0.5 truncate text-xs",
              enabled ? "text-slate-600" : "text-slate-400"
            )}
          >
            {description}
          </p>
        </div>
      </div>
      <div className="ml-4 flex shrink-0 items-center gap-3">
        <button
          onClick={onEdit}
          className="flex items-center gap-1 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-teal-600"
        >
          <Pencil className="h-3 w-3" />
          编辑
        </button>
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
      <input
        type="number"
        className="inline-block w-16 rounded-md border border-slate-300 bg-white px-2 py-1 text-center text-sm font-medium text-teal-700 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      <span className="text-xs text-slate-500">{unit}</span>
    </span>
  )
}
