"use client"

import { useCallback, useEffect, useId, useState } from "react"
import { useSearchParams } from "next/navigation"
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Pencil,
  ShieldCheck,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { Checkbox } from "@/components/ui/checkbox"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Textarea } from "@/components/ui/textarea"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Separator } from "@/components/ui/separator"
import {
  MetricCard,
  MetricGrid,
  PageIntro,
  Surface,
  EmptyState,
} from "@/components/console-shell"
import {
  getWAFActionMeta,
  owaspModuleOptions,
  terminalWAFActionOptions,
} from "@/lib/console"
import {
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
} from "@/lib/api"
import { CopyableBlock } from "@/components/log-presentation"
import {
  getOWASPRules,
  getOWASPRuleStats,
  updateOWASPRule,
  batchUpdateOWASPRules,
  getSensitivityConfig,
  updateSensitivityConfig,
  type OWASPRule,
  type OWASPRuleStats,
} from "@/lib/rules-api"

const sensitivityLevels = [
  "off",
  "low",
  "mid",
  "high",
  "very_high",
  "strict",
] as const
const levelLabel: Record<string, string> = {
  off: "关闭",
  low: "低",
  mid: "中",
  medium: "中",
  high: "高",
  very_high: "极高",
  strict: "严格",
}

function normalizeSensitivityLevel(value: string | undefined) {
  return value === "medium" ? "mid" : (value ?? "off")
}

function categoryFromSearchParams(searchParams: URLSearchParams) {
  const value = searchParams.get("category")
  return value && owaspModuleOptions.some((item) => item.key === value)
    ? value
    : "all"
}

function actionBadgeVariant(
  action: string
): "default" | "secondary" | "destructive" | "outline" {
  if (action === "intercept" || action === "block" || action === "drop") {
    return "destructive"
  }
  if (
    action === "challenge" ||
    action === "captcha_challenge" ||
    action === "shield_challenge" ||
    action === "chain_challenge"
  ) {
    return "secondary"
  }
  return "outline"
}

export default function OWASPRuleManagementPage() {
  const searchParams = useSearchParams()
  const editFormIdPrefix = useId()
  const [grouped, setGrouped] = useState<Record<string, OWASPRule[]>>({})
  const [stats, setStats] = useState<OWASPRuleStats | null>(null)
  const [sensitivity, setSensitivity] = useState<Record<string, string>>({})
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [savingSens, setSavingSens] = useState(false)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [editRule, setEditRule] = useState<OWASPRule | null>(null)
  const [editForm, setEditForm] = useState({
    action: "",
    status_code: 0,
    redirect_to: "",
    sensitivity: "",
    whitelist: "",
  })
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [categoryFilter, setCategoryFilter] = useState(() =>
    categoryFromSearchParams(searchParams)
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [rulesRes, statsRes] = await Promise.all([
        getOWASPRules(categoryFilter === "all" ? undefined : categoryFilter),
        getOWASPRuleStats(),
      ])
      const items = rulesRes.items ?? []
      const groupedRules =
        rulesRes.grouped ??
        items.reduce<Record<string, OWASPRule[]>>((acc, rule) => {
          const category = rule.category || "uncategorized"
          acc[category] = [...(acc[category] ?? []), rule]
          return acc
        }, {})
      setGrouped(groupedRules)
      setStats(statsRes)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载 OWASP 规则失败")
    } finally {
      setLoading(false)
    }
  }, [categoryFilter])

  const loadSensitivity = useCallback(async () => {
    try {
      const config = await getSensitivityConfig("global")
      setSensitivity(config.category_sensitivity ?? {})
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载 OWASP 敏感度失败")
    }
  }, [])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  useEffect(() => {
    return deferEffect(loadSensitivity)
  }, [loadSensitivity])

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  async function handleToggle(id: string, enabled: boolean) {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const payload = { enabled }
    try {
      const result = await updateOWASPRule(id, payload)
      setOperationDetails({
        operation: "toggle_rule",
        rule_id: id,
        payload,
        response: result,
      })
      await load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "toggle_rule",
            rule_id: id,
            payload,
            response: details,
          })
        }
        toast.error(e.message)
        await load()
      } else {
        toast.error(e instanceof Error ? e.message : "更新 OWASP 规则失败")
      }
    }
  }

  async function batchToggleCategory(category: string, enabled: boolean) {
    const ids = (grouped[category] ?? []).map((r) => r.id)
    if (ids.length === 0) return
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const rules = ids.map((id) => ({ id, enabled }))
    const payload = { rules }
    try {
      const result = await batchUpdateOWASPRules(rules)
      setOperationDetails({
        operation: "batch_toggle_category",
        category,
        rule_ids: ids,
        payload,
        response: result,
      })
      toast.success(
        `已${enabled ? "启用" : "禁用"}类别 ${category} 的 ${ids.length} 条规则`
      )
      await load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "batch_toggle_category",
            category,
            rule_ids: ids,
            payload,
            response: details,
          })
        }
        toast.error(e.message)
        await load()
      } else {
        toast.error(e instanceof Error ? e.message : "批量更新类别规则失败")
      }
    }
  }

  async function batchToggleSelected(enabled: boolean) {
    if (selected.size === 0) return
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const ruleIds = [...selected]
    const rules = ruleIds.map((id) => ({ id, enabled }))
    const payload = { rules }
    try {
      const result = await batchUpdateOWASPRules(rules)
      setOperationDetails({
        operation: "batch_toggle_selected",
        rule_ids: ruleIds,
        payload,
        response: result,
      })
      toast.success(`已${enabled ? "启用" : "禁用"} ${selected.size} 条规则`)
      setSelected(new Set())
      await load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "batch_toggle_selected",
            rule_ids: ruleIds,
            payload,
            response: details,
          })
        }
        toast.error(e.message)
        setSelected(new Set())
        await load()
      } else {
        toast.error(e instanceof Error ? e.message : "批量更新所选规则失败")
      }
    }
  }

  async function saveSensitivity() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSavingSens(true)
    const payload = {
      category_sensitivity: sensitivity,
    }
    try {
      const result = await updateSensitivityConfig("global", payload)
      setOperationDetails({
        operation: "update_sensitivity",
        protection_id: "global",
        payload,
        response: result,
      })
      toast.success("敏感度配置已保存")
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "update_sensitivity",
            protection_id: "global",
            payload,
            response: details,
          })
        }
        toast.error(e.message)
        await loadSensitivity()
      } else {
        toast.error(e instanceof Error ? e.message : "保存敏感度配置失败")
      }
    } finally {
      setSavingSens(false)
    }
  }

  function openRuleEdit(rule: OWASPRule) {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setEditRule(rule)
    setEditForm({
      action: rule.action || "",
      status_code: rule.status_code ?? 0,
      redirect_to: rule.redirect_to ?? "",
      sensitivity: rule.sensitivity ?? "",
      whitelist: (rule.whitelist ?? []).join("\n"),
    })
  }

  async function saveRuleOverride() {
    if (!editRule) return
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const ruleId = editRule.id
    const payload = {
      action: editForm.action,
      status_code: editForm.status_code,
      redirect_to: editForm.redirect_to,
      sensitivity: editForm.sensitivity,
      whitelist: editForm.whitelist
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean),
    }
    try {
      const result = await updateOWASPRule(ruleId, payload)
      setOperationDetails({
        operation: "update_rule_override",
        rule_id: ruleId,
        payload,
        response: result,
      })
      toast.success("规则动作已更新")
      setEditRule(null)
      await load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "update_rule_override",
            rule_id: ruleId,
            payload,
            response: details,
          })
        }
        toast.error(e.message)
        setEditRule(null)
        await load()
      } else {
        toast.error(e instanceof Error ? e.message : "保存规则动作失败")
      }
    }
  }

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleCollapse(cat: string) {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(cat)) next.delete(cat)
      else next.add(cat)
      return next
    })
  }

  const categories = Object.keys(grouped).sort()

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="OWASP Rule Management"
        title="OWASP 规则管理"
        description="按类别管理 OWASP 检测规则，配置敏感度矩阵，支持批量启用/禁用操作。"
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回 OWASP 规则操作响应体；请核对 error 字段。
          </AlertDescription>
          <CopyableBlock
            label="reload 失败响应体"
            value={JSON.stringify(reloadFailureDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {operationDetails ? (
        <Alert className="gap-3">
          <ShieldCheck />
          <AlertTitle>最近 OWASP 规则操作响应</AlertTitle>
          <AlertDescription>
            后端已返回 OWASP 规则操作响应体；请核对 operation、rule_id、updated
            或 category_sensitivity 字段。
          </AlertDescription>
          <CopyableBlock
            label="OWASP 规则操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {stats && (
        <MetricGrid>
          <MetricCard
            label="全量规则总数"
            value={stats.total}
            hint="OWASP 规则总量"
          />
          <MetricCard
            label="全量已启用"
            value={stats.enabled_count}
            tone="success"
            hint="当前启用规则"
          />
          <MetricCard
            label="全量已禁用"
            value={stats.disabled_count}
            hint="当前禁用规则"
          />
          <MetricCard
            label="全量类别数"
            value={Object.keys(stats.by_category ?? {}).length}
            hint="按规则类别聚合"
          />
        </MetricGrid>
      )}

      <Tabs defaultValue="rules" className="flex flex-col gap-4">
        <div className="overflow-x-auto overscroll-x-contain rounded-lg border border-border bg-card p-1 shadow-sm">
          <TabsList className="bg-transparent">
            <TabsTrigger value="rules">规则列表</TabsTrigger>
            <TabsTrigger value="sensitivity">敏感度矩阵</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="rules" className="flex flex-col gap-4">
          <Surface title="规则筛选">
            <FieldGroup className="flex-row flex-wrap items-end gap-3">
              <Field className="w-[240px]">
                <FieldLabel>类别</FieldLabel>
                <Select
                  value={categoryFilter}
                  onValueChange={(value) => {
                    setCategoryFilter(value)
                    setSelected(new Set())
                    setCollapsed(new Set())
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="all">全部类别</SelectItem>
                      {owaspModuleOptions.map((item) => (
                        <SelectItem key={item.key} value={item.key}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
            </FieldGroup>
          </Surface>

          {selected.size > 0 && (
            <div className="flex items-center gap-3 rounded-xl border border-border bg-muted/35 px-4 py-2">
              <span className="text-sm text-muted-foreground">
                当前视图已选 {selected.size} 条
              </span>
              <Button
                size="sm"
                variant="outline"
                className="rounded-md"
                onClick={() => batchToggleSelected(true)}
              >
                批量启用
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="rounded-md"
                onClick={() => batchToggleSelected(false)}
              >
                批量禁用
              </Button>
            </div>
          )}

          {loading ? (
            <Surface>
              <EmptyState
                title="OWASP 规则加载中"
                description="正在读取规则列表、类别分组和全量统计。"
              />
            </Surface>
          ) : categories.length === 0 ? (
            <Surface>
              <EmptyState
                title="暂无 OWASP 规则"
                description="引擎未注册任何 OWASP 规则。"
              />
            </Surface>
          ) : (
            categories.map((cat) => {
              const isCollapsed = collapsed.has(cat)
              return (
                <div
                  key={cat}
                  className="console-panel overflow-hidden shadow-sm"
                >
                  <div
                    className="flex cursor-pointer items-center justify-between px-5 py-3 transition-colors hover:bg-muted/45"
                    onClick={() => toggleCollapse(cat)}
                  >
                    <div className="flex items-center gap-2">
                      {isCollapsed ? (
                        <ChevronRight className="size-4 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="size-4 text-muted-foreground" />
                      )}
                      <span className="font-semibold text-foreground">
                        {cat}
                      </span>
                      <Badge variant="outline" className="rounded-md text-xs">
                        {grouped[cat].length} 条
                      </Badge>
                    </div>
                    <div
                      className="flex gap-2"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <Button
                        size="sm"
                        variant="outline"
                        className="rounded-md text-xs"
                        onClick={() => batchToggleCategory(cat, true)}
                      >
                        全部启用
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="rounded-md text-xs"
                        onClick={() => batchToggleCategory(cat, false)}
                      >
                        全部禁用
                      </Button>
                    </div>
                  </div>
                  {!isCollapsed && (
                    <div>
                      <Separator />
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-10">
                              <Checkbox
                                checked={grouped[cat].every((r) =>
                                  selected.has(r.id)
                                )}
                                onCheckedChange={(v) => {
                                  const ids = grouped[cat].map((r) => r.id)
                                  setSelected((prev) => {
                                    const s = new Set(prev)
                                    ids.forEach((id) =>
                                      v ? s.add(id) : s.delete(id)
                                    )
                                    return s
                                  })
                                }}
                              />
                            </TableHead>
                            <TableHead>规则 ID</TableHead>
                            <TableHead>名称</TableHead>
                            <TableHead>描述</TableHead>
                            <TableHead>动作覆盖</TableHead>
                            <TableHead>敏感度覆盖</TableHead>
                            <TableHead>启用</TableHead>
                            <TableHead className="text-right">配置</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {grouped[cat].map((rule) => (
                            <TableRow key={rule.id}>
                              <TableCell>
                                <Checkbox
                                  checked={selected.has(rule.id)}
                                  onCheckedChange={() => toggleSelect(rule.id)}
                                />
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant="outline"
                                  className="rounded-md font-mono text-xs"
                                >
                                  {rule.id}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-medium text-foreground">
                                {rule.name}
                              </TableCell>
                              <TableCell className="max-w-[300px] truncate text-sm text-muted-foreground">
                                {rule.description}
                              </TableCell>
                              <TableCell>
                                {rule.action ? (
                                  <Badge
                                    variant={actionBadgeVariant(rule.action)}
                                  >
                                    {getWAFActionMeta(rule.action).shortLabel}
                                    {rule.status_code
                                      ? ` ${rule.status_code}`
                                      : ""}
                                  </Badge>
                                ) : (
                                  <span className="text-xs text-muted-foreground">
                                    继承全局
                                  </span>
                                )}
                              </TableCell>
                              <TableCell>
                                {rule.sensitivity ? (
                                  <Badge variant="outline">
                                    {levelLabel[rule.sensitivity] ??
                                      rule.sensitivity}
                                  </Badge>
                                ) : (
                                  <span className="text-xs text-muted-foreground">
                                    继承类别
                                  </span>
                                )}
                              </TableCell>
                              <TableCell>
                                <Switch
                                  checked={rule.enabled}
                                  onCheckedChange={(v) =>
                                    handleToggle(rule.id, v)
                                  }
                                />
                              </TableCell>
                              <TableCell className="text-right">
                                <Button
                                  size="icon-sm"
                                  variant="outline"
                                  className="rounded-md"
                                  aria-label="配置规则动作覆盖"
                                  onClick={() => openRuleEdit(rule)}
                                >
                                  <Pencil data-icon="inline-start" />
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </div>
              )
            })
          )}
        </TabsContent>

        <TabsContent value="sensitivity">
          <Surface
            title="敏感度矩阵"
            description="保存到全局 protection 配置；站点级 OWASP 开关仍按站点详情页的继承/覆盖设置生效。"
            action={
              <Button
                onClick={saveSensitivity}
                disabled={savingSens}
                className="rounded-md"
              >
                {savingSens ? "保存中..." : "保存配置"}
              </Button>
            }
          >
            <div className="overflow-x-auto rounded-xl border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="min-w-[160px]">类别</TableHead>
                    {sensitivityLevels.map((l) => (
                      <TableHead key={l} className="text-center">
                        {levelLabel[l]}
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {owaspModuleOptions.map((mod) => (
                    <TableRow key={mod.key}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <ShieldCheck className="size-4 text-muted-foreground" />
                          <span className="font-medium text-foreground">
                            {mod.label}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell
                        colSpan={sensitivityLevels.length}
                        className="p-0"
                      >
                        <RadioGroup
                          name={`sens-${mod.key}`}
                          value={normalizeSensitivityLevel(
                            sensitivity[mod.key]
                          )}
                          onValueChange={(level) =>
                            setSensitivity({
                              ...sensitivity,
                              [mod.key]: level,
                            })
                          }
                          className="grid w-full grid-cols-6 gap-0"
                        >
                          {sensitivityLevels.map((level) => (
                            <div
                              key={level}
                              className="flex h-10 items-center justify-center px-2"
                            >
                              <RadioGroupItem
                                value={level}
                                aria-label={`${mod.label} ${levelLabel[level]}`}
                              />
                            </div>
                          ))}
                        </RadioGroup>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Surface>
        </TabsContent>
      </Tabs>

      <Dialog
        open={!!editRule}
        onOpenChange={(open) => {
          if (!open) setEditRule(null)
        }}
      >
        <DialogContent className="max-w-lg rounded-lg">
          <DialogHeader>
            <DialogTitle>规则级覆盖</DialogTitle>
            <DialogDescription>
              {editRule?.id} — 留空动作和敏感度表示继承站点/全局 OWASP 配置。
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor={`${editFormIdPrefix}-action`}>
                动作
              </FieldLabel>
              <Select
                value={editForm.action || "inherit"}
                onValueChange={(v) =>
                  setEditForm({ ...editForm, action: v === "inherit" ? "" : v })
                }
              >
                <SelectTrigger id={`${editFormIdPrefix}-action`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="inherit">继承全局/站点</SelectItem>
                    {terminalWAFActionOptions.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel htmlFor={`${editFormIdPrefix}-sensitivity`}>
                敏感度
              </FieldLabel>
              <Select
                value={editForm.sensitivity || "inherit"}
                onValueChange={(v) =>
                  setEditForm({
                    ...editForm,
                    sensitivity: v === "inherit" ? "" : v,
                  })
                }
              >
                <SelectTrigger id={`${editFormIdPrefix}-sensitivity`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="inherit">继承类别/全局</SelectItem>
                    {sensitivityLevels.map((level) => (
                      <SelectItem key={level} value={level}>
                        {levelLabel[level]}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <FieldGroup className="grid gap-4 md:grid-cols-2">
              <Field>
                <FieldLabel htmlFor={`${editFormIdPrefix}-status-code`}>
                  状态码
                </FieldLabel>
                <Input
                  id={`${editFormIdPrefix}-status-code`}
                  type="number"
                  min={0}
                  value={editForm.status_code}
                  onChange={(e) =>
                    setEditForm({
                      ...editForm,
                      status_code: Number(e.target.value),
                    })
                  }
                  disabled={
                    editForm.action === "drop" || editForm.action === "observe"
                  }
                />
              </Field>
              <Field>
                <FieldLabel htmlFor={`${editFormIdPrefix}-redirect-to`}>
                  重定向地址
                </FieldLabel>
                <Input
                  id={`${editFormIdPrefix}-redirect-to`}
                  value={editForm.redirect_to}
                  onChange={(e) =>
                    setEditForm({ ...editForm, redirect_to: e.target.value })
                  }
                  disabled={editForm.action !== "redirect"}
                  placeholder="https://example.com/blocked"
                />
              </Field>
            </FieldGroup>
            <Field>
              <FieldLabel htmlFor={`${editFormIdPrefix}-whitelist`}>
                白名单路径
              </FieldLabel>
              <Textarea
                id={`${editFormIdPrefix}-whitelist`}
                value={editForm.whitelist}
                onChange={(e) =>
                  setEditForm({ ...editForm, whitelist: e.target.value })
                }
                className="min-h-24"
                placeholder={"/api/health\n/status"}
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button
              variant="outline"
              className="rounded-md"
              onClick={() => setEditRule(null)}
            >
              取消
            </Button>
            <Button className="rounded-md" onClick={saveRuleOverride}>
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
