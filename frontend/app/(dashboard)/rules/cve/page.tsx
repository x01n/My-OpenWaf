"use client"

import { useCallback, useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import {
  Plus,
  RefreshCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Trash2,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Pagination } from "@/components/pagination"
import {
  MetricCard,
  MetricGrid,
  PageIntro,
  Surface,
  EmptyState,
} from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"
import {
  createCVERule,
  deleteCVERule,
  getCVEFeedStatus,
  getCVERules,
  patchCVERule,
  syncCVERules,
  toggleCVERule,
  updateCVERule,
  type CVEFeedStatus,
  type CVERule,
  type CVERuleQuery,
} from "@/lib/api"
import {
  getCVERuleStats,
  batchToggleCVERules,
  type CVERuleStats,
} from "@/lib/rules-api"
import { getWAFActionMeta, nonRedirectWAFActionOptions } from "@/lib/console"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

const cveCategoryOptions = ["general", "java", "node", "php"]
const cveSeverityOptions = ["critical", "high", "medium", "low"]
const cveTargetOptions = ["url", "body", "url_body", "header", "cookie"]
const cveSourceOptions = ["custom", "auto_generated", "manual", "nvd", "github"]

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback
}

type CVERuleFormState = {
  cve_id: string
  category: string
  pattern: string
  target: string
  severity: string
  action: string
  description: string
  enabled: boolean
}

type CVEQuickPatchFormState = Pick<
  CVERuleFormState,
  "enabled" | "severity" | "action"
>

const emptyCVERuleForm: CVERuleFormState = {
  cve_id: "",
  category: "general",
  pattern: "",
  target: "url",
  severity: "medium",
  action: "intercept",
  description: "",
  enabled: true,
}

const emptyCVEQuickPatchForm: CVEQuickPatchFormState = {
  enabled: true,
  severity: "medium",
  action: "intercept",
}

const severityMeta: Record<
  string,
  {
    className: string
    icon: React.ReactNode
  }
> = {
  critical: {
    className: "border-destructive/25 bg-destructive/10 text-destructive",
    icon: <ShieldAlert data-icon="inline-start" />,
  },
  high: {
    className: "border-chart-5/25 bg-chart-5/10 text-foreground",
    icon: <AlertTriangle data-icon="inline-start" />,
  },
  medium: {
    className: "border-chart-3/25 bg-chart-3/10 text-foreground",
    icon: <Shield data-icon="inline-start" />,
  },
  low: {
    className: "border-border bg-muted/45 text-muted-foreground",
    icon: <ShieldCheck data-icon="inline-start" />,
  },
}

function severityBadgeMeta(severity: string) {
  return (
    severityMeta[severity] ?? {
      className: "border-border bg-muted/45 text-muted-foreground",
      icon: <Shield data-icon="inline-start" />,
    }
  )
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

function cveSourceLabel(source: string) {
  const labels: Record<string, string> = {
    custom: "自定义",
    auto_generated: "自动生成",
    manual: "手动",
    nvd: "NVD",
    github: "GitHub",
  }

  return labels[source] ?? (source || "-")
}

function cveTargetLabel(target: string) {
  const labels: Record<string, string> = {
    url: "URL",
    body: "Body",
    url_body: "URL + Body",
    header: "Header",
    cookie: "Cookie",
  }

  return labels[target] ?? (target || "-")
}

function toCVEForm(rule: CVERule): CVERuleFormState {
  return {
    cve_id: rule.cve_id,
    category: rule.category || "general",
    pattern: rule.pattern || "",
    target: rule.target || "url",
    severity: rule.severity || "medium",
    action: rule.action || "intercept",
    description: rule.description || "",
    enabled: rule.enabled,
  }
}

function selectValueFromSearchParams(
  searchParams: URLSearchParams,
  key: string,
  allowed: readonly string[]
) {
  const value = searchParams.get(key)
  return value && allowed.includes(value) ? value : "all"
}

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

export default function CVERuleManagementPage() {
  const searchParams = useSearchParams()
  const [items, setItems] = useState<CVERule[]>([])
  const [stats, setStats] = useState<CVERuleStats | null>(null)
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [category, setCategory] = useState(() =>
    selectValueFromSearchParams(searchParams, "category", cveCategoryOptions)
  )
  const [severity, setSeverity] = useState(() =>
    selectValueFromSearchParams(searchParams, "severity", cveSeverityOptions)
  )
  const [source, setSource] = useState(() =>
    selectValueFromSearchParams(searchParams, "source", cveSourceOptions)
  )
  const [enabled, setEnabled] = useState(() =>
    selectValueFromSearchParams(searchParams, "enabled", ["true", "false"])
  )
  const [search, setSearch] = useState("")
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [loading, setLoading] = useState(true)
  const [editRule, setEditRule] = useState<CVERule | null>(null)
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false)
  const [ruleForm, setRuleForm] =
    useState<CVERuleFormState>(emptyCVERuleForm)
  const [savingRule, setSavingRule] = useState(false)
  const [quickPatchRule, setQuickPatchRule] = useState<CVERule | null>(null)
  const [quickPatchForm, setQuickPatchForm] =
    useState<CVEQuickPatchFormState>(emptyCVEQuickPatchForm)
  const [savingQuickPatch, setSavingQuickPatch] = useState(false)
  const [deleteRule, setDeleteRule] = useState<CVERule | null>(null)
  const [deletingRule, setDeletingRule] = useState(false)
  const [feedStatus, setFeedStatus] = useState<CVEFeedStatus | null>(null)
  const [feedLoading, setFeedLoading] = useState(false)
  const [syncingRules, setSyncingRules] = useState(false)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: CVERuleQuery = { page, page_size: PAGE_SIZE }
      if (category !== "all") params.category = category
      if (severity !== "all") params.severity = severity
      if (source !== "all") params.source = source
      if (enabled !== "all") params.enabled = enabled
      const res = await getCVERules(params)
      let list = res.items ?? []
      if (search) {
        const q = search.toLowerCase()
        list = list.filter(
          (r) =>
            r.cve_id.toLowerCase().includes(q) ||
            r.description?.toLowerCase().includes(q)
        )
      }
      setItems(list)
      setTotal(res.total ?? 0)
    } catch (e) {
      toast.error(errorMessage(e, "加载 CVE 规则失败"))
      setItems([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [page, category, severity, source, enabled, search])

  const loadStats = useCallback(async () => {
    try {
      const nextStats = await getCVERuleStats()
      setStats(nextStats)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载 CVE 统计失败")
    }
  }, [])

  const loadFeedStatus = useCallback(async () => {
    setFeedLoading(true)
    try {
      const nextStatus = await getCVEFeedStatus()
      setFeedStatus(nextStatus)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载 CVE 同步状态失败")
      setFeedStatus(null)
    } finally {
      setFeedLoading(false)
    }
  }, [])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  useEffect(() => {
    return deferEffect(() => setSelected(new Set()))
  }, [page, category, severity, source, enabled, search])

  useEffect(() => {
    return deferEffect(loadStats)
  }, [loadStats])

  useEffect(() => {
    return deferEffect(loadFeedStatus)
  }, [loadFeedStatus])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  function toggleSelect(id: number) {
    setSelected((prev) => {
      const s = new Set(prev)
      if (s.has(id)) {
        s.delete(id)
      } else {
        s.add(id)
      }
      return s
    })
  }

  function selectAll() {
    if (selected.size === items.length) setSelected(new Set())
    else setSelected(new Set(items.map((r) => r.id)))
  }

  async function batchToggle(en: boolean) {
    if (selected.size === 0) return
    const ruleIds = [...selected]
    const payload = { ids: ruleIds, enabled: en }
    setOperationDetails(null)
    try {
      const result = await batchToggleCVERules(ruleIds, en)
      setOperationDetails({
        operation: "batch_toggle",
        rule_ids: ruleIds,
        payload,
        response: result,
      })
      toast.success(`已${en ? "启用" : "禁用"} ${ruleIds.length} 条规则`)
      setSelected(new Set())
      await Promise.all([load(), loadStats()])
    } catch (e) {
      toast.error(errorMessage(e, "批量更新 CVE 规则失败"))
    }
  }

  async function handleToggle(rule: CVERule) {
    setOperationDetails(null)
    try {
      const payload = { enabled: !rule.enabled }
      const result = await toggleCVERule(rule.id, payload.enabled)
      setOperationDetails({
        operation: "toggle",
        rule_id: rule.id,
        cve_id: rule.cve_id,
        payload,
        response: result,
      })
      await Promise.all([load(), loadStats()])
    } catch (e) {
      toast.error(errorMessage(e, "更新 CVE 规则状态失败"))
    }
  }

  function openCreateRule() {
    setEditRule(null)
    setRuleForm(emptyCVERuleForm)
    setRuleDialogOpen(true)
  }

  function openEditRule(rule: CVERule) {
    setEditRule(rule)
    setRuleForm(toCVEForm(rule))
    setRuleDialogOpen(true)
  }

  function openQuickPatchRule(rule: CVERule) {
    setQuickPatchRule(rule)
    setQuickPatchForm({
      enabled: rule.enabled,
      severity: rule.severity || "medium",
      action: rule.action || "intercept",
    })
  }

  function patchRuleForm(patch: Partial<CVERuleFormState>) {
    setRuleForm((prev) => ({ ...prev, ...patch }))
  }

  function patchQuickPatchForm(patch: Partial<CVEQuickPatchFormState>) {
    setQuickPatchForm((prev) => ({ ...prev, ...patch }))
  }

  async function saveRule() {
    const payload = {
      cve_id: ruleForm.cve_id.trim(),
      category: ruleForm.category.trim(),
      pattern: ruleForm.pattern.trim(),
      target: ruleForm.target.trim(),
      severity: ruleForm.severity.trim(),
      action: ruleForm.action.trim(),
      description: ruleForm.description.trim(),
      enabled: ruleForm.enabled,
    }

    if (!payload.cve_id) {
      toast.error("请输入 CVE 编号")
      return
    }
    if (!payload.category) {
      toast.error("请选择分类")
      return
    }
    if (!payload.pattern) {
      toast.error("请输入正则匹配表达式")
      return
    }
    if (!payload.target) {
      toast.error("请选择匹配目标")
      return
    }
    if (!payload.severity) {
      toast.error("请选择严重等级")
      return
    }
    if (!payload.action) {
      toast.error("请选择命中动作")
      return
    }

    setSavingRule(true)
    setOperationDetails(null)
    try {
      if (editRule) {
        const result = await updateCVERule(editRule.id, payload)
        setOperationDetails({
          operation: "update",
          rule_id: editRule.id,
          cve_id: editRule.cve_id,
          payload,
          response: result,
        })
        toast.success("规则已更新")
      } else {
        const result = await createCVERule(payload)
        setOperationDetails({
          operation: "create",
          payload,
          response: result,
        })
        toast.success("自定义规则已创建")
        setPage(1)
      }
      setRuleDialogOpen(false)
      setEditRule(null)
      await Promise.all([load(), loadStats()])
    } catch (e) {
      toast.error(errorMessage(e, "保存 CVE 规则失败"))
    } finally {
      setSavingRule(false)
    }
  }

  async function handleDeleteRule() {
    if (!deleteRule || deleteRule.source !== "custom") return
    setDeletingRule(true)
    setOperationDetails(null)
    try {
      const result = await deleteCVERule(deleteRule.id)
      setOperationDetails({
        operation: "delete",
        rule_id: deleteRule.id,
        cve_id: deleteRule.cve_id,
        payload: { rule_id: deleteRule.id },
        response: result,
      })
      toast.success("自定义规则已删除")
      setSelected((prev) => {
        const next = new Set(prev)
        next.delete(deleteRule.id)
        return next
      })
      setDeleteRule(null)
      await Promise.all([load(), loadStats()])
    } catch (e) {
      toast.error(errorMessage(e, "删除 CVE 规则失败"))
    } finally {
      setDeletingRule(false)
    }
  }

  async function saveQuickPatchRule() {
    if (!quickPatchRule) return
    setSavingQuickPatch(true)
    setOperationDetails(null)
    try {
      const payload = {
        enabled: quickPatchForm.enabled,
        action: quickPatchForm.action.trim(),
        severity: quickPatchForm.severity.trim(),
      }
      const result = await patchCVERule(quickPatchRule.id, payload)
      setOperationDetails({
        operation: "quick_patch",
        rule_id: quickPatchRule.id,
        cve_id: quickPatchRule.cve_id,
        payload,
        response: result,
      })
      toast.success("CVE 规则运行字段已更新")
      setQuickPatchRule(null)
      await Promise.all([load(), loadStats()])
    } catch (e) {
      toast.error(errorMessage(e, "快速调整 CVE 规则失败"))
    } finally {
      setSavingQuickPatch(false)
    }
  }

  async function handleSyncRules() {
    setSyncingRules(true)
    setOperationDetails(null)
    const payload = null
    try {
      const result = await syncCVERules()
      setOperationDetails({
        operation: "sync",
        payload,
        response: result,
      })
      toast.success(result.message || "CVE 规则同步完成")
      await Promise.all([load(), loadStats(), loadFeedStatus()])
    } catch (e) {
      toast.error(errorMessage(e, "同步 CVE 规则失败"))
      await loadFeedStatus()
    } finally {
      setSyncingRules(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="CVE Rule Management"
        title="CVE 规则管理"
        description="筛选、搜索、批量操作和编辑 CVE 漏洞检测规则；顶部统计为全量规则，搜索仅过滤当前页。"
      />

      {operationDetails ? (
        <Alert className="gap-3">
          <ShieldAlert />
          <AlertTitle>最近 CVE 操作响应</AlertTitle>
          <AlertDescription>
            已记录最近一次 CVE 规则操作、提交内容和后端响应体；请核对
            operation、payload、response 与规则标识。
          </AlertDescription>
          <CopyableBlock
            label="CVE 操作详情"
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
            hint="后端 CVE 规则总量"
          />
          <MetricCard
            label="全量已启用"
            value={stats.enabled}
            tone="success"
            hint="当前启用规则"
          />
          <MetricCard
            label="Critical"
            value={stats.by_severity?.critical ?? 0}
            tone="danger"
            hint="严重等级 Critical"
          />
          <MetricCard
            label="High"
            value={stats.by_severity?.high ?? 0}
            tone="warning"
            hint="严重等级 High"
          />
        </MetricGrid>
      )}

      <Surface
        title="同步状态"
        description="查看 CVE feed 同步进度、待审核规则数和最近错误。"
        action={
          <Button
            size="sm"
            variant="outline"
            className="rounded-md"
            onClick={handleSyncRules}
            disabled={syncingRules || feedStatus?.syncing === true}
          >
            <RefreshCcw
              data-icon="inline-start"
              className={
                syncingRules || feedStatus?.syncing ? "animate-spin" : ""
              }
            />
            {syncingRules || feedStatus?.syncing ? "同步中..." : "立即同步"}
          </Button>
        }
      >
        <div className="grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border bg-card p-3">
            <div className="text-xs font-medium text-muted-foreground">
              同步状态
            </div>
            <div className="mt-2">
              <Badge variant={feedStatus?.syncing ? "secondary" : "outline"}>
                {feedStatus?.syncing
                  ? "同步中"
                  : feedLoading
                    ? "检查中"
                    : "空闲"}
              </Badge>
            </div>
          </div>
          <div className="rounded-lg border bg-card p-3">
            <div className="text-xs font-medium text-muted-foreground">
              最近同步
            </div>
            <div className="mt-2 text-sm font-medium">
              {feedStatus?.last_sync ? formatDate(feedStatus.last_sync) : "-"}
            </div>
          </div>
          <div className="rounded-lg border bg-card p-3">
            <div className="text-xs font-medium text-muted-foreground">
              待审核
            </div>
            <div className="mt-2 text-sm font-medium">
              {feedStatus?.pending_review ?? 0}
            </div>
          </div>
          <div className="rounded-lg border bg-card p-3">
            <div className="text-xs font-medium text-muted-foreground">
              最近错误
            </div>
            <div className="mt-2 line-clamp-2 text-sm font-medium">
              {feedStatus?.last_error || "-"}
            </div>
          </div>
        </div>
      </Surface>

      <Surface
        title="规则列表"
        description="按后端筛选条件分页管理 CVE 检测规则；全选与批量操作仅作用于当前页已选规则。"
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            {selected.size > 0 && (
              <>
                <span className="text-sm text-muted-foreground">
                  当前页已选 {selected.size} 条
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  className="rounded-md"
                  onClick={() => batchToggle(true)}
                >
                  批量启用
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="rounded-md"
                  onClick={() => batchToggle(false)}
                >
                  批量禁用
                </Button>
              </>
            )}
            <Button size="sm" className="rounded-md" onClick={openCreateRule}>
              <Plus data-icon="inline-start" />
              新增自定义规则
            </Button>
          </div>
        }
      >
        <div className="mb-4 flex flex-wrap gap-3">
          <Select
            value={category}
            onValueChange={(v) => {
              setCategory(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[140px] rounded-md">
              <SelectValue placeholder="分类" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部分类</SelectItem>
                <SelectItem value="general">general</SelectItem>
                <SelectItem value="java">java</SelectItem>
                <SelectItem value="node">node</SelectItem>
                <SelectItem value="php">php</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select
            value={severity}
            onValueChange={(v) => {
              setSeverity(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[140px] rounded-md">
              <SelectValue placeholder="严重等级" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部等级</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select
            value={source}
            onValueChange={(value) => {
              setSource(value)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[150px] rounded-md">
              <SelectValue placeholder="来源" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部来源</SelectItem>
                {cveSourceOptions.map((item) => (
                  <SelectItem key={item} value={item}>
                    {cveSourceLabel(item)}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select
            value={enabled}
            onValueChange={(v) => {
              setEnabled(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[120px] rounded-md">
              <SelectValue placeholder="状态" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部状态</SelectItem>
                <SelectItem value="true">启用</SelectItem>
                <SelectItem value="false">禁用</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <div className="relative min-w-[200px] flex-1">
            <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="当前页搜索 CVE 编号或描述..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(1)
              }}
              className="rounded-md pl-9"
            />
          </div>
          {search && (
            <span className="text-xs text-muted-foreground">
              搜索仅过滤当前页结果；分类、等级和状态筛选会影响后端分页总数。
            </span>
          )}
        </div>

        {loading ? (
          <EmptyState
            title="CVE 规则加载中"
            description="正在读取规则列表、分页统计和筛选条件。"
          />
        ) : items.length === 0 ? (
          <EmptyState
            title="暂无匹配规则"
            description="当前筛选条件下没有 CVE 规则。"
          />
        ) : (
          <div className="flex flex-col gap-4">
            <div className="overflow-x-auto rounded-xl border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={
                          selected.size === items.length && items.length > 0
                        }
                        onCheckedChange={selectAll}
                      />
                    </TableHead>
                    <TableHead className="w-16">ID</TableHead>
                    <TableHead>名称</TableHead>
                    <TableHead>CVE 编号</TableHead>
                    <TableHead>严重等级</TableHead>
                    <TableHead>分类</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>目标</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead>启用</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell>
                        <Checkbox
                          checked={selected.has(rule.id)}
                          onCheckedChange={() => toggleSelect(rule.id)}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {rule.id}
                      </TableCell>
                      <TableCell>
                        <div className="max-w-[220px] truncate font-medium text-foreground">
                          {rule.description || "未命名"}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-sm text-foreground">
                          {rule.cve_id}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`rounded-md ${severityBadgeMeta(rule.severity).className}`}
                        >
                          {severityBadgeMeta(rule.severity).icon}
                          {rule.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="rounded-md">
                          {rule.category}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            rule.source === "custom" ? "default" : "outline"
                          }
                        >
                          {cveSourceLabel(rule.source)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs text-muted-foreground">
                          {cveTargetLabel(rule.target)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={actionBadgeVariant(rule.action)}>
                          {getWAFActionMeta(rule.action).shortLabel}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={rule.enabled}
                          onCheckedChange={() => handleToggle(rule)}
                        />
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            variant="secondary"
                            className="rounded-md"
                            onClick={() => openQuickPatchRule(rule)}
                          >
                            快速调整
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="rounded-md"
                            onClick={() => openEditRule(rule)}
                          >
                            编辑
                          </Button>
                          {rule.source === "custom" && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="rounded-md text-destructive"
                              onClick={() => setDeleteRule(rule)}
                            >
                              <Trash2 data-icon="inline-start" />
                              删除
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Pagination
              page={page}
              totalPages={totalPages}
              total={total}
              pageSize={PAGE_SIZE}
              onPageChange={setPage}
            />
          </div>
        )}
      </Surface>

      <Dialog
        open={ruleDialogOpen}
        onOpenChange={(open) => {
          setRuleDialogOpen(open)
          if (!open && !savingRule) {
            setEditRule(null)
            setRuleForm(emptyCVERuleForm)
          }
        }}
      >
        <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>
              {editRule ? "编辑 CVE 规则" : "新增自定义 CVE 规则"}
            </DialogTitle>
            <DialogDescription>
              {editRule
                ? "更新后端 CVE 规则完整字段；保存时会触发 CVE 规则重载。"
                : "创建后端 source 为 custom 的自定义 CVE 检测规则。"}
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field
              orientation="horizontal"
              className="justify-between rounded-xl border border-border bg-muted/35 px-4 py-3"
            >
              <FieldLabel htmlFor="cve-rule-enabled">启用状态</FieldLabel>
              <Switch
                id="cve-rule-enabled"
                checked={ruleForm.enabled}
                onCheckedChange={(enabled) => patchRuleForm({ enabled })}
              />
            </Field>
            <div className="grid gap-4 md:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="cve-rule-id">CVE 编号</FieldLabel>
                <Input
                  id="cve-rule-id"
                  value={ruleForm.cve_id}
                  onChange={(event) =>
                    patchRuleForm({ cve_id: event.target.value })
                  }
                  placeholder="CVE-2024-0001"
                  className="font-mono"
                />
              </Field>
              <Field>
                <FieldLabel>分类</FieldLabel>
                <Select
                  value={ruleForm.category}
                  onValueChange={(category) => patchRuleForm({ category })}
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {cveCategoryOptions.map((item) => (
                        <SelectItem key={item} value={item}>
                          {item}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
            </div>
            <div className="grid gap-4 md:grid-cols-3">
              <Field>
                <FieldLabel>匹配目标</FieldLabel>
                <Select
                  value={ruleForm.target}
                  onValueChange={(target) => patchRuleForm({ target })}
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {cveTargetOptions.map((item) => (
                        <SelectItem key={item} value={item}>
                          {cveTargetLabel(item)}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
                <FieldDescription>
                  后端检测器支持 url、body、url_body、header、cookie。
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel>严重等级</FieldLabel>
                <Select
                  value={ruleForm.severity}
                  onValueChange={(severity) => patchRuleForm({ severity })}
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {cveSeverityOptions.map((item) => (
                        <SelectItem key={item} value={item}>
                          {item}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel>命中动作</FieldLabel>
                <Select
                  value={ruleForm.action}
                  onValueChange={(action) => patchRuleForm({ action })}
                >
                  <SelectTrigger className="rounded-md">
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
              </Field>
            </div>
            <Field>
              <FieldLabel htmlFor="cve-rule-pattern">正则匹配表达式</FieldLabel>
              <Textarea
                id="cve-rule-pattern"
                value={ruleForm.pattern}
                onChange={(event) =>
                  patchRuleForm({ pattern: event.target.value })
                }
                className="min-h-28 font-mono text-xs"
                placeholder="(?i)(?:payload|exploit)"
              />
              <FieldDescription>
                后端保存前会使用 regexp.Compile 校验此表达式。
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="cve-rule-description">描述</FieldLabel>
              <Textarea
                id="cve-rule-description"
                value={ruleForm.description}
                onChange={(event) =>
                  patchRuleForm({ description: event.target.value })
                }
                className="min-h-24"
                placeholder="规则说明、漏洞影响或匹配依据"
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button
              variant="outline"
              className="rounded-md"
              disabled={savingRule}
              onClick={() => setRuleDialogOpen(false)}
            >
              取消
            </Button>
            <Button onClick={saveRule} disabled={savingRule} className="rounded-md">
              {savingRule ? "保存中..." : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog
        open={!!quickPatchRule}
        onOpenChange={(open) => {
          if (!open && !savingQuickPatch) {
            setQuickPatchRule(null)
            setQuickPatchForm(emptyCVEQuickPatchForm)
          }
        }}
      >
        <DialogContent className="max-w-xl rounded-lg">
          <DialogHeader>
            <DialogTitle>快速调整 CVE 规则</DialogTitle>
            <DialogDescription>
              使用操作员级补丁接口更新启用状态、严重等级和命中动作，不修改 CVE
              编号、匹配目标、正则表达式或描述。
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field
              orientation="horizontal"
              className="justify-between rounded-xl border bg-muted/35 px-4 py-3"
            >
              <FieldLabel htmlFor="cve-rule-quick-enabled">
                启用状态
              </FieldLabel>
              <Switch
                id="cve-rule-quick-enabled"
                checked={quickPatchForm.enabled}
                onCheckedChange={(enabled) => patchQuickPatchForm({ enabled })}
              />
            </Field>
            <div className="grid gap-4 md:grid-cols-2">
              <Field>
                <FieldLabel>严重等级</FieldLabel>
                <Select
                  value={quickPatchForm.severity}
                  onValueChange={(severity) =>
                    patchQuickPatchForm({ severity })
                  }
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {cveSeverityOptions.map((item) => (
                        <SelectItem key={item} value={item}>
                          {item}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel>命中动作</FieldLabel>
                <Select
                  value={quickPatchForm.action}
                  onValueChange={(action) => patchQuickPatchForm({ action })}
                >
                  <SelectTrigger className="rounded-md">
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
              </Field>
            </div>
            <Field className="rounded-xl border bg-muted/35 px-4 py-3">
              <FieldLabel>规则范围</FieldLabel>
              <FieldDescription className="font-mono">
                {quickPatchRule
                  ? `${quickPatchRule.id} / ${quickPatchRule.cve_id} / ${cveSourceLabel(quickPatchRule.source)}`
                  : "-"}
              </FieldDescription>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button
              variant="outline"
              className="rounded-md"
              disabled={savingQuickPatch}
              onClick={() => setQuickPatchRule(null)}
            >
              取消
            </Button>
            <Button
              onClick={saveQuickPatchRule}
              disabled={savingQuickPatch}
              className="rounded-md"
            >
              {savingQuickPatch ? "保存中..." : "保存调整"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <AlertDialog
        open={!!deleteRule}
        onOpenChange={(open) => {
          if (!open && !deletingRule) setDeleteRule(null)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除自定义 CVE 规则</AlertDialogTitle>
            <AlertDialogDescription>
              确定删除规则「{deleteRule?.cve_id || "-"}」？后端仅允许删除
              source 为 custom 的规则，删除后会触发 CVE 规则重载。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletingRule}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deletingRule}
              onClick={(event) => {
                event.preventDefault()
                void handleDeleteRule()
              }}
            >
              {deletingRule ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
