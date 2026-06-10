"use client"

import {
  Suspense,
  type ChangeEvent,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from "react"
import { useSearchParams, useRouter } from "next/navigation"
import {
  AlertTriangle,
  Download,
  FileUp,
  Plus,
  Search,
  Pencil,
  Trash2,
  X,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import Link from "next/link"
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
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
import { Skeleton } from "@/components/ui/skeleton"
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Pagination } from "@/components/pagination"
import { PageIntro, Surface, EmptyState } from "@/components/console-shell"
import { RuleBuilder } from "@/components/rule-builder"
import {
  createRule,
  deleteRule,
  exportRules,
  getConfigAppliedReloadFailureDetails,
  getConfigAppliedReloadFailureItem,
  getRule,
  getRuleTemplates,
  getRules,
  importRules as importRulesAPI,
  isConfigAppliedReloadFailureError,
  listAllPolicies,
  type Rule,
  type Policy,
  type RuleQuery,
  type RuleTemplate,
  updateRule,
} from "@/lib/api"
import {
  getWAFActionMeta,
  ruleWAFActionOptions,
  phaseLabels,
} from "@/lib/console"
import { downloadTextFile } from "@/lib/download"
import { CopyableBlock } from "@/components/log-presentation"

const PAGE_SIZE = 20

interface RuleFormData {
  name: string
  phase: string
  pattern: string
  action: string
  priority: number
  enabled: boolean
  status_code: number
  redirect_to: string
  policy_id?: number
  description?: string
}

const emptyForm: RuleFormData = {
  name: "",
  phase: "acl",
  pattern: "",
  action: "intercept",
  priority: 100,
  enabled: true,
  status_code: 0,
  redirect_to: "",
}

type RuleBadgeVariant = "outline" | "secondary" | "destructive"

const ruleActionBadgeVariants: Record<string, RuleBadgeVariant> = {
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

function rulePageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

function rulePolicyIdFromSearchParams(searchParams: URLSearchParams) {
  const value = searchParams.get("policy_id")
  if (!value) return "all"
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0 ? value : "all"
}

function CustomRulesContent() {
  const formIdPrefix = useId()
  const searchParams = useSearchParams()
  const router = useRouter()
  const urlPolicyId = rulePolicyIdFromSearchParams(searchParams)
  const importFileInputRef = useRef<HTMLInputElement>(null)

  const [items, setItems] = useState<Rule[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [page, setPage] = useState(() =>
    rulePageFromSearchParams(searchParams)
  )
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState(() => searchParams.get("q") ?? "")
  const [filterPolicyId, setFilterPolicyId] = useState<string>(
    () => urlPolicyId
  )
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState<RuleFormData>(emptyForm)
  const [saving, setSaving] = useState(false)
  const [importing, setImporting] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [importRules, setImportRules] = useState<RuleFormData[] | null>(null)
  const [exporting, setExporting] = useState(false)
  const [templateDialogOpen, setTemplateDialogOpen] = useState(false)
  const [templates, setTemplates] = useState<RuleTemplate[]>([])
  const [templatesLoading, setTemplatesLoading] = useState(false)
  const [loadingEditId, setLoadingEditId] = useState<number | null>(null)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  // Load policies list for the filter dropdown
  useEffect(() => {
    listAllPolicies()
      .then((data) => setPolicies(data.items || []))
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载策略列表失败")
      )
  }, [])

  // Sync URL param to filter state
  useEffect(() => {
    return deferEffect(() => setFilterPolicyId(urlPolicyId))
  }, [urlPolicyId])

  const activePolicyId =
    filterPolicyId !== "all" ? Number(filterPolicyId) : undefined
  const activePolicy = activePolicyId
    ? policies.find((p) => p.id === activePolicyId)
    : undefined

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: RuleQuery = { page, page_size: PAGE_SIZE }
      if (activePolicyId) params.policy_id = activePolicyId
      if (search.trim()) params.q = search.trim()
      const res = await getRules(params)
      setItems(res.items ?? [])
      setTotal(res.total ?? 0)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载规则列表失败")
      setItems([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [page, search, activePolicyId])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  function rememberRuleReloadFailureOperation(
    error: unknown,
    operation: "create" | "update",
    payload: Record<string, unknown>,
    ruleId?: number | null
  ) {
    const item = getConfigAppliedReloadFailureItem<Rule>(error)
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    setOperationDetails({
      operation,
      rule_id: ruleId ?? item?.id ?? null,
      payload,
      response: {
        item,
        reload_failed: true,
        reload_error: error instanceof Error ? error.message : null,
        reload_failure: details,
      },
    })
  }

  function rememberRuleImportReloadFailureOperation(
    error: unknown,
    rules: RuleFormData[]
  ) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    setOperationDetails({
      operation: "import",
      payload: {
        rules,
      },
      response: {
        imported:
          typeof details?.imported === "number" ? details.imported : null,
        total: typeof details?.total === "number" ? details.total : null,
        reload_failed: true,
        reload_error: error instanceof Error ? error.message : null,
        reload_failure: details,
      },
    })
  }

  function handlePolicyFilterChange(value: string) {
    setFilterPolicyId(value)
    setPage(1)
    // Update URL without full navigation
    if (value === "all") {
      router.replace("/rules/")
    } else {
      router.replace(`/rules/?policy_id=${value}`)
    }
  }

  function openCreate() {
    setReloadFailureDetails(null)
    setEditingId(null)
    setForm({
      ...emptyForm,
      policy_id: activePolicyId,
    })
    setDialogOpen(true)
  }

  async function openEdit(rule: Rule) {
    setReloadFailureDetails(null)
    setLoadingEditId(rule.id)
    try {
      const detail = await getRule(rule.id)
      setEditingId(detail.id)
      setForm({
        name: detail.name,
        phase: detail.phase,
        pattern: detail.pattern,
        action: detail.action,
        priority: detail.priority,
        enabled: detail.enabled,
        status_code: detail.status_code ?? 0,
        redirect_to: detail.redirect_to ?? "",
        policy_id: detail.policy_id,
      })
      setDialogOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载规则详情失败")
    } finally {
      setLoadingEditId(null)
    }
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast.error("规则名称不能为空")
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    const payload = { ...form }
    try {
      if (editingId) {
        const result = await updateRule(editingId, payload)
        setOperationDetails({
          operation: "update",
          rule_id: editingId,
          payload,
          response: result,
        })
        toast.success("规则已更新")
      } else {
        const result = await createRule(payload)
        setOperationDetails({
          operation: "create",
          payload,
          response: result,
        })
        toast.success("规则已创建")
      }
      setDialogOpen(false)
      load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        rememberRuleReloadFailureOperation(
          e,
          editingId ? "update" : "create",
          payload,
          editingId
        )
        setDialogOpen(false)
        void load()
      }
      toast.error(e instanceof Error ? e.message : "保存规则失败")
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setDeleting(true)
    try {
      await deleteRule(deleteTarget.id)
      setOperationDetails({
        operation: "delete",
        rule_id: deleteTarget.id,
        payload: {
          rule_id: deleteTarget.id,
          name: deleteTarget.name,
          policy_id: deleteTarget.policy_id,
        },
        status_code: 204,
        response: null,
      })
      toast.success("规则已删除")
      setDeleteTarget(null)
      load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "delete",
            rule_id: deleteTarget.id,
            payload: {
              rule_id: deleteTarget.id,
              name: deleteTarget.name,
              policy_id: deleteTarget.policy_id,
            },
            response: details,
          })
        }
        setDeleteTarget(null)
        void load()
      }
      toast.error(e instanceof Error ? e.message : "删除规则失败")
    } finally {
      setDeleting(false)
    }
  }

  async function handleExport() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setExporting(true)
    try {
      const data = await exportRules()
      const exportedAt = new Date().toISOString()
      downloadTextFile(
        JSON.stringify(data, null, 2),
        `rules-export-${exportedAt.slice(0, 10)}.json`,
        "application/json"
      )
      setOperationDetails({
        operation: "export",
        payload: null,
        exported_at: exportedAt,
        response: data,
      })
      toast.success(`已导出 ${data.rules?.length ?? 0} 条规则`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "导出失败")
    } finally {
      setExporting(false)
    }
  }

  function handleImport() {
    importFileInputRef.current?.click()
  }

  async function handleImportFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ""
    if (!file) return
    try {
      const text = await file.text()
      const parsed = JSON.parse(text) as
        | RuleFormData[]
        | { rules?: RuleFormData[] }
      const rules = Array.isArray(parsed) ? parsed : parsed.rules
      if (!Array.isArray(rules)) {
        toast.error("无效的规则文件")
        return
      }
      setReloadFailureDetails(null)
      setOperationDetails(null)
      setImportRules(rules)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "文件解析失败")
    }
  }

  async function openTemplates() {
    setTemplateDialogOpen(true)
    if (templates.length > 0) return
    setTemplatesLoading(true)
    try {
      const data = await getRuleTemplates()
      setTemplates(data.templates ?? [])
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载规则模板失败")
      setTemplates([])
    } finally {
      setTemplatesLoading(false)
    }
  }

  function applyTemplate(template: RuleTemplate) {
    setForm((value) => ({
      ...value,
      name: value.name.trim() ? value.name : template.name,
      pattern: template.pattern,
    }))
    setTemplateDialogOpen(false)
    if (!dialogOpen) {
      setEditingId(null)
      setDialogOpen(true)
    }
  }

  async function confirmImport() {
    if (!importRules) return
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setImporting(true)
    try {
      const result = await importRulesAPI(importRules)
      setOperationDetails({
        operation: "import",
        payload: {
          rules: importRules,
        },
        response: result,
      })
      toast.success(`成功导入 ${result.imported} / ${result.total} 条规则`)
      setImportRules(null)
      load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        rememberRuleImportReloadFailureOperation(e, importRules)
        setImportRules(null)
        void load()
      }
      toast.error(e instanceof Error ? e.message : "导入失败")
    } finally {
      setImporting(false)
    }
  }

  function patternSummary(pattern: string) {
    if (!pattern) return "—"
    if (pattern.length > 50) return pattern.slice(0, 50) + "…"
    return pattern
  }

  function statusSummary(rule: Rule) {
    const meta = getWAFActionMeta(rule.action)
    if (rule.action === "drop") return "DROP"
    if (rule.status_code && rule.status_code > 0)
      return String(rule.status_code)
    return meta.defaultStatus
  }

  function actionHelp(action: string) {
    return getWAFActionMeta(action).description
  }

  function getPolicyName(policyId: number | undefined): string {
    if (!policyId) return "-"
    const p = policies.find((pol) => pol.id === policyId)
    return p ? p.name : `#${policyId}`
  }

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Custom Rules"
        title={activePolicy ? `${activePolicy.name} - 规则管理` : "自定义规则"}
        description={
          activePolicy
            ? `当前查看策略「${activePolicy.name}」下的规则。规则按 phase、priority 参与数据面处理链路。`
            : "管理 ACL、签名与自定义匹配规则。规则按 phase、priority 参与数据面处理链路。"
        }
        actions={
          <div className="flex gap-2">
            <Input
              ref={importFileInputRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              tabIndex={-1}
              aria-hidden="true"
              onChange={handleImportFile}
            />
            <Button
              variant="outline"
              className="rounded-md"
              onClick={handleImport}
              disabled={importing}
            >
              <FileUp data-icon="inline-start" />
              {importing ? "导入中..." : "导入"}
            </Button>
            <Button
              variant="outline"
              className="rounded-md"
              onClick={handleExport}
              disabled={exporting}
            >
              <Download data-icon="inline-start" />
              {exporting ? "导出中..." : "导出最多 10000 条 JSON"}
            </Button>
            <Button
              variant="outline"
              className="rounded-md"
              onClick={openTemplates}
            >
              <Search data-icon="inline-start" />
              规则模板
            </Button>
            <Button className="rounded-md" onClick={openCreate}>
              <Plus data-icon="inline-start" />
              创建规则
            </Button>
          </div>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回规则操作响应体；请核对 item、imported、total 或 error 字段。
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
          <FileUp />
          <AlertTitle>最近规则操作响应</AlertTitle>
          <AlertDescription>
            后端已返回规则操作响应体；请核对 operation、payload、response、
            rule_id、status_code 或 exported_at 字段。
          </AlertDescription>
          <CopyableBlock
            label="规则操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <Surface title="规则列表">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm">
            <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="搜索规则名称或条件..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(1)
              }}
              className="rounded-md pl-9"
            />
          </div>
          <Select
            value={filterPolicyId}
            onValueChange={handlePolicyFilterChange}
          >
            <SelectTrigger className="w-[180px] rounded-md">
              <SelectValue placeholder="按策略筛选" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部策略</SelectItem>
                {policies.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          {activePolicyId && (
            <Button
              variant="ghost"
              size="sm"
              className="rounded-md text-xs text-muted-foreground"
              onClick={() => handlePolicyFilterChange("all")}
            >
              <X data-icon="inline-start" />
              清除策略筛选
            </Button>
          )}
          {search && (
            <span className="text-xs text-muted-foreground">
              搜索会参与后端分页总数；策略筛选与搜索条件同时生效。
            </span>
          )}
        </div>

        {loading ? (
          <EmptyState
            title="规则列表加载中"
            description="正在读取自定义规则、策略筛选和分页统计。"
          />
        ) : items.length === 0 ? (
          <EmptyState
            title="暂无规则"
            description="点击「创建规则」添加第一条自定义规则。"
            action={
              <Button className="rounded-md" onClick={openCreate}>
                <Plus data-icon="inline-start" />
                创建规则
              </Button>
            }
          />
        ) : (
          <div className="flex flex-col gap-4">
            <div className="overflow-x-auto rounded-lg border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">状态</TableHead>
                    <TableHead>名称</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead className="w-24">状态码</TableHead>
                    {!activePolicyId && <TableHead>所属策略</TableHead>}
                    <TableHead>匹配条件摘要</TableHead>
                    <TableHead className="w-20">命中数</TableHead>
                    <TableHead>更新时间</TableHead>
                    <TableHead className="w-28 text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell>
                        <Badge
                          variant={rule.enabled ? "secondary" : "outline"}
                          className="rounded-md text-xs"
                        >
                          {rule.enabled ? "启用" : "禁用"}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium text-foreground">
                        {rule.name || "未命名"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="rounded-md">
                          {phaseLabels[rule.phase] ?? rule.phase}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            ruleActionBadgeVariants[
                              getWAFActionMeta(rule.action).value
                            ] ?? "outline"
                          }
                          className="rounded-md text-xs"
                        >
                          {getWAFActionMeta(rule.action).shortLabel}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {statusSummary(rule)}
                      </TableCell>
                      {!activePolicyId && (
                        <TableCell>
                          {rule.policy_id ? (
                            <Link
                              href={`/rules/?policy_id=${rule.policy_id}`}
                              className="text-xs text-primary hover:underline"
                            >
                              {getPolicyName(rule.policy_id)}
                            </Link>
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              -
                            </span>
                          )}
                        </TableCell>
                      )}
                      <TableCell>
                        <span className="font-mono text-xs text-muted-foreground">
                          {patternSummary(rule.pattern)}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        —
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {rule.updated_at
                          ? new Date(rule.updated_at).toLocaleString("zh-CN")
                          : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            className="rounded-md"
                            aria-label="编辑规则"
                            disabled={loadingEditId === rule.id}
                            onClick={() => void openEdit(rule)}
                          >
                            <Pencil data-icon="inline-start" />
                          </Button>
                          <Button
                            size="icon"
                            variant="destructive"
                            className="rounded-md"
                            aria-label="删除规则"
                            onClick={() => {
                              setReloadFailureDetails(null)
                              setDeleteTarget(rule)
                            }}
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

      {/* 创建/编辑 Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>{editingId ? "编辑规则" : "创建规则"}</DialogTitle>
            <DialogDescription>
              {editingId
                ? "修改规则的匹配条件和动作。"
                : "定义新的自定义规则。"}
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor={`${formIdPrefix}-name`}>规则名称</FieldLabel>
              <Input
                id={`${formIdPrefix}-name`}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="例如：阻断恶意管理入口扫描"
                className="rounded-md"
              />
            </Field>

            <FieldGroup className="grid gap-4 md:grid-cols-2">
              <Field>
                <FieldLabel htmlFor={`${formIdPrefix}-policy`}>
                  所属策略
                </FieldLabel>
                <Select
                  value={form.policy_id ? String(form.policy_id) : "none"}
                  onValueChange={(v) =>
                    setForm({
                      ...form,
                      policy_id: v === "none" ? undefined : Number(v),
                    })
                  }
                >
                  <SelectTrigger
                    id={`${formIdPrefix}-policy`}
                    className="rounded-md"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="none">未指定</SelectItem>
                      {policies.map((p) => (
                        <SelectItem key={p.id} value={String(p.id)}>
                          {p.name}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor={`${formIdPrefix}-phase`}>
                  执行阶段
                </FieldLabel>
                <Select
                  value={form.phase}
                  onValueChange={(v) => setForm({ ...form, phase: v })}
                >
                  <SelectTrigger
                    id={`${formIdPrefix}-phase`}
                    className="rounded-md"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="acl">ACL 访问控制</SelectItem>
                      <SelectItem value="rate_limit">频率限制</SelectItem>
                      <SelectItem value="owasp_default">OWASP 检测</SelectItem>
                      <SelectItem value="signature">签名匹配</SelectItem>
                      <SelectItem value="custom">自定义规则</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
            </FieldGroup>

            <FieldGroup className="grid gap-4 md:grid-cols-2">
              <Field>
                <FieldLabel htmlFor={`${formIdPrefix}-action`}>
                  命中动作
                </FieldLabel>
                <Select
                  value={form.action}
                  onValueChange={(v) => setForm({ ...form, action: v })}
                >
                  <SelectTrigger
                    id={`${formIdPrefix}-action`}
                    className="rounded-md"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {ruleWAFActionOptions.map((item) => (
                        <SelectItem key={item.value} value={item.value}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
                {actionHelp(form.action) ? (
                  <FieldDescription>{actionHelp(form.action)}</FieldDescription>
                ) : null}
              </Field>
              <Field>
                <FieldLabel htmlFor={`${formIdPrefix}-status-code`}>
                  HTTP 状态码
                </FieldLabel>
                <Input
                  id={`${formIdPrefix}-status-code`}
                  type="number"
                  min={0}
                  value={form.status_code}
                  onChange={(e) =>
                    setForm({ ...form, status_code: Number(e.target.value) })
                  }
                  disabled={
                    form.action === "drop" ||
                    form.action === "allow" ||
                    form.action === "observe"
                  }
                  className="rounded-md"
                />
                <FieldDescription>
                  0 表示使用后端默认；断连/放行/观察不产生拦截响应。
                </FieldDescription>
              </Field>
            </FieldGroup>

            <FieldGroup className="grid gap-4 md:grid-cols-2">
              <Field>
                <FieldLabel htmlFor={`${formIdPrefix}-redirect-to`}>
                  重定向地址
                </FieldLabel>
                <Input
                  id={`${formIdPrefix}-redirect-to`}
                  value={form.redirect_to}
                  onChange={(e) =>
                    setForm({ ...form, redirect_to: e.target.value })
                  }
                  disabled={form.action !== "redirect"}
                  placeholder="https://example.com/blocked"
                  className="rounded-md"
                />
              </Field>
              <Field>
                <FieldLabel htmlFor={`${formIdPrefix}-priority`}>
                  优先级
                </FieldLabel>
                <Input
                  id={`${formIdPrefix}-priority`}
                  type="number"
                  value={form.priority}
                  onChange={(e) =>
                    setForm({ ...form, priority: Number(e.target.value) })
                  }
                  className="rounded-md"
                />
                <FieldDescription>数值越小越先执行</FieldDescription>
              </Field>
            </FieldGroup>

            <Field>
              <div className="flex items-center justify-between gap-3">
                <FieldLabel>匹配条件</FieldLabel>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={openTemplates}
                >
                  <Search data-icon="inline-start" />
                  选择模板
                </Button>
              </div>
              <RuleBuilder
                value={form.pattern}
                onChange={(v) => setForm({ ...form, pattern: v })}
              />
            </Field>

            <Field
              orientation="horizontal"
              className="items-center justify-between rounded-lg border border-border bg-muted/35 px-4 py-3"
            >
              <FieldLabel
                htmlFor={`${formIdPrefix}-enabled`}
                className="font-medium"
              >
                启用
              </FieldLabel>
              <Switch
                id={`${formIdPrefix}-enabled`}
                checked={form.enabled}
                onCheckedChange={(v) => setForm({ ...form, enabled: v })}
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button
              variant="outline"
              className="rounded-md"
              onClick={() => setDialogOpen(false)}
            >
              取消
            </Button>
            <Button
              onClick={handleSave}
              disabled={saving}
              className="rounded-md"
            >
              {saving ? "保存中..." : editingId ? "更新规则" : "创建规则"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={!!importRules}
        onOpenChange={(open) => {
          if (!open && !importing) setImportRules(null)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认导入规则</AlertDialogTitle>
            <AlertDialogDescription>
              将导入 {importRules?.length ?? 0}{" "}
              条规则；导入使用事务，任一规则无效将全部失败。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={importing}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={importing}
              onClick={(event) => {
                event.preventDefault()
                confirmImport()
              }}
            >
              {importing ? "导入中..." : "确认导入"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Dialog open={templateDialogOpen} onOpenChange={setTemplateDialogOpen}>
        <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>规则模板</DialogTitle>
            <DialogDescription>
              选择后会把模板匹配条件写入当前规则表单；未填写名称时同步使用模板名称。
            </DialogDescription>
          </DialogHeader>
          {templatesLoading ? (
            <div className="flex flex-col gap-3">
              <Skeleton className="h-20 rounded-lg" />
              <Skeleton className="h-20 rounded-lg" />
              <Skeleton className="h-20 rounded-lg" />
            </div>
          ) : templates.length === 0 ? (
            <EmptyState
              title="暂无规则模板"
              description="后端当前没有返回可用模板。"
            />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {templates.map((template) => (
                <div
                  key={`${template.category}-${template.name}-${template.pattern}`}
                  className="flex flex-col gap-3 rounded-lg border bg-muted/35 p-3"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="font-medium text-foreground">
                        {template.name}
                      </div>
                      <div className="mt-1 text-sm leading-5 text-muted-foreground">
                        {template.description}
                      </div>
                    </div>
                    <Badge variant="outline" className="shrink-0 rounded-md">
                      {template.category}
                    </Badge>
                  </div>
                  <code className="block rounded-md bg-background p-2 font-mono text-xs break-all text-muted-foreground">
                    {template.pattern}
                  </code>
                  <div className="flex justify-end">
                    <Button
                      type="button"
                      size="sm"
                      onClick={() => applyTemplate(template)}
                    >
                      应用模板
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setTemplateDialogOpen(false)}
            >
              关闭
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open && !deleting) setDeleteTarget(null)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除规则</AlertDialogTitle>
            <AlertDialogDescription>
              确认删除规则「{deleteTarget?.name || deleteTarget?.id || "-"}
              」？删除后会立即从所属策略中移除并重新加载运行时配置。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault()
                handleDelete()
              }}
            >
              {deleting ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

export default function CustomRulesPage() {
  return (
    <Suspense>
      <CustomRulesContent />
    </Suspense>
  )
}
