"use client"

import { Suspense, useCallback, useEffect, useState } from "react"
import { useSearchParams, useRouter } from "next/navigation"
import { Download, FileUp, Plus, Search, Pencil, Trash2, X } from "lucide-react"
import { toast } from "sonner"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import {
  Select,
  SelectContent,
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
  api,
  type Rule,
  type Policy,
  type PaginatedResponse,
  buildQuery,
} from "@/lib/api"
import {
  getWAFActionMeta,
  ruleWAFActionOptions,
  phaseLabels,
} from "@/lib/console"

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

function CustomRulesContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const urlPolicyId = searchParams.get("policy_id")

  const [items, setItems] = useState<Rule[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState("")
  const [filterPolicyId, setFilterPolicyId] = useState<string>(
    urlPolicyId || "all"
  )
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState<RuleFormData>(emptyForm)
  const [saving, setSaving] = useState(false)

  // Load policies list for the filter dropdown
  useEffect(() => {
    api<{ items: Policy[] }>("/api/v1/policies")
      .then((data) => setPolicies(data.items || []))
      .catch(() => {})
  }, [])

  // Sync URL param to filter state
  useEffect(() => {
    if (urlPolicyId) {
      setFilterPolicyId(urlPolicyId)
    }
  }, [urlPolicyId])

  const activePolicyId =
    filterPolicyId !== "all" ? Number(filterPolicyId) : undefined
  const activePolicy = activePolicyId
    ? policies.find((p) => p.id === activePolicyId)
    : undefined

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { page, page_size: PAGE_SIZE }
      if (activePolicyId) params.policy_id = activePolicyId
      const res = await api<PaginatedResponse<Rule>>(
        `/api/v1/rules${buildQuery(params)}`
      )
      let list = res.items ?? []
      if (search) {
        const q = search.toLowerCase()
        list = list.filter(
          (r) =>
            r.name.toLowerCase().includes(q) ||
            r.pattern.toLowerCase().includes(q)
        )
      }
      setItems(list)
      setTotal(res.total ?? 0)
    } catch (e) {
      toast.error(String(e))
    } finally {
      setLoading(false)
    }
  }, [page, search, activePolicyId])

  useEffect(() => {
    load()
  }, [load])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

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
    setEditingId(null)
    setForm({
      ...emptyForm,
      policy_id: activePolicyId,
    })
    setDialogOpen(true)
  }

  function openEdit(rule: Rule) {
    setEditingId(rule.id)
    setForm({
      name: rule.name,
      phase: rule.phase,
      pattern: rule.pattern,
      action: rule.action,
      priority: rule.priority,
      enabled: rule.enabled,
      status_code: rule.status_code ?? 0,
      redirect_to: rule.redirect_to ?? "",
      policy_id: rule.policy_id,
    })
    setDialogOpen(true)
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast.error("规则名称不能为空")
      return
    }
    setSaving(true)
    try {
      if (editingId) {
        await api(`/api/v1/rules/${editingId}/update`, {
          method: "POST",
          body: JSON.stringify(form),
        })
        toast.success("规则已更新")
      } else {
        await api("/api/v1/rules", {
          method: "POST",
          body: JSON.stringify(form),
        })
        toast.success("规则已创建")
      }
      setDialogOpen(false)
      load()
    } catch (e) {
      toast.error(String(e))
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(id: number) {
    try {
      await api(`/api/v1/rules/${id}/delete`, { method: "POST" })
      toast.success("规则已删除")
      load()
    } catch (e) {
      toast.error(String(e))
    }
  }

  function handleExport() {
    const data = JSON.stringify(items, null, 2)
    const blob = new Blob([data], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `rules-export-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
    toast.success("规则已导出")
  }

  function handleImport() {
    const input = document.createElement("input")
    input.type = "file"
    input.accept = ".json"
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (!file) return
      try {
        const text = await file.text()
        const rules = JSON.parse(text) as RuleFormData[]
        if (!Array.isArray(rules)) {
          toast.error("无效的规则文件")
          return
        }
        const result = await api<{ imported: number; total: number }>(
          "/api/v1/rules/import",
          {
            method: "POST",
            body: JSON.stringify({ rules }),
          }
        )
        toast.success(`成功导入 ${result.imported} / ${result.total} 条规则`)
        load()
      } catch {
        toast.error("文件解析失败")
      }
    }
    input.click()
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
    <div className="space-y-6">
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
            <Button
              variant="outline"
              className="rounded-md border-slate-200 text-slate-700 hover:bg-slate-100"
              onClick={handleImport}
            >
              <FileUp className="mr-2 h-4 w-4" /> 导入
            </Button>
            <Button
              variant="outline"
              className="rounded-md border-slate-200 text-slate-700 hover:bg-slate-100"
              onClick={handleExport}
            >
              <Download className="mr-2 h-4 w-4" /> 导出
            </Button>
            <Button
              className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
              onClick={openCreate}
            >
              <Plus className="mr-2 h-4 w-4" /> 创建规则
            </Button>
          </div>
        }
      />

      <Surface title="规则列表">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative max-w-sm">
            <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-400" />
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
              <SelectItem value="all">全部策略</SelectItem>
              {policies.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {activePolicyId && (
            <Button
              variant="ghost"
              size="sm"
              className="gap-1 rounded-md text-xs text-slate-500"
              onClick={() => handlePolicyFilterChange("all")}
            >
              <X className="h-3.5 w-3.5" /> 清除策略筛选
            </Button>
          )}
        </div>

        {loading ? (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">
            加载中...
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            title="暂无规则"
            description="点击「创建规则」添加第一条自定义规则。"
            action={
              <Button
                className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
                onClick={openCreate}
              >
                <Plus className="mr-2 h-4 w-4" /> 创建规则
              </Button>
            }
          />
        ) : (
          <div className="space-y-4">
            <div className="overflow-x-auto rounded-lg border border-slate-200">
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
                          className={`rounded-md border text-xs ${rule.enabled ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 bg-slate-100 text-slate-500"}`}
                        >
                          {rule.enabled ? "启用" : "禁用"}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium text-slate-900">
                        {rule.name || "未命名"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="rounded-md">
                          {phaseLabels[rule.phase] ?? rule.phase}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={`rounded-md border text-xs ${getWAFActionMeta(rule.action).className}`}
                        >
                          {getWAFActionMeta(rule.action).shortLabel}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-600">
                        {statusSummary(rule)}
                      </TableCell>
                      {!activePolicyId && (
                        <TableCell>
                          {rule.policy_id ? (
                            <Link
                              href={`/rules/?policy_id=${rule.policy_id}`}
                              className="text-xs text-blue-600 hover:underline"
                            >
                              {getPolicyName(rule.policy_id)}
                            </Link>
                          ) : (
                            <span className="text-xs text-slate-400">-</span>
                          )}
                        </TableCell>
                      )}
                      <TableCell>
                        <span className="font-mono text-xs text-slate-600">
                          {patternSummary(rule.pattern)}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm text-slate-600">
                        —
                      </TableCell>
                      <TableCell className="text-sm text-slate-500">
                        {rule.updated_at
                          ? new Date(rule.updated_at).toLocaleString("zh-CN")
                          : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8 rounded-md"
                            onClick={() => openEdit(rule)}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8 rounded-md text-rose-500 hover:text-rose-700"
                            onClick={() => handleDelete(rule.id)}
                          >
                            <Trash2 className="h-4 w-4" />
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
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>规则名称</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="例如：阻断恶意管理入口扫描"
                className="rounded-md"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>所属策略</Label>
                <Select
                  value={form.policy_id ? String(form.policy_id) : "none"}
                  onValueChange={(v) =>
                    setForm({
                      ...form,
                      policy_id: v === "none" ? undefined : Number(v),
                    })
                  }
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">未指定</SelectItem>
                    {policies.map((p) => (
                      <SelectItem key={p.id} value={String(p.id)}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>执行阶段</Label>
                <Select
                  value={form.phase}
                  onValueChange={(v) => setForm({ ...form, phase: v })}
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="acl">ACL 访问控制</SelectItem>
                    <SelectItem value="rate_limit">频率限制</SelectItem>
                    <SelectItem value="owasp_default">OWASP 检测</SelectItem>
                    <SelectItem value="signature">签名匹配</SelectItem>
                    <SelectItem value="custom">自定义规则</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>命中动作</Label>
                <Select
                  value={form.action}
                  onValueChange={(v) => setForm({ ...form, action: v })}
                >
                  <SelectTrigger className="rounded-md">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ruleWAFActionOptions.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {actionHelp(form.action) && (
                  <p className="text-xs text-slate-500">
                    {actionHelp(form.action)}
                  </p>
                )}
              </div>
              <div className="space-y-2">
                <Label>HTTP 状态码</Label>
                <Input
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
                <p className="text-xs text-slate-500">
                  0 表示使用后端默认；断连/放行/观察不产生拦截响应。
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>重定向地址</Label>
                <Input
                  value={form.redirect_to}
                  onChange={(e) =>
                    setForm({ ...form, redirect_to: e.target.value })
                  }
                  disabled={form.action !== "redirect"}
                  placeholder="https://example.com/blocked"
                  className="rounded-md"
                />
              </div>
              <div className="space-y-2">
                <Label>优先级</Label>
                <Input
                  type="number"
                  value={form.priority}
                  onChange={(e) =>
                    setForm({ ...form, priority: Number(e.target.value) })
                  }
                  className="rounded-md"
                />
                <p className="text-xs text-slate-500">数值越小越先执行</p>
              </div>
            </div>
            <div className="space-y-2">
              <Label>匹配条件</Label>
              <RuleBuilder
                value={form.pattern}
                onChange={(v) => setForm({ ...form, pattern: v })}
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
              <Label className="font-medium">启用</Label>
              <Switch
                checked={form.enabled}
                onCheckedChange={(v) => setForm({ ...form, enabled: v })}
              />
            </div>
          </div>
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
              className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
            >
              {saving ? "保存中..." : editingId ? "更新规则" : "创建规则"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
