"use client"

import { useCallback, useEffect, useState } from "react"
import {
  Ban,
  Edit2,
  Plus,
  ShieldCheck,
  ShieldX,
  Trash2,
  Zap,
} from "lucide-react"
import { toast } from "sonner"
import { api, type IPListItem } from "@/lib/api"
import { Pagination } from "@/components/pagination"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

interface ListResponse {
  items: IPListItem[]
  total: number
}

const PAGE_SIZE = 20

export default function IPListsPage() {
  const [items, setItems] = useState<IPListItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingItem, setEditingItem] = useState<IPListItem | null>(null)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<IPListItem | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [batchDeleting, setBatchDeleting] = useState(false)
  const [kindFilter, setKindFilter] = useState<
    "all" | "whitelist" | "blacklist"
  >("all")

  // form state
  const [formKind, setFormKind] = useState<"whitelist" | "blacklist">(
    "whitelist"
  )
  const [formValue, setFormValue] = useState("")
  const [formNote, setFormNote] = useState("")
  const [formAction, setFormAction] = useState<"intercept" | "drop">(
    "intercept"
  )
  const [formEnabled, setFormEnabled] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
      })
      if (kindFilter !== "all") params.set("kind", kindFilter)
      const result = await api<ListResponse>(
        `/api/v1/ip-lists?${params.toString()}`
      )
      setItems(result.items ?? [])
      setTotal(result.total ?? 0)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败")
      setItems([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [page, kindFilter])

  useEffect(() => {
    load()
  }, [load])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  function resetForm() {
    setFormKind("whitelist")
    setFormValue("")
    setFormNote("")
    setFormAction("intercept")
    setFormEnabled(true)
  }

  function openCreate() {
    setEditingItem(null)
    resetForm()
    setDialogOpen(true)
  }

  function openEdit(item: IPListItem) {
    setEditingItem(item)
    setFormKind(item.kind as "whitelist" | "blacklist")
    setFormValue(item.value)
    setFormNote(item.note)
    setFormAction(
      item.action === "block" || item.action === "drop" ? "drop" : "intercept"
    )
    setFormEnabled(item.enabled)
    setDialogOpen(true)
  }

  async function handleSave() {
    const lines = formValue
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
    if (lines.length === 0) {
      toast.error("请输入 IP 或 CIDR")
      return
    }
    setSaving(true)
    try {
      if (editingItem) {
        await api(`/api/v1/ip-lists/${editingItem.id}/update`, {
          method: "POST",
          body: JSON.stringify({
            kind: formKind,
            value: lines[0],
            note: formNote.trim(),
            action: formKind === "blacklist" ? formAction : undefined,
            enabled: formEnabled,
          }),
        })
        toast.success("条目已更新")
      } else {
        // batch create - one per line
        for (const line of lines) {
          await api("/api/v1/ip-lists", {
            method: "POST",
            body: JSON.stringify({
              kind: formKind,
              value: line,
              note: formNote.trim(),
              action: formKind === "blacklist" ? formAction : undefined,
              enabled: formEnabled,
            }),
          })
        }
        toast.success(
          lines.length > 1 ? `已创建 ${lines.length} 个条目` : "条目已创建"
        )
      }
      setDialogOpen(false)
      setEditingItem(null)
      resetForm()
      load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存失败")
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await api(`/api/v1/ip-lists/${deleteTarget.id}/delete`, {
        method: "POST",
      })
      toast.success("条目已删除")
      setDeleteTarget(null)
      load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "删除失败")
    } finally {
      setDeleting(false)
    }
  }

  async function handleToggle(item: IPListItem) {
    try {
      await api(`/api/v1/ip-lists/${item.id}/update`, {
        method: "POST",
        body: JSON.stringify({ ...item, enabled: !item.enabled }),
      })
      toast.success(item.enabled ? "已禁用" : "已启用")
      load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "更新失败")
    }
  }

  function toggleSelect(id: number) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleSelectAll() {
    if (selected.size === items.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(items.map((i) => i.id)))
    }
  }

  async function handleBatchDelete() {
    if (selected.size === 0) return
    setBatchDeleting(true)
    try {
      for (const id of selected) {
        await api(`/api/v1/ip-lists/${id}/delete`, { method: "POST" })
      }
      toast.success(`已删除 ${selected.size} 个条目`)
      setSelected(new Set())
      load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "批量删除失败")
    } finally {
      setBatchDeleting(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">IP 黑白名单</h1>
          <p className="mt-1 text-sm text-slate-500">
            管理 IP 黑名单与白名单条目，保存后立即生效
          </p>
        </div>
        <Button
          onClick={openCreate}
          className="gap-2 rounded-md bg-teal-500 text-white hover:bg-teal-600"
        >
          <Plus className="h-4 w-4" /> 添加条目
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
        <Select
          value={kindFilter}
          onValueChange={(v) => {
            setKindFilter(v as "all" | "whitelist" | "blacklist")
            setPage(1)
          }}
        >
          <SelectTrigger className="w-[160px] rounded-lg">
            <SelectValue placeholder="类型筛选" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部类型</SelectItem>
            <SelectItem value="whitelist">白名单</SelectItem>
            <SelectItem value="blacklist">黑名单</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Batch action bar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-2.5">
          <span className="text-sm text-slate-700">
            已选择 <strong>{selected.size}</strong> 项
          </span>
          <Button
            size="sm"
            variant="outline"
            className="gap-1.5 rounded-lg border-red-200 text-red-600 hover:bg-red-50"
            onClick={handleBatchDelete}
            disabled={batchDeleting}
          >
            <Trash2 className="h-3.5 w-3.5" />
            {batchDeleting ? "删除中..." : "批量删除"}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="rounded-lg text-slate-500"
            onClick={() => setSelected(new Set())}
          >
            取消选择
          </Button>
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        {loading ? (
          <div className="p-16 text-center text-sm text-slate-400">
            加载中...
          </div>
        ) : items.length === 0 ? (
          <div className="p-16 text-center">
            <div className="text-sm text-slate-400">暂无 IP 条目</div>
            <p className="mt-1 text-xs text-slate-400">
              点击右上角按钮添加黑白名单条目
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                    <th className="w-10 px-4 py-3">
                      <Checkbox
                        checked={
                          items.length > 0 && selected.size === items.length
                        }
                        onCheckedChange={toggleSelectAll}
                      />
                    </th>
                    <th className="px-4 py-3">类型</th>
                    <th className="px-4 py-3">值</th>
                    <th className="px-4 py-3">动作</th>
                    <th className="px-4 py-3">备注</th>
                    <th className="px-4 py-3">启用</th>
                    <th className="px-4 py-3 text-right">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {items.map((item) => (
                    <tr
                      key={item.id}
                      className="transition-colors hover:bg-slate-50/50"
                    >
                      <td className="px-4 py-3">
                        <Checkbox
                          checked={selected.has(item.id)}
                          onCheckedChange={() => toggleSelect(item.id)}
                        />
                      </td>
                      <td className="px-4 py-3">
                        {item.kind === "whitelist" ? (
                          <Badge className="gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-50">
                            <ShieldCheck className="h-3 w-3" /> 白名单
                          </Badge>
                        ) : (
                          <Badge className="gap-1 border-red-200 bg-red-50 text-red-700 hover:bg-red-50">
                            <ShieldX className="h-3 w-3" /> 黑名单
                          </Badge>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-700">
                          {item.value}
                        </code>
                      </td>
                      <td className="px-4 py-3">
                        {item.kind === "blacklist" ? (
                          item.action === "block" || item.action === "drop" ? (
                            <Badge
                              variant="outline"
                              className="gap-1 border-rose-200 bg-rose-50 text-rose-700"
                            >
                              <Zap className="h-3 w-3" /> TCP RST
                            </Badge>
                          ) : (
                            <Badge
                              variant="outline"
                              className="gap-1 border-amber-200 bg-amber-50 text-amber-700"
                            >
                              <Ban className="h-3 w-3" /> 拦截 403
                            </Badge>
                          )
                        ) : (
                          <span className="text-xs text-slate-300">-</span>
                        )}
                      </td>
                      <td className="max-w-[200px] truncate px-4 py-3 text-xs text-slate-500">
                        {item.note || "-"}
                      </td>
                      <td className="px-4 py-3">
                        <Switch
                          checked={item.enabled}
                          onCheckedChange={() => handleToggle(item)}
                        />
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 rounded-lg p-0 text-slate-400 hover:text-slate-700"
                            onClick={() => openEdit(item)}
                          >
                            <Edit2 className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 rounded-lg p-0 text-slate-400 hover:text-red-600"
                            onClick={() => setDeleteTarget(item)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="border-t border-slate-100 p-3">
              <Pagination
                page={page}
                totalPages={totalPages}
                total={total}
                pageSize={PAGE_SIZE}
                onPageChange={setPage}
              />
            </div>
          </>
        )}
      </div>

      {/* Add/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg rounded-xl">
          <DialogHeader>
            <DialogTitle>
              {editingItem ? "编辑 IP 条目" : "添加 IP 条目"}
            </DialogTitle>
            <DialogDescription>
              保存后立即生效，支持单个 IP 或 CIDR 格式
            </DialogDescription>
          </DialogHeader>

          <Tabs
            value={formKind}
            onValueChange={(v) => setFormKind(v as "whitelist" | "blacklist")}
          >
            <TabsList className="w-full">
              <TabsTrigger value="whitelist" className="flex-1 gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5" /> 白名单
              </TabsTrigger>
              <TabsTrigger value="blacklist" className="flex-1 gap-1.5">
                <ShieldX className="h-3.5 w-3.5" /> 黑名单
              </TabsTrigger>
            </TabsList>

            <TabsContent value="whitelist" className="mt-4 space-y-4">
              <div className="space-y-2">
                <Label>IP / CIDR（每行一个）</Label>
                {editingItem ? (
                  <Input
                    value={formValue}
                    onChange={(e) => setFormValue(e.target.value)}
                    placeholder="192.168.1.10 或 192.168.1.0/24"
                    className="rounded-lg font-mono"
                  />
                ) : (
                  <Textarea
                    value={formValue}
                    onChange={(e) => setFormValue(e.target.value)}
                    placeholder={"192.168.1.10\n10.0.0.0/8\n172.16.0.0/12"}
                    rows={4}
                    className="rounded-lg font-mono text-sm"
                  />
                )}
              </div>
              <div className="space-y-2">
                <Label>备注</Label>
                <Input
                  value={formNote}
                  onChange={(e) => setFormNote(e.target.value)}
                  placeholder="例如：办公出口"
                  className="rounded-lg"
                />
              </div>
              <div className="flex items-center justify-between rounded-lg border border-slate-200 px-4 py-3">
                <Label className="cursor-pointer">启用</Label>
                <Switch
                  checked={formEnabled}
                  onCheckedChange={setFormEnabled}
                />
              </div>
            </TabsContent>

            <TabsContent value="blacklist" className="mt-4 space-y-4">
              <div className="space-y-2">
                <Label>IP / CIDR（每行一个）</Label>
                {editingItem ? (
                  <Input
                    value={formValue}
                    onChange={(e) => setFormValue(e.target.value)}
                    placeholder="192.168.1.10 或 192.168.1.0/24"
                    className="rounded-lg font-mono"
                  />
                ) : (
                  <Textarea
                    value={formValue}
                    onChange={(e) => setFormValue(e.target.value)}
                    placeholder={"1.2.3.4\n5.6.7.0/24"}
                    rows={4}
                    className="rounded-lg font-mono text-sm"
                  />
                )}
              </div>
              <div className="space-y-2">
                <Label>备注</Label>
                <Input
                  value={formNote}
                  onChange={(e) => setFormNote(e.target.value)}
                  placeholder="例如：恶意扫描源"
                  className="rounded-lg"
                />
              </div>
              <div className="space-y-2">
                <Label>动作</Label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setFormAction("intercept")}
                    className={`rounded-lg border p-3 text-left transition-colors ${
                      formAction === "intercept"
                        ? "border-slate-300 bg-slate-50"
                        : "border-slate-200 bg-white hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-center gap-2 text-sm font-medium">
                      <Ban className="h-4 w-4 text-amber-600" />
                      拦截 (403)
                    </div>
                    <p className="mt-1 text-xs text-slate-500">
                      返回 403 拦截页面
                    </p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormAction("drop")}
                    className={`rounded-lg border p-3 text-left transition-colors ${
                      formAction === "drop"
                        ? "border-slate-300 bg-slate-50"
                        : "border-slate-200 bg-white hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-center gap-2 text-sm font-medium">
                      <Zap className="h-4 w-4 text-rose-600" />
                      Drop（无 HTTP 响应）
                    </div>
                    <p className="mt-1 text-xs text-slate-500">
                      关闭连接并记录 status_code=0
                    </p>
                  </button>
                </div>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-slate-200 px-4 py-3">
                <Label className="cursor-pointer">启用</Label>
                <Switch
                  checked={formEnabled}
                  onCheckedChange={setFormEnabled}
                />
              </div>
            </TabsContent>
          </Tabs>

          <DialogFooter>
            <Button
              variant="outline"
              className="rounded-lg"
              onClick={() => setDialogOpen(false)}
            >
              取消
            </Button>
            <Button
              className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? "保存中..." : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirm Dialog */}
      <Dialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <DialogContent className="max-w-sm rounded-xl">
          <DialogHeader>
            <DialogTitle>确认删除</DialogTitle>
            <DialogDescription>
              删除后该条目立即从运行时名单中移除
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            即将删除{" "}
            <code className="rounded bg-red-100 px-1 font-mono text-xs">
              {deleteTarget?.value}
            </code>{" "}
            ，此操作不可撤销。
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="rounded-lg"
              onClick={() => setDeleteTarget(null)}
            >
              取消
            </Button>
            <Button
              className="rounded-lg bg-red-600 hover:bg-red-500"
              disabled={deleting}
              onClick={handleDelete}
            >
              {deleting ? "删除中..." : "删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
