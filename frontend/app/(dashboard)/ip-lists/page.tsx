"use client"

import { useCallback, useEffect, useId, useState } from "react"
import { useSearchParams } from "next/navigation"
import {
  AlertTriangle,
  Ban,
  Edit2,
  Plus,
  ShieldCheck,
  ShieldX,
  Trash2,
  Zap,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import {
  createIPListEntry,
  deleteIPListEntry,
  getConfigAppliedReloadFailureDetails,
  getConfigAppliedReloadFailureItem,
  getIPListEntry,
  getIPListEntries,
  isConfigAppliedReloadFailureError,
  updateIPListEntry,
  type IPListItem,
  type IPListQuery,
} from "@/lib/api"
import { Pagination } from "@/components/pagination"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  ConsoleTableShell,
  EmptyState,
  PageIntro,
} from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"

const PAGE_SIZE = 20
const IP_LIST_KIND_FILTERS = ["all", "whitelist", "blacklist"] as const

type IPListKindFilter = (typeof IP_LIST_KIND_FILTERS)[number]

function ipListPageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

function ipListKindFromSearchParams(
  searchParams: URLSearchParams
): IPListKindFilter {
  const value = searchParams.get("kind")
  return IP_LIST_KIND_FILTERS.includes(value as IPListKindFilter)
    ? (value as IPListKindFilter)
    : "all"
}

export default function IPListsPage() {
  const formIdPrefix = useId()
  const searchParams = useSearchParams()
  const [items, setItems] = useState<IPListItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(() =>
    ipListPageFromSearchParams(searchParams)
  )
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingItem, setEditingItem] = useState<IPListItem | null>(null)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<IPListItem | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [batchDeleting, setBatchDeleting] = useState(false)
  const [batchDeleteOpen, setBatchDeleteOpen] = useState(false)
  const [loadingEditId, setLoadingEditId] = useState<number | null>(null)
  const [togglingId, setTogglingId] = useState<number | null>(null)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [kindFilter, setKindFilter] = useState<IPListKindFilter>(() =>
    ipListKindFromSearchParams(searchParams)
  )

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
      const params: IPListQuery = {
        page,
        page_size: PAGE_SIZE,
      }
      if (kindFilter !== "all") params.kind = kindFilter
      const result = await getIPListEntries(params)
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
    return deferEffect(load)
  }, [load])

  useEffect(() => {
    return deferEffect(() => setSelected(new Set()))
  }, [page, kindFilter])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  function getIPListReloadFailureResponse(error: unknown) {
    return {
      item: getConfigAppliedReloadFailureItem<IPListItem>(error),
      reload_failed: true,
      reload_error: error instanceof Error ? error.message : null,
      reload_failure:
        getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error),
    }
  }

  function rememberIPListReloadFailureOperation(
    error: unknown,
    operation: "update" | "toggle",
    payload: Record<string, unknown>,
    ipListId?: number | null
  ) {
    const response = getIPListReloadFailureResponse(error)
    setOperationDetails({
      operation,
      ip_list_id: ipListId ?? response.item?.id ?? null,
      payload,
      response,
    })
  }

  function resetForm() {
    setFormKind("whitelist")
    setFormValue("")
    setFormNote("")
    setFormAction("intercept")
    setFormEnabled(true)
  }

  function openCreate() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setEditingItem(null)
    resetForm()
    setDialogOpen(true)
  }

  async function openEdit(item: IPListItem) {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setLoadingEditId(item.id)
    try {
      const detail = await getIPListEntry(item.id)
      setEditingItem(detail)
      setFormKind(detail.kind as "whitelist" | "blacklist")
      setFormValue(detail.value)
      setFormNote(detail.note)
      setFormAction(
        detail.action === "block" || detail.action === "drop"
          ? "drop"
          : "intercept"
      )
      setFormEnabled(detail.enabled)
      setDialogOpen(true)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载 IP 条目失败")
    } finally {
      setLoadingEditId(null)
    }
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
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    const updatePayload = editingItem
      ? {
          kind: formKind,
          value: lines[0],
          note: formNote.trim(),
          action: formKind === "blacklist" ? formAction : undefined,
          enabled: formEnabled,
        }
      : null
    const createPayload = editingItem
      ? null
      : lines.map((line) => ({
          kind: formKind,
          value: line,
          note: formNote.trim(),
          action: formKind === "blacklist" ? formAction : undefined,
          enabled: formEnabled,
        }))
    try {
      let reloadFailureMessage = ""
      if (editingItem) {
        const payload = updatePayload!
        const result = await updateIPListEntry(editingItem.id, payload)
        setOperationDetails({
          operation: "update",
          ip_list_id: editingItem.id,
          payload,
          response: result,
        })
        toast.success("条目已更新")
      } else {
        const payload = createPayload!
        const createdItems: IPListItem[] = []
        const reloadFailureResults: Array<
          Record<string, unknown> & {
            payload: Record<string, unknown>
          }
        > = []
        for (const entryPayload of payload) {
          try {
            const result = await createIPListEntry(entryPayload)
            createdItems.push(result)
          } catch (error) {
            if (!isConfigAppliedReloadFailureError(error)) {
              throw error
            }
            rememberReloadFailureDetails(error)
            reloadFailureResults.push({
              payload: entryPayload,
              ...getIPListReloadFailureResponse(error),
            })
            if (!reloadFailureMessage) {
              reloadFailureMessage = error.message
            }
          }
        }
        if (reloadFailureMessage) {
          setOperationDetails({
            operation: "create",
            total: lines.length,
            created: createdItems.length + reloadFailureResults.length,
            payload,
            response: {
              items: createdItems,
              reload_failures: reloadFailureResults,
              reload_failed: true,
              reload_error: reloadFailureMessage,
            },
          })
          toast.error(reloadFailureMessage)
        } else {
          toast.success(
            lines.length > 1 ? `已创建 ${lines.length} 个条目` : "条目已创建"
          )
          if (createdItems.length > 0) {
            setOperationDetails({
              operation: "create",
              total: lines.length,
              created: createdItems.length,
              payload,
              response: createdItems,
            })
          }
        }
      }
      setDialogOpen(false)
      setEditingItem(null)
      resetForm()
      load()
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        if (editingItem && updatePayload) {
          rememberIPListReloadFailureOperation(
            error,
            "update",
            updatePayload,
            editingItem.id
          )
        }
        setDialogOpen(false)
        setEditingItem(null)
        resetForm()
        void load()
      }
      toast.error(error instanceof Error ? error.message : "保存失败")
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    const target = deleteTarget
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setDeleting(true)
    try {
      await deleteIPListEntry(target.id)
      setOperationDetails({
        operation: "delete",
        ip_list_id: target.id,
        payload: {
          ip_list_id: target.id,
          kind: target.kind,
          value: target.value,
        },
        status_code: 204,
        response: null,
      })
      toast.success("条目已删除")
      setDeleteTarget(null)
      load()
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
        if (details) {
          setOperationDetails({
            operation: "delete",
            ip_list_id: target.id,
            payload: {
              ip_list_id: target.id,
              kind: target.kind,
              value: target.value,
            },
            response: details,
          })
        }
        setDeleteTarget(null)
        void load()
      }
      toast.error(error instanceof Error ? error.message : "删除失败")
    } finally {
      setDeleting(false)
    }
  }

  async function handleToggle(item: IPListItem) {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setTogglingId(item.id)
    let payload: Record<string, unknown> | null = null
    try {
      const detail = await getIPListEntry(item.id)
      payload = {
        enabled: !detail.enabled,
      }
      const result = await updateIPListEntry(detail.id, payload)
      setOperationDetails({
        operation: "toggle",
        ip_list_id: detail.id,
        payload,
        response: result,
      })
      toast.success(detail.enabled ? "已禁用" : "已启用")
      load()
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        if (payload) {
          rememberIPListReloadFailureOperation(
            error,
            "toggle",
            payload,
            item.id
          )
        }
        void load()
      }
      toast.error(error instanceof Error ? error.message : "更新失败")
    } finally {
      setTogglingId(null)
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
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setBatchDeleting(true)
    let deletedCount = 0
    const deletedIds: number[] = []
    try {
      let reloadFailureMessage = ""
      const reloadFailureResults: Array<{
        payload: { ip_list_id: number }
        response: Record<string, unknown>
      }> = []
      for (const id of selected) {
        try {
          await deleteIPListEntry(id)
          deletedCount += 1
          deletedIds.push(id)
        } catch (error) {
          if (!isConfigAppliedReloadFailureError(error)) {
            throw error
          }
          rememberReloadFailureDetails(error)
          const details =
            getConfigAppliedReloadFailureDetails<Record<string, unknown>>(
              error
            )
          if (details) {
            reloadFailureResults.push({
              payload: { ip_list_id: id },
              response: details,
            })
          }
          deletedCount += 1
          deletedIds.push(id)
          if (!reloadFailureMessage) {
            reloadFailureMessage = error.message
          }
        }
      }
      if (reloadFailureMessage) {
        setOperationDetails({
          operation: "batch_delete",
          deleted: deletedCount,
          payload: deletedIds.map((id) => ({ ip_list_id: id })),
          response: {
            reload_failed: true,
            reload_error: reloadFailureMessage,
            reload_failures: reloadFailureResults,
          },
        })
        toast.error(reloadFailureMessage)
      } else {
        toast.success(`已删除 ${selected.size} 个条目`)
        setOperationDetails({
          operation: "batch_delete",
          deleted: deletedCount,
          payload: deletedIds.map((id) => ({ ip_list_id: id })),
          status_code: 204,
          response: null,
        })
      }
      setSelected(new Set())
      setBatchDeleteOpen(false)
      load()
    } catch (error) {
      if (deletedCount > 0) {
        setSelected(new Set())
        setBatchDeleteOpen(false)
        void load()
      }
      toast.error(error instanceof Error ? error.message : "批量删除失败")
    } finally {
      setBatchDeleting(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="IP Lists"
        title="IP 黑白名单"
        description="管理 IP 黑名单与白名单条目，保存后立即生效。"
        actions={
          <Button onClick={openCreate}>
            <Plus data-icon="inline-start" /> 添加条目
          </Button>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回 IP 黑白名单操作响应体；请核对 item 或 error 字段。
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
          <AlertTitle>最近 IP 黑白名单操作响应</AlertTitle>
          <AlertDescription>
            后端已返回 IP 黑白名单操作响应体；请核对 operation、payload、
            response、ip_list_id、deleted 或 status_code 字段。
          </AlertDescription>
          <CopyableBlock
            label="IP 黑白名单操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <ConsoleTableShell
        title="IP 条目列表"
        description={`当前筛选命中 ${total} 条，批量删除仅作用于当前页已选条目。`}
        toolbar={
          <>
            <div className="flex flex-wrap items-center gap-3">
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
                  <SelectGroup>
                    <SelectItem value="all">全部类型</SelectItem>
                    <SelectItem value="whitelist">白名单</SelectItem>
                    <SelectItem value="blacklist">黑名单</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            {selected.size > 0 ? (
              <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-muted/45 px-3 py-2">
                <span className="text-sm text-muted-foreground">
                  当前页已选择 <strong>{selected.size}</strong> 项
                </span>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => {
                    setReloadFailureDetails(null)
                    setOperationDetails(null)
                    setBatchDeleteOpen(true)
                  }}
                  disabled={batchDeleting}
                >
                  <Trash2 data-icon="inline-start" />
                  {batchDeleting ? "删除中..." : "批量删除"}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setSelected(new Set())}
                >
                  取消选择
                </Button>
              </div>
            ) : null}
          </>
        }
        state={
          loading ? (
            <EmptyState
              title="IP 黑白名单加载中"
              description="正在读取当前筛选条件下的 IP 条目。"
            />
          ) : items.length === 0 ? (
            <EmptyState
              title="暂无 IP 条目"
              description="点击右上角按钮添加黑白名单条目。"
              action={
                <Button onClick={openCreate}>
                  <Plus data-icon="inline-start" /> 添加条目
                </Button>
              }
            />
          ) : undefined
        }
        footer={
          !loading && items.length > 0 ? (
            <Pagination
              page={page}
              totalPages={totalPages}
              total={total}
              pageSize={PAGE_SIZE}
              onPageChange={setPage}
            />
          ) : null
        }
      >
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground">
              <TableHead className="w-10 px-4 py-3">
                <Checkbox
                  checked={items.length > 0 && selected.size === items.length}
                  onCheckedChange={toggleSelectAll}
                />
              </TableHead>
              <TableHead className="px-4 py-3">类型</TableHead>
              <TableHead className="px-4 py-3">值</TableHead>
              <TableHead className="px-4 py-3">动作</TableHead>
              <TableHead className="px-4 py-3">备注</TableHead>
              <TableHead className="px-4 py-3">启用</TableHead>
              <TableHead className="px-4 py-3 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((item) => (
              <TableRow
                key={item.id}
                className="transition-colors hover:bg-muted/35"
              >
                <TableCell className="px-4 py-3">
                  <Checkbox
                    checked={selected.has(item.id)}
                    onCheckedChange={() => toggleSelect(item.id)}
                  />
                </TableCell>
                <TableCell className="px-4 py-3">
                  {item.kind === "whitelist" ? (
                    <Badge>
                      <ShieldCheck data-icon="inline-start" /> 白名单
                    </Badge>
                  ) : (
                    <Badge variant="destructive">
                      <ShieldX data-icon="inline-start" /> 黑名单
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground">
                    {item.value}
                  </code>
                </TableCell>
                <TableCell className="px-4 py-3">
                  {item.kind === "blacklist" ? (
                    item.action === "block" || item.action === "drop" ? (
                      <Badge variant="destructive">
                        <Zap data-icon="inline-start" /> TCP RST
                      </Badge>
                    ) : (
                      <Badge variant="secondary">
                        <Ban data-icon="inline-start" /> 拦截 403
                      </Badge>
                    )
                  ) : (
                    <span className="text-xs text-muted-foreground">-</span>
                  )}
                </TableCell>
                <TableCell className="max-w-[200px] truncate px-4 py-3 text-xs text-muted-foreground">
                  {item.note || "-"}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <Switch
                    checked={item.enabled}
                    disabled={togglingId === item.id}
                    onCheckedChange={() => void handleToggle(item)}
                  />
                </TableCell>
                <TableCell className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="text-muted-foreground"
                      disabled={loadingEditId === item.id}
                      onClick={() => void openEdit(item)}
                      aria-label="编辑 IP 条目"
                    >
                      <Edit2 data-icon="inline-start" />
                    </Button>
                    <Button
                      variant="destructive"
                      size="icon-sm"
                      onClick={() => {
                        setReloadFailureDetails(null)
                        setOperationDetails(null)
                        setDeleteTarget(item)
                      }}
                      aria-label="删除 IP 条目"
                    >
                      <Trash2 data-icon="inline-start" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </ConsoleTableShell>

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
              <TabsTrigger value="whitelist" className="flex-1">
                <ShieldCheck data-icon="inline-start" /> 白名单
              </TabsTrigger>
              <TabsTrigger value="blacklist" className="flex-1">
                <ShieldX data-icon="inline-start" /> 黑名单
              </TabsTrigger>
            </TabsList>

            <TabsContent value="whitelist" className="mt-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor={`${formIdPrefix}-whitelist-value`}>
                    IP / CIDR（每行一个）
                  </FieldLabel>
                  {editingItem ? (
                    <Input
                      id={`${formIdPrefix}-whitelist-value`}
                      value={formValue}
                      onChange={(e) => setFormValue(e.target.value)}
                      placeholder="192.168.1.10 或 192.168.1.0/24"
                      className="rounded-lg font-mono"
                    />
                  ) : (
                    <Textarea
                      id={`${formIdPrefix}-whitelist-value`}
                      value={formValue}
                      onChange={(e) => setFormValue(e.target.value)}
                      placeholder={"192.168.1.10\n10.0.0.0/8\n172.16.0.0/12"}
                      rows={4}
                      className="rounded-lg font-mono text-sm"
                    />
                  )}
                  <FieldDescription>
                    新增时支持每行一个 IP 或 CIDR；编辑时只保存第一行。
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor={`${formIdPrefix}-whitelist-note`}>
                    备注
                  </FieldLabel>
                  <Input
                    id={`${formIdPrefix}-whitelist-note`}
                    value={formNote}
                    onChange={(e) => setFormNote(e.target.value)}
                    placeholder="例如：办公出口"
                    className="rounded-lg"
                  />
                </Field>
                <Field
                  orientation="horizontal"
                  className="items-center justify-between rounded-lg border border-border px-4 py-3"
                >
                  <FieldLabel
                    htmlFor={`${formIdPrefix}-whitelist-enabled`}
                    className="cursor-pointer"
                  >
                    启用
                  </FieldLabel>
                  <Switch
                    id={`${formIdPrefix}-whitelist-enabled`}
                    checked={formEnabled}
                    onCheckedChange={setFormEnabled}
                  />
                </Field>
              </FieldGroup>
            </TabsContent>

            <TabsContent value="blacklist" className="mt-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor={`${formIdPrefix}-blacklist-value`}>
                    IP / CIDR（每行一个）
                  </FieldLabel>
                  {editingItem ? (
                    <Input
                      id={`${formIdPrefix}-blacklist-value`}
                      value={formValue}
                      onChange={(e) => setFormValue(e.target.value)}
                      placeholder="192.168.1.10 或 192.168.1.0/24"
                      className="rounded-lg font-mono"
                    />
                  ) : (
                    <Textarea
                      id={`${formIdPrefix}-blacklist-value`}
                      value={formValue}
                      onChange={(e) => setFormValue(e.target.value)}
                      placeholder={"1.2.3.4\n5.6.7.0/24"}
                      rows={4}
                      className="rounded-lg font-mono text-sm"
                    />
                  )}
                  <FieldDescription>
                    新增时支持每行一个 IP 或 CIDR；编辑时只保存第一行。
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor={`${formIdPrefix}-blacklist-note`}>
                    备注
                  </FieldLabel>
                  <Input
                    id={`${formIdPrefix}-blacklist-note`}
                    value={formNote}
                    onChange={(e) => setFormNote(e.target.value)}
                    placeholder="例如：恶意扫描源"
                    className="rounded-lg"
                  />
                </Field>
                <Field>
                  <FieldLabel>动作</FieldLabel>
                  <ToggleGroup
                    type="single"
                    value={formAction}
                    onValueChange={(value) => {
                      if (value === "intercept" || value === "drop") {
                        setFormAction(value)
                      }
                    }}
                    className="grid w-full grid-cols-2 items-stretch"
                    variant="outline"
                  >
                    <ToggleGroupItem
                      value="intercept"
                      className="h-auto flex-col items-start justify-start gap-1 p-3 text-left"
                    >
                      <span className="flex items-center gap-2 text-sm font-medium">
                        <Ban data-icon="inline-start" />
                        拦截 (403)
                      </span>
                      <span className="text-xs text-muted-foreground">
                        返回 403 拦截页面
                      </span>
                    </ToggleGroupItem>
                    <ToggleGroupItem
                      value="drop"
                      className="h-auto flex-col items-start justify-start gap-1 p-3 text-left"
                    >
                      <span className="flex items-center gap-2 text-sm font-medium">
                        <Zap data-icon="inline-start" />
                        Drop（无 HTTP 响应）
                      </span>
                      <span className="text-xs text-muted-foreground">
                        关闭连接并记录 status_code=0
                      </span>
                    </ToggleGroupItem>
                  </ToggleGroup>
                </Field>
                <Field
                  orientation="horizontal"
                  className="items-center justify-between rounded-lg border border-border px-4 py-3"
                >
                  <FieldLabel
                    htmlFor={`${formIdPrefix}-blacklist-enabled`}
                    className="cursor-pointer"
                  >
                    启用
                  </FieldLabel>
                  <Switch
                    id={`${formIdPrefix}-blacklist-enabled`}
                    checked={formEnabled}
                    onCheckedChange={setFormEnabled}
                  />
                </Field>
              </FieldGroup>
            </TabsContent>
          </Tabs>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              取消
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? "保存中..." : "保存"}
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
        <AlertDialogContent className="max-w-sm rounded-xl">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              删除后该条目立即从运行时名单中移除
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Alert variant="destructive">
            <Trash2 />
            <AlertDescription>
              即将删除{" "}
              <code className="rounded bg-destructive/10 px-1 font-mono text-xs">
                {deleteTarget?.value}
              </code>{" "}
              ，此操作不可撤销。
            </AlertDescription>
          </Alert>
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

      <AlertDialog
        open={batchDeleteOpen}
        onOpenChange={(open) => {
          if (!open && !batchDeleting) setBatchDeleteOpen(false)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认批量删除</AlertDialogTitle>
            <AlertDialogDescription>
              将删除当前页已选的 {selected.size} 个 IP
              黑白名单条目。删除后这些条目会立即从运行时名单中移除。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={batchDeleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={batchDeleting}
              onClick={(event) => {
                event.preventDefault()
                handleBatchDelete()
              }}
            >
              {batchDeleting ? "删除中..." : "批量删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
