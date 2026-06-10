"use client"

import { useEffect, useState, useCallback, useRef } from "react"
import { Loader2, Pencil, Plus, Trash2 } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { EmptyState, PageIntro, Surface } from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Switch } from "@/components/ui/switch"
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
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
import { Skeleton } from "@/components/ui/skeleton"
import { api } from "@/lib/api"

export interface FieldDef {
  key: string
  label: string
  type?: "text" | "number" | "textarea" | "boolean" | "select" | "async-select"
  options?: { value: string; label: string }[]
  asyncOptions?: {
    apiPath: string
    valueKey?: string
    labelKey?: string | ((item: Record<string, unknown>) => string)
  }
  hideInTable?: boolean
  defaultValue?: unknown
  nullable?: boolean
  placeholder?: string
  description?: string
  render?: (value: unknown, item: Record<string, unknown>) => React.ReactNode
  customInput?: (props: {
    value: unknown
    onChange: (val: unknown) => void
  }) => React.ReactNode
}

interface CrudPageProps {
  title: string
  description?: string
  apiPath: string
  fields: FieldDef[]
  idField?: string
  onAfterSave?: () => void
}

interface CrudListResponse {
  items: Record<string, unknown>[]
}

type CrudOperationDetails = {
  operation: "create" | "update" | "delete"
  api_path: string
  id_field: string
  resource_id?: unknown
  payload?: Record<string, unknown>
  response: unknown
}

export function CrudPage({
  title,
  description,
  apiPath,
  fields,
  idField = "id",
  onAfterSave,
}: CrudPageProps) {
  const [items, setItems] = useState<Record<string, unknown>[]>([])
  const [editing, setEditing] = useState<Record<string, unknown> | null>(null)
  const [isNew, setIsNew] = useState(false)
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Record<
    string,
    unknown
  > | null>(null)
  const [asyncOpts, setAsyncOpts] = useState<
    Record<string, { value: string; label: string }[]>
  >({})
  const [operationDetails, setOperationDetails] =
    useState<CrudOperationDetails | null>(null)
  const asyncOptsLoadedRef = useRef(false)

  useEffect(() => {
    if (asyncOptsLoadedRef.current) return
    asyncOptsLoadedRef.current = true

    const asyncFields = fields.filter(
      (field) => field.type === "async-select" && field.asyncOptions
    )
    if (asyncFields.length === 0) return

    asyncFields.forEach(async (field) => {
      try {
        const config = field.asyncOptions!
        const data = await api<CrudListResponse>(config.apiPath)
        const valueKey = config.valueKey || "id"
        const options = (data.items || []).map((item) => ({
          value: String(item[valueKey] ?? ""),
          label:
            typeof config.labelKey === "function"
              ? config.labelKey(item)
              : String(item[config.labelKey || "name"] ?? item[valueKey] ?? ""),
        }))
        if (field.nullable) {
          options.unshift({ value: "__null__", label: "— 不选择 —" })
        }
        setAsyncOpts((prev) => ({ ...prev, [field.key]: options }))
      } catch {
        setAsyncOpts((prev) => ({ ...prev, [field.key]: [] }))
      }
    })
  }, [fields])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api<CrudListResponse>(apiPath)
      setItems(data.items || [])
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败")
      setItems([])
    } finally {
      setLoading(false)
    }
  }, [apiPath])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  function openNew() {
    const defaults: Record<string, unknown> = {}
    fields.forEach((field) => {
      defaults[field.key] = getDefaultValue(field)
    })
    setEditing(defaults)
    setIsNew(true)
    setOpen(true)
  }

  function openEdit(item: Record<string, unknown>) {
    setEditing({ ...item })
    setIsNew(false)
    setOpen(true)
  }

  async function handleSave() {
    if (!editing) return
    setOperationDetails(null)
    setSaving(true)
    try {
      if (isNew) {
        const response = await api<unknown>(apiPath, {
          method: "POST",
          body: JSON.stringify(editing),
        })
        setOperationDetails({
          operation: "create",
          api_path: apiPath,
          id_field: idField,
          payload: editing,
          response: response ?? null,
        })
        toast.success("创建成功，配置已自动生效")
      } else {
        const endpoint = `${apiPath}/${editing[idField]}/update`
        const response = await api<unknown>(endpoint, {
          method: "POST",
          body: JSON.stringify(editing),
        })
        setOperationDetails({
          operation: "update",
          api_path: endpoint,
          id_field: idField,
          resource_id: editing[idField],
          payload: editing,
          response: response ?? null,
        })
        toast.success("更新成功，配置已自动生效")
      }
      setOpen(false)
      onAfterSave?.()
      load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "操作失败")
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setOperationDetails(null)
    try {
      const endpoint = `${apiPath}/${deleteTarget[idField]}/delete`
      const response = await api<unknown>(endpoint, {
        method: "POST",
      })
      setOperationDetails({
        operation: "delete",
        api_path: endpoint,
        id_field: idField,
        resource_id: deleteTarget[idField],
        response: response ?? null,
      })
      toast.success("已删除，配置已自动生效")
      setDeleteTarget(null)
      onAfterSave?.()
      load()
    } catch {
      toast.error("删除失败")
    }
  }

  const tableColumns = fields.filter((field) => !field.hideInTable)

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Resource Manager"
        title={title}
        description={
          description ||
          "通过真实后端 API 管理资源，并在配置写入后触发即时生效。"
        }
        actions={
          <Button className="rounded-md" onClick={openNew}>
            <Plus data-icon="inline-start" />
            新增{title}
          </Button>
        }
      />

      {operationDetails ? (
        <Alert className="gap-3">
          <AlertTitle>最近{title}操作响应</AlertTitle>
          <AlertDescription>
            后端已返回通用 CRUD 操作响应体；请核对 operation、api_path、
            payload 或 response 字段。
          </AlertDescription>
          <CopyableBlock
            label={`${title}操作响应体`}
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <Surface
        title={`${title}列表`}
        description="点击编辑可调整单条记录，删除操作会直接调用后端 delete 接口。"
      >
        {loading ? (
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">ID</TableHead>
                  {tableColumns.map((field) => (
                    <TableHead key={field.key}>{field.label}</TableHead>
                  ))}
                  <TableHead className="w-24 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array.from({ length: 4 }).map((_, index) => (
                  <TableRow key={index}>
                    <TableCell>
                      <Skeleton className="h-4 w-8" />
                    </TableCell>
                    {tableColumns.map((field) => (
                      <TableCell key={field.key}>
                        <Skeleton className="h-4 w-28" />
                      </TableCell>
                    ))}
                    <TableCell>
                      <Skeleton className="h-4 w-12" />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            title={`暂无${title}`}
            description="创建第一条记录后，这里会显示真实后端返回的数据列表。"
          />
        ) : (
          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">ID</TableHead>
                  {tableColumns.map((field) => (
                    <TableHead key={field.key}>{field.label}</TableHead>
                  ))}
                  <TableHead className="w-24 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => (
                  <TableRow key={String(item[idField])}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {String(item[idField])}
                    </TableCell>
                    {tableColumns.map((field) => (
                      <TableCell
                        key={field.key}
                        className="max-w-[300px] truncate text-sm text-foreground"
                      >
                        {field.render
                          ? field.render(item[field.key], item)
                          : field.type === "boolean"
                            ? item[field.key]
                              ? "已启用"
                              : "已禁用"
                            : field.type === "async-select" &&
                                asyncOpts[field.key]
                              ? (asyncOpts[field.key].find(
                                  (option) =>
                                    option.value === String(item[field.key])
                                )?.label ?? String(item[field.key] ?? ""))
                              : String(item[field.key] ?? "")}
                      </TableCell>
                    ))}
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-lg"
                          aria-label={`编辑${title}`}
                          onClick={() => openEdit(item)}
                        >
                          <Pencil data-icon="inline-start" />
                        </Button>
                        <Button
                          variant="destructive"
                          size="icon-sm"
                          className="rounded-lg"
                          aria-label={`删除${title}`}
                          onClick={() => setDeleteTarget(item)}
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
      </Surface>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[84vh] overflow-y-auto rounded-lg sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{isNew ? `新增${title}` : `编辑${title}`}</DialogTitle>
            <DialogDescription>
              {isNew
                ? "填写真实后端字段后立即创建资源。"
                : "调整当前资源字段并在保存后即时生效。"}
            </DialogDescription>
          </DialogHeader>
          <FieldGroup className="py-2">
            {fields.map((field) => (
              <Field key={field.key}>
                <FieldLabel htmlFor={`field-${field.key}`}>
                  {field.label}
                </FieldLabel>
                {field.description ? (
                  <FieldDescription>{field.description}</FieldDescription>
                ) : null}
                {field.customInput ? (
                  field.customInput({
                    value: editing?.[field.key] ?? "",
                    onChange: (value) =>
                      setEditing((prev) =>
                        prev ? { ...prev, [field.key]: value } : prev
                      ),
                  })
                ) : field.type === "textarea" ? (
                  <Textarea
                    id={`field-${field.key}`}
                    placeholder={field.placeholder}
                    value={String(editing?.[field.key] ?? "")}
                    onChange={(event) =>
                      setEditing((prev) =>
                        prev
                          ? { ...prev, [field.key]: event.target.value }
                          : prev
                      )
                    }
                    className="min-h-[120px] rounded-lg font-mono text-sm"
                  />
                ) : field.type === "boolean" ? (
                  <div className="flex items-center gap-3 rounded-lg border bg-muted/35 px-4 py-3">
                    <Switch
                      id={`field-${field.key}`}
                      checked={!!editing?.[field.key]}
                      onCheckedChange={(checked) =>
                        setEditing((prev) =>
                          prev ? { ...prev, [field.key]: checked } : prev
                        )
                      }
                    />
                    <span className="text-sm text-muted-foreground">
                      {editing?.[field.key] ? "已启用" : "已禁用"}
                    </span>
                  </div>
                ) : field.type === "select" || field.type === "async-select" ? (
                  <Select
                    value={
                      editing?.[field.key] == null
                        ? field.nullable
                          ? "__null__"
                          : ""
                        : String(editing?.[field.key])
                    }
                    onValueChange={(value) => {
                      const resolved =
                        value === "__null__"
                          ? null
                          : field.asyncOptions
                            ? Number(value)
                            : value
                      setEditing((prev) =>
                        prev ? { ...prev, [field.key]: resolved } : prev
                      )
                    }}
                  >
                    <SelectTrigger id={`field-${field.key}`}>
                      <SelectValue placeholder="请选择" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {(field.type === "async-select"
                          ? asyncOpts[field.key] || []
                          : field.options || []
                        ).map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    id={`field-${field.key}`}
                    type={field.type || "text"}
                    placeholder={field.placeholder}
                    value={
                      editing?.[field.key] == null
                        ? ""
                        : String(editing?.[field.key])
                    }
                    onChange={(event) => {
                      let value: unknown = event.target.value
                      if (field.nullable && event.target.value === "") {
                        value = null
                      } else if (field.type === "number") {
                        value =
                          event.target.value === ""
                            ? 0
                            : Number(event.target.value)
                      }
                      setEditing((prev) =>
                        prev ? { ...prev, [field.key]: value } : prev
                      )
                    }}
                  />
                )}
              </Field>
            ))}
          </FieldGroup>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button
              onClick={handleSave}
              disabled={saving}
              className="rounded-lg"
            >
              {saving ? (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              ) : null}
              {isNew ? "创建" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(visible) => !visible && setDeleteTarget(null)}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              此操作不可撤销。删除后，相关配置将立即从当前资源列表中移除。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function getDefaultValue(field: FieldDef): unknown {
  if (field.defaultValue !== undefined) return field.defaultValue
  if (field.nullable) return null
  if (field.type === "boolean") return false
  if (field.type === "number") return 0
  if (field.type === "select") return field.options?.[0]?.value ?? ""
  return ""
}
