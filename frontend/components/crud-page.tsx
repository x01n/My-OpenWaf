"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Loader2, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { EmptyState, PageIntro, Surface } from "@/components/console-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";

export interface FieldDef {
  key: string;
  label: string;
  type?: "text" | "number" | "textarea" | "boolean" | "select" | "async-select";
  options?: { value: string; label: string }[];
  asyncOptions?: {
    apiPath: string;
    valueKey?: string;
    labelKey?: string | ((item: Record<string, unknown>) => string);
  };
  hideInTable?: boolean;
  defaultValue?: unknown;
  nullable?: boolean;
  placeholder?: string;
  description?: string;
  render?: (value: unknown, item: Record<string, unknown>) => React.ReactNode;
  customInput?: (props: { value: unknown; onChange: (val: unknown) => void }) => React.ReactNode;
}

interface CrudPageProps {
  title: string;
  description?: string;
  apiPath: string;
  fields: FieldDef[];
  idField?: string;
  onAfterSave?: () => void;
}

export function CrudPage({ title, description, apiPath, fields, idField = "id", onAfterSave }: CrudPageProps) {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [editing, setEditing] = useState<Record<string, unknown> | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Record<string, unknown> | null>(null);
  const [asyncOpts, setAsyncOpts] = useState<Record<string, { value: string; label: string }[]>>({});
  const asyncOptsLoadedRef = useRef(false);

  useEffect(() => {
    if (asyncOptsLoadedRef.current) return;
    asyncOptsLoadedRef.current = true;

    const asyncFields = fields.filter((field) => field.type === "async-select" && field.asyncOptions);
    if (asyncFields.length === 0) return;

    asyncFields.forEach(async (field) => {
      try {
        const config = field.asyncOptions!;
        const data = await api<{ items: Record<string, unknown>[] }>(config.apiPath);
        const valueKey = config.valueKey || "id";
        const options = (data.items || []).map((item) => ({
          value: String(item[valueKey] ?? ""),
          label:
            typeof config.labelKey === "function"
              ? config.labelKey(item)
              : String(item[config.labelKey || "name"] ?? item[valueKey] ?? ""),
        }));
        if (field.nullable) {
          options.unshift({ value: "__null__", label: "— 不选择 —" });
        }
        setAsyncOpts((prev) => ({ ...prev, [field.key]: options }));
      } catch {
        setAsyncOpts((prev) => ({ ...prev, [field.key]: [] }));
      }
    });
  }, [fields]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api<{ items: Record<string, unknown>[] }>(apiPath);
      setItems(data.items || []);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败");
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [apiPath]);

  useEffect(() => {
    load();
  }, [load]);

  function openNew() {
    const defaults: Record<string, unknown> = {};
    fields.forEach((field) => {
      defaults[field.key] = getDefaultValue(field);
    });
    setEditing(defaults);
    setIsNew(true);
    setOpen(true);
  }

  function openEdit(item: Record<string, unknown>) {
    setEditing({ ...item });
    setIsNew(false);
    setOpen(true);
  }

  async function handleSave() {
    if (!editing) return;
    setSaving(true);
    try {
      if (isNew) {
        await api(apiPath, { method: "POST", body: JSON.stringify(editing) });
        toast.success("创建成功，配置已自动生效");
      } else {
        await api(`${apiPath}/${editing[idField]}/update`, {
          method: "POST",
          body: JSON.stringify(editing),
        });
        toast.success("更新成功，配置已自动生效");
      }
      setOpen(false);
      onAfterSave?.();
      load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "操作失败");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api(`${apiPath}/${deleteTarget[idField]}/delete`, { method: "POST" });
      toast.success("已删除，配置已自动生效");
      setDeleteTarget(null);
      onAfterSave?.();
      load();
    } catch {
      toast.error("删除失败");
    }
  }

  const tableColumns = fields.filter((field) => !field.hideInTable);

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Resource Manager"
        title={title}
        description={description || "通过真实后端 API 管理资源，并在配置写入后触发即时生效。"}
        actions={
          <Button className="rounded-md bg-teal-500 text-white hover:bg-teal-600" onClick={openNew}>
            <Plus className="mr-2 h-4 w-4" /> 新增{title}
          </Button>
        }
      />

      <Surface title={`${title}列表`} description="点击编辑可调整单条记录，删除操作会直接调用后端 delete 接口。">
        {loading ? (
          <div className="overflow-hidden rounded-lg border border-slate-200">
            <Table>
              <TableHeader>
                <TableRow className="bg-slate-50">
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
                    <TableCell><Skeleton className="h-4 w-8" /></TableCell>
                    {tableColumns.map((field) => (
                      <TableCell key={field.key}><Skeleton className="h-4 w-28" /></TableCell>
                    ))}
                    <TableCell><Skeleton className="h-4 w-12" /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : items.length === 0 ? (
          <EmptyState title={`暂无${title}`} description="创建第一条记录后，这里会显示真实后端返回的数据列表。" />
        ) : (
          <div className="overflow-hidden rounded-lg border border-slate-200">
            <Table>
              <TableHeader>
                <TableRow className="bg-slate-50 text-xs uppercase tracking-[0.16em] text-slate-500">
                  <TableHead className="w-16">ID</TableHead>
                  {tableColumns.map((field) => (
                    <TableHead key={field.key}>{field.label}</TableHead>
                  ))}
                  <TableHead className="w-24 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => (
                  <TableRow key={String(item[idField])} className="hover:bg-slate-50">
                    <TableCell className="font-mono text-xs text-slate-500">{String(item[idField])}</TableCell>
                    {tableColumns.map((field) => (
                      <TableCell key={field.key} className="max-w-[300px] truncate text-sm text-slate-700">
                        {field.render
                          ? field.render(item[field.key], item)
                          : field.type === "boolean"
                            ? item[field.key]
                              ? "已启用"
                              : "已禁用"
                            : field.type === "async-select" && asyncOpts[field.key]
                              ? asyncOpts[field.key].find((option) => option.value === String(item[field.key]))?.label ?? String(item[field.key] ?? "")
                              : String(item[field.key] ?? "")}
                      </TableCell>
                    ))}
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="icon-sm" className="rounded-lg" onClick={() => openEdit(item)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon-sm" className="rounded-lg text-rose-600 hover:bg-rose-50 hover:text-rose-700" onClick={() => setDeleteTarget(item)}>
                          <Trash2 className="h-4 w-4" />
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
            <DialogDescription>{isNew ? "填写真实后端字段后立即创建资源。" : "调整当前资源字段并在保存后即时生效。"}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {fields.map((field) => (
              <div key={field.key} className="space-y-2">
                <Label htmlFor={`field-${field.key}`}>{field.label}</Label>
                {field.description ? <p className="text-xs text-slate-500">{field.description}</p> : null}
                {field.customInput ? (
                  field.customInput({
                    value: editing?.[field.key] ?? "",
                    onChange: (value) => setEditing((prev) => (prev ? { ...prev, [field.key]: value } : prev)),
                  })
                ) : field.type === "textarea" ? (
                  <Textarea
                    id={`field-${field.key}`}
                    placeholder={field.placeholder}
                    value={String(editing?.[field.key] ?? "")}
                    onChange={(event) => setEditing((prev) => (prev ? { ...prev, [field.key]: event.target.value } : prev))}
                    className="min-h-[120px] rounded-lg font-mono text-sm"
                  />
                ) : field.type === "boolean" ? (
                  <div className="flex items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                    <Switch
                      id={`field-${field.key}`}
                      checked={!!editing?.[field.key]}
                      onCheckedChange={(checked) => setEditing((prev) => (prev ? { ...prev, [field.key]: checked } : prev))}
                    />
                    <span className="text-sm text-slate-600">{editing?.[field.key] ? "已启用" : "已禁用"}</span>
                  </div>
                ) : field.type === "select" || field.type === "async-select" ? (
                  <Select
                    value={editing?.[field.key] == null ? (field.nullable ? "__null__" : "") : String(editing?.[field.key])}
                    onValueChange={(value) => {
                      const resolved = value === "__null__" ? null : field.asyncOptions ? Number(value) : value;
                      setEditing((prev) => (prev ? { ...prev, [field.key]: resolved } : prev));
                    }}
                  >
                    <SelectTrigger className="rounded-lg"><SelectValue placeholder="请选择" /></SelectTrigger>
                    <SelectContent>
                      {(field.type === "async-select" ? asyncOpts[field.key] || [] : field.options || []).map((option) => (
                        <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    id={`field-${field.key}`}
                    type={field.type || "text"}
                    placeholder={field.placeholder}
                    value={editing?.[field.key] == null ? "" : String(editing?.[field.key])}
                    onChange={(event) => {
                      let value: unknown = event.target.value;
                      if (field.nullable && event.target.value === "") {
                        value = null;
                      } else if (field.type === "number") {
                        value = event.target.value === "" ? 0 : Number(event.target.value);
                      }
                      setEditing((prev) => (prev ? { ...prev, [field.key]: value } : prev));
                    }}
                    className="rounded-lg"
                  />
                )}
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>取消</Button>
            <Button onClick={handleSave} disabled={saving} className="rounded-lg bg-teal-500 text-white hover:bg-teal-600">
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              {isNew ? "创建" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={(visible) => !visible && setDeleteTarget(null)}>
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>此操作不可撤销。删除后，相关配置将立即从当前资源列表中移除。</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction className="bg-rose-600 hover:bg-rose-500" onClick={handleDelete}>删除</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function getDefaultValue(field: FieldDef): unknown {
  if (field.defaultValue !== undefined) return field.defaultValue;
  if (field.nullable) return null;
  if (field.type === "boolean") return false;
  if (field.type === "number") return 0;
  if (field.type === "select") return field.options?.[0]?.value ?? "";
  return "";
}
