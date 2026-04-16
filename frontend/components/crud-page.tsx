"use client";

import { useEffect, useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
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
import { toast } from "sonner";
import { Plus, Pencil, Trash2, Loader2 } from "lucide-react";

export interface FieldDef {
  key: string;
  label: string;
  type?: "text" | "number" | "textarea" | "boolean" | "select" | "async-select";
  options?: { value: string; label: string }[];
  /** For async-select: API path to fetch options from. Response must have { items: [...] }. */
  asyncOptions?: {
    apiPath: string;
    /** Field name to use as option value (default: "id") */
    valueKey?: string;
    /** Field name(s) to use as option label. Can be a string or a function. */
    labelKey?: string | ((item: Record<string, unknown>) => string);
  };
  hideInTable?: boolean;
  defaultValue?: unknown;
  nullable?: boolean;
  placeholder?: string;
  description?: string;
  render?: (value: unknown, item: Record<string, unknown>) => React.ReactNode;
  /** Custom input component for the form dialog. Receives value and onChange. */
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
  // Async-select options cache: field key → options array
  const [asyncOpts, setAsyncOpts] = useState<Record<string, { value: string; label: string }[]>>({});

  // Load async-select options on mount (for table display) and when dialog opens (for form).
  useEffect(() => {
    const asyncFields = fields.filter((f) => f.type === "async-select" && f.asyncOptions);
    if (asyncFields.length === 0) return;

    asyncFields.forEach(async (f) => {
      try {
        const cfg = f.asyncOptions!;
        const data = await api<{ items: Record<string, unknown>[] }>(cfg.apiPath);
        const items = data.items || [];
        const vk = cfg.valueKey || "id";
        const opts = items.map((item) => {
          const labelStr = typeof cfg.labelKey === "function"
            ? cfg.labelKey(item)
            : String(item[cfg.labelKey || "name"] ?? item[vk] ?? "");
          return { value: String(item[vk] ?? ""), label: labelStr };
        });
        // Add a "none" option for nullable fields
        if (f.nullable) {
          opts.unshift({ value: "__null__", label: "— 不选择 —" });
        }
        setAsyncOpts((prev) => ({ ...prev, [f.key]: opts }));
      } catch {
        // Silently fail — will show empty select
      }
    });
  }, [fields]);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api<{ items: Record<string, unknown>[] }>(apiPath);
      setItems(data.items || []);
    } catch {
      toast.error("加载失败");
    } finally {
      setLoading(false);
    }
  }, [apiPath]);

  useEffect(() => { load(); }, [load]);

  function openNew() {
    const defaults: Record<string, unknown> = {};
    fields.forEach((f) => {
      defaults[f.key] = getDefaultValue(f);
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
    try {
      setSaving(true);
      if (isNew) {
        await api(apiPath, { method: "POST", body: JSON.stringify(editing) });
        toast.success("创建成功，配置已自动生效");
      } else {
        await api(`${apiPath}/${editing[idField]}/update`, { method: "POST", body: JSON.stringify(editing) });
        toast.success("更新成功，配置已自动生效");
      }
      setOpen(false);
      load();
      onAfterSave?.();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "操作失败");
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
      load();
      onAfterSave?.();
    } catch {
      toast.error("删除失败");
    }
  }

  const tableCols = fields.filter((f) => !f.hideInTable);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">{title}</h1>
          {description && <p className="text-sm text-muted-foreground mt-1 max-w-2xl">{description}</p>}
        </div>
        <Button size="sm" onClick={openNew}>
          <Plus className="mr-1 h-4 w-4" /> 新增
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-16">ID</TableHead>
                {tableCols.map((f) => (
                  <TableHead key={f.key}>{f.label}</TableHead>
                ))}
                <TableHead className="w-24">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell><Skeleton className="h-4 w-8" /></TableCell>
                    {tableCols.map((f) => (
                      <TableCell key={f.key}><Skeleton className="h-4 w-24" /></TableCell>
                    ))}
                    <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                  </TableRow>
                ))
              ) : items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={tableCols.length + 2} className="h-20 text-center text-muted-foreground">
                    暂无数据
                  </TableCell>
                </TableRow>
              ) : (
                items.map((item) => (
                  <TableRow key={String(item[idField])}>
                    <TableCell className="font-mono text-xs">{String(item[idField])}</TableCell>
                    {tableCols.map((f) => (
                      <TableCell key={f.key} className="max-w-xs truncate text-sm">
                        {f.render
                          ? f.render(item[f.key], item)
                          : f.type === "boolean"
                            ? (item[f.key] ? "✓" : "✗")
                            : f.type === "async-select" && asyncOpts[f.key]
                              ? (asyncOpts[f.key].find((o) => o.value === String(item[f.key]))?.label ?? String(item[f.key] ?? ""))
                              : String(item[f.key] ?? "")}
                      </TableCell>
                    ))}
                    <TableCell>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="icon" onClick={() => openEdit(item)}>
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(item)}>
                          <Trash2 className="h-3.5 w-3.5 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Edit/Create Dialog */}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[80vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{isNew ? `新增${title}` : `编辑${title}`}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {fields.map((f) => (
              <div key={f.key} className="space-y-2">
                <Label htmlFor={`field-${f.key}`}>{f.label}</Label>
                {f.description && (
                  <p className="text-xs text-muted-foreground">{f.description}</p>
                )}
                {f.customInput ? (
                  f.customInput({
                    value: editing?.[f.key] ?? "",
                    onChange: (val) => setEditing((p) => p ? { ...p, [f.key]: val } : p),
                  })
                ) : f.type === "textarea" ? (
                  <Textarea
                    id={`field-${f.key}`}
                    placeholder={f.placeholder}
                    value={String(editing?.[f.key] ?? "")}
                    onChange={(e) => setEditing((p) => p ? { ...p, [f.key]: e.target.value } : p)}
                    className="min-h-[80px] font-mono text-sm"
                  />
                ) : f.type === "boolean" ? (
                  <div className="flex items-center gap-2">
                    <Switch
                      id={`field-${f.key}`}
                      checked={!!editing?.[f.key]}
                      onCheckedChange={(checked) => setEditing((p) => p ? { ...p, [f.key]: checked } : p)}
                    />
                    <Label htmlFor={`field-${f.key}`} className="text-sm text-muted-foreground">
                      {editing?.[f.key] ? "已启用" : "已禁用"}
                    </Label>
                  </div>
                ) : f.type === "select" || f.type === "async-select" ? (
                  <Select
                    value={editing?.[f.key] == null ? (f.nullable ? "__null__" : "") : String(editing?.[f.key])}
                    onValueChange={(val) => {
                      const resolved = val === "__null__" ? null : (f.asyncOptions ? Number(val) : val);
                      setEditing((p) => p ? { ...p, [f.key]: resolved } : p);
                    }}
                  >
                    <SelectTrigger id={`field-${f.key}`}>
                      <SelectValue placeholder="请选择" />
                    </SelectTrigger>
                    <SelectContent>
                      {(f.type === "async-select" ? (asyncOpts[f.key] || []) : (f.options || [])).map((o) => (
                        <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    id={`field-${f.key}`}
                    type={f.type || "text"}
                    placeholder={f.placeholder}
                    value={editing?.[f.key] == null ? "" : String(editing?.[f.key])}
                    onChange={(e) => {
                      let val: unknown = e.target.value;
                      if (f.nullable && e.target.value === "") {
                        val = null;
                      } else if (f.type === "number") {
                        val = e.target.value === "" ? 0 : Number(e.target.value);
                      }
                      setEditing((p) => p ? { ...p, [f.key]: val } : p);
                    }}
                  />
                )}
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>取消</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
              {isNew ? "创建" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              此操作不可撤销。确定要删除这条记录吗？
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={handleDelete}>删除</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function getDefaultValue(field: FieldDef): unknown {
  if (field.defaultValue !== undefined) {
    return field.defaultValue;
  }
  if (field.nullable) {
    return null;
  }
  if (field.type === "boolean") {
    return false;
  }
  if (field.type === "number") {
    return 0;
  }
  if (field.type === "select") {
    return field.options?.[0]?.value ?? "";
  }
  return "";
}
