"use client";

import { useEffect, useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Plus, Pencil, Trash2 } from "lucide-react";

export interface FieldDef {
  key: string;
  label: string;
  type?: "text" | "number" | "textarea" | "boolean" | "select";
  options?: { value: string; label: string }[];
  hideInTable?: boolean;
  defaultValue?: unknown;
  nullable?: boolean;
}

interface CrudPageProps {
  title: string;
  description?: string;
  apiPath: string;
  fields: FieldDef[];
  idField?: string;
}

export function CrudPage({ title, description, apiPath, fields, idField = "id" }: CrudPageProps) {
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [editing, setEditing] = useState<Record<string, unknown> | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [open, setOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api<{ items: Record<string, unknown>[] }>(apiPath);
      setItems(data.items || []);
    } catch {
      toast.error("加载失败");
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
      if (isNew) {
        await api(apiPath, { method: "POST", body: JSON.stringify(editing) });
        toast.success("创建成功");
      } else {
        await api(`${apiPath}/${editing[idField]}`, { method: "PUT", body: JSON.stringify(editing) });
        toast.success("更新成功");
      }
      setOpen(false);
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "操作失败");
    }
  }

  async function handleDelete(item: Record<string, unknown>) {
    if (!confirm("确认删除？")) return;
    try {
      await api(`${apiPath}/${item[idField]}`, { method: "DELETE" });
      toast.success("已删除");
      load();
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
          {description && <p className="text-sm text-muted-foreground">{description}</p>}
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
              {items.map((item) => (
                <TableRow key={String(item[idField])}>
                  <TableCell className="font-mono text-xs">{String(item[idField])}</TableCell>
                  {tableCols.map((f) => (
                    <TableCell key={f.key} className="max-w-xs truncate text-sm">
                      {f.type === "boolean" ? (String(item[f.key]) === "true" ? "✓" : "✗") : String(item[f.key] ?? "")}
                    </TableCell>
                  ))}
                  <TableCell>
                    <div className="flex gap-1">
                      <Button variant="ghost" size="icon" onClick={() => openEdit(item)}>
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button variant="ghost" size="icon" onClick={() => handleDelete(item)}>
                        <Trash2 className="h-3.5 w-3.5 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={tableCols.length + 2} className="h-20 text-center text-muted-foreground">
                    暂无数据
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{isNew ? `新增${title}` : `编辑${title}`}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            {fields.map((f) => (
              <div key={f.key} className="space-y-1">
                <Label>{f.label}</Label>
                {f.type === "textarea" ? (
                  <textarea
                    className="flex min-h-[60px] w-full rounded-md border bg-background px-3 py-2 text-sm"
                    value={String(editing?.[f.key] ?? "")}
                    onChange={(e) => setEditing((p) => p ? { ...p, [f.key]: e.target.value } : p)}
                  />
                ) : f.type === "boolean" ? (
                  <div>
                    <input
                      type="checkbox"
                      checked={!!editing?.[f.key]}
                      onChange={(e) => setEditing((p) => p ? { ...p, [f.key]: e.target.checked } : p)}
                    />
                  </div>
                ) : f.type === "select" ? (
                  <select
                    className="flex h-9 w-full rounded-md border bg-background px-3 text-sm"
                    value={String(editing?.[f.key] ?? "")}
                    onChange={(e) => setEditing((p) => p ? { ...p, [f.key]: e.target.value } : p)}
                  >
                    {f.options?.map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                ) : (
                  <Input
                    type={f.type || "text"}
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
            <Button onClick={handleSave}>{isNew ? "创建" : "保存"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
