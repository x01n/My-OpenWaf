"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Ban, ShieldAlert, ShieldCheck, ShieldX, Zap } from "lucide-react";
import { toast } from "sonner";
import { api, type IPListItem } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Pagination } from "@/components/pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, InlineMeta, PageIntro, Surface, statusToneClass } from "@/components/console-shell";

interface ListResponse {
  items: IPListItem[];
  total: number;
}

const PAGE_SIZE = 20;
const emptyForm = {
  kind: "whitelist",
  value: "",
  note: "",
  action: "intercept" as string,
  enabled: true,
};

const actionOptions = [
  { value: "intercept", label: "拦截 (403)", description: "返回 403 拦截页面" },
  { value: "block", label: "阻断 (TCP RST)", description: "直接断开 TCP 连接" },
] as const;

function ActionBadge({ action }: { action?: string }) {
  if (!action || action === "intercept") {
    return (
      <Badge variant="outline" className="gap-1 rounded-xl border-amber-200 bg-amber-50 text-amber-700">
        <Ban className="h-3 w-3" />
        拦截 403
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="gap-1 rounded-xl border-rose-200 bg-rose-50 text-rose-700">
      <Zap className="h-3 w-3" />
      TCP RST
    </Badge>
  );
}

export default function IPListsPage() {
  const [items, setItems] = useState<IPListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [kindFilter, setKindFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<IPListItem | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [saving, setSaving] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<IPListItem | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
      });
      if (kindFilter !== "all") {
        params.set("kind", kindFilter);
      }
      const result = await api<ListResponse>(`/api/v1/ip-lists?${params.toString()}`);
      setItems(result.items ?? []);
      setTotal(result.total ?? 0);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败");
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [kindFilter, page]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const currentPageSummary = useMemo(() => {
    const enabledCount = items.filter((item) => item.enabled).length;
    const whitelistCount = items.filter((item) => item.kind === "whitelist").length;
    const blacklistCount = items.filter((item) => item.kind === "blacklist").length;
    return { enabledCount, whitelistCount, blacklistCount };
  }, [items]);

  function openCreate() {
    setEditingItem(null);
    setForm(emptyForm);
    setDialogOpen(true);
  }

  function openEdit(item: IPListItem) {
    setEditingItem(item);
    setForm({
      kind: item.kind,
      value: item.value,
      note: item.note,
      action: item.action || "intercept",
      enabled: item.enabled,
    });
    setDialogOpen(true);
  }

  async function handleSave() {
    const payload = {
      kind: form.kind,
      value: form.value.trim(),
      note: form.note.trim(),
      action: form.kind === "blacklist" ? form.action : undefined,
      enabled: form.enabled,
    };

    if (!payload.value) {
      toast.error("请输入 IP 或 CIDR");
      return;
    }

    setSaving(true);
    try {
      if (editingItem) {
        await api(`/api/v1/ip-lists/${editingItem.id}/update`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast.success("条目已更新");
      } else {
        await api("/api/v1/ip-lists", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        toast.success("条目已创建");
      }
      setDialogOpen(false);
      setEditingItem(null);
      setForm(emptyForm);
      load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api(`/api/v1/ip-lists/${deleteTarget.id}/delete`, { method: "POST" });
      toast.success("条目已删除");
      setDeleteTarget(null);
      load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "删除失败");
    } finally {
      setDeleting(false);
    }
  }

  async function handleActionChange(item: IPListItem, newAction: string) {
    try {
      await api(`/api/v1/ip-lists/${item.id}/update`, {
        method: "POST",
        body: JSON.stringify({ ...item, action: newAction }),
      });
      toast.success("动作类型已更新");
      load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "更新失败");
    }
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Access Control"
        title="IP 黑白名单"
        description="管理 IP 黑名单与白名单条目。黑名单条目支持选择拦截动作（403 页面或 TCP RST），保存后立即触发运行时 reload。"
        actions={<Button onClick={openCreate}>新增条目</Button>}
      />

      <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <Surface title="筛选与列表" description="支持按条目类型过滤，值字段可直接填写单 IP 或 CIDR。">
          <div className="mb-4 grid gap-3 md:grid-cols-3">
            <select
              value={kindFilter}
              onChange={(event) => {
                setKindFilter(event.target.value);
                setPage(1);
              }}
              className="h-10 rounded-xl border border-slate-200 bg-white px-3 text-sm text-slate-900"
            >
              <option value="all">全部类型</option>
              <option value="whitelist">白名单</option>
              <option value="blacklist">黑名单</option>
            </select>
            <Button
              variant="outline"
              className="rounded-xl"
              onClick={() => {
                setKindFilter("all");
                setPage(1);
              }}
            >
              重置筛选
            </Button>
          </div>

          {loading ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
          ) : items.length === 0 ? (
            <EmptyState title="暂无 IP 条目" description="创建后即可参与白名单放行或黑名单阻断流程。" />
          ) : (
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {items.map((item) => {
                  const kindLabel = item.kind === "whitelist" ? "白名单" : "黑名单";
                  const kindTone = item.kind === "whitelist" ? "success" : "error";
                  const isCIDR = item.value.includes("/");
                  return (
                    <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="mb-3 flex items-start justify-between gap-3">
                        <div className="space-y-2">
                          <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                            {item.kind === "whitelist" ? (
                              <ShieldCheck className="h-4 w-4 text-emerald-700" />
                            ) : (
                              <ShieldX className="h-4 w-4 text-rose-700" />
                            )}
                            {kindLabel}
                          </div>
                          <div className="font-mono text-xs text-slate-500">#{item.id}</div>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <span className={`console-badge ${statusToneClass(kindTone)}`}>{kindLabel}</span>
                          <span className={`console-badge ${statusToneClass(item.enabled ? "success" : "default")}`}>{item.enabled ? "启用" : "禁用"}</span>
                        </div>
                      </div>

                      <div className="space-y-3 text-sm text-slate-600">
                        <div className="rounded-2xl border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-slate-700 break-all">
                          {item.value}
                        </div>
                        <div className="flex items-center justify-between">
                          <span>{isCIDR ? "CIDR 网段" : "单 IP 条目"}</span>
                          {item.kind === "blacklist" && <ActionBadge action={item.action} />}
                        </div>
                        {item.kind === "blacklist" && (
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-slate-500 shrink-0">动作：</span>
                            <Select
                              value={item.action || "intercept"}
                              onValueChange={(value) => handleActionChange(item, value)}
                            >
                              <SelectTrigger className="h-8 rounded-xl text-xs">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="intercept">拦截 (403 页面)</SelectItem>
                                <SelectItem value="block">阻断 (TCP RST)</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        )}
                        <div className="text-xs text-slate-500">备注：{item.note || "无"}</div>
                        <div className="text-xs text-slate-500">更新时间：{formatDate(item.updated_at)}</div>
                      </div>

                      <div className="mt-4 flex items-center gap-2">
                        <Button variant="outline" size="sm" className="rounded-xl" onClick={() => openEdit(item)}>
                          编辑
                        </Button>
                        <Button variant="ghost" size="sm" className="rounded-xl text-rose-600" onClick={() => setDeleteTarget(item)}>
                          删除
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
              <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
            </div>
          )}
        </Surface>

        <Surface title="当前页概览" description="便于快速判断当前筛选结果中的条目结构。">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-1">
            <InlineMeta label="总条目数" value={String(total)} />
            <InlineMeta label="当前页启用" value={String(currentPageSummary.enabledCount)} />
            <InlineMeta label="当前页白名单" value={String(currentPageSummary.whitelistCount)} />
            <InlineMeta label="当前页黑名单" value={String(currentPageSummary.blacklistCount)} />
          </div>
        </Surface>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-xl rounded-[28px]">
          <DialogHeader>
            <DialogTitle>{editingItem ? "编辑 IP 条目" : "新增 IP 条目"}</DialogTitle>
            <DialogDescription>保存后将立即写入黑白名单配置，并触发运行时 reload。</DialogDescription>
          </DialogHeader>

          <div className="space-y-5">
            <div className="grid gap-3 md:grid-cols-2">
              <button
                type="button"
                onClick={() => setForm((current) => ({ ...current, kind: "whitelist" }))}
                className={form.kind === "whitelist" ? "rounded-2xl border-2 border-emerald-300 bg-emerald-50 p-4 text-left" : "rounded-2xl border border-slate-200 bg-slate-50 p-4 text-left"}
              >
                <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                  <ShieldCheck className="h-4 w-4 text-emerald-700" /> 白名单
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">命中后优先放行，适合可信来源或运维地址。</p>
              </button>
              <button
                type="button"
                onClick={() => setForm((current) => ({ ...current, kind: "blacklist" }))}
                className={form.kind === "blacklist" ? "rounded-2xl border-2 border-rose-300 bg-rose-50 p-4 text-left" : "rounded-2xl border border-slate-200 bg-slate-50 p-4 text-left"}
              >
                <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                  <ShieldX className="h-4 w-4 text-rose-700" /> 黑名单
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">命中后进入阻断链路，适合恶意来源或封禁网段。</p>
              </button>
            </div>

            {form.kind === "blacklist" && (
              <div className="space-y-2">
                <Label>阻断动作</Label>
                <div className="grid gap-3 md:grid-cols-2">
                  {actionOptions.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setForm((current) => ({ ...current, action: opt.value }))}
                      className={
                        form.action === opt.value
                          ? "rounded-2xl border-2 border-cyan-300 bg-cyan-50 p-4 text-left"
                          : "rounded-2xl border border-slate-200 bg-slate-50 p-4 text-left"
                      }
                    >
                      <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                        {opt.value === "intercept" ? <Ban className="h-4 w-4 text-amber-600" /> : <Zap className="h-4 w-4 text-rose-600" />}
                        {opt.label}
                      </div>
                      <p className="mt-2 text-xs leading-5 text-slate-500">{opt.description}</p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="ip-value">IP / CIDR</Label>
              <Input
                id="ip-value"
                value={form.value}
                onChange={(event) => setForm((current) => ({ ...current, value: event.target.value }))}
                placeholder="例如 192.168.1.10 或 192.168.1.0/24"
                className="rounded-xl font-mono"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="ip-note">备注</Label>
              <Input
                id="ip-note"
                value={form.note}
                onChange={(event) => setForm((current) => ({ ...current, note: event.target.value }))}
                placeholder="例如：办公出口、已确认恶意扫描源"
                className="rounded-xl"
              />
            </div>

            <button
              type="button"
              onClick={() => setForm((current) => ({ ...current, enabled: !current.enabled }))}
              className={form.enabled ? "flex w-full items-center justify-between rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-left" : "flex w-full items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-left"}
            >
              <div>
                <div className="text-sm font-medium text-slate-900">立即启用</div>
                <div className="mt-1 text-xs text-slate-500">关闭后条目仍保留，但不会参与运行时匹配。</div>
              </div>
              <span className={`console-badge ${statusToneClass(form.enabled ? "success" : "default")}`}>{form.enabled ? "启用" : "禁用"}</span>
            </button>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>取消</Button>
            <Button onClick={handleSave} disabled={saving}>{saving ? "保存中..." : "保存"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="max-w-md rounded-[28px]">
          <DialogHeader>
            <DialogTitle>确认删除</DialogTitle>
            <DialogDescription>删除后该条目会立即从运行时黑白名单中移除。</DialogDescription>
          </DialogHeader>
          <div className="flex gap-3 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-900">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <p>删除后该条目将立即从黑白名单中移除，并触发运行时配置 reload。</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>取消</Button>
            <Button className="bg-rose-600 hover:bg-rose-500" disabled={deleting} onClick={handleDelete}>
              {deleting ? "删除中..." : "删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
