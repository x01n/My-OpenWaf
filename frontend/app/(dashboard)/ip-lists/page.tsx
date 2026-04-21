"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  ShieldCheck,
  ShieldX,
  Plus,
  Pencil,
  Trash2,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

interface IPListItem {
  id: number;
  kind: string;
  value: string;
  note: string;
  enabled: boolean;
  hit_count?: number;
  updated_at: string;
}

interface ListResponse {
  items: IPListItem[];
  total: number;
}

const PAGE_SIZE = 20;

export default function IPListsPage() {
  const [items, setItems] = useState<IPListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [kindFilter, setKindFilter] = useState("all");
  const [loading, setLoading] = useState(true);

  // dialog state
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<IPListItem | null>(null);
  const [formKind, setFormKind] = useState<string>("whitelist");
  const [formName, setFormName] = useState("");
  const [formMatchMode, setFormMatchMode] = useState("equal");
  const [formValue, setFormValue] = useState("");
  const [formEnabled, setFormEnabled] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  // delete confirm
  const [deleteTarget, setDeleteTarget] = useState<IPListItem | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
      });
      if (kindFilter !== "all") params.set("kind", kindFilter);
      const res = await api<ListResponse>(
        `/api/v1/ip-lists?${params.toString()}`
      );
      setItems(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch {
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page, kindFilter]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // reset page when filter changes
  useEffect(() => {
    setPage(1);
  }, [kindFilter]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  function openCreate() {
    setEditingItem(null);
    setFormKind("whitelist");
    setFormName("");
    setFormMatchMode("equal");
    setFormValue("");
    setFormEnabled(true);
    setDialogOpen(true);
  }

  function openEdit(item: IPListItem) {
    setEditingItem(item);
    setFormKind(item.kind);
    setFormName(item.note);
    setFormMatchMode(item.value.includes("/") ? "cidr" : "equal");
    setFormValue(item.value);
    setFormEnabled(item.enabled);
    setDialogOpen(true);
  }

  async function handleSubmit() {
    setSubmitting(true);
    try {
      const body = {
        kind: formKind,
        value: formValue.trim(),
        note: formName.trim(),
        enabled: formEnabled,
      };
      if (editingItem) {
        await api(`/api/v1/ip-lists/${editingItem.id}/update`, {
          method: "POST",
          body: JSON.stringify(body),
        });
      } else {
        await api(`/api/v1/ip-lists`, {
          method: "POST",
          body: JSON.stringify(body),
        });
      }
      setDialogOpen(false);
      fetchData();
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api(`/api/v1/ip-lists/${deleteTarget.id}/delete`, {
        method: "POST",
      });
      setDeleteTarget(null);
      fetchData();
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-gray-800">IP 黑白名单</h1>
        <p className="text-gray-500 text-sm mt-0.5">管理 IP 黑名单和白名单规则，支持单 IP 和 CIDR 网段</p>
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500">类型</span>
          <Select value={kindFilter} onValueChange={setKindFilter}>
            <SelectTrigger className="w-[120px] h-8 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部</SelectItem>
              <SelectItem value="whitelist">白名单</SelectItem>
              <SelectItem value="blacklist">黑名单</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="text-teal-600 border-teal-500 hover:bg-teal-50">
            订阅在线规则
          </Button>
          <Button onClick={openCreate} size="sm" className="bg-teal-500 hover:bg-teal-600 text-white">
            <Plus className="mr-1 h-4 w-4" />
            添加规则
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-gray-200 overflow-hidden bg-white">
        <Table>
          <TableHeader>
            <TableRow className="bg-gray-50">
              <TableHead className="w-[80px] text-gray-600 font-medium">状态</TableHead>
              <TableHead className="w-[100px] text-gray-600 font-medium">类型</TableHead>
              <TableHead className="text-gray-600 font-medium">名称</TableHead>
              <TableHead className="text-gray-600 font-medium">详情</TableHead>
              <TableHead className="w-[90px] text-center text-gray-600 font-medium">今日命中</TableHead>
              <TableHead className="w-[170px] text-gray-600 font-medium">更新时间</TableHead>
              <TableHead className="w-[80px] text-right text-gray-600 font-medium">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-32 text-center text-gray-400">加载中...</TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="h-32 text-center text-gray-400">暂无数据</TableCell>
              </TableRow>
            ) : (
              items.map((item) => (
                <TableRow key={item.id} className="hover:bg-gray-50">
                  <TableCell>
                    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${item.enabled ? "bg-teal-50 text-teal-700 border border-teal-200" : "bg-gray-100 text-gray-500 border border-gray-200"}`}>
                      {item.enabled ? "启用" : "禁用"}
                    </span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      {item.kind === "whitelist" ? (
                        <ShieldCheck className="h-4 w-4 text-teal-500" />
                      ) : (
                        <ShieldX className="h-4 w-4 text-red-500" />
                      )}
                      <span className="text-sm text-gray-700">{item.kind === "whitelist" ? "白名单" : "黑名单"}</span>
                    </div>
                  </TableCell>
                  <TableCell className="font-medium text-gray-800">{item.note || "-"}</TableCell>
                  <TableCell>
                    <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-700">{item.value}</code>
                  </TableCell>
                  <TableCell className="text-center text-gray-700">{item.hit_count ?? 0}</TableCell>
                  <TableCell className="text-gray-500 text-sm">{formatDate(item.updated_at)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-gray-400 hover:text-teal-600" onClick={() => openEdit(item)}>
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-gray-400 hover:text-red-500" onClick={() => setDeleteTarget(item)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>{PAGE_SIZE} 条每页，共 {total} 条</span>
          <div className="flex items-center gap-1">
            <Button variant="outline" size="icon" className="h-7 w-7" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="px-2">{page} / {totalPages}</span>
            <Button variant="outline" size="icon" className="h-7 w-7" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Create / Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-[520px]">
          <DialogHeader>
            <DialogTitle>{editingItem ? "编辑规则" : "添加规则"}</DialogTitle>
          </DialogHeader>

          <div className="space-y-5 py-2">
            {/* Kind selector - card style */}
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setFormKind("whitelist")}
                className={`flex items-center gap-2 rounded-lg border-2 px-4 py-3 transition-colors ${formKind === "whitelist" ? "border-teal-500 bg-teal-50" : "border-gray-200 bg-white hover:border-gray-300"}`}
              >
                <div className={`h-4 w-4 rounded-full border-2 flex items-center justify-center ${formKind === "whitelist" ? "border-teal-500" : "border-gray-300"}`}>
                  {formKind === "whitelist" && <div className="h-2 w-2 rounded-full bg-teal-500" />}
                </div>
                <ShieldCheck className="h-4 w-4 text-teal-500" />
                <span className="text-sm font-medium text-gray-700">白名单</span>
              </button>
              <button
                onClick={() => setFormKind("blacklist")}
                className={`flex items-center gap-2 rounded-lg border-2 px-4 py-3 transition-colors ${formKind === "blacklist" ? "border-teal-500 bg-teal-50" : "border-gray-200 bg-white hover:border-gray-300"}`}
              >
                <div className={`h-4 w-4 rounded-full border-2 flex items-center justify-center ${formKind === "blacklist" ? "border-teal-500" : "border-gray-300"}`}>
                  {formKind === "blacklist" && <div className="h-2 w-2 rounded-full bg-teal-500" />}
                </div>
                <ShieldX className="h-4 w-4 text-red-500" />
                <span className="text-sm font-medium text-gray-700">黑名单</span>
              </button>
            </div>

            {/* Name */}
            <div className="space-y-2">
              <Label className="text-gray-700">名称 <span className="text-red-500">*</span></Label>
              <Input placeholder="规则名称" value={formName} onChange={(e) => setFormName(e.target.value)} />
            </div>

            {/* Condition row */}
            <div className="space-y-2">
              <Label className="text-gray-700">匹配条件</Label>
              <div className="flex gap-2">
                <Select value="source_ip" disabled>
                  <SelectTrigger className="w-[110px]"><SelectValue placeholder="源IP" /></SelectTrigger>
                  <SelectContent><SelectItem value="source_ip">源IP</SelectItem></SelectContent>
                </Select>
                <Select value={formMatchMode} onValueChange={setFormMatchMode}>
                  <SelectTrigger className="w-[120px]"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="equal">等于</SelectItem>
                    <SelectItem value="cidr">属于网段</SelectItem>
                  </SelectContent>
                </Select>
                <Input
                  className="flex-1"
                  placeholder={formMatchMode === "cidr" ? "例: 192.168.1.0/24" : "例: 192.168.1.1"}
                  value={formValue}
                  onChange={(e) => setFormValue(e.target.value)}
                />
              </div>
            </div>

            {/* Enabled */}
            <div className="flex items-center gap-2">
              <Checkbox id="rule-enabled" checked={formEnabled} onCheckedChange={(v) => setFormEnabled(v === true)} />
              <Label htmlFor="rule-enabled" className="font-normal cursor-pointer text-gray-700">启用此规则</Label>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} className="text-teal-600 border-teal-500">取消</Button>
            <Button onClick={handleSubmit} disabled={!formValue.trim() || submitting} className="bg-teal-500 hover:bg-teal-600 text-white">
              {submitting ? "提交中..." : "提交"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              确定要删除规则「{deleteTarget?.note || deleteTarget?.value}」吗？此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-red-600 hover:bg-red-700 text-white"
            >
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
