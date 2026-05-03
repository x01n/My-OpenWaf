"use client";

import { useCallback, useEffect, useState } from "react";
import { Download, FileUp, Plus, Search, Pencil, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Pagination } from "@/components/pagination";
import { PageIntro, Surface, EmptyState } from "@/components/console-shell";
import { RuleBuilder } from "@/components/rule-builder";
import { api, type Rule, type PaginatedResponse, buildQuery } from "@/lib/api";

const PAGE_SIZE = 20;

const phaseLabels: Record<string, string> = {
  acl: "ACL",
  signature: "签名匹配",
  custom: "自定义",
};

interface RuleFormData {
  name: string;
  phase: string;
  pattern: string;
  action: string;
  priority: number;
  enabled: boolean;
  policy_id?: number;
  description?: string;
}

const emptyForm: RuleFormData = {
  name: "", phase: "acl", pattern: "", action: "intercept",
  priority: 100, enabled: true,
};

export default function CustomRulesPage() {
  const [items, setItems] = useState<Rule[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState<RuleFormData>(emptyForm);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api<PaginatedResponse<Rule>>(`/api/v1/rules${buildQuery({ page, page_size: PAGE_SIZE })}`);
      let list = res.items ?? [];
      if (search) {
        const q = search.toLowerCase();
        list = list.filter((r) => r.name.toLowerCase().includes(q) || r.pattern.toLowerCase().includes(q));
      }
      setItems(list);
      setTotal(res.total ?? 0);
    } catch (e) { toast.error(String(e)); }
    finally { setLoading(false); }
  }, [page, search]);

  useEffect(() => { load(); }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  function openCreate() {
    setEditingId(null);
    setForm(emptyForm);
    setDialogOpen(true);
  }

  function openEdit(rule: Rule) {
    setEditingId(rule.id);
    setForm({
      name: rule.name,
      phase: rule.phase,
      pattern: rule.pattern,
      action: rule.action,
      priority: rule.priority,
      enabled: rule.enabled,
      policy_id: rule.policy_id,
    });
    setDialogOpen(true);
  }

  async function handleSave() {
    if (!form.name.trim()) { toast.error("规则名称不能为空"); return; }
    setSaving(true);
    try {
      if (editingId) {
        await api(`/api/v1/rules/${editingId}/update`, { method: "POST", body: JSON.stringify(form) });
        toast.success("规则已更新");
      } else {
        await api("/api/v1/rules", { method: "POST", body: JSON.stringify(form) });
        toast.success("规则已创建");
      }
      setDialogOpen(false);
      load();
    } catch (e) { toast.error(String(e)); }
    finally { setSaving(false); }
  }

  async function handleDelete(id: number) {
    try {
      await api(`/api/v1/rules/${id}/delete`, { method: "POST" });
      toast.success("规则已删除");
      load();
    } catch (e) { toast.error(String(e)); }
  }

  function handleExport() {
    const data = JSON.stringify(items, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `rules-export-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("规则已导出");
  }

  function handleImport() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const rules = JSON.parse(text) as RuleFormData[];
        if (!Array.isArray(rules)) { toast.error("无效的规则文件"); return; }
        let count = 0;
        for (const rule of rules) {
          try {
            await api("/api/v1/rules", { method: "POST", body: JSON.stringify(rule) });
            count++;
          } catch { /* skip invalid */ }
        }
        toast.success(`成功导入 ${count} 条规则`);
        load();
      } catch { toast.error("文件解析失败"); }
    };
    input.click();
  }

  function patternSummary(pattern: string) {
    if (!pattern) return "—";
    if (pattern.length > 50) return pattern.slice(0, 50) + "…";
    return pattern;
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Custom Rules"
        title="自定义规则"
        description="管理 ACL、签名与自定义匹配规则。规则按 phase、priority 参与数据面处理链路。"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" className="rounded-md border-white/20 text-white hover:bg-white/10" onClick={handleImport}>
              <FileUp className="mr-2 h-4 w-4" /> 导入
            </Button>
            <Button variant="outline" className="rounded-md border-white/20 text-white hover:bg-white/10" onClick={handleExport}>
              <Download className="mr-2 h-4 w-4" /> 导出
            </Button>
            <Button className="rounded-md bg-cyan-500 hover:bg-cyan-600 text-white" onClick={openCreate}>
              <Plus className="mr-2 h-4 w-4" /> 创建规则
            </Button>
          </div>
        }
      />

      <Surface title="规则列表">
        <div className="mb-4">
          <div className="relative max-w-sm">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <Input placeholder="搜索规则名称或条件..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} className="rounded-md pl-9" />
          </div>
        </div>

        {loading ? (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : items.length === 0 ? (
          <EmptyState title="暂无规则" description="点击「创建规则」添加第一条自定义规则。" action={
            <Button className="rounded-md bg-cyan-600 hover:bg-cyan-700" onClick={openCreate}><Plus className="mr-2 h-4 w-4" /> 创建规则</Button>
          } />
        ) : (
          <div className="space-y-4">
            <div className="overflow-x-auto rounded-lg border border-slate-200">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">状态</TableHead>
                    <TableHead>名称</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>匹配条件摘要</TableHead>
                    <TableHead className="w-20">命中数</TableHead>
                    <TableHead>更新时间</TableHead>
                    <TableHead className="text-right w-28">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell>
                        <Badge className={`rounded-md border text-xs ${rule.enabled ? "bg-emerald-50 text-emerald-700 border-emerald-200" : "bg-slate-100 text-slate-500 border-slate-200"}`}>
                          {rule.enabled ? "启用" : "禁用"}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium text-slate-900">{rule.name || "未命名"}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="rounded-md">{phaseLabels[rule.phase] ?? rule.phase}</Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs text-slate-600">{patternSummary(rule.pattern)}</span>
                      </TableCell>
                      <TableCell className="text-sm text-slate-600">—</TableCell>
                      <TableCell className="text-sm text-slate-500">
                        {rule.updated_at ? new Date(rule.updated_at).toLocaleString("zh-CN") : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button size="icon" variant="ghost" className="h-8 w-8 rounded-md" onClick={() => openEdit(rule)}>
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button size="icon" variant="ghost" className="h-8 w-8 rounded-md text-rose-500 hover:text-rose-700" onClick={() => handleDelete(rule.id)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
          </div>
        )}
      </Surface>

      {/* 创建/编辑 Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>{editingId ? "编辑规则" : "创建规则"}</DialogTitle>
            <DialogDescription>{editingId ? "修改规则的匹配条件和动作。" : "定义新的自定义规则。"}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>规则名称</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="例如：阻断恶意管理入口扫描" className="rounded-md" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>执行阶段</Label>
                <Select value={form.phase} onValueChange={(v) => setForm({ ...form, phase: v })}>
                  <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="acl">ACL</SelectItem>
                    <SelectItem value="signature">签名匹配</SelectItem>
                    <SelectItem value="custom">自定义</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>命中动作</Label>
                <Select value={form.action} onValueChange={(v) => setForm({ ...form, action: v })}>
                  <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="intercept">拦截</SelectItem>
                    <SelectItem value="observe">观察</SelectItem>
                    <SelectItem value="allow">放行</SelectItem>
                    <SelectItem value="drop">断连</SelectItem>
                    <SelectItem value="redirect">重定向</SelectItem>
                    <SelectItem value="challenge">挑战</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label>匹配条件</Label>
              <RuleBuilder value={form.pattern} onChange={(v) => setForm({ ...form, pattern: v })} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>优先级</Label>
                <Input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} className="rounded-md" />
                <p className="text-xs text-slate-500">数值越小越先执行</p>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 mt-6">
                <Label className="font-medium">启用</Label>
                <Switch checked={form.enabled} onCheckedChange={(v) => setForm({ ...form, enabled: v })} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" className="rounded-md" onClick={() => setDialogOpen(false)}>取消</Button>
            <Button onClick={handleSave} disabled={saving} className="rounded-md bg-cyan-600 hover:bg-cyan-700">
              {saving ? "保存中..." : editingId ? "更新规则" : "创建规则"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
