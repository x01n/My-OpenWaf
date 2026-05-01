"use client";

import { useCallback, useEffect, useState } from "react";
import { Search } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Pagination } from "@/components/pagination";
import { MetricCard, MetricGrid, PageIntro, Surface, EmptyState } from "@/components/console-shell";
import { getCVERules, updateCVERule, toggleCVERule, type CVERule, type CVERuleQuery } from "@/lib/api";
import { getCVERuleStats, batchToggleCVERules, type CVERuleStats } from "@/lib/rules-api";

const PAGE_SIZE = 20;

const severityColor: Record<string, string> = {
  critical: "bg-rose-100 text-rose-700 border-rose-200",
  high: "bg-orange-100 text-orange-700 border-orange-200",
  medium: "bg-amber-100 text-amber-700 border-amber-200",
  low: "bg-sky-100 text-sky-700 border-sky-200",
};

export default function CVERuleManagementPage() {
  const [items, setItems] = useState<CVERule[]>([]);
  const [stats, setStats] = useState<CVERuleStats | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [category, setCategory] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [enabled, setEnabled] = useState("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const [editRule, setEditRule] = useState<CVERule | null>(null);
  const [editForm, setEditForm] = useState({ enabled: true, action: "intercept", severity: "medium" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: CVERuleQuery = { page, page_size: PAGE_SIZE };
      if (category !== "all") params.category = category;
      if (severity !== "all") params.severity = severity;
      if (enabled !== "all") params.enabled = enabled;
      const res = await getCVERules(params);
      let list = res.items ?? [];
      if (search) {
        const q = search.toLowerCase();
        list = list.filter((r) => r.cve_id.toLowerCase().includes(q) || r.description?.toLowerCase().includes(q));
      }
      setItems(list);
      setTotal(res.total ?? 0);
    } catch (e) {
      toast.error(String(e));
    } finally {
      setLoading(false);
    }
  }, [page, category, severity, enabled, search]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { getCVERuleStats().then(setStats).catch(() => {}); }, []);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  function toggleSelect(id: number) {
    setSelected((prev) => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });
  }

  function selectAll() {
    if (selected.size === items.length) setSelected(new Set());
    else setSelected(new Set(items.map((r) => r.id)));
  }

  async function batchToggle(en: boolean) {
    if (selected.size === 0) return;
    try {
      await batchToggleCVERules([...selected], en);
      toast.success(`已${en ? "启用" : "禁用"} ${selected.size} 条规则`);
      setSelected(new Set());
      load();
    } catch (e) { toast.error(String(e)); }
  }

  async function handleToggle(id: number) {
    try { await toggleCVERule(id); load(); } catch (e) { toast.error(String(e)); }
  }

  async function saveEdit() {
    if (!editRule) return;
    try {
      await updateCVERule(editRule.id, editForm);
      toast.success("规则已更新");
      setEditRule(null);
      load();
    } catch (e) { toast.error(String(e)); }
  }

  return (
    <div className="space-y-6">
      <PageIntro eyebrow="CVE Rule Management" title="CVE 规则管理" description="筛选、搜索、批量操作和编辑 CVE 漏洞检测规则。支持按分类、严重等级和启用状态过滤。" />

      {stats && (
        <MetricGrid>
          <MetricCard label="规则总数" value={stats.total} />
          <MetricCard label="已启用" value={stats.enabled} tone="success" />
          <MetricCard label="已禁用" value={stats.disabled} />
          <MetricCard label="严重 (Critical)" value={stats.by_severity?.critical ?? 0} tone="danger" />
        </MetricGrid>
      )}

      <Surface title="规则列表" description="管理所有 CVE 检测规则。" action={
        selected.size > 0 && (
          <div className="flex gap-2">
            <span className="text-sm text-slate-500">已选 {selected.size} 条</span>
            <Button size="sm" variant="outline" className="rounded-xl" onClick={() => batchToggle(true)}>批量启用</Button>
            <Button size="sm" variant="outline" className="rounded-xl" onClick={() => batchToggle(false)}>批量禁用</Button>
          </div>
        )
      }>
        <div className="mb-4 flex flex-wrap gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <Input placeholder="搜索 CVE 编号或描述..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} className="rounded-xl pl-9" />
          </div>
          <Select value={category} onValueChange={(v) => { setCategory(v); setPage(1); }}>
            <SelectTrigger className="w-[140px] rounded-xl"><SelectValue placeholder="分类" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部分类</SelectItem>
              <SelectItem value="general">general</SelectItem>
              <SelectItem value="java">java</SelectItem>
              <SelectItem value="php">php</SelectItem>
              <SelectItem value="node">node</SelectItem>
            </SelectContent>
          </Select>
          <Select value={severity} onValueChange={(v) => { setSeverity(v); setPage(1); }}>
            <SelectTrigger className="w-[140px] rounded-xl"><SelectValue placeholder="严重等级" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部等级</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={enabled} onValueChange={(v) => { setEnabled(v); setPage(1); }}>
            <SelectTrigger className="w-[120px] rounded-xl"><SelectValue placeholder="状态" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部状态</SelectItem>
              <SelectItem value="true">启用</SelectItem>
              <SelectItem value="false">禁用</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : items.length === 0 ? (
          <EmptyState title="暂无匹配规则" description="当前筛选条件下没有 CVE 规则。" />
        ) : (
          <div className="space-y-4">
            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10"><Checkbox checked={selected.size === items.length && items.length > 0} onCheckedChange={selectAll} /></TableHead>
                    <TableHead>CVE 编号</TableHead>
                    <TableHead>分类</TableHead>
                    <TableHead>严重等级</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead>启用</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell><Checkbox checked={selected.has(rule.id)} onCheckedChange={() => toggleSelect(rule.id)} /></TableCell>
                      <TableCell>
                        <div className="font-medium text-slate-900">{rule.cve_id}</div>
                        <div className="text-xs text-slate-500 max-w-[300px] truncate">{rule.description || "无描述"}</div>
                      </TableCell>
                      <TableCell><Badge variant="outline" className="rounded-lg">{rule.category}</Badge></TableCell>
                      <TableCell><Badge className={`rounded-lg border ${severityColor[rule.severity] ?? "bg-slate-100 text-slate-600"}`}>{rule.severity}</Badge></TableCell>
                      <TableCell className="text-sm">{rule.action}</TableCell>
                      <TableCell><Switch checked={rule.enabled} onCheckedChange={() => handleToggle(rule.id)} /></TableCell>
                      <TableCell className="text-right">
                        <Button size="sm" variant="ghost" className="rounded-xl" onClick={() => { setEditRule(rule); setEditForm({ enabled: rule.enabled, action: rule.action, severity: rule.severity }); }}>编辑</Button>
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

      <Dialog open={!!editRule} onOpenChange={(o) => { if (!o) setEditRule(null); }}>
        <DialogContent className="max-w-md rounded-[28px]">
          <DialogHeader>
            <DialogTitle>编辑 CVE 规则</DialogTitle>
            <DialogDescription>{editRule?.cve_id} — {editRule?.description}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
              <span className="text-sm font-medium">启用状态</span>
              <Switch checked={editForm.enabled} onCheckedChange={(v) => setEditForm({ ...editForm, enabled: v })} />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">动作</label>
              <Select value={editForm.action} onValueChange={(v) => setEditForm({ ...editForm, action: v })}>
                <SelectTrigger className="rounded-xl"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="intercept">拦截</SelectItem>
                  <SelectItem value="observe">观察</SelectItem>
                  <SelectItem value="drop">断连</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">严重等级</label>
              <Select value={editForm.severity} onValueChange={(v) => setEditForm({ ...editForm, severity: v })}>
                <SelectTrigger className="rounded-xl"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditRule(null)}>取消</Button>
            <Button onClick={saveEdit}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}