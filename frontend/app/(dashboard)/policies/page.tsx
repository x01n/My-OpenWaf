"use client";

import { useEffect, useState, useCallback } from "react";
import { BookOpen, ExternalLink, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { EmptyState, PageIntro, Surface } from "@/components/console-shell";
import { api, type Policy, type Site } from "@/lib/api";
import { formatDate } from "@/lib/utils";

interface PolicyWithMeta extends Policy {
  description?: string;
  rules_count?: number;
}

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyWithMeta[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [isNew, setIsNew] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editId, setEditId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<PolicyWithMeta | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      api<{ items: PolicyWithMeta[] }>("/api/v1/policies"),
      api<{ items: Site[]; total: number }>("/api/v1/sites?page_size=1000"),
    ])
      .then(([policyData, siteData]) => {
        setPolicies(policyData.items || []);
        setSites(siteData.items || []);
      })
      .catch((e) => toast.error(String(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  function sitesForPolicy(policyId: number): Site[] {
    return sites.filter((s) => s.policy_id === policyId);
  }

  function openNew() {
    setIsNew(true);
    setEditName("");
    setEditDesc("");
    setEditId(null);
    setDialogOpen(true);
  }

  function openEdit(p: PolicyWithMeta) {
    setIsNew(false);
    setEditName(p.name);
    setEditDesc(p.description || "");
    setEditId(p.id);
    setDialogOpen(true);
  }

  async function handleSave() {
    if (!editName.trim()) { toast.error("请输入策略名称"); return; }
    setSaving(true);
    try {
      if (isNew) {
        await api("/api/v1/policies", { method: "POST", body: JSON.stringify({ name: editName, description: editDesc }) });
        toast.success("策略已创建");
      } else {
        await api(`/api/v1/policies/${editId}/update`, { method: "POST", body: JSON.stringify({ name: editName, description: editDesc }) });
        toast.success("策略已更新");
      }
      setDialogOpen(false);
      load();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api(`/api/v1/policies/${deleteTarget.id}/delete`, { method: "POST" });
      toast.success("策略已删除");
      setDeleteTarget(null);
      load();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Security Policies"
        title="策略管理"
        description="策略是规则的容器，一个站点绑定一个策略。在此管理策略及其规则分组。"
        actions={
          <Button className="gap-2 rounded-md bg-teal-500 text-white hover:bg-teal-600" onClick={openNew}>
            <Plus className="h-4 w-4" /> 创建策略
          </Button>
        }
      />

      <Surface title="策略列表" description="所有安全策略、关联规则数量和绑定站点。">
        {loading ? (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : policies.length === 0 ? (
          <EmptyState title="暂无策略" description="创建第一个策略后，可以在站点配置中将其关联。" />
        ) : (
          <div className="overflow-hidden rounded-lg border border-slate-200">
            <Table>
              <TableHeader>
                <TableRow className="bg-slate-50 text-xs uppercase tracking-wider text-slate-500">
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead>名称</TableHead>
                  <TableHead>描述</TableHead>
                  <TableHead className="w-24">规则数</TableHead>
                  <TableHead>关联站点</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead className="w-40 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p) => {
                  const linkedSites = sitesForPolicy(p.id);
                  return (
                    <TableRow key={p.id} className="hover:bg-slate-50">
                      <TableCell className="font-mono text-xs text-slate-500">{p.id}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <BookOpen className="h-4 w-4 text-slate-600" />
                          <span className="font-medium text-slate-900">{p.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-sm text-slate-500">{p.description || "-"}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="rounded-md font-mono">
                          {p.rules_count ?? 0}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {linkedSites.length === 0 ? (
                          <span className="text-xs text-slate-400">未绑定</span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {linkedSites.map((s) => (
                              <Badge key={s.id} variant="outline" className="rounded-md text-xs">
                                {s.host}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-slate-500 whitespace-nowrap">{formatDate(p.created_at)}</TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="outline" size="sm" className="rounded-md gap-1 text-xs" asChild>
                            <Link href={`/rules/?policy_id=${p.id}`}>
                              <ExternalLink className="h-3.5 w-3.5" /> 管理规则
                            </Link>
                          </Button>
                          <Button variant="ghost" size="icon-sm" className="rounded-md" onClick={() => openEdit(p)}>
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button variant="ghost" size="icon-sm" className="rounded-md text-rose-600 hover:bg-rose-50 hover:text-rose-700" onClick={() => setDeleteTarget(p)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </Surface>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>{isNew ? "创建策略" : "编辑策略"}</DialogTitle>
            <DialogDescription>{isNew ? "创建新的安全策略以组织规则集。" : "修改策略名称和描述。"}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>策略名称</Label>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} placeholder="例如：核心应用默认策略" className="rounded-md" />
            </div>
            <div className="space-y-2">
              <Label>描述</Label>
              <Textarea value={editDesc} onChange={(e) => setEditDesc(e.target.value)} placeholder="策略用途说明（可选）" rows={3} className="rounded-md" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>取消</Button>
            <Button onClick={handleSave} disabled={saving}>{saving ? "保存中..." : isNew ? "创建" : "保存"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>确认删除策略</DialogTitle>
            <DialogDescription>删除后关联此策略的站点将失去规则绑定。</DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-900">
            目标策略：{deleteTarget?.name || "-"}
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
