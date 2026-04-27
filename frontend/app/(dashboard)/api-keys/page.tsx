"use client";

import { useEffect, useState } from "react";
import { Copy, KeyRound, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { EmptyState, InlineMeta, PageIntro, Surface } from "@/components/console-shell";
import { createAPIKey, getAPIKeys, removeAPIKey, type APIKey } from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function APIKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<APIKey | null>(null);
  const [deleting, setDeleting] = useState(false);

  function load() {
    setLoading(true);
    getAPIKeys()
      .then((data) => setKeys(data.items || []))
      .catch((error) => toast.error(String(error)))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
  }, []);

  async function handleCreate() {
    try {
      const response = await createAPIKey(newKeyName || "unnamed");
      setCreatedToken(response.token || null);
      setNewKeyName("");
      toast.success("密钥已创建，请立即复制明文 Token。");
      load();
    } catch (error) {
      toast.error(String(error));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    setBusyId(deleteTarget.id);
    try {
      await removeAPIKey(deleteTarget.id);
      toast.success("API 密钥已删除");
      setDeleteTarget(null);
      load();
    } catch (error) {
      toast.error(String(error));
    } finally {
      setDeleting(false);
      setBusyId(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Automation Access"
        title="API 密钥"
        description="为自动化任务、CI/CD 或运维脚本生成 Bearer Token。后端只会在创建成功时返回一次明文 Token。"
        actions={
          <Button className="rounded-2xl bg-white text-slate-950 hover:bg-slate-100" onClick={() => { setDialogOpen(true); setCreatedToken(null); setNewKeyName(""); }}>
            <Plus className="mr-2 h-4 w-4" /> 创建密钥
          </Button>
        }
      />

      <Surface title="密钥清单" description="当前账户下所有 API 密钥的名称、创建时间与最近使用情况。">
        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : keys.length === 0 ? (
          <EmptyState title="还没有 API 密钥" description="创建后可用于自动化访问管理 API。建议按用途拆分，便于审计与吊销。" />
        ) : (
          <div className="grid gap-4 xl:grid-cols-2">
            {keys.map((item) => (
              <Surface key={item.id} className="overflow-hidden">
                <div className="space-y-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyan-50 text-cyan-700">
                        <KeyRound className="h-5 w-5" />
                      </div>
                      <div>
                        <h2 className="text-lg font-semibold text-slate-950">{item.name}</h2>
                        <p className="mt-1 text-sm text-slate-500">ID #{item.id}</p>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="rounded-xl text-rose-600 hover:bg-rose-50 hover:text-rose-700"
                      disabled={busyId === item.id}
                      onClick={() => setDeleteTarget(item)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="grid gap-3 md:grid-cols-2">
                    <InlineMeta label="创建时间" value={formatDate(item.created_at)} />
                    <InlineMeta label="最近使用" value={item.last_used_at ? formatDate(item.last_used_at) : "从未使用"} />
                  </div>
                </div>
              </Surface>
            ))}
          </div>
        )}
      </Surface>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg rounded-[28px]">
          <DialogHeader>
            <DialogTitle>{createdToken ? "令牌已创建" : "创建 API 密钥"}</DialogTitle>
            <DialogDescription>{createdToken ? "请立即复制返回的明文 Token。" : "创建后仅会返回一次明文 Token。"}</DialogDescription>
          </DialogHeader>
          {createdToken ? (
            <div className="space-y-4">
              <p className="text-sm leading-6 text-slate-500">请立即复制此 Token，关闭后将无法再次查看明文。</p>
              <div className="flex gap-2 rounded-2xl border border-slate-200 bg-slate-50 p-3">
                <code className="flex-1 break-all text-xs text-slate-700">{createdToken}</code>
                <Button
                  variant="outline"
                  size="icon-sm"
                  className="rounded-xl"
                  onClick={() => {
                    navigator.clipboard.writeText(createdToken);
                    toast.success("已复制到剪贴板");
                  }}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <Label htmlFor="api-key-name">密钥名称</Label>
              <Input
                id="api-key-name"
                value={newKeyName}
                onChange={(event) => setNewKeyName(event.target.value)}
                placeholder="例如：CI Deploy / Terraform / Alert Sync"
                className="rounded-xl"
              />
            </div>
          )}
          <DialogFooter>
            {createdToken ? (
              <Button onClick={() => setDialogOpen(false)}>完成</Button>
            ) : (
              <Button onClick={handleCreate}>创建</Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="max-w-md rounded-[28px]">
          <DialogHeader>
            <DialogTitle>确认删除 API 密钥</DialogTitle>
            <DialogDescription>删除后该密钥将立即失效，相关自动化任务需要改用新的 Token。</DialogDescription>
          </DialogHeader>
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-900">
            目标密钥：{deleteTarget?.name || "-"}
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
