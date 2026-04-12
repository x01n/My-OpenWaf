"use client";

import { useEffect, useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Plus, Trash2, Copy } from "lucide-react";

interface APIKey {
  id: number;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export default function APIKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [newToken, setNewToken] = useState("");

  const load = useCallback(async () => {
    const data = await api<{ items: APIKey[] }>("/api/v1/api-keys");
    setKeys(data.items || []);
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleCreate() {
    try {
      const res = await api<{ token: string }>("/api/v1/api-keys", {
        method: "POST",
        body: JSON.stringify({ name: name || "unnamed" }),
      });
      setNewToken(res.token);
      toast.success("创建成功，请立即保存 Token");
      load();
    } catch {
      toast.error("创建失败");
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("确认删除？")) return;
    await api(`/api/v1/api-keys/${id}`, { method: "DELETE" });
    toast.success("已删除");
    load();
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">API 密钥</h1>
          <p className="text-sm text-muted-foreground">用于自动化或机器调用的 Bearer Token。人机登录使用密码。</p>
        </div>
        <Button size="sm" onClick={() => { setOpen(true); setNewToken(""); setName(""); }}>
          <Plus className="mr-1 h-4 w-4" /> 新增
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>名称</TableHead>
                <TableHead>创建时间</TableHead>
                <TableHead>最近使用</TableHead>
                <TableHead className="w-16">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((k) => (
                <TableRow key={k.id}>
                  <TableCell>{k.id}</TableCell>
                  <TableCell>{k.name}</TableCell>
                  <TableCell className="text-xs">{k.created_at}</TableCell>
                  <TableCell className="text-xs">{k.last_used_at ?? "—"}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" onClick={() => handleDelete(k.id)}>
                      <Trash2 className="h-3.5 w-3.5 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新增 API 密钥</DialogTitle>
          </DialogHeader>
          {!newToken ? (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label>名称</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="用途备注" />
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <p className="text-sm font-medium text-destructive">请立即复制此 Token，关闭后将无法再查看。</p>
              <div className="flex gap-2">
                <Input readOnly value={newToken} className="font-mono text-xs" />
                <Button size="icon" variant="outline" onClick={() => { navigator.clipboard.writeText(newToken); toast.success("已复制"); }}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
          <DialogFooter>
            {!newToken ? (
              <Button onClick={handleCreate}>创建</Button>
            ) : (
              <Button onClick={() => setOpen(false)}>完成</Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
