"use client";

import { useEffect, useState } from "react";
import { FileKey2, Plus, Trash2, Eye, Upload, Pencil } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { EmptyState, PageIntro, Surface } from "@/components/console-shell";
import { api, createCertificate, updateCertificate, type Certificate } from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function CertificatesPage() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [detailCert, setDetailCert] = useState<Certificate | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Certificate | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Upload form
  const [formName, setFormName] = useState("");
  const [formCert, setFormCert] = useState("");
  const [formKey, setFormKey] = useState("");
  const [uploading, setUploading] = useState(false);
  const [editingCert, setEditingCert] = useState<Certificate | null>(null);

  function load() {
    setLoading(true);
    api<{ items: Certificate[] }>("/api/v1/certificates")
      .then((data) => setCerts(data.items || []))
      .catch((e) => toast.error(String(e)))
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(); }, []);

  async function handleUpload() {
    if (!formName.trim()) { toast.error("请输入证书名称"); return; }
    if (!formCert.trim()) { toast.error("请输入证书 PEM 内容"); return; }
    if (!formKey.trim()) { toast.error("请输入私钥 PEM 内容"); return; }
    setUploading(true);
    try {
      const payload = { name: formName, cert_pem: formCert, key_pem: formKey };
      if (editingCert) {
        await updateCertificate(editingCert.id, payload);
        toast.success("证书已更新");
      } else {
        await createCertificate(payload);
        toast.success("证书已上传");
      }
      setUploadOpen(false);
      setEditingCert(null);
      setFormName(""); setFormCert(""); setFormKey("");
      load();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setUploading(false);
    }
  }

  function openUpload() {
    setEditingCert(null);
    setFormName(""); setFormCert(""); setFormKey("");
    setUploadOpen(true);
  }

  function openEdit(cert: Certificate) {
    setEditingCert(cert);
    setFormName(cert.name || "");
    setFormCert(cert.cert_pem || "");
    setFormKey(cert.key_pem || "");
    setUploadOpen(true);
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api(`/api/v1/certificates/${deleteTarget.id}/delete`, { method: "POST" });
      toast.success("证书已删除");
      setDeleteTarget(null);
      load();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setDeleting(false);
    }
  }

  function handleFileUpload(field: "cert" | "key", file: File) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (field === "cert") setFormCert(content);
      else setFormKey(content);
    };
    reader.readAsText(file);
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="TLS Certificates"
        title="证书管理"
        description="管理站点 HTTPS 接入所需的 TLS 证书和私钥，支持 PEM 格式上传。"
        actions={
          <Button className="gap-2 rounded-md bg-slate-950 text-white hover:bg-slate-800" onClick={openUpload}>
            <Plus className="h-4 w-4" /> 上传证书
          </Button>
        }
      />

      <Surface title="证书列表" description="当前系统中所有 TLS 证书。">
        {loading ? (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : certs.length === 0 ? (
          <EmptyState title="暂无证书" description="上传第一个证书以启用站点 HTTPS 接入。" />
        ) : (
          <div className="overflow-hidden rounded-lg border border-slate-200">
            <Table>
              <TableHeader>
                <TableRow className="bg-slate-50 text-xs uppercase tracking-wider text-slate-500">
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead>名称</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead>更新时间</TableHead>
                  <TableHead className="w-32 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {certs.map((cert) => (
                  <TableRow key={cert.id} className="hover:bg-slate-50">
                    <TableCell className="font-mono text-xs text-slate-500">{cert.id}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <FileKey2 className="h-4 w-4 text-slate-600" />
                        <span className="font-medium text-slate-900">{cert.name}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-slate-500 whitespace-nowrap">{formatDate(cert.created_at)}</TableCell>
                    <TableCell className="text-xs text-slate-500 whitespace-nowrap">{formatDate(cert.updated_at)}</TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="icon-sm" className="rounded-lg" onClick={() => setDetailCert(cert)}>
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon-sm" className="rounded-lg" onClick={() => openEdit(cert)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon-sm" className="rounded-lg text-rose-600 hover:bg-rose-50 hover:text-rose-700" onClick={() => setDeleteTarget(cert)}>
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

      {/* 上传 Dialog */}
      <Dialog open={uploadOpen} onOpenChange={(open) => { setUploadOpen(open); if (!open) setEditingCert(null); }}>
        <DialogContent className="max-w-lg rounded-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editingCert ? "编辑证书" : "上传证书"}</DialogTitle>
            <DialogDescription>输入证书名称，并粘贴 PEM 格式的证书和私钥内容，或通过文件上传。</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>证书名称</Label>
              <Input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="例如：example.com" className="rounded-lg" />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>证书内容 (PEM)</Label>
                <label className="cursor-pointer text-xs text-slate-600 hover:text-slate-800">
                  <input type="file" accept=".pem,.crt,.cer" className="hidden" onChange={(e) => e.target.files?.[0] && handleFileUpload("cert", e.target.files[0])} />
                  <Upload className="inline h-3 w-3 mr-1" />选择文件
                </label>
              </div>
              <Textarea value={formCert} onChange={(e) => setFormCert(e.target.value)} rows={6} className="rounded-lg font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>私钥内容 (PEM)</Label>
                <label className="cursor-pointer text-xs text-slate-600 hover:text-slate-800">
                  <input type="file" accept=".pem,.key" className="hidden" onChange={(e) => e.target.files?.[0] && handleFileUpload("key", e.target.files[0])} />
                  <Upload className="inline h-3 w-3 mr-1" />选择文件
                </label>
              </div>
              <Textarea value={formKey} onChange={(e) => setFormKey(e.target.value)} rows={6} className="rounded-lg font-mono text-xs" placeholder="-----BEGIN PRIVATE KEY-----" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)}>取消</Button>
            <Button onClick={handleUpload} disabled={uploading}>{uploading ? "保存中..." : editingCert ? "保存" : "上传"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 详情 Dialog */}
      <Dialog open={!!detailCert} onOpenChange={(open) => !open && setDetailCert(null)}>
        <DialogContent className="max-w-xl rounded-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>证书详情 — {detailCert?.name}</DialogTitle>
            <DialogDescription>查看证书完整内容。</DialogDescription>
          </DialogHeader>
          {detailCert && (
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">名称</div>
                  <div className="text-sm font-medium text-slate-900">{detailCert.name}</div>
                </div>
                <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">创建时间</div>
                  <div className="text-sm font-medium text-slate-900">{formatDate(detailCert.created_at)}</div>
                </div>
              </div>
              <div className="space-y-2">
                <Label>证书 PEM</Label>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 max-h-[200px] overflow-y-auto">
                  <pre className="whitespace-pre-wrap font-mono text-xs text-slate-600">{detailCert.cert_pem}</pre>
                </div>
              </div>
              <div className="space-y-2">
                <Label>私钥 PEM</Label>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 max-h-[120px] overflow-y-auto">
                  <pre className="whitespace-pre-wrap font-mono text-xs text-slate-600">{detailCert.key_pem?.slice(0, 80)}...</pre>
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setDetailCert(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除确认 */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>确认删除证书</DialogTitle>
            <DialogDescription>删除后使用此证书的站点将无法建立 HTTPS 连接。</DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-900">
            目标证书：{deleteTarget?.name || "-"}
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
