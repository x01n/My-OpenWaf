"use client"

import { useEffect, useState } from "react"
import {
  FileKey2,
  Globe,
  Plus,
  RefreshCcw,
  Trash2,
  Eye,
  Upload,
  Pencil,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState, PageIntro, Surface } from "@/components/console-shell"
import { Badge } from "@/components/ui/badge"
import {
  api,
  createCertificate,
  getACMECertStatus,
  updateCertificate,
  type Certificate,
} from "@/lib/api"
import { formatDate } from "@/lib/utils"

export default function CertificatesPage() {
  const [certs, setCerts] = useState<Certificate[]>([])
  const [loading, setLoading] = useState(true)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [detailCert, setDetailCert] = useState<Certificate | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Certificate | null>(null)
  const [deleting, setDeleting] = useState(false)

  // Upload form
  const [formName, setFormName] = useState("")
  const [formCert, setFormCert] = useState("")
  const [formKey, setFormKey] = useState("")
  const [uploading, setUploading] = useState(false)
  const [editingCert, setEditingCert] = useState<Certificate | null>(null)

  // ACME
  const [acmeOpen, setAcmeOpen] = useState(false)
  const [acmeDomain, setAcmeDomain] = useState("")
  const [acmeEmail, setAcmeEmail] = useState("")
  const [acmeName, setAcmeName] = useState("")
  const [acmeApplying, setAcmeApplying] = useState(false)
  const [renewingId, setRenewingId] = useState<number | null>(null)
  const [acmeStatus, setAcmeStatus] = useState<
    Record<
      number,
      {
        domain: string
        expires_at?: string
        auto_renew: boolean
        error?: string
        renew_error?: string
      }
    >
  >({})

  async function loadACMEStatus() {
    try {
      const data = await getACMECertStatus()
      const next: Record<
        number,
        {
          domain: string
          expires_at?: string
          auto_renew: boolean
          error?: string
          renew_error?: string
        }
      > = {}
      for (const item of data.items || []) {
        next[item.id] = item
      }
      setAcmeStatus(next)
    } catch {
      // ignore ACME status load failures so certificate list still works
    }
  }

  function load() {
    setLoading(true)
    api<{ items: Certificate[] }>("/api/v1/certificates")
      .then((data) => setCerts(data.items || []))
      .catch((e) => toast.error(String(e)))
      .finally(() => setLoading(false))
    void loadACMEStatus()
  }

  useEffect(() => {
    load()
  }, [])

  async function handleUpload() {
    if (!formName.trim()) {
      toast.error("请输入证书名称")
      return
    }
    if (!formCert.trim()) {
      toast.error("请输入证书 PEM 内容")
      return
    }
    if (!formKey.trim()) {
      toast.error("请输入私钥 PEM 内容")
      return
    }
    setUploading(true)
    try {
      const payload = { name: formName, cert_pem: formCert, key_pem: formKey }
      if (editingCert) {
        await updateCertificate(editingCert.id, payload)
        toast.success("证书已更新")
      } else {
        await createCertificate(payload)
        toast.success("证书已上传")
      }
      setUploadOpen(false)
      setEditingCert(null)
      setFormName("")
      setFormCert("")
      setFormKey("")
      load()
    } catch (e) {
      toast.error(String(e))
    } finally {
      setUploading(false)
    }
  }

  function openUpload() {
    setEditingCert(null)
    setFormName("")
    setFormCert("")
    setFormKey("")
    setUploadOpen(true)
  }

  async function handleACMEApply() {
    if (!acmeDomain.trim()) {
      toast.error("请输入域名")
      return
    }
    setAcmeApplying(true)
    try {
      await api("/api/v1/certificates/acme/apply", {
        method: "POST",
        body: JSON.stringify({
          domain: acmeDomain,
          name: acmeName || acmeDomain,
        }),
      })
      toast.success(`证书申请成功：${acmeDomain}`)
      setAcmeOpen(false)
      setAcmeDomain("")
      setAcmeEmail("")
      setAcmeName("")
      load()
    } catch (e) {
      toast.error(String(e))
    } finally {
      setAcmeApplying(false)
    }
  }

  async function handleRenew(certId: number) {
    setRenewingId(certId)
    try {
      await api(`/api/v1/certificates/acme/${certId}/renew`, { method: "POST" })
      toast.success("证书续期成功")
      load()
    } catch (e) {
      toast.error(String(e))
    } finally {
      setRenewingId(null)
    }
  }

  function openEdit(cert: Certificate) {
    setEditingCert(cert)
    setFormName(cert.name || "")
    setFormCert(cert.cert_pem || "")
    setFormKey(cert.key_pem || "")
    setUploadOpen(true)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await api(`/api/v1/certificates/${deleteTarget.id}/delete`, {
        method: "POST",
      })
      toast.success("证书已删除")
      setDeleteTarget(null)
      load()
    } catch (e) {
      toast.error(String(e))
    } finally {
      setDeleting(false)
    }
  }

  function handleFileUpload(field: "cert" | "key", file: File) {
    const reader = new FileReader()
    reader.onload = (e) => {
      const content = e.target?.result as string
      if (field === "cert") setFormCert(content)
      else setFormKey(content)
    }
    reader.readAsText(file)
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="TLS Certificates"
        title="证书管理"
        description="管理站点 HTTPS 接入所需的 TLS 证书和私钥，支持 PEM 格式上传。"
        actions={
          <div className="flex gap-2">
            <Button
              className="gap-2 rounded-md bg-indigo-500 text-white hover:bg-indigo-600"
              onClick={() => setAcmeOpen(true)}
            >
              <Globe className="h-4 w-4" /> ACME 申请
            </Button>
            <Button
              className="gap-2 rounded-md bg-teal-500 text-white hover:bg-teal-600"
              onClick={openUpload}
            >
              <Plus className="h-4 w-4" /> 上传证书
            </Button>
          </div>
        }
      />

      <Surface title="证书列表" description="当前系统中所有 TLS 证书。">
        {loading ? (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">
            加载中...
          </div>
        ) : certs.length === 0 ? (
          <EmptyState
            title="暂无证书"
            description="上传第一个证书以启用站点 HTTPS 接入。"
          />
        ) : (
          <div className="overflow-hidden rounded-lg border border-slate-200">
            <Table>
              <TableHeader>
                <TableRow className="bg-slate-50 text-xs tracking-wider text-slate-500 uppercase">
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead>名称</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>过期时间</TableHead>
                  <TableHead>更新时间</TableHead>
                  <TableHead className="w-40 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {certs.map((cert) => (
                  <TableRow key={cert.id} className="hover:bg-slate-50">
                    <TableCell className="font-mono text-xs text-slate-500">
                      {cert.id}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <FileKey2 className="h-4 w-4 text-slate-600" />
                        <span className="font-medium text-slate-900">
                          {cert.name}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          cert.source === "acme"
                            ? "default"
                            : cert.source === "self_signed"
                              ? "secondary"
                              : "outline"
                        }
                      >
                        {cert.source === "acme"
                          ? "ACME"
                          : cert.source === "self_signed"
                            ? "自签"
                            : "手动"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs whitespace-nowrap text-slate-500">
                      {acmeStatus[cert.id]?.expires_at
                        ? formatDate(acmeStatus[cert.id].expires_at!)
                        : cert.expires_at
                          ? formatDate(cert.expires_at)
                          : "-"}
                    </TableCell>
                    <TableCell className="text-xs whitespace-nowrap text-slate-500">
                      {formatDate(cert.updated_at)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-lg"
                          onClick={() => setDetailCert(cert)}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-lg"
                          onClick={() => openEdit(cert)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        {cert.source === "acme" && (
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            className="rounded-lg text-indigo-600 hover:bg-indigo-50"
                            disabled={renewingId === cert.id}
                            onClick={() => handleRenew(cert.id)}
                          >
                            <RefreshCcw
                              className={`h-4 w-4 ${renewingId === cert.id ? "animate-spin" : ""}`}
                            />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-lg text-rose-600 hover:bg-rose-50 hover:text-rose-700"
                          onClick={() => setDeleteTarget(cert)}
                        >
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
      <Dialog
        open={uploadOpen}
        onOpenChange={(open) => {
          setUploadOpen(open)
          if (!open) setEditingCert(null)
        }}
      >
        <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>{editingCert ? "编辑证书" : "上传证书"}</DialogTitle>
            <DialogDescription>
              输入证书名称，并粘贴 PEM 格式的证书和私钥内容，或通过文件上传。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>证书名称</Label>
              <Input
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="例如：example.com"
                className="rounded-lg"
              />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>证书内容 (PEM)</Label>
                <label className="cursor-pointer text-xs text-slate-600 hover:text-slate-800">
                  <input
                    type="file"
                    accept=".pem,.crt,.cer"
                    className="hidden"
                    onChange={(e) =>
                      e.target.files?.[0] &&
                      handleFileUpload("cert", e.target.files[0])
                    }
                  />
                  <Upload className="mr-1 inline h-3 w-3" />
                  选择文件
                </label>
              </div>
              <Textarea
                value={formCert}
                onChange={(e) => setFormCert(e.target.value)}
                rows={6}
                className="rounded-lg font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>私钥内容 (PEM)</Label>
                <label className="cursor-pointer text-xs text-slate-600 hover:text-slate-800">
                  <input
                    type="file"
                    accept=".pem,.key"
                    className="hidden"
                    onChange={(e) =>
                      e.target.files?.[0] &&
                      handleFileUpload("key", e.target.files[0])
                    }
                  />
                  <Upload className="mr-1 inline h-3 w-3" />
                  选择文件
                </label>
              </div>
              <Textarea
                value={formKey}
                onChange={(e) => setFormKey(e.target.value)}
                rows={6}
                className="rounded-lg font-mono text-xs"
                placeholder="-----BEGIN PRIVATE KEY-----"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)}>
              取消
            </Button>
            <Button onClick={handleUpload} disabled={uploading}>
              {uploading ? "保存中..." : editingCert ? "保存" : "上传"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 详情 Dialog */}
      <Dialog
        open={!!detailCert}
        onOpenChange={(open) => !open && setDetailCert(null)}
      >
        <DialogContent className="max-h-[85vh] max-w-xl overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>证书详情 — {detailCert?.name}</DialogTitle>
            <DialogDescription>查看证书完整内容。</DialogDescription>
          </DialogHeader>
          {detailCert && (
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                    名称
                  </div>
                  <div className="text-sm font-medium text-slate-900">
                    {detailCert.name}
                  </div>
                </div>
                <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                    来源
                  </div>
                  <div className="text-sm font-medium text-slate-900">
                    <Badge
                      variant={
                        detailCert.source === "acme"
                          ? "default"
                          : detailCert.source === "self_signed"
                            ? "secondary"
                            : "outline"
                      }
                    >
                      {detailCert.source === "acme"
                        ? "ACME (Let's Encrypt)"
                        : detailCert.source === "self_signed"
                          ? "自签证书"
                          : "手动上传"}
                    </Badge>
                  </div>
                </div>
                <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                    创建时间
                  </div>
                  <div className="text-sm font-medium text-slate-900">
                    {formatDate(detailCert.created_at)}
                  </div>
                </div>
                <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                    过期时间
                  </div>
                  <div className="text-sm font-medium text-slate-900">
                    {detailCert.expires_at
                      ? formatDate(detailCert.expires_at)
                      : "未知"}
                  </div>
                </div>
                {detailCert.domain && (
                  <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                    <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                      域名
                    </div>
                    <div className="font-mono text-sm font-medium text-slate-900">
                      {detailCert.domain}
                    </div>
                  </div>
                )}
                {detailCert.source === "acme" && (
                  <div className="space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3">
                    <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                      自动续期
                    </div>
                    <div className="text-sm font-medium text-slate-900">
                      <Badge
                        variant={
                          detailCert.auto_renew ? "default" : "secondary"
                        }
                      >
                        {detailCert.auto_renew ? "已启用" : "未启用"}
                      </Badge>
                    </div>
                  </div>
                )}
              </div>
              {detailCert.source === "acme" &&
                (acmeStatus[detailCert.id]?.error ||
                  acmeStatus[detailCert.id]?.renew_error ||
                  detailCert.renew_error) && (
                  <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
                    <div className="mb-1 text-[11px] font-medium tracking-wider text-rose-400 uppercase">
                      ACME 状态
                    </div>
                    {acmeStatus[detailCert.id]?.error ||
                      acmeStatus[detailCert.id]?.renew_error ||
                      detailCert.renew_error}
                  </div>
                )}
              <div className="space-y-2">
                <Label>证书 PEM</Label>
                <div className="max-h-[200px] overflow-y-auto rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <pre className="font-mono text-xs whitespace-pre-wrap text-slate-600">
                    {detailCert.cert_pem}
                  </pre>
                </div>
              </div>
              <div className="space-y-2">
                <Label>私钥 PEM</Label>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
                  私钥已加密存储，不在详情页展示。需要更换私钥时请使用编辑功能重新上传。
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setDetailCert(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ACME 申请 Dialog */}
      <Dialog open={acmeOpen} onOpenChange={setAcmeOpen}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>ACME 证书申请</DialogTitle>
            <DialogDescription>
              通过 Let&apos;s Encrypt 自动申请免费 TLS 证书（HTTP-01
              质询）。确保域名已解析到本服务器并且 80 端口可访问。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>域名</Label>
              <Input
                value={acmeDomain}
                onChange={(e) => setAcmeDomain(e.target.value)}
                placeholder="example.com"
              />
            </div>
            <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
              ACME 账户邮箱由服务端环境变量 MY_OPENWAF_ACME_EMAIL
              配置；申请时会使用服务端已配置邮箱。
            </div>
            <div className="space-y-2">
              <Label>证书名称（可选）</Label>
              <Input
                value={acmeName}
                onChange={(e) => setAcmeName(e.target.value)}
                placeholder="留空则使用域名"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAcmeOpen(false)}>
              取消
            </Button>
            <Button
              onClick={handleACMEApply}
              disabled={acmeApplying}
              className="bg-indigo-500 hover:bg-indigo-600"
            >
              {acmeApplying ? "申请中..." : "申请证书"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除确认 */}
      <Dialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>确认删除证书</DialogTitle>
            <DialogDescription>
              删除后使用此证书的站点将无法建立 HTTPS 连接。
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-900">
            目标证书：{deleteTarget?.name || "-"}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button
              className="bg-rose-600 hover:bg-rose-500"
              disabled={deleting}
              onClick={handleDelete}
            >
              {deleting ? "删除中..." : "删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
