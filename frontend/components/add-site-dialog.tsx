"use client";

import { useEffect, useState } from "react";
import { Globe, Loader2, Lock, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";

interface Certificate {
  id: number;
  name: string;
}

interface AddSiteDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

const defaultUpstream = "http://127.0.0.1:8080";

export function AddSiteDialog({ open, onOpenChange, onSuccess }: AddSiteDialogProps) {
  const [host, setHost] = useState("");
  const [bind, setBind] = useState(":80");
  const [tlsEnabled, setTLSEnabled] = useState(false);
  const [certId, setCertId] = useState<number | null>(null);
  const [upstreams, setUpstreams] = useState<string[]>([defaultUpstream]);
  const [saving, setSaving] = useState(false);
  const [certificates, setCertificates] = useState<Certificate[]>([]);

  useEffect(() => {
    if (!open) return;
    api<{ items: Certificate[] }>("/api/v1/certificates")
      .then((data) => setCertificates(data.items || []))
      .catch(() => setCertificates([]));
  }, [open]);

  function reset() {
    setHost("");
    setBind(":80");
    setTLSEnabled(false);
    setCertId(null);
    setUpstreams([defaultUpstream]);
  }

  function close(nextOpen: boolean) {
    if (!nextOpen) reset();
    onOpenChange(nextOpen);
  }

  function setProtocol(nextTLS: boolean) {
    setTLSEnabled(nextTLS);
    setBind(nextTLS ? ":443" : ":80");
    if (!nextTLS) {
      setCertId(null);
    }
  }

  function updateUpstream(index: number, value: string) {
    setUpstreams((current) => current.map((item, itemIndex) => (itemIndex === index ? value : item)));
  }

  function removeUpstream(index: number) {
    setUpstreams((current) => current.filter((_, itemIndex) => itemIndex !== index));
  }

  async function handleSubmit() {
    const normalizedHost = host.trim();
    const normalizedBind = bind.trim() || (tlsEnabled ? ":443" : ":80");
    const normalizedUpstreams = upstreams.map((item) => item.trim()).filter(Boolean);

    if (!normalizedHost) {
      toast.error("请输入站点 Host");
      return;
    }
    if (normalizedUpstreams.length === 0) {
      toast.error("请至少填写一个上游地址");
      return;
    }
    if (tlsEnabled && !certId) {
      toast.error("启用 HTTPS 时请选择证书");
      return;
    }

    setSaving(true);
    try {
      await api("/api/v1/sites", {
        method: "POST",
        body: JSON.stringify({
          host: normalizedHost,
          bind: normalizedBind,
          network: "tcp",
          tls_enabled: tlsEnabled,
          cert_id: tlsEnabled ? certId : null,
          upstream_urls: JSON.stringify(normalizedUpstreams),
          enabled: true,
          maintenance_enabled: false,
        }),
      });
      toast.success("站点已创建");
      close(false);
      onSuccess();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "创建失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-h-[88vh] max-w-2xl overflow-y-auto rounded-[28px] p-0">
        <DialogHeader className="border-b border-white/10 bg-[linear-gradient(135deg,rgba(10,19,34,0.96),rgba(11,27,48,0.9)_55%,rgba(10,69,88,0.5))] px-6 py-6 text-left text-white">
          <DialogTitle className="text-2xl font-semibold tracking-tight">新增站点</DialogTitle>
          <DialogDescription className="mt-2 text-sm leading-6 text-slate-300/90">
            仅填写当前站点模型真实存在的字段：Host、监听地址、TLS 证书与上游地址。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 px-6 py-6">
          <div className="grid gap-4 md:grid-cols-[1.2fr_0.8fr]">
            <label className="space-y-2">
              <span className="text-sm font-medium text-slate-900">Host</span>
              <div className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-3">
                <Globe className="h-4 w-4 text-slate-400" />
                <Input
                  value={host}
                  onChange={(event) => setHost(event.target.value)}
                  placeholder="example.com"
                  className="border-0 bg-transparent px-0 shadow-none focus-visible:ring-0"
                />
              </div>
            </label>

            <label className="space-y-2">
              <span className="text-sm font-medium text-slate-900">监听地址</span>
              <Input
                value={bind}
                onChange={(event) => setBind(event.target.value)}
                placeholder=":80"
                className="rounded-2xl border-slate-200 bg-slate-50"
              />
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-[0.9fr_1.1fr]">
            <div className="space-y-2">
              <span className="text-sm font-medium text-slate-900">接入协议</span>
              <div className="grid grid-cols-2 gap-2 rounded-[20px] border border-slate-200 bg-slate-50 p-2">
                <button
                  type="button"
                  onClick={() => setProtocol(false)}
                  className={tlsEnabled ? "rounded-2xl px-4 py-3 text-sm font-medium text-slate-600" : "rounded-2xl bg-white px-4 py-3 text-sm font-medium text-slate-950 shadow-sm"}
                >
                  HTTP
                </button>
                <button
                  type="button"
                  onClick={() => setProtocol(true)}
                  className={tlsEnabled ? "rounded-2xl bg-white px-4 py-3 text-sm font-medium text-slate-950 shadow-sm" : "rounded-2xl px-4 py-3 text-sm font-medium text-slate-600"}
                >
                  HTTPS
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-sm font-medium text-slate-900">TLS 证书</span>
              {tlsEnabled ? (
                <div className="rounded-[20px] border border-slate-200 bg-slate-50 p-3">
                  <div className="mb-2 flex items-center gap-2 text-xs text-slate-500">
                    <Lock className="h-3.5 w-3.5" /> 启用 HTTPS 时必须绑定证书
                  </div>
                  <Select value={certId ? String(certId) : ""} onValueChange={(value) => setCertId(value ? Number(value) : null)}>
                    <SelectTrigger className="rounded-2xl border-slate-200 bg-white">
                      <SelectValue placeholder={certificates.length ? "选择证书" : "当前没有可用证书"} />
                    </SelectTrigger>
                    <SelectContent>
                      {certificates.map((certificate) => (
                        <SelectItem key={certificate.id} value={String(certificate.id)}>
                          {certificate.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ) : (
                <div className="flex min-h-[82px] items-center rounded-[20px] border border-dashed border-slate-300 bg-slate-50 px-4 text-sm text-slate-500">
                  当前为 HTTP 接入，无需证书。
                </div>
              )}
            </div>
          </div>

          <div className="space-y-3 rounded-[24px] border border-slate-200 bg-slate-50/80 p-5">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">上游地址</h3>
                <p className="mt-1 text-xs leading-5 text-slate-500">按 `upstream_urls` 数组写入，至少保留一个 HTTP/HTTPS 地址。</p>
              </div>
              <Button type="button" variant="outline" size="sm" className="rounded-xl" onClick={() => setUpstreams((current) => [...current, defaultUpstream])}>
                <Plus className="mr-1.5 h-3.5 w-3.5" /> 添加上游
              </Button>
            </div>

            <div className="space-y-3">
              {upstreams.map((upstream, index) => (
                <div key={`${index}-${upstream}`} className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-white p-2">
                  <Input
                    value={upstream}
                    onChange={(event) => updateUpstream(index, event.target.value)}
                    placeholder="http://127.0.0.1:8080"
                    className="border-0 bg-transparent font-mono text-sm shadow-none focus-visible:ring-0"
                  />
                  {upstreams.length > 1 ? (
                    <Button type="button" variant="ghost" size="icon-sm" className="rounded-xl text-rose-600 hover:bg-rose-50 hover:text-rose-700" onClick={() => removeUpstream(index)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        </div>

        <DialogFooter className="border-t border-slate-200 bg-white px-6 py-4">
          <Button variant="outline" className="rounded-xl" onClick={() => close(false)}>
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={saving} className="rounded-xl bg-slate-950 text-white hover:bg-slate-800">
            {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {saving ? "创建中..." : "创建站点"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
