"use client";

import { useEffect, useState } from "react";
import { Globe, Loader2, Lock, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, getCertificates, type Certificate } from "@/lib/api";
import { findInvalidSiteUpstream, serializeSiteUpstreams } from "@/lib/site-upstreams";

interface AddSiteDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

interface ListenerEntry {
  port: string;
  tls: boolean;
}

const defaultUpstream = "http://127.0.0.1:8080";

type AccessMode = "proxy" | "static" | "redirect";

export function AddSiteDialog({ open, onOpenChange, onSuccess }: AddSiteDialogProps) {
  const [host, setHost] = useState("");
  const [listeners, setListeners] = useState<ListenerEntry[]>([{ port: "80", tls: false }]);
  const [certId, setCertId] = useState<number | null>(null);
  const [accessMode, setAccessMode] = useState<AccessMode>("proxy");
  const [upstreams, setUpstreams] = useState<string[]>([defaultUpstream]);
  const [appName, setAppName] = useState("");
  const [saving, setSaving] = useState(false);
  const [certificates, setCertificates] = useState<Certificate[]>([]);

  const hasAnyTLS = listeners.some((l) => l.tls);

  useEffect(() => {
    if (!open) return;
    getCertificates()
      .then((data) => setCertificates(data.items || []))
      .catch(() => setCertificates([]));
  }, [open]);

  function reset() {
    setHost("");
    setListeners([{ port: "80", tls: false }]);
    setCertId(null);
    setAccessMode("proxy");
    setUpstreams([defaultUpstream]);
    setAppName("");
  }

  function close(nextOpen: boolean) {
    if (!nextOpen) reset();
    onOpenChange(nextOpen);
  }

  function addListener() {
    setListeners((prev) => [...prev, { port: "443", tls: true }]);
  }

  function removeListener(index: number) {
    setListeners((prev) => prev.filter((_, i) => i !== index));
  }

  function updateListener(index: number, patch: Partial<ListenerEntry>) {
    setListeners((prev) => prev.map((l, i) => (i === index ? { ...l, ...patch } : l)));
  }

  function updateUpstream(index: number, value: string) {
    setUpstreams((current) => current.map((item, itemIndex) => (itemIndex === index ? value : item)));
  }

  function removeUpstream(index: number) {
    setUpstreams((current) => current.filter((_, itemIndex) => itemIndex !== index));
  }

  async function handleSubmit() {
    const normalizedHost = host.trim();
    const normalizedUpstreams = upstreams.map((item) => item.trim()).filter(Boolean);
    const invalidUpstream = findInvalidSiteUpstream(normalizedUpstreams);

    if (!normalizedHost) {
      toast.error("请输入域名");
      return;
    }
    if (listeners.length === 0) {
      toast.error("请至少添加一个监听端口");
      return;
    }
    for (const l of listeners) {
      const portNum = Number(l.port);
      if (!l.port.trim() || Number.isNaN(portNum) || portNum < 1 || portNum > 65535) {
        toast.error(`端口号无效：${l.port}`);
        return;
      }
    }
    if (accessMode === "proxy") {
      if (normalizedUpstreams.length === 0) {
        toast.error("请至少填写一个上游地址");
        return;
      }
      if (invalidUpstream) {
        toast.error(`上游地址格式无效：${invalidUpstream}`);
        return;
      }
    }
    if (hasAnyTLS && !certId) {
      toast.error("存在 HTTPS 端口时请选择证书");
      return;
    }

    const primaryListener = listeners[0];
    const primaryTLS = primaryListener.tls;
    const primaryBind = `:${primaryListener.port.trim()}`;

    setSaving(true);
    try {
      const siteRes = await api<{ id: number }>("/api/v1/sites", {
        method: "POST",
        body: JSON.stringify({
          host: normalizedHost,
          bind: primaryBind,
          network: "tcp",
          tls_enabled: primaryTLS,
          cert_id: primaryTLS ? certId : null,
          upstream_urls: serializeSiteUpstreams(normalizedUpstreams),
          enabled: true,
          maintenance_enabled: false,
        }),
      });

      if (listeners.length > 1 && siteRes?.id) {
        for (let i = 1; i < listeners.length; i++) {
          const l = listeners[i];
          await api(`/api/v1/sites/${siteRes.id}/listeners`, {
            method: "POST",
            body: JSON.stringify({
              bind: `:${l.port.trim()}`,
              network: "tcp",
              tls_enabled: l.tls,
              cert_id: l.tls ? certId : null,
              enabled: true,
              note: `${l.tls ? "HTTPS" : "HTTP"} :${l.port.trim()}`,
            }),
          });
        }
      }

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
      <DialogContent className="max-h-[88vh] max-w-2xl overflow-y-auto rounded-lg p-0">
        <DialogHeader className="border-b border-slate-200 bg-white px-6 py-5 text-left">
          <DialogTitle className="text-xl font-semibold tracking-tight text-slate-950">添加应用</DialogTitle>
          <DialogDescription className="mt-1 text-sm leading-6 text-slate-600">
            配置域名、监听端口、接入方式与上游服务器。支持同一站点监听多个端口。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 px-6 py-6">
          {/* Domain */}
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-900">
              域名 <span className="text-red-500">*</span>
            </span>
            <div className="flex items-center gap-2 rounded-lg border border-cyan-300 bg-white px-3 focus-within:ring-2 focus-within:ring-cyan-200">
              <Globe className="h-4 w-4 text-slate-400" />
              <Input
                value={host}
                onChange={(event) => setHost(event.target.value)}
                placeholder="example.com"
                className="border-0 bg-transparent px-0 shadow-none focus-visible:ring-0"
              />
            </div>
            {host.trim() && (
              <div className="rounded-md bg-slate-50 px-3 py-1 text-xs text-slate-500">{host.trim()}</div>
            )}
          </label>

          {/* Listeners - multi-port */}
          <div className="space-y-3">
            <span className="text-sm font-medium text-slate-900">
              监听端口 <span className="text-red-500">*</span>
            </span>
            <div className="space-y-2">
              {listeners.map((l, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <label className="space-y-1 flex-1">
                    <span className="text-xs text-slate-500">端口 <span className="text-red-500">*</span></span>
                    <Input
                      value={l.port}
                      onChange={(e) => updateListener(idx, { port: e.target.value })}
                      placeholder="80"
                      type="number"
                      min={1}
                      max={65535}
                      className="rounded-lg border-slate-200 bg-white"
                    />
                  </label>
                  <div className="flex items-end gap-1 pb-0.5">
                    <button
                      type="button"
                      onClick={() => updateListener(idx, { tls: false })}
                      className={`rounded-md px-3 py-2 text-xs font-medium transition-colors ${
                        !l.tls
                          ? "bg-cyan-500 text-white shadow-sm"
                          : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                      }`}
                    >
                      HTTP
                    </button>
                    <button
                      type="button"
                      onClick={() => updateListener(idx, { tls: true })}
                      className={`rounded-md px-3 py-2 text-xs font-medium transition-colors ${
                        l.tls
                          ? "bg-cyan-500 text-white shadow-sm"
                          : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                      }`}
                    >
                      HTTPS
                    </button>
                    {listeners.length > 1 && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="h-9 w-9 rounded-md text-slate-400 hover:bg-red-50 hover:text-red-500"
                        onClick={() => removeListener(idx)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
            <button
              type="button"
              onClick={addListener}
              className="w-full rounded-lg border-2 border-dashed border-cyan-300 bg-cyan-50/30 py-2.5 text-sm font-medium text-cyan-600 transition-colors hover:bg-cyan-50"
            >
              <Plus className="mr-1.5 inline h-4 w-4" />
              添加一个监听端口
            </button>
          </div>

          {/* Certificate */}
          {hasAnyTLS && (
            <div className="space-y-2">
              <span className="text-sm font-medium text-slate-900">证书</span>
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                <div className="mb-2 flex items-center gap-2 text-xs text-slate-500">
                  <Lock className="h-3.5 w-3.5" /> 存在 HTTPS 端口时必须绑定证书
                </div>
                <Select value={certId ? String(certId) : ""} onValueChange={(value) => setCertId(value ? Number(value) : null)}>
                  <SelectTrigger className="rounded-lg border-slate-200 bg-white">
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
            </div>
          )}

          {/* Access Mode */}
          <div className="space-y-2">
            <span className="text-sm font-medium text-slate-900">接入方式</span>
            <div className="grid grid-cols-3 gap-2">
              {([
                { key: "proxy", label: "代理到已有应用" },
                { key: "static", label: "使用静态文件搭建" },
                { key: "redirect", label: "重定向" },
              ] as const).map((m) => (
                <button
                  key={m.key}
                  type="button"
                  onClick={() => setAccessMode(m.key)}
                  className={`rounded-lg border-2 px-3 py-2.5 text-sm font-medium transition-colors ${
                    accessMode === m.key
                      ? "border-cyan-500 bg-cyan-50/50 text-cyan-700"
                      : "border-slate-200 text-slate-600 hover:border-slate-300"
                  }`}
                >
                  {accessMode === m.key && <span className="mr-1">●</span>}
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          {/* Upstream */}
          {accessMode === "proxy" && (
            <div className="space-y-3 rounded-lg border border-slate-200 bg-slate-50/80 p-5">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">
                    上游服务器 <span className="text-red-500">*</span>
                  </h3>
                  <p className="mt-1 text-xs leading-5 text-slate-500">
                    请求将转发到以下上游地址，多个地址按轮询负载均衡。
                  </p>
                </div>
                <Button type="button" variant="outline" size="sm" className="rounded-md" onClick={() => setUpstreams((current) => [...current, defaultUpstream])}>
                  <Plus className="mr-1.5 h-3.5 w-3.5" /> 添加上游
                </Button>
              </div>

              <div className="space-y-3">
                {upstreams.map((upstream, index) => (
                  <div key={`${index}-${upstream}`} className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white p-2">
                    <Input
                      value={upstream}
                      onChange={(event) => updateUpstream(index, event.target.value)}
                      placeholder="http://192.168.1.10:8080，不支持路径"
                      className="border-0 bg-transparent font-mono text-sm shadow-none focus-visible:ring-0"
                    />
                    {upstreams.length > 1 ? (
                      <Button type="button" variant="ghost" size="icon-sm" className="rounded-md text-rose-600 hover:bg-rose-50 hover:text-rose-700" onClick={() => removeUpstream(index)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    ) : null}
                  </div>
                ))}
              </div>
              <button
                type="button"
                onClick={() => setUpstreams((current) => [...current, defaultUpstream])}
                className="w-full rounded-lg border-2 border-dashed border-cyan-300 bg-cyan-50/30 py-2 text-sm font-medium text-cyan-600 transition-colors hover:bg-cyan-50"
              >
                <Plus className="mr-1 inline h-4 w-4" />
                添加上游服务
              </button>
            </div>
          )}

          {/* App Name */}
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-900">应用名称</span>
            <Input
              value={appName}
              onChange={(e) => setAppName(e.target.value)}
              placeholder="应用名称（可选）"
              className="rounded-lg border-slate-200 bg-white"
            />
          </label>
        </div>

        <DialogFooter className="border-t border-slate-200 bg-white px-6 py-4">
          <Button variant="outline" className="rounded-md" onClick={() => close(false)}>
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={saving} className="rounded-md bg-cyan-500 text-white hover:bg-cyan-600">
            {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {saving ? "创建中..." : "提交"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
