"use client";

import { useCallback, useEffect, useState } from "react";
import { Loader2, Lock, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Surface } from "@/components/console-shell";
import {
  api,
  createSiteListener,
  deleteSiteListener,
  listSiteListeners,
  updateSiteListener,
  type SiteListener,
} from "@/lib/api";
import { cn } from "@/lib/utils";

interface Certificate {
  id: number;
  name: string;
}

interface SiteListenersPanelProps {
  siteId: number;
  onChanged?: () => void;
}

interface DialogDraft {
  bind: string;
  tlsEnabled: boolean;
  certId: number | null;
  note: string;
  enabled: boolean;
}

const emptyDraft: DialogDraft = {
  bind: ":80",
  tlsEnabled: false,
  certId: null,
  note: "",
  enabled: true,
};

export function SiteListenersPanel({ siteId, onChanged }: SiteListenersPanelProps) {
  const [items, setItems] = useState<SiteListener[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<SiteListener | null>(null);
  const [draft, setDraft] = useState<DialogDraft>(emptyDraft);
  const [saving, setSaving] = useState(false);
  const [certificates, setCertificates] = useState<Certificate[]>([]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listSiteListeners(siteId);
      setItems(data.items || []);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载监听端口失败");
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [siteId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!dialogOpen) return;
    api<{ items: Certificate[] }>("/api/v1/certificates")
      .then((data) => setCertificates(data.items || []))
      .catch(() => setCertificates([]));
  }, [dialogOpen]);

  function openCreate() {
    setEditing(null);
    setDraft(emptyDraft);
    setDialogOpen(true);
  }

  function openEdit(listener: SiteListener) {
    setEditing(listener);
    setDraft({
      bind: listener.bind || "",
      tlsEnabled: !!listener.tls_enabled,
      certId: listener.cert_id ?? null,
      note: listener.note || "",
      enabled: !!listener.enabled,
    });
    setDialogOpen(true);
  }

  function setProtocol(nextTLS: boolean) {
    setDraft((current) => ({
      ...current,
      tlsEnabled: nextTLS,
      bind: current.bind && current.bind !== ":80" && current.bind !== ":443" ? current.bind : nextTLS ? ":443" : ":80",
      certId: nextTLS ? current.certId : null,
    }));
  }

  async function submit() {
    const bind = draft.bind.trim();
    if (!bind) {
      toast.error("请输入监听地址");
      return;
    }
    if (draft.tlsEnabled && !draft.certId) {
      toast.error("启用 HTTPS 时请选择证书");
      return;
    }
    setSaving(true);
    try {
      const payload: Partial<SiteListener> = {
        bind,
        network: "tcp",
        tls_enabled: draft.tlsEnabled,
        cert_id: draft.tlsEnabled ? draft.certId : null,
        enabled: draft.enabled,
        note: draft.note.trim(),
      };
      if (editing) {
        await updateSiteListener(siteId, editing.id, payload);
        toast.success("监听端口已更新");
      } else {
        await createSiteListener(siteId, payload);
        toast.success("监听端口已创建");
      }
      setDialogOpen(false);
      await refresh();
      onChanged?.();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function toggleEnabled(listener: SiteListener, enabled: boolean) {
    if (listener.id === 0) {
      toast.error("旧配置请先点击编辑保存为正式监听");
      return;
    }
    try {
      await updateSiteListener(siteId, listener.id, {
        bind: listener.bind,
        network: listener.network || "tcp",
        tls_enabled: listener.tls_enabled,
        cert_id: listener.cert_id ?? null,
        enabled,
        note: listener.note || "",
      });
      await refresh();
      onChanged?.();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "更新失败");
    }
  }

  async function remove(listener: SiteListener) {
    if (listener.id === 0) {
      toast.error("旧配置无法直接删除，请先创建新的监听端口");
      return;
    }
    if (!confirm(`确认删除监听端口 ${listener.bind}？`)) return;
    try {
      await deleteSiteListener(siteId, listener.id);
      toast.success("监听端口已删除");
      await refresh();
      onChanged?.();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "删除失败");
    }
  }

  function certName(certId?: number | null) {
    if (!certId) return null;
    const found = certificates.find((cert) => cert.id === certId);
    return found?.name || `#${certId}`;
  }

  return (
    <Surface
      title="监听端口"
      description="一个站点可以同时监听多个端口（如同时启用 80 与 443），保存后自动热加载。"
      action={
        <Button className="rounded-xl bg-cyan-500 text-white hover:bg-cyan-600" onClick={openCreate}>
          <Plus className="mr-1.5 h-4 w-4" /> 新增监听端口
        </Button>
      }
    >
      {loading ? (
        <div className="flex items-center justify-center rounded-2xl border border-dashed border-slate-200 bg-slate-50 py-10 text-sm text-slate-500">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" /> 加载中...
        </div>
      ) : items.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-8 text-center text-sm text-slate-500">
          暂无监听端口，点击右上角添加。
        </div>
      ) : (
        <div className="overflow-hidden rounded-2xl border border-slate-200">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3">状态</th>
                <th className="px-4 py-3">监听地址</th>
                <th className="px-4 py-3">协议</th>
                <th className="px-4 py-3">证书</th>
                <th className="px-4 py-3">备注</th>
                <th className="px-4 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {items.map((listener, index) => {
                const isLegacy = listener.note === "legacy" || listener.id === 0;
                return (
                  <tr key={listener.id || `legacy-${index}`} className="border-t border-slate-100">
                    <td className="px-4 py-3">
                      <Switch
                        checked={!!listener.enabled}
                        onCheckedChange={(v) => toggleEnabled(listener, v)}
                        disabled={isLegacy}
                      />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-700">{listener.bind}</td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          "inline-flex items-center rounded-full px-2.5 py-1 font-mono text-xs",
                          listener.tls_enabled
                            ? "bg-emerald-50 text-emerald-700"
                            : "bg-slate-100 text-slate-600",
                        )}
                      >
                        {listener.tls_enabled ? "HTTPS" : "HTTP"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-700">
                      {listener.tls_enabled ? (
                        <span className="inline-flex items-center gap-1.5">
                          <Lock className="h-3.5 w-3.5 text-slate-400" />
                          {certName(listener.cert_id) || (
                            <span className="text-rose-600">未绑定</span>
                          )}
                        </span>
                      ) : (
                        <span className="text-slate-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-600">
                      {isLegacy ? (
                        <span className="inline-flex items-center rounded-full bg-amber-50 px-2 py-0.5 text-xs text-amber-700">
                          旧配置
                        </span>
                      ) : (
                        listener.note || <span className="text-slate-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-xl text-slate-600 hover:bg-slate-100"
                          onClick={() => openEdit(listener)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-xl text-rose-600 hover:bg-rose-50"
                          onClick={() => remove(listener)}
                          disabled={isLegacy}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg overflow-y-auto rounded-[28px] p-0">
          <DialogHeader className="border-b border-white/10 bg-[linear-gradient(135deg,rgba(10,19,34,0.96),rgba(11,27,48,0.9)_55%,rgba(10,69,88,0.5))] px-6 py-5 text-left text-white">
            <DialogTitle className="text-xl font-semibold tracking-tight">
              {editing ? "编辑监听端口" : "新增监听端口"}
            </DialogTitle>
            <DialogDescription className="mt-1.5 text-sm text-slate-300/90">
              监听 Bind、协议与证书信息会即时下发至数据面。
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-5 px-6 py-6">
            <div className="space-y-2">
              <Label className="text-sm font-medium text-slate-900">监听地址</Label>
              <Input
                value={draft.bind}
                onChange={(e) => setDraft({ ...draft, bind: e.target.value })}
                placeholder=":80"
                className="rounded-2xl border-slate-200 bg-slate-50 font-mono"
              />
            </div>

            <div className="space-y-2">
              <Label className="text-sm font-medium text-slate-900">接入协议</Label>
              <div className="grid grid-cols-2 gap-2 rounded-[20px] border border-slate-200 bg-slate-50 p-2">
                <button
                  type="button"
                  onClick={() => setProtocol(false)}
                  className={cn(
                    "rounded-2xl px-4 py-2.5 text-sm font-medium",
                    draft.tlsEnabled
                      ? "text-slate-600"
                      : "bg-white text-slate-950 shadow-sm",
                  )}
                >
                  HTTP
                </button>
                <button
                  type="button"
                  onClick={() => setProtocol(true)}
                  className={cn(
                    "rounded-2xl px-4 py-2.5 text-sm font-medium",
                    draft.tlsEnabled
                      ? "bg-white text-slate-950 shadow-sm"
                      : "text-slate-600",
                  )}
                >
                  HTTPS
                </button>
              </div>
            </div>

            {draft.tlsEnabled ? (
              <div className="space-y-2">
                <Label className="text-sm font-medium text-slate-900">TLS 证书</Label>
                <div className="rounded-[20px] border border-slate-200 bg-slate-50 p-3">
                  <div className="mb-2 flex items-center gap-2 text-xs text-slate-500">
                    <Lock className="h-3.5 w-3.5" /> 启用 HTTPS 时必须绑定证书
                  </div>
                  <Select
                    value={draft.certId ? String(draft.certId) : ""}
                    onValueChange={(value) =>
                      setDraft({ ...draft, certId: value ? Number(value) : null })
                    }
                  >
                    <SelectTrigger className="rounded-2xl border-slate-200 bg-white">
                      <SelectValue placeholder={certificates.length ? "选择证书" : "当前没有可用证书"} />
                    </SelectTrigger>
                    <SelectContent>
                      {certificates.map((cert) => (
                        <SelectItem key={cert.id} value={String(cert.id)}>
                          {cert.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            ) : null}

            <div className="space-y-2">
              <Label className="text-sm font-medium text-slate-900">备注</Label>
              <Input
                value={draft.note}
                onChange={(e) => setDraft({ ...draft, note: e.target.value })}
                placeholder="例如：管理后台专用端口"
                className="rounded-2xl border-slate-200 bg-slate-50"
              />
            </div>

            <label className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
              <div>
                <div className="text-sm font-medium text-slate-900">启用此监听</div>
                <div className="mt-0.5 text-xs text-slate-500">关闭后该端口将停止接收流量。</div>
              </div>
              <Switch
                checked={draft.enabled}
                onCheckedChange={(v) => setDraft({ ...draft, enabled: v })}
              />
            </label>
          </div>

          <DialogFooter className="border-t border-slate-200 bg-white px-6 py-4">
            <Button variant="outline" className="rounded-xl" onClick={() => setDialogOpen(false)}>
              取消
            </Button>
            <Button
              onClick={submit}
              disabled={saving}
              className="rounded-xl bg-cyan-500 text-white hover:bg-cyan-600"
            >
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              {saving ? "保存中..." : editing ? "保存修改" : "创建监听"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Surface>
  );
}
