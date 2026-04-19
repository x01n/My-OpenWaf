"use client";

import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Plus, Loader2, X } from "lucide-react";

interface Certificate {
  id: number;
  name: string;
}

interface AddSiteDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

export function AddSiteDialog({
  open,
  onOpenChange,
  onSuccess,
}: AddSiteDialogProps) {
  const [host, setHost] = useState("");
  const [bind, setBind] = useState(":80");
  const [tlsEnabled, setTlsEnabled] = useState(false);
  const [certId, setCertId] = useState<number | null>(null);
  const [upstreams, setUpstreams] = useState<string[]>(["http://"]);
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [certificates, setCertificates] = useState<Certificate[]>([]);

  useEffect(() => {
    if (open) {
      api<{ items: Certificate[] }>("/api/v1/certificates")
        .then((d) => setCertificates(d.items || []))
        .catch(() => {});
    }
  }, [open]);

  function reset() {
    setHost("");
    setBind(":80");
    setTlsEnabled(false);
    setCertId(null);
    setUpstreams(["http://"]);
    setName("");
  }

  async function handleSubmit() {
    if (!host.trim()) {
      toast.error("请输入域名");
      return;
    }
    if (upstreams.filter((u) => u.trim()).length === 0) {
      toast.error("请输入至少一个上游服务器");
      return;
    }
    try {
      setSaving(true);
      await api("/api/v1/sites", {
        method: "POST",
        body: JSON.stringify({
          host: host.trim(),
          bind,
          network: "tcp",
          tls_enabled: tlsEnabled,
          cert_id: certId,
          upstream_urls: JSON.stringify(
            upstreams.filter((u) => u.trim())
          ),
          enabled: true,
          maintenance_enabled: false,
        }),
      });
      toast.success("应用添加成功");
      reset();
      onOpenChange(false);
      onSuccess();
    } catch (err) {
      toast.error("添加失败: " + String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) reset();
        onOpenChange(v);
      }}
    >
      <DialogContent className="sm:max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>添加应用</DialogTitle>
        </DialogHeader>
        <div className="space-y-5 py-2">
          {/* Domain */}
          <div className="space-y-2">
            <Label>域名</Label>
            <Input
              placeholder="example.com"
              value={host}
              onChange={(e) => setHost(e.target.value)}
            />
          </div>

          {/* Port + protocol toggle */}
          <div className="space-y-2">
            <Label>端口</Label>
            <div className="flex gap-2">
              <div className="flex rounded-md border overflow-hidden">
                <button
                  className={`px-3 py-1.5 text-sm font-medium transition-colors ${
                    !tlsEnabled
                      ? "bg-teal-600 text-white"
                      : "bg-background text-muted-foreground hover:bg-muted"
                  }`}
                  onClick={() => {
                    setTlsEnabled(false);
                    setBind(":80");
                  }}
                >
                  HTTP
                </button>
                <button
                  className={`px-3 py-1.5 text-sm font-medium transition-colors ${
                    tlsEnabled
                      ? "bg-teal-600 text-white"
                      : "bg-background text-muted-foreground hover:bg-muted"
                  }`}
                  onClick={() => {
                    setTlsEnabled(true);
                    setBind(":443");
                  }}
                >
                  HTTPS
                </button>
              </div>
              <Input
                value={bind}
                onChange={(e) => setBind(e.target.value)}
                className="w-32"
              />
            </div>
          </div>

          {/* Certificate dropdown (when HTTPS) */}
          {tlsEnabled && (
            <div className="space-y-2">
              <Label>证书</Label>
              <Select
                value={certId ? String(certId) : ""}
                onValueChange={(v) => setCertId(v ? Number(v) : null)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="选择证书" />
                </SelectTrigger>
                <SelectContent>
                  {certificates.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* Upstream servers */}
          <div className="space-y-2">
            <Label>上游服务器</Label>
            {upstreams.map((u, i) => (
              <div key={i} className="flex gap-2">
                <Input
                  placeholder="http://192.168.1.10:8080"
                  value={u}
                  onChange={(e) => {
                    const next = [...upstreams];
                    next[i] = e.target.value;
                    setUpstreams(next);
                  }}
                />
                {upstreams.length > 1 && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() =>
                      setUpstreams(upstreams.filter((_, j) => j !== i))
                    }
                  >
                    <X className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setUpstreams([...upstreams, "http://"])}
              className="text-teal-600"
            >
              <Plus className="mr-1 h-3 w-3" />
              添加上游服务
            </Button>
          </div>

          {/* App name */}
          <div className="space-y-2">
            <Label>应用名称</Label>
            <Input
              placeholder="可选，留空使用域名作为名称"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={saving}
            className="bg-teal-600 hover:bg-teal-700 text-white"
          >
            {saving && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
            确认添加
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
