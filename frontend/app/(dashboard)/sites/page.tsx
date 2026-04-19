"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { AddSiteDialog } from "@/components/add-site-dialog";
import {
  ProtectionModeDialog,
  getProtectionMode,
  protectionModeLabel,
  type ProtectionMode,
} from "@/components/protection-mode-dialog";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Globe, Plus, Trash2, AlignJustify } from "lucide-react";
import { cn } from "@/lib/utils";

interface Site {
  id: number;
  host: string;
  listener_id: number;
  upstream_urls: string;
  bind: string;
  network: string;
  enabled: boolean;
  tls_enabled: boolean;
  cert_id?: number;
  policy_id?: number;
  maintenance_enabled: boolean;
  bot_protection_enabled: boolean;
  attack_protection_level?: string;
  created_at: string;
  updated_at: string;
}

export default function SitesPage() {
  const router = useRouter();
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Site | null>(null);
  const [modeDialogSite, setModeDialogSite] = useState<Site | null>(null);
  const [modeLoading, setModeLoading] = useState(false);

  const loadSites = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api<{ items: Site[] }>("/api/v1/sites");
      setSites(data.items || []);
    } catch (err) {
      toast.error("加载应用失败: " + String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSites();
  }, [loadSites]);

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await api(`/api/v1/sites/${deleteTarget.id}/delete`, { method: "POST" });
      toast.success("应用已删除");
      setDeleteTarget(null);
      await loadSites();
    } catch (err) {
      toast.error("删除失败: " + String(err));
    }
  };

  const handleModeConfirm = async (mode: ProtectionMode) => {
    if (!modeDialogSite) return;
    try {
      setModeLoading(true);
      await api(`/api/v1/sites/${modeDialogSite.id}/update`, {
        method: "POST",
        body: JSON.stringify({
          ...modeDialogSite,
          maintenance_enabled: mode === "maintenance",
          attack_protection_level: mode === "observe" ? "observe" : "block",
        }),
      });
      toast.success("防护模式已更新");
      setModeDialogSite(null);
      await loadSites();
    } catch (err) {
      toast.error("更新失败: " + String(err));
    } finally {
      setModeLoading(false);
    }
  };

  function modeButtonStyle(mode: ProtectionMode) {
    switch (mode) {
      case "protect":
        return "border-teal-500 text-teal-600 hover:bg-teal-50";
      case "observe":
        return "border-amber-500 text-amber-600 hover:bg-amber-50";
      case "maintenance":
        return "border-rose-500 text-rose-600 hover:bg-rose-50";
    }
  }

  function modeDescription(mode: ProtectionMode) {
    switch (mode) {
      case "protect":
        return "发现攻击后将自动拦截，并记录攻击事件";
      case "observe":
        return "发现攻击后仅记录攻击事件，不拦截";
      case "maintenance":
        return "展示维护页面，任何人都将无法访问您的应用";
    }
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-500">
            共{" "}
            <span className="font-semibold text-gray-800">{sites.length}</span>
            {" "}个应用
          </span>
          <div className="inline-flex items-center rounded border border-gray-200 bg-gray-50 px-3 py-1 text-sm font-medium text-gray-700">
            应用
          </div>
        </div>
        <Button
          onClick={() => setAddOpen(true)}
          className="bg-teal-600 hover:bg-teal-700 text-white"
        >
          <Plus className="mr-1.5 h-4 w-4" />
          添加应用
        </Button>
      </div>

      {/* Site Cards */}
      {loading ? (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <Skeleton key={i} className="h-24 w-full rounded-xl" />
          ))}
        </div>
      ) : sites.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-gray-200 bg-white py-20 text-gray-400">
          <Globe className="mb-3 h-10 w-10 text-teal-400/60" />
          <p className="text-sm">暂无应用，点击右上角添加</p>
        </div>
      ) : (
        <div className="space-y-3">
          {sites.map((site) => {
            const mode = getProtectionMode(site);
            return (
              <div
                key={site.id}
                className="rounded-xl border border-gray-200 bg-white shadow-sm transition-shadow hover:shadow-md"
              >
                <div className="flex items-center gap-5 px-5 py-4">
                  {/* Globe icon + name + domain */}
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-teal-500/15">
                      <Globe className="h-5 w-5 text-teal-600" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-base font-semibold text-gray-900 truncate">
                        {site.host}
                      </div>
                      <div className="mt-0.5 text-xs text-gray-400 truncate">
                        {site.tls_enabled ? "https" : "http"}://{site.host}
                        {site.bind && site.bind !== ":80" && site.bind !== ":443"
                          ? site.bind
                          : ""}
                      </div>
                    </div>
                  </div>

                  {/* Protection mode + description */}
                  <div className="hidden md:flex flex-col gap-1 shrink-0 min-w-[200px]">
                    <button
                      onClick={() => setModeDialogSite(site)}
                      className={cn(
                        "self-start flex items-center gap-1.5 rounded border px-3 py-1 text-sm font-medium transition-colors",
                        modeButtonStyle(mode)
                      )}
                    >
                      <AlignJustify className="h-3.5 w-3.5" />
                      {protectionModeLabel(mode)}
                    </button>
                    <span className="text-xs text-gray-400 leading-snug">
                      {modeDescription(mode)}
                    </span>
                  </div>

                  {/* Stats */}
                  <div className="hidden sm:flex items-center gap-6 shrink-0">
                    <div className="text-center">
                      <div className="text-xs text-gray-400">今日请求</div>
                      <div className="mt-0.5 text-lg font-bold text-gray-800">--</div>
                    </div>
                    <div className="text-center">
                      <div className="text-xs text-gray-400">今日拦截</div>
                      <div className="mt-0.5 text-lg font-bold text-rose-500">--</div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 shrink-0 ml-2">
                    {/* Mobile: mode button */}
                    <button
                      onClick={() => setModeDialogSite(site)}
                      className={cn(
                        "md:hidden rounded border px-2 py-1 text-xs font-medium transition-colors",
                        modeButtonStyle(mode)
                      )}
                    >
                      {protectionModeLabel(mode)}
                    </button>

                    <button
                      onClick={() => router.push(`/sites/${site.id}/`)}
                      className="rounded px-3 py-1 text-sm font-medium text-teal-600 hover:text-teal-700 hover:bg-teal-50 transition-colors"
                    >
                      详情
                    </button>
                    <button
                      onClick={() => setDeleteTarget(site)}
                      className="rounded p-1.5 text-gray-400 hover:text-rose-500 hover:bg-rose-50 transition-colors"
                      title="删除"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Dialogs */}
      <AddSiteDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        onSuccess={loadSites}
      />

      {modeDialogSite && (
        <ProtectionModeDialog
          open={!!modeDialogSite}
          onOpenChange={(v) => !v && setModeDialogSite(null)}
          currentMode={getProtectionMode(modeDialogSite)}
          onConfirm={handleModeConfirm}
          loading={modeLoading}
        />
      )}

      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={() => setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除</AlertDialogTitle>
            <AlertDialogDescription>
              确定要删除应用{" "}
              <strong>{deleteTarget?.host}</strong>{" "}
              吗？此操作无法撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete}>删除</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
