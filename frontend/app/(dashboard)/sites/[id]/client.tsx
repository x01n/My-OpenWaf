"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ProtectionModeDialog,
  getProtectionMode,
  protectionModeLabel,
  type ProtectionMode,
} from "@/components/protection-mode-dialog";
import { api } from "@/lib/api";
import { toast } from "sonner";
import {
  Globe,
  ArrowLeft,
  ShieldCheck,
  Bot,
  KeyRound,
  Swords,
  BarChart3,
  Activity,
  FileText,
  AlertCircle,
} from "lucide-react";
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

export default function SiteDetailClient() {
  const params = useParams();
  const router = useRouter();
  const siteId = params.id as string;

  const [site, setSite] = useState<Site | null>(null);
  const [loading, setLoading] = useState(true);
  const [modeOpen, setModeOpen] = useState(false);
  const [modeLoading, setModeLoading] = useState(false);

  const loadSite = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api<Site>(`/api/v1/sites/${siteId}`);
      setSite(data);
    } catch (err) {
      toast.error("加载应用详情失败: " + String(err));
    } finally {
      setLoading(false);
    }
  }, [siteId]);

  useEffect(() => {
    loadSite();
  }, [loadSite]);

  function parseUpstreams(raw: string): string[] {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    } catch {}
    return raw ? raw.split(",").map((s) => s.trim()) : [];
  }

  const handleModeConfirm = async (mode: ProtectionMode) => {
    if (!site) return;
    try {
      setModeLoading(true);
      await api(`/api/v1/sites/${site.id}/update`, {
        method: "POST",
        body: JSON.stringify({
          ...site,
          maintenance_enabled: mode === "maintenance",
          attack_protection_level: mode === "observe" ? "observe" : "block",
        }),
      });
      toast.success("防护模式已更新");
      setModeOpen(false);
      await loadSite();
    } catch (err) {
      toast.error("更新失败: " + String(err));
    } finally {
      setModeLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-48" />
        <Skeleton className="h-32 w-full rounded-xl" />
        <Skeleton className="h-64 w-full rounded-xl" />
      </div>
    );
  }

  if (!site) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
        <AlertCircle className="mb-3 h-10 w-10" />
        <p>应用不存在或加载失败</p>
        <Button variant="outline" className="mt-4" onClick={() => router.push("/sites/")}>
          返回列表
        </Button>
      </div>
    );
  }

  const mode = getProtectionMode(site);
  const ups = parseUpstreams(site.upstream_urls);

  function modeButtonStyle(m: ProtectionMode) {
    switch (m) {
      case "protect":
        return "border-teal-500 text-teal-600 hover:bg-teal-50 dark:hover:bg-teal-950";
      case "observe":
        return "border-amber-500 text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-950";
      case "maintenance":
        return "border-rose-500 text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950";
    }
  }

  return (
    <div className="space-y-6">
      <Button
        variant="ghost"
        size="sm"
        onClick={() => router.push("/sites/")}
        className="text-muted-foreground -ml-2"
      >
        <ArrowLeft className="mr-1 h-4 w-4" />
        返回应用列表
      </Button>

      <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-teal-500/15">
            <Globe className="h-6 w-6 text-teal-600" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-xl font-bold text-gray-900 truncate">{site.host}</h2>
            <p className="text-sm text-gray-400 mt-0.5">
              {site.tls_enabled ? "HTTPS" : "HTTP"} | {site.bind}
            </p>
          </div>
          <button
            onClick={() => setModeOpen(true)}
            className={cn(
              "rounded-md border px-4 py-1.5 text-sm font-medium transition-colors",
              modeButtonStyle(mode)
            )}
          >
            {protectionModeLabel(mode)}
          </button>
          <div className="hidden sm:flex items-center gap-8">
            <div className="text-center">
              <div className="text-xs text-gray-400">今日请求</div>
              <div className="text-lg font-bold text-gray-800">--</div>
            </div>
            <div className="text-center">
              <div className="text-xs text-gray-400">今日拦截</div>
              <div className="text-lg font-bold text-rose-500">--</div>
            </div>
          </div>
        </div>
      </div>

      <Tabs defaultValue="basic" className="space-y-4">
        <TabsList className="bg-transparent border-b border-gray-200 rounded-none w-full justify-start h-auto p-0 gap-0">
          <TabsTrigger value="basic" className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600">基本信息</TabsTrigger>
          <TabsTrigger value="forward" className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600">转发规则</TabsTrigger>
          <TabsTrigger value="advanced" className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600">高级配置</TabsTrigger>
          <TabsTrigger value="routes" className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600">应用路由</TabsTrigger>
          <TabsTrigger value="tamper" className="rounded-none border-b-2 border-transparent data-[state=active]:border-teal-500 data-[state=active]:text-teal-600 data-[state=active]:shadow-none data-[state=active]:bg-transparent px-4 py-2.5 text-sm text-gray-600">网页防篡改</TabsTrigger>
        </TabsList>

        <TabsContent value="basic" className="space-y-5">
          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <div className="flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-teal-500 rounded" />
              <h3 className="font-semibold text-gray-700">基础配置</h3>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
              <InfoRow label="应用域名" value={site.host} />
              <InfoRow label="监听端口" value={site.bind} mono />
              <InfoRow label="接入方式" value={site.tls_enabled ? "HTTPS" : "HTTP"} />
              <InfoRow label="上游服务器" value={ups.join(", ") || "未配置"} mono />
            </div>
          </section>

          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <div className="flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-teal-500 rounded" />
              <h3 className="font-semibold text-gray-700">高级防护</h3>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <FeatureButton icon={ShieldCheck} label="CC 防护" onClick={() => router.push("/protection/")} />
              <FeatureButton icon={Bot} label="BOT 防护" onClick={() => router.push("/protection/")} />
              <FeatureButton icon={KeyRound} label="身份认证" onClick={() => router.push("/settings/")} />
              <FeatureButton icon={Swords} label="攻击防护" onClick={() => router.push("/protection/")} />
            </div>
          </section>

          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <div className="flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-teal-500 rounded" />
              <h3 className="font-semibold text-gray-700">数据统计</h3>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <FeatureButton icon={BarChart3} label="流量分析" onClick={() => router.push("/dashboard/")} />
              <FeatureButton icon={Activity} label="安全态势" onClick={() => router.push("/security-events/")} />
            </div>
          </section>

          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <div className="flex items-center gap-2 mb-4">
              <span className="w-1 h-4 bg-teal-500 rounded" />
              <h3 className="font-semibold text-gray-700">应用日志</h3>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <FeatureButton icon={FileText} label="访问日志" onClick={() => router.push("/security-events/")} />
              <FeatureButton icon={AlertCircle} label="错误日志" onClick={() => router.push("/security-events/")} />
            </div>
          </section>
        </TabsContent>

        <TabsContent value="forward"><PlaceholderTab title="转发规则" /></TabsContent>
        <TabsContent value="advanced"><PlaceholderTab title="高级配置" /></TabsContent>
        <TabsContent value="routes"><PlaceholderTab title="应用路由" /></TabsContent>
        <TabsContent value="tamper"><PlaceholderTab title="网页防篡改" /></TabsContent>
      </Tabs>

      <ProtectionModeDialog
        open={modeOpen}
        onOpenChange={setModeOpen}
        currentMode={mode}
        onConfirm={handleModeConfirm}
        loading={modeLoading}
      />
    </div>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <span className="text-gray-500 text-xs">{label}</span>
      <div className={cn("mt-0.5 font-medium text-gray-800", mono && "font-mono text-xs")}>{value}</div>
    </div>
  );
}

function FeatureButton({
  icon: Icon,
  label,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center gap-2 rounded-lg border border-gray-200 bg-white p-4 text-sm font-medium text-gray-500 transition-colors hover:border-teal-500/50 hover:text-teal-600 hover:bg-teal-50"
    >
      <Icon className="h-5 w-5" />
      {label}
    </button>
  );
}

function PlaceholderTab({ title }: { title: string }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-12 text-center text-gray-400">
      <p className="text-lg font-medium">{title}</p>
      <p className="mt-1 text-sm">此功能正在开发中</p>
    </div>
  );
}
