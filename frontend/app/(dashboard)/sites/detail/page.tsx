"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { useSite, useSiteRules, useSiteMutation } from "@/hooks/use-api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import {
  IconArrowLeft,
  IconWorld,
  IconPlayerPlay,
  IconPlayerPause,
  IconEdit,
  IconLayoutDashboard,
  IconServer,
  IconShield,
  IconLock,
  IconBolt,
  IconFlame,
  IconDatabase,
  IconSettings,
  IconRoute,
  IconList,
  IconChartBar,
} from "@tabler/icons-react";
import { SiteFormDialog } from "../components/site-form-dialog";
import { OverviewTab } from "./components/overview-tab";
import { UpstreamTab } from "./components/upstream-tab";
import { ProtectionTab } from "./components/protection-tab";
import { DynamicProtectionTab } from "./components/dynamic-protection-tab";
import { CCProtectionTab } from "./components/cc-protection-tab";
import { AccessControlTab } from "./components/access-control-tab";
import { CacheTab } from "./components/cache-tab";
import { AdvancedTab } from "./components/advanced-tab";
import { ListenersTab } from "./components/listeners-tab";
import { RulesTab } from "./components/rules-tab";
import { MonitorTab } from "./components/monitor-tab";

function SiteDetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-40" />
      <Skeleton className="h-32" />
      <Skeleton className="h-64" />
    </div>
  );
}

const ALLOWED_TABS = [
  "overview",
  "monitor",
  "listeners",
  "rules",
  "upstream",
  "protection",
  "dynamic",
  "cc",
  "access",
  "cache",
  "advanced",
] as const;

function SiteDetailContent() {
  const { t } = useTranslation();
  const searchParams = useSearchParams();
  const siteId = searchParams.get("id") || "";
  const tabParam = searchParams.get("tab") || "";
  const initialTab = (ALLOWED_TABS as readonly string[]).includes(tabParam)
    ? tabParam
    : "overview";

  const { data: site, isLoading: siteLoading } = useSite(siteId);
  const { data: rules } = useSiteRules(siteId);
  const updateSite = useSiteMutation();

  const [showEdit, setShowEdit] = useState(false);

  const handleToggle = async () => {
    if (!site) return;
    try {
      await updateSite.execute({ id: site.id, data: { enabled: !site.enabled } });
      toast.success(site.enabled ? t("sites.stopSuccess") : t("sites.startSuccess"));
    } catch {
      toast.error(t("common.operationFailed"));
    }
  };

  if (siteLoading || !site) {
    return <SiteDetailSkeleton />;
  }

  return (
    <div className="space-y-4">
      {/* 顶部站点信息栏 */}
      <div className="flex flex-col gap-4 rounded-lg border bg-card p-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-center gap-3">
          <Link href="/sites">
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <IconArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
            <IconWorld className="h-5 w-5 text-primary" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight">{site.host || t("sites.detail.unnamed")}</h1>
              <Badge variant={site.enabled ? "default" : "secondary"} className="h-5 text-[10px]">
                {site.enabled ? t("common.running") : t("common.stopped")}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground mt-1">{site.bind}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant={site.enabled ? "destructive" : "outline"}
            size="sm"
            className="h-8"
            onClick={handleToggle}
          >
            {site.enabled ? (
              <IconPlayerPause className="mr-1 h-4 w-4" />
            ) : (
              <IconPlayerPlay className="mr-1 h-4 w-4" />
            )}
            {site.enabled ? t("common.stop") : t("common.start")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8"
            onClick={() => setShowEdit(true)}
          >
            <IconEdit className="mr-1 h-4 w-4" />
            {t("common.edit")}
          </Button>
        </div>
      </div>

      {/* Tab 内容 */}
      <Tabs defaultValue={initialTab} className="space-y-4">
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">
            <IconLayoutDashboard className="mr-1 h-4 w-4" />
            {t("sites.detail.overview")}
          </TabsTrigger>
          <TabsTrigger value="monitor">
            <IconChartBar className="mr-1 h-4 w-4" />
            {t("sites.detail.monitor.tab")}
          </TabsTrigger>
          <TabsTrigger value="listeners">
            <IconRoute className="mr-1 h-4 w-4" />
            {t("sites.detail.listeners")}
          </TabsTrigger>
          <TabsTrigger value="rules">
            <IconList className="mr-1 h-4 w-4" />
            {t("sites.detail.rules")}
          </TabsTrigger>
          <TabsTrigger value="upstream">
            <IconServer className="mr-1 h-4 w-4" />
            {t("sites.detail.upstream")}
          </TabsTrigger>
          <TabsTrigger value="protection">
            <IconShield className="mr-1 h-4 w-4" />
            {t("sites.detail.securityProtection")}
          </TabsTrigger>
          <TabsTrigger value="dynamic">
            <IconBolt className="mr-1 h-4 w-4" />
            {t("sites.detail.dynamicProtection")}
          </TabsTrigger>
          <TabsTrigger value="cc">
            <IconFlame className="mr-1 h-4 w-4" />
            {t("sites.detail.ccProtection.tab")}
          </TabsTrigger>
          <TabsTrigger value="access">
            <IconLock className="mr-1 h-4 w-4" />
            {t("sites.detail.accessControl")}
          </TabsTrigger>
          <TabsTrigger value="cache">
            <IconDatabase className="mr-1 h-4 w-4" />
            {t("sites.detail.cache")}
          </TabsTrigger>
          <TabsTrigger value="advanced">
            <IconSettings className="mr-1 h-4 w-4" />
            {t("sites.detail.advanced")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab site={site} rulesCount={rules?.items?.length || 0} />
        </TabsContent>

        <TabsContent value="monitor">
          <MonitorTab site={site} />
        </TabsContent>

        <TabsContent value="listeners">
          <ListenersTab site={site} />
        </TabsContent>

        <TabsContent value="rules">
          <RulesTab site={site} />
        </TabsContent>

        <TabsContent value="upstream">
          <UpstreamTab site={site} />
        </TabsContent>

        <TabsContent value="protection">
          <ProtectionTab site={site} />
        </TabsContent>

        <TabsContent value="dynamic">
          <DynamicProtectionTab site={site} />
        </TabsContent>

        <TabsContent value="cc">
          <CCProtectionTab site={site} />
        </TabsContent>

        <TabsContent value="access">
          <AccessControlTab site={site} />
        </TabsContent>

        <TabsContent value="cache">
          <CacheTab site={site} />
        </TabsContent>

        <TabsContent value="advanced">
          <AdvancedTab site={site} />
        </TabsContent>
      </Tabs>

      <SiteFormDialog
        open={showEdit}
        onOpenChange={setShowEdit}
        site={site}
      />
    </div>
  );
}

export default function SiteDetailPage() {
  return (
    <Suspense fallback={<SiteDetailSkeleton />}>
      <SiteDetailContent />
    </Suspense>
  );
}
