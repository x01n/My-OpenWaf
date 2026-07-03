"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { useSite, useSiteListeners, useSiteRules, useSiteMutation } from "@/hooks/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import {
  IconArrowLeft,
  IconWorld,
  IconShield,
  IconPlayerPlay,
  IconPlayerPause,
  IconEdit,
  IconChartBar,
  IconShieldExclamation,
  IconList,
  IconRoute,
  IconSettings,
  IconBolt,
  IconRobot,
  IconLock,
  IconSword,
  IconChartLine,
  IconFileAnalytics,
  IconFileText,
  IconAlertCircle,
} from "@tabler/icons-react";
import { DataTable } from "@/components/data-table";
import { SiteFormDialog } from "../components/site-form-dialog";
import { AttackProtectionDialog } from "../components/attack-protection-dialog";
import { BotProtectionDialog } from "../components/bot-protection-dialog";

function SiteDetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-40" />
      <Skeleton className="h-32" />
      <Skeleton className="h-64" />
    </div>
  );
}

function SiteDetailContent() {
  const { t } = useTranslation();
  const searchParams = useSearchParams();
  const siteId = searchParams.get("id") || "";

  const { data: site, isLoading: siteLoading } = useSite(siteId);
  const { data: listeners } = useSiteListeners(siteId);
  const { data: rules } = useSiteRules(siteId);
  const updateSite = useSiteMutation();

  const [showEdit, setShowEdit] = useState(false);
  const [showAttackDlg, setShowAttackDlg] = useState(false);
  const [showBotDlg, setShowBotDlg] = useState(false);

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

  const listenerColumns = [
    { key: "bind", title: t("sites.detail.bindAddress") },
    { key: "network", title: t("sites.detail.network") },
    {
      key: "tls_enabled",
      title: t("sites.detail.tls"),
      render: (row: any) => (
        <Badge variant={row.tls_enabled ? "default" : "outline"} className="h-5 text-[10px]">
          {row.tls_enabled ? "HTTPS" : "HTTP"}
        </Badge>
      ),
    },
    { key: "enabled", title: t("common.status"), render: (row: any) => (row.enabled ? t("sites.detail.listenerEnabled") : t("sites.detail.listenerDisabled")) },
  ];

  const ruleColumns = [
    { key: "name", title: t("common.name") },
    { key: "phase", title: t("securityEvents.phase") },
    { key: "pattern", title: t("rules.pattern") },
    { key: "action", title: t("common.actions") },
    { key: "priority", title: t("rules.priority") },
  ];

  /** 高级防护快捷入口 */
  const protectionItems = [
    { key: "cc", label: t("nav.ccProtection"), icon: IconBolt, href: "/cc-protection", dialog: false as const },
    { key: "bot", label: t("nav.captcha"), icon: IconRobot, dialog: true as const },
    { key: "auth", label: t("nav.authConfig"), icon: IconLock, href: "/auth-config", dialog: false as const },
    { key: "attack", label: t("nav.attacks"), icon: IconSword, dialog: true as const },
  ];

  /** 数据统计入口 */
  const statItems = [
    { key: "traffic", label: t("dashboard.requestTrend"), icon: IconChartLine },
    { key: "security", label: t("dashboard.blockTrend"), icon: IconFileAnalytics },
  ];

  /** 日志入口 */
  const logItems = [
    { key: "access", label: t("nav.accessLogs"), icon: IconFileText },
    { key: "error", label: t("sites.detail.errorLogs"), icon: IconAlertCircle },
  ];

  return (
    <div className="space-y-4">
      {/* 顶部站点信息栏 */}
      <div className="flex flex-col gap-4 rounded-lg border bg-card p-4 sm:flex-row sm:items-center sm:justify-between">
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
              <h1 className="text-base font-semibold">{site.host || t("sites.detail.unnamed")}</h1>
              <Badge variant={site.enabled ? "default" : "secondary"} className="h-5 text-[10px]">
                {site.enabled ? t("common.running") : t("common.stopped")}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground">{site.host}</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* 今日统计 */}
          <div className="flex items-center gap-4 text-sm">
            <div className="text-right">
              <p className="text-xs text-muted-foreground">{t("sites.detail.todayRequests")}</p>
              <p className="font-semibold">-</p>
            </div>
            <div className="text-right">
              <p className="text-xs text-muted-foreground">{t("sites.detail.todayBlocks")}</p>
              <p className="font-semibold">-</p>
            </div>
          </div>

          {/* 操作按钮 */}
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
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
      </div>

      {/* 快捷统计卡片 */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="flex items-center gap-3 py-4">
            <IconChartBar className="h-8 w-8 text-primary" />
            <div>
              <p className="text-xs text-muted-foreground">{t("sites.detail.todayRequests")}</p>
              <p className="text-lg font-semibold">-</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 py-4">
            <IconShieldExclamation className="h-8 w-8 text-destructive" />
            <div>
              <p className="text-xs text-muted-foreground">{t("sites.detail.todayBlocks")}</p>
              <p className="text-lg font-semibold">-</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 py-4">
            <IconShield className="h-8 w-8 text-primary" />
            <div>
              <p className="text-xs text-muted-foreground">{t("sites.detail.protectionMode")}</p>
              <p className="text-lg font-semibold">{site.attack_protection_level || t("common.balanced")}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 py-4">
            <IconList className="h-8 w-8 text-primary" />
            <div>
              <p className="text-xs text-muted-foreground">{t("sites.detail.ruleCount")}</p>
              <p className="text-lg font-semibold">{rules?.items?.length || 0}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tab 内容 */}
      <Tabs defaultValue="basic" className="space-y-4">
        <TabsList>
          <TabsTrigger value="basic">
            <IconSettings className="mr-1 h-4 w-4" />
            {t("sites.detail.basicInfo")}
          </TabsTrigger>
          <TabsTrigger value="listeners">
            <IconRoute className="mr-1 h-4 w-4" />
            {t("sites.detail.listeners")}
          </TabsTrigger>
          <TabsTrigger value="rules">
            <IconShield className="mr-1 h-4 w-4" />
            {t("sites.detail.rules")}
          </TabsTrigger>
          <TabsTrigger value="advanced">
            <IconShieldExclamation className="mr-1 h-4 w-4" />
            {t("sites.detail.advancedProtection")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="basic" className="space-y-4">
          {/* 基础配置 */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{t("sites.detail.basicInfo")}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.appDomain")}</span>
                  <p className="font-medium">{site.host}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.listeners")}</span>
                  <p className="font-medium">{site.bind}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.accessMethod")}</span>
                  <p className="font-medium">{t("sites.detail.proxyMode")}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.upstreamServer")}</span>
                  <p className="font-medium">{site.upstream_urls}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.tls")}</span>
                  <p className="font-medium">{site.tls_enabled ? t("sites.detail.tlsEnabled") : t("sites.detail.tlsDisabled")}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">{t("sites.detail.maxBody")}</span>
                  <p className="font-medium">{(site.max_body_bytes / 1024 / 1024).toFixed(1)} MB</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="listeners">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{t("sites.detail.listeners")}</CardTitle>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={listenerColumns}
                data={listeners?.items || []}
                loading={!listeners}
                rowKey={(row) => row.id}
                emptyText={t("sites.detail.noListeners")}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rules">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{t("sites.detail.rules")}</CardTitle>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={ruleColumns}
                data={rules?.items || []}
                loading={!rules}
                rowKey={(row) => row.id}
                emptyText={t("sites.detail.noRules")}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="advanced" className="space-y-4">
          {/* 高级防护 */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{t("sites.detail.advancedProtection")}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-3">
                {protectionItems.map((item) => {
                  const ItemIcon = item.icon;
                  if (item.dialog) {
                    return (
                      <Button
                        key={item.key}
                        variant="outline"
                        className="h-10 gap-2"
                        onClick={() => {
                          if (item.key === "attack") setShowAttackDlg(true);
                          if (item.key === "bot") setShowBotDlg(true);
                        }}
                      >
                        <ItemIcon className="h-4 w-4" />
                        {item.label}
                      </Button>
                    );
                  }
                  return (
                    <Link key={item.key} href={item.href!}>
                      <Button variant="outline" className="h-10 gap-2">
                        <ItemIcon className="h-4 w-4" />
                        {item.label}
                      </Button>
                    </Link>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* 数据统计 */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{t("sites.detail.dataStats")}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-3">
                {statItems.map((item) => {
                  const ItemIcon = item.icon;
                  return (
                    <Button key={item.key} variant="outline" className="h-10 gap-2">
                      <ItemIcon className="h-4 w-4" />
                      {item.label}
                    </Button>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* 应用日志 */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{t("sites.detail.appLogs")}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-3">
                {logItems.map((item) => {
                  const ItemIcon = item.icon;
                  return (
                    <Button key={item.key} variant="outline" className="h-10 gap-2">
                      <ItemIcon className="h-4 w-4" />
                      {item.label}
                    </Button>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <SiteFormDialog
        open={showEdit}
        onOpenChange={setShowEdit}
        site={site}
      />

      <AttackProtectionDialog
        open={showAttackDlg}
        onOpenChange={setShowAttackDlg}
      />

            <BotProtectionDialog
        open={showBotDlg}
        onOpenChange={setShowBotDlg}
        siteId={site.id}
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
