"use client";

import { useTranslation } from "react-i18next";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  IconChartBar,
  IconShieldExclamation,
  IconShield,
  IconList,
  IconChartLine,
  IconFileAnalytics,
  IconFileText,
  IconAlertCircle,
} from "@tabler/icons-react";
import { useSiteStats, useSiteAccessStats, useSiteListeners } from "@/hooks/use-api";
import type { Site } from "@/lib/types";

interface OverviewTabProps {
  site: Site;
  rulesCount: number;
}

export function OverviewTab({ site, rulesCount }: OverviewTabProps) {
  const { t } = useTranslation();
  const router = useRouter();
  const { data: secStats } = useSiteStats(site.id);
  const { data: accessStats } = useSiteAccessStats(site.id);
  const { data: listeners } = useSiteListeners(site.id);

  const todayRequests = accessStats?.requests ?? secStats?.requests ?? 0;
  const todayBlocks = secStats?.intercepts ?? 0;

  return (
    <div className="space-y-4">
      {/* 快捷统计卡片 */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="flex items-center gap-3 py-4">
            <IconChartBar className="h-8 w-8 text-primary" />
            <div>
              <p className="text-xs text-muted-foreground">{t("sites.detail.todayRequests")}</p>
              <p className="text-lg font-semibold">{todayRequests.toLocaleString()}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 py-4">
            <IconShieldExclamation className="h-8 w-8 text-destructive" />
            <div>
              <p className="text-xs text-muted-foreground">{t("sites.detail.todayBlocks")}</p>
              <p className="text-lg font-semibold">{todayBlocks.toLocaleString()}</p>
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
              <p className="text-lg font-semibold">{rulesCount}</p>
            </div>
          </CardContent>
        </Card>
      </div>

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
              <p className="font-medium">
                <Badge variant={site.tls_enabled ? "default" : "outline"} className="h-5 text-[10px]">
                  {site.tls_enabled ? "HTTPS" : "HTTP"}
                </Badge>
              </p>
            </div>
            <div>
              <span className="text-muted-foreground">{t("sites.detail.maxBody")}</span>
              <p className="font-medium">{(site.max_body_bytes / 1024 / 1024).toFixed(1)} MB</p>
            </div>
            <div>
              <span className="text-muted-foreground">{t("sites.detail.listenerCount")}</span>
              <p className="font-medium">{listeners?.items?.length ?? 0}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 快捷入口：数据统计与日志 */}
      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">{t("sites.detail.dataStats")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <Button
                variant="outline"
                className="h-10 gap-2"
                onClick={() => router.push(`/security-events?site_id=${site.id}`)}
              >
                <IconChartLine className="h-4 w-4" />
                {t("dashboard.requestTrend")}
              </Button>
              <Button
                variant="outline"
                className="h-10 gap-2"
                onClick={() => router.push(`/security-events?site_id=${site.id}`)}
              >
                <IconFileAnalytics className="h-4 w-4" />
                {t("dashboard.blockTrend")}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">{t("sites.detail.appLogs")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <Button
                variant="outline"
                className="h-10 gap-2"
                onClick={() => router.push(`/access-logs?site_id=${site.id}`)}
              >
                <IconFileText className="h-4 w-4" />
                {t("nav.accessLogs")}
              </Button>
              <Button
                variant="outline"
                className="h-10 gap-2"
                onClick={() => router.push(`/security-events?site_id=${site.id}`)}
              >
                <IconAlertCircle className="h-4 w-4" />
                {t("sites.detail.errorLogs")}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
