"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import Link from "next/link";
import { useSites, useSiteDelete, useSiteStart, useSiteStop } from "@/hooks/use-api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardHeader,
  CardTitle,
  CardAction,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { toast } from "sonner";
import {
  IconPlus,
  IconShield,
  IconWorld,
  IconEdit,
  IconTrash,
  IconEye,
  IconSettings,
  IconShieldCheck,
  IconRobot,
  IconFingerprint,
  IconBug,
} from "@tabler/icons-react";
import type { Site } from "@/lib/types";
import { SiteFormDialog } from "./components/site-form-dialog";

export default function SitesPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [editingSite, setEditingSite] = useState<Site | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const { data, isLoading } = useSites({ page: 1, page_size: 50 });
  const deleteSite = useSiteDelete();
  const startSite = useSiteStart();
  const stopSite = useSiteStop();

  const items = (data?.items || []).filter((site) =>
    site.host.toLowerCase().includes(search.toLowerCase())
  );
  const total = data?.total || 0;

  const handleDelete = async () => {
    if (!deletingId) return;
    try {
      await deleteSite.execute(deletingId);
      toast.success(t("sites.deleteSuccess"));
    } catch {
      toast.error(t("common.deleteFailed"));
    } finally {
      setDeletingId(null);
    }
  };

  const handleToggle = async (site: Site) => {
    try {
      if (site.enabled) {
        await stopSite.execute(site.id);
        toast.success(t("sites.stopSuccess"));
      } else {
        await startSite.execute(site.id);
        toast.success(t("sites.startSuccess"));
      }
    } catch {
      toast.error(t("common.operationFailed"));
    }
  };

  /** 构建监听端口摘要文本 */
  const getListenerText = (site: Site): string => {
    if (site.listener_summary) return site.listener_summary;
    const port = site.bind?.replace(/^.*:/, "") || site.bind;
    return site.tls_enabled ? `${port}/HTTPS` : `${port}/HTTP`;
  };

  return (
    <div className="space-y-4">
      {/* 顶部操作栏 */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <IconShield className="h-6 w-6 text-primary" />
          <h1 className="text-xl font-semibold">{t("sites.title")}</h1>
          <Badge variant="secondary" className="h-5 px-2 text-xs">
            {t("common.total", { count: total })}
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <Input
            placeholder={t("sites.searchPlaceholder")}
            className="h-9 w-64"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <Button
            className="h-9 bg-primary hover:bg-primary/90"
            onClick={() => {
              setEditingSite(null);
              setShowForm(true);
            }}
          >
            <IconPlus className="mr-1 h-4 w-4" />
            {t("sites.add")}
          </Button>
        </div>
      </div>

      {/* 站点卡片网格 */}
      {isLoading ? (
        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardContent className="h-48" />
            </Card>
          ))}
        </div>
      ) : items.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <IconWorld className="h-12 w-12 mb-3 opacity-40" />
          <p className="text-sm">{t("sites.empty")}</p>
        </div>
      ) : (
        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {items.map((site) => (
            <Card
              key={site.id}
              className="transition-shadow hover:shadow-lg"
            >
              {/* 卡片头部：图标 + 站点名 + 操作按钮 */}
              <CardHeader>
                <div className="flex items-center gap-2 min-w-0">
                  <IconWorld
                    className={`h-5 w-5 shrink-0 ${
                      site.enabled ? "text-emerald-500" : "text-muted-foreground"
                    }`}
                  />
                  <CardTitle className="truncate text-sm">
                    {site.host}
                  </CardTitle>
                </div>
                <CardAction>
                  <div className="flex items-center gap-0.5">
                    <Link href={`/sites/detail/?id=${site.id}`}>
                      <Button variant="ghost" size="icon" className="h-7 w-7">
                        <IconEye className="h-3.5 w-3.5" />
                      </Button>
                    </Link>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => {
                        setEditingSite(site);
                        setShowForm(true);
                      }}
                    >
                      <IconSettings className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </CardAction>
              </CardHeader>

              {/* 卡片内容 */}
              <CardContent className="space-y-3">
                {/* 防护模式 + 状态开关 */}
                <div className="flex items-center justify-between">
                  <Badge
                    variant={site.owasp_enabled !== false ? "default" : "outline"}
                    className={
                      site.owasp_enabled !== false
                        ? "bg-emerald-500/15 text-emerald-700 border-emerald-500/25 dark:text-emerald-400"
                        : "bg-amber-500/15 text-amber-700 border-amber-500/25 dark:text-amber-400"
                    }
                  >
                    {site.owasp_enabled !== false
                      ? t("sites.protectionMode", "防护模式")
                      : t("sites.observeMode", "观察模式")}
                  </Badge>
                  <div className="flex items-center gap-1.5">
                    <Switch
                      checked={site.enabled}
                      onCheckedChange={() => handleToggle(site)}
                      className="scale-90"
                    />
                    <span
                      className={`text-xs ${
                        site.enabled ? "text-emerald-600" : "text-muted-foreground"
                      }`}
                    >
                      {site.enabled ? t("common.running") : t("common.stopped")}
                    </span>
                  </div>
                </div>

                {/* 域名与监听端口 */}
                <div className="space-y-1.5 text-sm">
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-muted-foreground shrink-0">
                      {t("sites.host", "域名")}:
                    </span>
                    <span className="truncate font-medium">{site.host}</span>
                  </div>
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-muted-foreground shrink-0">
                      {t("sites.listeners", "监听")}:
                    </span>
                    <span className="truncate">{getListenerText(site)}</span>
                  </div>
                </div>

                {/* 今日统计 */}
                <div className="flex items-center gap-4 rounded-md bg-muted/50 px-3 py-2">
                  <div className="flex flex-col items-center flex-1">
                    <span className="text-xs text-muted-foreground">
                      {t("sites.todayRequests", "今日请求")}
                    </span>
                    <span className="text-base font-semibold tabular-nums">
                      {(site as Site & { today_requests?: number }).today_requests ?? 0}
                    </span>
                  </div>
                  <div className="w-px h-6 bg-border" />
                  <div className="flex flex-col items-center flex-1">
                    <span className="text-xs text-muted-foreground">
                      {t("sites.todayBlocks", "今日拦截")}
                    </span>
                    <span className="text-base font-semibold tabular-nums text-destructive">
                      {(site as Site & { today_blocks?: number }).today_blocks ?? 0}
                    </span>
                  </div>
                </div>
              </CardContent>

              {/* 快捷功能按钮 + 删除 */}
              <CardFooter className="flex-wrap gap-1.5 pt-0">
                <Badge variant="outline" className="cursor-default text-[10px] gap-1 px-1.5">
                  <IconShieldCheck className="h-3 w-3" />
                  {t("sites.ccProtection", "CC防护")}
                </Badge>
                <Badge variant="outline" className="cursor-default text-[10px] gap-1 px-1.5">
                  <IconRobot className="h-3 w-3" />
                  {t("sites.botProtection", "BOT防护")}
                </Badge>
                <Badge variant="outline" className="cursor-default text-[10px] gap-1 px-1.5">
                  <IconFingerprint className="h-3 w-3" />
                  {t("sites.authProtection", "身份认证")}
                </Badge>
                <Badge variant="outline" className="cursor-default text-[10px] gap-1 px-1.5">
                  <IconBug className="h-3 w-3" />
                  {t("sites.attackProtection", "攻击防护")}
                </Badge>
                <div className="ml-auto">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 text-destructive hover:text-destructive"
                    onClick={() => setDeletingId(site.id)}
                  >
                    <IconTrash className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardFooter>
            </Card>
          ))}
        </div>
      )}

      <SiteFormDialog
        open={showForm}
        onOpenChange={setShowForm}
        site={editingSite}
      />

      <ConfirmDialog
        open={!!deletingId}
        onOpenChange={() => setDeletingId(null)}
        title={t("sites.deleteTitle")}
        description={t("sites.deleteConfirm")}
        confirmText={t("common.delete")}
        onConfirm={handleDelete}
        loading={deleteSite.loading}
      />
    </div>
  );
}
