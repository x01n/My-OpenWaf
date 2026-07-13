"use client";

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import Link from "next/link";
import { useSites, useSiteDelete, useSiteStart, useSiteStop } from "@/hooks/use-api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { toast } from "sonner";
import {
  IconPlus,
  IconShield,
  IconWorld,
  IconTrash,
  IconEye,
  IconEdit,
  IconRobot,
  IconGauge,
  IconKey,
  IconBolt,
  IconLock,
  IconDotsVertical,
  IconPlayerPlay,
  IconPlayerPause,
  IconServer,
} from "@tabler/icons-react";
import type { Site } from "@/lib/types";
import { SiteFormDialog } from "./components/site-form-dialog";

/**
 * @typedef {"protection" | "observe" | "maintenance"} SiteMode
 */
type SiteMode = "protection" | "observe" | "maintenance";

/**
 * 根据站点字段解析当前防护模式。
 * - maintenance_enabled 为 true → 维护中
 * - owasp_action = observe 或 owasp_enabled=false → 观察模式
 * - 其余情况 → 防护模式
 */
function resolveSiteMode(site: Site): SiteMode {
  if (site.maintenance_enabled) return "maintenance";
  const observeAction =
    site.owasp_action === "observe" || site.owasp_action === "log_only";
  if (site.owasp_enabled === false || observeAction) return "observe";
  return "protection";
}

/**
 * 从 bind / listener_summary 中提取监听端口条目，用于渲染端口徽章列表。
 * 返回形如 `{ port: "80", scheme: "HTTP" }` 的列表。
 */
function extractListeners(
  site: Site
): Array<{ port: string; scheme: "HTTP" | "HTTPS" }> {
  const parseOne = (
    text: string,
    defaultTls: boolean
  ): { port: string; scheme: "HTTP" | "HTTPS" } | null => {
    const trimmed = text.trim();
    if (!trimmed) return null;
    // 支持形如 ":80/HTTP"、":443/HTTPS"、"0.0.0.0:8080"
    const slashIdx = trimmed.indexOf("/");
    const addr = slashIdx >= 0 ? trimmed.slice(0, slashIdx) : trimmed;
    const label = slashIdx >= 0 ? trimmed.slice(slashIdx + 1).toUpperCase() : "";
    const port = addr.replace(/^.*:/, "") || addr;
    const scheme: "HTTP" | "HTTPS" =
      label === "HTTPS" || (label === "" && defaultTls) ? "HTTPS" : "HTTP";
    return { port, scheme };
  };

  const source = site.listener_summary?.trim();
  if (source) {
    return source
      .split(/[,\s]+/)
      .map((seg) => parseOne(seg, site.tls_enabled))
      .filter((x): x is { port: string; scheme: "HTTP" | "HTTPS" } => !!x);
  }
  if (site.bind) {
    const one = parseOne(site.bind, site.tls_enabled);
    return one ? [one] : [];
  }
  return [];
}

/**
 * 解析上游 URL 列表，返回第一个可展示的 URL 与总数。
 */
function extractUpstreams(site: Site): { first: string; count: number } {
  const raw = (site.upstream_urls || "").trim();
  if (!raw) return { first: "", count: 0 };
  const list = raw
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return { first: list[0] || "", count: list.length };
}

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

  const items = useMemo(
    () =>
      (data?.items || []).filter((site) =>
        site.host.toLowerCase().includes(search.toLowerCase())
      ),
    [data?.items, search]
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

  /** 快捷入口按钮定义（点击直接跳到 detail 对应 Tab）。 */
  const quickAccessItems: Array<{
    key: string;
    tab: string;
    icon: typeof IconRobot;
    label: string;
  }> = [
    {
      key: "bot",
      tab: "protection",
      icon: IconRobot,
      label: t("sites.botProtection", "BOT 防护"),
    },
    {
      key: "auth",
      tab: "access",
      icon: IconKey,
      label: t("sites.authProtection", "身份认证"),
    },
    {
      key: "attack",
      tab: "protection",
      icon: IconShield,
      label: t("sites.attackProtection", "攻击防护"),
    },
    {
      key: "cc",
      tab: "cc",
      icon: IconGauge,
      label: t("sites.ccProtection", "CC 防护"),
    },
    {
      key: "dynamic",
      tab: "dynamic",
      icon: IconBolt,
      label: t("sites.dynamicProtection", "动态防护"),
    },
    {
      key: "access",
      tab: "access",
      icon: IconLock,
      label: t("sites.accessControl", "访问控制"),
    },
  ];

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
              <CardContent className="h-56" />
            </Card>
          ))}
        </div>
      ) : items.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-16 text-center">
          <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
            <IconWorld className="h-8 w-8 text-primary/60" />
          </div>
          <p className="mb-4 text-sm text-muted-foreground">
            {t("sites.emptyHint", "还没有防护应用，立即添加")}
          </p>
          <Button
            className="bg-primary hover:bg-primary/90"
            onClick={() => {
              setEditingSite(null);
              setShowForm(true);
            }}
          >
            <IconPlus className="mr-1 h-4 w-4" />
            {t("sites.add")}
          </Button>
        </div>
      ) : (
        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {items.map((site) => {
            const mode = resolveSiteMode(site);
            const listeners = extractListeners(site);
            const { first: upstreamFirst, count: upstreamCount } =
              extractUpstreams(site);

            return (
              <Card
                key={site.id}
                className="group relative transition-all hover:border-primary/40 hover:shadow-lg"
              >
                {/* 头部：状态圆点 + 域名 + 更多操作 */}
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <Link
                      href={`/sites/detail/?id=${site.id}`}
                      className="group/link flex min-w-0 flex-1 items-center gap-2"
                    >
                      {/* 状态圆点：启用绿色 + 脉动，禁用灰色 */}
                      <span
                        className="relative flex h-2.5 w-2.5 shrink-0"
                        aria-label={
                          site.enabled
                            ? t("common.running")
                            : t("common.stopped")
                        }
                      >
                        {site.enabled && (
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                        )}
                        <span
                          className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                            site.enabled
                              ? "bg-emerald-500"
                              : "bg-muted-foreground/50"
                          }`}
                        />
                      </span>
                      <h3
                        className="truncate text-base font-semibold group-hover/link:text-primary"
                        title={site.host}
                      >
                        {site.host}
                      </h3>
                    </Link>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 shrink-0 opacity-60 transition-opacity group-hover:opacity-100"
                          aria-label={t("sites.moreActions", "更多操作")}
                        >
                          <IconDotsVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-40">
                        <DropdownMenuItem asChild>
                          <Link href={`/sites/detail/?id=${site.id}`}>
                            <IconEye className="mr-2 h-4 w-4" />
                            {t("common.viewDetail", "查看详情")}
                          </Link>
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => {
                            setEditingSite(site);
                            setShowForm(true);
                          }}
                        >
                          <IconEdit className="mr-2 h-4 w-4" />
                          {t("common.edit")}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleToggle(site)}>
                          {site.enabled ? (
                            <>
                              <IconPlayerPause className="mr-2 h-4 w-4" />
                              {t("common.stop")}
                            </>
                          ) : (
                            <>
                              <IconPlayerPlay className="mr-2 h-4 w-4" />
                              {t("common.start")}
                            </>
                          )}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          variant="destructive"
                          onClick={() => setDeletingId(site.id)}
                        >
                          <IconTrash className="mr-2 h-4 w-4" />
                          {t("common.delete")}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>

                <CardContent className="space-y-3 pb-3">
                  {/* 中央大徽章：防护模式 / 观察模式 / 维护中 */}
                  <div className="flex justify-center">
                    {mode === "protection" && (
                      <Badge className="border-teal-500/25 bg-teal-500/15 px-3 py-1 text-sm font-medium text-teal-700 hover:bg-teal-500/20 dark:text-teal-300">
                        <IconShield className="mr-1 h-3.5 w-3.5" />
                        {t("sites.protectionMode", "防护模式")}
                      </Badge>
                    )}
                    {mode === "observe" && (
                      <Badge className="border-amber-500/25 bg-amber-500/15 px-3 py-1 text-sm font-medium text-amber-700 hover:bg-amber-500/20 dark:text-amber-300">
                        <IconEye className="mr-1 h-3.5 w-3.5" />
                        {t("sites.observeMode", "观察模式")}
                      </Badge>
                    )}
                    {mode === "maintenance" && (
                      <Badge className="border-slate-500/25 bg-slate-500/15 px-3 py-1 text-sm font-medium text-slate-700 hover:bg-slate-500/20 dark:text-slate-300">
                        <IconPlayerPause className="mr-1 h-3.5 w-3.5" />
                        {t("sites.maintenanceMode", "维护中")}
                      </Badge>
                    )}
                  </div>

                  {/* 端口列表 */}
                  <div className="space-y-1.5">
                    <div className="text-xs text-muted-foreground">
                      {t("sites.listeners", "监听端口")}
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {listeners.length === 0 ? (
                        <span className="text-xs text-muted-foreground">
                          {site.bind || "-"}
                        </span>
                      ) : (
                        listeners.map((l, i) => (
                          <Badge
                            key={`${l.port}-${l.scheme}-${i}`}
                            variant="outline"
                            className={`h-5 px-1.5 font-mono text-[11px] ${
                              l.scheme === "HTTPS"
                                ? "border-emerald-500/30 text-emerald-700 dark:text-emerald-400"
                                : "border-sky-500/30 text-sky-700 dark:text-sky-400"
                            }`}
                          >
                            <span className="mr-1 opacity-70">{l.scheme}</span>
                            {l.port}
                          </Badge>
                        ))
                      )}
                    </div>
                  </div>

                  {/* 上游预览 */}
                  <div className="space-y-1.5">
                    <div className="text-xs text-muted-foreground">
                      {t("sites.upstream", "上游")}
                    </div>
                    <div className="flex items-center gap-1.5 text-xs">
                      <IconServer className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      {upstreamFirst ? (
                        <span
                          className="truncate font-mono"
                          title={upstreamFirst}
                        >
                          {upstreamFirst}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                      {upstreamCount > 1 && (
                        <Badge
                          variant="secondary"
                          className="h-4 shrink-0 px-1.5 text-[10px]"
                        >
                          {t("sites.upstreamMoreCount", "共 {{count}} 个", {
                            count: upstreamCount,
                          })}
                        </Badge>
                      )}
                    </div>
                  </div>
                </CardContent>

                {/* 底部快捷入口：一排小按钮，深链到 detail 对应 Tab */}
                <CardFooter className="flex-wrap gap-1 border-t pt-3">
                  <div className="mb-1 w-full text-[10px] uppercase tracking-wide text-muted-foreground">
                    {t("sites.quickAccess", "快捷入口")}
                  </div>
                  {quickAccessItems.map((item) => {
                    const Icon = item.icon;
                    return (
                      <Link
                        key={item.key}
                        href={`/sites/detail/?id=${site.id}&tab=${item.tab}`}
                      >
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 gap-1 px-2 text-[11px] hover:bg-primary/10 hover:text-primary"
                          title={item.label}
                        >
                          <Icon className="h-3.5 w-3.5" />
                          <span>{item.label}</span>
                        </Button>
                      </Link>
                    );
                  })}
                </CardFooter>
              </Card>
            );
          })}
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
