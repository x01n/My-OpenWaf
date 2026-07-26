"use client";

import { useMemo, useState, useSyncExternalStore } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-header";
import { useSites, useSiteDelete, useSiteStart, useSiteStop } from "@/hooks/use-api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { MetricTile } from "@/components/metric-tile";
import { toast } from "sonner";
import {
  IconLayoutGrid,
  IconList,
  IconPlayerPause,
  IconPlayerPlay,
  IconPlus,
  IconSearch,
  IconShieldCheck,
  IconWorld,
  IconWorldOff,
} from "@tabler/icons-react";
import type { Site } from "@/lib/types";
import { SiteFormDialog } from "./components/site-form-dialog";
import { SiteCard } from "./components/site-card";
import { SiteTable } from "./components/site-table";

/** 列表展现形式 */
type ViewMode = "table" | "grid";
/** 运行状态筛选 */
type StatusFilter = "all" | "running" | "stopped";

/** 视图偏好的本地存储键 */
const VIEW_STORAGE_KEY = "owaf.sites.view";

/**
 * 视图偏好的外部存储。
 *
 * 静态导出会预渲染这个页面，直接在 state 初始值里读 localStorage 会造成水合不一致，
 * 在 effect 里 setState 又会引发级联渲染。这里用 `useSyncExternalStore` 的标准做法：
 * 服务端快照固定返回默认视图，客户端水合后再切到用户偏好。
 */
const viewListeners = new Set<() => void>();
let cachedView: ViewMode | null = null;

/** @returns {ViewMode} 客户端当前视图偏好（缓存以保证快照引用稳定） */
function getViewSnapshot(): ViewMode {
  if (cachedView === null) {
    const saved = window.localStorage.getItem(VIEW_STORAGE_KEY);
    cachedView = saved === "grid" || saved === "table" ? saved : "table";
  }
  return cachedView;
}

/** @returns {ViewMode} 预渲染阶段使用的默认视图 */
function getViewServerSnapshot(): ViewMode {
  return "table";
}

/**
 * @param {() => void} onChange 变更回调
 * @returns {() => void} 取消订阅
 */
function subscribeView(onChange: () => void): () => void {
  viewListeners.add(onChange);
  return () => {
    viewListeners.delete(onChange);
  };
}

/**
 * 写入并广播视图偏好。
 * @param {ViewMode} next 目标视图
 */
function setStoredView(next: ViewMode): void {
  cachedView = next;
  window.localStorage.setItem(VIEW_STORAGE_KEY, next);
  viewListeners.forEach((listener) => listener());
}

export default function SitesPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const view = useSyncExternalStore(
    subscribeView,
    getViewSnapshot,
    getViewServerSnapshot
  );
  const [showForm, setShowForm] = useState(false);
  const [editingSite, setEditingSite] = useState<Site | null>(null);
  const [deletingSite, setDeletingSite] = useState<Site | null>(null);

  const { data, isLoading, error } = useSites({ page: 1, page_size: 50 });
  const deleteSite = useSiteDelete();
  const startSite = useSiteStart();
  const stopSite = useSiteStop();

  const handleViewChange = (next: string) => {
    if (next !== "grid" && next !== "table") return;
    setStoredView(next);
  };

  const allItems = useMemo(() => data?.items || [], [data?.items]);
  const total = data?.total || 0;

  /**
   * 统计口径：`total` 是后端返回的全局总数；运行中/已停止/维护中只能基于
   * 已加载的这一页数据统计。当总数超过已加载数量时在指标区标注口径。
   */
  const loadedCount = allItems.length;
  const isPartialScope = total > loadedCount;
  const runningCount = useMemo(
    () => allItems.filter((s) => s.enabled).length,
    [allItems]
  );
  const maintenanceCount = useMemo(
    () => allItems.filter((s) => s.maintenance_enabled).length,
    [allItems]
  );

  const items = useMemo(() => {
    const keyword = search.trim().toLowerCase();
    return allItems.filter((site) => {
      if (keyword && !site.host.toLowerCase().includes(keyword)) return false;
      if (statusFilter === "running" && !site.enabled) return false;
      if (statusFilter === "stopped" && site.enabled) return false;
      return true;
    });
  }, [allItems, search, statusFilter]);

  const isFiltering = search.trim() !== "" || statusFilter !== "all";

  const handleDelete = async () => {
    if (!deletingSite) return;
    try {
      await deleteSite.execute(deletingSite.id);
      toast.success(t("sites.deleteSuccess"));
    } catch {
      toast.error(t("common.deleteFailed"));
    } finally {
      setDeletingSite(null);
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

  const handleEdit = (site: Site) => {
    setEditingSite(site);
    setShowForm(true);
  };

  const openCreate = () => {
    setEditingSite(null);
    setShowForm(true);
  };

  const actionHandlers = {
    onEdit: handleEdit,
    onToggle: handleToggle,
    onDelete: setDeletingSite,
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("sites.title")}
        description={t("sites.description")}
        titleExtra={
          <Badge variant="secondary" className="h-5 px-2 text-xs">
            {t("common.total", { count: total })}
          </Badge>
        }
        actions={
          <Button className="h-9" onClick={openCreate}>
            <IconPlus className="size-4" />
            {t("sites.add")}
          </Button>
        }
      />

      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {error.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}

      {/* 概览指标 */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricTile
          title={t("sites.total")}
          value={String(total)}
          rawValue={total}
          icon={<IconWorld className="size-3.5" />}
          tone="accent"
          description={t("sites.stats.totalDesc")}
        />
        <MetricTile
          title={t("sites.running")}
          value={String(runningCount)}
          rawValue={runningCount}
          icon={<IconPlayerPlay className="size-3.5" />}
          tone="success"
          description={
            isPartialScope
              ? t("sites.stats.currentPageScope", { count: loadedCount })
              : t("sites.stats.runningDesc")
          }
        />
        <MetricTile
          title={t("sites.stopped")}
          value={String(loadedCount - runningCount)}
          rawValue={loadedCount - runningCount}
          icon={<IconWorldOff className="size-3.5" />}
          tone="danger"
          description={
            isPartialScope
              ? t("sites.stats.currentPageScope", { count: loadedCount })
              : t("sites.stats.stoppedDesc")
          }
        />
        <MetricTile
          title={t("sites.maintenanceMode")}
          value={String(maintenanceCount)}
          rawValue={maintenanceCount}
          icon={<IconPlayerPause className="size-3.5" />}
          tone="warning"
          description={
            isPartialScope
              ? t("sites.stats.currentPageScope", { count: loadedCount })
              : t("sites.stats.maintenanceDesc")
          }
        />
      </div>

      {/* 工具栏：搜索 + 状态筛选 + 视图切换 */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-56 flex-1 sm:max-w-xs">
          <IconSearch className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={t("sites.searchPlaceholder")}
            className="h-9 ps-8"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <ToggleGroup
          type="single"
          variant="outline"
          size="sm"
          value={statusFilter}
          onValueChange={(v) => v && setStatusFilter(v as StatusFilter)}
          className="shrink-0"
        >
          <ToggleGroupItem value="all" className="px-3 text-xs">
            {t("sites.filter.all")}
          </ToggleGroupItem>
          <ToggleGroupItem value="running" className="px-3 text-xs">
            {t("sites.running")}
          </ToggleGroupItem>
          <ToggleGroupItem value="stopped" className="px-3 text-xs">
            {t("sites.stopped")}
          </ToggleGroupItem>
        </ToggleGroup>

        <div className="ms-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground tabular-nums">
            {t("sites.filter.matched", { count: items.length })}
          </span>
          <ToggleGroup
            type="single"
            variant="outline"
            size="sm"
            value={view}
            onValueChange={handleViewChange}
            className="shrink-0"
          >
            <Tooltip>
              <TooltipTrigger asChild>
                <ToggleGroupItem value="table" aria-label={t("sites.view.list")}>
                  <IconList className="size-4" />
                </ToggleGroupItem>
              </TooltipTrigger>
              <TooltipContent>{t("sites.view.list")}</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <ToggleGroupItem value="grid" aria-label={t("sites.view.grid")}>
                  <IconLayoutGrid className="size-4" />
                </ToggleGroupItem>
              </TooltipTrigger>
              <TooltipContent>{t("sites.view.grid")}</TooltipContent>
            </Tooltip>
          </ToggleGroup>
        </div>
      </div>

      {/* 内容区 */}
      {isLoading ? (
        view === "grid" ? (
          <div className="grid grid-cols-[repeat(auto-fill,minmax(320px,1fr))] gap-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-48 rounded-xl" />
            ))}
          </div>
        ) : (
          <Skeleton className="h-64 rounded-xl" />
        )
      ) : allItems.length === 0 ? (
        <EmptyState
          icon={IconShieldCheck}
          title={t("sites.empty")}
          description={t("sites.emptyHint")}
          action={
            <Button onClick={openCreate}>
              <IconPlus className="size-4" />
              {t("sites.add")}
            </Button>
          }
          className="py-16"
        />
      ) : items.length === 0 ? (
        <EmptyState
          icon={IconSearch}
          title={t("sites.filter.noMatch")}
          description={t("sites.filter.noMatchHint")}
          action={
            <Button
              variant="outline"
              onClick={() => {
                setSearch("");
                setStatusFilter("all");
              }}
            >
              {t("sites.filter.reset")}
            </Button>
          }
          className="py-12"
        />
      ) : view === "grid" ? (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(320px,1fr))] gap-3">
          {items.map((site) => (
            <SiteCard key={site.id} site={site} {...actionHandlers} />
          ))}
        </div>
      ) : (
        <SiteTable sites={items} {...actionHandlers} />
      )}

      {isFiltering && items.length > 0 && (
        <p className="text-center text-xs text-muted-foreground">
          {t("sites.filter.filteredHint", {
            count: items.length,
            total: allItems.length,
          })}
        </p>
      )}

      <SiteFormDialog
        open={showForm}
        onOpenChange={setShowForm}
        site={editingSite}
      />

      <ConfirmDialog
        open={!!deletingSite}
        onOpenChange={() => setDeletingSite(null)}
        title={t("sites.deleteTitle")}
        description={t("sites.deleteConfirm")}
        confirmText={t("common.delete")}
        onConfirm={handleDelete}
        loading={deleteSite.loading}
      />
    </div>
  );
}
