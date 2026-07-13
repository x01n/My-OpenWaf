"use client";

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  useThreatIntelFeeds,
  useThreatIntelMutation,
  useThreatIntelDelete,
  useThreatIntelSync,
  useThreatIntelSyncLogs,
  useSites,
} from "@/hooks/use-api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";
import {
  IconPlus,
  IconTrash,
  IconEdit,
  IconRefresh,
  IconShieldCheck,
  IconBan,
  IconWorldBolt,
  IconHistory,
  IconList,
} from "@tabler/icons-react";
import type { ThreatIntelFeed, ThreatIntelSyncLog } from "@/lib/types";

/** 作用域下拉的全局选项标识值（Select 不接受空字符串作为 value） */
const SCOPE_GLOBAL = "global";

/** 同步历史筛选的“全部”选项标识值 */
const FILTER_ALL = "all";

/** 常用同步间隔（秒） */
const INTERVAL_OPTIONS = [
  { value: 600, key: "interval10m" },
  { value: 1800, key: "interval30m" },
  { value: 3600, key: "interval1h" },
  { value: 21600, key: "interval6h" },
  { value: 86400, key: "interval24h" },
] as const;

interface FeedForm {
  name: string;
  url: string;
  kind: "blacklist" | "whitelist";
  action: "intercept" | "drop";
  sync_interval: number;
  scope: string;
  enabled: boolean;
}

const emptyForm: FeedForm = {
  name: "",
  url: "",
  kind: "blacklist",
  action: "intercept",
  sync_interval: 3600,
  scope: SCOPE_GLOBAL,
  enabled: true,
};

export default function ThreatIntelPage() {
  const { t } = useTranslation();

  return (
    <div className="space-y-4">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
          <IconWorldBolt className="h-6 w-6" />
          {t("threatIntel.title")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("threatIntel.description")}
        </p>
      </div>

      <Tabs defaultValue="feeds" className="space-y-4">
        <TabsList>
          <TabsTrigger value="feeds">
            <IconList className="mr-1 h-4 w-4" />
            {t("threatIntel.tabs.feeds")}
          </TabsTrigger>
          <TabsTrigger value="history">
            <IconHistory className="mr-1 h-4 w-4" />
            {t("threatIntel.tabs.syncHistory")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="feeds">
          <FeedsTab />
        </TabsContent>

        <TabsContent value="history">
          <SyncHistoryTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/**
 * 订阅源 Tab：完整保留原有 CRUD 与手动同步逻辑。
 */
function FeedsTab() {
  const { t } = useTranslation();

  const { data, isLoading, mutate: refresh } = useThreatIntelFeeds();
  const feeds = useMemo(() => data?.items || [], [data]);

  // 站点列表用于作用域下拉与站点名映射（显示名用 host）
  const { data: sitesData } = useSites({ page_size: 500 });
  const sites = useMemo(() => sitesData?.items || [], [sitesData]);
  const siteNameMap = useMemo(() => {
    const map = new Map<number, string>();
    for (const s of sites) map.set(s.id, s.host);
    return map;
  }, [sites]);

  const { execute: mutateFeed, loading: mutateLoading } = useThreatIntelMutation();
  const { execute: deleteFeed, loading: deleteLoading } = useThreatIntelDelete();
  const { execute: syncFeed } = useThreatIntelSync();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [form, setForm] = useState<FeedForm>(emptyForm);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  // 单行同步中的 ID 集合，用于按钮 loading
  const [syncingIds, setSyncingIds] = useState<Set<number>>(new Set());

  /** 将站点 ID 映射为可读作用域名称 */
  const scopeLabel = (siteId?: number | null) => {
    if (siteId === undefined || siteId === null) return t("threatIntel.scopeGlobal");
    return siteNameMap.get(siteId) || `#${siteId}`;
  };

  /** 将秒数格式化为友好的间隔文案 */
  const formatInterval = (seconds: number) => {
    if (seconds > 0 && seconds % 3600 === 0) {
      return t("threatIntel.hours", { count: seconds / 3600 });
    }
    if (seconds > 0 && seconds % 60 === 0) {
      return t("threatIntel.minutes", { count: seconds / 60 });
    }
    return t("threatIntel.seconds", { count: seconds });
  };

  const openCreate = () => {
    setEditId(null);
    setForm(emptyForm);
    setDialogOpen(true);
  };

  const openEdit = (feed: ThreatIntelFeed) => {
    setEditId(feed.id);
    setForm({
      name: feed.name,
      url: feed.url,
      kind: feed.kind,
      action: feed.action,
      sync_interval: feed.sync_interval,
      scope:
        feed.site_id === undefined || feed.site_id === null
          ? SCOPE_GLOBAL
          : String(feed.site_id),
      enabled: feed.enabled,
    });
    setDialogOpen(true);
  };

  const handleSubmit = async () => {
    try {
      const payload: Partial<ThreatIntelFeed> = {
        name: form.name.trim(),
        url: form.url.trim(),
        kind: form.kind,
        action: form.action,
        sync_interval: form.sync_interval,
        enabled: form.enabled,
        site_id: form.scope === SCOPE_GLOBAL ? null : Number(form.scope),
      };
      await mutateFeed({ id: editId ?? undefined, data: payload });
      toast.success(
        editId ? t("common.updateSuccess") : t("common.createSuccess")
      );
      setDialogOpen(false);
      refresh();
    } catch {
      toast.error(editId ? t("common.updateFailed") : t("common.createFailed"));
    }
  };

  /** 行内启用开关：合并现有字段避免覆盖，仅切换 enabled */
  const handleToggleEnabled = async (feed: ThreatIntelFeed, enabled: boolean) => {
    try {
      await mutateFeed({ id: feed.id, data: { enabled } });
      refresh();
    } catch {
      toast.error(t("common.updateFailed"));
    }
  };

  const handleSync = async (id: number) => {
    setSyncingIds((prev) => new Set(prev).add(id));
    try {
      await syncFeed(id);
      toast.success(t("threatIntel.syncSuccess"));
      refresh();
    } catch {
      toast.error(t("threatIntel.syncFailed"));
    } finally {
      setSyncingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const confirmDelete = async () => {
    if (deleteId === null) return;
    try {
      await deleteFeed(deleteId);
      toast.success(t("common.deleteSuccess"));
      setDeleteId(null);
      refresh();
    } catch {
      toast.error(t("common.deleteFailed"));
    }
  };

  const columns = [
    {
      key: "name",
      title: t("threatIntel.name"),
      render: (row: ThreatIntelFeed) => (
        <span className="font-medium">{row.name}</span>
      ),
    },
    {
      key: "url",
      title: t("threatIntel.url"),
      render: (row: ThreatIntelFeed) => (
        <span
          className="block max-w-[280px] truncate font-mono text-xs text-muted-foreground"
          title={row.url}
        >
          {row.url}
        </span>
      ),
    },
    {
      key: "kind",
      title: t("threatIntel.kind"),
      width: "110px",
      render: (row: ThreatIntelFeed) =>
        row.kind === "whitelist" ? (
          <div className="flex items-center gap-1.5">
            <IconShieldCheck className="h-4 w-4 text-primary" />
            <Badge variant="default">{t("threatIntel.whitelist")}</Badge>
          </div>
        ) : (
          <div className="flex items-center gap-1.5">
            <IconBan className="h-4 w-4 text-destructive" />
            <Badge variant="destructive">{t("threatIntel.blacklist")}</Badge>
          </div>
        ),
    },
    {
      key: "action",
      title: t("threatIntel.action"),
      width: "100px",
      render: (row: ThreatIntelFeed) => (
        <Badge variant={row.action === "drop" ? "destructive" : "secondary"}>
          {row.action === "drop"
            ? t("threatIntel.actionDrop")
            : t("threatIntel.actionIntercept")}
        </Badge>
      ),
    },
    {
      key: "scope",
      title: t("threatIntel.scope"),
      width: "150px",
      render: (row: ThreatIntelFeed) =>
        row.site_id === undefined || row.site_id === null ? (
          <Badge variant="secondary">{t("threatIntel.scopeGlobal")}</Badge>
        ) : (
          <Badge variant="outline">{scopeLabel(row.site_id)}</Badge>
        ),
    },
    {
      key: "entry_count",
      title: t("threatIntel.entryCount"),
      width: "90px",
      render: (row: ThreatIntelFeed) => (
        <span className="font-mono text-sm">{row.entry_count}</span>
      ),
    },
    {
      key: "sync_interval",
      title: t("threatIntel.syncInterval"),
      width: "110px",
      render: (row: ThreatIntelFeed) => (
        <span className="text-sm text-muted-foreground">
          {formatInterval(row.sync_interval)}
        </span>
      ),
    },
    {
      key: "last_sync_at",
      title: t("threatIntel.lastSyncAt"),
      width: "150px",
      render: (row: ThreatIntelFeed) => (
        <span className="text-xs text-muted-foreground">
          {row.last_sync_at
            ? formatDate(row.last_sync_at)
            : t("threatIntel.neverSynced")}
        </span>
      ),
    },
    {
      key: "status",
      title: t("common.status"),
      width: "110px",
      render: (row: ThreatIntelFeed) =>
        row.last_error ? (
          <Badge variant="destructive" title={row.last_error}>
            {t("threatIntel.statusError")}
          </Badge>
        ) : (
          <Badge variant="secondary">{t("threatIntel.statusOk")}</Badge>
        ),
    },
    {
      key: "enabled",
      title: t("threatIntel.enabled"),
      width: "80px",
      render: (row: ThreatIntelFeed) => (
        <Switch
          checked={row.enabled}
          onCheckedChange={(v) => handleToggleEnabled(row, v)}
        />
      ),
    },
    {
      key: "op",
      title: t("common.action"),
      width: "140px",
      render: (row: ThreatIntelFeed) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => handleSync(row.id)}
            disabled={syncingIds.has(row.id)}
            title={t("threatIntel.sync")}
          >
            <IconRefresh
              className={
                syncingIds.has(row.id) ? "h-4 w-4 animate-spin" : "h-4 w-4"
              }
            />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => openEdit(row)}
            title={t("common.edit")}
          >
            <IconEdit className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => setDeleteId(row.id)}
            title={t("common.delete")}
          >
            <IconTrash className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={openCreate}>
          <IconPlus className="h-4 w-4" />
          {t("threatIntel.add")}
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={feeds}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("threatIntel.empty")}
      />

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editId ? t("threatIntel.editTitle") : t("threatIntel.addTitle")}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t("threatIntel.name")}</Label>
              <Input
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                placeholder={t("threatIntel.namePlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("threatIntel.url")}</Label>
              <Input
                value={form.url}
                onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                placeholder={t("threatIntel.urlPlaceholder")}
                className="font-mono text-sm"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t("threatIntel.kind")}</Label>
                <Select
                  value={form.kind}
                  onValueChange={(v) =>
                    setForm((f) => ({
                      ...f,
                      kind: v as "blacklist" | "whitelist",
                    }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="blacklist">
                      {t("threatIntel.blacklist")}
                    </SelectItem>
                    <SelectItem value="whitelist">
                      {t("threatIntel.whitelist")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t("threatIntel.action")}</Label>
                <Select
                  value={form.action}
                  onValueChange={(v) =>
                    setForm((f) => ({
                      ...f,
                      action: v as "intercept" | "drop",
                    }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="intercept">
                      {t("threatIntel.actionIntercept")}
                    </SelectItem>
                    <SelectItem value="drop">
                      {t("threatIntel.actionDrop")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t("threatIntel.syncInterval")}</Label>
              <Select
                value={String(form.sync_interval)}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, sync_interval: Number(v) }))
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INTERVAL_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={String(opt.value)}>
                      {t(`threatIntel.${opt.key}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t("threatIntel.syncIntervalHint")}
              </p>
            </div>
            <div className="space-y-2">
              <Label>{t("threatIntel.scope")}</Label>
              <Select
                value={form.scope}
                onValueChange={(v) => setForm((f) => ({ ...f, scope: v }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={SCOPE_GLOBAL}>
                    {t("threatIntel.scopeGlobal")}
                  </SelectItem>
                  {sites.map((s) => (
                    <SelectItem key={s.id} value={String(s.id)}>
                      {s.host}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t("threatIntel.scopeHint")}
              </p>
            </div>
            <div className="flex items-center justify-between">
              <Label>{t("threatIntel.enabled")}</Label>
              <Switch
                checked={form.enabled}
                onCheckedChange={(v) =>
                  setForm((f) => ({ ...f, enabled: v }))
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={
                mutateLoading || !form.name.trim() || !form.url.trim()
              }
            >
              {mutateLoading
                ? t("common.submitting")
                : editId
                  ? t("common.save")
                  : t("common.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleteId !== null}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("common.confirmDeleteTitle")}
        description={t("threatIntel.deleteConfirm")}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  );
}

/**
 * 将毫秒数格式化为可读的耗时字符串（>=1s 用 "X.Xs"，否则 "Xms"）。
 */
function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "-";
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  return `${ms}ms`;
}

/**
 * 同步历史 Tab：分页展示订阅源每次同步的结果，30 秒自动刷新。
 */
function SyncHistoryTab() {
  const { t } = useTranslation();

  const [page, setPage] = useState(1);
  const pageSize = 20;
  const [feedFilter, setFeedFilter] = useState<string>(FILTER_ALL);
  const [statusFilter, setStatusFilter] = useState<string>(FILTER_ALL);

  const { data: feedsData } = useThreatIntelFeeds();
  const feeds = useMemo(() => feedsData?.items || [], [feedsData]);

  const queryParams = useMemo(
    () => ({
      page,
      page_size: pageSize,
      feed_id:
        feedFilter === FILTER_ALL ? undefined : Number(feedFilter),
      status:
        statusFilter === FILTER_ALL
          ? undefined
          : (statusFilter as "success" | "failed"),
    }),
    [page, feedFilter, statusFilter],
  );

  const { data, isLoading } = useThreatIntelSyncLogs(queryParams);
  const items = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / pageSize) || 1;

  const handleFeedChange = (v: string) => {
    setFeedFilter(v);
    setPage(1);
  };
  const handleStatusChange = (v: string) => {
    setStatusFilter(v);
    setPage(1);
  };

  const columns = [
    {
      key: "time",
      title: t("threatIntel.syncHistory.columns.time"),
      width: "170px",
      render: (row: ThreatIntelSyncLog) => (
        <span className="text-xs text-muted-foreground">
          {formatDate(row.started_at || row.created_at)}
        </span>
      ),
    },
    {
      key: "feed",
      title: t("threatIntel.syncHistory.columns.feed"),
      render: (row: ThreatIntelSyncLog) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.feed_name || "-"}</span>
          <span className="text-xs text-muted-foreground">#{row.feed_id}</span>
        </div>
      ),
    },
    {
      key: "trigger",
      title: t("threatIntel.syncHistory.columns.trigger"),
      width: "90px",
      render: (row: ThreatIntelSyncLog) => (
        <Badge variant={row.trigger === "manual" ? "outline" : "secondary"}>
          {row.trigger === "manual"
            ? t("threatIntel.syncHistory.trigger.manual")
            : t("threatIntel.syncHistory.trigger.auto")}
        </Badge>
      ),
    },
    {
      key: "result",
      title: t("threatIntel.syncHistory.columns.result"),
      width: "90px",
      render: (row: ThreatIntelSyncLog) =>
        row.success ? (
          <Badge className="bg-teal-600 text-white hover:bg-teal-600/90">
            {t("threatIntel.syncHistory.result.success")}
          </Badge>
        ) : (
          <Badge variant="destructive">
            {t("threatIntel.syncHistory.result.failed")}
          </Badge>
        ),
    },
    {
      key: "duration",
      title: t("threatIntel.syncHistory.columns.duration"),
      width: "90px",
      render: (row: ThreatIntelSyncLog) => (
        <span className="font-mono text-sm">
          {formatDurationMs(row.duration_ms)}
        </span>
      ),
    },
    {
      key: "entries",
      title: t("threatIntel.syncHistory.columns.entries"),
      width: "90px",
      render: (row: ThreatIntelSyncLog) => (
        <span className="font-mono text-sm">
          {row.success ? row.entries_added : "-"}
        </span>
      ),
    },
    {
      key: "error",
      title: t("threatIntel.syncHistory.columns.error"),
      render: (row: ThreatIntelSyncLog) => {
        if (!row.error) return <span className="text-muted-foreground">-</span>;
        return (
          <TooltipProvider delayDuration={200}>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="block max-w-[320px] truncate font-mono text-xs text-destructive">
                  {row.error}
                </span>
              </TooltipTrigger>
              <TooltipContent className="max-w-md whitespace-pre-wrap break-all">
                {row.error}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        );
      },
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid gap-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="space-y-1.5">
          <Label className="text-xs">
            {t("threatIntel.syncHistory.filter.feed")}
          </Label>
          <Select value={feedFilter} onValueChange={handleFeedChange}>
            <SelectTrigger className="h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={FILTER_ALL}>
                {t("threatIntel.syncHistory.filter.allFeeds")}
              </SelectItem>
              {feeds.map((f) => (
                <SelectItem key={f.id} value={String(f.id)}>
                  {f.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">
            {t("threatIntel.syncHistory.filter.status")}
          </Label>
          <Select value={statusFilter} onValueChange={handleStatusChange}>
            <SelectTrigger className="h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={FILTER_ALL}>
                {t("threatIntel.syncHistory.filter.allStatus")}
              </SelectItem>
              <SelectItem value="success">
                {t("threatIntel.syncHistory.result.success")}
              </SelectItem>
              <SelectItem value="failed">
                {t("threatIntel.syncHistory.result.failed")}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <DataTable<ThreatIntelSyncLog>
        columns={columns}
        data={items}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("threatIntel.syncHistory.empty")}
      />

      {totalPages > 1 && (
        <Pagination>
          <PaginationContent>
            <PaginationItem>
              <PaginationPrevious
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className={
                  page <= 1 ? "pointer-events-none opacity-50" : ""
                }
              />
            </PaginationItem>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const pageNum = i + 1;
              return (
                <PaginationItem key={pageNum}>
                  <PaginationLink
                    isActive={page === pageNum}
                    onClick={() => setPage(pageNum)}
                  >
                    {pageNum}
                  </PaginationLink>
                </PaginationItem>
              );
            })}
            {totalPages > 5 && (
              <PaginationItem>
                <PaginationEllipsis />
              </PaginationItem>
            )}
            <PaginationItem>
              <PaginationNext
                onClick={() =>
                  setPage((p) => Math.min(totalPages, p + 1))
                }
                className={
                  page >= totalPages ? "pointer-events-none opacity-50" : ""
                }
              />
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      )}
    </div>
  );
}
