"use client";

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-header";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { toast } from "sonner";
import {
  useLuaPlugins,
  useLuaPluginDelete,
  useLuaPluginToggle,
  useLuaPluginStats,
  useSites,
} from "@/hooks/use-api";
import {
  IconPlus,
  IconTrash,
  IconEdit,
  IconCode,
  IconInfoCircle,
} from "@tabler/icons-react";
import type { LuaPlugin, LuaPluginStage } from "@/lib/types";
import { PluginEditorDialog } from "./components/plugin-editor-dialog";
import {
  buildLuaStatsIndex,
  lookupLuaStat,
  LuaRuntimeStatsAlert,
  LuaRuntimeStatsCell,
  LuaRuntimeStatsSummary,
} from "./components/runtime-stats";

/** 阶段徽章配色：pre 与 post 的执行时机不同，用不同色系区分以免误读。 */
const STAGE_CLASS: Record<LuaPluginStage, string> = {
  pre: "border-sky-500/30 bg-sky-500/12 text-sky-700 dark:border-sky-400/30 dark:bg-sky-400/15 dark:text-sky-300",
  post: "border-violet-500/30 bg-violet-500/12 text-violet-700 dark:border-violet-400/30 dark:bg-violet-400/15 dark:text-violet-300",
};

/**
 * Lua 自定义策略脚本管理页。
 *
 * @returns {React.ReactElement} 页面元素
 */
export default function LuaPluginsPage() {
  const { t } = useTranslation();

  const { data, isLoading, error, mutate: refresh } = useLuaPlugins();
  const plugins = useMemo(() => data?.items || [], [data]);

  // 运行时统计是独立的只读接口：拉取失败只让统计区降级，不影响脚本的增删改查。
  const {
    data: statsData,
    isLoading: statsLoading,
    error: statsError,
  } = useLuaPluginStats();
  const statsItems = statsData?.items;
  const statsIndex = useMemo(() => buildLuaStatsIndex(statsItems), [statsItems]);
  // 轮询期间的一次失败不该抹掉已有数据：SWR 会同时保留 data 和 error，
  // 此时继续展示上一轮的真实计数，只有从未拿到过数据才降级为「不可用」。
  const statsUnavailable = Boolean(statsError) && statsItems === undefined;

  const { data: sitesData } = useSites({ page_size: 500 });
  const siteNameMap = useMemo(() => {
    const map = new Map<number, string>();
    for (const s of sitesData?.items || []) map.set(s.id, s.host);
    return map;
  }, [sitesData]);

  const { execute: deletePlugin, loading: deleteLoading } =
    useLuaPluginDelete();
  const { execute: togglePlugin } = useLuaPluginToggle();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<LuaPlugin | null>(null);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  // 每次打开都递增，作为编辑器的 key 强制重挂载，使表单态从 editing 重新初始化。
  // 只在打开时变化，因此不会打断对话框的关闭动画。
  const [dialogSeq, setDialogSeq] = useState(0);

  const openCreate = () => {
    setEditing(null);
    setDialogSeq((n) => n + 1);
    setDialogOpen(true);
  };

  const openEdit = (plugin: LuaPlugin) => {
    setEditing(plugin);
    setDialogSeq((n) => n + 1);
    setDialogOpen(true);
  };

  const handleToggle = async (plugin: LuaPlugin, enabled: boolean) => {
    try {
      await togglePlugin({ id: plugin.id, enabled });
      refresh();
    } catch {
      toast.error(t("common.updateFailed"));
    }
  };

  const confirmDelete = async () => {
    if (deleteId === null) return;
    try {
      await deletePlugin(deleteId);
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
      title: t("luaPlugins.name"),
      render: (row: LuaPlugin) => (
        <span className="font-medium">{row.name}</span>
      ),
    },
    {
      key: "stage",
      title: t("luaPlugins.stage"),
      width: "120px",
      render: (row: LuaPlugin) => (
        <Badge variant="outline" className={STAGE_CLASS[row.stage]}>
          {row.stage === "pre"
            ? t("luaPlugins.stagePre")
            : t("luaPlugins.stagePost")}
        </Badge>
      ),
    },
    {
      key: "priority",
      title: t("luaPlugins.priority"),
      width: "90px",
      render: (row: LuaPlugin) => (
        <span className="font-mono text-sm">{row.priority}</span>
      ),
    },
    {
      key: "scope",
      title: t("luaPlugins.scope"),
      width: "150px",
      render: (row: LuaPlugin) =>
        row.site_id === undefined || row.site_id === null ? (
          <Badge variant="secondary">{t("luaPlugins.scopeGlobal")}</Badge>
        ) : (
          <Badge variant="outline">
            {siteNameMap.get(row.site_id) || `#${row.site_id}`}
          </Badge>
        ),
    },
    {
      key: "timeout_ms",
      title: t("luaPlugins.timeout"),
      width: "110px",
      render: (row: LuaPlugin) => (
        <span className="font-mono text-sm text-muted-foreground">
          {row.timeout_ms > 0
            ? `${row.timeout_ms}ms`
            : t("luaPlugins.timeoutDefault")}
        </span>
      ),
    },
    {
      key: "description",
      title: t("common.description"),
      render: (row: LuaPlugin) => {
        if (!row.description) {
          return <span className="text-muted-foreground">-</span>;
        }
        return (
          <TooltipProvider delayDuration={200}>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="block max-w-[240px] truncate text-sm text-muted-foreground">
                  {row.description}
                </span>
              </TooltipTrigger>
              <TooltipContent className="max-w-md break-all whitespace-pre-wrap">
                {row.description}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        );
      },
    },
    {
      key: "enabled",
      title: t("luaPlugins.enabled"),
      width: "80px",
      render: (row: LuaPlugin) => (
        <Switch
          checked={row.enabled}
          onCheckedChange={(v) => handleToggle(row, v)}
        />
      ),
    },
    {
      key: "runtime",
      title: t("luaPlugins.stats.column"),
      width: "230px",
      render: (row: LuaPlugin) => (
        <LuaRuntimeStatsCell
          plugin={row}
          stat={lookupLuaStat(statsIndex, row)}
          loading={statsLoading}
          unavailable={statsUnavailable}
        />
      ),
    },
    {
      key: "op",
      title: t("common.action"),
      width: "100px",
      render: (row: LuaPlugin) => (
        <div className="flex items-center gap-1">
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
      <PageHeader
        icon={<IconCode className="h-6 w-6" />}
        title={t("luaPlugins.title")}
        description={t("luaPlugins.description")}
        actions={
          <Button onClick={openCreate}>
            <IconPlus className="h-4 w-4" />
            {t("luaPlugins.add")}
          </Button>
        }
      />

      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {(error as Error)?.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}

      <Alert>
        <IconInfoCircle className="h-4 w-4" />
        <AlertTitle>{t("luaPlugins.pipelineTitle")}</AlertTitle>
        <AlertDescription className="space-y-1">
          <span>{t("luaPlugins.stagePreDesc")}</span>
          <span>{t("luaPlugins.stagePostDesc")}</span>
          <span className="font-medium text-foreground">
            {t("luaPlugins.stagePostOverride")}
          </span>
        </AlertDescription>
      </Alert>

      <LuaRuntimeStatsAlert items={statsItems} />

      <LuaRuntimeStatsSummary
        items={statsItems}
        loading={statsLoading}
        error={statsUnavailable ? statsError : undefined}
      />

      <DataTable<LuaPlugin>
        columns={columns}
        data={plugins}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("luaPlugins.empty")}
      />

      <PluginEditorDialog
        key={dialogSeq}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        editing={editing}
        onSaved={refresh}
      />

      <ConfirmDialog
        open={deleteId !== null}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("common.confirmDeleteTitle")}
        description={t("luaPlugins.deleteConfirm")}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  );
}
