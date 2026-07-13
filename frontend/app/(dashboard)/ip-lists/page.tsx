"use client";

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  useIPLists,
  useIPListMutation,
  useIPListDelete,
  useSites,
  usePresetBotWhitelist,
  usePresetBotWhitelistSeed,
} from "@/hooks/use-api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
import { toast } from "sonner";
import {
  IconPlus,
  IconTrash,
  IconShieldCheck,
  IconBan,
  IconUpload,
  IconRobot,
} from "@tabler/icons-react";
import type { IPEntry } from "@/lib/types";

/** 作用域下拉的全局选项标识值（Select 不接受空字符串作为 value） */
const SCOPE_GLOBAL = "global";

export default function IPListsPage() {
  const { t } = useTranslation();

  // 作用域：全局或某站点 ID（字符串形式，SCOPE_GLOBAL 表示全局）
  const [scope, setScope] = useState<string>(SCOPE_GLOBAL);
  const scopeSiteId = scope === SCOPE_GLOBAL ? undefined : Number(scope);

  // 站点列表用于作用域下拉与站点名映射
  const { data: sitesData } = useSites({ page_size: 500 });
  const sites = useMemo(() => sitesData?.items || [], [sitesData]);
  const siteNameMap = useMemo(() => {
    const map = new Map<number, string>();
    for (const s of sites) map.set(s.id, s.host);
    return map;
  }, [sites]);

  // 全局条目始终查询；站点条目仅在选中站点时按需查询
  const {
    data: globalData,
    isLoading: globalLoading,
    mutate: mutateGlobal,
  } = useIPLists();
  const {
    data: siteData,
    isLoading: siteLoading,
    mutate: mutateSite,
  } = useIPLists(
    scopeSiteId !== undefined ? { site_id: scopeSiteId } : undefined,
    scopeSiteId !== undefined
  );

  const { execute: mutateIP, loading: mutateLoading } = useIPListMutation();
  const { execute: deleteIP, loading: deleteLoading } = useIPListDelete();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [bulkDialogOpen, setBulkDialogOpen] = useState(false);
  const [presetDialogOpen, setPresetDialogOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterKind, setFilterKind] = useState<
    "all" | "whitelist" | "blacklist"
  >("all");

  // 预置爬虫白名单：仅在对话框打开时拉取预览，避免首屏无谓请求
  const {
    data: presetData,
    isLoading: presetLoading,
  } = usePresetBotWhitelist(presetDialogOpen);
  const {
    execute: seedPreset,
    loading: presetSeeding,
  } = usePresetBotWhitelistSeed();

  const [form, setForm] = useState({
    value: "",
    kind: "blacklist" as "blacklist" | "whitelist",
    action: "intercept" as "intercept" | "drop",
    note: "",
    scope: SCOPE_GLOBAL as string,
  });
  const [bulkText, setBulkText] = useState("");
  const [bulkKind, setBulkKind] = useState<"blacklist" | "whitelist">(
    "blacklist"
  );
  const [bulkScope, setBulkScope] = useState<string>(SCOPE_GLOBAL);

  /** 刷新当前作用域涉及的数据源 */
  const refresh = () => {
    mutateGlobal();
    if (scopeSiteId !== undefined) mutateSite();
  };

  // 选中站点时合并展示 站点条目 + 全局条目，符合实际防护并集语义
  const entries: IPEntry[] = useMemo(() => {
    const globalItems = globalData?.items || [];
    if (scopeSiteId === undefined) return globalItems;
    const siteItems = siteData?.items || [];
    return [...siteItems, ...globalItems];
  }, [globalData, siteData, scopeSiteId]);

  const isLoading =
    globalLoading || (scopeSiteId !== undefined && siteLoading);

  const filteredEntries = entries.filter((entry) => {
    const matchesSearch =
      !searchQuery ||
      (entry.value && entry.value.includes(searchQuery)) ||
      (entry.note && entry.note.includes(searchQuery));
    const matchesKind = filterKind === "all" || entry.kind === filterKind;
    return matchesSearch && matchesKind;
  });

  /** 将站点 ID 映射为可读作用域名称 */
  const scopeLabel = (siteId?: number | null) => {
    if (siteId === undefined || siteId === null) return t("ipLists.scopeGlobal");
    return siteNameMap.get(siteId) || `#${siteId}`;
  };

  const handleCreate = async () => {
    try {
      const payload: Partial<IPEntry> = {
        value: form.value.trim(),
        kind: form.kind,
        action: form.action,
        note: form.note || undefined,
        site_id: form.scope === SCOPE_GLOBAL ? null : Number(form.scope),
      };
      await mutateIP({ data: payload });
      toast.success(t("common.createSuccess"));
      setDialogOpen(false);
      resetForm();
      refresh();
    } catch {
      toast.error(t("common.createFailed"));
    }
  };

  const handleBulkImport = async () => {
    const lines = bulkText
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (lines.length === 0) {
      toast.error(t("ipLists.bulkEmpty"));
      return;
    }
    const siteId = bulkScope === SCOPE_GLOBAL ? null : Number(bulkScope);
    let successCount = 0;
    let failCount = 0;
    for (const line of lines) {
      try {
        const entry: Partial<IPEntry> = {
          kind: bulkKind,
          value: line,
          action: "intercept",
          site_id: siteId,
        };
        await mutateIP({ data: entry });
        successCount++;
      } catch {
        failCount++;
      }
    }
    toast.success(
      t("ipLists.bulkResult", { success: successCount, fail: failCount })
    );
    setBulkDialogOpen(false);
    setBulkText("");
    refresh();
  };

  const confirmDelete = async () => {
    if (!deleteId) return;
    try {
      await deleteIP(deleteId);
      toast.success(t("common.deleteSuccess"));
      setDeleteId(null);
      refresh();
    } catch {
      toast.error(t("common.deleteFailed"));
    }
  };

  /** 应用预置爬虫白名单：调用 seed 后按返回统计给出提示并刷新列表 */
  const handleApplyPresetBots = async () => {
    try {
      const res = await seedPreset(undefined);
      toast.success(
        t("ipLists.presetBots.result", {
          added: res.added,
          skipped: res.skipped,
        })
      );
      setPresetDialogOpen(false);
      refresh();
    } catch {
      toast.error(t("ipLists.presetBots.applyFailed"));
    }
  };

  const resetForm = () => {
    setForm({
      value: "",
      kind: "blacklist",
      action: "intercept",
      note: "",
      scope: SCOPE_GLOBAL,
    });
  };

  const columns = [
    {
      key: "value",
      title: t("ipLists.ipCidr"),
      render: (row: IPEntry) => (
        <span className="font-mono text-sm">{row.value || "-"}</span>
      ),
    },
    {
      key: "kind",
      title: t("common.type"),
      width: "120px",
      render: (row: IPEntry) => (
        <div className="flex items-center gap-1.5">
          {row.kind === "whitelist" ? (
            <>
              <IconShieldCheck className="h-4 w-4 text-primary" />
              <Badge variant="default">{t("ipLists.whitelist")}</Badge>
            </>
          ) : (
            <>
              <IconBan className="h-4 w-4 text-destructive" />
              <Badge variant="destructive">{t("ipLists.blacklist")}</Badge>
            </>
          )}
        </div>
      ),
    },
    {
      key: "scope",
      title: t("ipLists.scope"),
      width: "160px",
      render: (row: IPEntry) =>
        row.site_id === undefined || row.site_id === null ? (
          <Badge variant="secondary">{t("ipLists.scopeGlobal")}</Badge>
        ) : (
          <Badge variant="outline">{scopeLabel(row.site_id)}</Badge>
        ),
    },
    {
      key: "action",
      title: t("ipLists.action"),
      width: "110px",
      render: (row: IPEntry) => (
        <Badge variant={row.action === "drop" ? "destructive" : "secondary"}>
          {row.action === "drop"
            ? t("ipLists.actionDrop")
            : t("ipLists.actionIntercept")}
        </Badge>
      ),
    },
    {
      key: "note",
      title: t("ipLists.reason"),
      render: (row: IPEntry) => (
        <span className="text-sm text-muted-foreground">{row.note || "-"}</span>
      ),
    },
    {
      key: "op",
      title: t("common.action"),
      width: "80px",
      render: (row: IPEntry) => (
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setDeleteId(row.id)}
          title={t("common.delete")}
        >
          <IconTrash className="h-4 w-4 text-destructive" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            {t("ipLists.title")}
          </h1>
          <p className="text-sm text-muted-foreground">
            {t("ipLists.description")}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => setPresetDialogOpen(true)}
          >
            <IconRobot className="h-4 w-4" />
            {t("ipLists.presetBots.button")}
          </Button>
          <Button variant="outline" onClick={() => setBulkDialogOpen(true)}>
            <IconUpload className="h-4 w-4" />
            {t("ipLists.bulkImport")}
          </Button>
          <Button onClick={() => setDialogOpen(true)}>
            <IconPlus className="h-4 w-4" />
            {t("ipLists.add")}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder={t("ipLists.searchPlaceholder")}
          className="w-64"
        />
        <Select value={scope} onValueChange={setScope}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder={t("ipLists.scope")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={SCOPE_GLOBAL}>
              {t("ipLists.scopeGlobal")}
            </SelectItem>
            {sites.map((s) => (
              <SelectItem key={s.id} value={String(s.id)}>
                {s.host}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={filterKind}
          onValueChange={(v) =>
            setFilterKind(v as "all" | "whitelist" | "blacklist")
          }
        >
          <SelectTrigger className="w-32">
            <SelectValue placeholder={t("common.all")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("common.all")}</SelectItem>
            <SelectItem value="whitelist">{t("ipLists.whitelist")}</SelectItem>
            <SelectItem value="blacklist">{t("ipLists.blacklist")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        data={filteredEntries}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("ipLists.empty")}
      />

      <Dialog
        open={dialogOpen}
        onOpenChange={(open) => {
          setDialogOpen(open);
          if (!open) resetForm();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("ipLists.addTitle")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t("ipLists.ipOrCidr")}</Label>
              <Input
                value={form.value}
                onChange={(e) =>
                  setForm((f) => ({ ...f, value: e.target.value }))
                }
                placeholder={t("ipLists.ipOrCidrPlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("common.type")}</Label>
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
                  <SelectItem value="whitelist">
                    {t("ipLists.whitelist")}
                  </SelectItem>
                  <SelectItem value="blacklist">
                    {t("ipLists.blacklist")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("ipLists.action")}</Label>
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
                    {t("ipLists.actionIntercept")}
                  </SelectItem>
                  <SelectItem value="drop">
                    {t("ipLists.actionDrop")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("ipLists.scope")}</Label>
              <Select
                value={form.scope}
                onValueChange={(v) => setForm((f) => ({ ...f, scope: v }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={SCOPE_GLOBAL}>
                    {t("ipLists.scopeGlobal")}
                  </SelectItem>
                  {sites.map((s) => (
                    <SelectItem key={s.id} value={String(s.id)}>
                      {s.host}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t("ipLists.scopeHint")}
              </p>
            </div>
            <div className="space-y-2">
              <Label>{t("ipLists.reason")}</Label>
              <Input
                value={form.note}
                onChange={(e) =>
                  setForm((f) => ({ ...f, note: e.target.value }))
                }
                placeholder={t("ipLists.reasonPlaceholder")}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handleCreate}
              disabled={mutateLoading || !form.value.trim()}
            >
              {mutateLoading ? t("common.submitting") : t("common.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={bulkDialogOpen} onOpenChange={setBulkDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("ipLists.bulkImportTitle")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t("common.type")}</Label>
              <Select
                value={bulkKind}
                onValueChange={(v) =>
                  setBulkKind(v as "blacklist" | "whitelist")
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="whitelist">
                    {t("ipLists.whitelist")}
                  </SelectItem>
                  <SelectItem value="blacklist">
                    {t("ipLists.blacklist")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("ipLists.scope")}</Label>
              <Select value={bulkScope} onValueChange={setBulkScope}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={SCOPE_GLOBAL}>
                    {t("ipLists.scopeGlobal")}
                  </SelectItem>
                  {sites.map((s) => (
                    <SelectItem key={s.id} value={String(s.id)}>
                      {s.host}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("ipLists.bulkInput")}</Label>
              <Textarea
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                placeholder={t("ipLists.bulkInputPlaceholder")}
                rows={8}
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">
                {t("ipLists.bulkInputHint")}
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBulkDialogOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handleBulkImport}
              disabled={mutateLoading || !bulkText.trim()}
            >
              {mutateLoading ? t("common.submitting") : t("ipLists.importBtn")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={presetDialogOpen} onOpenChange={setPresetDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t("ipLists.presetBots.dialogTitle")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {t("ipLists.presetBots.description")}
            </p>
            <div className="max-h-[360px] overflow-auto rounded-md border">
              {presetLoading ? (
                <div className="p-4 text-center text-sm text-muted-foreground">
                  {t("ipLists.presetBots.loading")}
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead className="bg-muted/50 sticky top-0">
                    <tr>
                      <th className="px-3 py-2 text-left font-medium">
                        {t("ipLists.presetBots.value")}
                      </th>
                      <th className="px-3 py-2 text-left font-medium">
                        {t("ipLists.presetBots.note")}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {(presetData?.items || []).map((item, idx) => (
                      <tr key={idx} className="border-t">
                        <td className="px-3 py-2 font-mono">{item.value}</td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {item.note}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {t("ipLists.presetBots.total", {
                count: presetData?.total ?? 0,
              })}
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setPresetDialogOpen(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handleApplyPresetBots}
              disabled={presetSeeding || presetLoading}
            >
              {presetSeeding
                ? t("common.submitting")
                : t("ipLists.presetBots.apply")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleteId}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("common.confirmDeleteTitle")}
        description={t("ipLists.deleteConfirm")}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  );
}
