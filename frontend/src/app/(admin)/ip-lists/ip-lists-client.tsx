"use client";

/**
 * IP 名单：列表、按类型筛选、前端搜索、新建/编辑、删除与预置爬虫白名单导入。
 *
 * 后端契约：
 * - 列表 GET /ip-lists?kind=blacklist|whitelist → { items: IPListEntry[], total }
 * - 新建 POST /ip-lists；更新 POST /ip-lists/:id/update；删除 POST /ip-lists/:id/delete
 * - 预置条目 GET /preset-bot-whitelist；一键导入 POST /preset-bot-whitelist/seed
 */

import { useMemo, useState } from "react";
import { useOverlayState, Button, Chip } from "@heroui/react";
import { Plus, Upload } from "lucide-react";
import { apiPost } from "@/lib/api/client";
import { useList } from "@/lib/hooks/use-api";
import type { IPListEntry } from "@/lib/types/ip";
import { formatDateTime } from "@/lib/utils/format";
import {
  PageHeader,
  Toolbar,
  SimpleSelect,
  SearchInput,
  Pager,
  ErrorState,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";
import { IPListFormDialog } from "./ip-list-form-dialog";
import { IPPresetDialog } from "./ip-preset-dialog";
import {
  ACTION_LABELS,
  EMPTY_FORM,
  KIND_FILTER_OPTIONS,
  KIND_LABELS,
  type IPFormState,
  type Kind,
} from "./ip-lists-model";

function IPListsClient() {
  const { t } = useI18n();
  const [kindFilter, setKindFilter] = useState<"" | Kind>("");
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<IPListEntry | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  const [presetVisible, setPresetVisible] = useState(false);

  const formState = useOverlayState();
  const presetState = useOverlayState();

  const { items, total, page, pageSize, setPage, loading, error, reload } =
    useList<IPListEntry>("/ip-lists", { kind: kindFilter });

  /** 按 value 前端过滤（列表接口无搜索参数） */
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) => it.value.toLowerCase().includes(q));
  }, [items, search]);

  /**
   * 已激活筛选条件清单（Cloudflare 风格可见 chips）。
   * kind + search；只在有值时展示短标签。
   */
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const items: ActiveFilter[] = [];
    const add = (key: string, label: string, value: string) => {
      if (value && value.trim() !== "") {
        items.push({ key, label, value: value.trim() });
      }
    };

    if (kindFilter) {
      const labelKey = KIND_LABELS[kindFilter];
      const val = labelKey ? t(labelKey) : kindFilter;
      add("kind", t("ipLists.cond.kind"), val);
    }
    add("q", t("ipLists.cond.q"), search.trim());

    return items;
  }, [t, kindFilter, search]);

  /** 单个筛选的清除器表 */
  const FILTER_RESETTERS: Record<string, () => void> = {
    kind: () => setKindFilter(""),
    q: () => setSearch(""),
  };

  function clearFilter(key: string) {
    FILTER_RESETTERS[key]?.();
  }

  function clearAllFilters() {
    Object.values(FILTER_RESETTERS).forEach((reset) => reset());
  }

  /** 打开新建或编辑弹窗；`entry` 为 null 表示新建。 */
  function openForm(entry: IPListEntry | null) {
    setEditing(entry);
    setFormVisible(true);
    formState.open();
  }

  const initialForm: IPFormState = editing
    ? {
        kind: editing.kind,
        value: editing.value,
        action: editing.action,
        note: editing.note,
        enabled: editing.enabled,
      }
    : EMPTY_FORM;

  const columns: DataTableColumn<IPListEntry>[] = [
    {
      header: t("ipLists.col.value"),
      render: (it) => <span className="font-mono text-sm">{it.value}</span>,
    },
    {
      header: t("ipLists.col.kind"),
      render: (it) =>
        it.kind === "blacklist" ? (
          <Chip size="sm" variant="soft" color="danger">
            {t(KIND_LABELS.blacklist)}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="success">
            {t(KIND_LABELS.whitelist)}
          </Chip>
        ),
    },
    {
      header: t("ipLists.col.action"),
      render: (it) => (ACTION_LABELS[it.action] ? t(ACTION_LABELS[it.action]) : it.action),
    },
    {
      header: t("ipLists.col.note"),
      render: (it) => <span className="text-muted">{it.note || "-"}</span>,
    },
    {
      header: t("ipLists.col.status"),
      render: (it) =>
        it.enabled ? (
          <Chip size="sm" variant="soft" color="success">
            {t("common.enabled")}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="default">
            {t("common.disabled")}
          </Chip>
        ),
    },
    // 后端 site_id 带 omitempty，全局条目该字段缺失（undefined），必须用宽松判空
    {
      header: t("ipLists.col.site"),
      render: (it) =>
        it.site_id == null ? t("ipLists.global") : `#${it.site_id}`,
    },
    { header: t("ipLists.col.updatedAt"), render: (it) => formatDateTime(it.updated_at) },
    {
      header: t("common.actions"),
      render: (it) => (
        <div className="flex items-center gap-1.5">
          <Button size="sm" variant="outline" onPress={() => openForm(it)}>
            {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("ipLists.deleteConfirm", { value: it.value })}
            successText={t("ipLists.deleted")}
            onConfirm={async () => {
              await apiPost(`/ip-lists/${it.id}/delete`);
              reload();
            }}
          >
            {t("common.delete")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("ipLists.title")}
        description={t("ipLists.description")}
        actions={
          <>
            <Button
              variant="outline"
              onPress={() => {
                setPresetVisible(true);
                presetState.open();
              }}
            >
              <Upload className="size-4" /> {t("ipLists.importPreset")}
            </Button>
            <Button variant="primary" onPress={() => openForm(null)}>
              <Plus className="size-4" /> {t("ipLists.create")}
            </Button>
          </>
        }
      />

      <Toolbar>
        <SimpleSelect<"" | Kind>
          value={kindFilter}
          onChange={(v) => setKindFilter(v)}
          label={t("ipLists.kind")}
          options={localizeOptions(KIND_FILTER_OPTIONS, t)}
        />
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder={t("ipLists.search")}
        />
      </Toolbar>

      <ActiveFilterBar
        filters={activeFilters}
        onClear={clearFilter}
        onClearAll={clearAllFilters}
      />

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : (
        <DataTable
          ariaLabel={t("ipLists.listAria")}
          columns={columns}
          rows={filtered}
          loading={loading}
          emptyMessage={t("ipLists.empty")}
        />
      )}
      <Pager page={page} pageSize={pageSize} total={total} onPageChange={setPage} />

      {formVisible ? (
        <IPListFormDialog
          key={editing ? `ip-list-${editing.id}` : "ip-list-new"}
          state={formState}
          entryId={editing?.id ?? null}
          initial={initialForm}
          onSaved={() => {
            setFormVisible(false);
            reload();
          }}
        />
      ) : null}

      {presetVisible ? (
        <IPPresetDialog
          state={presetState}
          onImported={() => {
            setPresetVisible(false);
            reload();
          }}
        />
      ) : null}
    </div>
  );
}

export default IPListsClient;
