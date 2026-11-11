"use client";

/**
 * 通用键值设置面板：
 * - GET /settings（{items}，内部键已过滤、敏感值已脱敏）
 * - 新建 POST /settings {key,value}
 * - 编辑 POST /settings/:key/update {value}
 * - 删除 POST /settings/:key/delete
 * 受保护键（protection / redis_config 等）由后端拒绝写入并提示专用端点。
 */

import { useCallback, useState } from "react";
import {
  Button,
  TextField,
  Input,
  TextArea,
  useOverlayState,
} from "@heroui/react";
import { Pencil, Plus } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { FormDialog } from "@/components/ui/dialogs";
import { Toolbar } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { truncate } from "@/lib/utils/format";
import { PanelError, PanelSkeleton } from "./form-kit";
import type { SettingsListItem } from "@/lib/types/settings";

type Rows = SettingsListItem & { id: number };

export function KVPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<{ items: SettingsListItem[] }>(
    useCallback(() => apiGet<{ items: SettingsListItem[] }>("/settings"), []),
  );
  const createState = useOverlayState();
  const [editing, setEditing] = useState<SettingsListItem | null>(null);
  const editState = useOverlayState();

  const rows: Rows[] = (data?.items ?? []).map((it) => ({ ...it, id: it.id }));

  async function create(key: string, value: string) {
    try {
      await apiPost("/settings", { key, value });
      createState.close();
      showSuccess(t("settings.kv.created"));
      void reload();
    } catch (err) {
      showError(t("settings.kv.createFailed"), err instanceof ApiError ? err.message : undefined);
    }
  }

  async function update(key: string, value: string) {
    try {
      await apiPost(`/settings/${encodeURIComponent(key)}/update`, { value });
      editState.close();
      showSuccess(t("settings.panel.saved"));
      void reload();
    } catch (err) {
      showError(t("settings.panel.saveFailed"), err instanceof ApiError ? err.message : undefined);
    }
  }

  const columns: DataTableColumn<Rows>[] = [
    { header: t("settings.kv.colKey"), render: (r) => <span className="font-mono text-xs">{r.key}</span> },
    {
      header: t("settings.kv.colValue"),
      className: "max-w-[520px]",
      render: (r) => (
        <span className="font-mono text-muted block text-xs leading-5" title={r.value}>
          {truncate(r.value, 120)}
        </span>
      ),
    },
    {
      header: t("common.actions"),
      className: "w-44",
      render: (r) => (
        <div className="flex items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            onPress={() => {
              setEditing(r);
              editState.open();
            }}
          >
            <Pencil className="size-3.5" /> {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("settings.kv.deleteConfirm", { key: r.key })}
            onConfirm={async () => {
              await apiPost(`/settings/${encodeURIComponent(r.key)}/delete`);
              void reload();
            }}
          >
            {t("common.delete")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading && !data) return <PanelSkeleton />;

  return (
    <PanelCardWrap>
      <Toolbar>
        <Button variant="primary" size="sm" onPress={createState.open}>
          <Plus className="size-4" /> {t("settings.kv.createBtn")}
        </Button>
      </Toolbar>
      <DataTable
        ariaLabel={t("settings.kv.listAria")}
        columns={columns}
        rows={rows}
        loading={loading}
        emptyMessage={t("settings.kv.empty")}
      />

      <CreateDialog state={createState} onSubmit={create} />
      <EditDialog item={editing} state={editState} onSubmit={update} />
    </PanelCardWrap>
  );
}

function PanelCardWrap({ children }: { children: React.ReactNode }) {
  return <div className="bg-surface rounded-xl border border-separator p-4">{children}</div>;
}

function CreateDialog({
  state,
  onSubmit,
}: {
  state: ReturnType<typeof useOverlayState>;
  onSubmit: (key: string, value: string) => Promise<void>;
}) {
  const { t } = useI18n();
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);

  return (
    <FormDialog
      state={state}
      title={t("settings.kv.createTitle")}
      description={t("settings.kv.createDescription")}
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            isPending={saving}
            isDisabled={key.trim() === ""}
            onPress={async () => {
              setSaving(true);
              await onSubmit(key.trim(), value);
              setSaving(false);
              setKey("");
              setValue("");
            }}
          >
            {t("settings.kv.createSubmit")}
          </Button>
        </>
      }
    >
      <TextField aria-label={t("settings.kv.colKey")} isRequired>
        <Input
          placeholder={t("settings.kv.keyPlaceholder")}
          value={key}
          onChange={(e) => setKey(e.target.value)}
        />
      </TextField>
      <TextArea
        aria-label={t("settings.kv.colValue")}
        placeholder={t("settings.kv.valuePlaceholder")}
        className="min-h-24"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
    </FormDialog>
  );
}

function EditDialog({
  item,
  state,
  onSubmit,
}: {
  item: SettingsListItem | null;
  state: ReturnType<typeof useOverlayState>;
  onSubmit: (key: string, value: string) => Promise<void>;
}) {
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [loaded, setLoaded] = useState<{ key: string; value: string } | null>(null);
  const { t } = useI18n();

  // 打开（或切换）条目时同步一次值
  if (item && (loaded?.key !== item.key || loaded?.value !== item.value)) {
    setLoaded({ key: item.key, value: item.value });
    setValue(item.value);
  }

  return (
    <FormDialog
      state={state}
      title={t("settings.kv.editTitle")}
      description={item ? t("settings.kv.editKeyDescription", { key: item.key }) : undefined}
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            isPending={saving}
            onPress={async () => {
              if (!item) return;
              setSaving(true);
              await onSubmit(item.key, value);
              setSaving(false);
            }}
          >
            {t("common.save")}
          </Button>
        </>
      }
    >
      <TextArea
        aria-label={t("settings.kv.colValue")}
        className="min-h-28"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
    </FormDialog>
  );
}
