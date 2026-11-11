"use client";

/**
 * 站点详情「访问控制：路径规则」面板。
 *
 * 后端契约：
 * - GET  /sites/:id/access/rules
 * - POST /sites/:id/access/rules
 * - POST /sites/:id/access/rules/:id/update
 * - POST /sites/:id/access/rules/:id/delete
 */

import { useCallback, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input, Chip } from "@heroui/react";
import { Plus, Pencil } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type { AccessPathRule, AccessPathRulesResponse } from "@/lib/types/access";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { SimpleSelect, StatusChip, ToggleSwitch } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n, type MessageKey } from "@/i18n";

/** 路径规则动作 → 语言包键。 */
const PATH_ACTION_LABEL_KEYS: Record<string, MessageKey> = {
  require_auth: "siteDetail.pathRules.action.requireAuth",
  allow: "siteDetail.pathRules.action.allow",
  deny: "siteDetail.pathRules.action.deny",
};

/** 路径规则动作配色。 */
const PATH_ACTION_COLORS: Record<string, "default" | "accent" | "success" | "danger"> = {
  require_auth: "accent",
  allow: "success",
  deny: "danger",
};

export function PathRulesPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const list = useApi(
    useCallback(() => apiGet<AccessPathRulesResponse>(`/sites/${siteId}/access/rules`), [siteId]),
  );
  const items = list.data?.rules ?? [];

  const [editing, setEditing] = useState<AccessPathRule | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  const formState = useOverlayState();

  function openForm(row: AccessPathRule | null) {
    setEditing(row);
    setFormVisible(true);
    formState.open();
  }

  function actionLabel(action: string): string {
    const key = PATH_ACTION_LABEL_KEYS[action];
    return key ? t(key) : action;
  }

  const columns: DataTableColumn<AccessPathRule>[] = [
    {
      header: t("common.path"),
      render: (row) => <span className="font-mono break-all text-xs">{row.path}</span>,
    },
    {
      header: t("rules.col.action"),
      render: (row) => (
        <Chip size="sm" variant="soft" color={PATH_ACTION_COLORS[row.action] ?? "default"}>
          {actionLabel(row.action)}
        </Chip>
      ),
    },
    {
      header: t("rules.col.priority"),
      render: (row) => <span className="tabular">{row.priority}</span>,
    },
    {
      header: t("siteDetail.listeners.status"),
      render: (row) => (
        <StatusChip tone={row.enabled ? "success" : "neutral"}>
          {row.enabled ? t("common.enabled") : t("common.disabled")}
        </StatusChip>
      ),
    },
    {
      header: t("common.actions"),
      render: (row) => (
        <div className="flex items-center gap-1.5">
          <Button size="sm" variant="outline" onPress={() => openForm(row)}>
            <Pencil className="size-3.5" /> {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("siteDetail.pathRules.deleteConfirm", { path: row.path })}
            successText={t("siteDetail.pathRules.deleted")}
            onConfirm={async () => {
              await apiPost(`/sites/${siteId}/access/rules/${row.id}/delete`);
              void list.reload();
            }}
          >
            {t("common.delete")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center justify-between border-t border-separator pt-3">
        <h4 className="text-muted text-xs font-semibold">{t("siteDetail.pathRules.title")}</h4>
        <Button size="sm" variant="primary" onPress={() => openForm(null)}>
          <Plus className="size-3.5" /> {t("common.create")}
        </Button>
      </div>
      <DataTable
        ariaLabel={t("siteDetail.pathRules.listAria")}
        columns={columns}
        rows={items.length > 0 ? items : undefined}
        loading={list.loading}
        emptyMessage={t("siteDetail.pathRules.empty")}
      />
      {formVisible ? (
        <PathRuleFormModal
          key={editing ? `pathrule-${editing.id}` : "pathrule-new"}
          state={formState}
          siteId={siteId}
          editing={editing}
          onSaved={() => {
            void list.reload();
            setFormVisible(false);
          }}
        />
      ) : null}
    </section>
  );
}

/** 路径规则新建/编辑弹窗。 */
function PathRuleFormModal({
  state,
  siteId,
  editing,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  siteId: number;
  editing: AccessPathRule | null;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const isEdit = editing !== null;
  const [path, setPath] = useState(editing?.path ?? "");
  const [action, setAction] = useState(editing?.action ?? "require_auth");
  const [priority, setPriority] = useState(String(editing?.priority ?? 0));
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [saving, setSaving] = useState(false);

  const actionOptions = Object.entries(PATH_ACTION_LABEL_KEYS).map(([key, labelKey]) => ({
    key,
    label: t(labelKey),
  }));

  async function handleSave() {
    if (!path.trim()) {
      showError(t("siteDetail.pathRules.error.path"), t("siteDetail.pathRules.error.pathHint"));
      return;
    }
    setSaving(true);
    const payload = {
      path: path.trim(),
      action,
      priority: Number(priority) || 0,
      enabled,
    };
    try {
      if (isEdit) {
        await apiPost(`/sites/${siteId}/access/rules/${editing!.id}/update`, payload);
      } else {
        await apiPost(`/sites/${siteId}/access/rules`, payload);
      }
      showSuccess(
        isEdit
          ? t("siteDetail.pathRules.saved.update")
          : t("siteDetail.pathRules.saved.create"),
      );
      onSaved();
      state.close();
    } catch (err) {
      showError(t("sites.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal state={state}>
      <Modal.Backdrop>
        <Modal.Container size="md">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>
                {isEdit
                  ? t("siteDetail.pathRules.form.edit")
                  : t("siteDetail.pathRules.form.create")}
              </Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <TextField aria-label={t("common.path")} isRequired>
                <Input
                  placeholder={t("siteDetail.pathRules.form.pathPlaceholder")}
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                />
              </TextField>
              <div className="flex items-end gap-4">
                <SimpleSelect
                  value={action}
                  onChange={setAction}
                  label={t("rules.col.action")}
                  className="w-40"
                  options={actionOptions}
                />
                <TextField aria-label={t("rules.col.priority")}>
                  <Input
                    type="number"
                    placeholder={t("rules.col.priority")}
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  />
                </TextField>
              </div>
              <ToggleSwitch isSelected={enabled} onChange={setEnabled}>
                {t("common.enabled")}
              </ToggleSwitch>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {t("common.cancel")}
              </Button>
              <Button variant="primary" isPending={saving} onPress={() => void handleSave()}>
                {t("common.save")}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}
