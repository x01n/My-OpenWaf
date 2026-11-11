"use client";

/**
 * 站点详情「访问控制：本地用户」面板。
 *
 * 后端契约：
 * - GET  /sites/:id/access/users
 * - POST /sites/:id/access/users
 * - POST /sites/:id/access/users/:id/update
 * - POST /sites/:id/access/users/:id/delete
 *
 * 编辑时用户名不可改、密码留空保持原值。
 */

import { useCallback, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input } from "@heroui/react";
import { Plus, Pencil } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type { AccessUser, AccessUsersResponse } from "@/lib/types/access";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { StatusChip, ToggleSwitch } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { formatDateTime } from "@/lib/utils/format";
import { useI18n } from "@/i18n";

export function UsersPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const list = useApi(
    useCallback(() => apiGet<AccessUsersResponse>(`/sites/${siteId}/access/users`), [siteId]),
  );
  const items = list.data?.users ?? [];

  const [editing, setEditing] = useState<AccessUser | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  const formState = useOverlayState();

  function openForm(row: AccessUser | null) {
    setEditing(row);
    setFormVisible(true);
    formState.open();
  }

  const columns: DataTableColumn<AccessUser>[] = [
    {
      header: t("siteDetail.users.col.username"),
      render: (row) => <span className="font-medium">{row.username}</span>,
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
      header: t("siteDetail.field.createdAt"),
      render: (row) => <span className="tabular">{formatDateTime(row.created_at)}</span>,
    },
    {
      header: t("common.actions"),
      render: (row) => (
        <div className="flex items-center gap-1.5">
          <Button size="sm" variant="outline" onPress={() => openForm(row)}>
            <Pencil className="size-3.5" /> {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("siteDetail.users.deleteConfirm", { username: row.username })}
            successText={t("siteDetail.users.deleted")}
            onConfirm={async () => {
              await apiPost(`/sites/${siteId}/access/users/${row.id}/delete`);
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
        <h4 className="text-muted text-xs font-semibold">{t("siteDetail.users.title")}</h4>
        <Button size="sm" variant="primary" onPress={() => openForm(null)}>
          <Plus className="size-3.5" /> {t("common.create")}
        </Button>
      </div>
      <DataTable
        ariaLabel={t("siteDetail.users.listAria")}
        columns={columns}
        rows={items.length > 0 ? items : undefined}
        loading={list.loading}
        emptyMessage={t("siteDetail.users.empty")}
      />
      {formVisible ? (
        <UserFormModal
          key={editing ? `user-${editing.id}` : "user-new"}
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

/** 本地用户新建/编辑弹窗。 */
function UserFormModal({
  state,
  siteId,
  editing,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  siteId: number;
  editing: AccessUser | null;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const isEdit = editing !== null;
  const [username, setUsername] = useState(editing?.username ?? "");
  const [password, setPassword] = useState("");
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!isEdit && !username.trim()) {
      showError(t("siteDetail.users.error.username"), t("siteDetail.users.error.usernameHint"));
      return;
    }
    if (!isEdit && !password) {
      showError(t("siteDetail.users.error.password"), t("siteDetail.users.error.passwordHint"));
      return;
    }
    setSaving(true);
    try {
      if (isEdit) {
        const body: Record<string, unknown> = { enabled };
        if (password) body.password = password;
        await apiPost(`/sites/${siteId}/access/users/${editing!.id}/update`, body);
      } else {
        await apiPost(`/sites/${siteId}/access/users`, {
          username: username.trim(),
          password,
          enabled,
        });
      }
      showSuccess(
        isEdit ? t("siteDetail.users.saved.update") : t("siteDetail.users.saved.create"),
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
                {isEdit ? t("siteDetail.users.form.edit") : t("siteDetail.users.form.create")}
              </Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              {isEdit ? (
                <div className="text-muted text-xs">
                  {t("siteDetail.users.form.usernameLocked", { name: editing!.username })}
                </div>
              ) : (
                <TextField aria-label={t("siteDetail.users.col.username")} isRequired>
                  <Input
                    placeholder={t("siteDetail.users.col.username")}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </TextField>
              )}
              <TextField aria-label={t("login.password")} isRequired={!isEdit}>
                <Input
                  type="password"
                  placeholder={
                    isEdit ? t("siteDetail.users.form.passwordKeep") : t("login.password")
                  }
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </TextField>
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
