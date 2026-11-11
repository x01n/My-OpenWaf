"use client";

/**
 * 管理员账户面板：
 * - GET /admin-users
 * - 新建 POST /admin-users {username,password,role}（密码 ≥8 位，服务端哈希存储）
 * - 改密码 POST /admin-users/:id/update-password；改角色 POST /admin-users/:id/update-role
 * - 删除 POST /admin-users/:id/delete（最后一个 admin 受服务端保护）
 */

import { useCallback, useState } from "react";
import { Button, Select, ListBox, TextField, Input, useOverlayState } from "@heroui/react";
import { KeyRound, Plus, ShieldCog } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { FormDialog } from "@/components/ui/dialogs";
import {
  CardSkeleton,
  ErrorState,
  StatusChip,
  Toolbar,
  type StatusTone,
} from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { formatDateTime } from "@/lib/utils/format";
import { useI18n, type MessageKey } from "@/i18n";
import type { AdminUser } from "@/lib/types/system";

type Rows = AdminUser & { id: number };

/** 角色选项：key 为后端原值，文案经 i18n 解析。 */
const ROLE_OPTIONS: ReadonlyArray<{ key: string; labelKey: MessageKey }> = [
  { key: "admin", labelKey: "admin.users.role.admin" },
  { key: "operator", labelKey: "admin.users.role.operator" },
  { key: "readonly", labelKey: "admin.users.role.readonly" },
];

const ROLE_TONE: Record<string, StatusTone> = {
  admin: "danger",
  operator: "info",
  readonly: "neutral",
};

export function UsersPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<{ items: AdminUser[] }>(
    useCallback(() => apiGet<{ items: AdminUser[] }>("/admin-users"), []),
  );
  const createState = useOverlayState();
  const [passwordTarget, setPasswordTarget] = useState<AdminUser | null>(null);
  const [roleTarget, setRoleTarget] = useState<AdminUser | null>(null);
  const passwordState = useOverlayState();
  const roleState = useOverlayState();

  const rows: Rows[] = (data?.items ?? []).map((it) => ({ ...it, id: it.id }));

  async function create(username: string, password: string, role: string) {
    try {
      await apiPost("/admin-users", { username, password, role });
      createState.close();
      showSuccess(t("admin.users.created"));
      void reload();
    } catch (err) {
      showError(t("admin.users.createFailed"), err instanceof ApiError ? err.message : undefined);
    }
  }

  const columns: DataTableColumn<Rows>[] = [
    { header: t("admin.users.col.username"), render: (r) => <span className="font-medium">{r.username}</span> },
    {
      header: t("admin.users.col.role"),
      render: (r) => (
        <StatusChip tone={ROLE_TONE[r.role] ?? "neutral"}>{r.role}</StatusChip>
      ),
    },
    {
      header: t("admin.users.col.createdAt"),
      render: (r) => <span className="tabular text-muted text-xs">{formatDateTime(r.created_at)}</span>,
    },
    {
      header: t("common.actions"),
      className: "w-[280px] whitespace-nowrap",
      render: (r) => (
        <div className="flex flex-nowrap items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            onPress={() => {
              setPasswordTarget(r);
              passwordState.open();
            }}
          >
            <KeyRound className="size-3.5" /> {t("admin.users.changePassword")}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onPress={() => {
              setRoleTarget(r);
              roleState.open();
            }}
          >
            <ShieldCog className="size-3.5" /> {t("admin.users.changeRole")}
          </Button>
          <ConfirmButton
            confirmText={t("admin.users.deleteConfirm", { name: r.username })}
            onConfirm={async () => {
              await apiPost(`/admin-users/${r.id}/delete`);
              void reload();
            }}
          >
            {t("common.delete")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (loading && !data) return <CardSkeleton height="h-56" />;

  return (
    <div className="bg-surface rounded-xl border border-separator p-4">
      <Toolbar>
        <Button variant="primary" size="sm" onPress={createState.open}>
          <Plus className="size-4" /> {t("admin.users.create")}
        </Button>
      </Toolbar>
      <DataTable
        ariaLabel={t("admin.users.listAria")}
        columns={columns}
        rows={rows}
        loading={loading}
        emptyMessage={t("admin.users.empty")}
      />

      <CreateUserDialog key={createState.isOpen ? "open" : "closed"} state={createState} onSubmit={create} />
      <PasswordDialog
        key={`${passwordTarget?.id ?? 0}-${passwordState.isOpen}`}
        target={passwordTarget}
        state={passwordState}
        onSaved={() => void reload()}
      />
      <RoleDialog
        key={`${roleTarget?.id ?? 0}-${roleState.isOpen}`}
        target={roleTarget}
        state={roleState}
        onSaved={() => void reload()}
      />
    </div>
  );
}

function CreateUserDialog({
  state,
  onSubmit,
}: {
  state: ReturnType<typeof useOverlayState>;
  onSubmit: (username: string, password: string, role: string) => Promise<void>;
}) {
  const { t } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<string>("readonly");
  const [saving, setSaving] = useState(false);

  return (
    <FormDialog
      state={state}
      title={t("admin.users.form.createTitle")}
      description={t("admin.users.form.createDesc")}
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            isPending={saving}
            isDisabled={username.trim() === "" || password.length < 8}
            onPress={async () => {
              setSaving(true);
              await onSubmit(username.trim(), password, role);
              setSaving(false);
              setUsername("");
              setPassword("");
            }}
          >
            {t("admin.users.form.submit")}
          </Button>
        </>
      }
    >
      <TextField aria-label={t("admin.users.form.username")} isRequired>
        <Input placeholder={t("admin.users.form.usernamePlaceholder")} value={username} onChange={(e) => setUsername(e.target.value)} />
      </TextField>
      <TextField aria-label={t("admin.users.form.initialPassword")} isRequired>
        <Input
          type="password"
          placeholder={t("admin.users.form.initialPasswordPlaceholder")}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </TextField>
      <RoleSelect value={role} onChange={setRole} />
    </FormDialog>
  );
}

function RoleSelect({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-muted text-xs">{t("admin.users.role")}</span>
      <Select
        aria-label={t("admin.users.role")}
        selectedKey={value}
        onSelectionChange={(key) => {
          if (key !== null) onChange(key as string);
        }}
      >
        <ListBox>
          {ROLE_OPTIONS.map((opt) => (
            <ListBox.Item key={opt.key} id={opt.key} textValue={t(opt.labelKey)}>
              {t(opt.labelKey)}
            </ListBox.Item>
          ))}
        </ListBox>
      </Select>
    </div>
  );
}

function PasswordDialog({
  target,
  state,
  onSaved,
}: {
  target: AdminUser | null;
  state: ReturnType<typeof useOverlayState>;
  onSaved: () => void;
}) {
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const { t } = useI18n();

  async function submit() {
    if (!target) return;
    setSaving(true);
    try {
      await apiPost(`/admin-users/${target.id}/update-password`, { password });
      state.close();
      showSuccess(t("admin.users.passwordUpdated", { name: target.username }));
      onSaved();
    } catch (err) {
      showError(t("admin.users.passwordChangeFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
      setPassword("");
    }
  }

  return (
    <FormDialog
      state={state}
      title={t("admin.users.passwordDialogTitle")}
      description={target ? t("admin.users.passwordDialogDesc", { name: target.username }) : undefined}
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            isPending={saving}
            isDisabled={password.length < 8}
            onPress={() => void submit()}
          >
            {t("common.save")}
          </Button>
        </>
      }
    >
      <TextField aria-label={t("admin.users.form.newPassword")} isRequired>
        <Input
          type="password"
          placeholder={t("admin.users.form.newPasswordPlaceholder")}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </TextField>
    </FormDialog>
  );
}

function RoleDialog({
  target,
  state,
  onSaved,
}: {
  target: AdminUser | null;
  state: ReturnType<typeof useOverlayState>;
  onSaved: () => void;
}) {
  const [role, setRole] = useState("readonly");
  const [saving, setSaving] = useState(false);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const { t } = useI18n();

  if (target && target.username !== loadedFor) {
    setLoadedFor(target.username);
    setRole(target.role);
  }

  async function submit() {
    if (!target) return;
    setSaving(true);
    try {
      await apiPost(`/admin-users/${target.id}/update-role`, { role });
      state.close();
      showSuccess(t("admin.users.roleUpdated", { name: target.username }));
      onSaved();
    } catch (err) {
      showError(t("admin.users.roleChangeFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <FormDialog
      state={state}
      title={t("admin.users.roleDialogTitle")}
      description={target ? t("admin.users.roleDialogDesc", { name: target.username }) : undefined}
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" isPending={saving} onPress={() => void submit()}>
            {t("common.save")}
          </Button>
        </>
      }
    >
      <RoleSelect value={role} onChange={setRole} />
    </FormDialog>
  );
}
