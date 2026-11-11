"use client";

/**
 * API 密钥面板：
 * - GET /api-keys（name / username / last_used_at / created_at）
 * - 新建 POST /api-keys {name} → 响应 token 只展示一次（等宽 + 复制）
 * - 删除 POST /api-keys/:id/delete
 */

import { useCallback, useState } from "react";
import { Button, TextField, Input, useOverlayState } from "@heroui/react";
import { Check, Copy, KeyRound, Plus, TriangleAlert } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { FormDialog } from "@/components/ui/dialogs";
import { CardSkeleton, ErrorState, Toolbar } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { formatDateTime } from "@/lib/utils/format";
import { useI18n } from "@/i18n";
import type { APIKey } from "@/lib/types/system";

type Rows = APIKey & { id: number };

type CreateAPIKeyResponse = {
  token: string;
  id: number;
  name: string;
  user_id: number;
  username: string;
};

export function APIKeysPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<{ items: APIKey[] }>(
    useCallback(() => apiGet<{ items: APIKey[] }>("/api-keys"), []),
  );
  const createState = useOverlayState();
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreateAPIKeyResponse | null>(null);
  const [saving, setSaving] = useState(false);

  const rows: Rows[] = (data?.items ?? []).map((it) => ({ ...it, id: it.id }));

  async function create() {
    setSaving(true);
    try {
      const result = await apiPost<CreateAPIKeyResponse>("/api-keys", { name: name.trim() });
      setCreated(result);
      setName("");
      void reload();
    } catch (err) {
      showError(t("admin.keys.createFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  const columns: DataTableColumn<Rows>[] = [
    { header: t("admin.keys.col.name"), render: (r) => <span className="font-medium">{r.name}</span> },
    { header: t("admin.keys.col.owner"), render: (r) => r.username || "-" },
    {
      header: t("admin.keys.col.lastUsed"),
      render: (r) => (
        <span className="tabular text-muted text-xs">{formatDateTime(r.last_used_at)}</span>
      ),
    },
    {
      header: t("admin.keys.col.createdAt"),
      render: (r) => (
        <span className="tabular text-muted text-xs">{formatDateTime(r.created_at)}</span>
      ),
    },
    {
      header: t("common.actions"),
      className: "w-24",
      render: (r) => (
        <ConfirmButton
          confirmText={t("admin.keys.deleteConfirm", { name: r.name })}
          onConfirm={async () => {
            await apiPost(`/api-keys/${r.id}/delete`);
            void reload();
          }}
        >
          {t("common.delete")}
        </ConfirmButton>
      ),
    },
  ];

  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (loading && !data) return <CardSkeleton height="h-56" />;

  return (
    <div className="bg-surface rounded-xl border border-separator p-4">
      <Toolbar>
        <Button
          variant="primary"
          size="sm"
          onPress={() => {
            setCreated(null);
            createState.open();
          }}
        >
          <Plus className="size-4" /> {t("admin.keys.create")}
        </Button>
      </Toolbar>
      <DataTable
        ariaLabel={t("admin.keys.listAria")}
        columns={columns}
        rows={rows}
        loading={loading}
        emptyMessage={t("admin.keys.empty")}
      />

      <FormDialog
        state={createState}
        title={created ? t("admin.keys.createdTitle") : t("admin.keys.form.createTitle")}
        description={created ? undefined : t("admin.keys.form.createDesc")}
        size="md"
        footer={
          created ? (
            <Button
              variant="primary"
              onPress={() => {
                createState.close();
                setCreated(null);
              }}
            >
              {t("admin.keys.ackSaved")}
            </Button>
          ) : (
            <>
              <Button variant="ghost" onPress={createState.close}>
                {t("common.cancel")}
              </Button>
              <Button
                variant="primary"
                isPending={saving}
                isDisabled={name.trim() === ""}
                onPress={() => void create()}
              >
                {t("admin.keys.form.submit")}
              </Button>
            </>
          )
        }
      >
        {created ? (
          <TokenReveal token={created.token} />
        ) : (
          <TextField aria-label={t("admin.keys.form.name")} isRequired>
            <Input
              placeholder={t("admin.keys.form.namePlaceholder")}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </TextField>
        )}
      </FormDialog>
    </div>
  );
}

function TokenReveal({ token }: { token: string }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      showSuccess(t("admin.keys.copiedToast"));
    } catch {
      showError(t("admin.keys.copyFailed"), t("admin.keys.copyFailedDesc"));
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="bg-warning-soft text-warning flex items-start gap-2 rounded-lg p-3 text-sm">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" />
        <div>{t("admin.keys.revealWarning")}</div>
      </div>
      <div className="bg-default flex items-center gap-2 rounded-lg p-3">
        <code className="font-mono min-w-0 flex-1 text-xs break-all">{token}</code>
        <Button size="sm" variant="outline" onPress={() => void copy()}>
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          {copied ? t("admin.keys.copied") : t("admin.keys.copy")}
        </Button>
      </div>
      <div className="text-muted flex items-center gap-1 text-xs">
        <KeyRound className="size-3.5" /> {t("admin.keys.usageHint")}
      </div>
    </div>
  );
}
