"use client";

/**
 * 站点详情「访问控制：认证提供方」面板。
 *
 * 后端契约：
 * - GET  /sites/:id/access/providers
 * - POST /sites/:id/access/providers
 * - POST /sites/:id/access/providers/:id/update
 * - POST /sites/:id/access/providers/:id/delete
 *
 * oauth2/oidc 提供方在创建/编辑时展示 config 表单；client_secret 留空表示沿用旧密文。
 */

import { useCallback, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input, Chip } from "@heroui/react";
import { Plus, Pencil } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type {
  AccessProvider,
  AccessProvidersResponse,
} from "@/lib/types/access";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { SimpleSelect, StatusChip, ToggleSwitch } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";

/** 提供方类型配色（internal/store 认证提供方类型）。 */
const PROVIDER_TYPE_COLORS: Record<string, "default" | "accent" | "success"> = {
  password: "default",
  oauth2: "accent",
  oidc: "success",
};

/** 类型展示名：password 走语言包，OAuth2/OIDC 保持专有名词。 */
function providerTypeLabel(type: string, passwordLabel: string): string {
  if (type === "password") return passwordLabel;
  if (type === "oauth2") return "OAuth2";
  if (type === "oidc") return "OIDC";
  return type;
}

export function ProvidersPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const list = useApi(
    useCallback(() => apiGet<AccessProvidersResponse>(`/sites/${siteId}/access/providers`), [siteId]),
  );
  const items = list.data?.providers ?? [];

  const [editing, setEditing] = useState<AccessProvider | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  const formState = useOverlayState();

  function openForm(row: AccessProvider | null) {
    setEditing(row);
    setFormVisible(true);
    formState.open();
  }

  const typeLabel = (type: string) =>
    providerTypeLabel(type, t("siteDetail.providers.type.password"));

  const columns: DataTableColumn<AccessProvider>[] = [
    {
      header: t("siteDetail.providers.col.name"),
      render: (row) => <span className="font-medium">{row.name}</span>,
    },
    {
      header: t("siteDetail.providers.col.type"),
      render: (row) => (
        <Chip size="sm" variant="soft" color={PROVIDER_TYPE_COLORS[row.type] ?? "default"}>
          {typeLabel(row.type)}
        </Chip>
      ),
    },
    {
      header: t("siteDetail.providers.col.priority"),
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
      header: t("siteDetail.providers.col.config"),
      className: "max-w-56",
      render: (row) =>
        row.type !== "password" && row.config ? (
          <span className="text-muted block truncate text-xs" title={row.config.client_id}>
            {t("siteDetail.providers.config.clientId")}: {row.config.client_id || "-"} ·{" "}
            {t("siteDetail.providers.config.secret")}{" "}
            {row.config.client_secret_set
              ? t("siteDetail.access.passwordSet")
              : t("siteDetail.access.passwordUnset")}
          </span>
        ) : (
          <span className="text-muted">-</span>
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
            confirmText={t("siteDetail.providers.deleteConfirm", { name: row.name })}
            successText={t("siteDetail.providers.deleted")}
            onConfirm={async () => {
              await apiPost(`/sites/${siteId}/access/providers/${row.id}/delete`);
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
        <h4 className="text-muted text-xs font-semibold">{t("siteDetail.providers.title")}</h4>
        <Button size="sm" variant="primary" onPress={() => openForm(null)}>
          <Plus className="size-3.5" /> {t("common.create")}
        </Button>
      </div>
      <DataTable
        ariaLabel={t("siteDetail.providers.listAria")}
        columns={columns}
        rows={items.length > 0 ? items : undefined}
        loading={list.loading}
        emptyMessage={t("siteDetail.providers.empty")}
      />
      {formVisible ? (
        <ProviderFormModal
          key={editing ? `provider-${editing.id}` : "provider-new"}
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

/** 认证提供方新建/编辑弹窗。 */
function ProviderFormModal({
  state,
  siteId,
  editing,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  siteId: number;
  editing: AccessProvider | null;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const isEdit = editing !== null;
  const isOAuth = (type: string) => type === "oauth2" || type === "oidc";

  const [type, setType] = useState(editing?.type ?? "password");
  const [name, setName] = useState(editing?.name ?? "");
  const [priority, setPriority] = useState(String(editing?.priority ?? 0));
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);

  const [clientId, setClientId] = useState(editing?.config?.client_id ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [authUrl, setAuthUrl] = useState(editing?.config?.auth_url ?? "");
  const [tokenUrl, setTokenUrl] = useState(editing?.config?.token_url ?? "");
  const [userinfoUrl, setUserinfoUrl] = useState(editing?.config?.userinfo_url ?? "");
  const [issuer, setIssuer] = useState(editing?.config?.issuer ?? "");
  const [scopes, setScopes] = useState((editing?.config?.scopes ?? []).join(", "));
  const [redirectPath, setRedirectPath] = useState(editing?.config?.redirect_path ?? "");
  const [usePkce, setUsePkce] = useState(editing?.config?.use_pkce ?? false);
  const [saving, setSaving] = useState(false);

  const typeLabel = (value: string) =>
    providerTypeLabel(value, t("siteDetail.providers.type.password"));

  /** 组装 OAuth config 对象；client_secret 空串时不放入（编辑时沿用旧密文）。 */
  function buildConfig(): Record<string, unknown> {
    const cfg: Record<string, unknown> = {
      client_id: clientId.trim(),
      auth_url: authUrl.trim(),
      token_url: tokenUrl.trim(),
      userinfo_url: userinfoUrl.trim(),
      issuer: issuer.trim(),
      scopes: scopes
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      redirect_path: redirectPath.trim(),
      use_pkce: usePkce,
    };
    if (clientSecret.trim() !== "") {
      cfg.client_secret = clientSecret;
    }
    return cfg;
  }

  async function handleSave() {
    if (!name.trim()) {
      showError(t("siteDetail.providers.error.name"), t("siteDetail.providers.error.nameHint"));
      return;
    }
    const effectiveType = isEdit ? editing!.type : type;
    if (isOAuth(effectiveType) && !clientId.trim()) {
      showError(
        t("siteDetail.providers.error.clientId"),
        t("siteDetail.providers.error.clientIdHint"),
      );
      return;
    }
    setSaving(true);
    try {
      if (isEdit) {
        const body: Record<string, unknown> = {
          name: name.trim(),
          priority: Number(priority) || 0,
          enabled,
        };
        if (isOAuth(effectiveType)) {
          body.config = buildConfig();
        }
        await apiPost(`/sites/${siteId}/access/providers/${editing!.id}/update`, body);
      } else {
        const body: Record<string, unknown> = {
          type,
          name: name.trim(),
          priority: Number(priority) || 0,
          enabled,
        };
        if (isOAuth(type)) {
          body.config = buildConfig();
        }
        await apiPost(`/sites/${siteId}/access/providers`, body);
      }
      showSuccess(
        isEdit
          ? t("siteDetail.providers.saved.update")
          : t("siteDetail.providers.saved.create"),
      );
      onSaved();
      state.close();
    } catch (err) {
      showError(t("sites.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  const showConfig = isOAuth(isEdit ? editing!.type : type);

  return (
    <Modal state={state}>
      <Modal.Backdrop>
        <Modal.Container size="lg">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>
                {isEdit
                  ? t("siteDetail.providers.form.edit")
                  : t("siteDetail.providers.form.create")}
              </Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              {isEdit ? (
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-muted text-xs">{t("siteDetail.providers.col.type")}</span>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={PROVIDER_TYPE_COLORS[editing!.type] ?? "default"}
                  >
                    {typeLabel(editing!.type)}
                  </Chip>
                  <span className="text-muted text-xs">
                    {t("siteDetail.providers.form.typeLocked")}
                  </span>
                </div>
              ) : (
                <SimpleSelect
                  value={type}
                  onChange={setType}
                  label={t("siteDetail.providers.col.type")}
                  className="w-40"
                  options={[
                    { key: "password", label: t("siteDetail.providers.type.password") },
                    { key: "oauth2", label: "OAuth2" },
                    { key: "oidc", label: "OIDC" },
                  ]}
                />
              )}
              <TextField aria-label={t("siteDetail.providers.col.name")} isRequired>
                <Input
                  placeholder={t("siteDetail.providers.form.namePlaceholder")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("siteDetail.providers.col.priority")}>
                <Input
                  type="number"
                  placeholder={t("siteDetail.providers.form.priorityPlaceholder")}
                  value={priority}
                  onChange={(e) => setPriority(e.target.value)}
                />
              </TextField>
              <ToggleSwitch isSelected={enabled} onChange={setEnabled}>
                {t("common.enabled")}
              </ToggleSwitch>

              {showConfig ? (
                <>
                  <div className="border-t border-separator pt-3">
                    <h5 className="text-muted mb-2 text-xs font-semibold">
                      {t("siteDetail.providers.form.oauthTitle")}
                    </h5>
                  </div>
                  <TextField aria-label="Client ID" isRequired>
                    <Input
                      placeholder="Client ID"
                      value={clientId}
                      onChange={(e) => setClientId(e.target.value)}
                    />
                  </TextField>
                  <TextField aria-label="Client Secret">
                    <Input
                      type="password"
                      placeholder={
                        editing?.config?.client_secret_set
                          ? t("siteDetail.providers.form.clientSecretSet")
                          : "Client Secret"
                      }
                      value={clientSecret}
                      onChange={(e) => setClientSecret(e.target.value)}
                    />
                  </TextField>
                  {editing?.config?.client_secret_set ? (
                    <div className="text-muted -mt-1 text-xs">
                      {t("siteDetail.providers.form.clientSecretHint")}
                    </div>
                  ) : null}
                  <TextField aria-label="Authorization URL">
                    <Input
                      placeholder="Authorization URL"
                      value={authUrl}
                      onChange={(e) => setAuthUrl(e.target.value)}
                    />
                  </TextField>
                  <TextField aria-label="Token URL">
                    <Input
                      placeholder="Token URL"
                      value={tokenUrl}
                      onChange={(e) => setTokenUrl(e.target.value)}
                    />
                  </TextField>
                  <TextField aria-label="UserInfo URL">
                    <Input
                      placeholder="UserInfo URL"
                      value={userinfoUrl}
                      onChange={(e) => setUserinfoUrl(e.target.value)}
                    />
                  </TextField>
                  <TextField aria-label="Issuer">
                    <Input
                      placeholder={t("siteDetail.providers.form.issuerPlaceholder")}
                      value={issuer}
                      onChange={(e) => setIssuer(e.target.value)}
                    />
                  </TextField>
                  <TextField aria-label="Scopes">
                    <Input
                      placeholder={t("siteDetail.providers.form.scopesPlaceholder")}
                      value={scopes}
                      onChange={(e) => setScopes(e.target.value)}
                    />
                  </TextField>
                  <TextField aria-label="Redirect Path">
                    <Input
                      placeholder={t("siteDetail.providers.form.redirectPathPlaceholder")}
                      value={redirectPath}
                      onChange={(e) => setRedirectPath(e.target.value)}
                    />
                  </TextField>
                  <ToggleSwitch isSelected={usePkce} onChange={setUsePkce}>
                    {t("siteDetail.providers.form.usePkce")}
                  </ToggleSwitch>
                </>
              ) : null}
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
