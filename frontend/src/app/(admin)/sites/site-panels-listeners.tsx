"use client";

/**
 * 站点详情「监听器」面板：监听地址、网络协议与 TLS 证书绑定。
 *
 * 后端契约：
 * - GET  /sites/:id/listeners
 * - POST /sites/:id/listeners
 * - POST /sites/:id/listeners/:lid/update
 * - POST /sites/:id/listeners/:lid/delete
 */

import { useCallback, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input } from "@heroui/react";
import { Plus, Pencil } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type { Certificate } from "@/lib/types/site";
import type { SiteListenerItem, SiteListenerPayload } from "@/lib/types/site-admin";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { SimpleSelect, StatusChip, ToggleSwitch } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";

export function ListenersPanel({
  siteId,
  certs,
  onChanged,
}: {
  siteId: number;
  certs: Certificate[];
  onChanged: () => void;
}) {
  const { t } = useI18n();
  const list = useApi(
    useCallback(() => apiGet<ListResponse<SiteListenerItem>>(`/sites/${siteId}/listeners`), [siteId]),
  );
  const items = list.data?.items ?? [];

  const [editing, setEditing] = useState<SiteListenerItem | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  const formState = useOverlayState();

  function openForm(row: SiteListenerItem | null) {
    setEditing(row);
    setFormVisible(true);
    formState.open();
  }

  const columns: DataTableColumn<SiteListenerItem>[] = [
    {
      header: t("siteDetail.field.bind"),
      render: (row) => <span className="font-medium break-all">{row.bind}</span>,
    },
    {
      header: t("siteDetail.listeners.network"),
      render: (row) => row.network?.toUpperCase() ?? "-",
    },
    {
      header: t("siteDetail.listeners.tls"),
      render: (row) => (
        <StatusChip tone={row.tls_enabled ? "success" : "neutral"}>
          {row.tls_enabled ? "HTTPS" : "HTTP"}
        </StatusChip>
      ),
    },
    {
      header: t("siteDetail.listeners.certId"),
      render: (row) => <span className="tabular">{row.cert_id ?? "-"}</span>,
    },
    {
      header: t("siteDetail.listeners.status"),
      render: (row) => (
        <StatusChip tone={row.enabled ? "success" : "neutral"}>
          {row.enabled ? t("common.enabled") : t("common.disabled")}
        </StatusChip>
      ),
    },
    { header: t("siteDetail.listeners.note"), render: (row) => row.note || "-" },
    {
      header: t("common.actions"),
      render: (row) => (
        <div className="flex items-center gap-1.5">
          <Button size="sm" variant="outline" onPress={() => openForm(row)}>
            <Pencil className="size-3.5" /> {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("siteDetail.listeners.deleteConfirm", { bind: row.bind })}
            successText={t("siteDetail.listeners.deleted")}
            onConfirm={async () => {
              await apiPost(`/sites/${siteId}/listeners/${row.id}/delete`);
              void list.reload();
              onChanged();
            }}
          >
            {t("common.delete")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-2 py-2">
      <div className="flex justify-end">
        <Button size="sm" variant="primary" onPress={() => openForm(null)}>
          <Plus className="size-3.5" /> {t("siteDetail.listeners.create")}
        </Button>
      </div>
      <DataTable
        ariaLabel={t("siteDetail.listeners.listAria")}
        columns={columns}
        rows={items.length > 0 ? items : undefined}
        loading={list.loading}
        emptyMessage={t("siteDetail.listeners.empty")}
      />
      {formVisible ? (
        <ListenerFormModal
          key={editing ? `listener-${editing.id}` : "listener-new"}
          state={formState}
          siteId={siteId}
          editing={editing}
          certs={certs}
          onSaved={() => {
            void list.reload();
            onChanged();
            setFormVisible(false);
          }}
        />
      ) : null}
    </div>
  );
}

/** 监听器新建/编辑弹窗（字段宽松处理：仅 bind 必填，其余走后端默认值）。 */
function ListenerFormModal({
  state,
  siteId,
  editing,
  certs,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  siteId: number;
  editing: SiteListenerItem | null;
  certs: Certificate[];
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [bind, setBind] = useState(editing?.bind ?? "");
  const [network, setNetwork] = useState(editing?.network ?? "tcp");
  const [tlsEnabled, setTlsEnabled] = useState(editing?.tls_enabled ?? false);
  const [certId, setCertId] = useState(editing?.cert_id ? String(editing.cert_id) : "none");
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [note, setNote] = useState(editing?.note ?? "");
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!bind.trim()) {
      showError(t("siteDetail.listeners.error.bind"), t("siteDetail.listeners.error.bindHint"));
      return;
    }
    setSaving(true);
    const payload: SiteListenerPayload = {
      bind: bind.trim(),
      network,
      tls_enabled: tlsEnabled,
      cert_id: certId === "none" ? null : Number(certId),
      enabled,
      note: note.trim() || undefined,
    };
    try {
      if (editing) {
        await apiPost(`/sites/${siteId}/listeners/${editing.id}/update`, payload);
      } else {
        await apiPost(`/sites/${siteId}/listeners`, payload);
      }
      showSuccess(
        editing ? t("siteDetail.listeners.saved.update") : t("siteDetail.listeners.saved.create"),
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
        <Modal.Container size="lg">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>
                {editing
                  ? t("siteDetail.listeners.form.edit")
                  : t("siteDetail.listeners.form.create")}
              </Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <TextField aria-label={t("siteDetail.field.bind")} isRequired>
                <Input
                  placeholder={t("siteDetail.listeners.form.bindPlaceholder")}
                  value={bind}
                  onChange={(e) => setBind(e.target.value)}
                />
              </TextField>
              <div className="flex items-end gap-4">
                <SimpleSelect
                  value={network}
                  onChange={setNetwork}
                  label={t("siteDetail.listeners.form.network")}
                  className="w-36"
                  options={[
                    { key: "tcp", label: t("siteDetail.network.tcp") },
                    { key: "udp", label: t("siteDetail.network.udp") },
                  ]}
                />
                <SimpleSelect
                  value={certId}
                  onChange={setCertId}
                  label={t("siteDetail.listeners.form.cert")}
                  options={[
                    { key: "none", label: t("sites.form.certNone") },
                    ...certs.map((c) => ({
                      key: String(c.id),
                      label: c.domain
                        ? t("siteDetail.listeners.form.certOption", { name: c.name, domain: c.domain })
                        : c.name,
                    })),
                  ]}
                />
              </div>
              <div className="flex items-center gap-6">
                <ToggleSwitch isSelected={tlsEnabled} onChange={setTlsEnabled}>
                  {t("siteDetail.listeners.form.tlsEnabled")}
                </ToggleSwitch>
                <ToggleSwitch isSelected={enabled} onChange={setEnabled}>
                  {t("siteDetail.listeners.form.listenerEnabled")}
                </ToggleSwitch>
              </div>
              <TextField aria-label={t("siteDetail.listeners.note")}>
                <Input
                  placeholder={t("siteDetail.listeners.form.notePlaceholder")}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                />
              </TextField>
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
