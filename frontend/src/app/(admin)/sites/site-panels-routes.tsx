"use client";

/**
 * 站点详情「应用路由规则」面板：按目标字段与操作符匹配请求并路由。
 *
 * 后端契约：
 * - GET  /sites/:id/application-route-rules
 * - POST /sites/:id/application-route-rules
 * - POST /sites/:id/application-route-rules/:rid/update
 * - POST /sites/:id/application-route-rules/:rid/delete
 */

import { useCallback, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input } from "@heroui/react";
import { Plus, Pencil } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type {
  ApplicationRouteRule,
  ApplicationRouteRulePayload,
} from "@/lib/types/site-admin";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { SimpleSelect, StatusChip, ToggleSwitch } from "@/components/ui/primitives";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n, type MessageKey } from "@/i18n";

/** 匹配目标 → 语言包键（internal/admin/site 路由规则 target）。 */
const TARGET_LABEL_KEYS: Record<string, MessageKey> = {
  request_header: "siteDetail.routes.target.requestHeader",
  request_body: "siteDetail.routes.target.requestBody",
  response_body: "siteDetail.routes.target.responseBody",
  request_headers_full: "siteDetail.routes.target.requestHeadersFull",
  response_headers_full: "siteDetail.routes.target.responseHeadersFull",
  full_http_request: "siteDetail.routes.target.fullHttpRequest",
  full_http_response: "siteDetail.routes.target.fullHttpResponse",
  request_method: "siteDetail.routes.target.requestMethod",
  fingerprint: "siteDetail.routes.target.fingerprint",
};

/** 匹配操作符 → 语言包键。 */
const OP_LABEL_KEYS: Record<string, MessageKey> = {
  eq: "siteDetail.routes.op.eq",
  ne: "siteDetail.routes.op.ne",
  contains: "siteDetail.routes.op.contains",
  not_contains: "siteDetail.routes.op.notContains",
  prefix: "siteDetail.routes.op.prefix",
  suffix: "siteDetail.routes.op.suffix",
  regex: "siteDetail.routes.op.regex",
  fuzzy: "siteDetail.routes.op.fuzzy",
};

export function RulesPanel({
  siteId,
  onChanged,
}: {
  siteId: number;
  onChanged: () => void;
}) {
  const { t } = useI18n();
  const list = useApi(
    useCallback(
      () =>
        apiGet<ListResponse<ApplicationRouteRule>>(`/sites/${siteId}/application-route-rules`, {
          page: 1,
          page_size: 100,
        }),
      [siteId],
    ),
  );
  const items = list.data?.items ?? [];

  const [editing, setEditing] = useState<ApplicationRouteRule | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  const formState = useOverlayState();

  function openForm(row: ApplicationRouteRule | null) {
    setEditing(row);
    setFormVisible(true);
    formState.open();
  }

  const columns: DataTableColumn<ApplicationRouteRule>[] = [
    {
      header: t("rules.col.name"),
      render: (row) => <span className="font-medium">{row.name || "-"}</span>,
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
      header: t("rules.col.priority"),
      render: (row) => <span className="tabular">{row.priority}</span>,
    },
    {
      header: t("siteDetail.routes.col.target"),
      className: "text-xs",
      render: (row) => {
        const targetKey = TARGET_LABEL_KEYS[row.target];
        const opKey = OP_LABEL_KEYS[row.op];
        const target = targetKey ? t(targetKey) : row.target;
        const op = opKey ? t(opKey) : row.op;
        return `${target} · ${op}`;
      },
    },
    {
      header: t("siteDetail.routes.col.pattern"),
      className: "max-w-40",
      render: (row) => <span className="text-muted break-all">{row.pattern}</span>,
    },
    { header: "Header", render: (row) => row.header_key || "-" },
    {
      header: t("common.actions"),
      render: (row) => (
        <div className="flex items-center gap-1.5">
          <Button size="sm" variant="outline" onPress={() => openForm(row)}>
            <Pencil className="size-3.5" /> {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("siteDetail.routes.deleteConfirm", { name: row.name || row.id })}
            successText={t("siteDetail.routes.deleted")}
            onConfirm={async () => {
              await apiPost(`/sites/${siteId}/application-route-rules/${row.id}/delete`);
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
          <Plus className="size-3.5" /> {t("siteDetail.routes.create")}
        </Button>
      </div>
      <DataTable
        ariaLabel={t("siteDetail.routes.listAria")}
        columns={columns}
        rows={items.length > 0 ? items : undefined}
        loading={list.loading}
        emptyMessage={t("siteDetail.routes.empty")}
      />
      {formVisible ? (
        <RuleFormModal
          key={editing ? `rule-${editing.id}` : "rule-new"}
          state={formState}
          siteId={siteId}
          editing={editing}
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

/** 应用路由规则新建/编辑弹窗。 */
function RuleFormModal({
  state,
  siteId,
  editing,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  siteId: number;
  editing: ApplicationRouteRule | null;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [name, setName] = useState(editing?.name ?? "");
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [priority, setPriority] = useState(String(editing?.priority ?? 0));
  const [target, setTarget] = useState(editing?.target ?? "request_header");
  const [op, setOp] = useState(editing?.op ?? "contains");
  const [pattern, setPattern] = useState(editing?.pattern ?? "");
  const [headerKey, setHeaderKey] = useState(editing?.header_key ?? "");
  const [saving, setSaving] = useState(false);

  const targetOptions = Object.entries(TARGET_LABEL_KEYS).map(([key, labelKey]) => ({
    key,
    label: t(labelKey),
  }));
  const opOptions = Object.entries(OP_LABEL_KEYS).map(([key, labelKey]) => ({
    key,
    label: t(labelKey),
  }));

  async function handleSave() {
    if (!pattern.trim()) {
      showError(t("siteDetail.routes.error.pattern"), t("siteDetail.routes.error.patternHint"));
      return;
    }
    setSaving(true);
    const payload: ApplicationRouteRulePayload = {
      name: name.trim(),
      enabled,
      priority: Number(priority) || 0,
      target,
      op,
      pattern: pattern.trim(),
      header_key: headerKey.trim() || undefined,
    };
    try {
      if (editing) {
        await apiPost(`/sites/${siteId}/application-route-rules/${editing.id}/update`, payload);
      } else {
        await apiPost(`/sites/${siteId}/application-route-rules`, payload);
      }
      showSuccess(
        editing ? t("siteDetail.routes.saved.update") : t("siteDetail.routes.saved.create"),
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
                {editing ? t("siteDetail.routes.form.edit") : t("siteDetail.routes.form.create")}
              </Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <TextField aria-label={t("rules.col.name")}>
                <Input
                  placeholder={t("siteDetail.routes.form.namePlaceholder")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </TextField>
              <div className="flex items-end gap-4">
                <TextField aria-label={t("rules.col.priority")}>
                  <Input
                    type="number"
                    placeholder={t("rules.col.priority")}
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  />
                </TextField>
                <SimpleSelect
                  value={target}
                  onChange={setTarget}
                  label={t("siteDetail.routes.form.target")}
                  className="w-44"
                  options={targetOptions}
                />
                <SimpleSelect
                  value={op}
                  onChange={setOp}
                  label={t("siteDetail.routes.form.op")}
                  className="w-36"
                  options={opOptions}
                />
              </div>
              <TextField aria-label={t("siteDetail.routes.col.pattern")} isRequired>
                <Input
                  placeholder={t("siteDetail.routes.form.patternPlaceholder")}
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                />
              </TextField>
              {target === "request_header" ? (
                <TextField aria-label="Header" isRequired>
                  <Input
                    placeholder={t("siteDetail.routes.form.headerPlaceholder")}
                    value={headerKey}
                    onChange={(e) => setHeaderKey(e.target.value)}
                  />
                </TextField>
              ) : null}
              <ToggleSwitch isSelected={enabled} onChange={setEnabled}>
                {t("siteDetail.routes.form.enabled")}
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
