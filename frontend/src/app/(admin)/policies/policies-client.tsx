"use client";

/**
 * 策略页面入口：列表 + 新建 / 编辑弹窗 + OWASP 概要抽屉编排。
 *
 * 表单弹窗与抽屉分别实现于同目录下的单一职责文件；
 * 弹窗通过 `key` 重挂载避免新建与编辑串值。
 */

import { useCallback, useState } from "react";
import { useOverlayState, Button, Chip } from "@heroui/react";
import { Plus, ChartColumn } from "lucide-react";
import { apiPost } from "@/lib/api/client";
import { useList } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import type { Policy } from "@/lib/types/rule";
import { formatDateTime } from "@/lib/utils/format";
import { PageHeader, Pager, ErrorState } from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { PolicyFormDialog } from "./policy-form-dialog";
import { PolicyOwaspDrawer } from "./policy-owasp-drawer";

function PoliciesClient() {
  const { t } = useI18n();
  const [formVisible, setFormVisible] = useState(false);
  const [editing, setEditing] = useState<Policy | null>(null);
  const formState = useOverlayState();
  const [detail, setDetail] = useState<Policy | null>(null);
  const detailState = useOverlayState();

  const list = useList<Policy>("/policies");

  /** 打开新建（policy = null）或编辑弹窗 */
  const openForm = useCallback(
    (policy: Policy | null) => {
      setEditing(policy);
      setFormVisible(true);
      formState.open();
    },
    [formState],
  );

  const openDetail = useCallback(
    (policy: Policy) => {
      setDetail(policy);
      detailState.open();
    },
    [detailState],
  );

  const columns: DataTableColumn<Policy>[] = [
    {
      header: t("policies.col.name"),
      render: (p) => (
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">{p.name}</span>
          {p.is_default && (
            <Chip size="sm" variant="soft" color="success">
              {t("policies.defaultBadge")}
            </Chip>
          )}
        </div>
      ),
    },
    {
      header: t("policies.col.description"),
      render: (p) => <span className="text-muted">{p.description || "-"}</span>,
    },
    {
      header: t("policies.col.isDefault"),
      render: (p) =>
        p.is_default ? (
          <Chip size="sm" variant="soft" color="success">
            {t("policies.yes")}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="default">
            {t("policies.no")}
          </Chip>
        ),
    },
    {
      header: t("policies.col.createdAt"),
      render: (p) => <span className="text-muted text-xs">{formatDateTime(p.created_at)}</span>,
    },
    {
      header: t("common.actions"),
      render: (p) => (
        <div className="flex items-center gap-1.5">
          <Button size="sm" variant="outline" onPress={() => openDetail(p)}>
            <ChartColumn className="size-3.5" /> {t("policies.owaspSummary")}
          </Button>
          <Button size="sm" variant="outline" onPress={() => openForm(p)}>
            {t("common.edit")}
          </Button>
          <ConfirmButton
            variant="primary"
            isDisabled={p.is_default}
            confirmText={t("policies.setDefaultConfirm", { name: p.name })}
            successText={t("policies.setDefaultSuccess")}
            onConfirm={async () => {
              await apiPost(`/policies/${p.id}/set-default`);
              void list.reload();
            }}
          >
            {t("policies.setDefault")}
          </ConfirmButton>
          <ConfirmButton
            confirmText={t("policies.deleteConfirm", { name: p.name })}
            successText={t("policies.deleteSuccess")}
            onConfirm={async () => {
              await apiPost(`/policies/${p.id}/delete`);
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
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("policies.title")}
        description={t("policies.description")}
        actions={
          <Button variant="primary" onPress={() => openForm(null)}>
            <Plus className="size-4" /> {t("policies.create")}
          </Button>
        }
      />

      {list.error ? (
        <ErrorState message={list.error} onRetry={list.reload} />
      ) : (
        <DataTable
          ariaLabel={t("policies.listAria")}
          columns={columns}
          rows={list.items}
          loading={list.loading}
          emptyMessage={t("policies.empty")}
        />
      )}
      <Pager page={list.page} pageSize={list.pageSize} total={list.total} onPageChange={list.setPage} />

      {formVisible ? (
        <PolicyFormDialog
          key={editing ? `policy-edit-${editing.id}` : "policy-create"}
          state={formState}
          editing={editing}
          onSaved={() => {
            setFormVisible(false);
            void list.reload();
          }}
        />
      ) : null}

      <PolicyOwaspDrawer state={detailState} policy={detail} />
    </div>
  );
}

export default PoliciesClient;
