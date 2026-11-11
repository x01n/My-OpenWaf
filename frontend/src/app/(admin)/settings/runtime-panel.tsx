"use client";

/**
 * 运行时配置面板：
 * - GET /runtime-config 只读展示（revision、db_driver、data_dir、redis、
 *   tls_capabilities、upstream_transport_pools）
 * - GET/POST /runtime-config/env-overrides：三态清单 + 可写键的覆盖 / 清除
 *   （写体 {overrides:{key:value}} 或 {clear:[key]}，见 runtime_overrides.go）
 */

import { useCallback, useState } from "react";
import {
  Button,
  Chip,
  TextField,
  Input,
  Select,
  ListBox,
  useOverlayState,
} from "@heroui/react";
import { Pencil, RotateCcw } from "lucide-react";
import { apiGet, apiPost } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { SimpleSelect, StatusChip } from "@/components/ui/primitives";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { FormDialog } from "@/components/ui/dialogs";
import { showError } from "@/components/ui/toast-host";
import {
  PanelCard,
  PanelError,
  PanelSkeleton,
  Field,
  WarningBanner,
  SourceChip,
  valueText,
} from "./form-kit";
import type {
  RuntimeConfig,
  RuntimeOverrideItem,
  RuntimeOverridesResponse,
  TLSCapabilityStatus,
} from "@/lib/types/settings";

/* ---------- 运行态概览 ---------- */

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-muted text-xs">{label}</div>
      <div className="tabular mt-0.5 text-sm font-medium">{value}</div>
    </div>
  );
}

function RuntimeOverview({ data }: { data: RuntimeConfig }) {
  const { t } = useI18n();
  const pools = data.upstream_transport_pools;
  return (
    <PanelCard title={t("settings.runtime.overview.title")} description={t("settings.runtime.overview.description")}>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <InfoItem label={t("settings.runtime.overview.revision")} value={`#${data.revision}`} />
        <InfoItem label={t("settings.runtime.overview.dbDriver")} value={data.db_driver || "-"} />
        <InfoItem label={t("settings.runtime.overview.dataDir")} value={data.data_dir || "-"} />
        <InfoItem
          label="Redis"
          value={
            data.redis_enabled
              ? `${data.redis_addr} / db ${data.redis_db}`
              : t("settings.runtime.overview.redisDisabled")
          }
        />
        <InfoItem label={t("settings.runtime.overview.totalTransports")} value={String(pools.total_transports)} />
        <InfoItem label={t("settings.runtime.overview.httpTransports")} value={String(pools.http_transports)} />
        <InfoItem label={t("settings.runtime.overview.http3Transports")} value={String(pools.http3_transports)} />
        <InfoItem label={t("settings.runtime.overview.totalClients")} value={String(pools.total_clients)} />
      </div>
    </PanelCard>
  );
}

const CAP_TONE: Record<string, "success" | "warning" | "danger" | "info" | "neutral"> = {
  enabled: "success",
  supported: "success",
  disabled: "warning",
  not_supported: "danger",
};

function CapabilitiesCard({ data }: { data: RuntimeConfig }) {
  const { t } = useI18n();
  const rows = data.tls_capabilities.map((c) => ({ ...c, id: c.key }));
  const columns: DataTableColumn<TLSCapabilityStatus & { id: string }>[] = [
    { header: t("settings.runtime.caps.colCapability"), render: (r) => <span className="text-sm">{r.label}</span> },
    {
      header: t("settings.runtime.caps.colStatus"),
      render: (r) => (
        <StatusChip tone={CAP_TONE[r.status] ?? "neutral"}>{r.status}</StatusChip>
      ),
    },
    {
      header: t("settings.runtime.caps.colDetail"),
      className: "max-w-[480px]",
      render: (r) => (
        <span className="text-muted block text-xs leading-5" title={r.detail}>
          {r.detail}
        </span>
      ),
    },
    {
      header: t("settings.runtime.caps.colMissing"),
      render: (r) => (r.missing ? t("settings.runtime.yes") : t("settings.runtime.no")),
    },
  ];
  return (
    <PanelCard
      title={t("settings.runtime.caps.title")}
      description={t("settings.runtime.caps.description")}
    >
      <DataTable
        ariaLabel={t("settings.runtime.caps.listAria")}
        columns={columns}
        rows={rows}
        emptyMessage={t("settings.runtime.caps.empty")}
      />
    </PanelCard>
  );
}

/* ---------- 环境变量覆盖 ---------- */

function overrideInputType(type: string): string {
  if (type === "int") return "number";
  return "text";
}

/** 按键类型把文本输入转换为提交 JSON 值 */
function parseOverrideValue(item: RuntimeOverrideItem, raw: string): unknown {
  switch (item.type) {
    case "bool":
      return raw === "true";
    case "int": {
      const n = Number(raw);
      return Number.isNaN(n) ? raw : n;
    }
    default:
      return raw;
  }
}

function OverrideDialog({
  item,
  state,
  onSaved,
}: {
  item: RuntimeOverrideItem;
  state: ReturnType<typeof useOverlayState>;
  onSaved: () => void;
}) {
  const initial =
    item.overridden && item.value !== null && item.value !== undefined
      ? String(item.value)
      : item.default_value === null || item.default_value === undefined
        ? ""
        : String(item.default_value);
  const [value, setValue] = useState(initial);
  const [saving, setSaving] = useState(false);
  const { t } = useI18n();

  const boundHint =
    item.min !== null || item.max !== null
      ? t("settings.runtime.override.rangeHint", {
          min: String(item.min ?? "-∞"),
          max: String(item.max ?? "+∞"),
        })
      : undefined;

  async function submit() {
    setSaving(true);
    try {
      await apiPost("/runtime-config/env-overrides", {
        overrides: { [item.key]: parseOverrideValue(item, value) },
      });
      state.close();
      onSaved();
    } catch (err) {
      showError(
        t("settings.runtime.override.saveFailed"),
        err instanceof Error ? err.message : undefined,
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <FormDialog
      state={state}
      title={t("settings.runtime.override.title", { key: item.key })}
      description={
        item.description || t("settings.runtime.override.description", { env: item.env || "-" })
      }
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" isPending={saving} onPress={() => void submit()}>
            {t("settings.runtime.override.save")}
          </Button>
        </>
      }
    >
      {item.enum_values && item.enum_values.length > 0 ? (
        <Field label={t("settings.runtime.override.enumValue")}>
          <Select
            aria-label={t("settings.runtime.override.valueLabel")}
            selectedKey={item.enum_values.includes(value) ? value : null}
            onSelectionChange={(key) => {
              if (key !== null) setValue(key as string);
            }}
          >
            <ListBox>
              {item.enum_values.map((v) => (
                <ListBox.Item key={v} id={v} textValue={v}>
                  {v}
                </ListBox.Item>
              ))}
            </ListBox>
          </Select>
        </Field>
      ) : item.type === "bool" ? (
        <Field label={t("settings.runtime.override.value")}>
          <SimpleSelect
            className="w-full"
            value={value === "true" ? "true" : "false"}
            onChange={(v) => setValue(v)}
            options={[
              { key: "true", label: "true" },
              { key: "false", label: "false" },
            ]}
          />
        </Field>
      ) : (
        <Field label={t("settings.runtime.override.valueLabel")} hint={boundHint}>
          <TextField aria-label={t("settings.runtime.override.valueLabel")}>
            <Input
              type={overrideInputType(item.type)}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          </TextField>
        </Field>
      )}
    </FormDialog>
  );
}

function OverridesCard() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<RuntimeOverridesResponse>(
    useCallback(() => apiGet<RuntimeOverridesResponse>("/runtime-config/env-overrides"), []),
  );
  const [editing, setEditing] = useState<RuntimeOverrideItem | null>(null);
  const dialogState = useOverlayState();

  const rows = (data?.items ?? []).map((it) => ({ ...it, id: it.key }));
  const columns: DataTableColumn<RuntimeOverrideItem & { id: string }>[] = [
    {
      header: t("settings.runtime.overrides.colKey"),
      render: (r) => (
        <span className="font-mono text-xs" title={r.description}>
          {r.key}
        </span>
      ),
    },
    {
      header: t("settings.runtime.overrides.colEnv"),
      render: (r) => <span className="font-mono text-muted text-xs">{r.env || "-"}</span>,
    },
    { header: t("settings.runtime.overrides.colType"), render: (r) => <span className="text-muted text-xs">{r.type}</span> },
    { header: t("settings.runtime.overrides.colDefault"), render: (r) => <span className="tabular text-xs">{valueText(r.default_value)}</span> },
    {
      header: t("settings.runtime.overrides.colEffective"),
      render: (r) =>
        r.sensitive ? (
          <Chip size="sm" variant="soft" color={r.secret_set ? "success" : "default"}>
            {r.secret_set ? t("settings.panel.set") : t("settings.panel.unset")}
          </Chip>
        ) : (
          <span className="tabular text-xs">{valueText(r.effective_value)}</span>
        ),
    },
    { header: t("settings.runtime.overrides.colSource"), render: (r) => <SourceChip source={r.source} /> },
    {
      header: t("settings.runtime.overrides.colOverridden"),
      render: (r) => (r.overridden ? t("settings.runtime.yes") : t("settings.runtime.no")),
    },
    {
      header: t("common.actions"),
      className: "w-40",
      render: (r) =>
        r.editable ? (
          <div className="flex items-center gap-1.5">
            <Button
              size="sm"
              variant="outline"
              onPress={() => {
                setEditing(r);
                dialogState.open();
              }}
            >
              <Pencil className="size-3.5" /> {t("settings.runtime.overrides.overrideBtn")}
            </Button>
            {r.overridden && (
              <ConfirmButton
                variant="ghost"
                confirmText={t("settings.runtime.overrides.clearConfirm", { key: r.key })}
                title={t("settings.runtime.overrides.clearTitle")}
                successText={t("settings.runtime.overrides.clearSuccess")}
                onConfirm={async () => {
                  await apiPost("/runtime-config/env-overrides", { clear: [r.key] });
                  void reload();
                }}
              >
                <RotateCcw className="size-3.5" /> {t("settings.runtime.overrides.clearBtn")}
              </ConfirmButton>
            )}
          </div>
        ) : (
          <span className="text-muted text-xs">{t("settings.runtime.overrides.notWritable")}</span>
        ),
    },
  ];

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading && !data) return <PanelSkeleton />;

  return (
    <PanelCard
      title={t("settings.runtime.overrides.title")}
      description={t("settings.runtime.overrides.description")}
    >
      {data?.warnings && data.warnings.length > 0 && (
        <WarningBanner>
          <div className="flex flex-col gap-1">
            {data.warnings.map((w, i) => (
              <span key={i}>{w}</span>
            ))}
          </div>
        </WarningBanner>
      )}
      <DataTable
        ariaLabel={t("settings.runtime.overrides.listAria")}
        columns={columns}
        rows={rows}
        loading={loading}
        emptyMessage={t("settings.runtime.overrides.empty")}
      />
      {editing && (
        <OverrideDialog
          key={editing.key}
          item={editing}
          state={dialogState}
          onSaved={() => void reload()}
        />
      )}
    </PanelCard>
  );
}

/* ---------- 面板入口 ---------- */

/** 配置快照重载：POST /reload（opsGroup，admin/operator 可写） */
function ReloadCard() {
  const { t } = useI18n();
  return (
    <PanelCard
      title={t("settings.runtime.reload.title")}
      description={t("settings.runtime.reload.description")}
    >
      <div className="flex flex-wrap items-center gap-3">
        <ConfirmButton
          variant="ghost"
          title={t("settings.runtime.reload.confirmTitle")}
          confirmText={t("settings.runtime.reload.confirmText")}
          successText={t("settings.runtime.reload.success")}
          onConfirm={() => apiPost("/reload")}
        >
          <RotateCcw className="size-3.5" /> {t("settings.runtime.reload.btn")}
        </ConfirmButton>
      </div>
    </PanelCard>
  );
}

export function RuntimePanel() {
  const { data, loading, error, reload } = useApi<RuntimeConfig>(
    useCallback(() => apiGet<RuntimeConfig>("/runtime-config"), []),
  );

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading && !data) return <PanelSkeleton />;
  if (!data) return null;

  return (
    <div className="flex flex-col gap-4">
      <RuntimeOverview data={data} />
      <CapabilitiesCard data={data} />
      <ReloadCard />
      <OverridesCard />
    </div>
  );
}
