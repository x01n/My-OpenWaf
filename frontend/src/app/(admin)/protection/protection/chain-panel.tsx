"use client";

/**
 * 连锁验证 Tab：GET/POST /chain/config + GET /chain/sessions + 删除会话。
 * 字段取自 internal/admin/protect/chain/chain.go chainConfigResponse（L14-17）
 * 与 internal/waf/challenge/chain.go ChainSessionInfo（L38-44）。
 */

import { useCallback, useEffect, useState } from "react";
import { Button } from "@heroui/react";
import { Plus, Trash2 } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton, StatCard, Pager } from "@/components/ui/primitives";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { formatDateTime } from "@/lib/utils/format";
import type { ChainConfig, ChainSession, ChainStep, ChainStepType } from "@/lib/types/protection";
import { SectionCard, SwitchRow, SelectRow } from "./field-controls";
import { CHAIN_STEP_TYPES, CHAIN_CONDITIONS, CAPTCHA_TYPES } from "./protection-model";

const PAGE_SIZE = 10;

export function ChainPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<ChainConfig>(
    useCallback(() => apiGet<ChainConfig>("/chain/config"), []),
  );
  const [page, setPage] = useState(1);
  // 后端 ListSessions 返回全量会话，分页在前端切片
  const sessions = useApi<{ items: ChainSession[]; total: number }>(
    useCallback(() => apiGet<{ items: ChainSession[]; total: number }>("/chain/sessions"), []),
  );
  const allSessions = sessions.data?.items ?? [];
  const pageSessions = allSessions.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const [form, setForm] = useState<ChainConfig | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  const patchStep = useCallback((index: number, value: ChainStep) => {
    setForm((f) => {
      if (!f) return f;
      const steps = f.chain_steps.map((s, i) => (i === index ? value : s));
      return { ...f, chain_steps: steps };
    });
  }, []);

  const removeStep = useCallback((index: number) => {
    setForm((f) => (f ? { ...f, chain_steps: f.chain_steps.filter((_, i) => i !== index) } : f));
  }, []);

  const addStep = useCallback(() => {
    setForm((f) => (f ? { ...f, chain_steps: [...f.chain_steps, { type: "env", condition: "all" }] } : f));
  }, []);

  async function save() {
    if (!form) return;
    setSaving(true);
    try {
      await apiPost("/chain/config", form);
      showSuccess(t("protection.saved"));
      await reload();
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  async function deleteSession(id: string) {
    return apiPost(`/chain/sessions/${encodeURIComponent(id)}/delete`);
  }

  const stepTypes = localizeOptions(CHAIN_STEP_TYPES, t);
  const chainConditions = localizeOptions(CHAIN_CONDITIONS, t);
  const captchaTypes = localizeOptions(CAPTCHA_TYPES, t);

  const columns: DataTableColumn<ChainSession>[] = [
    { header: t("protection.chain.col.sessionId"), render: (r) => <span className="font-mono text-xs">{r.id}</span> },
    { header: t("protection.chain.col.currentStep"), render: (r) => <span className="tabular">{r.current_step}</span> },
    { header: t("protection.chain.col.stepCount"), render: (r) => <span className="tabular">{r.step_count}</span> },
    { header: t("protection.chain.col.originalUrl"), render: (r) => <span className="max-w-xs truncate text-xs">{r.original_url}</span> },
    { header: t("protection.chain.col.startedAt"), render: (r) => <span className="text-xs">{formatDateTime(r.started_at)}</span> },
    {
      header: t("common.actions"),
      render: (r) => (
        <ConfirmButton
          onConfirm={async () => {
            await deleteSession(r.id);
            await sessions.reload();
          }}
          confirmText={t("protection.chain.deleteConfirm", { id: r.id })}
          successText={t("protection.chain.deleted")}
        >
          <Trash2 className="size-3.5" /> {t("common.delete")}
        </ConfirmButton>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !form ? (
        <CardSkeleton height="h-64" />
      ) : form ? (
        <SectionCard
          title={t("protection.chain.title")}
          description={t("protection.chain.description")}
        >
          <SwitchRow label={t("protection.chain.enabled")} value={form.chain_enabled} onChange={(v) => setForm({ ...form, chain_enabled: v })} />
          <div className="flex flex-col gap-3">
            {form.chain_steps.map((step, i) => (
              <div key={i} className="bg-default grid grid-cols-1 items-end gap-2 rounded-lg border border-separator p-3 md:grid-cols-[1fr_1.4fr_auto]">
                <SelectRow<ChainStepType>
                  label={t("protection.field.stepType", { n: i + 1 })}
                  value={step.type}
                  onChange={(v) => patchStep(i, { ...step, type: v })}
                  options={stepTypes}
                />
                <SelectRow
                  label={t("protection.field.condition")}
                  value={step.condition || "all"}
                  onChange={(v) => patchStep(i, { ...step, condition: v })}
                  options={chainConditions}
                />
                <div className="flex items-center justify-end pb-1">
                  <Button variant="danger" size="sm" onPress={() => removeStep(i)} aria-label={t("protection.field.deleteStep", { n: i + 1 })}>
                    <Trash2 className="size-3.5" /> {t("common.delete")}
                  </Button>
                </div>
                {step.type === "captcha" && (
                  <div className="md:col-span-3">
                    <SelectRow
                      label={t("protection.chain.captchaType")}
                      value={step.captcha_type ?? ""}
                      onChange={(v) => patchStep(i, { ...step, captcha_type: v })}
                      options={[
                        { key: "", label: t("protection.action.inheritGlobal") },
                        ...captchaTypes,
                      ]}
                    />
                  </div>
                )}
              </div>
            ))}
            <div>
              <Button variant="outline" size="sm" onPress={addStep}>
                <Plus className="size-3.5" /> {t("protection.field.addStep")}
              </Button>
            </div>
          </div>
          <div className="flex justify-end">
            <Button variant="primary" isPending={saving} onPress={save}>
              {t("protection.chain.save")}
            </Button>
          </div>
        </SectionCard>
      ) : null}

      {/* 进行中的连锁会话 */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label={t("protection.chain.sessions.stat")} value={allSessions.length} tone="info" />
      </div>

      <div className="bg-surface rounded-xl border border-separator p-4">
        <h3 className="mb-3 text-sm font-medium">{t("protection.chain.sessions.title")}</h3>
        {sessions.error ? (
          <ErrorState message={sessions.error} onRetry={sessions.reload} />
        ) : (
          <>
            <DataTable ariaLabel={t("protection.chain.listAria")} columns={columns} rows={pageSessions} loading={sessions.loading} emptyMessage={t("protection.chain.empty")} />
            <Pager page={page} pageSize={PAGE_SIZE} total={allSessions.length} onPageChange={setPage} />
          </>
        )}
      </div>
    </div>
  );
}
