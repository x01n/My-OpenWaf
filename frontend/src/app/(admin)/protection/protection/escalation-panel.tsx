"use client";

/**
 * 分级升级 Tab：GET/POST /protection/global/escalation
 * + GET /escalation/status/:ip + POST /escalation/status/:ip/reset。
 * 字段取自 internal/admin/protect/escalation/escalation.go（L31-35、L48-79）
 * 与 internal/waf/escalation/escalation.go IPEscalationStatus（L215-220）。
 */

import { useCallback, useEffect, useState } from "react";
import { Button, TextField, Input } from "@heroui/react";
import { Plus, Trash2, Search, RotateCcw } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton } from "@/components/ui/primitives";
import type { EscalationConfig, EscalationIPStatus, EscalationStep } from "@/lib/types/protection";
import { SectionCard, SwitchRow, NumberField, SelectRow } from "./field-controls";
import { ESCALATION_ACTIONS } from "./protection-model";

export function EscalationPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<EscalationConfig>(
    useCallback(() => apiGet<EscalationConfig>("/protection/global/escalation"), []),
  );
  const [form, setForm] = useState<EscalationConfig | null>(null);
  const [saving, setSaving] = useState(false);

  const [ip, setIp] = useState("");
  const [status, setStatus] = useState<EscalationIPStatus | null>(null);
  const [querying, setQuerying] = useState(false);

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  const patchStep = useCallback((index: number, value: EscalationStep) => {
    setForm((f) => {
      if (!f) return f;
      return { ...f, escalation_steps: f.escalation_steps.map((s, i) => (i === index ? value : s)) };
    });
  }, []);

  const removeStep = useCallback((index: number) => {
    setForm((f) => (f ? { ...f, escalation_steps: f.escalation_steps.filter((_, i) => i !== index) } : f));
  }, []);

  const addStep = useCallback(() => {
    setForm((f) => {
      if (!f) return f;
      const last = f.escalation_steps[f.escalation_steps.length - 1];
      return {
        ...f,
        escalation_steps: [
          ...f.escalation_steps,
          { threshold: last ? last.threshold + 10 : 10, action: "challenge" },
        ],
      };
    });
  }, []);

  async function save() {
    if (!form) return;
    setSaving(true);
    try {
      await apiPost("/protection/global/escalation", form);
      showSuccess(t("protection.saved"));
      await reload();
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  async function queryStatus() {
    const target = ip.trim();
    if (!target) {
      showError(t("protection.escalation.status.ipRequired"));
      return;
    }
    setQuerying(true);
    try {
      const result = await apiGet<EscalationIPStatus>(`/escalation/status/${encodeURIComponent(target)}`);
      setStatus(result);
    } catch (err) {
      setStatus(null);
      showError(t("protection.escalation.status.queryFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setQuerying(false);
    }
  }

  async function resetStatus() {
    const target = ip.trim();
    if (!target) return;
    try {
      await apiPost(`/escalation/status/${encodeURIComponent(target)}/reset`);
      showSuccess(t("protection.escalation.status.resetSuccess"));
      await queryStatus();
    } catch (err) {
      showError(t("protection.escalation.status.resetFailed"), err instanceof ApiError ? err.message : undefined);
    }
  }

  const escalationActions = localizeOptions(ESCALATION_ACTIONS, t);

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !form ? (
        <CardSkeleton height="h-80" />
      ) : form ? (
        <SectionCard
          title={t("protection.escalation.title")}
          description={t("protection.escalation.description")}
        >
          <SwitchRow label={t("protection.escalation.enabled")} value={form.escalation_enabled} onChange={(v) => setForm({ ...form, escalation_enabled: v })} />
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <NumberField label={t("protection.escalation.window")} value={form.escalation_window_secs} onChange={(v) => setForm({ ...form, escalation_window_secs: v })} min={1} />
          </div>
          <div className="flex flex-col gap-3">
            {form.escalation_steps.map((step, i) => (
              <div key={i} className="bg-default grid grid-cols-1 items-end gap-2 rounded-lg border border-separator p-3 md:grid-cols-[1fr_1.4fr_auto]">
                <NumberField label={t("protection.field.stepThreshold", { n: i + 1 })} value={step.threshold} onChange={(v) => patchStep(i, { ...step, threshold: v })} min={1} />
                <SelectRow label={t("protection.escalation.stepAction")} value={step.action} onChange={(v) => patchStep(i, { ...step, action: v })} options={escalationActions} />
                <div className="flex items-center justify-end pb-1">
                  <Button variant="danger" size="sm" onPress={() => removeStep(i)} aria-label={t("protection.field.deleteStep", { n: i + 1 })}>
                    <Trash2 className="size-3.5" /> {t("common.delete")}
                  </Button>
                </div>
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
              {t("protection.escalation.save")}
            </Button>
          </div>
        </SectionCard>
      ) : null}

      {/* IP 状态查询 */}
      <SectionCard
        title={t("protection.escalation.status.title")}
        description={t("protection.escalation.status.description")}
      >
        <div className="flex flex-wrap items-end gap-2">
          <TextField aria-label={t("protection.escalation.status.ipLabel")} className="w-64">
            <Input placeholder={t("protection.escalation.status.ipPlaceholder")} value={ip} onChange={(e) => setIp(e.target.value)} />
          </TextField>
          <Button variant="primary" isPending={querying} onPress={queryStatus}>
            <Search className="size-3.5" /> {t("protection.escalation.status.query")}
          </Button>
          <Button variant="outline" onPress={resetStatus} isDisabled={!ip.trim()}>
            <RotateCcw className="size-3.5" /> {t("protection.escalation.status.reset")}
          </Button>
        </div>
        {status && (
          <div className="bg-default grid grid-cols-2 gap-3 rounded-lg border border-separator p-3 text-sm md:grid-cols-4">
            <div>
              <div className="text-muted text-xs">IP</div>
              <div className="font-mono">{status.ip}</div>
            </div>
            <div>
              <div className="text-muted text-xs">{t("protection.escalation.status.hitCount")}</div>
              <div className="tabular">{status.hit_count}</div>
            </div>
            <div>
              <div className="text-muted text-xs">{t("protection.escalation.status.currentStep")}</div>
              <div className="tabular">{status.current_step}</div>
            </div>
            <div>
              <div className="text-muted text-xs">{t("protection.escalation.status.currentAction")}</div>
              <div>{status.action || t("protection.escalation.status.none")}</div>
            </div>
            {status.message && <div className="text-muted col-span-2 text-xs md:col-span-4">{status.message}</div>}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
