"use client";

/**
 * OWASP 批量覆盖。
 *
 * POST /api/v1/owasp-rules/batch（router.go:328，admin/operator）
 * 请求体 {policy_id, ids[], patch{}}；ids 为目录数字主键（后端 findOWASPCatalog 接受数字或 rule_id）。
 */

import { useEffect, useState } from "react";
import { Button } from "@heroui/react";
import { apiPost, ApiError } from "@/lib/api/client";
import type { OWASPRuleBatchPayload } from "@/lib/types/owasp";
import { useI18n } from "@/i18n";
import { FormDialog } from "@/components/ui/dialogs";
import { SimpleSelect } from "@/components/ui/primitives";
import { showSuccess, showError } from "@/components/ui/toast-host";
import {
  ACTION_OPTIONS,
  localizeOptions,
  SENSITIVITY_OPTIONS,
} from "@/lib/utils/rule-constants";

export function OWASPBatchDialog({
  state,
  policyId,
  ids,
  onDone,
}: {
  state: ReturnType<typeof import("@heroui/react").useOverlayState>;
  policyId: number;
  ids: number[];
  onDone: () => void;
}) {
  const { t } = useI18n();
  const [enabledChoice, setEnabledChoice] = useState("");
  const [action, setAction] = useState("");
  const [sensitivity, setSensitivity] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (state.isOpen) {
      setEnabledChoice("");
      setAction("");
      setSensitivity("");
    }
  }, [state.isOpen]);

  async function handleSubmit() {
    if (!enabledChoice && !action && !sensitivity) {
      showError(t("owaspRules.batch.failed"), t("owaspRules.batch.error.pickOne"));
      return;
    }
    if (action === "redirect") {
      showError(t("owaspRules.batch.failed"), t("owaspRules.batch.error.redirectManual"));
      return;
    }
    const payload: OWASPRuleBatchPayload = {
      policy_id: policyId,
      ids,
      patch: {
        ...(enabledChoice ? { enabled: enabledChoice === "on" } : {}),
        ...(action ? { action } : {}),
        ...(sensitivity ? { sensitivity } : {}),
      },
    };
    setSaving(true);
    try {
      const res = await apiPost<{ updated: number }>("/owasp-rules/batch", payload);
      showSuccess(t("owaspRules.batch.updated", { count: res.updated ?? ids.length }));
      state.close();
      onDone();
    } catch (err) {
      showError(t("owaspRules.batch.failed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <FormDialog
      state={state}
      title={t("owaspRules.batch.title", { id: policyId })}
      description={t("owaspRules.batch.description", { count: ids.length })}
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" isPending={saving} onPress={handleSubmit}>
            {t("owaspRules.batch.apply")}
          </Button>
        </>
      }
    >
      <SimpleSelect<string>
        value={enabledChoice}
        onChange={setEnabledChoice}
        label={t("owaspRules.batch.enabledLabel")}
        className="w-full"
        options={[
          { key: "", label: t("owaspRules.batch.keep") },
          { key: "on", label: t("common.enabled") },
          { key: "off", label: t("common.disabled") },
        ]}
      />
      <SimpleSelect<string>
        value={action}
        onChange={setAction}
        label={t("owaspRules.drawer.actionLabel")}
        className="w-full"
        options={[{ key: "", label: t("owaspRules.batch.keep") }, ...localizeOptions(ACTION_OPTIONS, t)]}
      />
      <SimpleSelect<string>
        value={sensitivity}
        onChange={setSensitivity}
        label={t("owaspRules.drawer.sensitivityLabel")}
        className="w-full"
        options={[{ key: "", label: t("owaspRules.batch.keep") }, ...localizeOptions(SENSITIVITY_OPTIONS, t)]}
      />
    </FormDialog>
  );
}
