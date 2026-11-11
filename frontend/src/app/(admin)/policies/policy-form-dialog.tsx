"use client";

/**
 * 策略新建 / 编辑弹窗。
 *
 * 表单状态由组件自持，父级通过 `key` 控制重挂载（新建与编辑互不串值）；
 * 保存成功后关闭弹窗并回调 `onSaved`，由父级统一刷新列表。
 */

import { useState } from "react";
import { Button, TextField, Input, TextArea } from "@heroui/react";
import { apiPost, ApiError } from "@/lib/api/client";
import { FormDialog } from "@/components/ui/dialogs";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";
import type { Policy } from "@/lib/types/rule";
import { EMPTY_FORM, policyToForm, type PolicyFormState } from "./policies-model";

export function PolicyFormDialog({
  state,
  editing,
  onSaved,
}: {
  state: ReturnType<typeof import("@heroui/react").useOverlayState>;
  /** null 表示新建 */
  editing: Policy | null;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [form, setForm] = useState<PolicyFormState>(editing ? policyToForm(editing) : EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!form.name.trim()) {
      showError(t("policies.saveFailed"), t("policies.error.name"));
      return;
    }
    setSaving(true);
    try {
      const payload = { name: form.name.trim(), description: form.description.trim() };
      if (editing) {
        await apiPost(`/policies/${editing.id}/update`, payload);
      } else {
        await apiPost("/policies", payload);
      }
      showSuccess(t("policies.saved"));
      state.close();
      onSaved();
    } catch (err) {
      showError(t("policies.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <FormDialog
      state={state}
      title={
        editing ? t("policies.form.editTitle", { id: editing.id }) : t("policies.form.createTitle")
      }
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" isPending={saving} onPress={() => void handleSave()}>
            {t("common.save")}
          </Button>
        </>
      }
    >
      <TextField aria-label={t("policies.form.name")} isRequired>
        <Input
          placeholder={t("policies.form.namePlaceholder")}
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
        />
      </TextField>
      <TextArea
        aria-label={t("policies.form.description")}
        placeholder={t("policies.form.descriptionPlaceholder")}
        value={form.description}
        onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
        className="min-h-[80px]"
      />
    </FormDialog>
  );
}
