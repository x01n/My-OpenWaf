"use client";

/**
 * IP 名单新建 / 编辑弹窗。
 *
 * 表单字段与 internal/admin/ip_lists 的绑定结构一致；保存成功后由调用方刷新列表。
 */

import { useState } from "react";
import { useOverlayState, Button, TextField, Input } from "@heroui/react";
import { apiPost, ApiError } from "@/lib/api/client";
import { SimpleSelect, ToggleSwitch } from "@/components/ui/primitives";
import { FormDialog } from "@/components/ui/dialogs";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import {
  ACTION_FORM_OPTIONS,
  EMPTY_FORM,
  KIND_FORM_OPTIONS,
  type Action,
  type IPFormState,
  type Kind,
} from "./ip-lists-model";

export function IPListFormDialog({
  state,
  entryId,
  initial,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  /** null 表示新建 */
  entryId: number | null;
  initial: IPFormState;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [form, setForm] = useState<IPFormState>(initial);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!form.value.trim()) {
      showError(t("ipLists.saveFailed"), t("ipLists.error.value"));
      return;
    }
    setSaving(true);
    try {
      const payload = {
        kind: form.kind,
        value: form.value.trim(),
        action: form.action,
        note: form.note,
        enabled: form.enabled,
      };
      if (entryId != null) {
        await apiPost(`/ip-lists/${entryId}/update`, payload);
      } else {
        await apiPost("/ip-lists", payload);
      }
      showSuccess(t("ipLists.saved"));
      state.close();
      onSaved();
    } catch (err) {
      showError(t("ipLists.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <FormDialog
      state={state}
      title={entryId != null ? t("ipLists.form.editTitle") : t("ipLists.form.createTitle")}
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
      <SimpleSelect<Kind>
        value={form.kind}
        onChange={(kind) => setForm((f) => ({ ...f, kind }))}
        label={t("ipLists.kind")}
        className="w-full"
        options={localizeOptions(KIND_FORM_OPTIONS, t)}
      />
      <TextField aria-label={t("ipLists.form.value")} isRequired>
        <Input
          placeholder={t("ipLists.form.valuePlaceholder")}
          value={form.value}
          onChange={(e) => setForm((f) => ({ ...f, value: e.target.value }))}
        />
      </TextField>
      <SimpleSelect<Action>
        value={form.action}
        onChange={(action) => setForm((f) => ({ ...f, action }))}
        label={t("ipLists.form.action")}
        className="w-full"
        options={localizeOptions(ACTION_FORM_OPTIONS, t)}
      />
      <TextField aria-label={t("ipLists.col.note")}>
        <Input
          placeholder={t("ipLists.form.notePlaceholder")}
          value={form.note}
          onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))}
        />
      </TextField>
      <ToggleSwitch
        isSelected={form.enabled}
        onChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
      >
        {t("ipLists.form.enabled")}
      </ToggleSwitch>
    </FormDialog>
  );
}
