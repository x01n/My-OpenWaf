"use client";

/**
 * 威胁情报订阅源新建 / 编辑弹窗。
 *
 * 表单字段与 internal/admin/system/threatintel 的绑定结构一致；
 * 保存成功后关闭弹窗并调用 `onSaved`，由调用方统一刷新列表。
 */

import { useState } from "react";
import { useOverlayState, Button, TextField, Input } from "@heroui/react";
import { apiPost, ApiError } from "@/lib/api/client";
import { SimpleSelect, ToggleSwitch } from "@/components/ui/primitives";
import { FormDialog } from "@/components/ui/dialogs";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import type { Site } from "@/lib/types/site";
import type { ThreatIntelFeed } from "@/lib/types/ip";
import {
  ACTION_FORM_OPTIONS,
  EMPTY_FORM,
  KIND_FORM_OPTIONS,
  SYNC_INTERVAL_FORM_OPTIONS,
  feedToForm,
  type FeedAction,
  type FeedFormState,
  type FeedKind,
} from "./threat-intel-model";

export function FeedFormDialog({
  state,
  feed,
  sites,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  /** null 表示新建 */
  feed: ThreatIntelFeed | null;
  sites: Site[];
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [form, setForm] = useState<FeedFormState>(feed ? feedToForm(feed) : EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!form.name.trim() || !form.url.trim()) {
      showError(t("threatIntel.saveFailed"), t("threatIntel.form.required"));
      return;
    }
    setSaving(true);
    try {
      const base = {
        name: form.name.trim(),
        url: form.url.trim(),
        kind: form.kind,
        // 白名单仅做放行，命中动作固定为 intercept（与源文件行为一致）
        action: form.kind === "whitelist" ? ("intercept" as const) : form.action,
        auth_header_name: form.auth_header_name,
        sync_interval: form.sync_interval,
        enabled: form.enabled,
        site_id: form.site_id,
      };
      // 编辑时未改动认证头值则不提交，避免低权限回显的掩码值覆盖真实密钥
      const payload =
        feed && form.auth_header_value === feed.auth_header_value
          ? { ...base, auth_header_value: undefined }
          : { ...base, auth_header_value: form.auth_header_value };
      if (feed) {
        await apiPost(`/threat-intel-feeds/${feed.id}/update`, payload);
      } else {
        await apiPost("/threat-intel-feeds", payload);
      }
      showSuccess(t("threatIntel.saved"));
      state.close();
      onSaved();
    } catch (err) {
      showError(t("threatIntel.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  /** 站点选项：首项为全局，其余按「名称（主机）」插值 */
  const siteOptions: { key: string; label: string }[] = [
    { key: "none", label: t("threatIntel.form.siteGlobal") },
    ...sites.map((s) => ({
      key: String(s.id),
      label: s.host,
    })),
  ];

  return (
    <FormDialog
      state={state}
      title={feed ? t("threatIntel.form.editTitle") : t("threatIntel.form.createTitle")}
      size="lg"
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
      <TextField aria-label={t("threatIntel.form.name")} isRequired>
        <Input
          placeholder={t("threatIntel.form.namePlaceholder")}
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
        />
      </TextField>
      <TextField aria-label={t("threatIntel.form.url")} isRequired>
        <Input
          placeholder="https://example.com/feeds/ip.txt"
          value={form.url}
          onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
        />
      </TextField>
      <div className="flex gap-3">
        <SimpleSelect<FeedKind>
          value={form.kind}
          onChange={(kind) => setForm((f) => ({ ...f, kind }))}
          label={t("threatIntel.form.kind")}
          className="w-1/2"
          options={localizeOptions(KIND_FORM_OPTIONS, t)}
        />
        <SimpleSelect<FeedAction>
          value={form.kind === "whitelist" ? "intercept" : form.action}
          onChange={(action) => setForm((f) => ({ ...f, action }))}
          label={t("threatIntel.form.action")}
          className="w-1/2"
          options={localizeOptions(ACTION_FORM_OPTIONS, t)}
        />
      </div>
      <div className="flex gap-3">
        <TextField aria-label={t("threatIntel.form.authName")} className="flex-1">
          <Input
            placeholder={t("threatIntel.form.authNamePlaceholder")}
            value={form.auth_header_name}
            onChange={(e) => setForm((f) => ({ ...f, auth_header_name: e.target.value }))}
          />
        </TextField>
        <TextField aria-label={t("threatIntel.form.authValue")} className="flex-1">
          <Input
            placeholder={t("threatIntel.form.authValuePlaceholder")}
            value={form.auth_header_value}
            onChange={(e) => setForm((f) => ({ ...f, auth_header_value: e.target.value }))}
          />
        </TextField>
      </div>
      <div className="flex gap-3">
        <div className="w-1/2">
          <SimpleSelect
            value={String(form.sync_interval)}
            onChange={(v) => setForm((f) => ({ ...f, sync_interval: Number(v) || 0 }))}
            label={t("threatIntel.form.syncInterval")}
            className="w-full"
            options={localizeOptions(SYNC_INTERVAL_FORM_OPTIONS, t)}
          />
        </div>
        <div className="w-1/2">
          <SimpleSelect<string>
            value={form.site_id === null ? "none" : String(form.site_id)}
            onChange={(v) =>
              setForm((f) => ({ ...f, site_id: v === "none" ? null : Number(v) }))
            }
            label={t("threatIntel.form.site")}
            className="w-full"
            options={siteOptions}
          />
        </div>
      </div>
      <ToggleSwitch
        isSelected={form.enabled}
        onChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
      >
        {t("threatIntel.form.enabled")}
      </ToggleSwitch>
    </FormDialog>
  );
}
