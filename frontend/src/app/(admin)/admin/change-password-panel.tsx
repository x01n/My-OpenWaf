"use client";

/**
 * 修改自己的密码：POST /auth/change-password {old_password,new_password}。
 * 成功后清空本地会话并跳转登录页（后端同时吊销该账号凭据）。
 */

import { useState } from "react";
import { Button, TextField, Input } from "@heroui/react";
import { apiPost, ApiError, clearSession } from "@/lib/api/client";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { PanelCard, Field, WarningBanner } from "@/app/(admin)/settings/form-kit";
import { useI18n } from "@/i18n";

export function ChangePasswordPanel() {
  const { t } = useI18n();
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [saving, setSaving] = useState(false);

  const mismatch = confirmPassword !== "" && confirmPassword !== newPassword;
  const canSubmit =
    oldPassword !== "" && newPassword.length >= 8 && newPassword === confirmPassword;

  async function submit() {
    setSaving(true);
    try {
      await apiPost("/auth/change-password", {
        old_password: oldPassword,
        new_password: newPassword,
      });
      showSuccess(t("admin.account.changedRelogin"));
      clearSession();
      window.location.href = "/login";
    } catch (err) {
      showError(t("admin.account.changeFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="max-w-xl">
      <PanelCard title={t("admin.account.title")} description={t("admin.account.desc")}>
        <WarningBanner>{t("admin.account.warning")}</WarningBanner>
        <Field label={t("admin.account.currentPassword")}>
          <TextField aria-label={t("admin.account.currentPassword")}>
            <Input
              type="password"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
            />
          </TextField>
        </Field>
        <Field label={t("admin.account.newPassword")} hint={t("admin.account.minChars")}>
          <TextField aria-label={t("admin.account.newPassword")}>
            <Input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </TextField>
        </Field>
        <Field label={t("admin.account.confirmPassword")}>
          <TextField aria-label={t("admin.account.confirmPassword")}>
            <Input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </TextField>
        </Field>
        {mismatch && <span className="text-danger text-xs">{t("admin.account.mismatch")}</span>}
        <div className="flex justify-end">
          <Button
            variant="primary"
            isPending={saving}
            isDisabled={!canSubmit}
            onPress={() => void submit()}
          >
            {t("admin.account.changePassword")}
          </Button>
        </div>
      </PanelCard>
    </div>
  );
}
