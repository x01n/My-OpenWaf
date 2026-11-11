"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Input, Label, TextField } from "@heroui/react";
import { login, ApiError } from "@/lib/api/client";
import { ToastHost, showError } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";

/**
 * 登录表单卡片：唯一持有凭据与提交状态的组件。
 *
 * 字段使用可见 Label（而非 placeholder 冒充标签），空值时提交按钮禁用；
 * 失败提示走全局 Toast，保持错误信息与语言切换一致。
 */
export function LoginForm() {
  const router = useRouter();
  const { t } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);

  const canSubmit = username.length > 0 && password.length > 0;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit || pending) return;
    setPending(true);
    try {
      await login(username, password);
      router.replace("/dashboard");
    } catch (err) {
      /** 401 统一用本地化提示，避免中文界面里出现后端英文原文 */
      const description =
        err instanceof ApiError && err.status !== 401 ? err.message : t("login.failedHint");
      showError(t("login.failed"), description);
      setPending(false);
    }
  }

  return (
    <div className="login-card enter">
      <div className="login-card-head">
        <h1 className="login-card-title">{t("login.title")}</h1>
        <p className="login-card-desc">{t("login.subtitle")}</p>
      </div>

      <form onSubmit={handleSubmit} className="login-form" noValidate>
        <TextField isRequired className="login-field">
          <Label className="login-label">{t("login.username")}</Label>
          <Input
            value={username}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
          />
        </TextField>

        <TextField isRequired className="login-field">
          <Label className="login-label">{t("login.password")}</Label>
          <Input
            type="password"
            value={password}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </TextField>

        <Button
          type="submit"
          variant="primary"
          isPending={pending}
          isDisabled={!canSubmit}
          className="login-submit"
        >
          {t("login.submit")}
        </Button>
      </form>

      <p className="login-form-note">{t("login.form.note")}</p>
      <ToastHost />
    </div>
  );
}
