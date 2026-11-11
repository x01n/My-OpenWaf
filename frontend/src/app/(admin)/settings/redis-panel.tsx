"use client";

/**
 * Redis 连接面板：GET /redis-config（响应不回显密码）+ POST /redis-config。
 * 密码留空表示不变更；后端保存前会做连通性探测。
 */

import { useState } from "react";
import { Button, TextField, Input, Chip } from "@heroui/react";
import { useI18n } from "@/i18n";
import {
  useConfigForm,
  PanelCard,
  PanelError,
  PanelSkeleton,
  Field,
  ToggleRow,
  WarningBanner,
} from "./form-kit";
import type { RedisConfigResponse } from "@/lib/types/settings";

/** 表单模型：password 只在用户输入时参与提交 */
type RedisForm = {
  enabled: boolean;
  addr: string;
  db: number;
  password: string;
};

export function RedisPanel() {
  const { t } = useI18n();
  const { form, setForm, loading, error, reload, saving, save } =
    useConfigForm<RedisConfigResponse>("/redis-config");
  const [password, setPassword] = useState("");

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading || !form) return <PanelSkeleton />;

  const submit = async () => {
    const payload: Record<string, unknown> = {
      enabled: form.enabled,
      addr: form.addr,
      db: form.db,
    };
    if (password.trim() !== "") payload.password = password;
    await save(payload);
    setPassword("");
  };

  return (
    <PanelCard
      title={t("settings.redis.title")}
      description={t("settings.redis.description")}
    >
      {form.restart_required && (
        <WarningBanner>{t("settings.redis.restartRequired")}</WarningBanner>
      )}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <ToggleRow
          label={t("settings.redis.enabled")}
          checked={form.enabled}
          onChange={(v) => setForm({ ...form, enabled: v })}
        />
        <Field label={t("settings.redis.source")} hint={t("settings.redis.sourceHint")}>
          <Chip size="sm" variant="soft" color="accent">
            {form.source}
          </Chip>
        </Field>
        <Field label={t("settings.redis.addr")} hint={t("settings.redis.addrHint")}>
          <TextField aria-label={t("settings.redis.addrAria")}>
            <Input
              placeholder="127.0.0.1:6379"
              value={form.addr}
              onChange={(e) => setForm({ ...form, addr: e.target.value })}
            />
          </TextField>
        </Field>
        <Field label={t("settings.redis.db")}>
          <TextField aria-label="Redis DB">
            <Input
              type="number"
              className="tabular"
              value={String(form.db)}
              onChange={(e) => setForm({ ...form, db: Number(e.target.value) })}
            />
          </TextField>
        </Field>
        <Field
          label={t("settings.redis.password")}
          hint={t("settings.redis.passwordHint")}
        >
          <TextField aria-label={t("settings.redis.passwordAria")}>
            <Input
              type="password"
              placeholder={
                form.password_set
                  ? t("settings.redis.passwordSetPlaceholder")
                  : t("settings.redis.passwordUnsetPlaceholder")
              }
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </TextField>
        </Field>
        <Field label={t("settings.redis.passwordStatus")}>
          {form.password_set ? (
            <Chip size="sm" variant="soft" color="success">
              {t("settings.panel.set")}
            </Chip>
          ) : (
            <Chip size="sm" variant="soft" color="default">
              {t("settings.panel.unset")}
            </Chip>
          )}
        </Field>
      </div>
      <div className="flex justify-end">
        <Button variant="primary" isPending={saving} onPress={() => void submit()}>
          {t("common.save")}
        </Button>
      </div>
    </PanelCard>
  );
}
