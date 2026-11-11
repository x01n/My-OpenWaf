"use client";

/**
 * 日志面板：GET/POST /log-config（network.go LogConfig；保存立即生效，无需重启）。
 */

import { Button, TextField, Input } from "@heroui/react";
import { useI18n } from "@/i18n";
import { SimpleSelect } from "@/components/ui/primitives";
import {
  useConfigForm,
  PanelCard,
  PanelError,
  PanelSkeleton,
  Field,
  ToggleRow,
} from "./form-kit";
import type { LogConfig } from "@/lib/types/settings";

const LEVELS = ["DEBUG", "INFO", "WARN", "ERROR"];

export function LogPanel() {
  const { t } = useI18n();
  const { form, setForm, loading, error, reload, saving, save } =
    useConfigForm<LogConfig>("/log-config");

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading || !form) return <PanelSkeleton />;

  return (
    <PanelCard title={t("settings.log.title")} description={t("settings.log.description")}>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Field label={t("settings.log.level")}>
          <SimpleSelect
            className="w-full"
            value={form.level}
            onChange={(v) => setForm({ ...form, level: v })}
            options={LEVELS.map((l) => ({ key: l, label: l }))}
          />
        </Field>
        <Field label={t("settings.log.filePath")} hint={t("settings.log.filePathHint")}>
          <TextField aria-label={t("settings.log.filePath")}>
            <Input
              placeholder="/var/log/my-openwaf.log"
              value={form.file_path}
              onChange={(e) => setForm({ ...form, file_path: e.target.value })}
            />
          </TextField>
        </Field>
      </div>
      <ToggleRow
        label={t("settings.log.alsoStdout")}
        checked={form.also_stdout}
        onChange={(v) => setForm({ ...form, also_stdout: v })}
      />
      <div className="flex justify-end">
        <Button variant="primary" isPending={saving} onPress={() => void save()}>
          {t("common.save")}
        </Button>
      </div>
    </PanelCard>
  );
}
