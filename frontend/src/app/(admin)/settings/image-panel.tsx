"use client";

/**
 * 图片处理面板：GET/POST /image-transform（imagery.Config，字段与数据面同源）。
 */

import { Button, TextField, Input } from "@heroui/react";
import { useI18n, type MessageKey } from "@/i18n";
import {
  useConfigForm,
  PanelCard,
  PanelError,
  PanelSkeleton,
  Field,
  ToggleRow,
} from "./form-kit";
import type { ImageTransformConfig } from "@/lib/types/settings";

const NUMBER_FIELDS: { key: keyof ImageTransformConfig; label: MessageKey; hint?: MessageKey }[] = [
  { key: "max_pixels", label: "settings.image.maxPixels", hint: "settings.image.maxPixelsHint" },
  { key: "max_side", label: "settings.image.maxSide" },
  { key: "max_bytes", label: "settings.image.maxBytes" },
  { key: "timeout_ms", label: "settings.image.timeoutMs", hint: "settings.image.timeoutMsHint" },
  { key: "concurrency", label: "settings.image.concurrency", hint: "settings.image.concurrencyHint" },
  { key: "default_quality", label: "settings.image.defaultQuality", hint: "settings.image.defaultQualityHint" },
];

export function ImagePanel() {
  const { t } = useI18n();
  const { form, setForm, loading, error, reload, saving, save } =
    useConfigForm<ImageTransformConfig>("/image-transform");

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading || !form) return <PanelSkeleton />;

  return (
    <PanelCard
      title={t("settings.image.title")}
      description={t("settings.image.description")}
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <ToggleRow
          label={t("settings.image.enabled")}
          checked={form.enabled}
          onChange={(v) => setForm({ ...form, enabled: v })}
        />
        <ToggleRow
          label={t("settings.image.adaptiveWebp")}
          description={t("settings.image.adaptiveWebpDesc")}
          checked={form.adaptive_webp}
          onChange={(v) => setForm({ ...form, adaptive_webp: v })}
        />
        {NUMBER_FIELDS.map((f) => (
          <Field key={f.key} label={t(f.label)} hint={f.hint ? t(f.hint) : undefined}>
            <TextField aria-label={t(f.label)}>
              <Input
                type="number"
                className="tabular"
                value={String(form[f.key] ?? 0)}
                onChange={(e) =>
                  setForm({ ...form, [f.key]: Number(e.target.value) } as ImageTransformConfig)
                }
              />
            </TextField>
          </Field>
        ))}
      </div>
      <div className="flex justify-end">
        <Button variant="primary" isPending={saving} onPress={() => void save()}>
          {t("common.save")}
        </Button>
      </div>
    </PanelCard>
  );
}
