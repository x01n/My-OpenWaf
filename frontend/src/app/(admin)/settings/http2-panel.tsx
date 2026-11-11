"use client";

/**
 * HTTP/2 运行参数面板：GET/POST /http2-config（network.go，12 个字段）。
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
import type { HTTP2Config } from "@/lib/types/settings";

/** 数值字段清单：label 语言键 + 表单键（键名与后端 json tag 一致） */
const NUMBER_FIELDS: { key: keyof HTTP2Config; label: MessageKey; hint?: MessageKey }[] = [
  { key: "read_timeout_seconds", label: "settings.http2.readTimeout" },
  { key: "idle_timeout_seconds", label: "settings.http2.idleTimeout" },
  { key: "max_concurrent_streams", label: "settings.http2.maxConcurrentStreams" },
  { key: "max_read_frame_size", label: "settings.http2.maxReadFrameSize" },
  { key: "max_upload_buffer_per_connection", label: "settings.http2.maxUploadBufferConn" },
  { key: "max_upload_buffer_per_stream", label: "settings.http2.maxUploadBufferStream" },
  { key: "max_header_bytes", label: "settings.http2.maxHeaderBytes" },
  { key: "max_header_fields", label: "settings.http2.maxHeaderFields" },
  { key: "max_handlers", label: "settings.http2.maxHandlers" },
  { key: "max_queued_control_frames", label: "settings.http2.maxQueuedControlFrames" },
];

export function HTTP2Panel() {
  const { t } = useI18n();
  const { form, setForm, loading, error, reload, saving, save } =
    useConfigForm<HTTP2Config>("/http2-config");

  if (error) return <PanelError message={error} onRetry={reload} />;
  if (loading || !form) return <PanelSkeleton />;

  return (
    <PanelCard
      title={t("settings.http2.title")}
      description={t("settings.http2.description")}
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <ToggleRow
          label={t("settings.http2.disableKeepalive")}
          checked={form.disable_keepalive}
          onChange={(v) => setForm({ ...form, disable_keepalive: v })}
        />
        <ToggleRow
          label={t("settings.http2.permitProhibited")}
          description="permit_prohibited_cipher_suites"
          checked={form.permit_prohibited_cipher_suites}
          onChange={(v) => setForm({ ...form, permit_prohibited_cipher_suites: v })}
        />
        {NUMBER_FIELDS.map((f) => (
          <Field key={f.key} label={t(f.label)} hint={f.hint ? t(f.hint) : undefined}>
            <TextField aria-label={t(f.label)}>
              <Input
                type="number"
                className="tabular"
                value={String(form[f.key] ?? "")}
                onChange={(e) =>
                  setForm({ ...form, [f.key]: Number(e.target.value) } as HTTP2Config)
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
