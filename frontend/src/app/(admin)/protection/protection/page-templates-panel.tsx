"use client";

/**
 * 页面模板 Tab：GET /page-templates 列出 captcha / challenge / block 三类模板；
 * 编辑保存 POST /page-templates/:type；预览 GET/POST /page-templates/:type/preview
 * （返回 text/html）；重置 POST /page-templates/:type/reset。
 * 字段取自 internal/waf/pageconfig/config.go PageConfig（L23-31）及三类扩展（L36-63）。
 */

import { useCallback, useEffect, useState } from "react";
import { Button, Modal, useOverlayState } from "@heroui/react";
import { Pencil, Eye, RotateCcw } from "lucide-react";
import { apiGet, apiPost, getToken, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import type { TranslateFn } from "@/i18n";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ErrorState, CardSkeleton } from "@/components/ui/primitives";
import { ConfirmButton } from "@/components/ui/confirm-button";
import type {
  PageTemplateConfig,
  PageTemplatesResponse,
  PageTemplateType,
} from "@/lib/types/protection";
import { SectionCard, TextFieldRow, JsonTextArea } from "./field-controls";
import {
  PAGE_TEMPLATE_META,
  PAGE_TEMPLATE_COMMON_FIELDS,
  PAGE_TEMPLATE_TYPE_FIELDS,
} from "./protection-model";

/**
 * 原生 fetch 读取 text/html 预览。
 * apiGet 会走 JSON.parse，无法处理 HTML 响应，因此此处直接复用 token。
 */
async function fetchPreviewHtml(
  path: string,
  body: unknown,
  t: TranslateFn,
): Promise<string> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api/v1${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers,
    credentials: "include",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let message = t("protection.pages.previewFailedStatus", { status: res.status });
    try {
      const payload = (await res.json()) as { error?: unknown };
      if (payload?.error) message = String(payload.error);
    } catch {
      /* 非 JSON 错误响应 */
    }
    throw new ApiError(res.status, message);
  }
  return res.text();
}

export function PageTemplatesPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<PageTemplatesResponse>(
    useCallback(() => apiGet<PageTemplatesResponse>("/page-templates"), []),
  );
  const [editing, setEditing] = useState<PageTemplateType | null>(null);
  const [draft, setDraft] = useState<PageTemplateConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const editState = useOverlayState();
  const previewState = useOverlayState();

  /** 当前编辑类型对应的完整草稿（编辑时从服务端数据克隆） */
  const openEditor = useCallback(
    (type: PageTemplateType, current: PageTemplateConfig) => {
      setEditing(type);
      setDraft({ ...current });
      editState.open();
    },
    [editState],
  );

  const patch = useCallback(<K extends keyof PageTemplateConfig>(key: K, value: PageTemplateConfig[K]) => {
    setDraft((d) => (d ? { ...d, [key]: value } : d));
  }, []);

  async function saveDraft() {
    if (!editing || !draft) return;
    setSaving(true);
    try {
      await apiPost(`/page-templates/${editing}`, draft);
      showSuccess(t("protection.pages.saved"));
      editState.close();
      await reload();
    } catch (err) {
      showError(t("protection.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  /** 草稿预览：POST /page-templates/:type/preview，不持久化 */
  async function previewDraft() {
    if (!editing || !draft) return;
    setPreviewing(true);
    try {
      const html = await fetchPreviewHtml(`/page-templates/${editing}/preview`, draft, t);
      setPreviewHtml(html);
      previewState.open();
    } catch (err) {
      showError(t("protection.pages.previewFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setPreviewing(false);
    }
  }

  /** 当前版本预览：GET /page-templates/:type/preview */
  async function previewCurrent(type: PageTemplateType) {
    setPreviewing(true);
    try {
      const html = await fetchPreviewHtml(`/page-templates/${type}/preview`, undefined, t);
      setPreviewHtml(html);
      previewState.open();
    } catch (err) {
      showError(t("protection.pages.previewFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setPreviewing(false);
    }
  }

  async function resetTemplate(type: PageTemplateType) {
    return apiPost(`/page-templates/${type}/reset`);
  }

  const types: PageTemplateType[] = ["captcha", "challenge", "block"];

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && !data ? (
        <CardSkeleton height="h-64" />
      ) : data ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          {types.map((type) => {
            const cfg = data[type];
            const meta = PAGE_TEMPLATE_META[type];
            return (
              <SectionCard key={type} title={t(meta.labelKey)} description={t(meta.descriptionKey)}>
                <div className="flex flex-col gap-1.5 text-sm">
                  <div className="flex justify-between gap-2">
                    <span className="text-muted text-xs">{t("protection.pages.summary.title")}</span>
                    <span className="truncate">{cfg.title || "—"}</span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-muted text-xs">{t("protection.pages.summary.brand")}</span>
                    <span className="truncate">{cfg.brand_name || "—"}</span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted text-xs">{t("protection.pages.summary.primaryColor")}</span>
                    <span className="flex items-center gap-1.5">
                      <span className="inline-block size-3 rounded-full border border-separator" style={{ backgroundColor: cfg.primary_color || "transparent" }} />
                      <span className="font-mono text-xs">{cfg.primary_color || "—"}</span>
                    </span>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button variant="outline" size="sm" onPress={() => openEditor(type, cfg)}>
                    <Pencil className="size-3.5" /> {t("protection.pages.edit")}
                  </Button>
                  <Button variant="ghost" size="sm" isPending={previewing} onPress={() => previewCurrent(type)}>
                    <Eye className="size-3.5" /> {t("protection.pages.preview")}
                  </Button>
                  <ConfirmButton
                    onConfirm={async () => {
                      await resetTemplate(type);
                      await reload();
                    }}
                    confirmText={t("protection.pages.resetConfirm", { type: t(meta.labelKey) })}
                    successText={t("protection.pages.resetDone")}
                  >
                    <RotateCcw className="size-3.5" /> {t("protection.pages.resetDefault")}
                  </ConfirmButton>
                </div>
              </SectionCard>
            );
          })}
        </div>
      ) : null}

      {/* 编辑弹窗 */}
      <Modal state={editState}>
        <Modal.Backdrop>
          <Modal.Container size="lg">
            <Modal.Dialog>
              <Modal.Header>
                <Modal.Heading>
                  {editing
                    ? t("protection.pages.editTitle", {
                        type: t(PAGE_TEMPLATE_META[editing].labelKey),
                      })
                    : t("protection.pages.editFallback")}
                </Modal.Heading>
                <Modal.CloseTrigger />
              </Modal.Header>
              <Modal.Body>
                {draft && editing ? (
                  <div className="flex flex-col gap-3">
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      {PAGE_TEMPLATE_COMMON_FIELDS.map((f) => (
                        <TextFieldRow
                          key={String(f.key)}
                          label={t(f.labelKey)}
                          value={String(draft[f.key] ?? "")}
                          onChange={(v) => patch(f.key, v)}
                        />
                      ))}
                      {PAGE_TEMPLATE_TYPE_FIELDS[editing].map((f) => (
                        <TextFieldRow
                          key={String(f.key)}
                          label={t(f.labelKey)}
                          value={String(draft[f.key] ?? "")}
                          onChange={(v) => patch(f.key, v)}
                        />
                      ))}
                    </div>
                    <JsonTextArea
                      label={t("protection.pages.customCss")}
                      value={draft.custom_css ?? ""}
                      onChange={(v) => patch("custom_css", v)}
                      hint={t("protection.pages.customCssHint")}
                    />
                  </div>
                ) : null}
              </Modal.Body>
              <Modal.Footer>
                <Button variant="ghost" onPress={editState.close}>
                  {t("common.cancel")}
                </Button>
                <Button variant="outline" isPending={previewing} onPress={previewDraft}>
                  {t("protection.pages.draftPreview")}
                </Button>
                <Button variant="primary" isPending={saving} onPress={saveDraft}>
                  {t("common.save")}
                </Button>
              </Modal.Footer>
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>

      {/* 预览弹窗（iframe srcDoc） */}
      <Modal state={previewState}>
        <Modal.Backdrop>
          <Modal.Container size="full">
            <Modal.Dialog>
              <Modal.Header>
                <Modal.Heading>{t("protection.pages.previewTitle")}</Modal.Heading>
                <Modal.CloseTrigger />
              </Modal.Header>
              <Modal.Body>
                {previewHtml ? (
                  <iframe
                    title={t("protection.pages.previewFrameTitle")}
                    srcDoc={previewHtml}
                    sandbox="allow-scripts"
                    className="h-[70vh] w-full rounded-lg border border-separator bg-white"
                  />
                ) : (
                  <div className="text-muted text-sm">{t("common.loading")}</div>
                )}
              </Modal.Body>
              <Modal.Footer>
                <Button variant="ghost" onPress={previewState.close}>
                  {t("common.close")}
                </Button>
              </Modal.Footer>
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>
    </div>
  );
}
