"use client";

/**
 * 站点详情「错误页」面板：按状态码配置自定义标题与 HTML。
 *
 * 后端契约：
 * - GET  /sites/:id/error-pages
 * - GET  /error-pages/defaults
 * - POST /error-pages/preview（仅渲染，不持久化）
 * - POST /sites/:id/error-pages
 */

import { useCallback, useEffect, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input, TextArea } from "@heroui/react";
import { Wand2 } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type {
  DefaultErrorPagesResponse,
  ErrorPageConfig,
  SiteErrorPagesResponse,
} from "@/lib/types/site-admin";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";

/** 后端允许的错误页状态码（internal/admin/site/errorpage defaults）。 */
const ERROR_PAGE_CODES = ["403", "404", "429", "431", "500", "502", "503", "504"] as const;

type ErrorPageDraft = { title: string; html: string };

export function ErrorPagesPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const pages = useApi(
    useCallback(() => apiGet<SiteErrorPagesResponse>(`/sites/${siteId}/error-pages`), [siteId]),
  );
  const defaults = useApi(
    useCallback(() => apiGet<DefaultErrorPagesResponse>("/error-pages/defaults"), []),
  );

  const [code, setCode] = useState<string>("403");
  const [drafts, setDrafts] = useState<Record<string, ErrorPageDraft>>({});
  const [saving, setSaving] = useState(false);

  /* 预览：POST /error-pages/preview 渲染草稿，不持久化。 */
  const [previewHtml, setPreviewHtml] = useState("");
  const [previewing, setPreviewing] = useState(false);
  const previewState = useOverlayState();

  async function handlePreview() {
    if (!current.html.trim()) {
      showError(t("siteDetail.errorPages.previewFailed"), t("siteDetail.errorPages.previewEmpty"));
      return;
    }
    setPreviewing(true);
    try {
      const res = await apiPost<{ rendered: string; status_code: number }>("/error-pages/preview", {
        html: current.html,
        status_code: Number(code),
      });
      setPreviewHtml(res.rendered ?? current.html);
      previewState.open();
    } catch (err) {
      showError(
        t("siteDetail.errorPages.previewFailed"),
        err instanceof ApiError ? err.message : undefined,
      );
    } finally {
      setPreviewing(false);
    }
  }

  useEffect(() => {
    const remote = pages.data?.error_pages;
    if (!remote) return;
    setDrafts(() => {
      const next: Record<string, ErrorPageDraft> = {};
      for (const c of ERROR_PAGE_CODES) {
        const p: ErrorPageConfig | undefined = remote[c];
        next[c] = { title: p?.title ?? "", html: p?.html ?? "" };
      }
      return next;
    });
  }, [pages.data]);

  const current = drafts[code] ?? { title: "", html: "" };

  function updateDraft(patch: Partial<ErrorPageDraft>) {
    setDrafts((prev) => ({ ...prev, [code]: { ...current, ...patch } }));
  }

  function fillDefault() {
    const def = defaults.data?.defaults[code];
    if (!def) {
      showError(
        t("siteDetail.errorPages.noDefault"),
        t("siteDetail.errorPages.noDefaultHint", { code }),
      );
      return;
    }
    updateDraft({ title: def.title, html: def.html });
  }

  async function handleSave() {
    setSaving(true);
    try {
      const entries = Object.entries(drafts).filter(
        ([, v]) => v.title.trim() !== "" || v.html.trim() !== "",
      );
      await apiPost(`/sites/${siteId}/error-pages`, {
        error_pages: Object.fromEntries(
          entries.map(([c, v]) => [
            c,
            { status_code: Number(c), title: v.title, html: v.html, content_type: "text/html" },
          ]),
        ),
      });
      showSuccess(t("siteDetail.errorPages.saved"));
      void pages.reload();
    } catch (err) {
      showError(t("sites.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-col gap-3 py-2">
      <div className="flex flex-wrap gap-1.5">
        {ERROR_PAGE_CODES.map((c) => (
          <Button
            key={c}
            size="sm"
            variant={c === code ? "primary" : "outline"}
            onPress={() => setCode(c)}
          >
            {c}
          </Button>
        ))}
      </div>
      <TextField aria-label={t("siteDetail.errorPages.previewTitle", { code })}>
        <Input
          placeholder={t("siteDetail.errorPages.titlePlaceholder", { code })}
          value={current.title}
          onChange={(e) => updateDraft({ title: e.target.value })}
        />
      </TextField>
      <TextArea
        aria-label={t("siteDetail.errorPages.htmlPlaceholder")}
        className="min-h-40 font-mono text-xs"
        placeholder={t("siteDetail.errorPages.htmlPlaceholder")}
        value={current.html}
        onChange={(e) => updateDraft({ html: e.target.value })}
      />
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" onPress={fillDefault}>
          <Wand2 className="size-3.5" /> {t("siteDetail.errorPages.fillDefault")}
        </Button>
        <Button
          variant="outline"
          size="sm"
          isPending={previewing}
          onPress={() => void handlePreview()}
        >
          {t("siteDetail.errorPages.preview")}
        </Button>
        <Button variant="primary" size="sm" isPending={saving} onPress={() => void handleSave()}>
          {t("common.save")}
        </Button>
        <span className="text-muted text-xs">{t("siteDetail.errorPages.emptyHint")}</span>
      </div>

      <Modal state={previewState}>
        <Modal.Backdrop>
          <Modal.Container size="lg">
            <Modal.Dialog>
              <Modal.Header>
                <Modal.Heading>
                  {t("siteDetail.errorPages.previewTitle", { code })}
                </Modal.Heading>
                <Modal.CloseTrigger />
              </Modal.Header>
              <Modal.Body>
                <iframe
                  title={t("siteDetail.errorPages.previewAria")}
                  srcDoc={previewHtml}
                  sandbox=""
                  className="border-separator h-[420px] w-full rounded-lg border bg-white"
                />
              </Modal.Body>
              <Modal.Footer>
                <Button size="sm" variant="ghost" onPress={previewState.close}>
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
