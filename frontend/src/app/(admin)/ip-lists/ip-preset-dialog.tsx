"use client";

/**
 * 预置爬虫白名单弹窗。
 *
 * 数据源 `GET /preset-bot-whitelist`，导入走 `POST /preset-bot-whitelist/seed`；
 * 导入完成后返回新增与跳过条数。
 */

import { useCallback } from "react";
import { useOverlayState, Button } from "@heroui/react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { FormDialog } from "@/components/ui/dialogs";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";
import type { PresetItem } from "./ip-lists-model";

export function IPPresetDialog({
  state,
  onImported,
}: {
  state: ReturnType<typeof useOverlayState>;
  onImported: () => void;
}) {
  const { t } = useI18n();
  const presetList = useApi<{ items: PresetItem[] }>(
    useCallback(() => apiGet<{ items: PresetItem[] }>("/preset-bot-whitelist"), []),
  );

  const items = presetList.data?.items ?? [];

  async function handleSeed() {
    try {
      const res = await apiPost<{ added: number; skipped: number }>(
        "/preset-bot-whitelist/seed",
      );
      showSuccess(
        t("ipLists.importDone", { added: res.added, skipped: res.skipped }),
      );
      onImported();
      void presetList.reload();
    } catch (err) {
      showError(t("ipLists.importFailed"), err instanceof ApiError ? err.message : undefined);
    }
  }

  return (
    <FormDialog
      state={state}
      title={t("ipLists.preset.title")}
      description={t("ipLists.preset.description")}
      size="md"
      footer={
        <>
          <Button variant="ghost" onPress={state.close}>
            {t("common.close")}
          </Button>
          <Button variant="primary" onPress={() => void handleSeed()}>
            {t("ipLists.preset.import")}
          </Button>
        </>
      }
    >
      {presetList.loading ? (
        <div className="text-muted py-4 text-center text-sm">{t("common.loading")}</div>
      ) : items.length === 0 ? (
        <div className="text-muted py-4 text-center text-sm">{t("ipLists.preset.empty")}</div>
      ) : (
        <div className="flex flex-col gap-1.5">
          {items.map((it) => (
            <div
              key={it.value}
              className="flex items-baseline justify-between gap-3 border-b border-separator py-1.5 text-sm last:border-0"
            >
              <span className="font-mono">{it.value}</span>
              <span className="text-muted text-xs">{it.note}</span>
            </div>
          ))}
        </div>
      )}
    </FormDialog>
  );
}
