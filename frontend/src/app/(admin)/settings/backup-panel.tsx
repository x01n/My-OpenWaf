"use client";

/**
 * 配置备份面板：
 * - GET /backup/export（admin 会话，返回完整备份 JSON）
 * - POST /backup/import {data, replace_mode}，响应为导入统计
 * 导出走 JSON 文件下载 / 上传，不依赖对象存储。
 */

import { useRef, useState } from "react";
import { Button, Chip } from "@heroui/react";
import { Download, Upload } from "lucide-react";
import { apiGet, apiPost, ApiError } from "@/lib/api/client";
import { useI18n } from "@/i18n";
import { ToggleSwitch } from "@/components/ui/primitives";
import { PanelCard, WarningBanner } from "./form-kit";
import { showSuccess, showError } from "@/components/ui/toast-host";
import type { BackupImportStats } from "@/lib/types/settings";

export function BackupPanel() {
  const { t } = useI18n();
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [replaceMode, setReplaceMode] = useState(false);
  const [stats, setStats] = useState<BackupImportStats | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleExport() {
    setExporting(true);
    try {
      const data = await apiGet<Record<string, unknown>>("/backup/export");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `owaf-backup-${new Date().toISOString().slice(0, 19).replaceAll(":", "").replace("T", "-")}.json`;
      link.click();
      // 让下载任务先拿到 blob，再回收对象 URL
      setTimeout(() => URL.revokeObjectURL(url), 0);
      showSuccess(t("settings.backup.exportSuccess"));
    } catch (err) {
      showError(t("settings.backup.exportFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setExporting(false);
    }
  }

  async function handleImport(file: File) {
    setImporting(true);
    setStats(null);
    try {
      const parsed: unknown = JSON.parse(await file.text());
      const result = await apiPost<BackupImportStats>("/backup/import", {
        data: parsed,
        replace_mode: replaceMode,
      });
      setStats(result);
      showSuccess(t("settings.backup.importSuccess"));
    } catch (err) {
      if (err instanceof SyntaxError) {
        showError(t("settings.backup.importFailed"), t("settings.backup.invalidJson"));
      } else {
        showError(t("settings.backup.importFailed"), err instanceof ApiError ? err.message : undefined);
      }
    } finally {
      setImporting(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <PanelCard
        title={t("settings.backup.exportTitle")}
        description={t("settings.backup.exportDescription")}
      >
        <Button variant="primary" isPending={exporting} onPress={() => void handleExport()}>
          <Download className="size-4" /> {t("settings.backup.exportBtn")}
        </Button>
      </PanelCard>

      <PanelCard
        title={t("settings.backup.importTitle")}
        description={t("settings.backup.importDescription")}
      >
        <WarningBanner>
          {replaceMode
            ? t("settings.backup.modeReplaceWarning")
            : t("settings.backup.modeMergeWarning")}
        </WarningBanner>
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-2 text-sm">
            <ToggleSwitch
              isSelected={replaceMode}
              onChange={setReplaceMode}
              aria-label={t("settings.backup.replaceMode")}
            />
            {t("settings.backup.replaceMode")}
          </label>
          <label>
            <input
              ref={fileRef}
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void handleImport(file);
              }}
            />
            <Button
              variant="outline"
              isPending={importing}
              onPress={() => fileRef.current?.click()}
            >
              <Upload className="size-4" /> {t("settings.backup.selectFileBtn")}
            </Button>
          </label>
        </div>
        {stats && (
          <div className="flex flex-wrap items-center gap-2">
            <Chip size="sm" variant="soft" color="success">
              {t("settings.backup.statSites", { count: stats.sites })}
            </Chip>
            <Chip size="sm" variant="soft" color="success">
              {t("settings.backup.statCertificates", { count: stats.certificates })}
            </Chip>
            <Chip size="sm" variant="soft" color="success">
              {t("settings.backup.statRules", { count: stats.rules })}
            </Chip>
            <Chip size="sm" variant="soft" color="success">
              {t("settings.backup.statIpEntries", { count: stats.ip_entries })}
            </Chip>
          </div>
        )}
      </PanelCard>
    </div>
  );
}
