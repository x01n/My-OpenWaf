"use client";

import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  IconDatabaseExport,
  IconDatabaseImport,
  IconDownload,
  IconUpload,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { backupApi } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import type { BackupData } from "@/lib/types";

/**
 * 校验对象是否为合法的 BackupData（至少含版本号与关键数组字段）。
 *
 * @param obj 解析后的 JSON 对象。
 * @return 是否为可用备份数据。
 */
function isBackupData(obj: unknown): obj is BackupData {
  if (typeof obj !== "object" || obj === null) return false;
  const b = obj as Record<string, unknown>;
  return (
    typeof b.version === "number" &&
    b.version > 0 &&
    Array.isArray(b.sites) &&
    Array.isArray(b.rules)
  );
}

/**
 * BackupPage 提供配置的整体导出与恢复界面。
 */
export default function BackupPage() {
  const { t } = useTranslation();

  const [exporting, setExporting] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [replaceMode, setReplaceMode] = useState(false);
  const [fileData, setFileData] = useState<BackupData | null>(null);
  const [fileName, setFileName] = useState<string>("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  /** 触发浏览器下载导出的备份 JSON。 */
  const handleExport = async () => {
    setExporting(true);
    try {
      const data = await backupApi.export();
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const date = new Date().toISOString().slice(0, 10);
      const a = document.createElement("a");
      a.href = url;
      a.download = `owaf-backup-${date}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(t("backup.exportSuccess"), {
        description: t("backup.exportSummary", {
          sites: data.sites?.length ?? 0,
          certificates: data.certificates?.length ?? 0,
          rules: data.rules?.length ?? 0,
          ipEntries: data.ip_list_entries?.length ?? 0,
        }),
      });
    } catch {
      toast.error(t("backup.exportFailed"));
    } finally {
      setExporting(false);
    }
  };

  /** 读取所选备份文件并解析为 BackupData。 */
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result));
        if (!isBackupData(parsed)) {
          setFileData(null);
          toast.error(t("backup.invalidBackup"));
          return;
        }
        setFileData(parsed);
      } catch {
        setFileData(null);
        toast.error(t("backup.fileParseError"));
      }
    };
    reader.onerror = () => {
      setFileData(null);
      toast.error(t("backup.fileParseError"));
    };
    reader.readAsText(file);
  };

  /** 执行恢复导入。 */
  const doRestore = async () => {
    if (!fileData) return;
    setRestoring(true);
    try {
      const result = await backupApi.import(fileData, replaceMode);
      toast.success(
        t("backup.restoreSuccess", {
          sites: result.sites,
          certificates: result.certificates,
          rules: result.rules,
          ipEntries: result.ip_entries,
        })
      );
      setConfirmOpen(false);
      setFileData(null);
      setFileName("");
      if (fileInputRef.current) fileInputRef.current.value = "";
    } catch {
      toast.error(t("backup.restoreFailed"));
    } finally {
      setRestoring(false);
    }
  };

  /** 备份文件概要中的各类数量项。 */
  const summaryItems = fileData
    ? [
        { label: t("backup.sites"), value: fileData.sites?.length ?? 0 },
        { label: t("backup.certificates"), value: fileData.certificates?.length ?? 0 },
        { label: t("backup.rules"), value: fileData.rules?.length ?? 0 },
        { label: t("backup.ipEntries"), value: fileData.ip_list_entries?.length ?? 0 },
      ]
    : [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <IconDatabaseExport className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-xl font-semibold">{t("backup.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("backup.description")}</p>
        </div>
      </div>

      {/* 导出备份 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconDownload className="h-5 w-5 text-primary" />
            {t("backup.exportTitle")}
          </CardTitle>
          <CardDescription>{t("backup.exportDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={handleExport} disabled={exporting}>
            <IconDownload className="h-4 w-4" />
            {exporting ? t("backup.exporting") : t("backup.exportButton")}
          </Button>
        </CardContent>
      </Card>

      {/* 恢复备份 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconDatabaseImport className="h-5 w-5 text-primary" />
            {t("backup.restoreTitle")}
          </CardTitle>
          <CardDescription>{t("backup.restoreDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor="backup-file">{t("backup.selectFile")}</Label>
            <Input
              id="backup-file"
              ref={fileInputRef}
              type="file"
              accept=".json,application/json"
              onChange={handleFileChange}
              className="max-w-md cursor-pointer"
            />
          </div>

          {fileData && (
            <div className="rounded-lg border bg-muted/30 p-4">
              <div className="mb-3 flex items-center gap-2">
                <span className="text-sm font-medium">{t("backup.fileSummaryTitle")}</span>
                {fileName && (
                  <span className="font-mono text-xs text-muted-foreground">{fileName}</span>
                )}
              </div>
              <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
                <div className="flex items-center gap-1.5">
                  <span className="text-muted-foreground">{t("backup.version")}</span>
                  <Badge variant="secondary">v{fileData.version}</Badge>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-muted-foreground">{t("backup.exportedAt")}</span>
                  <span className="font-mono text-xs">
                    {fileData.exported_at ? formatDate(fileData.exported_at) : "-"}
                  </span>
                </div>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {summaryItems.map((item) => (
                  <Badge key={item.label} variant="outline" className="font-normal">
                    {item.label}: {item.value}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="flex items-start gap-3 rounded-lg border p-3">
            <Switch
              id="replace-mode"
              checked={replaceMode}
              onCheckedChange={setReplaceMode}
            />
            <div className="space-y-1">
              <Label htmlFor="replace-mode" className="cursor-pointer text-sm">
                {t("backup.replaceMode")}
              </Label>
              <p className="text-xs text-muted-foreground">{t("backup.replaceModeDesc")}</p>
              {replaceMode && (
                <p className="flex items-start gap-1 text-xs font-medium text-destructive">
                  <IconAlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  {t("backup.replaceModeWarning")}
                </p>
              )}
            </div>
          </div>

          <Button
            variant={replaceMode ? "destructive" : "default"}
            disabled={!fileData || restoring}
            onClick={() => setConfirmOpen(true)}
          >
            <IconUpload className="h-4 w-4" />
            {restoring ? t("backup.restoring") : t("backup.restoreButton")}
          </Button>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t("backup.confirmTitle")}
        description={
          replaceMode ? t("backup.confirmReplaceDesc") : t("backup.confirmMergeDesc")
        }
        confirmText={t("backup.restoreButton")}
        onConfirm={doRestore}
        loading={restoring}
      />
    </div>
  );
}
