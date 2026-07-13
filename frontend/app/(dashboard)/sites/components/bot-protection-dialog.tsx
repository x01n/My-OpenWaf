"use client";

import { useState, useMemo, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { toast } from "sonner";
import {
  IconUserCheck,
  IconShield,
  IconRefresh,
  IconHelpCircle,
  IconFileSearch,
} from "@tabler/icons-react";
import {
  useBotSettings,
  useBotSettingsUpdate,
  useSiteRecordedResources,
} from "@/hooks/use-api";
import { ResourcePathTree } from "@/components/ui/resource-path-tree";
import { cn } from "@/lib/utils";

interface DynamicOption {
  key: string;
  labelKey: string;
  descKey: string;
  recommended?: boolean;
  configKey?: string;
  resourceLabelKey?: string;
  resourceEmptyKey?: string;
}

interface BotProtectionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  siteId?: number;
}

export function BotProtectionDialog({ open, onOpenChange, siteId }: BotProtectionDialogProps) {
  const { t } = useTranslation();
  const { data: botSettings, isLoading, mutate } = useBotSettings();
  const updateBot = useBotSettingsUpdate();
  const { data: recordedResourcesData } = useSiteRecordedResources(siteId);

  const recordedResources = useMemo(() => {
    return recordedResourcesData || [];
  }, [recordedResourcesData]);

  const [localSettings, setLocalSettings] = useState<Record<string, any>>({}); // eslint-disable-line @typescript-eslint/no-explicit-any

  const getValue = useCallback(
    (key: string, defaultValue: any = false) => { // eslint-disable-line @typescript-eslint/no-explicit-any
      return localSettings[key] !== undefined
        ? localSettings[key]
        : (botSettings?.[key] ?? defaultValue);
    },
    [localSettings, botSettings]
  );

  const handleToggle = useCallback(
    (key: string) => {
      setLocalSettings((prev) => ({ ...prev, [key]: !getValue(key) }));
    },
    [getValue]
  );

  const handleSubToggle = useCallback(
    (key: string) => {
      setLocalSettings((prev) => ({ ...prev, [key]: !getValue(key) }));
    },
    [getValue]
  );

  const handleResourceSelect = useCallback(
    (key: string, path: string, checked: boolean) => {
      const current = (getValue(key, []) as string[]) || [];
      let next: string[];
      if (checked) {
        next = current.includes(path) ? current : [...current, path];
      } else {
        next = current.filter((p) => p !== path);
      }
      setLocalSettings((prev) => ({ ...prev, [key]: next }));
    },
    [getValue]
  );

  const handleTextChange = useCallback(
    (key: string, value: string) => {
      setLocalSettings((prev) => ({ ...prev, [key]: value }));
    },
    []
  );

  const handleValueChange = useCallback(
    (key: string, value: unknown) => {
      setLocalSettings((prev) => ({ ...prev, [key]: value }));
    },
    []
  );

  const handleArrayChange = useCallback(
    (key: string, value: string) => {
      setLocalSettings((prev) => ({
        ...prev,
        [key]: value
          .split("\n")
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
      }));
    },
    []
  );

  const hasChanges = useMemo(() => {
    return Object.keys(localSettings).length > 0;
  }, [localSettings]);

  const handleSave = useCallback(async () => {
    try {
      await updateBot.execute({ ...botSettings, ...localSettings });
      toast.success(t("captcha.saveSuccess"));
      setLocalSettings({});
      mutate();
      onOpenChange(false);
    } catch {
      toast.error(t("captcha.saveFailed"));
    }
  }, [botSettings, localSettings, updateBot, mutate, t, onOpenChange]);

  const handleCancel = useCallback(() => {
    setLocalSettings({});
    onOpenChange(false);
  }, [onOpenChange]);

  const dynamicProtectionEnabled = getValue("dynamic_protection_enabled", false);

  const dynamicOptions: DynamicOption[] = [
    {
      key: "html_obfuscation",
      labelKey: "captcha.htmlObfuscation",
      descKey: "captcha.htmlObfuscationDesc",
      recommended: true,
    },
    {
      key: "js_obfuscation",
      labelKey: "captcha.jsObfuscation",
      descKey: "captcha.jsObfuscationDesc",
      configKey: "js_obfuscation_paths",
      resourceLabelKey: "captcha.jsObfuscationPaths",
      resourceEmptyKey: "captcha.noRecordedResources",
    },
    {
      key: "image_watermark",
      labelKey: "captcha.imageWatermark",
      descKey: "captcha.imageWatermarkDesc",
      configKey: "image_watermark_paths",
      resourceLabelKey: "captcha.imageWatermarkPaths",
      resourceEmptyKey: "captcha.noRecordedResources",
    },
  ];

  const sections = [
    {
      key: "captcha",
      titleKey: "captcha.section.captcha",
      switchKey: "captcha_enabled",
      descKey: "captcha.enableCaptchaDesc",
    },
    {
      key: "dynamic",
      titleKey: "captcha.section.dynamicProtection",
      switchKey: "dynamic_protection_enabled",
      descKey: "captcha.enableDynamicProtectionDesc",
      hasSubOptions: true,
    },
    {
      key: "antiReplay",
      titleKey: "captcha.section.antiReplay",
      switchKey: "anti_replay_enabled",
      descKey: "captcha.enableAntiReplayDesc",
    },
  ];

  if (isLoading) {
    return (
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleCancel(); }}>
        <DialogContent className="max-w-lg p-0">
          <DialogHeader className="px-6 pt-6 pb-2">
            <DialogTitle className="flex items-center gap-2 text-base">
              <IconUserCheck className="h-5 w-5 text-primary" />
              {t("captcha.botProtection")}
            </DialogTitle>
          </DialogHeader>
          <div className="px-6 py-8 space-y-4">
            <div className="h-32 animate-pulse rounded-lg bg-muted" />
            <div className="h-32 animate-pulse rounded-lg bg-muted" />
            <div className="h-16 animate-pulse rounded-lg bg-muted" />
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleCancel(); }}>
      <DialogContent className="max-w-xl p-0 max-h-[85vh] overflow-y-auto">
        <DialogHeader className="px-6 pt-6 pb-2">
          <DialogTitle className="flex items-center gap-2 text-base">
            <IconUserCheck className="h-5 w-5 text-primary" />
            {t("captcha.botProtection")}
          </DialogTitle>
        </DialogHeader>

        <div className="px-6 space-y-6 py-2">
          {sections.map((section) => {
            const enabled = getValue(section.switchKey, false);
            const isDynamic = section.key === "dynamic";

            return (
              <div key={section.key} className="space-y-3">
                {/* 标题行 */}
                <div className="flex items-center gap-3">
                  <div className="h-5 w-1 rounded-full bg-primary" />
                  <span className="text-sm font-medium">{t(section.titleKey)}</span>
                  <Switch
                    checked={enabled}
                    onCheckedChange={() => handleToggle(section.switchKey)}
                    id={`dlg-${section.switchKey}`}
                  />
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <IconHelpCircle className="h-3.5 w-3.5" />
                    <span>{t(section.descKey)}</span>
                  </div>
                </div>

                {/* 动态防护子选项 */}
                {isDynamic && (
                  <div
                    className={cn(
                      "ml-4 space-y-4 rounded-lg border p-4 transition-all",
                      dynamicProtectionEnabled
                        ? "opacity-100"
                        : "pointer-events-none opacity-40"
                    )}
                  >
                    {dynamicOptions.map((option) => {
                      const optionEnabled = getValue(option.key, false);
                      const isJs = option.key === "js_obfuscation";
                      const jsMode = getValue("js_protection_mode", "all") as
                        | "all"
                        | "paths";
                      // JS 保护在 all 模式下不需要选择路径，仅 paths 模式展示路径树
                      const showResourceTree =
                        option.configKey &&
                        siteId &&
                        (!isJs || jsMode === "paths");

                      return (
                        <div key={option.key} className="space-y-2">
                          <div className="flex items-start gap-3">
                            <Checkbox
                              id={`dlg-${option.key}`}
                              checked={optionEnabled}
                              onCheckedChange={() => handleSubToggle(option.key)}
                              disabled={!dynamicProtectionEnabled}
                            />
                            <div className="flex flex-col gap-0.5">
                              <div className="flex items-center gap-2">
                                <Label
                                  htmlFor={`dlg-${option.key}`}
                                  className={cn(
                                    "cursor-pointer text-sm font-normal",
                                    !dynamicProtectionEnabled && "cursor-not-allowed"
                                  )}
                                >
                                  {t(option.labelKey)}
                                </Label>
                                {option.recommended && (
                                  <span className="inline-flex items-center rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                                    {t("captcha.recommended")}
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-muted-foreground">
                                {t(option.descKey)}
                              </p>
                            </div>
                          </div>

                          {/* JS 保护范围模式选择 */}
                          {isJs && optionEnabled && dynamicProtectionEnabled && (
                            <div className="ml-7 space-y-2">
                              <Label className="text-xs font-medium">
                                {t("captcha.jsProtectionMode")}
                              </Label>
                              <RadioGroup
                                value={jsMode}
                                onValueChange={(v) =>
                                  handleValueChange("js_protection_mode", v)
                                }
                                className="flex flex-col gap-1.5"
                              >
                                <div className="flex items-center gap-2">
                                  <RadioGroupItem value="all" id="dlg-js-mode-all" />
                                  <Label
                                    htmlFor="dlg-js-mode-all"
                                    className="cursor-pointer text-xs font-normal"
                                  >
                                    {t("captcha.jsProtectionModeAll")}
                                  </Label>
                                </div>
                                <div className="flex items-center gap-2">
                                  <RadioGroupItem value="paths" id="dlg-js-mode-paths" />
                                  <Label
                                    htmlFor="dlg-js-mode-paths"
                                    className="cursor-pointer text-xs font-normal"
                                  >
                                    {t("captcha.jsProtectionModePaths")}
                                  </Label>
                                </div>
                              </RadioGroup>
                            </div>
                          )}

                          {/* 从已记录资源中选择路径 */}
                          {showResourceTree && optionEnabled && dynamicProtectionEnabled && (
                            <div className="ml-7 space-y-1">
                              <Label className="text-xs font-medium">
                                {t(option.resourceLabelKey!)}
                              </Label>
                              {recordedResources.length > 0 ? (
                                <ResourcePathTree
                                  resources={recordedResources}
                                  selectedPaths={
                                    (getValue(option.configKey!, []) as string[]) || []
                                  }
                                  onSelect={(path, checked) =>
                                    handleResourceSelect(option.configKey!, path, checked)
                                  }
                                />
                              ) : (
                                <div className="flex items-center gap-2 rounded-md border bg-muted/50 p-3 text-xs text-muted-foreground">
                                  <IconFileSearch className="h-4 w-4" />
                                  {t(option.resourceEmptyKey!)}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}

                    {/* 水印文字单独放在图片水印下方 */}
                    {getValue("image_watermark", false) && dynamicProtectionEnabled && (
                      <div className="ml-7 space-y-1">
                        <Label className="text-xs font-medium">
                          {t("captcha.watermarkText")}
                        </Label>
                        <Input
                          className="text-xs"
                          placeholder={t("captcha.watermarkTextPlaceholder")}
                          value={getValue("watermark_text", "")}
                          onChange={(e) => handleTextChange("watermark_text", e.target.value)}
                        />
                      </div>
                    )}

                    {/* 解密缓存时间 */}
                    {dynamicProtectionEnabled && (
                      <div className="ml-7 space-y-1">
                        <Label className="text-xs font-medium">
                          {t("captcha.decryptCacheTtl")}
                        </Label>
                        <div className="flex items-center gap-2">
                          <Input
                            type="number"
                            min={0}
                            className="w-32 text-xs"
                            value={getValue("decrypt_cache_ttl_seconds", 0)}
                            onChange={(e) =>
                              handleValueChange(
                                "decrypt_cache_ttl_seconds",
                                Math.max(0, Number(e.target.value) || 0)
                              )
                            }
                          />
                          <span className="text-xs text-muted-foreground">
                            {t("captcha.decryptCacheTtlUnit")}
                          </span>
                        </div>
                        <p className="text-[10px] text-muted-foreground">
                          {t("captcha.decryptCacheTtlDesc")}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {/* 排除采集头部配置 */}
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="h-5 w-1 rounded-full bg-primary" />
              <span className="text-sm font-medium">{t("captcha.excludeRecordHeaders")}</span>
            </div>
            <div className="ml-4 space-y-1">
              <Label className="text-xs font-medium">
                {t("captcha.excludeRecordHeadersLabel")}
              </Label>
              <textarea
                className="w-full min-h-[80px] rounded-md border border-input bg-background px-3 py-2 text-xs ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                placeholder={t("captcha.excludeRecordHeadersPlaceholder")}
                value={(getValue("exclude_record_headers", []) as string[]).join("\n")}
                onChange={(e) => handleArrayChange("exclude_record_headers", e.target.value)}
              />
              <p className="text-[10px] text-muted-foreground">
                {t("captcha.excludeRecordHeadersHint")}
              </p>
            </div>
          </div>
        </div>

        {/* 底部按钮 */}
        <div className="flex items-center justify-end gap-3 border-t px-6 py-4">
          <Button variant="outline" onClick={handleCancel} disabled={updateBot.loading}>
            {t("captcha.cancel")}
          </Button>
          <Button
            onClick={handleSave}
            disabled={!hasChanges || updateBot.loading}
            className="bg-primary hover:bg-primary/90"
          >
            {updateBot.loading ? (
              <>
                <IconRefresh className="mr-2 h-4 w-4 animate-spin" />
                {t("common.saving")}
              </>
            ) : (
              <>
                <IconShield className="mr-2 h-4 w-4" />
                {t("captcha.save")}
              </>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
