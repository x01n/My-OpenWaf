"use client";

import { useState, useMemo, useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import {
  IconShield,
  IconCopy,
  IconCheck,
  IconRefresh,
  IconDatabase,
  IconCode,
  IconUpload,
  IconFolder,
  IconTerminal2,
  IconCoffee,
  IconPackages,
  IconBug,
} from "@tabler/icons-react";
import { useOwaspRules, useOwaspBatchUpdate } from "@/hooks/use-api";
import { cn } from "@/lib/utils";

// ============================================================
// 类型定义
// ============================================================

interface OwaspRule {
  id: string;
  category: string;
  name: string;
  description: string;
  enabled: boolean;
  action?: string;
  sensitivity?: string;
}

interface OwaspRulesResponse {
  items: OwaspRule[];
  grouped: Record<string, OwaspRule[]>;
  total: number;
}

type ModuleMode = "disabled" | "observe" | "balanced" | "strict";
type ConfigMode = "global" | "custom";

interface AttackModule {
  key: string;
  nameKey: string;
  category: string;
  descKey: string;
  icon: React.ElementType;
}

// ============================================================
// 常量
// ============================================================

const MODULES: AttackModule[] = [
  { key: "sqli", nameKey: "attacks.sqli", category: "sqli", descKey: "attacks.moduleDesc.sqli", icon: IconDatabase },
  { key: "xss", nameKey: "attacks.xss", category: "xss", descKey: "attacks.moduleDesc.xss", icon: IconCode },
  { key: "file_upload", nameKey: "attacks.fileUpload", category: "file_upload", descKey: "attacks.moduleDesc.fileUpload", icon: IconUpload },
  { key: "path_traversal", nameKey: "attacks.pathTraversal", category: "path_traversal", descKey: "attacks.moduleDesc.pathTraversal", icon: IconFolder },
  { key: "cmd_injection", nameKey: "attacks.cmdInjection", category: "cmd_injection", descKey: "attacks.moduleDesc.cmdInjection", icon: IconTerminal2 },
  { key: "java_code", nameKey: "attacks.javaCodeInjection", category: "java_code_injection", descKey: "attacks.moduleDesc.javaCodeInjection", icon: IconCoffee },
  { key: "java_deser", nameKey: "attacks.javaDeserialization", category: "java_deserialization", descKey: "attacks.moduleDesc.javaDeserialization", icon: IconPackages },
  { key: "php_deser", nameKey: "attacks.phpDeserialization", category: "php_deserialization", descKey: "attacks.moduleDesc.phpDeserialization", icon: IconPackages },
  { key: "php_code", nameKey: "attacks.phpCodeInjection", category: "php_code_injection", descKey: "attacks.moduleDesc.phpCodeInjection", icon: IconBug },
  { key: "asp_code", nameKey: "attacks.aspCodeInjection", category: "asp_code_injection", descKey: "attacks.moduleDesc.aspCodeInjection", icon: IconBug },
];

const MODE_OPTIONS: { value: ModuleMode; labelKey: string }[] = [
  { value: "disabled", labelKey: "attacks.disabled" },
  { value: "observe", labelKey: "attacks.observe" },
  { value: "balanced", labelKey: "attacks.balanced" },
  { value: "strict", labelKey: "attacks.strict" },
];

const GLOBAL_DEFAULT_MODE: ModuleMode = "balanced";

// ============================================================
// 辅助函数
// ============================================================

function inferMode(rules: OwaspRule[] | undefined): ModuleMode {
  if (!rules || rules.length === 0) return GLOBAL_DEFAULT_MODE;
  const allDisabled = rules.every((r) => !r.enabled);
  if (allDisabled) return "disabled";
  const allObserve = rules.every((r) => r.enabled && r.action === "observe");
  if (allObserve) return "observe";
  const allStrict = rules.every(
    (r) =>
      r.enabled &&
      (r.action === "intercept" || !r.action) &&
      (r.sensitivity === "high" || r.sensitivity === "strict")
  );
  if (allStrict) return "strict";
  return "balanced";
}

function modeToOverride(mode: ModuleMode): {
  enabled: boolean;
  action: string;
  sensitivity: string;
} {
  switch (mode) {
    case "disabled":
      return { enabled: false, action: "", sensitivity: "" };
    case "observe":
      return { enabled: true, action: "observe", sensitivity: "" };
    case "balanced":
      return { enabled: true, action: "intercept", sensitivity: "medium" };
    case "strict":
      return { enabled: true, action: "intercept", sensitivity: "high" };
  }
}

function getModeBadgeVariant(mode: ModuleMode): "default" | "secondary" | "destructive" | "outline" {
  switch (mode) {
    case "disabled":
      return "secondary";
    case "observe":
      return "outline";
    case "balanced":
      return "default";
    case "strict":
      return "destructive";
  }
}

// ============================================================
// 组件
// ============================================================

interface AttackProtectionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AttackProtectionDialog({ open, onOpenChange }: AttackProtectionDialogProps) {
  const { t } = useTranslation();
  const { data, isLoading, mutate } = useOwaspRules() as {
    data: OwaspRulesResponse | undefined;
    isLoading: boolean;
    mutate: () => void;
  };
  const { execute: batchUpdate, loading: isSaving } = useOwaspBatchUpdate();

  const [configMode, setConfigMode] = useState<ConfigMode>("custom");
  const [batchMode, setBatchMode] = useState<ModuleMode>("balanced");
  const [moduleModes, setModuleModes] = useState<Record<string, ModuleMode>>({});
  const [hasChanges, setHasChanges] = useState(false);
  const [initialized, setInitialized] = useState(false);

  // 数据加载后推断初始配置模式
  useEffect(() => {
    if (data?.grouped && !initialized) {
      let hasCustom = false;
      for (const mod of MODULES) {
        const rules = data.grouped[mod.category];
        if (rules && rules.length > 0) {
          const mode = inferMode(rules);
          if (mode !== GLOBAL_DEFAULT_MODE) {
            hasCustom = true;
            break;
          }
        }
      }
      setConfigMode(hasCustom ? "custom" : "global"); // eslint-disable-line react-hooks/set-state-in-effect
      setInitialized(true);
    }
  }, [data, initialized]);

  // 从数据推断每个模块的初始模式
  useEffect(() => {
    if (data?.grouped && !initialized) {
      let hasCustom = false;
      for (const mod of MODULES) {
        const rules = data.grouped[mod.category];
        if (rules && rules.length > 0) {
          const mode = inferMode(rules);
          if (mode !== GLOBAL_DEFAULT_MODE) {
            hasCustom = true;
            break;
          }
        }
      }
      setConfigMode(hasCustom ? "custom" : "global"); // eslint-disable-line react-hooks/set-state-in-effect
      setInitialized(true);
    }
  }, [data, initialized]);
  // 从数据推断每个模块的初始模式
  const inferredModes = useMemo(() => {
    if (!data?.grouped) return {};
    const modes: Record<string, ModuleMode> = {};
    for (const mod of MODULES) {
      const rules = data.grouped[mod.category];
      modes[mod.key] = inferMode(rules);
    }
    return modes;
  }, [data]);

  const currentModes = useMemo(() => {
    const result: Record<string, ModuleMode> = {};
    for (const mod of MODULES) {
      if (configMode === "global") {
        result[mod.key] = GLOBAL_DEFAULT_MODE;
      } else {
        result[mod.key] = moduleModes[mod.key] ?? inferredModes[mod.key] ?? GLOBAL_DEFAULT_MODE;
      }
    }
    return result;
  }, [inferredModes, moduleModes, configMode]);

  const handleModeChange = useCallback((key: string, mode: ModuleMode) => {
    setModuleModes((prev) => ({ ...prev, [key]: mode }));
    setHasChanges(true);
  }, []);

  const handleConfigModeChange = useCallback((mode: ConfigMode) => {
    setConfigMode(mode);
    setHasChanges(true);
  }, []);

  const handleBatchApply = useCallback(() => {
    const updates: Record<string, ModuleMode> = {};
    for (const mod of MODULES) {
      const rules = data?.grouped?.[mod.category];
      if (rules && rules.length > 0) {
        updates[mod.key] = batchMode;
      }
    }
    setModuleModes(updates);
    setHasChanges(true);
    toast.success(t("attacks.batchApplied"));
  }, [batchMode, data, t]);

  const handleSave = useCallback(async () => {
    if (!data?.grouped) {
      toast.error(t("attacks.dataNotLoaded"));
      return;
    }

    if (configMode === "global") {
      toast.success(t("attacks.followGlobal"));
      setHasChanges(false);
      onOpenChange(false);
      return;
    }

    const updates: { id: string; enabled: boolean; action: string; sensitivity: string }[] = [];

    for (const mod of MODULES) {
      const rules = data.grouped[mod.category];
      if (!rules || rules.length === 0) continue;

      const mode = currentModes[mod.key];
      const override = modeToOverride(mode);

      for (const rule of rules) {
        updates.push({
          id: rule.id,
          enabled: override.enabled,
          action: override.action,
          sensitivity: override.sensitivity,
        });
      }
    }

    if (updates.length === 0) {
      toast.error(t("attacks.noModules"));
      return;
    }

    try {
      await batchUpdate({ rules: updates });
      toast.success(t("attacks.saveSuccess"));
      setHasChanges(false);
      mutate();
      onOpenChange(false);
    } catch (err) {
      toast.error(t("attacks.saveFailed", { message: err instanceof Error ? err.message : String(err) }));
    }
  }, [data, currentModes, configMode, batchUpdate, mutate, t, onOpenChange]);

  const handleCancel = useCallback(() => {
    setModuleModes({});
    setHasChanges(false);
    if (data?.grouped) {
      let hasCustom = false;
      for (const mod of MODULES) {
        const rules = data.grouped[mod.category];
        if (rules && rules.length > 0) {
          const mode = inferMode(rules);
          if (mode !== GLOBAL_DEFAULT_MODE) {
            hasCustom = true;
            break;
          }
        }
      }
      setConfigMode(hasCustom ? "custom" : "global");
    }
    onOpenChange(false);
  }, [data, onOpenChange]);

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleCancel(); }}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto p-0">
        <DialogHeader className="px-6 pt-6 pb-2">
          <DialogTitle className="flex items-center gap-2 text-base">
            <IconShield className="h-5 w-5 text-primary" />
            {t("attacks.title")}
          </DialogTitle>
        </DialogHeader>

        <div className="px-6 space-y-4">
          {/* 配置模式切换 + 批量配置 */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-5 w-1 rounded-full bg-primary" />
              <span className="text-sm font-medium">{t("attacks.protectionMode")}</span>

              <RadioGroup
                value={configMode}
                onValueChange={(v) => handleConfigModeChange(v as ConfigMode)}
                className="flex items-center gap-0 rounded-lg border p-1"
              >
                <div className="flex items-center">
                  <RadioGroupItem value="global" id="dlg-mode-global" className="sr-only" />
                  <Label
                    htmlFor="dlg-mode-global"
                    className={cn(
                      "cursor-pointer rounded-md px-3 py-1 text-xs font-medium transition-colors",
                      configMode === "global" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"
                    )}
                  >
                    {t("attacks.followGlobalConfig")}
                  </Label>
                </div>
                <div className="flex items-center">
                  <RadioGroupItem value="custom" id="dlg-mode-custom" className="sr-only" />
                  <Label
                    htmlFor="dlg-mode-custom"
                    className={cn(
                      "cursor-pointer rounded-md px-3 py-1 text-xs font-medium transition-colors",
                      configMode === "custom" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"
                    )}
                  >
                    {t("attacks.useCustomConfig")}
                  </Label>
                </div>
              </RadioGroup>
            </div>

            {configMode === "custom" && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">{t("attacks.batchConfig")}</span>
                <select
                  value={batchMode}
                  onChange={(e) => setBatchMode(e.target.value as ModuleMode)}
                  className="h-7 rounded-md border border-input bg-background px-2 text-xs outline-none focus:ring-2 focus:ring-ring"
                >
                  {MODE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {t(opt.labelKey)}
                    </option>
                  ))}
                </select>
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={handleBatchApply}>
                  <IconCopy className="mr-1 h-3 w-3" />
                  {t("attacks.apply")}
                </Button>
              </div>
            )}
          </div>

          {/* 模块列表 */}
          <div className="rounded-lg border overflow-hidden">
            {/* 表头 */}
            <div className="flex items-center bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
              <span className="flex-1">{t("attacks.moduleName")}</span>
              <span className="w-80 text-right">{t("common.actions")}</span>
            </div>

            <div className="divide-y">
              {isLoading ? (
                Array.from({ length: MODULES.length }).map((_, i) => (
                  <div key={i} className="flex items-center gap-4 px-4 py-3">
                    <Skeleton className="h-8 w-8 rounded-lg" />
                    <div className="flex-1 space-y-2">
                      <Skeleton className="h-3 w-24" />
                      <Skeleton className="h-2 w-40" />
                    </div>
                    <Skeleton className="h-6 w-64" />
                  </div>
                ))
              ) : (
                MODULES.map((mod) => {
                  const mode = currentModes[mod.key];
                  const rules = data?.grouped?.[mod.category];
                  const hasRules = rules && rules.length > 0;
                  const isDisabled = configMode === "global" || !hasRules || isSaving;
                  const ModIcon = mod.icon;
                  const modeLabel = MODE_OPTIONS.find((o) => o.value === mode)?.labelKey || "";

                  return (
                    <div
                      key={mod.key}
                      className={cn(
                        "flex items-center justify-between px-4 py-3 transition-colors",
                        hasChanges && configMode === "custom" && moduleModes[mod.key] !== undefined
                          ? "bg-primary/[0.02]"
                          : ""
                      )}
                    >
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                          <ModIcon className="h-4 w-4 text-primary" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">{t(mod.nameKey)}</span>
                            {!hasRules && (
                              <span className="text-xs text-muted-foreground">({t("attacks.noRules")})</span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <Badge variant={getModeBadgeVariant(mode)} className="shrink-0 text-[10px] h-5">
                          {t(modeLabel)}
                        </Badge>
                        <div className="flex items-center gap-1">
                          {MODE_OPTIONS.map((opt) => (
                            <button
                              key={opt.value}
                              type="button"
                              disabled={isDisabled}
                              onClick={() => handleModeChange(mod.key, opt.value)}
                              className={cn(
                                "flex items-center gap-1 rounded-md px-2 py-1 text-xs transition-colors",
                                mode === opt.value
                                  ? "bg-primary text-primary-foreground"
                                  : "text-muted-foreground hover:bg-muted",
                                isDisabled && "cursor-not-allowed opacity-50"
                              )}
                            >
                              <span
                                className={cn(
                                  "h-3 w-3 rounded-full border",
                                  mode === opt.value
                                    ? "border-primary-foreground bg-primary-foreground"
                                    : "border-muted-foreground"
                                )}
                              >
                                {mode === opt.value && (
                                  <span className="flex h-full w-full items-center justify-center">
                                    <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                                  </span>
                                )}
                              </span>
                              {t(opt.labelKey)}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* 底部按钮 */}
        <div className="flex items-center justify-end gap-3 border-t px-6 py-4">
          <Button variant="outline" onClick={handleCancel} disabled={isSaving}>
            {t("common.cancel")}
          </Button>
          <Button onClick={handleSave} disabled={isLoading || isSaving}>
            {isSaving ? (
              <>
                <IconRefresh className="mr-2 h-4 w-4 animate-spin" />
                {t("common.saving")}
              </>
            ) : (
              <>
                <IconCheck className="mr-2 h-4 w-4" />
                {t("common.save")}
              </>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
