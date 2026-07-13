"use client";

import { useState, useMemo, useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
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
  IconDeviceFloppy,
} from "@tabler/icons-react";
import { useOwaspRules, useOwaspBatchUpdate, useSiteMutation } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import type { Site } from "@/lib/types";

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

interface AttackModule {
  key: string;
  nameKey: string;
  category: string;
  icon: React.ElementType;
}

const MODULES: AttackModule[] = [
  { key: "sqli", nameKey: "attacks.sqli", category: "sqli", icon: IconDatabase },
  { key: "xss", nameKey: "attacks.xss", category: "xss", icon: IconCode },
  { key: "file_upload", nameKey: "attacks.fileUpload", category: "file_upload", icon: IconUpload },
  { key: "path_traversal", nameKey: "attacks.pathTraversal", category: "path_traversal", icon: IconFolder },
  { key: "cmd_injection", nameKey: "attacks.cmdInjection", category: "cmd_injection", icon: IconTerminal2 },
  { key: "java_code", nameKey: "attacks.javaCodeInjection", category: "java_code_injection", icon: IconCoffee },
  { key: "java_deser", nameKey: "attacks.javaDeserialization", category: "java_deserialization", icon: IconPackages },
  { key: "php_deser", nameKey: "attacks.phpDeserialization", category: "php_deserialization", icon: IconPackages },
  { key: "php_code", nameKey: "attacks.phpCodeInjection", category: "php_code_injection", icon: IconBug },
  { key: "asp_code", nameKey: "attacks.aspCodeInjection", category: "asp_code_injection", icon: IconBug },
];

const MODE_OPTIONS: { value: ModuleMode; labelKey: string }[] = [
  { value: "disabled", labelKey: "attacks.disabled" },
  { value: "observe", labelKey: "attacks.observe" },
  { value: "balanced", labelKey: "attacks.balanced" },
  { value: "strict", labelKey: "attacks.strict" },
];

const GLOBAL_DEFAULT_MODE: ModuleMode = "balanced";

function inferMode(rules: OwaspRule[] | undefined): ModuleMode {
  if (!rules || rules.length === 0) return GLOBAL_DEFAULT_MODE;
  const allDisabled = rules.every((r) => !r.enabled);
  if (allDisabled) return "disabled";
  const allObserve = rules.every((r) => r.enabled && r.action === "observe");
  if (allObserve) return "observe";
  const allStrict = rules.every(
    (r) => r.enabled && (r.action === "intercept" || !r.action) && (r.sensitivity === "high" || r.sensitivity === "strict")
  );
  if (allStrict) return "strict";
  return "balanced";
}

function modeToOverride(mode: ModuleMode): { enabled: boolean; action: string; sensitivity: string } {
  switch (mode) {
    case "disabled": return { enabled: false, action: "", sensitivity: "" };
    case "observe": return { enabled: true, action: "observe", sensitivity: "" };
    case "balanced": return { enabled: true, action: "intercept", sensitivity: "medium" };
    case "strict": return { enabled: true, action: "intercept", sensitivity: "high" };
  }
}

function getModeBadgeVariant(mode: ModuleMode): "default" | "secondary" | "destructive" | "outline" {
  switch (mode) {
    case "disabled": return "secondary";
    case "observe": return "outline";
    case "balanced": return "default";
    case "strict": return "destructive";
  }
}

interface ProtectionTabProps {
  site: Site;
}

export function ProtectionTab({ site }: ProtectionTabProps) {
  const { t } = useTranslation();
  const { data, isLoading, mutate } = useOwaspRules() as {
    data: OwaspRulesResponse | undefined;
    isLoading: boolean;
    mutate: () => void;
  };
  const { execute: batchUpdate, loading: isSaving } = useOwaspBatchUpdate();
  const updateSite = useSiteMutation();

  const [owaspEnabled, setOwaspEnabled] = useState(site.owasp_enabled ?? true);
  const [cveEnabled, setCveEnabled] = useState(site.cve_enabled ?? true);
  const [botEnabled, setBotEnabled] = useState(site.bot_protection_enabled ?? false);
  const [moduleModes, setModuleModes] = useState<Record<string, ModuleMode>>({});
  const [hasChanges, setHasChanges] = useState(false);
  const [batchMode, setBatchMode] = useState<ModuleMode>("balanced");

  const inferredModes = useMemo(() => {
    if (!data?.grouped) return {};
    const modes: Record<string, ModuleMode> = {};
    for (const mod of MODULES) {
      modes[mod.key] = inferMode(data.grouped[mod.category]);
    }
    return modes;
  }, [data]);

  const currentModes = useMemo(() => {
    const result: Record<string, ModuleMode> = {};
    for (const mod of MODULES) {
      result[mod.key] = moduleModes[mod.key] ?? inferredModes[mod.key] ?? GLOBAL_DEFAULT_MODE;
    }
    return result;
  }, [inferredModes, moduleModes]);

  const handleModeChange = useCallback((key: string, mode: ModuleMode) => {
    setModuleModes((prev) => ({ ...prev, [key]: mode }));
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

  const handleToggleSwitch = async (key: string, value: boolean) => {
    try {
      const payload: Record<string, unknown> = {};
      if (key === "owasp") {
        setOwaspEnabled(value);
        payload.owasp_enabled = value;
      } else if (key === "cve") {
        setCveEnabled(value);
        payload.cve_enabled = value;
      } else if (key === "bot") {
        setBotEnabled(value);
        payload.bot_protection_enabled = value;
      }
      await updateSite.execute({ id: site.id, data: payload });
      toast.success(t("common.saveSuccess"));
    } catch {
      toast.error(t("common.operationFailed"));
    }
  };

  const handleSaveModules = async () => {
    if (!data?.grouped) return;

    const updates: { id: string; enabled: boolean; action: string; sensitivity: string }[] = [];
    for (const mod of MODULES) {
      const rules = data.grouped[mod.category];
      if (!rules || rules.length === 0) continue;
      const mode = currentModes[mod.key];
      const override = modeToOverride(mode);
      for (const rule of rules) {
        updates.push({ id: rule.id, enabled: override.enabled, action: override.action, sensitivity: override.sensitivity });
      }
    }

    if (updates.length === 0) return;

    try {
      await batchUpdate({ rules: updates });
      toast.success(t("attacks.saveSuccess"));
      setHasChanges(false);
      mutate();
    } catch (err) {
      toast.error(t("attacks.saveFailed", { message: err instanceof Error ? err.message : String(err) }));
    }
  };

  return (
    <div className="space-y-4">
      {/* 全局防护开关 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("sites.detail.protectionSwitches")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">OWASP {t("sites.detail.protection")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.owaspDesc")}</p>
            </div>
            <Switch checked={owaspEnabled} onCheckedChange={(v) => handleToggleSwitch("owasp", v)} />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">CVE {t("sites.detail.protection")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.cveDesc")}</p>
            </div>
            <Switch checked={cveEnabled} onCheckedChange={(v) => handleToggleSwitch("cve", v)} />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">Bot {t("sites.detail.protection")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.botDesc")}</p>
            </div>
            <Switch checked={botEnabled} onCheckedChange={(v) => handleToggleSwitch("bot", v)} />
          </div>
        </CardContent>
      </Card>

      {/* OWASP 模块详细配置 */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t("attacks.title")}</CardTitle>
            <div className="flex items-center gap-2">
              <select
                value={batchMode}
                onChange={(e) => setBatchMode(e.target.value as ModuleMode)}
                className="h-7 rounded-md border border-input bg-background px-2 text-xs outline-none focus:ring-2 focus:ring-ring"
              >
                {MODE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{t(opt.labelKey)}</option>
                ))}
              </select>
              <Button variant="outline" size="sm" className="h-7 text-xs" onClick={handleBatchApply}>
                <IconCopy className="mr-1 h-3 w-3" />
                {t("attacks.apply")}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border overflow-hidden">
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
                    </div>
                    <Skeleton className="h-6 w-64" />
                  </div>
                ))
              ) : (
                MODULES.map((mod) => {
                  const mode = currentModes[mod.key];
                  const rules = data?.grouped?.[mod.category];
                  const hasRules = rules && rules.length > 0;
                  const isDisabled = !hasRules || isSaving;
                  const ModIcon = mod.icon;
                  const modeLabel = MODE_OPTIONS.find((o) => o.value === mode)?.labelKey || "";

                  return (
                    <div
                      key={mod.key}
                      className={cn(
                        "flex items-center justify-between px-4 py-3 transition-colors",
                        moduleModes[mod.key] !== undefined ? "bg-primary/[0.02]" : ""
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

          {hasChanges && (
            <div className="flex justify-end mt-4">
              <Button onClick={handleSaveModules} disabled={isSaving}>
                {isSaving ? (
                  <>
                    <IconRefresh className="mr-1 h-4 w-4 animate-spin" />
                    {t("common.saving")}
                  </>
                ) : (
                  <>
                    <IconDeviceFloppy className="mr-1 h-4 w-4" />
                    {t("common.save")}
                  </>
                )}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
