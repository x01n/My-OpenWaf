"use client";

import { useState, useMemo, useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useOwaspRules, useOwaspBatchUpdate } from "@/hooks/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import {
  IconSettings,
  IconCopy,
  IconCheck,
  IconAlertTriangle,
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
import { cn } from "@/lib/utils";

// ============================================================
// 类型定义
// ============================================================

/**
 * OWASP 规则视图
 */
interface OwaspRule {
  id: string;
  category: string;
  name: string;
  description: string;
  enabled: boolean;
  action?: string;
  sensitivity?: string;
}

/**
 * OWASP 规则列表响应
 */
interface OwaspRulesResponse {
  items: OwaspRule[];
  grouped: Record<string, OwaspRule[]>;
  total: number;
}

/**
 * 模块防护模式
 */
type ModuleMode = "disabled" | "observe" | "balanced" | "strict";

/**
 * 配置模式：跟随全局 / 自定义
 */
type ConfigMode = "global" | "custom";

/**
 * 攻击模块定义
 */
interface AttackModule {
  key: string;
  nameKey: string;
  category: string;
  descKey: string;
  icon: React.ElementType;
}

// ============================================================
// 常量定义
// ============================================================

/** 模块列表 */
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

/** 模式选项 */
const MODE_OPTIONS: { value: ModuleMode; labelKey: string }[] = [
  { value: "disabled", labelKey: "attacks.disabled" },
  { value: "observe", labelKey: "attacks.observe" },
  { value: "balanced", labelKey: "attacks.balanced" },
  { value: "strict", labelKey: "attacks.strict" },
];

/** 全局默认模式（平衡防护） */
const GLOBAL_DEFAULT_MODE: ModuleMode = "balanced";

// ============================================================
// 辅助函数
// ============================================================

/**
 * 根据规则列表推断当前模块模式
 * @param rules - 该模块对应的所有规则
 * @returns 推断出的模式
 */
function inferMode(rules: OwaspRule[] | undefined): ModuleMode {
  if (!rules || rules.length === 0) return GLOBAL_DEFAULT_MODE;

  const allDisabled = rules.every((r) => !r.enabled);
  if (allDisabled) return "disabled";

  const allObserve = rules.every(
    (r) => r.enabled && r.action === "observe"
  );
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

/**
 * 将模式转换为规则覆盖配置
 * @param mode - 选择的模式
 * @returns 对应的后端字段值
 */
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

/**
 * 获取模式对应的状态标签变体
 * @param mode - 模块模式
 * @returns Badge 变体名称
 */
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
// 主组件
// ============================================================

export default function AttacksPage() {
  const { t } = useTranslation();
  const { data, isLoading, error, mutate } = useOwaspRules() as {
    data: OwaspRulesResponse | undefined;
    isLoading: boolean;
    error: unknown;
    mutate: () => void;
  };
  const { execute: batchUpdate, loading: isSaving } = useOwaspBatchUpdate();

  const [configMode, setConfigMode] = useState<ConfigMode>("custom");
  const [batchMode, setBatchMode] = useState<ModuleMode>("balanced");
  const [moduleModes, setModuleModes] = useState<Record<string, ModuleMode>>({});
  const [hasChanges, setHasChanges] = useState(false);
  const [initialized, setInitialized] = useState(false);

  // 数据加载后根据实际配置推断初始配置模式
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
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setConfigMode(hasCustom ? "custom" : "global");
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

  // 当前显示的模式（跟随全局时统一显示全局默认值）
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

  /**
   * 切换单个模块模式
   */
  const handleModeChange = useCallback((key: string, mode: ModuleMode) => {
    setModuleModes((prev) => ({ ...prev, [key]: mode }));
    setHasChanges(true);
  }, []);

  /**
   * 切换全局配置模式
   */
  const handleConfigModeChange = useCallback((mode: ConfigMode) => {
    setConfigMode(mode);
    setHasChanges(true);
  }, []);

  /**
   * 批量应用模式到所有模块
   */
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

  /**
   * 保存配置
   */
  const handleSave = useCallback(async () => {
    if (!data?.grouped) {
      toast.error(t("attacks.dataNotLoaded"));
      return;
    }

    if (configMode === "global") {
      toast.success(t("attacks.followGlobal"));
      setHasChanges(false);
      return;
    }

    const updates: {
      id: string;
      enabled: boolean;
      action: string;
      sensitivity: string;
    }[] = [];

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
    } catch (err) {
      toast.error(
        t("attacks.saveFailed", {
          message: err instanceof Error ? err.message : String(err),
        })
      );
    }
  }, [data, currentModes, configMode, batchUpdate, mutate, t]);

  /**
   * 取消修改，重置状态
   */
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
    toast.info(t("attacks.cancelled"));
  }, [data, t]);

  // 加载错误处理
  if (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return (
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">{t("attacks.title")}</h1>
            <p className="text-sm text-muted-foreground mt-1">{t("attacks.description")}</p>
          </div>
          <div className="flex items-center gap-2" />
        </div>
        <div className="flex h-40 items-center justify-center gap-2 rounded-lg border border-destructive/20 bg-destructive/5 text-destructive">
          <IconAlertTriangle className="h-5 w-5" />
          <span>
            {t("attacks.loadFailed", {
              message: errMsg || t("common.unknownError"),
            })}
          </span>
          <Button variant="outline" size="sm" onClick={() => mutate()}>
            <IconRefresh className="mr-1 h-4 w-4" />
            {t("common.retry")}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 页面标题 */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("attacks.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{t("attacks.description")}</p>
        </div>
        <div className="flex items-center gap-2" />
      </div>

      {/* 防护模式配置 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconSettings className="h-5 w-5 text-primary" />
            {t("attacks.protectionMode")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            {/* 配置模式切换 */}
            <RadioGroup
              value={configMode}
              onValueChange={(v) => handleConfigModeChange(v as ConfigMode)}
              className="flex items-center gap-0 rounded-lg border p-1"
            >
              <div className="flex items-center">
                <RadioGroupItem
                  value="global"
                  id="mode-global"
                  className="sr-only"
                />
                <Label
                  htmlFor="mode-global"
                  className={cn(
                    "cursor-pointer rounded-md px-4 py-1.5 text-sm font-medium transition-colors",
                    configMode === "global"
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  {t("attacks.followGlobalConfig")}
                </Label>
              </div>
              <div className="flex items-center">
                <RadioGroupItem
                  value="custom"
                  id="mode-custom"
                  className="sr-only"
                />
                <Label
                  htmlFor="mode-custom"
                  className={cn(
                    "cursor-pointer rounded-md px-4 py-1.5 text-sm font-medium transition-colors",
                    configMode === "custom"
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  {t("attacks.useCustomConfig")}
                </Label>
              </div>
            </RadioGroup>

            {/* 批量配置 */}
            {configMode === "custom" && (
              <div className="flex items-center gap-2 rounded-lg border bg-muted/30 p-2">
                <span className="text-sm text-muted-foreground">
                  {t("attacks.batchConfig")}
                </span>
                <select
                  value={batchMode}
                  onChange={(e) => setBatchMode(e.target.value as ModuleMode)}
                  className="h-8 rounded-md border border-input bg-background px-2 text-xs outline-none focus:ring-2 focus:ring-ring"
                >
                  {MODE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {t(opt.labelKey)}
                    </option>
                  ))}
                </select>
                <Button
                  variant="default"
                  size="sm"
                  onClick={handleBatchApply}
                  className="h-8"
                >
                  <IconCopy className="mr-1 h-3.5 w-3.5" />
                  {t("attacks.apply")}
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 模块列表 */}
      <Card>
        <CardHeader className="border-b px-6 py-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t("attacks.moduleName")}</CardTitle>
            <Badge variant="secondary" className="text-xs">
              {t("common.total", { count: MODULES.length })}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="divide-y p-0">
          {isLoading ? (
            Array.from({ length: MODULES.length }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 px-6 py-4">
                <Skeleton className="h-10 w-10 rounded-lg" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-full" />
                </div>
                <Skeleton className="h-4 w-full max-w-[260px]" />
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
                    "flex flex-col gap-4 px-6 py-4 transition-colors sm:flex-row sm:items-center sm:justify-between",
                    hasChanges && configMode === "custom" && moduleModes[mod.key] !== undefined
                      ? "bg-primary/[0.02]"
                      : ""
                  )}
                >
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                      <ModIcon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{t(mod.nameKey)}</span>
                        {!hasRules && (
                          <span className="text-xs text-muted-foreground">
                            ({t("attacks.noRules")})
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {t(mod.descKey)}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <Badge
                      variant={getModeBadgeVariant(mode)}
                      className="shrink-0 text-xs"
                    >
                      {t(modeLabel)}
                    </Badge>
                    <div className="flex items-center gap-1 rounded-lg border bg-muted/30 p-1">
                      {MODE_OPTIONS.map((opt) => (
                        <button
                          key={opt.value}
                          type="button"
                          disabled={isDisabled}
                          onClick={() => handleModeChange(mod.key, opt.value)}
                          className={cn(
                            "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                            mode === opt.value
                              ? "bg-primary text-primary-foreground shadow-sm"
                              : "text-muted-foreground hover:bg-muted",
                            isDisabled && "cursor-not-allowed opacity-50"
                          )}
                        >
                          {t(opt.labelKey)}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </CardContent>

        {/* 底部操作栏 */}
        <div className="flex items-center justify-end gap-3 border-t px-6 py-4">
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={!hasChanges || isSaving || isLoading}
          >
            {t("common.cancel")}
          </Button>
          <Button
            onClick={handleSave}
            disabled={isLoading || isSaving}
          >
            {isSaving ? (
              <>
                <IconSettings className="mr-2 h-4 w-4 animate-spin" />
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
      </Card>
    </div>
  );
}
