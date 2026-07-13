"use client";

import { useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { toast } from "sonner";
import {
  IconRefresh,
  IconInfoCircle,
  IconDeviceFloppy,
} from "@tabler/icons-react";
import { useSiteMutation } from "@/hooks/use-api";
import { CCRulesEditor, type CCRule } from "@/components/cc-rules-editor";
import type { Site } from "@/lib/types";

/**
 * 站点级 CC 覆盖三态：
 * - "inherit" 继承全局（cc_use_custom 保存为 null）
 * - "custom"  站点自定义规则（cc_use_custom 保存为 true）
 * - "off"     站点关闭 CC（cc_use_custom 保存为 false）
 */
type CCTriState = "inherit" | "custom" | "off";

/**
 * 将站点 cc_use_custom 字段归一化为三态取值。
 *
 * @param value 站点 cc_use_custom 原始值
 * @returns CC 三态取值
 */
function toCCTriState(value: boolean | null | undefined): CCTriState {
  if (value === true) return "custom";
  if (value === false) return "off";
  return "inherit";
}

/**
 * 将 CC 三态取值转换回 cc_use_custom 提交值。
 *
 * @param value CC 三态取值
 * @returns null（继承）/ true（自定义）/ false（关闭）
 */
function fromCCTriState(value: CCTriState): boolean | null {
  if (value === "custom") return true;
  if (value === "off") return false;
  return null;
}

/**
 * 解析站点 cc_rules（JSON 数组字符串）为规则数组。
 *
 * @param raw cc_rules 原始字符串
 * @returns CC 规则数组
 */
function parseCCRules(raw: string | undefined): CCRule[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed as CCRule[];
    }
  } catch {
    // 忽略非法 JSON，返回空数组
  }
  return [];
}

interface CCProtectionTabProps {
  site: Site;
}

/**
 * 站点详情页 - 站点级 CC 防护覆盖配置。
 *
 * 全局 CC 防护在 CC 防护页维护；本 Tab 仅配置当前站点对全局 CC 防护的覆盖。
 * 采用三态：继承全局 / 站点自定义规则 / 站点关闭 CC。cc_use_custom 为 null 时表示继承全局。
 */
export function CCProtectionTab({ site }: CCProtectionTabProps) {
  const { t } = useTranslation();
  const updateSite = useSiteMutation();

  const [mode, setMode] = useState<CCTriState>(() => toCCTriState(site.cc_use_custom));
  const [rules, setRules] = useState<CCRule[]>(() => parseCCRules(site.cc_rules));
  const [dirty, setDirty] = useState(false);

  const markDirty = useCallback(() => setDirty(true), []);

  const handleModeChange = useCallback(
    (value: string) => {
      setMode(value as CCTriState);
      markDirty();
    },
    [markDirty]
  );

  const handleRulesChange = useCallback(
    (next: CCRule[]) => {
      setRules(next);
      markDirty();
    },
    [markDirty]
  );

  const handleSave = useCallback(async () => {
    const payload: Partial<Site> = {
      cc_use_custom: fromCCTriState(mode),
      // 后端将数组序列化为 JSON 字符串存储；仅在自定义模式下提交规则
      cc_rules: (mode === "custom" ? rules : []) as unknown as string,
    };
    try {
      await updateSite.execute({ id: site.id, data: payload });
      toast.success(t("common.saveSuccess"));
      setDirty(false);
    } catch {
      toast.error(t("common.operationFailed"));
    }
  }, [mode, rules, site.id, updateSite, t]);

  const options = useMemo(
    () => [
      { value: "inherit", labelKey: "sites.detail.ccProtection.inherit" },
      { value: "custom", labelKey: "sites.detail.ccProtection.custom" },
      { value: "off", labelKey: "sites.detail.ccProtection.off" },
    ],
    []
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("sites.detail.ccProtection.title")}</CardTitle>
          <p className="text-xs text-muted-foreground">{t("sites.detail.ccProtection.desc")}</p>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 三态选择 */}
          <RadioGroup value={mode} onValueChange={handleModeChange} className="flex flex-col gap-2">
            {options.map((opt) => (
              <div key={opt.value} className="flex items-center gap-2">
                <RadioGroupItem value={opt.value} id={`cc-mode-${opt.value}`} />
                <Label htmlFor={`cc-mode-${opt.value}`} className="cursor-pointer text-sm font-normal">
                  {t(opt.labelKey)}
                </Label>
              </div>
            ))}
          </RadioGroup>

          {mode === "inherit" && (
            <div className="flex items-center gap-2 rounded-md border bg-muted/50 p-2.5 text-xs text-muted-foreground">
              <IconInfoCircle className="h-4 w-4 shrink-0" />
              {t("sites.detail.ccProtection.inheritHint")}
            </div>
          )}
          {mode === "off" && (
            <div className="flex items-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-600 dark:text-amber-400">
              <IconInfoCircle className="h-4 w-4 shrink-0" />
              {t("sites.detail.ccProtection.offHint")}
            </div>
          )}

          {/* 站点自定义规则编辑器 */}
          {mode === "custom" && (
            <div className="rounded-lg border p-4">
              <CCRulesEditor rules={rules} onChange={handleRulesChange} />
            </div>
          )}
        </CardContent>
      </Card>

      {dirty && (
        <div className="flex justify-end">
          <Button onClick={handleSave} disabled={updateSite.loading}>
            {updateSite.loading ? (
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
    </div>
  );
}
