"use client";

import { useState, useMemo, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { toast } from "sonner";
import {
  IconRefresh,
  IconInfoCircle,
  IconFileSearch,
  IconDeviceFloppy,
} from "@tabler/icons-react";
import { useSiteRecordedResources, useSiteMutation } from "@/hooks/use-api";
import { ResourcePathTree } from "@/components/ui/resource-path-tree";
import { cn } from "@/lib/utils";
import type { Site } from "@/lib/types";

/**
 * 三态取值：
 * - "inherit" 继承全局（保存为 null）
 * - "on"      站点强制开启（保存为 true）
 * - "off"     站点强制关闭（保存为 false）
 */
type TriState = "inherit" | "on" | "off";

/**
 * 将站点级 *bool 覆盖字段（可能为 true/false/null/undefined）归一化为三态取值。
 *
 * @param value 站点字段原始值
 * @returns 三态取值
 */
function toTriState(value: boolean | null | undefined): TriState {
  if (value === true) return "on";
  if (value === false) return "off";
  return "inherit";
}

/**
 * 将三态取值转换回站点级 *bool 覆盖字段的提交值。
 *
 * @param value 三态取值
 * @returns null（继承）/ true / false
 */
function fromTriState(value: TriState): boolean | null {
  if (value === "on") return true;
  if (value === "off") return false;
  return null;
}

/**
 * 解析站点级 JS 路径 JSON 数组字符串。
 *
 * @param raw JSON 数组字符串
 * @returns 路径字符串数组
 */
function parseJSPaths(raw: string | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.filter((p): p is string => typeof p === "string");
    }
  } catch {
    // 忽略非法 JSON，返回空数组
  }
  return [];
}

interface TriStateSelectProps {
  value: TriState;
  onChange: (value: TriState) => void;
  idPrefix: string;
}

/**
 * 三态覆盖选择器：继承全局 / 强制开启 / 强制关闭。
 */
function TriStateSelect({ value, onChange, idPrefix }: TriStateSelectProps) {
  const { t } = useTranslation();
  const options: { value: TriState; labelKey: string }[] = [
    { value: "inherit", labelKey: "sites.detail.dynOverride.inherit" },
    { value: "on", labelKey: "sites.detail.dynOverride.on" },
    { value: "off", labelKey: "sites.detail.dynOverride.off" },
  ];
  return (
    <div className="inline-flex items-center gap-1 rounded-md border p-0.5">
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          id={`${idPrefix}-${opt.value}`}
          onClick={() => onChange(opt.value)}
          className={cn(
            "rounded px-2.5 py-1 text-xs transition-colors",
            value === opt.value
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:bg-muted"
          )}
        >
          {t(opt.labelKey)}
        </button>
      ))}
    </div>
  );
}

interface DynamicProtectionTabProps {
  site: Site;
}

/**
 * 站点详情页 - 动态防护站点级覆盖配置。
 *
 * 全局动态防护在人机验证配置页维护；本 Tab 仅配置当前站点对全局动态防护的覆盖。
 * 每个可覆盖开关采用三态（继承全局 / 强制开启 / 强制关闭），nil 语义为继承全局。
 */
export function DynamicProtectionTab({ site }: DynamicProtectionTabProps) {
  const { t } = useTranslation();
  const { data: recordedResourcesData } = useSiteRecordedResources(site.id);
  const updateSite = useSiteMutation();

  const recordedResources = useMemo(() => recordedResourcesData || [], [recordedResourcesData]);

  // 站点级三态覆盖状态
  const [master, setMaster] = useState<TriState>(() => toTriState(site.dynamic_protection_enabled));
  const [html, setHtml] = useState<TriState>(() => toTriState(site.dynamic_html_enabled));
  const [js, setJs] = useState<TriState>(() => toTriState(site.dynamic_js_enabled));
  const [jsMode, setJsMode] = useState<"all" | "paths">(
    () => (site.dynamic_js_mode === "paths" ? "paths" : "all")
  );
  const [jsPaths, setJsPaths] = useState<string[]>(() => parseJSPaths(site.dynamic_js_paths));
  const [ttl, setTtl] = useState<string>(() =>
    site.dynamic_decrypt_cache_ttl == null ? "" : String(site.dynamic_decrypt_cache_ttl)
  );
  const [dirty, setDirty] = useState(false);

  const markDirty = useCallback(() => setDirty(true), []);

  const handleJsPathSelect = useCallback(
    (path: string, checked: boolean) => {
      setJsPaths((prev) => {
        if (checked) {
          return prev.includes(path) ? prev : [...prev, path];
        }
        return prev.filter((p) => p !== path);
      });
      markDirty();
    },
    [markDirty]
  );

  const handleSave = useCallback(async () => {
    const trimmedTtl = ttl.trim();
    const ttlValue = trimmedTtl === "" ? null : Math.max(0, Number(trimmedTtl) || 0);
    const payload: Partial<Site> = {
      dynamic_protection_enabled: fromTriState(master),
      dynamic_html_enabled: fromTriState(html),
      dynamic_js_enabled: fromTriState(js),
      dynamic_js_mode: js === "on" ? jsMode : "",
      // 后端将数组序列化为 JSON 字符串存储；仅在 paths 模式下提交路径
      dynamic_js_paths: (js === "on" && jsMode === "paths" ? jsPaths : []) as unknown as string,
      dynamic_decrypt_cache_ttl: ttlValue,
    };
    try {
      await updateSite.execute({ id: site.id, data: payload });
      toast.success(t("common.saveSuccess"));
      setDirty(false);
    } catch {
      toast.error(t("common.operationFailed"));
    }
  }, [master, html, js, jsMode, jsPaths, ttl, site.id, updateSite, t]);

  const childActive = master !== "off";

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("sites.detail.dynOverride.title")}</CardTitle>
          <p className="text-xs text-muted-foreground">{t("sites.detail.dynOverride.desc")}</p>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 站点动态防护总开关 */}
          <div className="flex items-start justify-between gap-4 rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label>{t("sites.detail.dynOverride.master")}</Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.dynOverride.masterDesc")}
              </p>
            </div>
            <TriStateSelect
              value={master}
              idPrefix="dp-master"
              onChange={(v) => {
                setMaster(v);
                markDirty();
              }}
            />
          </div>

          {/* 覆盖生效提示 */}
          {master === "off" && (
            <div className="flex items-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-600 dark:text-amber-400">
              <IconInfoCircle className="h-4 w-4 shrink-0" />
              {t("sites.detail.dynOverride.masterOffHint")}
            </div>
          )}
          {master === "inherit" && (
            <div className="flex items-center gap-2 rounded-md border bg-muted/50 p-2.5 text-xs text-muted-foreground">
              <IconInfoCircle className="h-4 w-4 shrink-0" />
              {t("sites.detail.dynOverride.inheritHint")}
            </div>
          )}

          {/* 子项覆盖 */}
          <div
            className={cn(
              "space-y-4 rounded-lg border p-4 transition-all",
              childActive ? "opacity-100" : "pointer-events-none opacity-40"
            )}
          >
            {/* HTML 全站加密覆盖 */}
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-0.5">
                <Label className="font-normal">{t("sites.detail.dynOverride.html")}</Label>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.dynOverride.htmlDesc")}
                </p>
              </div>
              <TriStateSelect
                value={html}
                idPrefix="dp-html"
                onChange={(v) => {
                  setHtml(v);
                  markDirty();
                }}
              />
            </div>

            {/* JS 加密保护覆盖 */}
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-0.5">
                <Label className="font-normal">{t("sites.detail.dynOverride.js")}</Label>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.dynOverride.jsDesc")}
                </p>
              </div>
              <TriStateSelect
                value={js}
                idPrefix="dp-js"
                onChange={(v) => {
                  setJs(v);
                  markDirty();
                }}
              />
            </div>

            {/* JS 保护范围（仅在 JS 强制开启时显示） */}
            {js === "on" && (
              <div className="ml-1 space-y-2 border-l pl-4">
                <Label className="text-xs font-medium">
                  {t("sites.detail.dynOverride.jsMode")}
                </Label>
                <RadioGroup
                  value={jsMode}
                  onValueChange={(v) => {
                    setJsMode(v as "all" | "paths");
                    markDirty();
                  }}
                  className="flex flex-col gap-1.5"
                >
                  <div className="flex items-center gap-2">
                    <RadioGroupItem value="all" id="dp-js-mode-all" />
                    <Label htmlFor="dp-js-mode-all" className="cursor-pointer text-xs font-normal">
                      {t("sites.detail.dynOverride.jsModeAll")}
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <RadioGroupItem value="paths" id="dp-js-mode-paths" />
                    <Label htmlFor="dp-js-mode-paths" className="cursor-pointer text-xs font-normal">
                      {t("sites.detail.dynOverride.jsModePaths")}
                    </Label>
                  </div>
                </RadioGroup>

                {jsMode === "paths" && (
                  <div className="space-y-1 pt-1">
                    <Label className="text-xs font-medium">
                      {t("sites.detail.dynOverride.jsPaths")}
                    </Label>
                    {recordedResources.length > 0 ? (
                      <ResourcePathTree
                        resources={recordedResources}
                        selectedPaths={jsPaths}
                        onSelect={handleJsPathSelect}
                      />
                    ) : (
                      <div className="flex items-center gap-2 rounded-md border bg-muted/50 p-3 text-xs text-muted-foreground">
                        <IconFileSearch className="h-4 w-4" />
                        {t("sites.detail.dynOverride.noResources")}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* 解密缓存时间覆盖 */}
            <div className="space-y-1">
              <Label className="text-xs font-medium">{t("sites.detail.dynOverride.ttl")}</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={0}
                  className="w-40 text-xs"
                  placeholder={t("sites.detail.dynOverride.ttlPlaceholder")}
                  value={ttl}
                  onChange={(e) => {
                    setTtl(e.target.value);
                    markDirty();
                  }}
                />
                <span className="text-xs text-muted-foreground">
                  {t("sites.detail.dynOverride.ttlUnit")}
                </span>
              </div>
              <p className="text-[10px] text-muted-foreground">
                {t("sites.detail.dynOverride.ttlDesc")}
              </p>
            </div>
          </div>
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
