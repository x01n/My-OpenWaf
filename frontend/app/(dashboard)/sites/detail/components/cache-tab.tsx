"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import {
  IconAlertTriangle,
  IconChartLine,
  IconDeviceFloppy,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { useSiteMutation } from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import {
  parseSiteCacheRules,
  serializeSiteCacheRules,
  SITE_CACHE_LIMITS,
  SITE_CACHE_RULE_TYPES,
  siteCacheKeyPreview,
  validateSiteCacheConfig,
} from "@/lib/site-cache"
import type { Site, SiteCacheRule } from "@/lib/types"

interface CacheTabProps {
  site: Site
}

function newCacheRule(defaultTtl: number): SiteCacheRule {
  return {
    type: "prefix",
    value: "/assets/",
    ttl: defaultTtl > 0 ? 0 : 60,
    case_insensitive: false,
    ignore_query: false,
    disabled: false,
    note: "",
    stale_if_error_seconds: 0,
  }
}

/** Configure a site's bounded, shared response-cache allowlist. */
export function CacheTab({ site }: CacheTabProps) {
  const { t } = useTranslation()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const updateSite = useSiteMutation()
  const parsedConfig = useMemo(
    () => parseSiteCacheRules(site.cache_rules),
    [site.cache_rules]
  )
  const [draft, setDraft] = useState<{
    cacheEnabled: boolean
    defaultTtl: number
    rules: SiteCacheRule[]
    parseError: string | null
  } | null>(null)
  const [previewTarget, setPreviewTarget] = useState("/assets/app.js?version=1")
  const [saving, setSaving] = useState(false)

  const cacheEnabled = draft?.cacheEnabled ?? site.cache_enabled
  const defaultTtl = draft?.defaultTtl ?? site.cache_default_ttl
  const rules = draft?.rules ?? parsedConfig.rules
  const parseError = draft ? draft.parseError : parsedConfig.error

  const updateDraft = (patch: Partial<NonNullable<typeof draft>>) => {
    if (!canManage) return
    setDraft((current) => ({
      cacheEnabled: current?.cacheEnabled ?? site.cache_enabled,
      defaultTtl: current?.defaultTtl ?? site.cache_default_ttl,
      rules: current?.rules ?? parsedConfig.rules,
      parseError: current ? current.parseError : parsedConfig.error,
      ...patch,
    }))
  }

  const updateRule = (index: number, patch: Partial<SiteCacheRule>) => {
    updateDraft({
      rules: rules.map((rule, ruleIndex) =>
        ruleIndex === index ? { ...rule, ...patch } : rule
      ),
    })
  }

  const handleSave = async () => {
    if (!canManage) return
    const validationError = validateSiteCacheConfig(
      cacheEnabled,
      defaultTtl,
      rules
    )
    if (parseError || validationError) {
      toast.error(t(parseError || validationError!))
      return
    }
    setSaving(true)
    try {
      await updateSite.execute({
        id: site.id,
        data: {
          cache_enabled: cacheEnabled,
          cache_default_ttl: defaultTtl,
          cache_rules: serializeSiteCacheRules(rules),
        },
      })
      toast.success(t("common.saveSuccess"))
      setDraft(null)
    } catch (error: unknown) {
      toast.error(
        error instanceof Error ? error.message : t("common.operationFailed")
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="min-w-0 space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconChartLine className="h-5 w-5 text-primary" />
            {t("sites.detail.cacheMetricsTitle")}
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            {t("sites.detail.cacheMetricsHint")}
          </p>
        </CardHeader>
        <CardContent>
          <Alert>
            <IconChartLine />
            <AlertTitle>{t("sites.detail.cacheMetricsScopeTitle")}</AlertTitle>
            <AlertDescription>
              {t("sites.detail.cacheMetricsScopeDesc")}
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      {!authLoading && !canManage && (
        <Alert>
          <IconAlertTriangle />
          <AlertDescription>{t("common.readOnlyHint")}</AlertDescription>
        </Alert>
      )}
      <fieldset
        disabled={!canManage}
        className="m-0 min-w-0 space-y-4 border-0 p-0"
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">
              {t("sites.detail.cacheConfig")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex min-w-0 flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
              <div className="min-w-0 space-y-0.5">
                <Label className="text-sm font-medium">
                  {t("sites.detail.enableCache")}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.cacheDesc")}
                </p>
              </div>
              <Switch
                checked={cacheEnabled}
                onCheckedChange={(checked) =>
                  updateDraft({ cacheEnabled: checked })
                }
                disabled={saving}
              />
            </div>

            <div className="grid min-w-0 gap-4 sm:grid-cols-2">
              <div className="min-w-0 space-y-2">
                <Label htmlFor="cache-default-ttl" className="text-sm">
                  {t("sites.detail.defaultTtl")}
                </Label>
                <div className="flex min-w-0 items-center gap-2">
                  <Input
                    id="cache-default-ttl"
                    type="number"
                    min={0}
                    max={SITE_CACHE_LIMITS.maxTtlSeconds}
                    className="min-w-0 font-mono"
                    value={defaultTtl}
                    onChange={(event) =>
                      updateDraft({
                        defaultTtl: Math.max(
                          0,
                          Number(event.target.value) || 0
                        ),
                      })
                    }
                  />
                  <span className="shrink-0 text-sm text-muted-foreground">
                    {t("common.seconds")}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.cacheDefaultTtlHint")}
                </p>
              </div>

              <div className="min-w-0 space-y-2">
                <Label htmlFor="cache-preview-target" className="text-sm">
                  {t("sites.detail.cacheKeyPreviewTarget")}
                </Label>
                <Input
                  id="cache-preview-target"
                  className="min-w-0 font-mono text-xs"
                  value={previewTarget}
                  onChange={(event) => setPreviewTarget(event.target.value)}
                  placeholder="/assets/app.js?version=1"
                />
                <p className="text-xs text-muted-foreground">
                  {t("sites.detail.cacheKeyPreviewHint")}
                </p>
              </div>
            </div>

            <Alert>
              <IconAlertTriangle />
              <AlertTitle>{t("sites.detail.cacheSafetyTitle")}</AlertTitle>
              <AlertDescription>
                {t("sites.detail.cacheSafetyDesc")}
              </AlertDescription>
            </Alert>

            {parseError && (
              <Alert variant="destructive">
                <IconAlertTriangle />
                <AlertTitle>
                  {t("sites.detail.cacheRulesInvalidTitle")}
                </AlertTitle>
                <AlertDescription className="space-y-3">
                  <p>{t(parseError)}</p>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      updateDraft({ rules: [], parseError: null })
                    }}
                  >
                    {t("sites.detail.cacheResetInvalidRules")}
                  </Button>
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="gap-3 pb-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <CardTitle className="text-base">
                {t("sites.detail.cacheRules")}
              </CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">
                {t("sites.detail.cacheRulesHint")}
              </p>
            </div>
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="shrink-0"
              disabled={
                rules.length >= SITE_CACHE_LIMITS.maxRules || !!parseError
              }
              onClick={() =>
                updateDraft({ rules: [...rules, newCacheRule(defaultTtl)] })
              }
            >
              <IconPlus className="size-4" />
              {t("sites.detail.cacheAddRule")}
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {rules.length === 0 && !parseError && (
              <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
                {t("sites.detail.cacheNoRules")}
              </div>
            )}

            {rules.map((rule, index) => (
              <div
                key={`${index}-${rule.type}`}
                className="min-w-0 space-y-4 rounded-lg border p-3 sm:p-4"
              >
                <div className="flex min-w-0 flex-wrap items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-2">
                    <Switch
                      checked={!rule.disabled}
                      onCheckedChange={(checked) =>
                        updateRule(index, { disabled: !checked })
                      }
                    />
                    <span className="truncate text-sm font-medium">
                      {rule.note?.trim() ||
                        t("sites.detail.cacheRuleNumber", {
                          number: index + 1,
                        })}
                    </span>
                  </div>
                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    className="shrink-0 text-muted-foreground hover:text-destructive"
                    aria-label={t("common.delete")}
                    onClick={() =>
                      updateDraft({
                        rules: rules.filter(
                          (_, ruleIndex) => ruleIndex !== index
                        ),
                      })
                    }
                  >
                    <IconTrash />
                  </Button>
                </div>

                <div className="grid min-w-0 gap-3 sm:grid-cols-2">
                  <div className="min-w-0 space-y-1.5">
                    <Label>{t("sites.detail.cacheRuleType")}</Label>
                    <Select
                      value={rule.type}
                      onValueChange={(value) =>
                        updateRule(index, {
                          type: value as SiteCacheRule["type"],
                        })
                      }
                    >
                      <SelectTrigger className="w-full min-w-0">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SITE_CACHE_RULE_TYPES.map((type) => (
                          <SelectItem key={type} value={type}>
                            {t(`sites.detail.cacheRuleTypes.${type}`)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="min-w-0 space-y-1.5">
                    <Label htmlFor={`cache-rule-value-${index}`}>
                      {t("sites.detail.cacheRuleValue")}
                    </Label>
                    <Input
                      id={`cache-rule-value-${index}`}
                      className="min-w-0 font-mono text-xs"
                      value={rule.value}
                      onChange={(event) =>
                        updateRule(index, { value: event.target.value })
                      }
                    />
                  </div>

                  <div className="min-w-0 space-y-1.5">
                    <Label htmlFor={`cache-rule-ttl-${index}`}>
                      {t("sites.detail.cacheRuleTtl")}
                    </Label>
                    <Input
                      id={`cache-rule-ttl-${index}`}
                      type="number"
                      min={0}
                      max={SITE_CACHE_LIMITS.maxTtlSeconds}
                      className="min-w-0 font-mono"
                      value={rule.ttl}
                      onChange={(event) =>
                        updateRule(index, {
                          ttl: Math.max(0, Number(event.target.value) || 0),
                        })
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      {t("sites.detail.cacheRuleTtlHint")}
                    </p>
                  </div>

                  <div className="min-w-0 space-y-1.5">
                    <Label htmlFor={`cache-rule-stale-${index}`}>
                      {t("sites.detail.cacheRuleStale")}
                    </Label>
                    <Input
                      id={`cache-rule-stale-${index}`}
                      type="number"
                      min={0}
                      max={SITE_CACHE_LIMITS.maxStaleIfErrorSeconds}
                      className="min-w-0 font-mono"
                      value={rule.stale_if_error_seconds ?? 0}
                      onChange={(event) =>
                        updateRule(index, {
                          stale_if_error_seconds: Math.max(
                            0,
                            Number(event.target.value) || 0
                          ),
                        })
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      {t("sites.detail.cacheRuleStaleHint")}
                    </p>
                  </div>

                  <div className="min-w-0 space-y-1.5 sm:col-span-2">
                    <Label htmlFor={`cache-rule-note-${index}`}>
                      {t("sites.detail.cacheRuleNote")}
                    </Label>
                    <Input
                      id={`cache-rule-note-${index}`}
                      className="min-w-0"
                      value={rule.note ?? ""}
                      onChange={(event) =>
                        updateRule(index, { note: event.target.value })
                      }
                      placeholder={t("sites.detail.cacheRuleNotePlaceholder")}
                    />
                  </div>
                </div>

                <div className="grid min-w-0 gap-3 sm:grid-cols-2">
                  <div className="flex min-w-0 items-start justify-between gap-3 rounded-md bg-muted/40 p-3">
                    <div className="min-w-0">
                      <Label>{t("sites.detail.cacheCaseInsensitive")}</Label>
                      <p className="text-xs text-muted-foreground">
                        {t("sites.detail.cacheCaseInsensitiveHint")}
                      </p>
                    </div>
                    <Switch
                      className="shrink-0"
                      checked={Boolean(rule.case_insensitive)}
                      onCheckedChange={(checked) =>
                        updateRule(index, { case_insensitive: checked })
                      }
                    />
                  </div>

                  <div className="flex min-w-0 items-start justify-between gap-3 rounded-md bg-muted/40 p-3">
                    <div className="min-w-0">
                      <Label>{t("sites.detail.cacheIgnoreQuery")}</Label>
                      <p className="text-xs text-muted-foreground">
                        {t("sites.detail.cacheIgnoreQueryHint")}
                      </p>
                    </div>
                    <Switch
                      className="shrink-0"
                      checked={Boolean(rule.ignore_query)}
                      onCheckedChange={(checked) =>
                        updateRule(index, { ignore_query: checked })
                      }
                    />
                  </div>
                </div>

                {rule.ignore_query && (
                  <Alert variant="destructive">
                    <IconAlertTriangle />
                    <AlertDescription>
                      {t("sites.detail.cacheIgnoreQueryWarning")}
                    </AlertDescription>
                  </Alert>
                )}

                <div className="min-w-0 rounded-md bg-muted/50 p-3">
                  <p className="text-xs font-medium">
                    {t("sites.detail.cacheEffectiveKey")}
                  </p>
                  <code className="mt-1 block min-w-0 text-xs break-all text-muted-foreground">
                    {siteCacheKeyPreview(rule, previewTarget)}
                  </code>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button onClick={handleSave} disabled={saving || !!parseError}>
            <IconDeviceFloppy className="size-4" />
            {saving ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </fieldset>
    </div>
  )
}
