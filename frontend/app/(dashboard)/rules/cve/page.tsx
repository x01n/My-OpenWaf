"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { IconRefresh, IconRotateClockwise } from "@tabler/icons-react"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { ActionBadge } from "@/components/action-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { cveApi } from "@/lib/api"
import {
  useCveRules,
  useAllSites,
  useCveStats,
  usePolicies,
} from "@/hooks/use-api"
import type { CVERuleItem, CVEScopeType } from "@/lib/types"
import { categoryLabel, severityLabel } from "@/lib/attack-category"

const ACTIONS = [
  "intercept",
  "observe",
  "drop",
  "challenge",
  "rate_limit",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
]
const SCOPE_GLOBAL = "global"

export default function CVERulesPage() {
  const { t } = useTranslation()
  const [scope, setScope] = useState<CVEScopeType>(SCOPE_GLOBAL)
  const [policyID, setPolicyID] = useState<number | undefined>(undefined)
  const [siteID, setSiteID] = useState<number | undefined>(undefined)
  const { data: policies = [] } = usePolicies()
  const { data: sitesData } = useAllSites()
  const sites = useMemo(() => sitesData?.items ?? [], [sitesData?.items])
  const effectivePolicyID = policyID ?? policies[0]?.id
  const effectiveSiteID = siteID ?? sites[0]?.id

  const params = useMemo(() => {
    const base: Record<string, unknown> = { scope }
    if (scope === "policy") base.policy_id = effectivePolicyID
    if (scope === "site") base.site_id = effectiveSiteID
    return base
  }, [effectivePolicyID, effectiveSiteID, scope])
  const enabled =
    scope === "global" ||
    (scope === "policy" && effectivePolicyID) ||
    (scope === "site" && effectiveSiteID)
  const { data, isLoading, error, mutate } = useCveRules(
    enabled ? params : null
  )
  const { data: stats, mutate: mutateStats } = useCveStats(
    enabled ? params : null
  )
  const rules = data?.items ?? []

  const refresh = async () => {
    await Promise.all([mutate(), mutateStats()])
  }

  const scopedPatch = () => ({
    scope,
    policy_id: scope === "policy" ? effectivePolicyID : undefined,
    site_id: scope === "site" ? effectiveSiteID : undefined,
  })

  const updateRule = async (
    rule: CVERuleItem,
    patch: Record<string, unknown>
  ) => {
    try {
      await cveApi.patch(rule.id, { ...scopedPatch(), ...patch })
      await refresh()
      toast.success(t("common.updateSuccess"))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const resetRule = async (rule: CVERuleItem) => {
    try {
      await cveApi.reset(rule.id, scopedPatch())
      await refresh()
      toast.success(t("cveRules.resetSuccess", { defaultValue: "已恢复继承" }))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const columns = [
    {
      key: "enabled",
      title: t("common.enabled"),
      width: "80px",
      render: (row: CVERuleItem) => (
        <Switch
          checked={row.effective?.enabled ?? row.enabled}
          onCheckedChange={(v) => updateRule(row, { enabled: v })}
        />
      ),
    },
    {
      key: "rule",
      title: t("cveRules.rule", { defaultValue: "规则" }),
      render: (row: CVERuleItem) => (
        <div className="space-y-1">
          <div className="flex items-center gap-2 font-mono text-xs">
            {row.cve_id || row.cve || `#${row.id}`}
            {row.overridden && (
              <Badge variant="outline">
                {t("cveRules.overridden", { defaultValue: "已覆盖" })}
              </Badge>
            )}
            {row.inherited_from && (
              <Badge variant="secondary">{row.inherited_from}</Badge>
            )}
          </div>
          <div className="font-medium">
            {row.name || row.description || row.cve_id || row.cve}
          </div>
          <p className="line-clamp-2 text-xs text-muted-foreground">
            {row.description}
          </p>
        </div>
      ),
    },
    {
      key: "category",
      title: t("common.category", { defaultValue: "分类" }),
      width: "120px",
      render: (row: CVERuleItem) => categoryLabel(row.category),
    },
    {
      key: "severity",
      title: t("cveRules.severity", { defaultValue: "严重度" }),
      width: "100px",
      render: (row: CVERuleItem) => severityLabel(row.severity),
    },
    {
      key: "action",
      title: t("rules.action"),
      width: "170px",
      render: (row: CVERuleItem) => (
        <Select
          value={row.effective?.action || row.action || "intercept"}
          onValueChange={(v) => updateRule(row, { action: v })}
        >
          <SelectTrigger className="h-8">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ACTIONS.map((action) => (
              <SelectItem key={action} value={action}>
                <ActionBadge action={action} />
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ),
    },
    {
      key: "ops",
      title: t("common.action"),
      width: "120px",
      render: (row: CVERuleItem) => (
        <Button
          size="sm"
          variant="ghost"
          disabled={!row.overridden}
          onClick={() => resetRule(row)}
        >
          <IconRotateClockwise className="h-4 w-4" />
        </Button>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("cveRules.title", { defaultValue: "CVE 规则" })}
        description={t("cveRules.description", {
          defaultValue: "按全局、策略或站点作用域管理 CVE 规则覆盖。",
        })}
        actions={
          <Button variant="outline" onClick={refresh}>
            <IconRefresh className="mr-1 h-4 w-4" />
            {t("common.refresh")}
          </Button>
        }
      />
      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-wrap items-end gap-3 rounded-lg border bg-card p-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium">
            {t("cveRules.scope", { defaultValue: "作用域" })}
          </label>
          <Select
            value={scope}
            onValueChange={(v) => setScope(v as CVEScopeType)}
          >
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="global">
                {t("cveRules.scopeGlobal", { defaultValue: "全局" })}
              </SelectItem>
              <SelectItem value="policy">
                {t("cveRules.scopePolicy", { defaultValue: "策略" })}
              </SelectItem>
              <SelectItem value="site">
                {t("cveRules.scopeSite", { defaultValue: "站点" })}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
        {scope === "policy" && (
          <Select
            value={effectivePolicyID ? String(effectivePolicyID) : ""}
            onValueChange={(v) => setPolicyID(Number(v))}
          >
            <SelectTrigger className="w-64">
              <SelectValue
                placeholder={t("rules.policyPlaceholder", {
                  defaultValue: "选择策略",
                })}
              />
            </SelectTrigger>
            <SelectContent>
              {policies.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                  {p.is_default
                    ? ` (${t("common.default", { defaultValue: "默认" })})`
                    : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {scope === "site" && (
          <Select
            value={effectiveSiteID ? String(effectiveSiteID) : ""}
            onValueChange={(v) => setSiteID(Number(v))}
          >
            <SelectTrigger className="w-64">
              <SelectValue placeholder={t("nav.sites")} />
            </SelectTrigger>
            <SelectContent>
              {sites.map((s) => (
                <SelectItem key={s.id} value={String(s.id)}>
                  {s.host}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {stats && (
          <Badge variant="secondary" className="mb-2">
            {stats.enabled_count}/{stats.total} enabled
          </Badge>
        )}
      </div>
      <DataTable
        columns={columns}
        data={rules}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("cveRules.empty", { defaultValue: "暂无 CVE 规则" })}
      />
    </div>
  )
}
