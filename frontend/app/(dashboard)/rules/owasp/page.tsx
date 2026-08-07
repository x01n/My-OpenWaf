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
import { owaspApi } from "@/lib/api"
import { owaspCategoryLabel } from "@/lib/attack-category"
import {
  useDefaultPolicy,
  useOwaspRules,
  useOwaspStats,
  usePolicies,
} from "@/hooks/use-api"
import type { OWASPRuleItem } from "@/lib/types"

const FILTER_ALL = "__all__"
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
const SENSITIVITIES = ["low", "medium", "high", "very_high", "strict", "off"]

export default function OWASPRulesPage() {
  const { t } = useTranslation()
  const { data: policies = [] } = usePolicies()
  const { data: defaultPolicy } = useDefaultPolicy()
  const [policyId, setPolicyId] = useState<number | undefined>(undefined)
  const [category, setCategory] = useState("")
  const [query, setQuery] = useState("")

  const effectivePolicyId = policyId ?? defaultPolicy?.id

  const params = useMemo(
    () => ({
      policy_id: effectivePolicyId,
      page_size: 500,
      category: category || undefined,
      q: query.trim() || undefined,
    }),
    [category, effectivePolicyId, query]
  )
  const { data, isLoading, error, mutate } = useOwaspRules(
    effectivePolicyId ? params : null
  )
  const { data: stats, mutate: mutateStats } = useOwaspStats(
    effectivePolicyId ? params : null
  )
  const rules = useMemo(() => data?.items ?? [], [data?.items])
  const categories = useMemo(() => {
    const fromStats = Object.keys(stats?.by_category ?? {})
    if (fromStats.length > 0) return fromStats.sort()
    return Array.from(new Set(rules.map((r) => r.category))).sort()
  }, [rules, stats?.by_category])

  const refresh = async () => {
    await Promise.all([mutate(), mutateStats()])
  }

  const updateRule = async (
    rule: OWASPRuleItem,
    patch: Record<string, unknown>
  ) => {
    if (!effectivePolicyId) return
    try {
      await owaspApi.update(rule.id, { policy_id: effectivePolicyId, ...patch })
      await refresh()
      toast.success(t("common.updateSuccess"))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const resetRule = async (rule: OWASPRuleItem) => {
    if (!effectivePolicyId) return
    try {
      await owaspApi.reset(rule.id, effectivePolicyId)
      await refresh()
      toast.success(
        t("owaspRules.resetSuccess")
      )
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
      render: (row: OWASPRuleItem) => (
        <Switch
          checked={row.enabled}
          onCheckedChange={(v) => updateRule(row, { enabled: v })}
        />
      ),
    },
    {
      key: "rule",
      title: t("owaspRules.rule"),
      render: (row: OWASPRuleItem) => (
        <div className="space-y-1">
          <div className="flex items-center gap-2 font-mono text-xs">
            {row.id}
            {row.overridden && (
              <Badge variant="outline">
                {t("owaspRules.overridden")}
              </Badge>
            )}
          </div>
          <div className="font-medium">{row.name}</div>
          <p className="line-clamp-2 text-xs text-muted-foreground">
            {row.description}
          </p>
        </div>
      ),
    },
    {
      key: "category",
      title: t("common.category"),
      width: "140px",
      render: (row: OWASPRuleItem) => owaspCategoryLabel(row.category),
    },
    {
      key: "action",
      title: t("rules.action"),
      width: "170px",
      render: (row: OWASPRuleItem) => (
        <Select
          value={row.action || "intercept"}
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
      key: "sensitivity",
      title: t("attacks.sensitivity"),
      width: "150px",
      render: (row: OWASPRuleItem) => (
        <Select
          value={row.sensitivity || row.default_sensitivity || "medium"}
          onValueChange={(v) => updateRule(row, { sensitivity: v })}
        >
          <SelectTrigger className="h-8">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SENSITIVITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {t(`attacks.sensitivityValues.${s}`)}
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
      render: (row: OWASPRuleItem) => (
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
        title={t("owaspRules.title")}
        description={t("owaspRules.description")}
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
          <Label>{t("policies.title")}</Label>
          <Select
            value={effectivePolicyId ? String(effectivePolicyId) : ""}
            onValueChange={(v) => setPolicyId(Number(v))}
          >
            <SelectTrigger className="w-64">
              <SelectValue
                placeholder={t("rules.policyPlaceholder")}
              />
            </SelectTrigger>
            <SelectContent>
              {policies.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                  {p.is_default
                    ? ` (${t("common.default")})`
                    : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>{t("common.category")}</Label>
          <Select
            value={category || FILTER_ALL}
            onValueChange={(v) => setCategory(v === FILTER_ALL ? "" : v)}
          >
            <SelectTrigger className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={FILTER_ALL}>{t("common.all")}</SelectItem>
              {categories.map((c) => (
                <SelectItem key={c} value={c}>
                  {owaspCategoryLabel(c)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>{t("common.search")}</Label>
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-64"
            placeholder={t("rules.searchPlaceholder")}
          />
        </div>
        {stats && (
          <Badge variant="secondary" className="mb-2">
            {stats.enabled_count}/{stats.total} {t("common.enabled")}
          </Badge>
        )}
      </div>
      <DataTable
        columns={columns}
        data={rules}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("owaspRules.empty")}
      />
    </div>
  )
}
