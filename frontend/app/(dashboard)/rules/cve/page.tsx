"use client"

import { useCallback, useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  IconPencil,
  IconPlus,
  IconRefresh,
  IconRotateClockwise,
  IconTrash,
} from "@tabler/icons-react"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { TablePagination } from "@/components/table-pagination"
import { ActionBadge } from "@/components/action-badge"
import { ConfirmDialog } from "@/components/confirm-dialog"
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
  invalidateCVERuleCaches,
  useCveRules,
  useAllSites,
  usePolicies,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import type { CVERuleItem, CVERuleWriteInput, CVEScopeType } from "@/lib/types"
import { categoryLabel, severityLabel } from "@/lib/attack-category"
import { normalizeActionValue } from "@/lib/action-style"
import {
  BuiltinRuleEditDialog,
  type BuiltinRuleEditPatch,
} from "../components/builtin-rule-edit-dialog"
import { CVERuleFormDialog } from "../components/cve-rule-form-dialog"

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
const PAGE_SIZE = 50

export default function CVERulesPage() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const canManageCustom = user?.role === "admin"
  const [scope, setScope] = useState<CVEScopeType>(SCOPE_GLOBAL)
  const [policyID, setPolicyID] = useState<number | undefined>(undefined)
  const [siteID, setSiteID] = useState<number | undefined>(undefined)
  const [page, setPage] = useState(1)
  const [editingRule, setEditingRule] = useState<CVERuleItem | null>(null)
  const [customDialogOpen, setCustomDialogOpen] = useState(false)
  const [customEditingRule, setCustomEditingRule] =
    useState<CVERuleItem | null>(null)
  const [deletingRule, setDeletingRule] = useState<CVERuleItem | null>(null)
  const [deletePending, setDeletePending] = useState(false)
  const [pendingRuleIDs, setPendingRuleIDs] = useState<Set<number>>(
    () => new Set()
  )
  const {
    data: policies = [],
    isLoading: policiesLoading,
    error: policiesError,
  } = usePolicies(scope === "policy")
  const {
    data: sitesData,
    isLoading: sitesLoading,
    error: sitesError,
  } = useAllSites(scope === "site")
  const sites = useMemo(() => sitesData?.items ?? [], [sitesData?.items])
  const defaultPolicyID = useMemo(
    () => policies.find((policy) => policy.is_default)?.id,
    [policies]
  )
  const effectivePolicyID = policyID ?? defaultPolicyID
  const effectiveSiteID = siteID ?? sites[0]?.id

  const params = useMemo(() => {
    const base: Record<string, unknown> = {
      scope,
      page,
      page_size: PAGE_SIZE,
    }
    if (scope === "policy") base.policy_id = effectivePolicyID
    if (scope === "site") base.site_id = effectiveSiteID
    return base
  }, [effectivePolicyID, effectiveSiteID, page, scope])
  const enabled = Boolean(
    scope === "global" ||
    (scope === "policy" && effectivePolicyID) ||
    (scope === "site" && effectiveSiteID)
  )
  const { data, isLoading, isValidating, error, mutate } = useCveRules(
    enabled ? params : null
  )
  const effectiveScopeID =
    scope === "policy"
      ? effectivePolicyID
      : scope === "site"
        ? effectiveSiteID
        : 0
  const dataMatchesScope =
    data?.scope === scope && data.scope_id === effectiveScopeID
  const rules = dataMatchesScope ? (data?.items ?? []) : []
  const stats = dataMatchesScope ? data?.stats : undefined
  const total = dataMatchesScope ? (data?.total ?? 0) : 0
  const dependencyLoading =
    (scope === "policy" && policiesLoading) ||
    (scope === "site" && sitesLoading)
  const pageError = error ?? policiesError ?? sitesError

  const refresh = useCallback(async () => {
    if (!enabled) return
    await mutate()
  }, [enabled, mutate])

  const scopedPatch = useCallback(
    () => ({
      scope,
      policy_id: scope === "policy" ? effectivePolicyID : undefined,
      site_id: scope === "site" ? effectiveSiteID : undefined,
    }),
    [effectivePolicyID, effectiveSiteID, scope]
  )

  const isCustomRule = useCallback(
    (rule: CVERuleItem) => rule.source === "custom",
    []
  )

  /**
   * 将列表中的自定义规则转换为直接 CRUD 所需的完整模型字段。
   * 自定义规则没有作用域覆盖；缺少关键字段时拒绝写入，避免用默认值
   * 覆盖数据库中用户未展示的内容。
   */
  const customRulePayload = useCallback(
    (
      rule: CVERuleItem,
      patch: Record<string, unknown> = {}
    ): CVERuleWriteInput | null => {
      const cveID = (rule.cve_id || rule.cve || "").trim()
      const category = (rule.category || "").trim()
      const pattern = rule.pattern || ""
      const target = rule.target
      const severity = (rule.severity || "").trim()
      const action =
        typeof patch.action === "string"
          ? patch.action
          : (rule.action || "").trim()
      const captchaType =
        typeof patch.captcha_type === "string"
          ? patch.captcha_type
          : rule.captcha_type || ""
      const enabled =
        typeof patch.enabled === "boolean" ? patch.enabled : rule.enabled
      if (!category || !pattern.trim() || !target || !severity || !action) {
        return null
      }
      return {
        cve_id: cveID,
        category,
        pattern,
        target,
        severity,
        action,
        description: rule.description || "",
        enabled,
        captcha_type:
          action === "captcha_challenge"
            ? (captchaType as CVERuleWriteInput["captcha_type"])
            : "",
      }
    },
    []
  )

  const markRulePending = useCallback((ruleID: number, pending: boolean) => {
    setPendingRuleIDs((current) => {
      const next = new Set(current)
      if (pending) next.add(ruleID)
      else next.delete(ruleID)
      return next
    })
  }, [])

  const updateRule = useCallback(
    async (rule: CVERuleItem, patch: Record<string, unknown>) => {
      if (!canManage) return
      if (isCustomRule(rule) && !canManageCustom) return
      if (isCustomRule(rule) && scope !== SCOPE_GLOBAL) return
      markRulePending(rule.id, true)
      try {
        if (isCustomRule(rule)) {
          const payload = customRulePayload(rule, patch)
          if (!payload) {
            throw new Error(t("cveRules.customFieldsUnavailable"))
          }
          await cveApi.update(rule.id, payload)
        } else {
          await cveApi.patch(rule.id, { ...scopedPatch(), ...patch })
        }
        await invalidateCVERuleCaches().catch(() => undefined)
        toast.success(t("common.updateSuccess"))
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : t("common.operationFailed")
        )
      } finally {
        markRulePending(rule.id, false)
      }
    },
    [
      canManage,
      canManageCustom,
      customRulePayload,
      isCustomRule,
      markRulePending,
      scope,
      scopedPatch,
      t,
    ]
  )

  const resetRule = useCallback(
    async (rule: CVERuleItem) => {
      if (!canManage) return
      markRulePending(rule.id, true)
      try {
        await cveApi.reset(rule.id, scopedPatch())
        await invalidateCVERuleCaches().catch(() => undefined)
        toast.success(t("cveRules.resetSuccess"))
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : t("common.operationFailed")
        )
      } finally {
        markRulePending(rule.id, false)
      }
    },
    [canManage, markRulePending, scopedPatch, t]
  )

  const saveRuleOverride = useCallback(
    async (patch: BuiltinRuleEditPatch) => {
      if (!editingRule || !canManage) return
      markRulePending(editingRule.id, true)
      try {
        await cveApi.patch(editingRule.id, { ...scopedPatch(), ...patch })
        await invalidateCVERuleCaches().catch(() => undefined)
        toast.success(t("common.updateSuccess"))
      } finally {
        markRulePending(editingRule.id, false)
      }
    },
    [canManage, editingRule, markRulePending, scopedPatch, t]
  )

  const saveCustomRule = useCallback(
    async (payload: CVERuleWriteInput) => {
      if (!canManageCustom) {
        throw new Error(t("cveRules.customAdminOnly"))
      }
      if (scope !== SCOPE_GLOBAL) {
        throw new Error(t("cveRules.customGlobalOnly"))
      }
      const ruleID = customEditingRule?.id
      if (ruleID !== undefined) markRulePending(ruleID, true)
      try {
        if (ruleID === undefined) {
          await cveApi.create(payload)
          toast.success(t("cveRules.createSuccess"))
        } else {
          await cveApi.update(ruleID, payload)
          toast.success(t("cveRules.updateSuccess"))
        }
        await invalidateCVERuleCaches().catch(() => undefined)
        await mutate().catch(() => {
          toast.error(t("cveRules.refreshAfterWriteFailed"))
        })
      } finally {
        if (ruleID !== undefined) markRulePending(ruleID, false)
      }
    },
    [canManageCustom, customEditingRule, markRulePending, mutate, scope, t]
  )

  const confirmDelete = useCallback(async () => {
    if (!deletingRule || !isCustomRule(deletingRule)) return
    if (!canManageCustom) return
    if (scope !== SCOPE_GLOBAL) return
    setDeletePending(true)
    markRulePending(deletingRule.id, true)
    try {
      await cveApi.delete(deletingRule.id)
      await invalidateCVERuleCaches().catch(() => undefined)
      toast.success(t("cveRules.deleteSuccess"))
      setDeletingRule(null)
      if (rules.length === 1 && page > 1) setPage(page - 1)
      await mutate().catch(() => {
        toast.error(t("cveRules.refreshAfterWriteFailed"))
      })
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("cveRules.deleteFailed")
      )
    } finally {
      markRulePending(deletingRule.id, false)
      setDeletePending(false)
    }
  }, [
    deletingRule,
    canManageCustom,
    isCustomRule,
    markRulePending,
    mutate,
    page,
    rules.length,
    scope,
    t,
  ])

  const columns = useMemo(
    () => [
      {
        key: "enabled",
        title: t("common.enabled"),
        width: "80px",
        render: (row: CVERuleItem) => (
          <Switch
            checked={row.effective?.enabled ?? row.enabled}
            disabled={
              isValidating ||
              !canManage ||
              (isCustomRule(row) && !canManageCustom) ||
              pendingRuleIDs.has(row.id) ||
              (isCustomRule(row) && scope !== SCOPE_GLOBAL)
            }
            onCheckedChange={(v) => updateRule(row, { enabled: v })}
          />
        ),
      },
      {
        key: "rule",
        title: t("cveRules.rule"),
        cellClassName: "min-w-72 max-w-xl whitespace-normal",
        render: (row: CVERuleItem) => (
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
              {row.cve_id || row.cve || `#${row.id}`}
              {pendingRuleIDs.has(row.id) && (
                <IconRefresh
                  aria-label={t("common.saving")}
                  className="h-3.5 w-3.5 animate-spin text-muted-foreground"
                />
              )}
              {row.overridden && (
                <Badge variant="outline">{t("cveRules.overridden")}</Badge>
              )}
              {isCustomRule(row) && (
                <Badge variant="secondary">{t("cveRules.custom")}</Badge>
              )}
              {row.inherited_from && !isCustomRule(row) && (
                <Badge variant="secondary">{row.inherited_from}</Badge>
              )}
            </div>
            <div className="font-medium break-words">
              {row.name || row.description || row.cve_id || row.cve}
            </div>
            <p className="line-clamp-2 text-xs break-words whitespace-normal text-muted-foreground">
              {row.description}
            </p>
            {isCustomRule(row) && row.pattern && (
              <code className="block max-w-full truncate rounded bg-muted/60 px-2 py-1 text-[11px] text-muted-foreground">
                {row.target}: {row.pattern}
              </code>
            )}
          </div>
        ),
      },
      {
        key: "category",
        title: t("common.category"),
        width: "120px",
        render: (row: CVERuleItem) => categoryLabel(row.category),
      },
      {
        key: "severity",
        title: t("cveRules.severity"),
        width: "100px",
        render: (row: CVERuleItem) => severityLabel(row.severity),
      },
      {
        key: "action",
        title: t("rules.action"),
        width: "170px",
        render: (row: CVERuleItem) => (
          <Select
            value={
              normalizeActionValue(row.effective?.action || row.action) ||
              "intercept"
            }
            disabled={
              isValidating ||
              !canManage ||
              (isCustomRule(row) && !canManageCustom) ||
              pendingRuleIDs.has(row.id) ||
              (isCustomRule(row) && scope !== SCOPE_GLOBAL)
            }
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
        width: "140px",
        render: (row: CVERuleItem) => (
          <div className="flex items-center gap-1">
            <Button
              size="icon-sm"
              variant="ghost"
              disabled={
                isValidating ||
                !canManage ||
                (isCustomRule(row) && !canManageCustom) ||
                pendingRuleIDs.has(row.id) ||
                (isCustomRule(row) && scope !== SCOPE_GLOBAL)
              }
              title={t("common.edit")}
              onClick={() => {
                if (isCustomRule(row)) {
                  setCustomEditingRule(row)
                  setCustomDialogOpen(true)
                } else {
                  setEditingRule(row)
                }
              }}
            >
              <IconPencil className="h-4 w-4" />
            </Button>
            {isCustomRule(row) ? (
              <Button
                size="icon-sm"
                variant="ghost"
                disabled={
                  isValidating ||
                  !canManageCustom ||
                  scope !== SCOPE_GLOBAL ||
                  pendingRuleIDs.has(row.id)
                }
                title={t("common.delete")}
                onClick={() => setDeletingRule(row)}
              >
                <IconTrash className="h-4 w-4 text-destructive" />
              </Button>
            ) : (
              <Button
                size="icon-sm"
                variant="ghost"
                disabled={
                  isValidating ||
                  !canManage ||
                  !row.overridden ||
                  pendingRuleIDs.has(row.id)
                }
                title={t("cveRules.resetOverride", "删除当前作用域覆盖")}
                onClick={() => resetRule(row)}
              >
                <IconRotateClockwise
                  className={`h-4 w-4 ${pendingRuleIDs.has(row.id) ? "animate-spin" : ""}`}
                />
              </Button>
            )}
          </div>
        ),
      },
    ],
    [
      isCustomRule,
      canManage,
      canManageCustom,
      isValidating,
      pendingRuleIDs,
      resetRule,
      scope,
      t,
      updateRule,
    ]
  )

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("cveRules.title")}
        description={t("cveRules.description")}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={
                !canManageCustom ||
                scope !== SCOPE_GLOBAL ||
                !enabled ||
                isValidating ||
                pendingRuleIDs.size > 0
              }
              title={
                !canManageCustom
                  ? t("cveRules.customAdminOnly")
                  : scope === SCOPE_GLOBAL
                    ? t("cveRules.addCustom")
                    : t("cveRules.customGlobalOnly")
              }
              onClick={() => {
                setCustomEditingRule(null)
                setCustomDialogOpen(true)
              }}
            >
              <IconPlus className="mr-1 h-4 w-4" />
              {t("cveRules.addCustom")}
            </Button>
            <Button
              variant="outline"
              disabled={!enabled || isValidating || pendingRuleIDs.size > 0}
              onClick={refresh}
            >
              <IconRefresh
                className={`mr-1 h-4 w-4 ${isValidating ? "animate-spin" : ""}`}
              />
              {t("common.refresh")}
            </Button>
          </div>
        }
      />
      {pageError && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {pageError instanceof Error
              ? pageError.message
              : t("common.operationFailed")}
          </AlertDescription>
        </Alert>
      )}
      {isValidating && rules.length > 0 && (
        <div
          role="status"
          aria-live="polite"
          className="flex items-center gap-2 text-xs text-muted-foreground"
        >
          <IconRefresh className="size-3.5 animate-spin" />
          {t("common.refreshing")}
        </div>
      )}
      <div className="flex flex-wrap items-end gap-3 rounded-lg border bg-card p-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium">{t("cveRules.scope")}</label>
          <Select
            value={scope}
            onValueChange={(v) => {
              setScope(v as CVEScopeType)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="global">
                {t("cveRules.scopeGlobal")}
              </SelectItem>
              <SelectItem value="policy">
                {t("cveRules.scopePolicy")}
              </SelectItem>
              <SelectItem value="site">{t("cveRules.scopeSite")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {scope === "policy" && (
          <Select
            value={effectivePolicyID ? String(effectivePolicyID) : ""}
            onValueChange={(v) => {
              setPolicyID(Number(v))
              setPage(1)
            }}
          >
            <SelectTrigger className="w-64">
              <SelectValue placeholder={t("rules.policyPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              {policies.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                  {p.is_default ? ` (${t("common.default")})` : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {scope === "site" && (
          <Select
            value={effectiveSiteID ? String(effectiveSiteID) : ""}
            onValueChange={(v) => {
              setSiteID(Number(v))
              setPage(1)
            }}
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
            {stats.enabled_count}/{stats.total} {t("common.enabled")}
          </Badge>
        )}
      </div>
      <DataTable
        columns={columns}
        data={rules}
        loading={(isLoading || dependencyLoading) && rules.length === 0}
        rowKey={(row) => row.id}
        emptyText={t("cveRules.empty")}
      />
      <TablePagination
        page={page}
        pageSize={PAGE_SIZE}
        total={total}
        disabled={isValidating || pendingRuleIDs.size > 0}
        onPageChange={setPage}
      />
      {scope !== SCOPE_GLOBAL && (
        <p className="text-xs text-muted-foreground">
          {t("cveRules.customGlobalOnly")}
        </p>
      )}
      <CVERuleFormDialog
        open={customDialogOpen}
        rule={customEditingRule}
        onOpenChange={(open) => {
          setCustomDialogOpen(open)
          if (!open) setCustomEditingRule(null)
        }}
        onSubmit={saveCustomRule}
      />
      <ConfirmDialog
        open={Boolean(deletingRule)}
        onOpenChange={(open) =>
          !open && !deletePending && setDeletingRule(null)
        }
        title={t("cveRules.deleteTitle")}
        description={t("cveRules.deleteDescription")}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deletePending}
      />
      {editingRule && (
        <BuiltinRuleEditDialog
          key={`cve-${editingRule.id}`}
          open
          onOpenChange={(open) => !open && setEditingRule(null)}
          ruleID={editingRule.cve_id || editingRule.cve || `#${editingRule.id}`}
          name={
            editingRule.name ||
            editingRule.description ||
            editingRule.cve_id ||
            editingRule.cve ||
            `#${editingRule.id}`
          }
          description={editingRule.description}
          initial={{
            enabled: editingRule.effective?.enabled ?? editingRule.enabled,
            action:
              normalizeActionValue(
                editingRule.effective?.action || editingRule.action
              ) || "intercept",
            sensitivity: editingRule.effective?.sensitivity,
            statusCode: editingRule.effective?.status_code,
            redirectTo: editingRule.effective?.redirect_to,
            captchaType: editingRule.effective?.captcha_type || "",
          }}
          onSubmit={saveRuleOverride}
        />
      )}
    </div>
  )
}
