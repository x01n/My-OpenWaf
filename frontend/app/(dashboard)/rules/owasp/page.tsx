"use client"

import { useCallback, useMemo, useState } from "react"
import Link from "next/link"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  IconChevronDown,
  IconPencil,
  IconPlayerPause,
  IconPlayerPlay,
  IconPlus,
  IconRefresh,
  IconRotateClockwise,
  IconX,
} from "@tabler/icons-react"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { TablePagination } from "@/components/table-pagination"
import { ActionBadge } from "@/components/action-badge"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
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
import { normalizeActionValue } from "@/lib/action-style"
import {
  invalidateOWASPRuleCaches,
  useOwaspBatchUpdate,
  useOwaspRules,
  usePolicies,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import type { OWASPRuleItem } from "@/lib/types"
import {
  BuiltinRuleEditDialog,
  type BuiltinRuleEditPatch,
} from "../components/builtin-rule-edit-dialog"

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
const PAGE_SIZE = 50
const SEARCH_DEBOUNCE_MS = 300
/** 与后端 BatchUpdateOWASPRules 的 owaspRuleBatchMaxEntries 保持一致。 */
const BATCH_MAX_RULES = 1000

/** 批量操作执行的请求负载；patch 走 batch ids+patch，reset 走逐条 reset。 */
type BatchPayload =
  | { kind: "patch"; patch: Record<string, unknown> }
  | { kind: "reset" }

/**
 * 批量操作确认信息；value 为动作/灵敏度文案，供确认框插值。
 * text 为空串表示「全策略重置」，走独立强确认框。
 */
type BatchActionState = {
  variant: "confirm-set" | "reset-selected" | "reset-all"
  text: string
  value: string
  payload: BatchPayload
} | null

type SelectionState = { scope: string; ids: Set<string> }

function normalizeSensitivity(value: string | undefined): string {
  return value === "mid" ? "medium" : value || "medium"
}

export default function OWASPRulesPage() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const {
    data: policies = [],
    isLoading: policiesLoading,
    error: policiesError,
  } = usePolicies()
  const [policyId, setPolicyId] = useState<number | undefined>(undefined)
  const [category, setCategory] = useState("")
  const [query, setQuery] = useState("")
  const [page, setPage] = useState(1)
  const [editingRule, setEditingRule] = useState<OWASPRuleItem | null>(null)
  const [pendingRuleIDs, setPendingRuleIDs] = useState<Set<string>>(
    () => new Set()
  )
  const [selection, setSelection] = useState<SelectionState>({
    scope: "",
    ids: new Set<string>(),
  })
  const [batchAction, setBatchAction] = useState<BatchActionState>(null)
  const [batchLoading, setBatchLoading] = useState(false)
  const resetPage = useCallback(() => setPage(1), [])
  const debouncedQuery = useDebouncedValue(query, SEARCH_DEBOUNCE_MS, resetPage)
  const querySettling = query !== debouncedQuery

  const defaultPolicyId = useMemo(
    () => policies.find((policy) => policy.is_default)?.id,
    [policies]
  )
  const effectivePolicyId = policyId ?? defaultPolicyId
  const batchUpdateOwaspRules = useOwaspBatchUpdate()

  const listParams = useMemo(
    () => ({
      policy_id: effectivePolicyId,
      page,
      page_size: PAGE_SIZE,
      include_grouped: false,
      category: category || undefined,
      q: debouncedQuery.trim() || undefined,
    }),
    [category, debouncedQuery, effectivePolicyId, page]
  )
  const { data, isLoading, isValidating, error, mutate } = useOwaspRules(
    effectivePolicyId ? listParams : null
  )
  const dataMatchesPolicy = data?.policy_id === effectivePolicyId
  const rules = useMemo(
    () => (dataMatchesPolicy ? (data?.items ?? []) : []),
    [data?.items, dataMatchesPolicy]
  )
  const total = dataMatchesPolicy ? (data?.total ?? 0) : 0
  const stats = dataMatchesPolicy ? data?.stats : undefined
  const dependencyLoading = !effectivePolicyId && policiesLoading
  const pageError = error ?? policiesError
  const categories = useMemo(() => {
    const fromStats = Object.keys(stats?.by_category ?? {})
    if (fromStats.length > 0) return fromStats.sort()
    return Array.from(new Set(rules.map((r) => r.category))).sort()
  }, [rules, stats?.by_category])

  const refresh = useCallback(async () => {
    if (!effectivePolicyId) return
    await mutate()
  }, [effectivePolicyId, mutate])

  /** 选择范围跟随策略/分段，切换后旧页选择不残留也不误命中新页行。 */
  const selectionScope = `${effectivePolicyId ?? 0}:${page}:${category}:${debouncedQuery}`
  const scopedSelectedIds = useMemo(
    () =>
      selection.scope === selectionScope
        ? selection.ids
        : new Set<string>(),
    [selection.ids, selection.scope, selectionScope]
  )
  const selectedCurrentPageCount = rules.reduce(
    (count, rule) => count + (scopedSelectedIds.has(rule.id) ? 1 : 0),
    0
  )
  const allCurrentPageSelected =
    rules.length > 0 && selectedCurrentPageCount === rules.length
  const selectedIds = Array.from(scopedSelectedIds)

  const clearSelection = useCallback(() => {
    setBatchAction(null)
    setSelection({ scope: selectionScope, ids: new Set<string>() })
  }, [selectionScope])

  const toggleSelect = useCallback(
    (ruleID: string) => {
      setSelection((current) => {
        const next = new Set(
          current.scope === selectionScope ? current.ids : []
        )
        if (next.has(ruleID)) next.delete(ruleID)
        else if (next.size < BATCH_MAX_RULES) next.add(ruleID)
        return { scope: selectionScope, ids: next }
      })
    },
    [selectionScope]
  )

  const toggleSelectAll = useCallback(() => {
    setSelection({
      scope: selectionScope,
      ids: allCurrentPageSelected
        ? new Set<string>()
        : new Set(rules.slice(0, BATCH_MAX_RULES).map((rule) => rule.id)),
    })
  }, [allCurrentPageSelected, rules, selectionScope])

  const beginBatchAction = useCallback(
    (action: NonNullable<BatchActionState>) => {
      if (selectedCurrentPageCount === 0) return
      if (action.variant === "confirm-set") {
        setBatchAction({
          ...action,
          text: t("owaspRules.batch.confirmSet", {
            count: selectedCurrentPageCount,
            value: action.value,
          }),
        })
        return
      }
      setBatchAction(action)
    },
    [selectedCurrentPageCount, t]
  )

  const markRulePending = useCallback((ruleID: string, pending: boolean) => {
    setPendingRuleIDs((current) => {
      const next = new Set(current)
      if (pending) next.add(ruleID)
      else next.delete(ruleID)
      return next
    })
  }, [])

  const updateRule = useCallback(
    async (rule: OWASPRuleItem, patch: Record<string, unknown>) => {
      if (!canManage) return
      if (!effectivePolicyId) return
      markRulePending(rule.id, true)
      try {
        await owaspApi.update(rule.id, {
          policy_id: effectivePolicyId,
          ...patch,
        })
        await invalidateOWASPRuleCaches().catch(() => undefined)
        toast.success(t("common.updateSuccess"))
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : t("common.operationFailed")
        )
      } finally {
        markRulePending(rule.id, false)
      }
    },
    [canManage, effectivePolicyId, markRulePending, t]
  )

  const resetRule = useCallback(
    async (rule: OWASPRuleItem) => {
      if (!canManage) return
      if (!effectivePolicyId) return
      markRulePending(rule.id, true)
      try {
        await owaspApi.reset(rule.id, effectivePolicyId)
        await invalidateOWASPRuleCaches().catch(() => undefined)
        toast.success(t("owaspRules.resetSuccess"))
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : t("common.operationFailed")
        )
      } finally {
        markRulePending(rule.id, false)
      }
    },
    [canManage, effectivePolicyId, markRulePending, t]
  )

  const saveRuleOverride = useCallback(
    async (patch: BuiltinRuleEditPatch) => {
      if (!editingRule || !effectivePolicyId || !canManage) return
      markRulePending(editingRule.id, true)
      try {
        await owaspApi.update(editingRule.id, {
          policy_id: effectivePolicyId,
          ...patch,
        })
        await invalidateOWASPRuleCaches().catch(() => undefined)
        toast.success(t("common.updateSuccess"))
      } finally {
        markRulePending(editingRule.id, false)
      }
    },
    [canManage, editingRule, effectivePolicyId, markRulePending, t]
  )

  const runBatch = useCallback(
    async (patch: Record<string, unknown>) => {
      if (!canManage || !effectivePolicyId) return
      if (selectedIds.length === 0) return
      const body: Record<string, unknown> = {
        policy_id: effectivePolicyId,
        ids: selectedIds,
        patch,
      }
      setBatchLoading(true)
      try {
        await batchUpdateOwaspRules.execute(body)
        await invalidateOWASPRuleCaches().catch(() => undefined)
        toast.success(
          t("owaspRules.batchSuccess", {
            count: selectedIds.length,
          })
        )
        clearSelection()
      } catch (error: unknown) {
        toast.error(
          error instanceof Error ? error.message : t("common.operationFailed")
        )
      } finally {
        setBatchLoading(false)
      }
    },
    [
      batchUpdateOwaspRules,
      canManage,
      clearSelection,
      effectivePolicyId,
      selectedIds,
      t,
    ]
  )

  const runResetSelected = useCallback(async () => {
    if (!canManage || !effectivePolicyId) return
    const idsSnapshot = selectedIds.slice(0, BATCH_MAX_RULES)
    if (idsSnapshot.length === 0) return
    setBatchLoading(true)
    try {
      // 单条 reset 无请求体；仅支持「清除已选中规则的覆盖」，故逐条调用。
      for (const ruleId of idsSnapshot) {
        await owaspApi.reset(ruleId, effectivePolicyId)
      }
      await invalidateOWASPRuleCaches().catch(() => undefined)
      toast.success(
        t("owaspRules.batchSuccess", {
          count: idsSnapshot.length,
        })
      )
      clearSelection()
    } catch (error: unknown) {
      toast.error(
        error instanceof Error ? error.message : t("common.operationFailed")
      )
    } finally {
      setBatchLoading(false)
    }
  }, [canManage, clearSelection, effectivePolicyId, selectedIds, t])

  const runResetAll = useCallback(async () => {
    if (!canManage || !effectivePolicyId) return
    setBatchLoading(true)
    try {
      await batchUpdateOwaspRules.execute({
        policy_id: effectivePolicyId,
        reset_all: true,
      })
      await invalidateOWASPRuleCaches().catch(() => undefined)
      toast.success(t("owaspRules.resetAllSuccess"))
      clearSelection()
    } catch (error: unknown) {
      toast.error(
        error instanceof Error ? error.message : t("common.operationFailed")
      )
    } finally {
      setBatchLoading(false)
    }
  }, [
    batchUpdateOwaspRules,
    canManage,
    clearSelection,
    effectivePolicyId,
    t,
  ])

  /**
   * 批量栏确认回调：记录要执行的负载并退出确认显示；只有请求成功
   * 才会清除选择，失败时选择保留可重试。
   */
  const handleBatchConfirm = useCallback(() => {
    if (!batchAction) return
    const payload = batchAction.payload
    setBatchAction(null)
    if (payload.kind === "reset") {
      void runResetSelected()
    } else {
      void runBatch(payload.patch)
    }
  }, [batchAction, runBatch, runResetSelected])

  const columns = useMemo(
    () => [
      {
        key: "select",
        title: (
          <Checkbox
            checked={allCurrentPageSelected}
            onCheckedChange={toggleSelectAll}
            disabled={!canManage}
            aria-label={t("common.selectAll")}
          />
        ),
        width: "40px",
        render: (row: OWASPRuleItem) => {
          const checked = scopedSelectedIds.has(row.id)
          return (
            <Checkbox
              checked={checked}
              disabled={
                !canManage ||
                (!checked && scopedSelectedIds.size >= BATCH_MAX_RULES)
              }
              onCheckedChange={() => toggleSelect(row.id)}
              aria-label={t("owaspRules.batch.selectRule")}
            />
          )
        },
      },
      {
        key: "enabled",
        title: t("common.enabled"),
        width: "80px",
        render: (row: OWASPRuleItem) => (
          <Switch
            checked={row.enabled}
            disabled={
              !canManage ||
              querySettling ||
              isValidating ||
              pendingRuleIDs.has(row.id)
            }
            onCheckedChange={(v) => updateRule(row, { enabled: v })}
          />
        ),
      },
      {
        key: "rule",
        title: t("owaspRules.rule"),
        cellClassName: "min-w-72 max-w-xl whitespace-normal",
        render: (row: OWASPRuleItem) => (
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
              {row.id}
              {pendingRuleIDs.has(row.id) && (
                <IconRefresh
                  aria-label={t("common.saving")}
                  className="h-3.5 w-3.5 animate-spin text-muted-foreground"
                />
              )}
              {row.overridden && (
                <Badge variant="outline">{t("owaspRules.overridden")}</Badge>
              )}
            </div>
            <div className="font-medium break-words">{row.name}</div>
            <p className="line-clamp-2 text-xs break-words whitespace-normal text-muted-foreground">
              {row.description}
            </p>
            {row.note && (
              <p className="line-clamp-2 rounded bg-muted/60 px-2 py-1 text-xs break-words whitespace-normal text-foreground">
                {t("rules.policyNote", "策略备注")}：{row.note}
              </p>
            )}
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
            value={normalizeActionValue(row.action) || "intercept"}
            disabled={
              !canManage ||
              querySettling ||
              isValidating ||
              pendingRuleIDs.has(row.id)
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
        key: "sensitivity",
        title: t("attacks.sensitivity"),
        width: "150px",
        render: (row: OWASPRuleItem) => (
          <Select
            value={normalizeSensitivity(
              row.sensitivity || row.default_sensitivity
            )}
            disabled={
              !canManage ||
              querySettling ||
              isValidating ||
              pendingRuleIDs.has(row.id)
            }
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
        width: "140px",
        render: (row: OWASPRuleItem) => (
          <div className="flex items-center gap-1">
            <Button
              size="icon-sm"
              variant="ghost"
              disabled={
                !canManage ||
                querySettling ||
                isValidating ||
                pendingRuleIDs.has(row.id)
              }
              title={t("common.edit")}
              onClick={() => setEditingRule(row)}
            >
              <IconPencil className="h-4 w-4" />
            </Button>
            <Button
              size="icon-sm"
              variant="ghost"
              disabled={
                !canManage ||
                querySettling ||
                isValidating ||
                !row.overridden ||
                pendingRuleIDs.has(row.id)
              }
              title={t("owaspRules.resetOverride", "删除当前策略覆盖")}
              onClick={() => resetRule(row)}
            >
              <IconRotateClockwise
                className={`h-4 w-4 ${pendingRuleIDs.has(row.id) ? "animate-spin" : ""}`}
              />
            </Button>
          </div>
        ),
      },
    ],
    [
      allCurrentPageSelected,
      canManage,
      isValidating,
      pendingRuleIDs,
      querySettling,
      resetRule,
      scopedSelectedIds,
      t,
      toggleSelect,
      toggleSelectAll,
      updateRule,
    ]
  )

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("owaspRules.title")}
        description={t("owaspRules.description")}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button asChild disabled={!effectivePolicyId || !canManage}>
              <Link
                aria-disabled={!effectivePolicyId || !canManage}
                tabIndex={!effectivePolicyId || !canManage ? -1 : undefined}
                onClick={(event) => {
                  if (!effectivePolicyId || !canManage) event.preventDefault()
                }}
                className={
                  !effectivePolicyId || !canManage
                    ? "pointer-events-none opacity-50"
                    : undefined
                }
                href={
                  effectivePolicyId && canManage
                    ? `/rules?policy_id=${effectivePolicyId}&create=1`
                    : "/rules"
                }
              >
                <IconPlus className="h-4 w-4" />
                {t("rules.addCustomRule", "新增自定义规则")}
              </Link>
            </Button>
            <Button
              variant="outline"
              disabled={
                !effectivePolicyId ||
                querySettling ||
                isValidating ||
                pendingRuleIDs.size > 0
              }
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
          <Label>{t("policies.title")}</Label>
          <Select
            value={effectivePolicyId ? String(effectivePolicyId) : ""}
            onValueChange={(v) => {
              setPolicyId(Number(v))
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
        </div>
        <div className="space-y-1.5">
          <Label>{t("common.category")}</Label>
          <Select
            value={category || FILTER_ALL}
            onValueChange={(v) => {
              setCategory(v === FILTER_ALL ? "" : v)
              setPage(1)
            }}
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
            maxLength={256}
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
        loading={(isLoading || dependencyLoading) && rules.length === 0}
        rowKey={(row) => row.id}
        emptyText={t("owaspRules.empty")}
      />
      <TablePagination
        page={page}
        pageSize={PAGE_SIZE}
        total={total}
        disabled={querySettling || isValidating || pendingRuleIDs.size > 0}
        onPageChange={setPage}
      />
      {batchLoading && selectedIds.length === 0 && (
        <div
          role="status"
          aria-live="polite"
          className="flex items-center gap-2 text-xs text-muted-foreground"
        >
          <IconRefresh className="size-3.5 animate-spin" />
          {t("owaspRules.batch.resettingAll")}
        </div>
      )}
      {canManage && !batchLoading && selectedCurrentPageCount > 0 && (
        <div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2">
          <div className="flex items-center gap-3 rounded-xl border bg-background/95 px-5 py-3 shadow-lg backdrop-blur-sm">
            <span className="text-sm font-medium text-muted-foreground">
              {t("owaspRules.batch.selected", {
                count: selectedCurrentPageCount,
              })}
            </span>
            <Button
              size="sm"
              className="h-8 gap-1.5 text-xs"
              disabled={batchLoading}
              onClick={() =>
                beginBatchAction({
                  text: "",
                  value: t("owaspRules.batch.enable"),
                  variant: "confirm-set",
                  payload: { kind: "patch", patch: { enabled: true } },
                })
              }
            >
              <IconPlayerPlay className="h-3.5 w-3.5" />
              {t("owaspRules.batch.enable", { count: selectedCurrentPageCount })}
            </Button>
            <Button
              size="sm"
              className="h-8 gap-1.5 text-xs"
              disabled={batchLoading}
              onClick={() =>
                beginBatchAction({
                  text: "",
                  value: t("owaspRules.batch.disable"),
                  variant: "confirm-set",
                  payload: { kind: "patch", patch: { enabled: false } },
                })
              }
            >
              <IconPlayerPause className="h-3.5 w-3.5" />
              {t("owaspRules.batch.disable", { count: selectedCurrentPageCount })}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1.5 text-xs"
              disabled={batchLoading}
              onClick={() =>
                beginBatchAction({
                  text: t("owaspRules.batch.resetSelectedDescription", {
                    count: selectedCurrentPageCount,
                  }),
                  value: "",
                  variant: "reset-selected",
                  payload: { kind: "reset" },
                })
              }
            >
              <IconRotateClockwise className="h-3.5 w-3.5" />
              {t("owaspRules.batch.resetOverrides")}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 gap-1 text-xs"
                  disabled={batchLoading}
                >
                  {t("owaspRules.batch.setAction")}
                  <IconChevronDown className="h-3 w-3" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="center">
                <DropdownMenuSub>
                  <DropdownMenuSubTrigger>
                    {t("rules.action")}
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {ACTIONS.map((action) => (
                      <DropdownMenuItem
                        key={action}
                        onClick={() =>
                          beginBatchAction({
                            text: "",
                            value: t(`securityEvents.action.${action}`),
                            variant: "confirm-set",
                            payload: { kind: "patch", patch: { action } },
                          })
                        }
                      >
                        <ActionBadge action={action} />
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>
                <DropdownMenuSub>
                  <DropdownMenuSubTrigger>
                    {t("attacks.sensitivity")}
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {SENSITIVITIES.map((sensitivity) => (
                      <DropdownMenuItem
                        key={sensitivity}
                        onClick={() =>
                          beginBatchAction({
                            text: "",
                            value: t(`attacks.sensitivityValues.${sensitivity}`),
                            variant: "confirm-set",
                            payload: { kind: "patch", patch: { sensitivity } },
                          })
                        }
                      >
                        {t(`attacks.sensitivityValues.${sensitivity}`)}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1 text-xs"
              onClick={clearSelection}
            >
              <IconX className="h-3.5 w-3.5" />
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      )}
      {batchAction?.variant === "reset-all" && (
        <AlertDialog open={true} onOpenChange={(open) => !open && setBatchAction(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("owaspRules.batch.resetAllTitle")}</AlertDialogTitle>
              <AlertDialogDescription>
                {t("owaspRules.batch.resetAllDescription")}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={batchLoading}>
                {t("common.cancel")}
              </AlertDialogCancel>
              <AlertDialogAction
                disabled={batchLoading}
                onClick={() => void runResetAll()}
              >
                {batchLoading ? t("common.saving") : t("common.confirm")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
      {batchAction && batchAction.variant !== "reset-all" && (
        <AlertDialog open={true} onOpenChange={(open) => !open && setBatchAction(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("owaspRules.batch.confirmTitle")}</AlertDialogTitle>
              <AlertDialogDescription>
                {batchAction.text}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={batchLoading}>
                {t("common.cancel")}
              </AlertDialogCancel>
              <AlertDialogAction
                disabled={batchLoading}
                onClick={() => handleBatchConfirm()}
              >
                {batchLoading ? t("common.saving") : t("common.confirm")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
      {editingRule && (
        <BuiltinRuleEditDialog
          key={`owasp-${editingRule.id}`}
          open
          onOpenChange={(open) => !open && setEditingRule(null)}
          ruleID={editingRule.id}
          name={editingRule.name}
          description={editingRule.description}
          initial={{
            enabled: editingRule.enabled,
            action:
              normalizeActionValue(
                editingRule.action || editingRule.default_action
              ) || "intercept",
            // 编辑器必须保留空值的“继承”语义；否则未覆盖规则保存时会
            // 把页面展示用的默认 medium 写成新的策略覆盖。
            sensitivity: editingRule.sensitivity || "inherit",
            statusCode: editingRule.status_code,
            redirectTo: editingRule.redirect_to,
            captchaType: editingRule.captcha_type || "",
            whitelist: editingRule.whitelist,
            note: editingRule.note,
          }}
          allowWhitelist
          allowNote
          onSubmit={saveRuleOverride}
        />
      )}
    </div>
  )
}
