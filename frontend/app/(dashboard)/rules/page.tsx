"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "next/navigation"
import dynamic from "next/dynamic"
import { PageHeader } from "@/components/page-header"
import {
  usePolicies,
  useRules,
  useRuleMutation,
  useRuleDelete,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import { DataTable } from "@/components/data-table"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { toast } from "sonner"
import {
  IconPlus,
  IconPencil,
  IconTrash,
  IconShieldCheck,
  IconBan,
  IconListDetails,
  IconDownload,
  IconUpload,
} from "@tabler/icons-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { EmptyState } from "@/components/empty-state"
import { Skeleton } from "@/components/ui/skeleton"
import { TablePagination } from "@/components/table-pagination"
import type { Rule, RuleAction, RuleExportPayload } from "@/lib/types"
import { ruleApi } from "@/lib/api"

const PAGE_SIZE = 50
type RuleActionFilter = "all" | Extract<RuleAction, "allow" | "intercept">

/** 规则编辑器依赖表单与校验库，仅在用户真正打开弹窗时加载。 */
const RuleFormDialog = dynamic(
  () =>
    import("./components/rule-form-dialog").then(
      (module) => module.RuleFormDialog
    ),
  {
    loading: function RuleDialogLoading() {
      const { t } = useTranslation()
      return (
        <div
          role="status"
          aria-label={t("common.loading")}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/20 p-4 backdrop-blur-[1px]"
        >
          <div className="w-full max-w-2xl space-y-4 rounded-lg border bg-background p-6 shadow-xl">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-36 w-full" />
          </div>
        </div>
      )
    },
  }
)

/**
 * 黑白名单（自定义规则）列表页面
 * 支持规则筛选、启用/禁用、编辑、删除、添加操作
 */
export default function RulesPage() {
  const { t } = useTranslation()
  const searchParams = useSearchParams()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const [filterType, setFilterType] = useState<RuleActionFilter>("all")
  const [policyId, setPolicyId] = useState<number | undefined>(undefined)
  const [page, setPage] = useState(1)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const [deleteId, setDeleteId] = useState<number | null>(null)
  const [importing, setImporting] = useState(false)
  const [exporting, setExporting] = useState(false)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const createRequestConsumed = useRef(false)

  const {
    data: policies = [],
    isLoading: policiesLoading,
    error: policiesError,
  } = usePolicies()

  const initialPolicyId = useMemo(() => {
    const rawPolicyId = searchParams.get("policy_id")
    if (!rawPolicyId) return undefined
    const parsed = Number(rawPolicyId)
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined
  }, [searchParams])

  const defaultPolicyId = useMemo(
    () => policies.find((policy) => policy.is_default)?.id,
    [policies]
  )
  const effectivePolicyId = useMemo(() => {
    const requestedPolicyId = policyId ?? initialPolicyId
    if (
      requestedPolicyId &&
      policies.some((policy) => policy.id === requestedPolicyId)
    ) {
      return requestedPolicyId
    }
    return defaultPolicyId
  }, [defaultPolicyId, initialPolicyId, policies, policyId])

  /** 导出当前策略全部规则为 JSON 文件。 */
  const handleExport = async () => {
    if (!canManage || !effectivePolicyId) return
    if (exporting) return
    setExporting(true)
    try {
      const payload = await ruleApi.export()
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement("a")
      anchor.href = url
      anchor.download = `owaf-rules-${effectivePolicyId}.json`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      toast.success(t("rules.exportSuccess"))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("rules.exportFailed")
      )
    } finally {
      setExporting(false)
    }
  }

  /** 导入 JSON 规则导出文件；后端会忽略其中的 ID，按当前策略重建。 */
  const handleImport = async (file: File | null) => {
    if (!file || !canManage || !effectivePolicyId) return
    if (importing) return
    try {
      const payload = (await file.text()) as string
      const parsed: Partial<RuleExportPayload> = JSON.parse(
        payload
      ) as Partial<RuleExportPayload>
      if (!Array.isArray(parsed.rules) || parsed.rules.length === 0) {
        toast.error(t("rules.importEmpty"))
        return
      }
      // 导出文件可能是全局规则集合；导入目标锁定为当前所选策略。
      const imported = parsed.rules.map((rule) => ({
        ...rule,
        id: 0,
        policy_id: effectivePolicyId,
        created_at: "",
        updated_at: "",
      }))
      setImporting(true)
      await ruleApi.import({ rules: imported })
      toast.success(t("rules.importSuccess"))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("rules.importFailed")
      )
    } finally {
      setImporting(false)
      if (fileInputRef.current) fileInputRef.current.value = ""
    }
  }

  useEffect(() => {
    // Auth resolves after the first render. Consume the deep-link only once
    // role and policy are known, otherwise ?create=1 is lost permanently.
    if (
      createRequestConsumed.current ||
      authLoading ||
      searchParams.get("create") !== "1" ||
      !canManage ||
      !effectivePolicyId
    ) {
      return
    }
    createRequestConsumed.current = true
    setEditingRule(null)
    setDialogOpen(true)
  }, [authLoading, canManage, effectivePolicyId, searchParams])

  const { data, isLoading, error } = useRules(
    effectivePolicyId
      ? {
          policy_id: effectivePolicyId,
          page,
          page_size: PAGE_SIZE,
          ...(filterType === "all" ? {} : { action: filterType }),
        }
      : null
  )
  const { execute: mutateRule, loading: ruleMutationLoading } =
    useRuleMutation()
  const { execute: deleteRule, loading: deleteLoading } = useRuleDelete()
  const pageError = error ?? policiesError

  const rules = data?.items || []
  const total = data?.total ?? 0

  /** 切换规则启用状态 */
  const handleToggle = async (rule: Rule) => {
    if (!canManage) return
    try {
      await mutateRule({ id: rule.id, data: { enabled: !rule.enabled } })
      toast.success(
        t("rules.toggleSuccess", {
          action: rule.enabled ? t("common.disable") : t("common.enable"),
        })
      )
    } catch {
      toast.error(t("rules.toggleFailed"))
    }
  }

  /** 打开编辑弹窗 */
  const handleEdit = (rule: Rule) => {
    if (!canManage) return
    setEditingRule(rule)
    setDialogOpen(true)
  }

  /** 打开删除确认 */
  const handleDelete = (id: number) => {
    if (!canManage) return
    setDeleteId(id)
  }

  /** 确认删除 */
  const confirmDelete = async () => {
    if (!deleteId || !canManage) return
    try {
      await deleteRule(deleteId)
      toast.success(t("rules.deleteSuccess"))
      setDeleteId(null)
      if (rules.length === 1 && page > 1) setPage(page - 1)
    } catch {
      toast.error(t("rules.deleteFailed"))
    }
  }

  const columns = [
    {
      key: "enabled",
      title: t("rules.status"),
      width: "80px",
      render: (row: Rule) => (
        <Switch
          checked={row.enabled}
          disabled={ruleMutationLoading || !canManage}
          onCheckedChange={() => handleToggle(row)}
        />
      ),
    },
    {
      key: "type",
      title: t("rules.type"),
      width: "100px",
      render: (row: Rule) => (
        <div className="flex items-center gap-1.5">
          {row.action === "allow" ? (
            <>
              <IconShieldCheck className="h-4 w-4 text-primary" />
              <Badge variant="default">{t("rules.allow")}</Badge>
            </>
          ) : (
            <>
              <IconBan className="h-4 w-4 text-destructive" />
              <Badge variant="destructive">{t("rules.block")}</Badge>
            </>
          )}
        </div>
      ),
    },
    {
      key: "name",
      title: t("rules.name"),
      render: (row: Rule) => (
        <span className="font-medium">{row.name || "-"}</span>
      ),
    },
    {
      key: "detail",
      title: t("rules.detail"),
      cellClassName: "max-w-md whitespace-normal",
      render: (row: Rule) => (
        <span className="block truncate text-xs text-muted-foreground">
          {row.pattern || t("rules.compositeCondition")}
        </span>
      ),
    },
    {
      key: "updated_at",
      title: t("rules.updatedAt"),
      width: "160px",
      render: (row: Rule) =>
        row.updated_at ? row.updated_at.slice(0, 19).replace("T", " ") : "-",
    },
    {
      key: "action",
      title: t("rules.action"),
      width: "120px",
      render: (row: Rule) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => handleEdit(row)}
            disabled={!canManage || ruleMutationLoading || deleteLoading}
            title={t("common.edit")}
          >
            <IconPencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => handleDelete(row.id)}
            disabled={!canManage || ruleMutationLoading || deleteLoading}
            title={t("common.delete")}
          >
            <IconTrash className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("rules.title")}
        description={t("rules.description")}
        actions={
          <>
            <input
              ref={fileInputRef}
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(event) => handleImport(event.target.files?.[0] ?? null)}
            />
            <Button
              variant="outline"
              disabled={!effectivePolicyId || !canManage || exporting}
              title={t("rules.exportTitle")}
              onClick={handleExport}
            >
              {exporting ? (
                t("common.processing")
              ) : (
                <>
                  <IconDownload className="mr-1 h-4 w-4" />
                  {t("rules.export")}
                </>
              )}
            </Button>
            <Button
              variant="outline"
              disabled={!effectivePolicyId || !canManage || importing}
              title={t("rules.importTitle")}
              onClick={() => fileInputRef.current?.click()}
            >
              {importing ? (
                t("common.processing")
              ) : (
                <>
                  <IconUpload className="mr-1 h-4 w-4" />
                  {t("rules.import")}
                </>
              )}
            </Button>
            <Button
              disabled={!effectivePolicyId || !canManage}
              onClick={() => {
                setEditingRule(null)
                setDialogOpen(true)
              }}
            >
              <IconPlus className="h-4 w-4" />
              {t("rules.addTitle")}
            </Button>
          </>
        }
      />

      {pageError && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {pageError instanceof Error
              ? pageError.message
              : t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}

      {!authLoading && !canManage && (
        <Alert>
          <AlertTitle>{t("common.readOnlyHint")}</AlertTitle>
          <AlertDescription>{t("rules.readOnlyHint")}</AlertDescription>
        </Alert>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={effectivePolicyId ? String(effectivePolicyId) : ""}
          onValueChange={(v) => {
            setPolicyId(Number(v))
            setPage(1)
          }}
        >
          <SelectTrigger className="w-64">
            <SelectValue
              placeholder={t("rules.policyPlaceholder", {
                defaultValue: "选择策略",
              })}
            />
          </SelectTrigger>
          <SelectContent>
            {policies.map((policy) => (
              <SelectItem key={policy.id} value={String(policy.id)}>
                {policy.name}
                {policy.is_default
                  ? ` (${t("common.default", { defaultValue: "默认" })})`
                  : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={filterType}
          onValueChange={(v) => {
            setFilterType(v as RuleActionFilter)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-32">
            <SelectValue placeholder={t("rules.allTypes")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("common.all")}</SelectItem>
            <SelectItem value="allow">{t("rules.allow")}</SelectItem>
            <SelectItem value="intercept">{t("rules.block")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        data={rules}
        loading={(isLoading || policiesLoading) && rules.length === 0}
        rowKey={(row) => row.id}
        emptyText={t("rules.empty")}
        emptyContent={
          <EmptyState
            icon={IconListDetails}
            title={t("rules.empty")}
            description={t(
              "rules.emptyHint",
              "添加自定义黑白名单规则，精准控制站点的访问策略"
            )}
            action={
              <Button
                disabled={!effectivePolicyId || !canManage}
                onClick={() => {
                  setEditingRule(null)
                  setDialogOpen(true)
                }}
              >
                <IconPlus className="mr-1.5 h-4 w-4" />
                {t("rules.addTitle")}
              </Button>
            }
            className="py-20"
          />
        }
      />

      <TablePagination
        page={page}
        pageSize={PAGE_SIZE}
        total={total}
        disabled={isLoading}
        onPageChange={setPage}
      />

      {dialogOpen && (
        <RuleFormDialog
          open={dialogOpen}
          onOpenChange={(open) => {
            setDialogOpen(open)
            if (!open) setEditingRule(null)
          }}
          rule={editingRule}
          policyId={effectivePolicyId}
        />
      )}

      <ConfirmDialog
        open={!!deleteId}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("common.confirmDeleteTitle")}
        description={t("rules.deleteConfirmDescription")}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  )
}
