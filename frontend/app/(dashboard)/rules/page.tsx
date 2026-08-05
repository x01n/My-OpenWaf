"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { useSearchParams } from "next/navigation"
import { PageHeader } from "@/components/page-header"
import {
  useDefaultPolicy,
  usePolicies,
  useRules,
  useRuleMutation,
  useRuleDelete,
} from "@/hooks/use-api"
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
} from "@tabler/icons-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { RuleFormDialog } from "./components/rule-form-dialog"
import { EmptyState } from "@/components/empty-state"
import type { Rule } from "@/lib/types"

/**
 * 黑白名单（自定义规则）列表页面
 * 支持规则筛选、启用/禁用、编辑、删除、添加操作
 */
export default function RulesPage() {
  const { t } = useTranslation()
  const searchParams = useSearchParams()
  const [filterType, setFilterType] = useState<"all" | "allow" | "block">("all")
  const [policyId, setPolicyId] = useState<number | undefined>(undefined)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const [deleteId, setDeleteId] = useState<number | null>(null)

  const { data: policies = [] } = usePolicies()
  const { data: defaultPolicy } = useDefaultPolicy()

  const initialPolicyId = useMemo(() => {
    const rawPolicyId = searchParams.get("policy_id")
    if (!rawPolicyId) return undefined
    const parsed = Number(rawPolicyId)
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined
  }, [searchParams])

  const effectivePolicyId = policyId ?? initialPolicyId ?? defaultPolicy?.id

  const { data, isLoading, error, mutate } = useRules(
    effectivePolicyId ? { policy_id: effectivePolicyId } : undefined
  )
  const { execute: mutateRule } = useRuleMutation()
  const { execute: deleteRule, loading: deleteLoading } = useRuleDelete()

  const rules = data?.items || []
  const filteredRules =
    filterType === "all" ? rules : rules.filter((r) => r.action === filterType)

  /** 切换规则启用状态 */
  const handleToggle = async (rule: Rule) => {
    try {
      await mutateRule({ id: rule.id, data: { enabled: !rule.enabled } })
      toast.success(
        t("rules.toggleSuccess", {
          action: rule.enabled ? t("common.disable") : t("common.enable"),
        })
      )
      mutate()
    } catch {
      toast.error(t("rules.toggleFailed"))
    }
  }

  /** 打开编辑弹窗 */
  const handleEdit = (rule: Rule) => {
    setEditingRule(rule)
    setDialogOpen(true)
  }

  /** 打开删除确认 */
  const handleDelete = (id: number) => {
    setDeleteId(id)
  }

  /** 确认删除 */
  const confirmDelete = async () => {
    if (!deleteId) return
    try {
      await deleteRule(deleteId)
      toast.success(t("rules.deleteSuccess"))
      setDeleteId(null)
      mutate()
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
      render: (row: Rule) => (
        <span className="truncate text-xs text-muted-foreground">
          {row.pattern || t("rules.compositeCondition")}
        </span>
      ),
    },
    {
      key: "hits",
      title: t("rules.hits"),
      width: "100px",
      render: () => "-",
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
            title={t("common.edit")}
          >
            <IconPencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => handleDelete(row.id)}
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
          <Button
            disabled={!effectivePolicyId}
            onClick={() => {
              setEditingRule(null)
              setDialogOpen(true)
            }}
          >
            <IconPlus className="h-4 w-4" />
            {t("rules.addTitle")}
          </Button>
        }
      />

      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {error.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={effectivePolicyId ? String(effectivePolicyId) : ""}
          onValueChange={(v) => setPolicyId(Number(v))}
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
          onValueChange={(v) => setFilterType(v as "all" | "allow" | "block")}
        >
          <SelectTrigger className="w-32">
            <SelectValue placeholder={t("rules.allTypes")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("common.all")}</SelectItem>
            <SelectItem value="allow">{t("rules.allow")}</SelectItem>
            <SelectItem value="block">{t("rules.block")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        data={filteredRules}
        loading={isLoading}
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

      <RuleFormDialog
        open={dialogOpen}
        onOpenChange={(open) => {
          setDialogOpen(open)
          if (!open) setEditingRule(null)
        }}
        rule={editingRule}
        policyId={effectivePolicyId}
      />

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
