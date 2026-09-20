"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  IconPlus,
  IconRefresh,
  IconShieldCheck,
  IconTrash,
} from "@tabler/icons-react"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import {
  usePolicies,
  usePolicyDelete,
  usePolicyMutation,
  usePolicySetDefault,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import type { Policy } from "@/lib/types"

export default function PoliciesPage() {
  const { t } = useTranslation()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const { data: policies = [], isLoading, error, mutate } = usePolicies()
  const policyMutation = usePolicyMutation()
  const setDefault = usePolicySetDefault()
  const deletePolicy = usePolicyDelete()
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")

  const createPolicy = async () => {
    if (!canManage) return
    const trimmed = name.trim()
    if (!trimmed) {
      toast.error(t("policies.nameRequired"))
      return
    }
    try {
      await policyMutation.execute({
        data: { name: trimmed, description: description.trim() },
      })
      setName("")
      setDescription("")
      await mutate()
      toast.success(t("policies.createSuccess"))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const makeDefault = async (policy: Policy) => {
    if (!canManage || policy.is_default) return
    try {
      await setDefault.execute(policy.id)
      await mutate()
      toast.success(t("policies.defaultUpdated"))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const removePolicy = async (policy: Policy) => {
    if (!canManage) return
    if (policy.is_default) {
      toast.error(t("policies.defaultDeleteBlocked"))
      return
    }
    try {
      await deletePolicy.execute(policy.id)
      await mutate()
      toast.success(t("policies.deleteSuccess"))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const columns = [
    {
      key: "name",
      title: t("common.name"),
      cellClassName: "max-w-[420px] whitespace-normal align-top",
      render: (row: Policy) => (
        <div className="min-w-0 space-y-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2 font-medium">
            <span className="min-w-0 break-all" title={row.name}>
              {row.name}
            </span>
            {row.is_default && <Badge>{t("common.default")}</Badge>}
          </div>
          <p
            className="line-clamp-2 text-xs leading-relaxed break-all text-muted-foreground"
            title={row.description || undefined}
          >
            {row.description || "-"}
          </p>
        </div>
      ),
    },
    {
      key: "counts",
      title: t("policies.refs"),
      width: "180px",
      render: (row: Policy) => (
        <div className="text-xs text-muted-foreground">
          {t("policies.siteRefs")}: {row.site_count ?? 0} ·{" "}
          {t("policies.ruleRefs")}: {row.rule_count ?? 0}
        </div>
      ),
    },
    {
      key: "actions",
      title: t("common.action"),
      width: "220px",
      render: (row: Policy) => (
        <div className="flex justify-end gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={!canManage || row.is_default || setDefault.loading}
            onClick={() => makeDefault(row)}
          >
            <IconShieldCheck className="mr-1 h-4 w-4" />
            {t("policies.setDefault")}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={!canManage || row.is_default || deletePolicy.loading}
            onClick={() => removePolicy(row)}
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
        title={t("policies.title")}
        description={t("policies.description")}
        actions={
          <Button
            variant="outline"
            onClick={() => mutate()}
            disabled={isLoading || policyMutation.loading}
          >
            <IconRefresh className="mr-1 h-4 w-4" />
            {t("common.refresh")}
          </Button>
        }
      />

      {!authLoading && !canManage && (
        <Alert>
          <AlertDescription>{t("common.readOnlyHint")}</AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {error.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t("policies.create")}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] md:items-end">
          <div className="space-y-1.5">
            <Label>{t("common.name")}</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={!canManage}
              placeholder={t("policies.namePlaceholder")}
            />
          </div>
          <div className="space-y-1.5">
            <Label>{t("common.description")}</Label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={!canManage}
              rows={1}
            />
          </div>
          <Button
            onClick={createPolicy}
            disabled={!canManage || policyMutation.loading || !name.trim()}
          >
            <IconPlus className="mr-1 h-4 w-4" />
            {t("common.add")}
          </Button>
        </CardContent>
      </Card>

      <DataTable
        columns={columns}
        data={policies}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("policies.empty")}
      />
    </div>
  )
}
