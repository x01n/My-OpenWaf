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
import type { Policy } from "@/lib/types"

export default function PoliciesPage() {
  const { t } = useTranslation()
  const { data: policies = [], isLoading, error, mutate } = usePolicies()
  const policyMutation = usePolicyMutation()
  const setDefault = usePolicySetDefault()
  const deletePolicy = usePolicyDelete()
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")

  const createPolicy = async () => {
    const trimmed = name.trim()
    if (!trimmed) {
      toast.error(
        t("policies.nameRequired", { defaultValue: "请输入策略名称" })
      )
      return
    }
    try {
      await policyMutation.execute({
        data: { name: trimmed, description: description.trim() },
      })
      setName("")
      setDescription("")
      await mutate()
      toast.success(t("policies.createSuccess", { defaultValue: "策略已创建" }))
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const makeDefault = async (policy: Policy) => {
    if (policy.is_default) return
    try {
      await setDefault.execute(policy.id)
      await mutate()
      toast.success(
        t("policies.defaultUpdated", { defaultValue: "默认策略已更新" })
      )
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const removePolicy = async (policy: Policy) => {
    if (policy.is_default) {
      toast.error(
        t("policies.defaultDeleteBlocked", { defaultValue: "默认策略不可删除" })
      )
      return
    }
    try {
      await deletePolicy.execute(policy.id)
      await mutate()
      toast.success(t("policies.deleteSuccess", { defaultValue: "策略已删除" }))
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
      render: (row: Policy) => (
        <div className="space-y-1">
          <div className="flex items-center gap-2 font-medium">
            {row.name}
            {row.is_default && (
              <Badge>{t("common.default", { defaultValue: "默认" })}</Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            {row.description || "-"}
          </p>
        </div>
      ),
    },
    {
      key: "counts",
      title: t("policies.refs", { defaultValue: "引用" }),
      width: "180px",
      render: (row: Policy) => (
        <div className="text-xs text-muted-foreground">
          {t("policies.siteRefs", { defaultValue: "站点" })}:{" "}
          {row.site_count ?? 0} ·{" "}
          {t("policies.ruleRefs", { defaultValue: "规则" })}:{" "}
          {row.rule_count ?? 0}
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
            disabled={row.is_default}
            onClick={() => makeDefault(row)}
          >
            <IconShieldCheck className="mr-1 h-4 w-4" />
            {t("policies.setDefault", { defaultValue: "设为默认" })}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={row.is_default}
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
        title={t("policies.title", { defaultValue: "策略管理" })}
        description={t("policies.description", {
          defaultValue: "管理站点继承的默认策略和自定义策略。",
        })}
        actions={
          <Button variant="outline" onClick={() => mutate()}>
            <IconRefresh className="mr-1 h-4 w-4" />
            {t("common.refresh")}
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

      <Card>
        <CardHeader>
          <CardTitle>
            {t("policies.create", { defaultValue: "新增策略" })}
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] md:items-end">
          <div className="space-y-1.5">
            <Label>{t("common.name")}</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Default"
            />
          </div>
          <div className="space-y-1.5">
            <Label>{t("common.description", { defaultValue: "描述" })}</Label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={1}
            />
          </div>
          <Button onClick={createPolicy} disabled={policyMutation.loading}>
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
        emptyText={t("policies.empty", { defaultValue: "暂无策略" })}
      />
    </div>
  )
}
