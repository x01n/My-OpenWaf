"use client"

import { useCallback, useEffect, useId, useState } from "react"
import { useSearchParams } from "next/navigation"
import {
  AlertTriangle,
  BookOpen,
  ExternalLink,
  Pencil,
  Plus,
  Trash2,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import Link from "next/link"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import { Button } from "@/components/ui/button"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState, PageIntro, Surface } from "@/components/console-shell"
import {
  createPolicy,
  deletePolicy,
  getConfigAppliedReloadFailureDetails,
  getConfigAppliedReloadFailureItem,
  getPolicies,
  getPolicy,
  getRules,
  isConfigAppliedReloadFailureError,
  listAllSites,
  type Policy,
  type Site,
  updatePolicy,
} from "@/lib/api"
import { formatDate } from "@/lib/utils"
import { Pagination } from "@/components/pagination"
import { Separator } from "@/components/ui/separator"
import { CopyableBlock } from "@/components/log-presentation"

const POLICY_PAGE_SIZE = 20

interface PolicyWithMeta extends Policy {
  rules_total: number
}

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

export default function PoliciesPage() {
  const formIdPrefix = useId()
  const searchParams = useSearchParams()
  const [policies, setPolicies] = useState<PolicyWithMeta[]>([])
  const [sites, setSites] = useState<Site[]>([])
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [isNew, setIsNew] = useState(false)
  const [editName, setEditName] = useState("")
  const [editDesc, setEditDesc] = useState("")
  const [editId, setEditId] = useState<number | null>(null)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<PolicyWithMeta | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [loadingEditId, setLoadingEditId] = useState<number | null>(null)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  const load = useCallback(
    async (targetPage = page) => {
      setLoading(true)
      try {
        const [policyData, siteData] = await Promise.all([
          getPolicies({ page: targetPage, page_size: POLICY_PAGE_SIZE }),
          listAllSites(),
        ])
        const nextTotal = Number(policyData.total) || 0
        const nextTotalPages = Math.max(
          1,
          Math.ceil(nextTotal / POLICY_PAGE_SIZE)
        )
        if (targetPage > nextTotalPages) {
          setPage(nextTotalPages)
          return
        }
        const policyItems = policyData.items || []
        const ruleCountResults = await Promise.all(
          policyItems.map(async (policy) => {
            const result = await getRules({
              policy_id: policy.id,
              page: 1,
              page_size: 1,
            })
            return [policy.id, Number(result.total) || 0] as const
          })
        )
        const ruleCountMap = new Map(ruleCountResults)
        setPolicies(
          policyItems.map((policy) => ({
            ...policy,
            rules_total: ruleCountMap.get(policy.id) ?? 0,
          }))
        )
        setTotal(nextTotal)
        setSites(siteData.items || [])
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "加载策略列表失败")
        setPolicies([])
        setTotal(0)
      } finally {
        setLoading(false)
      }
    },
    [page]
  )

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  const totalPages = Math.max(1, Math.ceil(total / POLICY_PAGE_SIZE))

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  function rememberPolicyReloadFailureOperation(
    error: unknown,
    operation: "create" | "update",
    payload: Record<string, unknown>,
    policyId?: number | null
  ) {
    const item = getConfigAppliedReloadFailureItem<Policy>(error)
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    setOperationDetails({
      operation,
      policy_id: policyId ?? item?.id ?? null,
      payload,
      response: {
        item,
        reload_failed: true,
        reload_error: error instanceof Error ? error.message : null,
        reload_failure: details,
      },
    })
  }

  function sitesForPolicy(policyId: number): Site[] {
    return sites.filter((s) => s.policy_id === policyId)
  }

  function openNew() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setIsNew(true)
    setEditName("")
    setEditDesc("")
    setEditId(null)
    setDialogOpen(true)
  }

  async function openEdit(p: PolicyWithMeta) {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setLoadingEditId(p.id)
    try {
      const detail = await getPolicy(p.id)
      setIsNew(false)
      setEditName(detail.name)
      setEditDesc(detail.description || "")
      setEditId(detail.id)
      setDialogOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载策略详情失败")
    } finally {
      setLoadingEditId(null)
    }
  }

  async function handleSave() {
    if (!editName.trim()) {
      toast.error("请输入策略名称")
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    const payload = {
      name: editName,
      description: editDesc,
    }
    try {
      if (isNew) {
        const result = await createPolicy(payload)
        setOperationDetails({
          operation: "create",
          payload,
          response: result,
        })
        toast.success("策略已创建")
      } else {
        const result = await updatePolicy(editId!, payload)
        setOperationDetails({
          operation: "update",
          policy_id: editId!,
          payload,
          response: result,
        })
        toast.success("策略已更新")
      }
      setDialogOpen(false)
      void load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        rememberPolicyReloadFailureOperation(
          e,
          isNew ? "create" : "update",
          payload,
          isNew ? null : editId
        )
        setDialogOpen(false)
        void load()
      }
      toast.error(e instanceof Error ? e.message : "保存策略失败")
    } finally {
      setSaving(false)
    }
  }

  function deleteTargetSites() {
    return deleteTarget ? sitesForPolicy(deleteTarget.id) : []
  }

  async function handleDelete() {
    if (!deleteTarget) return
    const target = deleteTarget
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setDeleting(true)
    try {
      await deletePolicy(target.id)
      setOperationDetails({
        operation: "delete",
        policy_id: target.id,
        payload: {
          policy_id: target.id,
          name: target.name,
        },
        status_code: 204,
        response: null,
      })
      toast.success("策略已删除")
      setDeleteTarget(null)
      void load()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setOperationDetails({
            operation: "delete",
            policy_id: target.id,
            payload: {
              policy_id: target.id,
              name: target.name,
            },
            response: details,
          })
        }
        setDeleteTarget(null)
        void load()
      }
      toast.error(e instanceof Error ? e.message : "删除策略失败")
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Security Policies"
        title="策略管理"
        description="策略是规则的容器，一个站点绑定一个策略。在此管理策略及其规则分组。"
        actions={
          <Button onClick={openNew}>
            <Plus data-icon="inline-start" /> 创建策略
          </Button>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回策略操作响应体；请核对 item 或 error 字段。
          </AlertDescription>
          <CopyableBlock
            label="reload 失败响应体"
            value={JSON.stringify(reloadFailureDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {operationDetails ? (
        <Alert className="gap-3">
          <BookOpen />
          <AlertTitle>最近策略操作响应</AlertTitle>
          <AlertDescription>
            后端已返回策略操作响应体；请核对 operation、payload、response、
            policy_id 或 status_code 字段。
          </AlertDescription>
          <CopyableBlock
            label="策略操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <Surface
        title="策略列表"
        description="按后端分页读取安全策略、关联规则数量和绑定站点。"
      >
        {loading ? (
          <EmptyState
            title="策略列表加载中"
            description="正在读取策略、规则数量和关联站点。"
          />
        ) : policies.length === 0 ? (
          <EmptyState
            title="暂无策略"
            description="创建第一个策略后，可以在站点配置中将其关联。"
          />
        ) : (
          <div className="overflow-hidden rounded-xl border border-border">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/45 text-xs tracking-wider text-muted-foreground uppercase">
                  <TableHead className="w-16">ID</TableHead>
                  <TableHead>名称</TableHead>
                  <TableHead>描述</TableHead>
                  <TableHead className="w-24">规则数</TableHead>
                  <TableHead>关联站点</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead className="w-40 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p) => {
                  const linkedSites = sitesForPolicy(p.id)
                  return (
                    <TableRow key={p.id} className="hover:bg-muted/35">
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {p.id}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <BookOpen className="size-4 text-muted-foreground" />
                          <span className="font-medium text-foreground">
                            {p.name}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-sm text-muted-foreground">
                        {p.description || "-"}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="rounded-md font-mono"
                        >
                          {p.rules_total}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {linkedSites.length === 0 ? (
                          <span className="text-xs text-muted-foreground">
                            未绑定
                          </span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {linkedSites.map((s) => (
                              <Badge
                                key={s.id}
                                variant="outline"
                                className="rounded-md text-xs"
                              >
                                {s.host}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(p.created_at)}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            asChild
                          >
                            <Link href={`/rules/?policy_id=${p.id}`}>
                              <ExternalLink data-icon="inline-start" /> 管理规则
                            </Link>
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            onClick={() => void openEdit(p)}
                            disabled={loadingEditId === p.id}
                            aria-label="编辑策略"
                          >
                            <Pencil data-icon="inline-start" />
                          </Button>
                          <Button
                            variant="destructive"
                            size="icon-sm"
                            onClick={() => {
                              setReloadFailureDetails(null)
                              setOperationDetails(null)
                              setDeleteTarget(p)
                            }}
                            aria-label="删除策略"
                          >
                            <Trash2 data-icon="inline-start" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
            {total > POLICY_PAGE_SIZE ? (
              <>
                <Separator />
                <div className="bg-muted/20 px-4 py-3">
                  <Pagination
                    page={page}
                    totalPages={totalPages}
                    total={total}
                    pageSize={POLICY_PAGE_SIZE}
                    onPageChange={setPage}
                  />
                </div>
              </>
            ) : null}
          </div>
        )}
      </Surface>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>{isNew ? "创建策略" : "编辑策略"}</DialogTitle>
            <DialogDescription>
              {isNew
                ? "创建新的安全策略以组织规则集。"
                : "修改策略名称和描述。"}
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor={`${formIdPrefix}-name`}>策略名称</FieldLabel>
              <Input
                id={`${formIdPrefix}-name`}
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                placeholder="例如：核心应用默认策略"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor={`${formIdPrefix}-description`}>
                描述
              </FieldLabel>
              <Textarea
                id={`${formIdPrefix}-description`}
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                placeholder="策略用途说明（可选）"
                rows={3}
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              取消
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? "保存中..." : isNew ? "创建" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open && !deleting) setDeleteTarget(null)
        }}
      >
        <AlertDialogContent className="max-w-md rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除策略</AlertDialogTitle>
            <AlertDialogDescription>
              后端会拒绝删除仍被站点引用的策略；未被引用的策略删除后不可恢复。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Alert variant="destructive">
            <Trash2 />
            <AlertDescription className="flex flex-col gap-1">
              <span>目标策略：{deleteTarget?.name || "-"}</span>
              <span>当前绑定站点：{deleteTargetSites().length} 个</span>
              <span>当前规则数：{deleteTarget?.rules_total ?? 0} 条</span>
              {deleteTargetSites().length > 0 && (
                <span className="break-all">
                  {deleteTargetSites()
                    .map((site) => site.host || `站点 #${site.id}`)
                    .join("，")}
                </span>
              )}
              <span className="pt-1 text-xs">
                当前绑定站点来自后端分页全量读取；删除结果仍以后端校验为准。
              </span>
            </AlertDescription>
          </Alert>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault()
                void handleDelete()
              }}
            >
              {deleting ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
