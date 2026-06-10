"use client"

import { useEffect, useState } from "react"
import { Copy, KeyRound, Plus, Trash2, AlertTriangle } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
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
import {
  ConsoleTableShell,
  EmptyState,
  PageIntro,
} from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"
import { createAPIKey, getAPIKeys, removeAPIKey, type APIKey } from "@/lib/api"
import { formatDate } from "@/lib/utils"

function maskToken(token?: string): string {
  if (!token) return "••••••••••••••••"
  if (token.length <= 8) return "••••" + token.slice(-4)
  return token.slice(0, 4) + "••••••••" + token.slice(-4)
}

function apiKeyResponseSummary(response: { id: number; name: string; token?: string }) {
  return {
    id: response.id,
    name: response.name,
    token_masked: maskToken(response.token),
    token_returned_once: Boolean(response.token),
  }
}

export default function APIKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [newKeyName, setNewKeyName] = useState("")
  const [createdToken, setCreatedToken] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<APIKey | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  function load() {
    setLoading(true)
    getAPIKeys()
      .then((data) => setKeys(data.items || []))
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载 API 密钥失败")
      )
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    return deferEffect(load)
  }, [])

  async function handleCreate() {
    if (!newKeyName.trim()) {
      toast.error("请输入密钥名称")
      return
    }
    setCreating(true)
    try {
      const response = await createAPIKey(newKeyName)
      setCreatedToken(response.token || null)
      setOperationDetails({
        operation: "create",
        payload: {
          name: newKeyName,
        },
        response: apiKeyResponseSummary(response),
      })
      setNewKeyName("")
      toast.success("密钥已创建，请立即复制明文 Token。")
      load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "创建 API 密钥失败")
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      const target = deleteTarget
      await removeAPIKey(target.id)
      setOperationDetails({
        operation: "delete",
        payload: {
          id: target.id,
          name: target.name,
        },
        status_code: 204,
        response: null,
      })
      toast.success("API 密钥已删除")
      setDeleteTarget(null)
      load()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除 API 密钥失败")
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Automation Access"
        title="API 密钥"
        description="为自动化任务、CI/CD 或运维脚本生成 Bearer Token。创建后仅返回一次明文 Token。"
        actions={
          <Button
            onClick={() => {
              setDialogOpen(true)
              setCreatedToken(null)
              setNewKeyName("")
            }}
          >
            <Plus data-icon="inline-start" /> 创建密钥
          </Button>
        }
      />

      {operationDetails ? (
        <Alert className="gap-3">
          <KeyRound />
          <AlertTitle>最近 API 密钥操作响应</AlertTitle>
          <AlertDescription>
            后端已返回 API 密钥操作结果；明文 Token 只在创建窗口展示，操作详情仅保留脱敏摘要。
          </AlertDescription>
          <CopyableBlock
            label="API 密钥操作详情"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <ConsoleTableShell
        title="密钥列表"
        description="当前账户下所有 API 密钥。"
        state={
          loading ? (
            <EmptyState
              title="API 密钥加载中"
              description="正在读取当前账户下的 API 密钥。"
            />
          ) : keys.length === 0 ? (
            <EmptyState
              title="还没有 API 密钥"
              description="创建后可用于自动化访问管理 API。建议按用途拆分，便于审计与吊销。"
            />
          ) : undefined
        }
      >
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground">
              <TableHead className="w-16 px-4 py-3">ID</TableHead>
              <TableHead className="px-4 py-3">名称</TableHead>
              <TableHead className="px-4 py-3">密钥</TableHead>
              <TableHead className="px-4 py-3">创建时间</TableHead>
              <TableHead className="px-4 py-3">最近使用</TableHead>
              <TableHead className="w-28 px-4 py-3 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {keys.map((item) => (
              <TableRow key={item.id} className="hover:bg-muted/35">
                <TableCell className="px-4 py-3 font-mono text-xs text-muted-foreground">
                  {item.id}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <KeyRound className="size-4 text-muted-foreground" />
                    <span className="font-medium text-foreground">
                      {item.name}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="px-4 py-3">
                  <code className="rounded-lg bg-muted px-2 py-1 font-mono text-xs text-muted-foreground">
                    {maskToken(item.token)}
                  </code>
                </TableCell>
                <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                  {formatDate(item.created_at)}
                </TableCell>
                <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                  {item.last_used_at
                    ? formatDate(item.last_used_at)
                    : "从未使用"}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1">
                    <Button
                      variant="destructive"
                      size="icon-sm"
                      onClick={() => setDeleteTarget(item)}
                      aria-label="删除 API 密钥"
                    >
                      <Trash2 data-icon="inline-start" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </ConsoleTableShell>

      {/* 创建 Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg rounded-lg">
          <DialogHeader>
            <DialogTitle>
              {createdToken ? "令牌已创建" : "创建 API 密钥"}
            </DialogTitle>
            <DialogDescription>
              {createdToken
                ? "请立即复制返回的明文 Token。"
                : "创建后仅会返回一次明文 Token。"}
            </DialogDescription>
          </DialogHeader>
          {createdToken ? (
            <div className="flex flex-col gap-4">
              <Alert>
                <AlertTriangle />
                <AlertDescription>
                  请立即复制此 Token，关闭后将无法再次查看明文。
                </AlertDescription>
              </Alert>
              <div className="flex gap-2 rounded-xl border border-border bg-muted/35 p-3">
                <code className="flex-1 text-xs break-all text-foreground">
                  {createdToken}
                </code>
                <Button
                  variant="outline"
                  size="icon-sm"
                  className="shrink-0"
                  aria-label="复制 API Token"
                  onClick={() => {
                    navigator.clipboard.writeText(createdToken)
                    toast.success("已复制到剪贴板")
                  }}
                >
                  <Copy data-icon="inline-start" />
                </Button>
              </div>
            </div>
          ) : (
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="api-key-name">密钥名称</FieldLabel>
                <Input
                  id="api-key-name"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="例如：CI Deploy / Terraform / Alert Sync"
                  onKeyDown={(e) => e.key === "Enter" && handleCreate()}
                />
              </Field>
            </FieldGroup>
          )}
          <DialogFooter>
            {createdToken ? (
              <Button onClick={() => setDialogOpen(false)}>完成</Button>
            ) : (
              <>
                <Button variant="outline" onClick={() => setDialogOpen(false)}>
                  取消
                </Button>
                <Button onClick={handleCreate} disabled={creating}>
                  {creating ? "创建中..." : "创建"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除确认 */}
      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open && !deleting) setDeleteTarget(null)
        }}
      >
        <AlertDialogContent className="max-w-md rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除 API 密钥</AlertDialogTitle>
            <AlertDialogDescription>
              删除后该密钥将立即失效，相关自动化任务需要改用新的 Token。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Alert variant="destructive">
            <AlertTriangle />
            <AlertDescription>
              目标密钥：{deleteTarget?.name || "-"}
            </AlertDescription>
          </Alert>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault()
                handleDelete()
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
