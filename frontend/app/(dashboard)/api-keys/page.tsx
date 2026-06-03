"use client"

import { useEffect, useState } from "react"
import { Copy, KeyRound, Plus, Trash2, AlertTriangle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
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
  ConsoleTableShell,
  EmptyState,
  PageIntro,
} from "@/components/console-shell"
import { createAPIKey, getAPIKeys, removeAPIKey, type APIKey } from "@/lib/api"
import { formatDate } from "@/lib/utils"

function maskToken(token?: string): string {
  if (!token) return "••••••••••••••••"
  if (token.length <= 8) return "••••" + token.slice(-4)
  return token.slice(0, 4) + "••••••••" + token.slice(-4)
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

  function load() {
    setLoading(true)
    getAPIKeys()
      .then((data) => setKeys(data.items || []))
      .catch((e) => toast.error(String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
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
      setNewKeyName("")
      toast.success("密钥已创建，请立即复制明文 Token。")
      load()
    } catch (e) {
      toast.error(String(e))
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await removeAPIKey(deleteTarget.id)
      toast.success("API 密钥已删除")
      setDeleteTarget(null)
      load()
    } catch (e) {
      toast.error(String(e))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Automation Access"
        title="API 密钥"
        description="为自动化任务、CI/CD 或运维脚本生成 Bearer Token。创建后仅返回一次明文 Token。"
        actions={
          <Button
            className="gap-2 rounded-md bg-teal-500 text-white hover:bg-teal-600"
            onClick={() => {
              setDialogOpen(true)
              setCreatedToken(null)
              setNewKeyName("")
            }}
          >
            <Plus className="h-4 w-4" /> 创建密钥
          </Button>
        }
      />

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
              <TableRow key={item.id} className="hover:bg-slate-50">
                <TableCell className="px-4 py-3 font-mono text-xs text-slate-500">
                  {item.id}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <KeyRound className="h-4 w-4 text-slate-600" />
                    <span className="font-medium text-slate-900">
                      {item.name}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="px-4 py-3">
                  <code className="rounded-lg bg-slate-100 px-2 py-1 font-mono text-xs text-slate-500">
                    {maskToken(item.token)}
                  </code>
                </TableCell>
                <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-slate-500">
                  {formatDate(item.created_at)}
                </TableCell>
                <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-slate-500">
                  {item.last_used_at
                    ? formatDate(item.last_used_at)
                    : "从未使用"}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1">
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="text-destructive"
                      onClick={() => setDeleteTarget(item)}
                      aria-label="删除 API 密钥"
                    >
                      <Trash2 />
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
            <div className="space-y-4">
              <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/90 px-3 py-2 text-xs text-amber-800">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>请立即复制此 Token，关闭后将无法再次查看明文。</span>
              </div>
              <div className="flex gap-2 rounded-xl border border-slate-200/80 bg-slate-50/80 p-3">
                <code className="flex-1 text-xs break-all text-slate-700">
                  {createdToken}
                </code>
                <Button
                  variant="outline"
                  size="icon-sm"
                  className="shrink-0 rounded-lg"
                  onClick={() => {
                    navigator.clipboard.writeText(createdToken)
                    toast.success("已复制到剪贴板")
                  }}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <Label htmlFor="api-key-name">密钥名称</Label>
              <Input
                id="api-key-name"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="例如：CI Deploy / Terraform / Alert Sync"
                className="rounded-lg"
                onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              />
            </div>
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
      <Dialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>确认删除 API 密钥</DialogTitle>
            <DialogDescription>
              删除后该密钥将立即失效，相关自动化任务需要改用新的 Token。
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-xl border border-rose-200 bg-rose-50/90 px-4 py-4 text-sm leading-6 text-rose-900">
            目标密钥：{deleteTarget?.name || "-"}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button
              className="bg-rose-600 hover:bg-rose-500"
              disabled={deleting}
              onClick={handleDelete}
            >
              {deleting ? "删除中..." : "删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
