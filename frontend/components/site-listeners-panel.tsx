"use client"

import { useCallback, useEffect, useId, useState } from "react"
import {
  AlertTriangle,
  Info,
  Loader2,
  Lock,
  Pencil,
  Plus,
  Trash2,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
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
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
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
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Surface } from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"
import {
  createSiteListener,
  deleteSiteListener,
  getConfigAppliedReloadFailureDetails,
  getConfigAppliedReloadFailureItem,
  isConfigAppliedReloadFailureError,
  listAllCertificates,
  listSiteListeners,
  updateSiteListener,
  type Certificate,
  type SiteListener,
} from "@/lib/api"

interface SiteListenersPanelProps {
  siteId: number
  onChanged?: () => void
}

interface DialogDraft {
  bind: string
  network: string
  tlsEnabled: boolean
  certId: number | null
  note: string
  enabled: boolean
}

const emptyDraft: DialogDraft = {
  bind: ":80",
  network: "tcp",
  tlsEnabled: false,
  certId: null,
  note: "",
  enabled: true,
}

function isListenerEnabled(listener: Pick<SiteListener, "enabled">) {
  return listener.enabled !== false
}

function normalizeSimpleListenerBind(value: string) {
  const trimmed = value.trim()
  const match = trimmed.match(/^:?(\d+)$/)
  if (!match) return { bind: trimmed, error: "" }
  const port = Number(match[1])
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { bind: trimmed, error: `监听端口无效：${trimmed}` }
  }
  return { bind: `:${port}`, error: "" }
}

export function SiteListenersPanel({
  siteId,
  onChanged,
}: SiteListenersPanelProps) {
  const formIdPrefix = useId()
  const [items, setItems] = useState<SiteListener[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<SiteListener | null>(null)
  const [draft, setDraft] = useState<DialogDraft>(emptyDraft)
  const [saving, setSaving] = useState(false)
  const [certificates, setCertificates] = useState<Certificate[]>([])
  const [deleteTarget, setDeleteTarget] = useState<SiteListener | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const data = await listSiteListeners(siteId)
      setItems(data.items || [])
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载监听端口失败")
      setItems([])
    } finally {
      setLoading(false)
    }

    try {
      const data = await listAllCertificates()
      setCertificates(data.items || [])
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载证书列表失败")
      setCertificates([])
    }
  }, [siteId])

  useEffect(() => {
    return deferEffect(refresh)
  }, [refresh])

  const refreshAfterAppliedReloadFailure = useCallback(async () => {
    await refresh()
    onChanged?.()
  }, [onChanged, refresh])

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  function rememberListenerReloadFailureOperation(
    error: unknown,
    operation: string,
    payload: Partial<SiteListener>,
    listenerId?: number
  ) {
    const listener = getConfigAppliedReloadFailureItem<
      SiteListener | Record<string, unknown>
    >(error)
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    setOperationDetails({
      operation,
      site_id: siteId,
      listener_id: listenerId,
      payload,
      response: {
        listener,
        reload_failed: true,
        reload_error: error instanceof Error ? error.message : null,
        reload_failure: details,
      },
    })
  }

  function openCreate() {
    setReloadFailureDetails(null)
    setEditing(null)
    setDraft(emptyDraft)
    setDialogOpen(true)
  }

  function openEdit(listener: SiteListener) {
    setReloadFailureDetails(null)
    setEditing(listener)
    setDraft({
      bind: listener.bind || "",
      network: listener.network || "tcp",
      tlsEnabled: !!listener.tls_enabled,
      certId: listener.cert_id ?? null,
      note: listener.note || "",
      enabled: isListenerEnabled(listener),
    })
    setDialogOpen(true)
  }

  function setProtocol(nextTLS: boolean) {
    setDraft((current) => ({
      ...current,
      tlsEnabled: nextTLS,
      bind:
        current.bind && current.bind !== ":80" && current.bind !== ":443"
          ? current.bind
          : nextTLS
            ? ":443"
            : ":80",
      certId: nextTLS ? current.certId : null,
    }))
  }

  async function submit() {
    const normalizedBind = normalizeSimpleListenerBind(draft.bind)
    const bind = normalizedBind.bind
    if (!bind) {
      toast.error("请输入监听地址")
      return
    }
    if (normalizedBind.error) {
      toast.error(normalizedBind.error)
      return
    }
    if (
      items.some(
        (listener) =>
          listener.id > 0 &&
          listener.id !== editing?.id &&
          normalizeSimpleListenerBind(listener.bind).bind === bind
      )
    ) {
      toast.error(`监听地址重复：${bind}`)
      return
    }
    if (draft.tlsEnabled && !draft.certId) {
      toast.error("启用 HTTPS 时请选择证书")
      return
    }
    if (
      draft.tlsEnabled &&
      draft.certId &&
      !certificates.some((cert) => cert.id === draft.certId)
    ) {
      toast.error("当前绑定的证书不在可用证书列表中，请重新选择证书")
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    const payload: Partial<SiteListener> = {
      bind,
      network: draft.network,
      tls_enabled: draft.tlsEnabled,
      cert_id: draft.tlsEnabled ? draft.certId : null,
      enabled: draft.enabled,
      note: draft.note.trim(),
    }
    const operation = editing && editing.id !== 0 ? "update" : "create"
    const listenerId =
      editing && editing.id !== 0 ? editing.id : undefined
    try {
      if (editing && editing.id !== 0) {
        const result = await updateSiteListener(siteId, editing.id, payload)
        setOperationDetails({
          operation,
          site_id: siteId,
          listener_id: editing.id,
          payload,
          response: result,
        })
        toast.success("监听端口已更新")
      } else {
        const result = await createSiteListener(siteId, payload)
        setOperationDetails({
          operation,
          site_id: siteId,
          payload,
          response: result,
        })
        toast.success(editing ? "旧配置已保存为正式监听" : "监听端口已创建")
      }
      setDialogOpen(false)
      await refresh()
      onChanged?.()
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        rememberListenerReloadFailureOperation(
          error,
          operation,
          payload,
          listenerId
        )
        setDialogOpen(false)
        await refreshAfterAppliedReloadFailure()
      }
      toast.error(error instanceof Error ? error.message : "保存失败")
    } finally {
      setSaving(false)
    }
  }

  async function toggleEnabled(listener: SiteListener, enabled: boolean) {
    if (listener.id === 0) {
      toast.error("旧配置请先点击编辑保存为正式监听")
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const payload = {
      bind: listener.bind,
      network: listener.network || "tcp",
      tls_enabled: listener.tls_enabled,
      cert_id: listener.cert_id ?? null,
      enabled,
      note: listener.note || "",
    }
    try {
      const result = await updateSiteListener(siteId, listener.id, payload)
      setOperationDetails({
        operation: "toggle",
        site_id: siteId,
        listener_id: listener.id,
        payload,
        response: result,
      })
      await refresh()
      onChanged?.()
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        rememberListenerReloadFailureOperation(
          error,
          "toggle",
          payload,
          listener.id
        )
        await refreshAfterAppliedReloadFailure()
      }
      toast.error(error instanceof Error ? error.message : "更新失败")
    }
  }

  function requestRemove(listener: SiteListener) {
    if (listener.id === 0) {
      toast.error("旧配置无法直接删除，请先创建新的监听端口")
      return
    }
    setReloadFailureDetails(null)
    setDeleteTarget(listener)
  }

  async function remove() {
    if (!deleteTarget) return
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setDeleting(true)
    try {
      await deleteSiteListener(siteId, deleteTarget.id)
      setOperationDetails({
        operation: "delete",
        site_id: siteId,
        listener_id: deleteTarget.id,
        payload: {
          listener_id: deleteTarget.id,
          bind: deleteTarget.bind,
        },
        status_code: 204,
        response: null,
      })
      toast.success("监听端口已删除")
      setDeleteTarget(null)
      await refresh()
      onChanged?.()
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        rememberReloadFailureDetails(error)
        setDeleteTarget(null)
        await refreshAfterAppliedReloadFailure()
      }
      toast.error(error instanceof Error ? error.message : "删除失败")
    } finally {
      setDeleting(false)
    }
  }

  function certName(certId?: number | null) {
    if (!certId) return null
    const found = certificates.find((cert) => cert.id === certId)
    return found?.name || `#${certId}`
  }

  return (
    <Surface
      title="监听端口"
      description="一个站点可以同时监听多个端口（如同时启用 80 与 443），保存后自动热加载。"
      action={
        <Button className="rounded-md" onClick={openCreate}>
          <Plus data-icon="inline-start" />
          新增监听端口
        </Button>
      }
    >
      {reloadFailureDetails ? (
        <Alert className="mb-4 gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回监听端口操作响应体；请核对 item 或 error 字段。
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
        <Alert className="mb-4 gap-3">
          <Info />
          <AlertTitle>最近监听端口操作响应</AlertTitle>
          <AlertDescription>
            后端已返回监听端口操作结果；请核对 operation、payload、
            response、listener_id 或 status_code 字段。
          </AlertDescription>
          <CopyableBlock
            label="监听端口操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {loading ? (
        <div className="flex items-center justify-center rounded-lg border border-dashed bg-muted/35 py-10 text-sm text-muted-foreground">
          <Loader2 data-icon="inline-start" className="animate-spin" />
          加载中...
        </div>
      ) : items.length === 0 ? (
        <div className="rounded-lg border border-dashed bg-muted/35 p-8 text-center text-sm text-muted-foreground">
          暂无监听端口，点击右上角添加。
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="px-4 py-3">状态</TableHead>
                <TableHead className="px-4 py-3">监听地址</TableHead>
                <TableHead className="px-4 py-3">网络</TableHead>
                <TableHead className="px-4 py-3">协议</TableHead>
                <TableHead className="px-4 py-3">证书</TableHead>
                <TableHead className="px-4 py-3">备注</TableHead>
                <TableHead className="px-4 py-3 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((listener, index) => {
                const isLegacy = listener.note === "legacy" || listener.id === 0
                return (
                  <TableRow key={listener.id || `legacy-${index}`}>
                    <TableCell className="px-4 py-3">
                      <Switch
                        checked={isListenerEnabled(listener)}
                        onCheckedChange={(v) => toggleEnabled(listener, v)}
                        disabled={isLegacy}
                      />
                    </TableCell>
                    <TableCell className="px-4 py-3 font-mono text-xs text-foreground">
                      {listener.bind}
                    </TableCell>
                    <TableCell className="px-4 py-3 font-mono text-xs text-muted-foreground">
                      {listener.network || "tcp"}
                    </TableCell>
                    <TableCell className="px-4 py-3">
                      <Badge
                        variant={listener.tls_enabled ? "default" : "secondary"}
                        className="font-mono"
                      >
                        {listener.tls_enabled ? "HTTPS" : "HTTP"}
                      </Badge>
                    </TableCell>
                    <TableCell className="px-4 py-3 text-foreground">
                      {listener.tls_enabled ? (
                        <span className="inline-flex items-center gap-1.5">
                          <Lock className="size-3.5 text-muted-foreground" />
                          {certName(listener.cert_id) || (
                            <span className="text-destructive">未绑定</span>
                          )}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-muted-foreground">
                      {isLegacy ? (
                        <Badge variant="outline">旧配置</Badge>
                      ) : (
                        listener.note || (
                          <span className="text-muted-foreground">-</span>
                        )
                      )}
                    </TableCell>
                    <TableCell className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-md"
                          aria-label="编辑监听端口"
                          onClick={() => openEdit(listener)}
                        >
                          <Pencil data-icon="inline-start" />
                        </Button>
                        <Button
                          variant="destructive"
                          size="icon-sm"
                          className="rounded-md"
                          aria-label="删除监听端口"
                          onClick={() => requestRemove(listener)}
                          disabled={isLegacy}
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
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg overflow-y-auto rounded-lg p-0">
          <DialogHeader className="bg-card px-6 py-5 text-left">
            <DialogTitle className="text-xl font-semibold tracking-tight text-foreground">
              {editing?.id === 0
                ? "保存旧监听为正式监听"
                : editing
                  ? "编辑监听端口"
                  : "新增监听端口"}
            </DialogTitle>
            <DialogDescription className="text-sm text-muted-foreground">
              {editing?.id === 0
                ? "旧配置会创建为正式监听，之后可独立启停和删除。"
                : "监听 Bind、协议与证书信息会即时下发至数据面。"}
            </DialogDescription>
          </DialogHeader>
          <Separator />

          <FieldGroup className="px-6 py-6">
            <Field>
              <FieldLabel htmlFor={`${formIdPrefix}-bind`}>监听地址</FieldLabel>
              <Input
                id={`${formIdPrefix}-bind`}
                value={draft.bind}
                onChange={(e) => setDraft({ ...draft, bind: e.target.value })}
                placeholder=":80"
                className="rounded-lg font-mono"
              />
            </Field>

            <Field>
              <FieldLabel htmlFor={`${formIdPrefix}-network`}>
                网络类型
              </FieldLabel>
              <Select
                value={draft.network}
                onValueChange={(value) =>
                  setDraft({ ...draft, network: value })
                }
              >
                <SelectTrigger id={`${formIdPrefix}-network`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="tcp">TCP</SelectItem>
                    <SelectItem value="udp">UDP</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>

            <Field>
              <FieldLabel htmlFor={`${formIdPrefix}-protocol`}>
                接入协议
              </FieldLabel>
              <ToggleGroup
                id={`${formIdPrefix}-protocol`}
                type="single"
                value={draft.tlsEnabled ? "https" : "http"}
                onValueChange={(value) => {
                  if (!value) return
                  setProtocol(value === "https")
                }}
                variant="outline"
                spacing={0}
              >
                <ToggleGroupItem value="http">HTTP</ToggleGroupItem>
                <ToggleGroupItem value="https">HTTPS</ToggleGroupItem>
              </ToggleGroup>
            </Field>

            {draft.tlsEnabled ? (
              <Field>
                <FieldLabel htmlFor={`${formIdPrefix}-certificate`}>
                  TLS 证书
                </FieldLabel>
                <div className="flex flex-col gap-3 rounded-lg border bg-muted/35 p-3">
                  <Alert>
                    <Lock data-icon="inline-start" />
                    <AlertTitle>HTTPS 证书</AlertTitle>
                    <AlertDescription>
                      启用 HTTPS 时必须绑定证书。
                    </AlertDescription>
                  </Alert>
                  <Select
                    value={draft.certId ? String(draft.certId) : ""}
                    onValueChange={(value) =>
                      setDraft({
                        ...draft,
                        certId: value ? Number(value) : null,
                      })
                    }
                  >
                    <SelectTrigger id={`${formIdPrefix}-certificate`}>
                      <SelectValue
                        placeholder={
                          certificates.length ? "选择证书" : "当前没有可用证书"
                        }
                      />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {draft.certId &&
                          !certificates.some(
                            (cert) => cert.id === draft.certId
                          ) && (
                            <SelectItem value={String(draft.certId)}>
                              已失效证书 #{draft.certId}
                            </SelectItem>
                          )}
                        {certificates.map((cert) => (
                          <SelectItem key={cert.id} value={String(cert.id)}>
                            {cert.name}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>
              </Field>
            ) : null}

            <Field>
              <FieldLabel htmlFor={`${formIdPrefix}-note`}>备注</FieldLabel>
              <Input
                id={`${formIdPrefix}-note`}
                value={draft.note}
                onChange={(e) => setDraft({ ...draft, note: e.target.value })}
                placeholder="例如：管理后台专用端口"
                className="rounded-lg"
              />
            </Field>

            <Field
              orientation="horizontal"
              className="justify-between rounded-lg border bg-muted/35 px-4 py-3"
            >
              <FieldContent>
                <FieldLabel htmlFor={`${formIdPrefix}-enabled`}>
                  启用此监听
                </FieldLabel>
                <FieldDescription>
                  关闭后该端口将停止接收流量。
                </FieldDescription>
              </FieldContent>
              <Switch
                id={`${formIdPrefix}-enabled`}
                checked={draft.enabled}
                onCheckedChange={(v) => setDraft({ ...draft, enabled: v })}
              />
            </Field>
          </FieldGroup>

          <Separator />
          <DialogFooter className="bg-card px-6 py-4">
            <Button
              variant="outline"
              className="rounded-md"
              onClick={() => setDialogOpen(false)}
            >
              取消
            </Button>
            <Button onClick={submit} disabled={saving} className="rounded-md">
              {saving ? (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              ) : null}
              {saving
                ? "保存中..."
                : editing?.id === 0
                  ? "创建正式监听"
                  : editing
                    ? "保存修改"
                    : "创建监听"}
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
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除监听端口</AlertDialogTitle>
            <AlertDialogDescription>
              删除监听端口 {deleteTarget?.bind || "-"}{" "}
              后，该端口会立即停止接收流量并触发运行时配置热加载。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault()
                remove()
              }}
            >
              {deleting ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Surface>
  )
}
