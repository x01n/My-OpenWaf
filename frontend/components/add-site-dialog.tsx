"use client"

import { useEffect, useId, useState } from "react"
import { Loader2, Lock, Plus, Trash2 } from "@/lib/icons"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldTitle,
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
import {
  createSite,
  createSiteListener,
  getConfigAppliedReloadFailureDetails,
  getConfigAppliedReloadFailureItem,
  isConfigAppliedReloadFailureError,
  listAllCertificates,
  type Certificate,
  type Site,
  type SiteListener,
} from "@/lib/api"
import {
  findInvalidSiteUpstream,
  serializeSiteUpstreams,
} from "@/lib/site-upstreams"
import { MultiHostInput } from "@/components/multi-host-input"

interface AddSiteDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess: () => void
  onReloadFailureDetails?: (details: Record<string, unknown> | null) => void
  onOperationDetails?: (details: Record<string, unknown> | null) => void
}

interface ListenerEntry {
  port: string
  tls: boolean
}

const defaultUpstream = "http://127.0.0.1:8080"

function getPersistedSiteIdFromError(error: unknown) {
  const item = getConfigAppliedReloadFailureItem<Partial<Site>>(error)
  return typeof item?.id === "number" && item.id > 0 ? item.id : null
}

export function AddSiteDialog({
  open,
  onOpenChange,
  onSuccess,
  onReloadFailureDetails,
  onOperationDetails,
}: AddSiteDialogProps) {
  const certificateId = useId()
  const [hosts, setHosts] = useState<string[]>([])
  const [listeners, setListeners] = useState<ListenerEntry[]>([
    { port: "80", tls: false },
  ])
  const [certId, setCertId] = useState<number | null>(null)
  const [upstreams, setUpstreams] = useState<string[]>([defaultUpstream])
  const [saving, setSaving] = useState(false)
  const [certificates, setCertificates] = useState<Certificate[]>([])

  const hasAnyTLS = listeners.some((l) => l.tls)

  useEffect(() => {
    if (!open) return
    listAllCertificates()
      .then((data) => setCertificates(data.items || []))
      .catch((error) => {
        toast.error(error instanceof Error ? error.message : "加载证书列表失败")
        setCertificates([])
      })
  }, [open])

  function reset() {
    setHosts([])
    setListeners([{ port: "80", tls: false }])
    setCertId(null)
    setUpstreams([defaultUpstream])
  }

  function close(nextOpen: boolean) {
    if (!nextOpen) reset()
    onOpenChange(nextOpen)
  }

  function addListener() {
    setListeners((prev) => [...prev, { port: "443", tls: true }])
  }

  function removeListener(index: number) {
    setListeners((prev) => prev.filter((_, i) => i !== index))
  }

  function updateListener(index: number, patch: Partial<ListenerEntry>) {
    setListeners((prev) =>
      prev.map((l, i) => (i === index ? { ...l, ...patch } : l))
    )
  }

  function updateUpstream(index: number, value: string) {
    setUpstreams((current) =>
      current.map((item, itemIndex) => (itemIndex === index ? value : item))
    )
  }

  function removeUpstream(index: number) {
    setUpstreams((current) =>
      current.filter((_, itemIndex) => itemIndex !== index)
    )
  }

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      onReloadFailureDetails?.(details)
    }
  }

  async function handleSubmit() {
    const normalizedUpstreams = upstreams
      .map((item) => item.trim())
      .filter(Boolean)
    const invalidUpstream = findInvalidSiteUpstream(normalizedUpstreams)

    if (hosts.length === 0) {
      toast.error("请至少添加一个域名")
      return
    }
    const normalizedHost = hosts.join(", ")
    if (listeners.length === 0) {
      toast.error("请至少添加一个监听端口")
      return
    }
    const normalizedListeners: ListenerEntry[] = []
    const usedPorts = new Set<string>()
    for (const l of listeners) {
      const portNum = Number(l.port)
      if (
        !l.port.trim() ||
        Number.isNaN(portNum) ||
        !Number.isInteger(portNum) ||
        portNum < 1 ||
        portNum > 65535
      ) {
        toast.error(`端口号无效：${l.port}`)
        return
      }
      const normalizedPort = String(portNum)
      if (usedPorts.has(normalizedPort)) {
        toast.error(`监听端口重复：${normalizedPort}`)
        return
      }
      usedPorts.add(normalizedPort)
      normalizedListeners.push({
        port: normalizedPort,
        tls: l.tls,
      })
    }
    if (normalizedUpstreams.length === 0) {
      toast.error("请至少填写一个上游地址")
      return
    }
    if (invalidUpstream) {
      toast.error(`上游地址格式无效：${invalidUpstream}`)
      return
    }
    if (hasAnyTLS && !certId) {
      toast.error("存在 HTTPS 端口时请选择证书")
      return
    }
    if (
      hasAnyTLS &&
      certId &&
      !certificates.some((certificate) => certificate.id === certId)
    ) {
      toast.error("当前选择的证书不在可用证书列表中，请重新选择证书")
      return
    }

    const primaryListener = normalizedListeners[0]
    const primaryTLS = primaryListener.tls
    const primaryBind = `:${primaryListener.port}`
    const sitePayload: Partial<Site> = {
      host: normalizedHost,
      bind: primaryBind,
      network: "tcp",
      tls_enabled: primaryTLS,
      cert_id: primaryTLS ? certId : null,
      upstream_urls: serializeSiteUpstreams(normalizedUpstreams),
      enabled: true,
      maintenance_enabled: false,
    }

    let persistedSiteId: number | null = null
    setSaving(true)
    onReloadFailureDetails?.(null)
    onOperationDetails?.(null)
    try {
      let reloadFailureMessage = ""
      let reloadFailureDetails: Record<string, unknown> | null = null
      let createdSite: Site | Partial<Site> | null = null
      const createdListeners: Array<SiteListener | Record<string, unknown>> = []
      const listenerPayloads: Array<Partial<SiteListener>> = []
      try {
        const siteRes = await createSite(sitePayload)
        persistedSiteId = siteRes.id
        createdSite = siteRes
      } catch (error) {
        if (!isConfigAppliedReloadFailureError(error)) {
          throw error
        }
        persistedSiteId = getPersistedSiteIdFromError(error)
        if (!persistedSiteId) {
          throw error
        }
        createdSite = getConfigAppliedReloadFailureItem<Partial<Site>>(error)
        reloadFailureDetails =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
        rememberReloadFailureDetails(error)
        reloadFailureMessage = error.message
      }

      if (normalizedListeners.length > 1 && persistedSiteId) {
        for (let i = 0; i < normalizedListeners.length; i++) {
          const l = normalizedListeners[i]
          const listenerPayload: Partial<SiteListener> = {
            bind: `:${l.port}`,
            network: "tcp",
            tls_enabled: l.tls,
            cert_id: l.tls ? certId : null,
            enabled: true,
            note: `${l.tls ? "HTTPS" : "HTTP"} :${l.port}`,
          }
          listenerPayloads.push(listenerPayload)
          try {
            const listener = await createSiteListener(
              persistedSiteId,
              listenerPayload
            )
            createdListeners.push(listener)
          } catch (error) {
            if (!isConfigAppliedReloadFailureError(error)) {
              throw error
            }
            const listener =
              getConfigAppliedReloadFailureItem<Record<string, unknown>>(error)
            if (listener) {
              createdListeners.push(listener)
            }
            if (!reloadFailureMessage) {
              reloadFailureMessage = error.message
            }
            reloadFailureDetails =
              reloadFailureDetails ??
              getConfigAppliedReloadFailureDetails<Record<string, unknown>>(
                error
              )
            rememberReloadFailureDetails(error)
          }
        }
      }

      onOperationDetails?.({
        operation: "create",
        site_id: persistedSiteId,
        host: normalizedHost,
        payload: {
          site: sitePayload,
          listeners: listenerPayloads,
        },
        response: {
          site: createdSite,
          listeners: createdListeners,
          reload_failed: Boolean(reloadFailureMessage),
          reload_error: reloadFailureMessage || null,
          reload_failure: reloadFailureDetails,
        },
      })
      if (reloadFailureMessage) {
        toast.error(reloadFailureMessage)
      } else {
        toast.success("站点已创建")
      }
      close(false)
      onSuccess()
    } catch (error) {
      if (persistedSiteId) {
        close(false)
        onSuccess()
      }
      toast.error(error instanceof Error ? error.message : "创建失败")
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-h-[88vh] max-w-2xl overflow-y-auto rounded-lg p-0">
        <DialogHeader className="bg-card px-6 py-5 text-left">
          <DialogTitle className="text-xl font-semibold tracking-tight text-foreground">
            添加应用
          </DialogTitle>
          <DialogDescription className="text-sm leading-6 text-muted-foreground">
            配置域名、监听端口与上游服务器。支持同一站点监听多个端口。
          </DialogDescription>
        </DialogHeader>
        <Separator />

        <div className="flex flex-col gap-6 px-6 py-6">
          {/* Domain(s) */}
          <Field>
            <FieldTitle>
              域名 <span className="text-destructive">*</span>
              <FieldDescription className="ms-2">
                支持多域名 &amp; 泛域名
              </FieldDescription>
            </FieldTitle>
            <MultiHostInput hosts={hosts} onChange={setHosts} />
          </Field>

          {/* Listeners - multi-port */}
          <FieldGroup>
            <FieldTitle>
              监听端口 <span className="text-destructive">*</span>
            </FieldTitle>
            <div className="flex flex-col gap-2">
              {listeners.map((l, idx) => (
                <div key={idx} className="flex items-end gap-2">
                  <Field className="flex-1 gap-1">
                    <FieldLabel htmlFor={`listener-port-${idx}`}>
                      端口 <span className="text-destructive">*</span>
                    </FieldLabel>
                    <Input
                      id={`listener-port-${idx}`}
                      value={l.port}
                      onChange={(e) =>
                        updateListener(idx, { port: e.target.value })
                      }
                      placeholder="80"
                      type="number"
                      min={1}
                      max={65535}
                      className="rounded-lg"
                    />
                  </Field>
                  <div className="flex items-center gap-1">
                    <ToggleGroup
                      type="single"
                      value={l.tls ? "https" : "http"}
                      onValueChange={(value) => {
                        if (!value) return
                        updateListener(idx, { tls: value === "https" })
                      }}
                      variant="outline"
                      size="sm"
                      spacing={0}
                    >
                      <ToggleGroupItem value="http">HTTP</ToggleGroupItem>
                      <ToggleGroupItem value="https">HTTPS</ToggleGroupItem>
                    </ToggleGroup>
                    {listeners.length > 1 && (
                      <Button
                        type="button"
                        variant="destructive"
                        size="icon"
                        className="rounded-md"
                        aria-label="删除监听端口"
                        onClick={() => removeListener(idx)}
                      >
                        <Trash2 data-icon="inline-start" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
            <Button
              type="button"
              variant="outline"
              className="w-full rounded-lg border-dashed"
              onClick={addListener}
            >
              <Plus data-icon="inline-start" />
              添加一个监听端口
            </Button>
          </FieldGroup>

          {/* Certificate */}
          {hasAnyTLS && (
            <Field>
              <FieldLabel htmlFor={certificateId}>证书</FieldLabel>
              <div className="flex flex-col gap-3 rounded-lg border bg-muted/35 p-3">
                <Alert>
                  <Lock data-icon="inline-start" />
                  <AlertTitle>HTTPS 证书</AlertTitle>
                  <AlertDescription>
                    存在 HTTPS 端口时必须绑定证书。
                  </AlertDescription>
                </Alert>
                <Select
                  value={certId ? String(certId) : ""}
                  onValueChange={(value) =>
                    setCertId(value ? Number(value) : null)
                  }
                >
                  <SelectTrigger id={certificateId} className="rounded-lg">
                    <SelectValue
                      placeholder={
                        certificates.length ? "选择证书" : "当前没有可用证书"
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {certificates.map((certificate) => (
                        <SelectItem
                          key={certificate.id}
                          value={String(certificate.id)}
                        >
                          {certificate.name}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
            </Field>
          )}

          {/* Upstream */}
          <div className="flex flex-col gap-3 rounded-lg border bg-muted/35 p-5">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-foreground">
                  上游服务器 <span className="text-destructive">*</span>
                </h3>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                  请求将转发到以下上游地址，多个地址按轮询负载均衡。
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="rounded-md"
                onClick={() =>
                  setUpstreams((current) => [...current, defaultUpstream])
                }
              >
                <Plus data-icon="inline-start" />
                添加上游
              </Button>
            </div>

            <div className="flex flex-col gap-3">
              {upstreams.map((upstream, index) => (
                <div
                  key={`${index}-${upstream}`}
                  className="flex items-center gap-2 rounded-lg border bg-background p-2"
                >
                  <Input
                    value={upstream}
                    onChange={(event) =>
                      updateUpstream(index, event.target.value)
                    }
                    placeholder="http://192.168.1.10:8080，不支持路径"
                    className="border-0 bg-transparent font-mono text-sm shadow-none focus-visible:ring-0"
                  />
                  {upstreams.length > 1 ? (
                    <Button
                      type="button"
                      variant="destructive"
                      size="icon-sm"
                      className="rounded-md"
                      aria-label="删除上游服务"
                      onClick={() => removeUpstream(index)}
                    >
                      <Trash2 data-icon="inline-start" />
                    </Button>
                  ) : null}
                </div>
              ))}
            </div>
            <Button
              type="button"
              variant="outline"
              className="w-full rounded-lg border-dashed"
              onClick={() =>
                setUpstreams((current) => [...current, defaultUpstream])
              }
            >
              <Plus data-icon="inline-start" />
              添加上游服务
            </Button>
          </div>
        </div>

        <Separator />
        <DialogFooter className="bg-card px-6 py-4">
          <Button
            variant="outline"
            className="rounded-md"
            onClick={() => close(false)}
          >
            取消
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={saving}
            className="rounded-md"
          >
            {saving ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : null}
            {saving ? "创建中..." : "提交"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
