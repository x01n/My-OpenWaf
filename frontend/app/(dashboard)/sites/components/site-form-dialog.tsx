"use client"

import { useEffect } from "react"
import Link from "next/link"
import { useTranslation } from "react-i18next"
import { useForm, useFieldArray, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import {
  invalidateSiteCaches,
  useCertificates,
  usePolicies,
} from "@/hooks/use-api"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { siteApi } from "@/lib/api"
import {
  normalizeSiteHosts,
  parseSiteHosts,
  parseUpstreamUrls,
} from "@/lib/site-display"
import type { Site } from "@/lib/types"
import { IconExternalLink, IconPlus, IconTrash } from "@tabler/icons-react"

/**
 * 「不使用证书」的哨兵值。
 * Radix Select 不接受空字符串作为 SelectItem 的 value，必须用非空占位。
 */
const CERT_NONE = "none"
const POLICY_INHERIT = "inherit-default"

/** 后端 `internal/admin/shared/site_upstreams.go` 允许的上游 scheme */
const UPSTREAM_SCHEMES = ["http://", "https://", "h2c://", "h3://"]

const siteFormSchema = z
  .object({
    host: z
      .string()
      .refine((v) => parseSiteHosts(v).length > 0, "sites.form.hostRequired"),
    listeners: z
      .array(
        z.object({
          port: z
            .string()
            .min(1, "sites.form.portRequired")
            .regex(/^\d+$/, "sites.form.portNumber")
            .refine((v) => {
              const n = Number(v)
              return n >= 1 && n <= 65535
            }, "sites.form.portRange"),
          tls_enabled: z.boolean(),
        })
      )
      .min(1, "sites.form.listenersRequired"),
    cert_id: z.number().optional(),
    policy_id: z.number().nullable().optional(),
    upstreams: z
      .array(
        z.object({
          url: z
            .string()
            .min(1, "sites.form.upstreamUrlRequired")
            .refine(
              (v) =>
                UPSTREAM_SCHEMES.some((s) =>
                  v.trim().toLowerCase().startsWith(s)
                ),
              "sites.form.upstreamScheme"
            ),
        })
      )
      .min(1, "sites.form.upstreamRequired"),
    upstream_host: z.string().optional(),
  })
  // 对齐后端 shared.ValidateSiteTLSCertificate：启用 TLS 的站点必须绑定证书
  .refine(
    (v) => !v.listeners.some((l) => l.tls_enabled) || v.cert_id !== undefined,
    { message: "sites.form.certRequired", path: ["cert_id"] }
  )

type SiteFormValues = z.infer<typeof siteFormSchema>

interface SiteFormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  site?: Site | null
}

/** 新建站点时的初始表单值 */
const EMPTY_VALUES: SiteFormValues = {
  host: "",
  listeners: [{ port: "80", tls_enabled: false }],
  cert_id: undefined,
  policy_id: null,
  upstreams: [{ url: "http://127.0.0.1:8080" }],
  upstream_host: "",
}

/**
 * 添加 / 编辑防护应用弹窗。
 *
 * 仅暴露后端 `store.Site` 真实存在的字段：域名、监听端口 + TLS、证书、
 * 上游服务器列表与上游 Host 覆盖。
 *
 * @param {SiteFormDialogProps} props 组件属性
 * @returns {React.ReactElement} 弹窗
 */
export function SiteFormDialog({
  open,
  onOpenChange,
  site,
}: SiteFormDialogProps) {
  const { t } = useTranslation()
  const isEdit = !!site
  const { data: certificates } = useCertificates()
  const { data: policies = [] } = usePolicies()

  const form = useForm<SiteFormValues>({
    resolver: zodResolver(siteFormSchema),
    defaultValues: EMPTY_VALUES,
  })

  const {
    register,
    handleSubmit,
    control,
    setValue,
    reset,
    formState: { errors, isSubmitting },
  } = form

  const listenerArray = useFieldArray({ control, name: "listeners" })
  const upstreamArray = useFieldArray({ control, name: "upstreams" })

  // useWatch 订阅的是 control，可安全 memo；useForm().watch() 会被 React Compiler 跳过优化
  const watchedListeners = useWatch({ control, name: "listeners" })
  const watchedCertId = useWatch({ control, name: "cert_id" })
  const watchedPolicyId = useWatch({ control, name: "policy_id" })

  /** 弹窗打开或编辑目标变化时重置表单 */
  useEffect(() => {
    if (!open) return
    if (site) {
      const portMatch = (site.bind || "").match(/:(\d+)$/)
      const upstreams = parseUpstreamUrls(site.upstream_urls)
      reset({
        host: site.host,
        listeners: [
          {
            port: portMatch ? portMatch[1] : "80",
            tls_enabled: site.tls_enabled,
          },
        ],
        cert_id: site.cert_id,
        policy_id: site.policy_id ?? null,
        upstreams:
          upstreams.length > 0
            ? upstreams.map((url) => ({ url }))
            : [{ url: "" }],
        upstream_host: site.upstream_host || "",
      })
    } else {
      reset(EMPTY_VALUES)
    }
  }, [open, site, reset])

  /**
   * 提交表单。
   *
   * 新建时用第一个端口作为站点主 bind，其余端口创建为受管监听器；
   * 编辑时只更新站点主配置，额外监听器在站点详情页的「监听端口」中管理。
   */
  const onSubmit = async (values: SiteFormValues) => {
    try {
      const primary = values.listeners[0]
      const payload: Partial<Site> = {
        host: normalizeSiteHosts(values.host),
        bind: `0.0.0.0:${primary.port}`,
        tls_enabled: primary.tls_enabled,
        cert_id: values.cert_id,
        policy_id: values.policy_id === null ? undefined : values.policy_id,
        upstream_urls: values.upstreams
          .map((u) => u.url.trim())
          .filter(Boolean)
          .join(","),
        upstream_host: values.upstream_host?.trim() || undefined,
      }

      let savedSiteId: string | number
      if (isEdit && site) {
        await siteApi.update(site.id, payload)
        savedSiteId = site.id
        toast.success(t("sites.updateSuccess"))
      } else {
        const result = await siteApi.create(payload)
        savedSiteId = result.id
        for (let i = 1; i < values.listeners.length; i++) {
          const l = values.listeners[i]
          await siteApi.createListener(result.id, {
            bind: `0.0.0.0:${l.port}`,
            tls_enabled: l.tls_enabled,
            cert_id: l.tls_enabled ? values.cert_id : undefined,
            enabled: true,
          })
        }
        toast.success(t("sites.createSuccess"))
      }
      await invalidateSiteCaches(savedSiteId)
      onOpenChange(false)
    } catch (err: unknown) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const needsCert = (watchedListeners ?? []).some((l) => l?.tls_enabled)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? t("sites.form.editTitle") : t("sites.form.addTitle")}
          </DialogTitle>
          <DialogDescription>{t("sites.form.dialogDesc")}</DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
          {/* 域名 */}
          <div className="space-y-1.5">
            <Label htmlFor="host">
              {t("sites.form.host")}
              <span className="ms-0.5 text-destructive">*</span>
            </Label>
            <Input
              id="host"
              placeholder={t("sites.form.hostPlaceholder")}
              autoComplete="off"
              {...register("host")}
            />
            <p className="text-[11px] text-muted-foreground">
              {t("sites.form.hostHint")}
            </p>
            {errors.host && (
              <p className="text-xs text-destructive">
                {t(errors.host.message!)}
              </p>
            )}
          </div>

          {/* 监听端口 */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>
                {t("sites.form.listeners")}
                <span className="ms-0.5 text-destructive">*</span>
              </Label>
              {isEdit && site && (
                <Link
                  href={`/sites/detail/?id=${site.id}&tab=listeners`}
                  className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-primary"
                >
                  {t("sites.form.manageListeners")}
                  <IconExternalLink className="size-3" />
                </Link>
              )}
            </div>

            <div className="space-y-2">
              {listenerArray.fields.map((field, index) => (
                <div key={field.id} className="flex items-center gap-2">
                  <Input
                    placeholder="80"
                    inputMode="numeric"
                    className="w-28 font-mono"
                    {...register(`listeners.${index}.port` as const)}
                  />
                  <ToggleGroup
                    type="single"
                    variant="outline"
                    size="sm"
                    value={
                      watchedListeners?.[index]?.tls_enabled ? "https" : "http"
                    }
                    onValueChange={(v) => {
                      if (!v) return
                      setValue(
                        `listeners.${index}.tls_enabled`,
                        v === "https",
                        {
                          shouldDirty: true,
                        }
                      )
                    }}
                  >
                    <ToggleGroupItem value="http" className="px-3 text-xs">
                      {t("sites.http")}
                    </ToggleGroupItem>
                    <ToggleGroupItem value="https" className="px-3 text-xs">
                      {t("sites.https")}
                    </ToggleGroupItem>
                  </ToggleGroup>
                  {index === 0 ? (
                    <Badge
                      variant="secondary"
                      className="h-6 shrink-0 px-2 text-[10px]"
                    >
                      {t("sites.form.primaryListener")}
                    </Badge>
                  ) : (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      className="text-muted-foreground hover:text-destructive"
                      aria-label={t("common.delete")}
                      onClick={() => listenerArray.remove(index)}
                    >
                      <IconTrash />
                    </Button>
                  )}
                </div>
              ))}

              {/* 编辑态下新增的端口不会被保存，因此只在新建时提供 */}
              {!isEdit && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="w-full border-dashed"
                  onClick={() =>
                    listenerArray.append({ port: "", tls_enabled: false })
                  }
                >
                  <IconPlus className="size-3.5" />
                  {t("sites.form.addPort")}
                </Button>
              )}
            </div>

            {errors.listeners?.message && (
              <p className="text-xs text-destructive">
                {t(errors.listeners.message)}
              </p>
            )}
            {listenerArray.fields.map((field, index) =>
              errors.listeners?.[index]?.port ? (
                <p key={field.id} className="text-xs text-destructive">
                  {t(errors.listeners[index]!.port!.message!)}
                </p>
              ) : null
            )}
          </div>

          {/* 证书 */}
          <div className="space-y-1.5">
            <Label>{t("sites.form.cert")}</Label>
            <Select
              value={watchedCertId?.toString() ?? CERT_NONE}
              onValueChange={(v) =>
                setValue("cert_id", v === CERT_NONE ? undefined : Number(v), {
                  shouldDirty: true,
                })
              }
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder={t("sites.form.certPlaceholder")} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={CERT_NONE}>
                  {t("sites.form.certNone")}
                </SelectItem>
                {certificates?.map((cert) => (
                  <SelectItem key={cert.id} value={cert.id.toString()}>
                    {cert.name}
                    {cert.domain ? ` (${cert.domain})` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.cert_id ? (
              <p className="text-xs text-destructive">
                {t(errors.cert_id.message!)}
              </p>
            ) : needsCert && watchedCertId === undefined ? (
              <p className="text-[11px] text-amber-600 dark:text-amber-400">
                {t("sites.form.certRequiredHint")}
              </p>
            ) : null}
          </div>

          {/* 策略 */}
          <div className="space-y-1.5">
            <Label>
              {t("sites.form.policy")}
            </Label>
            <Select
              value={
                watchedPolicyId == null
                  ? POLICY_INHERIT
                  : String(watchedPolicyId)
              }
              onValueChange={(v) =>
                setValue("policy_id", v === POLICY_INHERIT ? null : Number(v), {
                  shouldDirty: true,
                })
              }
            >
              <SelectTrigger className="w-full">
                <SelectValue
                  placeholder={t("sites.form.policyPlaceholder")}
                />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={POLICY_INHERIT}>
                  {t("sites.form.policyInheritDefault")}
                </SelectItem>
                {policies.map((policy) => (
                  <SelectItem key={policy.id} value={String(policy.id)}>
                    {policy.name}
                    {policy.is_default
                      ? ` (${t("common.default")})`
                      : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">
              {t("sites.form.policyHint")}
            </p>
          </div>

          {/* 上游服务器 */}
          <div className="space-y-2">
            <Label>
              {t("sites.form.upstreamServers")}
              <span className="ms-0.5 text-destructive">*</span>
            </Label>
            <div className="space-y-2">
              {upstreamArray.fields.map((field, index) => (
                <div key={field.id} className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="http://127.0.0.1:8080"
                      autoComplete="off"
                      className="font-mono text-xs"
                      {...register(`upstreams.${index}.url` as const)}
                    />
                    {upstreamArray.fields.length > 1 && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon-sm"
                        className="shrink-0 text-muted-foreground hover:text-destructive"
                        aria-label={t("common.delete")}
                        onClick={() => upstreamArray.remove(index)}
                      >
                        <IconTrash />
                      </Button>
                    )}
                  </div>
                  {errors.upstreams?.[index]?.url && (
                    <p className="text-xs text-destructive">
                      {t(errors.upstreams[index]!.url!.message!)}
                    </p>
                  )}
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="w-full border-dashed"
                onClick={() => upstreamArray.append({ url: "" })}
              >
                <IconPlus className="size-3.5" />
                {t("sites.form.addUpstream")}
              </Button>
            </div>
            <p className="text-[11px] text-muted-foreground">
              {t("sites.form.upstreamUrlsHint")}
            </p>
            {errors.upstreams?.message && (
              <p className="text-xs text-destructive">
                {t(errors.upstreams.message)}
              </p>
            )}
          </div>

          {/* 上游 Host 覆盖 */}
          <div className="space-y-1.5">
            <Label htmlFor="upstream_host">
              {t("sites.form.upstreamHost")}
            </Label>
            <Input
              id="upstream_host"
              placeholder={t("sites.form.upstreamHostPlaceholder")}
              autoComplete="off"
              className="font-mono text-xs"
              {...register("upstream_host")}
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? t("common.saving") : t("common.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
