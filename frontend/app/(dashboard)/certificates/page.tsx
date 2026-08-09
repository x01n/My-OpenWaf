"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import {
  useCertificate,
  useCertificates,
  useCertificateMutation,
  useCertificateDelete,
} from "@/hooks/use-api"
import { ApiError } from "@/lib/api"
import { formatDate } from "@/lib/utils"
import { DataTable } from "@/components/data-table"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { EmptyState } from "@/components/empty-state"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog"
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
  IconTrash,
  IconEdit,
  IconEye,
  IconCertificate,
  IconAlertTriangle,
} from "@tabler/icons-react"
import type { Certificate } from "@/lib/types"

type CertificateDialogMode = "create" | "edit" | "view" | null

interface CertificateForm {
  name: string
  cert_pem: string
  key_pem: string
  source: Certificate["source"]
  domain: string
  acme_email: string
  auto_renew: boolean
}

interface DeleteErrorState {
  message: string
  siteRefs?: number
  listenerRefs?: number
}

const EMPTY_FORM: CertificateForm = {
  name: "",
  cert_pem: "",
  key_pem: "",
  source: "manual",
  domain: "",
  acme_email: "",
  auto_renew: false,
}

const PEM_FIELD_CLASS =
  "max-h-64 min-h-32 resize-y overflow-y-auto whitespace-pre-wrap break-all font-mono text-xs leading-5"

function certificateToForm(certificate: Certificate): CertificateForm {
  return {
    name: certificate.name,
    cert_pem: certificate.cert_pem,
    key_pem: "",
    source: certificate.source,
    domain: certificate.domain ?? "",
    acme_email: certificate.acme_email ?? "",
    auto_renew: certificate.auto_renew,
  }
}

function getDeleteError(error: unknown, fallback: string): DeleteErrorState {
  const message = error instanceof Error ? error.message : fallback
  if (
    !(error instanceof ApiError) ||
    !error.data ||
    typeof error.data !== "object"
  ) {
    return { message }
  }
  const data = error.data as Record<string, unknown>
  return {
    message,
    siteRefs: typeof data.site_refs === "number" ? data.site_refs : undefined,
    listenerRefs:
      typeof data.listener_refs === "number" ? data.listener_refs : undefined,
  }
}

export default function CertificatesPage() {
  const { t } = useTranslation()
  const { data, isLoading, error, mutate } = useCertificates()
  const { execute: mutateCert, loading: mutateLoading } =
    useCertificateMutation()
  const { execute: deleteCert, loading: deleteLoading } = useCertificateDelete()

  const [dialogMode, setDialogMode] = useState<CertificateDialogMode>(null)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [deleteId, setDeleteId] = useState<number | null>(null)
  const [deleteError, setDeleteError] = useState<DeleteErrorState | null>(null)
  const [form, setForm] = useState<CertificateForm>(EMPTY_FORM)

  const {
    data: selectedCertificate,
    isLoading: selectedLoading,
    error: selectedError,
  } = useCertificate(selectedId ?? undefined)

  const certificates: Certificate[] = data || []
  const isFormDialog = dialogMode === "create" || dialogMode === "edit"
  const isEdit = dialogMode === "edit"

  const daysUntilExpiry = (expiresAt?: string): number | null => {
    if (!expiresAt) return null
    const diff = new Date(expiresAt).getTime() - Date.now()
    return Math.ceil(diff / (1000 * 60 * 60 * 24))
  }

  const sourceLabel = (source: Certificate["source"]) => {
    if (source === "acme") return t("certificates.sourceAcme")
    if (source === "self_signed") return t("certificates.sourceSelfSigned")
    return t("certificates.sourceManual")
  }

  const closeDialog = () => {
    setDialogMode(null)
    setSelectedId(null)
    setForm(EMPTY_FORM)
  }

  const openCreate = () => {
    setDeleteError(null)
    setSelectedId(null)
    setForm(EMPTY_FORM)
    setDialogMode("create")
  }

  const openEdit = (certificate: Certificate) => {
    setDeleteError(null)
    setSelectedId(certificate.id)
    setForm(certificateToForm(certificate))
    setDialogMode("edit")
  }

  const openView = (certificate: Certificate) => {
    setDeleteError(null)
    setSelectedId(certificate.id)
    setDialogMode("view")
  }

  const handleSubmit = async () => {
    if (!isFormDialog || (isEdit && !selectedId)) return

    const payload: Partial<Certificate> = {
      name: form.name.trim(),
      cert_pem: form.cert_pem,
      source: form.source,
      domain: form.domain.trim(),
      acme_email: form.acme_email.trim(),
      auto_renew: form.auto_renew,
    }

    if (!isEdit) {
      payload.key_pem = form.key_pem
    } else if (form.key_pem.trim()) {
      payload.key_pem = form.key_pem
    }

    try {
      await mutateCert({ id: isEdit ? selectedId! : undefined, data: payload })
      toast.success(
        isEdit
          ? t("certificates.updateSuccess")
          : t("certificates.createSuccess")
      )
      closeDialog()
      await mutate()
    } catch (err: unknown) {
      toast.error(
        err instanceof Error ? err.message : t("common.operationFailed")
      )
    }
  }

  const confirmDelete = async () => {
    if (deleteId === null) return
    try {
      await deleteCert(deleteId)
      toast.success(t("common.deleteSuccess"))
      setDeleteId(null)
      setDeleteError(null)
      await mutate()
    } catch (err: unknown) {
      const details = getDeleteError(err, t("common.deleteFailed"))
      setDeleteError(details)
      const refs =
        details.siteRefs !== undefined || details.listenerRefs !== undefined
          ? t("certificates.deleteRefs", {
              siteRefs: details.siteRefs ?? 0,
              listenerRefs: details.listenerRefs ?? 0,
            })
          : undefined
      toast.error(refs ? `${details.message} · ${refs}` : details.message)
    }
  }

  const columns = [
    {
      key: "name",
      title: t("certificates.name"),
      render: (row: Certificate) => (
        <div className="flex items-center gap-2">
          <IconCertificate className="h-4 w-4 text-primary" />
          <span className="font-medium">{row.name}</span>
        </div>
      ),
    },
    {
      key: "domain",
      title: t("certificates.domain"),
      render: (row: Certificate) => (
        <span className="text-sm">{row.domain || "-"}</span>
      ),
    },
    {
      key: "source",
      title: t("certificates.source"),
      width: "120px",
      render: (row: Certificate) => (
        <Badge variant="secondary">{sourceLabel(row.source)}</Badge>
      ),
    },
    {
      key: "expires_at",
      title: t("certificates.expiresAt"),
      width: "180px",
      render: (row: Certificate) => {
        const days = daysUntilExpiry(row.expires_at)
        if (!row.expires_at)
          return <span className="text-muted-foreground">-</span>
        return (
          <div className="flex items-center gap-2">
            <span className="text-sm">{row.expires_at.slice(0, 10)}</span>
            {days !== null && days <= 30 && days > 0 && (
              <Badge variant="destructive" className="flex items-center gap-1">
                <IconAlertTriangle className="h-3 w-3" />
                {t("certificates.expiringDays", { days })}
              </Badge>
            )}
            {days !== null && days <= 0 && (
              <Badge variant="destructive">{t("certificates.expired")}</Badge>
            )}
          </div>
        )
      },
    },
    {
      key: "auto_renew",
      title: t("certificates.autoRenew"),
      width: "100px",
      render: (row: Certificate) => (
        <Badge variant={row.auto_renew ? "default" : "secondary"}>
          {row.auto_renew ? t("common.enabled") : t("common.disabled")}
        </Badge>
      ),
    },
    {
      key: "action",
      title: t("common.action"),
      width: "150px",
      render: (row: Certificate) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => openView(row)}
            title={t("common.view")}
            aria-label={t("common.view")}
          >
            <IconEye className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => openEdit(row)}
            title={t("common.edit")}
            aria-label={t("common.edit")}
          >
            <IconEdit className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => {
              setDeleteError(null)
              setDeleteId(row.id)
            }}
            title={t("common.delete")}
            aria-label={t("common.delete")}
          >
            <IconTrash className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ]

  const deleteDescription = deleteError
    ? deleteError.siteRefs !== undefined ||
      deleteError.listenerRefs !== undefined
      ? t("certificates.deleteBlocked", {
          message: deleteError.message,
          siteRefs: deleteError.siteRefs ?? 0,
          listenerRefs: deleteError.listenerRefs ?? 0,
        })
      : deleteError.message
    : t("certificates.deleteConfirm")

  const detail = selectedCertificate
  const detailLoading = selectedLoading && !detail
  const detailError = selectedError?.message || t("error.unexpectedError")

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("certificates.title")}
        description={t("certificates.description")}
        actions={
          <Button onClick={openCreate}>
            <IconPlus className="h-4 w-4" />
            {t("certificates.add")}
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

      <DataTable
        columns={columns}
        data={certificates}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("certificates.empty")}
        emptyContent={
          <EmptyState
            icon={IconCertificate}
            title={t("certificates.empty")}
            description={t(
              "certificates.emptyHint",
              "上传 TLS 证书以启用站点 HTTPS 加密，支持手动上传和 ACME 自动签发"
            )}
            action={
              <Button onClick={openCreate}>
                <IconPlus className="mr-1.5 h-4 w-4" />
                {t("certificates.add")}
              </Button>
            }
            className="py-20"
          />
        }
      />

      <Dialog
        open={dialogMode !== null}
        onOpenChange={(open) => {
          if (!open) closeDialog()
        }}
      >
        <DialogContent
          className={
            dialogMode === "view"
              ? "max-h-[90vh] overflow-y-auto sm:max-w-3xl"
              : "max-h-[90vh] overflow-y-auto sm:max-w-2xl"
          }
        >
          <DialogHeader>
            <DialogTitle>
              {dialogMode === "view"
                ? t("certificates.viewTitle")
                : dialogMode === "edit"
                  ? t("certificates.editTitle")
                  : t("certificates.addTitle")}
            </DialogTitle>
            <DialogDescription>
              {dialogMode === "view"
                ? t("certificates.viewDescription")
                : t("certificates.formDescription")}
            </DialogDescription>
          </DialogHeader>

          {dialogMode === "view" ? (
            <div className="space-y-5">
              {detailLoading && (
                <div className="py-8 text-center text-sm text-muted-foreground">
                  {t("common.loading")}
                </div>
              )}
              {selectedError && (
                <Alert variant="destructive">
                  <AlertTitle>{t("certificates.detailLoadFailed")}</AlertTitle>
                  <AlertDescription>{detailError}</AlertDescription>
                </Alert>
              )}
              {detail && (
                <>
                  <div className="grid gap-3 rounded-xl border bg-muted/20 p-4 sm:grid-cols-2">
                    <div className="min-w-0">
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.name")}
                      </p>
                      <p className="font-medium break-words">{detail.name}</p>
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.domain")}
                      </p>
                      <p className="break-all">{detail.domain || "-"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.source")}
                      </p>
                      <p>{sourceLabel(detail.source)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.expiresAt")}
                      </p>
                      <p>{formatDate(detail.expires_at)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.autoRenew")}
                      </p>
                      <Badge
                        variant={detail.auto_renew ? "default" : "secondary"}
                      >
                        {detail.auto_renew
                          ? t("common.enabled")
                          : t("common.disabled")}
                      </Badge>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.ocspStaple")}
                      </p>
                      <p>
                        {detail.ocsp_staple_pem
                          ? t("certificates.configured")
                          : t("certificates.notConfigured")}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.acmeEmail")}
                      </p>
                      <p className="break-all">{detail.acme_email || "-"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.lastRenewAt")}
                      </p>
                      <p>{formatDate(detail.last_renew_at)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.createdAt")}
                      </p>
                      <p>{formatDate(detail.created_at)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.updatedAt")}
                      </p>
                      <p>{formatDate(detail.updated_at)}</p>
                    </div>
                    {detail.renew_error && (
                      <div className="sm:col-span-2">
                        <p className="text-xs text-muted-foreground">
                          {t("certificates.renewError")}
                        </p>
                        <p className="text-sm break-words text-destructive">
                          {detail.renew_error}
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label>{t("certificates.certPem")}</Label>
                    <pre
                      className={`${PEM_FIELD_CLASS} rounded-xl border bg-muted/20 p-4`}
                    >
                      {detail.cert_pem || "-"}
                    </pre>
                  </div>
                </>
              )}
            </div>
          ) : (
            <>
              {isEdit && detailLoading ? (
                <div className="py-8 text-center text-sm text-muted-foreground">
                  {t("common.loading")}
                </div>
              ) : selectedError && !detail ? (
                <Alert variant="destructive">
                  <AlertTitle>{t("certificates.detailLoadFailed")}</AlertTitle>
                  <AlertDescription>{detailError}</AlertDescription>
                </Alert>
              ) : (
                <div className="space-y-5">
                  <div className="space-y-2">
                    <Label htmlFor="cert-name">{t("certificates.name")}</Label>
                    <Input
                      id="cert-name"
                      value={form.name}
                      onChange={(e) =>
                        setForm((current) => ({
                          ...current,
                          name: e.target.value,
                        }))
                      }
                      placeholder={t("certificates.namePlaceholder")}
                    />
                  </div>

                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="cert-source">
                        {t("certificates.source")}
                      </Label>
                      <Select
                        value={form.source}
                        onValueChange={(value) =>
                          setForm((current) => ({
                            ...current,
                            source: value as Certificate["source"],
                          }))
                        }
                      >
                        <SelectTrigger id="cert-source">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="manual">
                            {t("certificates.sourceManual")}
                          </SelectItem>
                          <SelectItem value="acme">
                            {t("certificates.sourceAcme")}
                          </SelectItem>
                          <SelectItem value="self_signed">
                            {t("certificates.sourceSelfSigned")}
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="cert-domain">
                        {t("certificates.domain")}
                      </Label>
                      <Input
                        id="cert-domain"
                        value={form.domain}
                        onChange={(e) =>
                          setForm((current) => ({
                            ...current,
                            domain: e.target.value,
                          }))
                        }
                        placeholder={t("certificates.domainPlaceholder")}
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between rounded-xl border p-3">
                    <div className="space-y-1">
                      <Label
                        htmlFor="cert-auto-renew"
                        className="cursor-pointer"
                      >
                        {t("certificates.autoRenew")}
                      </Label>
                      <p className="text-xs text-muted-foreground">
                        {t("certificates.autoRenewHint")}
                      </p>
                    </div>
                    <Switch
                      id="cert-auto-renew"
                      checked={form.auto_renew}
                      onCheckedChange={(checked) =>
                        setForm((current) => ({
                          ...current,
                          auto_renew: checked,
                        }))
                      }
                    />
                  </div>

                  {(form.source === "manual" || isEdit) && (
                    <div className="space-y-5">
                      <div className="space-y-2">
                        <Label htmlFor="cert-pem">
                          {t("certificates.certPem")}
                        </Label>
                        <Textarea
                          id="cert-pem"
                          value={form.cert_pem}
                          onChange={(e) =>
                            setForm((current) => ({
                              ...current,
                              cert_pem: e.target.value,
                            }))
                          }
                          placeholder={t("certificates.certPemPlaceholder")}
                          className={PEM_FIELD_CLASS}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="cert-key">
                          {isEdit
                            ? t("certificates.keyPemReplace")
                            : t("certificates.keyPem")}
                        </Label>
                        <Textarea
                          id="cert-key"
                          value={form.key_pem}
                          onChange={(e) =>
                            setForm((current) => ({
                              ...current,
                              key_pem: e.target.value,
                            }))
                          }
                          placeholder={
                            isEdit
                              ? t("certificates.keyPemReplacePlaceholder")
                              : t("certificates.keyPemPlaceholder")
                          }
                          className={PEM_FIELD_CLASS}
                        />
                        <p className="text-xs text-muted-foreground">
                          {isEdit
                            ? t("certificates.keyPemReplaceHint")
                            : t("certificates.keyPemHint")}
                        </p>
                      </div>
                    </div>
                  )}

                  {form.source === "acme" && (
                    <div className="space-y-2">
                      <Label htmlFor="cert-acme-email">
                        {t("certificates.acmeEmail")}
                      </Label>
                      <Input
                        id="cert-acme-email"
                        value={form.acme_email}
                        onChange={(e) =>
                          setForm((current) => ({
                            ...current,
                            acme_email: e.target.value,
                          }))
                        }
                        placeholder={t("certificates.acmeEmailPlaceholder")}
                      />
                    </div>
                  )}
                </div>
              )}
              <DialogFooter>
                <Button variant="outline" onClick={closeDialog}>
                  {t("common.cancel")}
                </Button>
                <Button
                  onClick={handleSubmit}
                  disabled={
                    mutateLoading ||
                    !form.name.trim() ||
                    (isEdit && (!detail || !!selectedError))
                  }
                >
                  {mutateLoading
                    ? t("common.submitting")
                    : isEdit
                      ? t("common.save")
                      : t("common.create")}
                </Button>
              </DialogFooter>
            </>
          )}

          {dialogMode === "view" && (
            <DialogFooter>
              <Button variant="outline" onClick={closeDialog}>
                {t("common.close")}
              </Button>
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleteId !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleteId(null)
            setDeleteError(null)
          }
        }}
        title={t("common.confirmDeleteTitle")}
        description={deleteDescription}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  )
}
