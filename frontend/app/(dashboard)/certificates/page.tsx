"use client"

import {
  type ReactNode,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from "react"
import { useSearchParams } from "next/navigation"
import {
  FileKey2,
  Globe,
  Info,
  AlertTriangle,
  Plus,
  RefreshCcw,
  Settings,
  Trash2,
  Eye,
  Link2,
  Upload,
  Pencil,
  TestTube,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
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
import { Badge } from "@/components/ui/badge"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Separator } from "@/components/ui/separator"
import { CopyableBlock } from "@/components/log-presentation"
import {
  applyACMECertificate,
  applyCertificateToSites,
  createCertificate,
  deleteCertificate,
  getCertificates,
  getACMEConfig,
  getACMECertStatus,
  getCertificate,
  getConfigAppliedReloadFailureDetails,
  getConfigAppliedReloadFailureItem,
  isConfigAppliedReloadFailureError,
  listAllSites,
  listSiteListeners,
  parseCertificate,
  renewACMECertificate,
  updateCertificate,
  updateACMEConfig,
  type ACMEConfig,
  type ACMECertStatusItem,
  type ACMEApplyResponse,
  type ACMERenewResponse,
  type Certificate,
  type CertificateApplyResponse,
  type CertificateParseResponse,
} from "@/lib/api"
import { formatDate } from "@/lib/utils"
import { Pagination } from "@/components/pagination"

const CERTIFICATE_PAGE_SIZE = 20

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

type CertificateOperationResponse =
  | ACMEApplyResponse
  | ACMERenewResponse
  | ACMEConfig
  | Certificate
  | CertificateApplyResponse

type CertificateUploadPayload = {
  name: string
  cert_pem: string
  key_pem: string
}

function certificateResponseSummary(cert: Certificate) {
  return {
    id: cert.id,
    name: cert.name,
    source: cert.source,
    domain: cert.domain,
    acme_email: cert.acme_email,
    expires_at: cert.expires_at,
    auto_renew: cert.auto_renew,
    renew_error: cert.renew_error,
    created_at: cert.created_at,
    updated_at: cert.updated_at,
  }
}

function isCertificateBindingResponse(
  response: CertificateOperationResponse
): response is ACMEApplyResponse | CertificateApplyResponse {
  return (
    "applied_sites" in response &&
    "site_count" in response &&
    "listener_count" in response
  )
}

function certificateUploadPayloadSummary(payload: CertificateUploadPayload) {
  return {
    name: payload.name,
    cert_pem_length: payload.cert_pem.length,
    key_pem_length: payload.key_pem.length,
  }
}

function certificateOperationResponseDetails(
  response: CertificateOperationResponse
) {
  if (isCertificateBindingResponse(response)) {
    return {
      certificate:
        "id" in response && "name" in response
          ? certificateResponseSummary(response)
          : { id: response.certificate_id },
      applied_sites: response.applied_sites ?? [],
      site_count: response.site_count ?? 0,
      listener_count: response.listener_count ?? 0,
    }
  }
  if ("message" in response) {
    return {
      message: response.message,
      domain: response.domain,
      expires_at: response.expires_at,
    }
  }
  if ("directory_url" in response) {
    return { config: response }
  }
  return { certificate: certificateResponseSummary(response) }
}

function certificateOperationDetails(
  operation: string,
  response: CertificateOperationResponse,
  payload?: Record<string, unknown>
) {
  const responseDetails = certificateOperationResponseDetails(response)
  return {
    operation,
    ...(payload ? { payload } : {}),
    response: responseDetails,
  }
}

function certificateReloadFailureOperationDetails(
  error: unknown,
  operation: string,
  payload?: Record<string, unknown>
) {
  const details =
    getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
  const item = getConfigAppliedReloadFailureItem<Certificate>(error)
  const response: Record<string, unknown> = {
    reload_failed: true,
    reload_error: error instanceof Error ? error.message : null,
    reload_failure: details,
  }
  if (item) {
    response.certificate = certificateResponseSummary(item)
  }
  if (Array.isArray(details?.applied_sites)) {
    response.applied_sites = details.applied_sites
  }
  if (typeof details?.site_count === "number") {
    response.site_count = details.site_count
  }
  if (typeof details?.listener_count === "number") {
    response.listener_count = details.listener_count
  }
  return {
    operation,
    ...(payload ? { payload } : {}),
    response,
  }
}

function formatCertificateBindingResult(
  result: Pick<
    CertificateApplyResponse,
    "applied_sites" | "site_count" | "listener_count"
  >
) {
  const siteHosts = (result.applied_sites || [])
    .map((site) => site.host)
    .filter(Boolean)
    .slice(0, 3)
  const siteDetail = siteHosts.length ? `，站点：${siteHosts.join("，")}` : ""
  return `已绑定 ${result.site_count || 0} 个站点、${result.listener_count || 0} 个 TLS 监听${siteDetail}`
}

function appendCertificateReference(
  refs: Record<number, string[]>,
  certID: number | null | undefined,
  label: string
) {
  if (certID === null || certID === undefined) return
  refs[certID] = refs[certID] || []
  refs[certID].push(label)
}

function formatCertificateReferenceSummary(
  siteRefs: string[] = [],
  listenerRefs: string[] = []
) {
  if (!siteRefs.length && !listenerRefs.length) return "未绑定证书"
  return `站点 ${siteRefs.length}，监听 ${listenerRefs.length}`
}

function formatCertificateReferencePreview(refs: string[] = [], limit = 4) {
  if (!refs.length) return "无"
  const visibleRefs = refs.slice(0, limit).join("，")
  const overflowCount = refs.length - limit
  return overflowCount > 0
    ? `${visibleRefs}，另 ${overflowCount} 项`
    : visibleRefs
}

function getACMEStatusMessage(
  cert: Certificate,
  status: ACMECertStatusItem | undefined
) {
  if (cert.source !== "acme") return "非 ACME"
  const error = status?.error || cert.renew_error
  if (error) return error
  return status?.auto_renew || cert.auto_renew ? "自动续期" : "手动续期"
}

function CertificateDetailItem({
  label,
  children,
  mono,
}: {
  label: string
  children: ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border bg-card p-3">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div
        className={
          mono
            ? "font-mono text-sm font-medium text-foreground"
            : "text-sm font-medium text-foreground"
        }
      >
        {children}
      </div>
    </div>
  )
}

function CertificateReferencePanel({
  siteRefs,
  listenerRefs,
}: {
  siteRefs: string[]
  listenerRefs: string[]
}) {
  const hasRefs = siteRefs.length > 0 || listenerRefs.length > 0

  if (!hasRefs) {
    return (
      <div className="rounded-lg border bg-card p-3 text-sm leading-6 text-muted-foreground">
        未绑定站点或监听端口。
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-card p-3 text-sm leading-6 text-muted-foreground">
      <div className="flex flex-col gap-1">
        <div className="font-medium text-foreground">
          站点引用（{siteRefs.length}）
        </div>
        <div>{formatCertificateReferencePreview(siteRefs)}</div>
      </div>
      <Separator />
      <div className="flex flex-col gap-1">
        <div className="font-medium text-foreground">
          监听引用（{listenerRefs.length}）
        </div>
        <div>{formatCertificateReferencePreview(listenerRefs)}</div>
      </div>
    </div>
  )
}

export default function CertificatesPage() {
  const searchParams = useSearchParams()
  const acmeConfigEnabledId = useId()
  const acmeConfigEmailId = useId()
  const acmeConfigDirectoryURLId = useId()
  const acmeConfigAutoRenewId = useId()
  const acmeConfigRenewBeforeDaysId = useId()
  const certFileInputRef = useRef<HTMLInputElement>(null)
  const keyFileInputRef = useRef<HTMLInputElement>(null)
  const [certs, setCerts] = useState<Certificate[]>([])
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [detailCert, setDetailCert] = useState<Certificate | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Certificate | null>(null)
  const [deleting, setDeleting] = useState(false)

  // Upload form
  const [formName, setFormName] = useState("")
  const [formCert, setFormCert] = useState("")
  const [formKey, setFormKey] = useState("")
  const [uploading, setUploading] = useState(false)
  const [editingCert, setEditingCert] = useState<Certificate | null>(null)
  const [certPreview, setCertPreview] =
    useState<CertificateParseResponse | null>(null)
  const [parsingCert, setParsingCert] = useState(false)
  const [applyingToSitesId, setApplyingToSitesId] = useState<number | null>(
    null
  )

  // ACME
  const [acmeOpen, setAcmeOpen] = useState(false)
  const [acmeConfigOpen, setAcmeConfigOpen] = useState(false)
  const [acmeDomain, setAcmeDomain] = useState("")
  const [acmeDomainError, setAcmeDomainError] = useState("")
  const [acmeEmail, setAcmeEmail] = useState("")
  const [acmeName, setAcmeName] = useState("")
  const [acmeApplying, setAcmeApplying] = useState(false)
  const [acmeConfig, setAcmeConfig] = useState<ACMEConfig | null>(null)
  const [acmeConfigLoading, setAcmeConfigLoading] = useState(false)
  const [savingACMEConfig, setSavingACMEConfig] = useState(false)
  const [acmeEnabled, setAcmeEnabled] = useState(false)
  const [acmeConfigEmail, setAcmeConfigEmail] = useState("")
  const [acmeDirectoryURL, setAcmeDirectoryURL] = useState("")
  const [acmeAutoRenew, setAcmeAutoRenew] = useState(true)
  const [acmeRenewBeforeDays, setAcmeRenewBeforeDays] = useState(30)
  const [renewingId, setRenewingId] = useState<number | null>(null)
  const [acmeStatus, setAcmeStatus] = useState<
    Record<number, ACMECertStatusItem>
  >({})
  const [siteCertRefs, setSiteCertRefs] = useState<Record<number, string[]>>({})
  const [listenerCertRefs, setListenerCertRefs] = useState<
    Record<number, string[]>
  >({})
  const [certRefsLoading, setCertRefsLoading] = useState(false)
  const [loadingDetailId, setLoadingDetailId] = useState<number | null>(null)
  const [loadingEditId, setLoadingEditId] = useState<number | null>(null)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  function applyACMEConfigState(config: ACMEConfig) {
    setAcmeConfig(config)
    setAcmeEnabled(config.enabled)
    setAcmeConfigEmail(config.email || "")
    setAcmeDirectoryURL(config.directory_url || "")
    setAcmeAutoRenew(config.auto_renew)
    setAcmeRenewBeforeDays(config.renew_before_days || 30)
  }

  const loadACMEConfig = useCallback(async () => {
    setAcmeConfigLoading(true)
    try {
      const config = await getACMEConfig()
      applyACMEConfigState(config)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载 ACME 配置失败")
      setAcmeConfig(null)
    } finally {
      setAcmeConfigLoading(false)
    }
  }, [])

  const loadACMEStatus = useCallback(async () => {
    try {
      const data = await getACMECertStatus()
      const next: Record<number, ACMECertStatusItem> = {}
      for (const item of data.items || []) {
        next[item.id] = item
      }
      setAcmeStatus(next)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载 ACME 状态失败")
      setAcmeStatus({})
    }
  }, [])

  const loadSiteCertRefs = useCallback(async () => {
    setCertRefsLoading(true)
    try {
      const data = await listAllSites()
      const sites = data.items || []
      const nextSiteRefs: Record<number, string[]> = {}
      const nextListenerRefs: Record<number, string[]> = {}

      for (const site of sites) {
        appendCertificateReference(
          nextSiteRefs,
          site.cert_id,
          site.host || `站点 #${site.id}`
        )
      }

      const listenerResults = await Promise.all(
        sites.map(async (site) => {
          const result = await listSiteListeners(site.id)
          return {
            site,
            listeners: result.items || [],
          }
        })
      )

      for (const { site, listeners } of listenerResults) {
        const siteLabel = site.host || `站点 #${site.id}`
        for (const listener of listeners) {
          const listenerLabel = listener.bind || `监听 #${listener.id}`
          const networkLabel = listener.network ? `/${listener.network}` : ""
          appendCertificateReference(
            nextListenerRefs,
            listener.cert_id,
            `${siteLabel}：${listenerLabel}${networkLabel}`
          )
        }
      }

      setSiteCertRefs(nextSiteRefs)
      setListenerCertRefs(nextListenerRefs)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载证书引用失败")
      setSiteCertRefs({})
      setListenerCertRefs({})
    } finally {
      setCertRefsLoading(false)
    }
  }, [])

  const loadCertificates = useCallback(
    async (targetPage = page) => {
    setLoading(true)
    try {
      const data = await getCertificates({
        page: targetPage,
        page_size: CERTIFICATE_PAGE_SIZE,
      })
      const nextTotal = Number(data.total) || 0
      const nextTotalPages = Math.max(
        1,
        Math.ceil(nextTotal / CERTIFICATE_PAGE_SIZE)
      )
      if (targetPage > nextTotalPages) {
        setPage(nextTotalPages)
        return
      }
      setCerts(data.items || [])
      setTotal(nextTotal)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载证书列表失败")
      setCerts([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [page])

  const loadCertificateAuxiliaryData = useCallback(() => {
    void loadACMEStatus()
    void loadACMEConfig()
    void loadSiteCertRefs()
  }, [loadACMEConfig, loadACMEStatus, loadSiteCertRefs])

  useEffect(() => {
    return deferEffect(loadCertificates)
  }, [loadCertificates])

  useEffect(() => {
    return deferEffect(loadCertificateAuxiliaryData)
  }, [loadCertificateAuxiliaryData])

  const totalPages = Math.max(1, Math.ceil(total / CERTIFICATE_PAGE_SIZE))

  function refreshCertificateState() {
    void loadCertificates()
    loadCertificateAuxiliaryData()
  }

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  function resetUploadForm() {
    setEditingCert(null)
    setFormName("")
    setFormCert("")
    setFormKey("")
    setCertPreview(null)
  }

  async function handleUpload() {
    if (!formName.trim()) {
      toast.error("请输入证书名称")
      return
    }
    if (!formCert.trim()) {
      toast.error("请输入证书 PEM 内容")
      return
    }
    if (!formKey.trim()) {
      toast.error("请输入私钥 PEM 内容")
      return
    }
    setUploading(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const payload = { name: formName, cert_pem: formCert, key_pem: formKey }
    const operation = editingCert ? "update" : "create"
    const operationPayload = editingCert
      ? {
          certificate_id: editingCert.id,
          ...certificateUploadPayloadSummary(payload),
        }
      : certificateUploadPayloadSummary(payload)
    try {
      if (editingCert) {
        const result = await updateCertificate(editingCert.id, payload)
        setOperationDetails(
          certificateOperationDetails("update", result, operationPayload)
        )
        toast.success("证书已更新")
      } else {
        const result = await createCertificate(payload)
        setOperationDetails(
          certificateOperationDetails("create", result, operationPayload)
        )
        toast.success("证书已上传")
      }
      setUploadOpen(false)
      resetUploadForm()
      refreshCertificateState()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        setOperationDetails(
          certificateReloadFailureOperationDetails(e, operation, operationPayload)
        )
        setUploadOpen(false)
        resetUploadForm()
        refreshCertificateState()
      }
      toast.error(e instanceof Error ? e.message : "保存证书失败")
    } finally {
      setUploading(false)
    }
  }

  function openUpload() {
    setEditingCert(null)
    setFormName("")
    setFormCert("")
    setFormKey("")
    setCertPreview(null)
    setUploadOpen(true)
  }

  async function handleACMEApply() {
    const domain = acmeDomain.trim()
    if (!domain) {
      setAcmeDomainError("请输入域名")
      toast.error("请输入域名")
      return
    }
    setAcmeDomainError("")
    setAcmeApplying(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    const payload = {
      domain,
      name: acmeName.trim() || domain,
      email: acmeEmail.trim() || undefined,
    }
    try {
      const result = await applyACMECertificate(payload)
      setOperationDetails(
        certificateOperationDetails("acme_apply", result, payload)
      )
      toast.success(
        `证书申请成功：${domain}，${formatCertificateBindingResult(result)}`
      )
      setAcmeOpen(false)
      setAcmeDomain("")
      setAcmeDomainError("")
      setAcmeEmail("")
      setAcmeName("")
      refreshCertificateState()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        setOperationDetails(
          certificateReloadFailureOperationDetails(e, "acme_apply", payload)
        )
        setAcmeOpen(false)
        setAcmeDomain("")
        setAcmeDomainError("")
        setAcmeEmail("")
        setAcmeName("")
        refreshCertificateState()
      }
      toast.error(e instanceof Error ? e.message : "申请 ACME 证书失败")
    } finally {
      setAcmeApplying(false)
    }
  }

  async function handleSaveACMEConfig() {
    if (acmeRenewBeforeDays <= 0) {
      toast.error("提前续期天数必须大于 0")
      return
    }
    setSavingACMEConfig(true)
    setOperationDetails(null)
    try {
      const payload = {
        enabled: acmeEnabled,
        email: acmeConfigEmail,
        directory_url: acmeDirectoryURL,
        auto_renew: acmeAutoRenew,
        renew_before_days: acmeRenewBeforeDays,
      }
      const config = await updateACMEConfig(payload)
      applyACMEConfigState(config)
      setOperationDetails(
        certificateOperationDetails("acme_config", config, payload)
      )
      toast.success("ACME 配置已保存")
      setAcmeConfigOpen(false)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "保存 ACME 配置失败")
    } finally {
      setSavingACMEConfig(false)
    }
  }

  async function handleRenew(certId: number) {
    setRenewingId(certId)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      const result = await renewACMECertificate(certId)
      setOperationDetails(
        certificateOperationDetails("acme_renew", result, {
          certificate_id: certId,
        })
      )
      toast.success("证书续期成功")
      refreshCertificateState()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        setOperationDetails(
          certificateReloadFailureOperationDetails(e, "acme_renew", {
            certificate_id: certId,
          })
        )
        refreshCertificateState()
      }
      toast.error(e instanceof Error ? e.message : "证书续期失败")
    } finally {
      setRenewingId(null)
    }
  }

  async function openDetail(cert: Certificate) {
    setLoadingDetailId(cert.id)
    try {
      const detail = await getCertificate(cert.id)
      setDetailCert(detail)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载证书详情失败")
    } finally {
      setLoadingDetailId(null)
    }
  }

  async function openEdit(cert: Certificate) {
    setLoadingEditId(cert.id)
    try {
      const detail = await getCertificate(cert.id)
      setEditingCert(detail)
      setFormName(detail.name || "")
      setFormCert(detail.cert_pem || "")
      setFormKey(detail.key_pem || "")
      setCertPreview(null)
      setUploadOpen(true)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载证书详情失败")
    } finally {
      setLoadingEditId(null)
    }
  }

  async function handleParseCertificate() {
    if (!formCert.trim()) {
      toast.error("请输入证书 PEM 内容")
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setParsingCert(true)
    try {
      const parsed = await parseCertificate(formCert)
      setCertPreview(parsed)
      setOperationDetails({
        operation: "parse",
        payload: {
          cert_pem_length: formCert.length,
        },
        response: parsed,
      })
      toast.success(
        `证书解析完成，匹配 ${parsed.matched_sites?.length || 0} 个站点`
      )
    } catch (e) {
      setCertPreview(null)
      toast.error(e instanceof Error ? e.message : "解析证书失败")
    } finally {
      setParsingCert(false)
    }
  }

  async function handleApplyToSites(cert: Certificate) {
    setApplyingToSitesId(cert.id)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    let payload: Record<string, unknown> | null = null
    try {
      const detail = await getCertificate(cert.id)
      payload = {
        certificate_id: detail.id,
      }
      const result = await applyCertificateToSites(detail.id)
      setOperationDetails(
        certificateOperationDetails("apply_to_sites", result, payload)
      )
      toast.success(
        `证书已应用：${detail.name}，${formatCertificateBindingResult(result)}`
      )
      refreshCertificateState()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        setOperationDetails(
          certificateReloadFailureOperationDetails(
            e,
            "apply_to_sites",
            payload ?? { certificate_id: cert.id }
          )
        )
        refreshCertificateState()
      }
      toast.error(e instanceof Error ? e.message : "应用证书失败")
    } finally {
      setApplyingToSitesId(null)
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    const target = deleteTarget
    setDeleting(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      await deleteCertificate(target.id)
      setOperationDetails({
        operation: "delete",
        payload: {
          certificate: certificateResponseSummary(target),
        },
        status_code: 204,
        response: null,
      })
      toast.success("证书已删除")
      setDeleteTarget(null)
      refreshCertificateState()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        rememberReloadFailureDetails(e)
        setOperationDetails(
          certificateReloadFailureOperationDetails(e, "delete", {
            certificate: certificateResponseSummary(target),
          })
        )
        setDeleteTarget(null)
        refreshCertificateState()
      }
      toast.error(e instanceof Error ? e.message : "删除证书失败")
    } finally {
      setDeleting(false)
    }
  }

  function handleFileUpload(field: "cert" | "key", file: File) {
    const reader = new FileReader()
    reader.onload = (e) => {
      const content = e.target?.result as string
      if (field === "cert") {
        setFormCert(content)
        setCertPreview(null)
      } else {
        setFormKey(content)
      }
    }
    reader.readAsText(file)
  }

  const deleteSiteRefs = deleteTarget ? siteCertRefs[deleteTarget.id] || [] : []
  const deleteListenerRefs = deleteTarget
    ? listenerCertRefs[deleteTarget.id] || []
    : []
  const deleteBlockedByRefs =
    deleteSiteRefs.length > 0 || deleteListenerRefs.length > 0

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="TLS Certificates"
        title="证书管理"
        description="管理站点 HTTPS 接入所需的 TLS 证书和私钥，支持 PEM 格式上传。"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setAcmeConfigOpen(true)}>
              <Settings data-icon="inline-start" /> ACME 配置
            </Button>
            <Button onClick={() => setAcmeOpen(true)}>
              <Globe data-icon="inline-start" /> ACME 申请
            </Button>
            <Button variant="outline" onClick={openUpload}>
              <Plus data-icon="inline-start" /> 上传证书
            </Button>
          </div>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回证书操作响应体；请核对 item、applied_sites 或 error
            字段。
          </AlertDescription>
          <CopyableBlock
            label="reload 失败响应体"
            value={JSON.stringify(reloadFailureDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {operationDetails ? (
        <Alert className="gap-3">
          <Info />
          <AlertTitle>最近证书操作响应</AlertTitle>
          <AlertDescription>
            后端已返回证书操作结果；删除接口返回 204
            无响应体时，status_code 字段为 204，response 字段为 null。解析接口返回体位于
            response 字段。上传和更新仅记录 PEM 长度，不展示证书 PEM 或私钥 PEM。
          </AlertDescription>
          <CopyableBlock
            label="证书操作详情"
            value={JSON.stringify(operationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <Alert>
        <Info />
        <AlertTitle>ACME 全局配置</AlertTitle>
        <AlertDescription>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={acmeConfig?.enabled ? "default" : "secondary"}>
              {acmeConfig?.enabled ? "已启用" : "未启用"}
            </Badge>
            <Badge variant="secondary">
              自动续期：{acmeConfig?.auto_renew ? "开启" : "关闭"}
            </Badge>
            <Badge variant="secondary">
              提前 {acmeConfig?.renew_before_days ?? 30} 天续期
            </Badge>
            <span className="font-mono text-xs break-all text-muted-foreground">
              {acmeConfig?.directory_url || "目录地址未加载"}
            </span>
          </div>
        </AlertDescription>
      </Alert>

      <ConsoleTableShell
        title="证书列表"
        description="按后端分页读取当前系统中的 TLS 证书。"
        state={
          loading ? (
            <EmptyState
              title="证书列表加载中"
              description="正在读取 TLS 证书、ACME 状态和站点引用。"
            />
          ) : certs.length === 0 ? (
            <EmptyState
              title="暂无证书"
              description="上传第一个证书以启用站点 HTTPS 接入。"
            />
          ) : undefined
        }
      >
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground">
              <TableHead className="w-16 px-4 py-3">ID</TableHead>
              <TableHead className="px-4 py-3">名称</TableHead>
              <TableHead className="px-4 py-3">来源</TableHead>
              <TableHead className="px-4 py-3">ACME 状态</TableHead>
              <TableHead className="px-4 py-3">过期时间</TableHead>
              <TableHead className="px-4 py-3">证书引用</TableHead>
              <TableHead className="px-4 py-3">更新时间</TableHead>
              <TableHead className="w-40 px-4 py-3 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {certs.map((cert) => {
              const siteRefs = siteCertRefs[cert.id] || []
              const listenerRefs = listenerCertRefs[cert.id] || []
              const certACMEStatus = acmeStatus[cert.id]
              const acmeStatusMessage = getACMEStatusMessage(
                cert,
                certACMEStatus
              )
              const hasACMEError =
                cert.source === "acme" &&
                Boolean(certACMEStatus?.error || cert.renew_error)

              return (
                <TableRow key={cert.id} className="hover:bg-muted/45">
                <TableCell className="px-4 py-3 font-mono text-xs text-muted-foreground">
                  {cert.id}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <FileKey2 className="size-4 text-muted-foreground" />
                    <span className="font-medium text-foreground">
                      {cert.name}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="px-4 py-3">
                  <Badge
                    variant={
                      cert.source === "acme"
                        ? "default"
                        : cert.source === "self_signed"
                          ? "secondary"
                          : "outline"
                    }
                  >
                    {cert.source === "acme"
                      ? "ACME"
                      : cert.source === "self_signed"
                        ? "自签"
                        : "手动"}
                  </Badge>
                </TableCell>
                <TableCell className="max-w-[160px] px-4 py-3">
                  {cert.source === "acme" ? (
                    <Badge
                      variant={hasACMEError ? "destructive" : "secondary"}
                      className="max-w-full truncate"
                    >
                      {acmeStatusMessage}
                    </Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">-</span>
                  )}
                </TableCell>
                <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                  {certACMEStatus?.expires_at
                    ? formatDate(certACMEStatus.expires_at)
                    : cert.expires_at
                      ? formatDate(cert.expires_at)
                      : "-"}
                </TableCell>
                  <TableCell className="max-w-[180px] px-4 py-3 text-xs text-muted-foreground">
                    {certRefsLoading ? (
                      <span>引用加载中</span>
                    ) : (
                      <span className="line-clamp-2">
                        {formatCertificateReferenceSummary(
                          siteRefs,
                          listenerRefs
                        )}
                      </span>
                    )}
                  </TableCell>
                <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                  {formatDate(cert.updated_at)}
                </TableCell>
                <TableCell className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1">
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      disabled={loadingDetailId === cert.id}
                      onClick={() => void openDetail(cert)}
                      aria-label="查看证书详情"
                    >
                      <Eye data-icon="inline-start" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      disabled={loadingEditId === cert.id}
                      onClick={() => void openEdit(cert)}
                      aria-label="编辑证书"
                    >
                      <Pencil data-icon="inline-start" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      disabled={applyingToSitesId === cert.id}
                      onClick={() => handleApplyToSites(cert)}
                      aria-label="应用证书到匹配站点"
                    >
                      <Link2 data-icon="inline-start" />
                    </Button>
                    {cert.source === "acme" && (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        disabled={renewingId === cert.id}
                        onClick={() => handleRenew(cert.id)}
                        aria-label="续期 ACME 证书"
                      >
                        <RefreshCcw
                          data-icon="inline-start"
                          className={
                            renewingId === cert.id ? "animate-spin" : ""
                          }
                        />
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="text-destructive"
                      onClick={() => setDeleteTarget(cert)}
                      aria-label="删除证书"
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
        {!loading && total > CERTIFICATE_PAGE_SIZE ? (
          <>
            <Separator />
            <div className="bg-muted/20 px-4 py-3">
              <Pagination
                page={page}
                totalPages={totalPages}
                total={total}
                pageSize={CERTIFICATE_PAGE_SIZE}
                onPageChange={setPage}
              />
            </div>
          </>
        ) : null}
      </ConsoleTableShell>

      {/* 上传 Dialog */}
      <Dialog
        open={uploadOpen}
        onOpenChange={(open) => {
          setUploadOpen(open)
          if (!open) {
            setEditingCert(null)
            setCertPreview(null)
          }
        }}
      >
        <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>{editingCert ? "编辑证书" : "上传证书"}</DialogTitle>
            <DialogDescription>
              输入证书名称，并粘贴 PEM 格式的证书和私钥内容，或通过文件上传。
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="cert-name">证书名称</FieldLabel>
              <Input
                id="cert-name"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="例如：example.com"
              />
            </Field>
            <Field>
              <div className="flex items-center justify-between">
                <FieldLabel htmlFor="cert-pem">证书内容 (PEM)</FieldLabel>
                <Button
                  variant="outline"
                  size="xs"
                  type="button"
                  onClick={() => certFileInputRef.current?.click()}
                >
                  <Upload data-icon="inline-start" />
                  选择文件
                </Button>
                <Input
                  ref={certFileInputRef}
                  type="file"
                  accept=".pem,.crt,.cer"
                  className="hidden"
                  tabIndex={-1}
                  aria-hidden="true"
                  onChange={(e) =>
                    e.target.files?.[0] &&
                    handleFileUpload("cert", e.target.files[0])
                  }
                />
              </div>
              <Textarea
                id="cert-pem"
                value={formCert}
                onChange={(e) => {
                  setFormCert(e.target.value)
                  setCertPreview(null)
                }}
                rows={6}
                className="font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
              />
              <div className="flex justify-end">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleParseCertificate}
                  disabled={parsingCert || !formCert.trim()}
                >
                  <TestTube data-icon="inline-start" />
                  {parsingCert ? "解析中..." : "解析证书"}
                </Button>
              </div>
            </Field>
            {certPreview && (
              <Alert>
                <Info />
                <AlertDescription>
                  <div className="flex flex-col gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="secondary">
                        CN：{certPreview.common_name || "-"}
                      </Badge>
                      <Badge variant="secondary">
                        DNS：{certPreview.dns_names?.length || 0}
                      </Badge>
                      <Badge variant="secondary">
                        IP：{certPreview.ip_addresses?.length || 0}
                      </Badge>
                      <Badge variant="secondary">
                        过期：{formatDate(certPreview.expires_at)}
                      </Badge>
                    </div>
                    <div className="text-muted-foreground">
                      匹配站点：
                      {certPreview.matched_sites?.length
                        ? certPreview.matched_sites
                            .map((site) => site.host)
                            .join("，")
                        : "无"}
                    </div>
                  </div>
                </AlertDescription>
              </Alert>
            )}
            <Field>
              <FieldLabel htmlFor="key-pem">私钥内容 (PEM)</FieldLabel>
              <Alert>
                <Info />
                <AlertDescription>
                  私钥只用于提交到后端；保存后详情页不会展示私钥。编辑证书会替换当前证书和私钥内容。
                </AlertDescription>
              </Alert>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  粘贴私钥或选择本地文件
                </span>
                <Button
                  variant="outline"
                  size="xs"
                  type="button"
                  onClick={() => keyFileInputRef.current?.click()}
                >
                  <Upload data-icon="inline-start" />
                  选择文件
                </Button>
                <Input
                  ref={keyFileInputRef}
                  type="file"
                  accept=".pem,.key"
                  className="hidden"
                  tabIndex={-1}
                  aria-hidden="true"
                  onChange={(e) =>
                    e.target.files?.[0] &&
                    handleFileUpload("key", e.target.files[0])
                  }
                />
              </div>
              <Textarea
                id="key-pem"
                value={formKey}
                onChange={(e) => setFormKey(e.target.value)}
                rows={6}
                className="font-mono text-xs"
                placeholder="-----BEGIN PRIVATE KEY-----"
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUploadOpen(false)}>
              取消
            </Button>
            <Button onClick={handleUpload} disabled={uploading}>
              {uploading ? "保存中..." : editingCert ? "保存" : "上传"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 详情 Dialog */}
      <Dialog
        open={!!detailCert}
        onOpenChange={(open) => !open && setDetailCert(null)}
      >
        <DialogContent className="max-h-[85vh] max-w-xl overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>证书详情 — {detailCert?.name}</DialogTitle>
            <DialogDescription>查看证书完整内容。</DialogDescription>
          </DialogHeader>
          {detailCert && (
            <div className="flex flex-col gap-4">
              <div className="grid gap-3 md:grid-cols-2">
                <CertificateDetailItem label="名称">
                  {detailCert.name}
                </CertificateDetailItem>
                <CertificateDetailItem label="来源">
                  <Badge
                    variant={
                      detailCert.source === "acme"
                        ? "default"
                        : detailCert.source === "self_signed"
                          ? "secondary"
                          : "outline"
                    }
                  >
                    {detailCert.source === "acme"
                      ? "ACME (Let's Encrypt)"
                      : detailCert.source === "self_signed"
                        ? "自签证书"
                        : "手动上传"}
                  </Badge>
                </CertificateDetailItem>
                <CertificateDetailItem label="创建时间">
                  {formatDate(detailCert.created_at)}
                </CertificateDetailItem>
                <CertificateDetailItem label="过期时间">
                  {detailCert.expires_at
                    ? formatDate(detailCert.expires_at)
                    : "未知"}
                </CertificateDetailItem>
                {detailCert.domain && (
                  <CertificateDetailItem label="域名" mono>
                    {detailCert.domain}
                  </CertificateDetailItem>
                )}
                {detailCert.source === "acme" && (
                  <CertificateDetailItem label="自动续期">
                    <Badge
                      variant={detailCert.auto_renew ? "default" : "secondary"}
                    >
                      {detailCert.auto_renew ? "已启用" : "未启用"}
                    </Badge>
                  </CertificateDetailItem>
                )}
              </div>
              {detailCert.source === "acme" &&
                (acmeStatus[detailCert.id]?.error || detailCert.renew_error) && (
                  <Alert variant="destructive">
                    <Info />
                    <AlertTitle>ACME 状态</AlertTitle>
                    <AlertDescription>
                      {acmeStatus[detailCert.id]?.error ||
                        detailCert.renew_error}
                    </AlertDescription>
                  </Alert>
                )}
              <Field>
                <FieldLabel>证书 PEM</FieldLabel>
                <div className="max-h-[200px] overflow-auto rounded-lg border bg-card p-3">
                  <pre className="font-mono text-xs break-all whitespace-pre-wrap text-muted-foreground">
                    {detailCert.cert_pem}
                  </pre>
                </div>
              </Field>
              <Field>
                <FieldLabel>证书引用</FieldLabel>
                <CertificateReferencePanel
                  siteRefs={siteCertRefs[detailCert.id] || []}
                  listenerRefs={listenerCertRefs[detailCert.id] || []}
                />
              </Field>
              <Field>
                <FieldLabel>私钥 PEM</FieldLabel>
                <div className="rounded-lg border bg-card p-3 text-sm text-muted-foreground">
                  私钥已加密存储，不在详情页展示。需要更换私钥时请使用编辑功能重新上传。
                </div>
              </Field>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setDetailCert(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ACME 配置 Dialog */}
      <Dialog open={acmeConfigOpen} onOpenChange={setAcmeConfigOpen}>
        <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>ACME 全局配置</DialogTitle>
            <DialogDescription>
              配置证书申请使用的 ACME 账户、目录地址和自动续期策略。
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field
              orientation="horizontal"
              className="items-center justify-between rounded-lg border bg-muted/35 px-4 py-3"
            >
              <FieldContent>
                <FieldLabel htmlFor={acmeConfigEnabledId}>
                  启用 ACME
                </FieldLabel>
                <FieldDescription>
                  启用后可申请和续期 ACME 来源证书。
                </FieldDescription>
              </FieldContent>
              <Switch
                id={acmeConfigEnabledId}
                checked={acmeEnabled}
                onCheckedChange={setAcmeEnabled}
                disabled={acmeConfigLoading}
              />
            </Field>

            <Field>
              <FieldLabel htmlFor={acmeConfigEmailId}>账户邮箱</FieldLabel>
              <Input
                id={acmeConfigEmailId}
                type="email"
                value={acmeConfigEmail}
                onChange={(e) => setAcmeConfigEmail(e.target.value)}
                placeholder="admin@example.com"
                disabled={acmeConfigLoading}
              />
              <FieldDescription>
                启用 ACME 且留空时，后端会生成随机 ACME 账户邮箱。
              </FieldDescription>
            </Field>

            <Field>
              <FieldLabel htmlFor={acmeConfigDirectoryURLId}>
                ACME 目录地址
              </FieldLabel>
              <Input
                id={acmeConfigDirectoryURLId}
                value={acmeDirectoryURL}
                onChange={(e) => setAcmeDirectoryURL(e.target.value)}
                placeholder="https://acme-v02.api.letsencrypt.org/directory"
                className="font-mono text-xs"
                disabled={acmeConfigLoading}
              />
              <FieldDescription>
                留空时后端使用默认 ACME 目录地址。
              </FieldDescription>
            </Field>

            <Field
              orientation="horizontal"
              className="items-center justify-between rounded-lg border bg-muted/35 px-4 py-3"
            >
              <FieldContent>
                <FieldLabel htmlFor={acmeConfigAutoRenewId}>
                  自动续期
                </FieldLabel>
                <FieldDescription>
                  对 ACME 来源证书启用到期前自动续期策略。
                </FieldDescription>
              </FieldContent>
              <Switch
                id={acmeConfigAutoRenewId}
                checked={acmeAutoRenew}
                onCheckedChange={setAcmeAutoRenew}
                disabled={acmeConfigLoading}
              />
            </Field>

            <Field data-invalid={acmeRenewBeforeDays <= 0}>
              <FieldLabel htmlFor={acmeConfigRenewBeforeDaysId}>
                提前续期天数
              </FieldLabel>
              <Input
                id={acmeConfigRenewBeforeDaysId}
                type="number"
                min={1}
                value={acmeRenewBeforeDays}
                onChange={(e) =>
                  setAcmeRenewBeforeDays(Number(e.target.value))
                }
                aria-invalid={acmeRenewBeforeDays <= 0}
                disabled={acmeConfigLoading}
              />
              <FieldDescription>
                后端要求该值大于 0，默认值为 30。
              </FieldDescription>
              <FieldError>
                {acmeRenewBeforeDays <= 0 ? "请输入大于 0 的天数" : ""}
              </FieldError>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                if (acmeConfig) applyACMEConfigState(acmeConfig)
                setAcmeConfigOpen(false)
              }}
              disabled={savingACMEConfig}
            >
              取消
            </Button>
            <Button
              onClick={handleSaveACMEConfig}
              disabled={savingACMEConfig || acmeConfigLoading}
            >
              {savingACMEConfig ? "保存中..." : "保存配置"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ACME 申请 Dialog */}
      <Dialog open={acmeOpen} onOpenChange={setAcmeOpen}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>ACME 证书申请</DialogTitle>
            <DialogDescription>
              通过 Let&apos;s Encrypt 自动申请免费 TLS 证书（HTTP-01
              质询）。确保域名已解析到本服务器并且 80 端口可访问。
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field data-invalid={Boolean(acmeDomainError)}>
              <FieldLabel htmlFor="acme-domain">域名</FieldLabel>
              <Input
                id="acme-domain"
                value={acmeDomain}
                onChange={(e) => {
                  setAcmeDomain(e.target.value)
                  if (acmeDomainError) setAcmeDomainError("")
                }}
                placeholder="example.com"
                aria-invalid={Boolean(acmeDomainError)}
              />
              <FieldError>{acmeDomainError}</FieldError>
            </Field>
            <Field>
              <FieldLabel htmlFor="acme-email">申请邮箱（可选）</FieldLabel>
              <Input
                id="acme-email"
                type="email"
                value={acmeEmail}
                onChange={(e) => setAcmeEmail(e.target.value)}
                placeholder="admin@example.com"
              />
              <FieldDescription>
                留空时后端会按申请域名生成随机 ACME 账户邮箱。
              </FieldDescription>
            </Field>
            <Alert>
              <Info />
              <AlertDescription>
                申请时会按域名匹配已启用站点，并由数据面直接处理 HTTP-01
                质询；请确保 80 端口可访问且域名已解析到本机。
              </AlertDescription>
            </Alert>
            <Field>
              <FieldLabel htmlFor="acme-name">证书名称（可选）</FieldLabel>
              <Input
                id="acme-name"
                value={acmeName}
                onChange={(e) => setAcmeName(e.target.value)}
                placeholder="留空则使用域名"
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAcmeOpen(false)}>
              取消
            </Button>
            <Button onClick={handleACMEApply} disabled={acmeApplying}>
              {acmeApplying ? "申请中..." : "申请证书"}
            </Button>
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
            <AlertDialogTitle>确认删除证书</AlertDialogTitle>
            <AlertDialogDescription>
              删除后使用此证书的站点或监听端口将无法建立 HTTPS
              连接。请先确认没有站点或 SNI 监听正在引用该证书。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Alert variant="destructive">
            <Info />
            <AlertTitle>目标证书</AlertTitle>
            <AlertDescription>{deleteTarget?.name || "-"}</AlertDescription>
          </Alert>
          <Alert variant={deleteBlockedByRefs ? "destructive" : "default"}>
            <Info />
            <AlertTitle>
              {deleteBlockedByRefs ? "证书仍被引用" : "证书引用"}
            </AlertTitle>
            <AlertDescription>
              <div className="flex flex-col gap-1">
                <div>
                  站点引用（{deleteSiteRefs.length}）：
                  {formatCertificateReferencePreview(deleteSiteRefs, 3)}
                </div>
                <div>
                  监听引用（{deleteListenerRefs.length}）：
                  {formatCertificateReferencePreview(deleteListenerRefs, 3)}
                </div>
              </div>
            </AlertDescription>
          </Alert>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting || certRefsLoading || deleteBlockedByRefs}
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
