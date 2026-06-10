"use client"

import Link from "next/link"
import { useCallback, useEffect, useId, useMemo, useState } from "react"
import { useParams, usePathname, useSearchParams } from "next/navigation"
import {
  ArrowLeft,
  AlertTriangle,
  Bot,
  Download,
  ExternalLink,
  FileText,
  Loader2,
  Plus,
  Route,
  Save,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Zap,
} from "@/lib/icons"
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
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
} from "@/components/ui/field"
import { SiteErrorPagesPanel } from "@/components/site-error-pages-panel"
import { SiteListenersPanel } from "@/components/site-listeners-panel"
import { SiteObservabilityPanel } from "@/components/site-observability-panel"
import { Pagination } from "@/components/pagination"
import {
  CopyableBlock,
  DetailField,
  redactSensitiveText,
} from "@/components/log-presentation"
import {
  clearRecordedResources,
  createApplicationRouteRule,
  deleteApplicationRouteRule,
  getSite,
  getSiteAccessLogStats,
  getSiteStatus,
  getConfigAppliedReloadFailureDetails,
  getUpstreamStatus,
  isConfigAppliedReloadFailureError,
  listApplicationRouteRules,
  listAllApplicationRouteRules,
  listAllCertificates,
  listRecordedResources,
  listSiteListeners,
  startSite,
  stopSite,
  updateApplicationRouteRule,
  updateSite,
  type ApplicationRouteRule,
  type ApplicationRouteRuleQuery,
  type Certificate,
  type RecordedResource,
  type RecordedResourceQuery,
  type Site,
  type SiteAccessLogStats,
  type SiteListener,
  type SiteStatus,
  type UpstreamStatusItem,
} from "@/lib/api"
import { EmptyState, PageIntro } from "@/components/console-shell"
import {
  antiReplayWAFActionOptions,
  nonRedirectWAFActionOptions,
} from "@/lib/console"
import {
  findInvalidSiteUpstream,
  parseSiteUpstreams,
  serializeSiteUpstreams,
} from "@/lib/site-upstreams"
import { downloadTextFile } from "@/lib/download"
import { MultiHostInput } from "@/components/multi-host-input"
import { cn, formatDate } from "@/lib/utils"
import { toast } from "sonner"

const sensitivityLevels = [
  { value: "off", label: "禁用" },
  { value: "low", label: "低" },
  { value: "mid", label: "中" },
  { value: "high", label: "高" },
  { value: "very_high", label: "极高" },
  { value: "strict", label: "严格" },
]

const DEFAULT_SITE_OWASP_SENSITIVITY = "mid"
const DEFAULT_SITE_OWASP_ACTION = "intercept"
const DEFAULT_SITE_CVE_ACTION = "intercept"
const DEFAULT_SITE_RATE_LIMIT_WINDOW = 60
const DEFAULT_SITE_RATE_LIMIT_MAX = 300
const DEFAULT_SITE_RATE_LIMIT_ACTION = "rate_limit"
const DEFAULT_SITE_BOT_LEVEL = "medium"
const APP_ROUTE_RULE_PAGE_SIZE = 50

const APP_ROUTE_TARGETS: { value: string; label: string }[] = [
  { value: "request_method", label: "请求方法" },
  { value: "request_header", label: "请求 Header（单项）" },
  { value: "request_body", label: "请求 Body" },
  { value: "response_body", label: "响应 Body" },
  { value: "request_headers_full", label: "完整请求头（文本）" },
  { value: "response_headers_full", label: "完整响应头（文本）" },
  { value: "full_http_request", label: "完整 HTTP 请求（摘要）" },
  { value: "full_http_response", label: "完整 HTTP 响应（摘要）" },
  { value: "fingerprint", label: "指纹特征（JA3+UA）" },
]

const APP_ROUTE_OPS: { value: string; label: string }[] = [
  { value: "eq", label: "等于" },
  { value: "ne", label: "不等于" },
  { value: "contains", label: "包含" },
  { value: "not_contains", label: "不包含" },
  { value: "prefix", label: "前缀" },
  { value: "suffix", label: "后缀" },
  { value: "regex", label: "正则" },
  { value: "fuzzy", label: "模糊（忽略大小写包含）" },
]

function extractSiteId(pathValue: string | undefined) {
  if (!pathValue) return ""
  const last = pathValue.split("/").filter(Boolean).at(-1) ?? ""
  return /^\d+$/.test(last) ? last : ""
}

function recordedAccessLogHref(resource: RecordedResource) {
  const params = new URLSearchParams()
  params.set("site_id", String(resource.site_id))
  if (resource.client_ip) params.set("client_ip", resource.client_ip)
  if (resource.host) params.set("host", resource.host)
  if (resource.path) params.set("path", resource.path)
  return `/access-logs/?${params.toString()}`
}

function recordedSecurityEventHref(resource: RecordedResource) {
  const params = new URLSearchParams()
  if (resource.client_ip) params.set("client_ip", resource.client_ip)
  if (resource.host) params.set("host", resource.host)
  if (resource.path) params.set("path", resource.path)
  const query = params.toString()
  return query ? `/security-events/?${query}` : "/security-events/"
}

function isManagedSiteListener(listener: SiteListener) {
  return listener.id > 0
}

function isSiteListenerEnabled(listener: SiteListener) {
  return listener.enabled !== false
}

function formatSiteEntrySummary(site: Site, listeners: SiteListener[]) {
  const managedListeners = listeners.filter(isManagedSiteListener)
  const activeManagedListeners = managedListeners.filter(isSiteListenerEnabled)
  if (managedListeners.length === 0) {
    return `${site.tls_enabled ? "HTTPS" : "HTTP"} · 监听 ${site.bind} · 网络 ${site.network}`
  }
  if (activeManagedListeners.length === 0) {
    return `显式监听已全部停用 · ${managedListeners.length} 个监听`
  }
  const binds = activeManagedListeners.map((listener) => listener.bind).join(" / ")
  const hasTLS = activeManagedListeners.some((listener) => listener.tls_enabled)
  return `${hasTLS ? "多监听（含 HTTPS）" : "多监听（HTTP）"} · 监听 ${binds}`
}

type TabKey =
  | "basic"
  | "listeners"
  | "upstream"
  | "advanced"
  | "inventory"
  | "observability"
  | "error-pages"

export default function SiteDetailClient() {
  const preserveOriginalHostId = useId()
  const upstreamTLSSkipVerifyId = useId()
  const owaspEnabledId = useId()
  const cveEnabledId = useId()
  const rateLimitEnabledId = useId()
  const params = useParams()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const siteId = useMemo(() => {
    const rawId = params.id as string | undefined
    const queryId = searchParams.get("id") || undefined
    return (
      extractSiteId(queryId) ||
      extractSiteId(rawId) ||
      extractSiteId(pathname) ||
      (typeof window !== "undefined"
        ? extractSiteId(window.location.pathname)
        : "") ||
      "_"
    )
  }, [params.id, pathname, searchParams])

  const [site, setSite] = useState<Site | null>(null)
  const [siteStatus, setSiteStatus] = useState<SiteStatus | null>(null)
  const [siteListeners, setSiteListeners] = useState<SiteListener[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [tab, setTab] = useState<TabKey>("basic")
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [siteOperationDetails, setSiteOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [appRouteOperationDetails, setAppRouteOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [accessStats, setAccessStats] = useState<SiteAccessLogStats | null>(
    null
  )

  const [hosts, setHosts] = useState<string[]>([])
  const [bind, setBind] = useState("")
  const [network, setNetwork] = useState("tcp")
  const [tlsEnabled, setTlsEnabled] = useState(false)
  const [certId, setCertId] = useState<number | null>(null)
  const [certificates, setCertificates] = useState<Certificate[]>([])
  const [minTlsVersion, setMinTlsVersion] = useState("TLS12")
  const [maxTlsVersion, setMaxTlsVersion] = useState("TLS13")
  const [cipherSuites, setCipherSuites] = useState("")
  const [alpn, setAlpn] = useState("h2,http/1.1")
  const [upstreams, setUpstreams] = useState<string[]>([])
  const [xffMode, setXFFMode] = useState("strip_all_and_set_remote")
  const [trustedCIDR, setTrustedCIDR] = useState("")
  const [preserveOriginalHost, setPreserveOriginalHost] = useState(false)
  const [upstreamTLSSkipVerify, setUpstreamTLSSkipVerify] = useState(false)
  const [upstreamTLSServerName, setUpstreamTLSServerName] = useState("")
  const [upstreamStatuses, setUpstreamStatuses] = useState<
    UpstreamStatusItem[]
  >([])
  const [upstreamStatusLoading, setUpstreamStatusLoading] = useState(false)
  const [cacheEnabled, setCacheEnabled] = useState(false)
  const [cacheDefaultTTL, setCacheDefaultTTL] = useState(0)
  const [cacheRules, setCacheRules] = useState<
    Array<{
      type: string
      value: string
      ttl: number
      case_insensitive: boolean
      ignore_query: boolean
    }>
  >([])
  const [owaspAction, setOwaspAction] = useState(DEFAULT_SITE_OWASP_ACTION)
  const [cveAction, setCveAction] = useState(DEFAULT_SITE_CVE_ACTION)
  const [rateLimitAction, setRateLimitAction] = useState(
    DEFAULT_SITE_RATE_LIMIT_ACTION
  )

  const [blockHtml, setBlockHtml] = useState("")
  const [blockStatus, setBlockStatus] = useState(403)
  const [maintenanceEnabled, setMaintenanceEnabled] = useState(false)
  const [maintenanceHtml, setMaintenanceHtml] = useState("")
  const [maintenanceStatus, setMaintenanceStatus] = useState(503)
  const [maxBodyBytes, setMaxBodyBytes] = useState(0)
  const [antiReplayEnabled, setAntiReplayEnabled] = useState(false)
  const [antiReplayTTL, setAntiReplayTTL] = useState(300)
  const [antiReplayAction, setAntiReplayAction] = useState("shield_challenge")

  const [owaspEnabled, setOwaspEnabled] = useState<boolean | null>(null)
  const [owaspSensitivity, setOwaspSensitivity] = useState("")
  const [cveEnabled, setCveEnabled] = useState<boolean | null>(null)
  const [rateLimitEnabled, setRateLimitEnabled] = useState<boolean | null>(null)
  const [rateLimitWindow, setRateLimitWindow] = useState(0)
  const [rateLimitMax, setRateLimitMax] = useState(0)
  const [botProtectionEnabled, setBotProtectionEnabled] = useState<
    boolean | null
  >(null)
  const [botProtectionLevel, setBotProtectionLevel] = useState(
    DEFAULT_SITE_BOT_LEVEL
  )

  const [appRules, setAppRules] = useState<ApplicationRouteRule[]>([])
  const [appRuleTotal, setAppRuleTotal] = useState(0)
  const [appRulePage, setAppRulePage] = useState(1)
  const [recItems, setRecItems] = useState<RecordedResource[]>([])
  const [recTotal, setRecTotal] = useState(0)
  const [recPage, setRecPage] = useState(1)
  const [invLoading, setInvLoading] = useState(false)
  const [exportingAppRules, setExportingAppRules] = useState(false)
  const [deleteAppRuleId, setDeleteAppRuleId] = useState<number | null>(null)
  const [deletingAppRule, setDeletingAppRule] = useState(false)
  const [clearRecordedOpen, setClearRecordedOpen] = useState(false)
  const [clearingRecorded, setClearingRecorded] = useState(false)
  const [recordedDetail, setRecordedDetail] = useState<RecordedResource | null>(
    null
  )
  const recPageSize = 20

  const load = useCallback(async () => {
    if (siteId === "_") {
      setSite(null)
      setLoading(false)
      return
    }
    setLoading(true)
    try {
      const [s, stats, listenerData] = await Promise.all([
        getSite(siteId),
        getSiteAccessLogStats(siteId).catch((error) => {
          toast.error(
            error instanceof Error ? error.message : "加载站点统计失败"
          )
          return null
        }),
        listSiteListeners(Number(siteId)).catch((error) => {
          toast.error(
            error instanceof Error ? error.message : "加载监听端口失败"
          )
          return null
        }),
      ])
      setSite(s)
      setAccessStats(stats)
      setSiteListeners(listenerData?.items || [])
      getSiteStatus(siteId)
        .then(setSiteStatus)
        .catch((error) => {
          toast.error(
            error instanceof Error ? error.message : "加载站点运行状态失败"
          )
          setSiteStatus({
            id: s.id,
            host: s.host,
            status: s.enabled ? "running" : "stopped",
          })
        })
      // Populate form
      setHosts(
        s.host
          ? s.host
              .split(",")
              .map((h: string) => h.trim())
              .filter(Boolean)
          : []
      )
      setBind(s.bind)
      setNetwork(s.network)
      setTlsEnabled(s.tls_enabled)
      setCertId(s.cert_id ?? null)
      setMinTlsVersion(s.min_tls_version || "TLS12")
      setMaxTlsVersion(s.max_tls_version || "TLS13")
      setCipherSuites(s.cipher_suites || "")
      setAlpn(s.alpn || "h2,http/1.1")
      setUpstreams(parseSiteUpstreams(s.upstream_urls))
      setXFFMode(s.xff_mode || "strip_all_and_set_remote")
      setTrustedCIDR(s.trusted_cidr || "")
      setPreserveOriginalHost(Boolean(s.preserve_original_host))
      setUpstreamTLSSkipVerify(Boolean(s.upstream_tls_skip_verify))
      setUpstreamTLSServerName(s.upstream_tls_server_name || "")
      setCacheEnabled(Boolean(s.cache_enabled))
      setCacheDefaultTTL(s.cache_default_ttl || 0)
      if (Array.isArray(s.cache_rules)) {
        setCacheRules(
          s.cache_rules.map((rule) => ({
            type: rule.type || "prefix",
            value: rule.value || rule.path || "",
            ttl: rule.ttl || 0,
            case_insensitive: Boolean(rule.case_insensitive),
            ignore_query: Boolean(rule.ignore_query),
          }))
        )
      } else if (typeof s.cache_rules === "string" && s.cache_rules.trim()) {
        try {
          const parsed = JSON.parse(s.cache_rules) as Array<{
            type?: string
            value?: string
            path?: string
            ttl?: number
            case_insensitive?: boolean
            ignore_query?: boolean
          }>
          setCacheRules(
            parsed.map((rule) => ({
              type: rule.type || "prefix",
              value: rule.value || rule.path || "",
              ttl: rule.ttl || 0,
              case_insensitive: Boolean(rule.case_insensitive),
              ignore_query: Boolean(rule.ignore_query),
            }))
          )
        } catch {
          setCacheRules([])
        }
      } else {
        setCacheRules([])
      }
      setOwaspAction(s.owasp_action || DEFAULT_SITE_OWASP_ACTION)
      setCveAction(s.cve_action || DEFAULT_SITE_CVE_ACTION)
      setRateLimitAction(
        s.rate_limit_action || DEFAULT_SITE_RATE_LIMIT_ACTION
      )
      setOwaspEnabled(s.owasp_enabled ?? null)
      setOwaspSensitivity(s.owasp_sensitivity || "")
      setCveEnabled(s.cve_enabled ?? null)
      setRateLimitEnabled(s.rate_limit_enabled ?? null)
      setRateLimitWindow(s.rate_limit_window || 0)
      setRateLimitMax(s.rate_limit_max || 0)
      setBotProtectionEnabled(s.bot_protection_enabled ?? null)
      setBotProtectionLevel(s.bot_protection_level || DEFAULT_SITE_BOT_LEVEL)
      setBlockHtml(s.block_html || "")
      setBlockStatus(s.block_status || 403)
      setMaintenanceEnabled(s.maintenance_enabled)
      setMaintenanceHtml(s.maintenance_html || "")
      setMaintenanceStatus(s.maintenance_status || 503)
      setMaxBodyBytes(s.max_body_bytes || 0)
      setAntiReplayEnabled(Boolean(s.anti_replay_enabled))
      setAntiReplayTTL(s.anti_replay_ttl || 300)
      setAntiReplayAction(s.anti_replay_action || "shield_challenge")
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "加载站点配置失败")
      setSite(null)
      setSiteStatus(null)
      setSiteListeners([])
    } finally {
      setLoading(false)
    }
  }, [siteId])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  useEffect(() => {
    listAllCertificates()
      .then((data) => setCertificates(data.items || []))
      .catch((error) => {
        toast.error(error instanceof Error ? error.message : "加载证书列表失败")
        setCertificates([])
      })
  }, [])

  const managedSiteListeners = useMemo(
    () => siteListeners.filter(isManagedSiteListener),
    [siteListeners]
  )
  const hasManagedListeners = managedSiteListeners.length > 0
  const hasManagedTLSListeners = managedSiteListeners.some(
    (listener) => listener.tls_enabled
  )
  const showTLSSettings = tlsEnabled || hasManagedTLSListeners
  const siteEntrySummary = site
    ? formatSiteEntrySummary(site, siteListeners)
    : ""

  const refreshInventory = useCallback(
    async (recordedPageOverride?: number, appRulePageOverride?: number) => {
      if (siteId === "_" || siteId === "") return
      const sid = Number(siteId)
      if (Number.isNaN(sid)) return
      const recordedPage = recordedPageOverride ?? recPage
      const rulePage = appRulePageOverride ?? appRulePage
      const appRouteRuleParams: ApplicationRouteRuleQuery = {
        page: rulePage,
        page_size: APP_ROUTE_RULE_PAGE_SIZE,
      }
      const recordedResourceParams: RecordedResourceQuery = {
        page: recordedPage,
        page_size: recPageSize,
      }
      setInvLoading(true)
      try {
        const [rRules, rRec] = await Promise.all([
          listApplicationRouteRules(sid, appRouteRuleParams),
          listRecordedResources(sid, recordedResourceParams),
        ])
        const nextRuleTotal = Number(rRules.total) || 0
        const nextRuleTotalPages = Math.max(
          1,
          Math.ceil(nextRuleTotal / APP_ROUTE_RULE_PAGE_SIZE)
        )
        if (rulePage > nextRuleTotalPages) {
          setAppRulePage(nextRuleTotalPages)
          return
        }
        setAppRules(rRules.items || [])
        setAppRuleTotal(nextRuleTotal)
        setRecItems(rRec.items || [])
        setRecTotal(Number(rRec.total) || 0)
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "加载站点资源清单失败")
      } finally {
        setInvLoading(false)
      }
    },
    [appRulePage, siteId, recPage, recPageSize]
  )

  useEffect(() => {
    if (tab !== "inventory" || siteId === "_") return
    return deferEffect(refreshInventory)
  }, [tab, siteId, appRulePage, recPage, recPageSize, refreshInventory])

  const refreshUpstreamStatus = useCallback(async () => {
    setUpstreamStatusLoading(true)
    try {
      const result = await getUpstreamStatus()
      setUpstreamStatuses(result.items ?? [])
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载上游健康失败")
      setUpstreamStatuses([])
    } finally {
      setUpstreamStatusLoading(false)
    }
  }, [])

  useEffect(() => {
    if (tab !== "upstream") return
    return deferEffect(refreshUpstreamStatus)
  }, [tab, refreshUpstreamStatus])

  function rememberReloadFailureDetails(error: unknown) {
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (details) {
      setReloadFailureDetails(details)
    }
  }

  async function handleSave() {
    if (!site) return
    const normalizedUpstreams = upstreams
      .map((item) => item.trim())
      .filter(Boolean)
    if (normalizedUpstreams.length === 0) {
      toast.error("至少需要配置一个上游地址")
      return
    }
    const invalidUpstream = findInvalidSiteUpstream(normalizedUpstreams)
    if (invalidUpstream) {
      toast.error(`上游地址格式无效：${invalidUpstream}`)
      return
    }
    if (tlsEnabled && !certId) {
      toast.error("启用 HTTPS 时请选择证书")
      return
    }
    if (
      tlsEnabled &&
      certId &&
      !certificates.some((cert) => cert.id === certId)
    ) {
      toast.error("当前绑定的证书不在可用证书列表中，请重新选择证书")
      return
    }

    let payload: Partial<Site>
    switch (tab) {
      case "basic":
        payload = {
          host: hosts.join(", "),
          bind,
          network,
          tls_enabled: tlsEnabled,
          cert_id: tlsEnabled ? certId : null,
          min_tls_version: showTLSSettings ? minTlsVersion : undefined,
          max_tls_version: showTLSSettings ? maxTlsVersion : undefined,
          cipher_suites: showTLSSettings ? cipherSuites : undefined,
          alpn: showTLSSettings ? alpn : undefined,
          xff_mode: xffMode,
          trusted_cidr: trustedCIDR,
          preserve_original_host: preserveOriginalHost,
        }
        break
      case "upstream":
        payload = {
          upstream_urls: serializeSiteUpstreams(normalizedUpstreams),
          upstream_tls_skip_verify: upstreamTLSSkipVerify,
          upstream_tls_server_name: upstreamTLSServerName,
        }
        break
      case "advanced":
        payload = {
          cache_enabled: cacheEnabled,
          cache_default_ttl: cacheDefaultTTL,
          cache_rules: JSON.stringify(
            cacheRules
              .filter(
                (rule) =>
                  rule.value.trim() &&
                  (rule.ttl > 0 || (rule.ttl === 0 && cacheDefaultTTL > 0))
              )
              .map((rule) => ({
                type: rule.type,
                value: rule.value.trim(),
                ttl: rule.ttl,
                case_insensitive: rule.case_insensitive,
                ignore_query: rule.ignore_query,
              }))
          ),
          owasp_action: owaspAction,
          cve_action: cveAction,
          rate_limit_action: rateLimitAction,
          owasp_enabled: owaspEnabled,
          owasp_sensitivity: owaspSensitivity || undefined,
          cve_enabled: cveEnabled,
          rate_limit_enabled: rateLimitEnabled,
          rate_limit_window: rateLimitWindow || undefined,
          rate_limit_max: rateLimitMax || undefined,
          bot_protection_enabled: botProtectionEnabled,
          bot_protection_level:
            botProtectionEnabled === null
              ? ""
              : botProtectionLevel || undefined,
          block_html: blockHtml,
          block_status: blockStatus,
          maintenance_enabled: maintenanceEnabled,
          maintenance_html: maintenanceHtml,
          maintenance_status: maintenanceStatus,
          max_body_bytes: maxBodyBytes,
          anti_replay_enabled: antiReplayEnabled,
          anti_replay_ttl: antiReplayTTL,
          anti_replay_action: antiReplayAction,
        }
        if (owaspEnabled === null) {
          payload.owasp_action = ""
          payload.owasp_sensitivity = ""
        }
        if (cveEnabled === null) {
          payload.cve_action = ""
        }
        if (rateLimitEnabled === null) {
          payload.rate_limit_action = ""
          payload.rate_limit_window = 0
          payload.rate_limit_max = 0
        }
        break
      default:
        return
    }

    setReloadFailureDetails(null)
    setSiteOperationDetails(null)
    setAppRouteOperationDetails(null)
    setSaving(true)
    try {
      const result = await updateSite(site.id, payload)
      setSiteOperationDetails({
        operation: `save_${tab}`,
        site_id: site.id,
        host: site.host,
        tab,
        payload,
        response: result,
      })
      toast.success("站点配置已保存")
      await load()
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(err)
        if (details) {
          setSiteOperationDetails({
            operation: `save_${tab}`,
            site_id: site.id,
            host: site.host,
            tab,
            payload,
            response: details,
          })
        }
        toast.error(err.message)
        await load()
      } else {
        toast.error(err instanceof Error ? err.message : "保存站点配置失败")
      }
    } finally {
      setSaving(false)
    }
  }

  async function handleToggle() {
    if (!site) return
    const operation = site.enabled ? "stop" : "start"
    const payload = { enabled: !site.enabled }
    setReloadFailureDetails(null)
    setSiteOperationDetails(null)
    setAppRouteOperationDetails(null)
    try {
      const response = site.enabled
        ? await stopSite(site.id)
        : await startSite(site.id)
      setSiteOperationDetails({
        operation,
        site_id: site.id,
        host: site.host,
        payload,
        response,
      })
      setSiteStatus({
        id: site.id,
        host: site.host,
        status: site.enabled ? "stopped" : "running",
      })
      toast.success(site.enabled ? "站点已停用" : "站点已启用")
      await load()
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(err)
        if (details) {
          setSiteOperationDetails({
            operation: site.enabled ? "stop" : "start",
            site_id: site.id,
            host: site.host,
            payload,
            response: details,
          })
        }
        toast.error(err.message)
        await load()
      } else {
        toast.error(err instanceof Error ? err.message : "更新站点状态失败")
      }
    }
  }

  function patchAppRule(ruleId: number, patch: Partial<ApplicationRouteRule>) {
    setAppRules((prev) =>
      prev.map((r) => (r.id === ruleId ? { ...r, ...patch } : r))
    )
  }

  function isAppRouteRuleEnabled(rule: Pick<ApplicationRouteRule, "enabled">) {
    return rule.enabled !== false
  }

  async function handleAddAppRule() {
    if (!site) return
    const payload = {
      name: `资源规则 ${appRuleTotal + 1}`,
      enabled: true,
      priority: 0,
      target: "request_method",
      op: "eq",
      pattern: "GET",
      header_key: "",
    }
    setReloadFailureDetails(null)
    setSiteOperationDetails(null)
    setAppRouteOperationDetails(null)
    try {
      const result = await createApplicationRouteRule(site.id, payload)
      setAppRouteOperationDetails({
        operation: "create",
        site_id: site.id,
        host: site.host,
        payload,
        response: result,
      })
      toast.success("已创建规则")
      setAppRulePage(1)
      await refreshInventory(undefined, 1)
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(err)
        if (details) {
          setAppRouteOperationDetails({
            operation: "create",
            site_id: site.id,
            host: site.host,
            payload: {
              name: `资源规则 ${appRuleTotal + 1}`,
              enabled: true,
              priority: 0,
              target: "request_method",
              op: "eq",
              pattern: "GET",
              header_key: "",
            },
            response: details,
          })
        }
        toast.error(err.message)
        setAppRulePage(1)
        await refreshInventory(undefined, 1)
      } else {
        toast.error(err instanceof Error ? err.message : "创建规则失败")
      }
    }
  }

  async function handleSaveAppRule(rule: ApplicationRouteRule) {
    if (!site || rule.id == null) return
    const payload = {
      name: rule.name ?? "",
      enabled: isAppRouteRuleEnabled(rule),
      priority: rule.priority ?? 0,
      target: rule.target,
      op: rule.op,
      pattern: rule.pattern,
      header_key: rule.header_key ?? "",
    }
    setReloadFailureDetails(null)
    setSiteOperationDetails(null)
    setAppRouteOperationDetails(null)
    try {
      const result = await updateApplicationRouteRule(site.id, rule.id, payload)
      setAppRouteOperationDetails({
        operation: "update",
        site_id: site.id,
        host: site.host,
        rule_id: rule.id,
        payload,
        response: result,
      })
      toast.success("规则已保存")
      await refreshInventory()
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(err)
        if (details) {
          setAppRouteOperationDetails({
            operation: "update",
            site_id: site.id,
            host: site.host,
            rule_id: rule.id,
            payload: {
              name: rule.name ?? "",
              enabled: isAppRouteRuleEnabled(rule),
              priority: rule.priority ?? 0,
              target: rule.target,
              op: rule.op,
              pattern: rule.pattern,
              header_key: rule.header_key ?? "",
            },
            response: details,
          })
        }
        toast.error(err.message)
        await refreshInventory()
      } else {
        toast.error(err instanceof Error ? err.message : "保存规则失败")
      }
    }
  }

  async function handleDeleteAppRule() {
    if (!site || deleteAppRuleId == null) return
    const ruleId = deleteAppRuleId
    setReloadFailureDetails(null)
    setSiteOperationDetails(null)
    setAppRouteOperationDetails(null)
    setDeletingAppRule(true)
    try {
      const result = await deleteApplicationRouteRule(site.id, ruleId)
      setAppRouteOperationDetails({
        operation: "delete",
        site_id: site.id,
        host: site.host,
        rule_id: ruleId,
        payload: {
          rule_id: ruleId,
        },
        status_code: 200,
        response: result,
      })
      toast.success("已删除")
      setDeleteAppRuleId(null)
      await refreshInventory()
    } catch (err) {
      if (isConfigAppliedReloadFailureError(err)) {
        rememberReloadFailureDetails(err)
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(err)
        if (details) {
          setAppRouteOperationDetails({
            operation: "delete",
            site_id: site.id,
            host: site.host,
            rule_id: ruleId,
            payload: {
              rule_id: ruleId,
            },
            response: details,
          })
        }
        toast.error(err.message)
        setDeleteAppRuleId(null)
        await refreshInventory()
      } else {
        toast.error(err instanceof Error ? err.message : "删除规则失败")
      }
    } finally {
      setDeletingAppRule(false)
    }
  }

  async function handleExportAppRules() {
    if (!site) return
    setReloadFailureDetails(null)
    setSiteOperationDetails(null)
    setAppRouteOperationDetails(null)
    setExportingAppRules(true)
    try {
      const result = await listAllApplicationRouteRules(site.id)
      const exportedAt = new Date().toISOString()
      const filename = `site-${site.id}-application-route-rules.json`
      const payload = {
        site_id: site.id,
        site_host: site.host,
        total: result.total,
        page_count: result.page,
        exported_at: exportedAt,
        items: result.items,
      }
      downloadTextFile(
        JSON.stringify(payload, null, 2),
        filename,
        "application/json;charset=utf-8;"
      )
      setAppRouteOperationDetails({
        operation: "export_application_route_rules",
        site_id: site.id,
        host: site.host,
        filename,
        response: result,
      })
      toast.success(`已导出 ${result.items.length} 条应用路由规则`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "导出应用路由规则失败")
    } finally {
      setExportingAppRules(false)
    }
  }

  async function handleClearRecorded() {
    if (!site) return
    const payload = {
      site_id: site.id,
    }
    setReloadFailureDetails(null)
    setSiteOperationDetails(null)
    setAppRouteOperationDetails(null)
    setClearingRecorded(true)
    try {
      const response = await clearRecordedResources(site.id)
      setAppRouteOperationDetails({
        operation: "clear_recorded_resources",
        site_id: site.id,
        host: site.host,
        payload,
        response,
      })
      toast.success("已清空")
      setRecPage(1)
      setClearRecordedOpen(false)
      await refreshInventory(1)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "清空录制资源失败")
    } finally {
      setClearingRecorded(false)
    }
  }

  if (loading) {
    return (
      <EmptyState
        title="正在加载站点配置"
        description="正在读取站点基础信息、监听器、证书和最近 24 小时访问统计。"
        action={
          <Loader2 className="size-5 animate-spin text-muted-foreground" />
        }
      />
    )
  }

  if (!site) {
    return (
      <EmptyState
        title="站点不存在"
        description="该站点可能已被删除，或当前账户没有访问权限。"
        action={
          <Button asChild>
            <Link href="/sites/">返回应用列表</Link>
          </Button>
        }
      />
    )
  }

  const tabs: { key: TabKey; label: string }[] = [
    { key: "basic", label: "基本配置" },
    { key: "listeners", label: "监听管理" },
    { key: "upstream", label: "上游管理" },
    { key: "advanced", label: "高级配置" },
    { key: "inventory", label: "应用路由" },
    { key: "observability", label: "站点观测" },
    { key: "error-pages", label: "错误页面" },
  ]

  const appRuleTotalPages = Math.max(
    1,
    Math.ceil(appRuleTotal / APP_ROUTE_RULE_PAGE_SIZE)
  )
  const recTotalPages = Math.max(1, Math.ceil(recTotal / recPageSize))
  const deleteAppRule = appRules.find((item) => item.id === deleteAppRuleId)
  const runtimeStatus =
    siteStatus?.status || (site.enabled ? "running" : "stopped")
  const isRunning = runtimeStatus === "running"

  const quickLinks = [
    {
      label: "CC 防护",
      desc: "管理 CC 防护规则与等待室",
      icon: Zap,
      href: "/cc-protection/",
      tone: "warning",
    },
    {
      label: "Bot 防护",
      desc: "调整 Bot 阈值与评分策略",
      icon: Bot,
      href: "/bot-protection/",
      tone: "primary",
    },
    {
      label: "攻击防护",
      desc: "配置 OWASP 与限流策略",
      icon: ShieldAlert,
      href: "/protection/",
      tone: "danger",
    },
    {
      label: "安全策略",
      desc: "验证码、5秒盾与防重放",
      icon: ShieldCheck,
      href: "/security/",
      tone: "muted",
    },
    {
      label: "请求日志",
      desc: "按首个 Host 检索请求明细",
      icon: FileText,
      href: `/access-logs/?host=${encodeURIComponent(site.host.split(",")[0]?.trim() || site.host)}`,
      tone: "primary",
    },
    {
      label: "拦截日志",
      desc: "按首个 Host 查看拦截事件",
      icon: ShieldAlert,
      href: `/security-events/?host=${encodeURIComponent(site.host.split(",")[0]?.trim() || site.host)}`,
      tone: "danger",
    },
  ]

  return (
    <div className="flex flex-col gap-6">
      <Button
        asChild
        variant="ghost"
        className="w-fit rounded-md text-muted-foreground"
      >
        <Link href="/sites/">
          <ArrowLeft data-icon="inline-start" />
          返回应用列表
        </Link>
      </Button>

      <PageIntro
        eyebrow="Site Detail"
        title={
          site.host
            ?.split(",")
            .map((h) => h.trim())
            .join(", ") || "未命名站点"
        }
        description={`${siteEntrySummary} · 创建于 ${formatDate(site.created_at)}`}
        actions={
          <>
            <span
              className={cn(
                "inline-flex h-8 items-center rounded-lg border px-2.5 text-xs font-medium",
                isRunning
                  ? "border-primary/25 bg-primary/10 text-primary"
                  : "border-border bg-muted/45 text-muted-foreground"
              )}
            >
              {isRunning ? "运行中" : "已停止"}
            </span>
            <Button
              variant="outline"
              className="rounded-md"
              onClick={handleToggle}
            >
              {site.enabled ? "停用站点" : "启用站点"}
            </Button>
            <Button variant="outline" className="rounded-md" onClick={load}>
              刷新
            </Button>
          </>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回站点详情操作响应体；请核对 item 或 error 字段。
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

      {siteOperationDetails ? (
        <Alert className="gap-3">
          <ShieldCheck />
          <AlertTitle>最近站点配置操作响应</AlertTitle>
          <AlertDescription>
            后端已返回站点配置操作响应体；请核对 operation、site_id、tab
            或 response 字段。
          </AlertDescription>
          <CopyableBlock
            label="站点配置操作响应体"
            value={JSON.stringify(siteOperationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {appRouteOperationDetails ? (
        <Alert className="gap-3">
          <Route />
          <AlertTitle>最近应用路由操作响应</AlertTitle>
          <AlertDescription>
            后端已返回应用路由操作响应体；请核对 operation、payload、rule_id、filename
            或 response 字段。
          </AlertDescription>
          <CopyableBlock
            label="应用路由操作响应体"
            value={JSON.stringify(appRouteOperationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard label="24h 请求" value={accessStats?.requests ?? 0} />
        <MetricCard
          label="24h 拦截"
          value={accessStats?.intercepts ?? 0}
          tone="rose"
        />
        <MetricCard
          label="24h 观察"
          value={accessStats?.observes ?? 0}
          tone="amber"
        />
      </div>

      {/* Quick Entry Cards */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {quickLinks.map((q) => (
          <Link
            key={q.label}
            href={q.href}
            className="group console-panel flex min-w-0 items-start gap-3 p-4 text-left transition-all hover:border-primary/30 hover:shadow-md"
          >
            <div
              className={cn(
                "flex size-10 shrink-0 items-center justify-center rounded-lg",
                getQuickLinkToneClass(q.tone)
              )}
            >
              <q.icon />
            </div>
            <div className="min-w-0">
              <h3 className="truncate text-sm font-semibold group-hover:text-primary">
                {q.label}
              </h3>
              <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">
                {q.desc}
              </p>
            </div>
          </Link>
        ))}
      </div>

      <Tabs
        value={tab}
        onValueChange={(value) => setTab(value as TabKey)}
        className="rounded-lg border bg-card shadow-sm"
      >
        <div className="overflow-x-auto overscroll-x-contain p-1">
          <TabsList variant="line" className="min-w-max bg-transparent">
            {tabs.map((t) => (
              <TabsTrigger key={t.key} value={t.key} className="px-5 py-2">
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <Separator />

        <div className="p-6">
          {tab === "basic" && (
            <div className="flex flex-col gap-5">
              {hasManagedListeners && (
                <Alert>
                  <AlertTitle>当前站点使用显式监听器</AlertTitle>
                  <AlertDescription>
                    运行时入口以“监听管理”中的监听地址、协议和证书为准；本页的
                    TLS 版本、ALPN 和密码套件仍会作为这些监听器的站点级 TLS
                    参数保存。
                  </AlertDescription>
                </Alert>
              )}
              <div className="grid gap-5 md:grid-cols-2">
                <FieldGroup label="域名 / Host" className="md:col-span-2">
                  <MultiHostInput hosts={hosts} onChange={setHosts} />
                </FieldGroup>
                <FieldGroup label="监听地址">
                  <Input
                    value={bind}
                    onChange={(e) => setBind(e.target.value)}
                    placeholder=":80"
                    className="rounded-md"
                    disabled={hasManagedListeners}
                  />
                </FieldGroup>
                <FieldGroup label="网络协议">
                  <Select
                    value={network}
                    onValueChange={(value) => setNetwork(value)}
                    disabled={hasManagedListeners}
                  >
                    <SelectTrigger className="rounded-md">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="tcp">TCP</SelectItem>
                        <SelectItem value="udp">UDP</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </FieldGroup>
                <FieldGroup label="接入协议">
                  <ToggleGroup
                    type="single"
                    value={tlsEnabled ? "https" : "http"}
                    onValueChange={(value) => {
                      if (value === "http") {
                        setTlsEnabled(false)
                        setCertId(null)
                        setBind(":80")
                      }
                      if (value === "https") {
                        setTlsEnabled(true)
                        setBind(":443")
                      }
                    }}
                    variant="outline"
                    spacing={0}
                    className="w-full"
                    disabled={hasManagedListeners}
                  >
                    <ToggleGroupItem value="http" className="flex-1">
                      HTTP
                    </ToggleGroupItem>
                    <ToggleGroupItem value="https" className="flex-1">
                      HTTPS
                    </ToggleGroupItem>
                  </ToggleGroup>
                </FieldGroup>
                {tlsEnabled && (
                  <FieldGroup label="TLS 证书">
                    <Select
                      value={certId ? String(certId) : "none"}
                      onValueChange={(value) =>
                        setCertId(value === "none" ? null : Number(value))
                      }
                      disabled={hasManagedListeners}
                    >
                      <SelectTrigger className="rounded-md">
                        <SelectValue
                          placeholder={
                            certificates.length
                              ? "选择证书"
                              : "当前没有可用证书"
                          }
                        />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="none">不绑定证书</SelectItem>
                          {certId &&
                            !certificates.some(
                              (cert) => cert.id === certId
                            ) && (
                              <SelectItem value={String(certId)}>
                                已失效证书 #{certId}
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
                  </FieldGroup>
                )}
                {showTLSSettings && (
                  <>
                    <FieldGroup label="最低 TLS 版本">
                      <Select
                        value={minTlsVersion}
                        onValueChange={setMinTlsVersion}
                      >
                        <SelectTrigger className="rounded-md">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="TLS10">
                              TLS 1.0（不推荐）
                            </SelectItem>
                            <SelectItem value="TLS11">
                              TLS 1.1（不推荐）
                            </SelectItem>
                            <SelectItem value="TLS12">
                              TLS 1.2（推荐）
                            </SelectItem>
                            <SelectItem value="TLS13">TLS 1.3</SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </FieldGroup>
                    <FieldGroup label="最高 TLS 版本">
                      <Select
                        value={maxTlsVersion}
                        onValueChange={setMaxTlsVersion}
                      >
                        <SelectTrigger className="rounded-md">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="TLS10">TLS 1.0</SelectItem>
                            <SelectItem value="TLS11">TLS 1.1</SelectItem>
                            <SelectItem value="TLS12">TLS 1.2</SelectItem>
                            <SelectItem value="TLS13">
                              TLS 1.3（推荐）
                            </SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </FieldGroup>
                    <FieldGroup label="ALPN 协议（逗号分隔）">
                      <Input
                        value={alpn}
                        onChange={(e) => setAlpn(e.target.value)}
                        placeholder="h2,http/1.1"
                        className="rounded-md font-mono"
                      />
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        常用值：h2（HTTP/2）、http/1.1（HTTP/1.1）、h3（HTTP/3）
                      </p>
                    </FieldGroup>
                    <div className="md:col-span-2">
                      <FieldGroup label="密码套件（逗号分隔，留空使用默认）">
                        <Input
                          value={cipherSuites}
                          onChange={(e) => setCipherSuites(e.target.value)}
                          placeholder="TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,..."
                          className="rounded-md font-mono text-xs"
                        />
                        <p className="mt-1 text-[11px] text-muted-foreground">
                          TLS 1.3 的密码套件由 Go 自动管理，此处主要影响 TLS 1.2
                          及以下版本。留空使用安全默认值。
                        </p>
                      </FieldGroup>
                    </div>
                  </>
                )}
                <FieldGroup label="客户端 IP 解析">
                  <Select value={xffMode} onValueChange={setXFFMode}>
                    <SelectTrigger className="rounded-md">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="strip_all_and_set_remote">
                          忽略 X-Forwarded-For，使用直连 IP
                        </SelectItem>
                        <SelectItem value="trust_outer_waf_cidr_then_take_leftmost">
                          信任外层 WAF CIDR 后取最左 IP
                        </SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </FieldGroup>
                <FieldGroup label="可信代理 CIDR">
                  <Input
                    value={trustedCIDR}
                    onChange={(e) => setTrustedCIDR(e.target.value)}
                    placeholder="10.0.0.0/8, 192.168.0.0/16"
                    className="rounded-md font-mono"
                  />
                </FieldGroup>
                <Field
                  orientation="horizontal"
                  className="rounded-md border bg-muted/35 px-4 py-3 md:col-span-2"
                >
                  <FieldContent>
                    <FieldLabel htmlFor={preserveOriginalHostId}>
                      保留原始 Host
                    </FieldLabel>
                    <FieldDescription>
                      转发到上游时使用客户端请求 Host，并写入 X-Forwarded-Host。
                    </FieldDescription>
                  </FieldContent>
                  <Switch
                    id={preserveOriginalHostId}
                    checked={preserveOriginalHost}
                    onCheckedChange={setPreserveOriginalHost}
                    aria-label="保留原始 Host"
                  />
                </Field>
              </div>
            </div>
          )}

          {tab === "listeners" && (
            <SiteListenersPanel siteId={site.id} onChanged={load} />
          )}

          {tab === "upstream" && (
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold">上游地址列表</h3>
                  <p className="text-xs text-muted-foreground">
                    请求将被转发到以下上游服务器
                  </p>
                </div>
                <div className="flex flex-wrap items-center justify-end gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="rounded-md"
                    disabled={upstreamStatusLoading}
                    onClick={() => void refreshUpstreamStatus()}
                  >
                    {upstreamStatusLoading ? (
                      <Loader2
                        data-icon="inline-start"
                        className="animate-spin"
                      />
                    ) : (
                      <Route data-icon="inline-start" />
                    )}
                    刷新健康
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="rounded-md"
                    onClick={() =>
                      setUpstreams([...upstreams, "http://127.0.0.1:8080"])
                    }
                  >
                    <Plus data-icon="inline-start" />
                    添加上游
                  </Button>
                </div>
              </div>
              <Alert>
                <AlertTitle>轮询与重试</AlertTitle>
                <AlertDescription>
                  多上游按轮询转发；安全请求在连接失败时会尝试下一个
                  upstream，避免重复提交非幂等请求。
                </AlertDescription>
              </Alert>
              <div className="grid gap-4 rounded-md border bg-muted/35 p-4 md:grid-cols-2">
                <Field
                  orientation="horizontal"
                  className="rounded-md border bg-card px-4 py-3"
                >
                  <FieldContent>
                    <FieldLabel htmlFor={upstreamTLSSkipVerifyId}>
                      跳过上游 TLS 校验
                    </FieldLabel>
                    <FieldDescription>
                      仅用于自签名或测试上游。
                    </FieldDescription>
                  </FieldContent>
                  <Switch
                    id={upstreamTLSSkipVerifyId}
                    checked={upstreamTLSSkipVerify}
                    onCheckedChange={setUpstreamTLSSkipVerify}
                    aria-label="跳过上游 TLS 校验"
                  />
                </Field>
                <FieldGroup label="上游 TLS Server Name">
                  <Input
                    value={upstreamTLSServerName}
                    onChange={(e) => setUpstreamTLSServerName(e.target.value)}
                    placeholder="origin.example.com"
                    className="rounded-md font-mono"
                  />
                </FieldGroup>
              </div>
              <div className="flex flex-col gap-3">
                {upstreams.length === 0 ? (
                  <div className="rounded-md border border-dashed bg-muted/35 px-4 py-8 text-center text-sm text-muted-foreground">
                    暂无上游地址，请点击上方按钮添加
                  </div>
                ) : (
                  upstreams.map((u, i) => {
                    const status = upstreamStatuses.find(
                      (item) => item.url === u.trim()
                    )

                    return (
                      <div
                        key={i}
                        className="flex flex-col gap-2 rounded-md border bg-muted/35 p-2"
                      >
                        <div className="flex items-center gap-2">
                          <Input
                            value={u}
                            onChange={(e) => {
                              const next = [...upstreams]
                              next[i] = e.target.value
                              setUpstreams(next)
                            }}
                            placeholder="http://127.0.0.1:8080"
                            className="border-0 bg-transparent font-mono text-sm shadow-none focus-visible:ring-0"
                          />
                          {upstreams.length > 1 && (
                            <Button
                              variant="destructive"
                              size="icon"
                              className="shrink-0 rounded-md"
                              aria-label="删除上游地址"
                              onClick={() =>
                                setUpstreams(
                                  upstreams.filter((_, idx) => idx !== i)
                                )
                              }
                            >
                              <Trash2 data-icon="inline-start" />
                            </Button>
                          )}
                        </div>
                        <div className="flex flex-wrap items-center gap-2 px-2 pb-1 text-[11px] text-muted-foreground">
                          {status ? (
                            <>
                              <Badge
                                variant={
                                  status.healthy ? "secondary" : "destructive"
                                }
                                className="rounded-md"
                              >
                                {status.healthy ? "健康" : "异常"}
                              </Badge>
                              <span>失败 {status.fail_count} 次</span>
                              <span className="text-muted-foreground/45">
                                ·
                              </span>
                              <span>
                                {status.checked_at
                                  ? formatDate(status.checked_at)
                                  : "未检查"}
                              </span>
                            </>
                          ) : (
                            <Badge variant="outline" className="rounded-md">
                              未检查
                            </Badge>
                          )}
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          )}

          {tab === "advanced" && (
            <div className="flex flex-col gap-6">
              {/* Per-site Protection Configuration */}
              <div className="rounded-md border p-5">
                <h3 className="mb-1 text-sm font-semibold">站点防护配置</h3>
                <p className="mb-3 text-xs text-muted-foreground">
                  为本站点单独配置防护策略，或跟随全局配置。规则级 action
                  优先级更高。
                </p>
                <Alert className="mb-5">
                  <AlertDescription>
                    只有 OWASP、CVE、频率限制、Bot 使用“继承全局 / 覆盖启用 /
                    覆盖关闭”三态；缓存、防重放、维护模式是站点本地开关。
                  </AlertDescription>
                </Alert>

                <div className="flex flex-col gap-5">
                  {/* OWASP Section */}
                  <div className="rounded-md border bg-muted/35 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <ShieldAlert className="size-4 text-destructive" />
                      <span className="text-sm font-semibold">
                        攻击防护 (OWASP)
                      </span>
                    </div>
                    <InheritToggle
                      value={owaspEnabled}
                      onChange={(value) => {
                        setOwaspEnabled(value)
                        if (value === null) {
                          setOwaspSensitivity("")
                          setOwaspAction("")
                        } else {
                          setOwaspSensitivity(
                            owaspSensitivity || DEFAULT_SITE_OWASP_SENSITIVITY
                          )
                          setOwaspAction(
                            owaspAction || DEFAULT_SITE_OWASP_ACTION
                          )
                        }
                      }}
                    />
                    {owaspEnabled !== null && (
                      <div className="mt-4 flex flex-col gap-3">
                        <Field
                          orientation="horizontal"
                          className="rounded-md border bg-card px-4 py-3"
                        >
                          <FieldContent>
                            <FieldLabel htmlFor={owaspEnabledId}>
                              启用 OWASP 检测
                            </FieldLabel>
                            <FieldDescription>
                              关闭后将跳过 OWASP 攻击检测
                            </FieldDescription>
                          </FieldContent>
                          <Switch
                            id={owaspEnabledId}
                            checked={owaspEnabled === true}
                            onCheckedChange={(v) => setOwaspEnabled(v)}
                            aria-label="启用 OWASP 检测"
                          />
                        </Field>
                        <div className="grid gap-4 md:grid-cols-2">
                          <FieldGroup label="检测灵敏度">
                            <Select
                              value={owaspSensitivity || "mid"}
                              onValueChange={setOwaspSensitivity}
                            >
                              <SelectTrigger className="rounded-md bg-background">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {sensitivityLevels.map((item) => (
                                    <SelectItem
                                      key={item.value}
                                      value={item.value}
                                    >
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                          <FieldGroup label="命中动作">
                            <Select
                              value={owaspAction}
                              onValueChange={setOwaspAction}
                            >
                              <SelectTrigger className="rounded-md bg-background">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {nonRedirectWAFActionOptions.map((item) => (
                                    <SelectItem
                                      key={item.value}
                                      value={item.value}
                                    >
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* CVE Section */}
                  <div className="rounded-md border bg-muted/35 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <ShieldCheck className="size-4 text-primary" />
                      <span className="text-sm font-semibold">CVE 检测</span>
                    </div>
                    <InheritToggle
                      value={cveEnabled}
                      onChange={(value) => {
                        setCveEnabled(value)
                        setCveAction(
                          value === null ? "" : cveAction || DEFAULT_SITE_CVE_ACTION
                        )
                      }}
                    />
                    {cveEnabled !== null && (
                      <div className="mt-4 flex flex-col gap-3">
                        <Field
                          orientation="horizontal"
                          className="rounded-md border bg-card px-4 py-3"
                        >
                          <FieldContent>
                            <FieldLabel htmlFor={cveEnabledId}>
                              启用 CVE 检测
                            </FieldLabel>
                            <FieldDescription>
                              关闭后将跳过 CVE 漏洞检测
                            </FieldDescription>
                          </FieldContent>
                          <Switch
                            id={cveEnabledId}
                            checked={cveEnabled === true}
                            onCheckedChange={(v) => setCveEnabled(v)}
                            aria-label="启用 CVE 检测"
                          />
                        </Field>
                        <div className="max-w-sm">
                          <FieldGroup label="命中动作">
                            <Select
                              value={cveAction}
                              onValueChange={setCveAction}
                            >
                              <SelectTrigger className="rounded-md bg-background">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {nonRedirectWAFActionOptions.map((item) => (
                                    <SelectItem
                                      key={item.value}
                                      value={item.value}
                                    >
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Rate Limit Section */}
                  <div className="rounded-md border bg-muted/35 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <Zap className="size-4 text-primary" />
                      <span className="text-sm font-semibold">频率限制</span>
                    </div>
                    <InheritToggle
                      value={rateLimitEnabled}
                      onChange={(value) => {
                        setRateLimitEnabled(value)
                        if (value === null) {
                          setRateLimitWindow(0)
                          setRateLimitMax(0)
                          setRateLimitAction("")
                        } else {
                          setRateLimitWindow(
                            rateLimitWindow || DEFAULT_SITE_RATE_LIMIT_WINDOW
                          )
                          setRateLimitMax(
                            rateLimitMax || DEFAULT_SITE_RATE_LIMIT_MAX
                          )
                          setRateLimitAction(
                            rateLimitAction || DEFAULT_SITE_RATE_LIMIT_ACTION
                          )
                        }
                      }}
                    />
                    {rateLimitEnabled !== null && (
                      <div className="mt-4 flex flex-col gap-3">
                        <Field
                          orientation="horizontal"
                          className="rounded-md border bg-card px-4 py-3"
                        >
                          <FieldContent>
                            <FieldLabel htmlFor={rateLimitEnabledId}>
                              启用频率限制
                            </FieldLabel>
                            <FieldDescription>
                              关闭后将跳过请求频率限制检查
                            </FieldDescription>
                          </FieldContent>
                          <Switch
                            id={rateLimitEnabledId}
                            checked={rateLimitEnabled === true}
                            onCheckedChange={(v) => setRateLimitEnabled(v)}
                            aria-label="启用频率限制"
                          />
                        </Field>
                        <div className="grid gap-4 md:grid-cols-3">
                          <FieldGroup label="时间窗口（秒）">
                            <Input
                              type="number"
                              min={1}
                              value={rateLimitWindow}
                              onChange={(e) =>
                                setRateLimitWindow(Number(e.target.value))
                              }
                              className="rounded-md bg-background"
                              placeholder="60"
                            />
                          </FieldGroup>
                          <FieldGroup label="最大请求数">
                            <Input
                              type="number"
                              min={1}
                              value={rateLimitMax}
                              onChange={(e) =>
                                setRateLimitMax(Number(e.target.value))
                              }
                              className="rounded-md bg-background"
                              placeholder="100"
                            />
                          </FieldGroup>
                          <FieldGroup label="命中动作">
                            <Select
                              value={rateLimitAction}
                              onValueChange={setRateLimitAction}
                            >
                              <SelectTrigger className="rounded-md bg-background">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {nonRedirectWAFActionOptions.map((item) => (
                                    <SelectItem
                                      key={item.value}
                                      value={item.value}
                                    >
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Bot Protection Section */}
                  <div className="rounded-md border bg-muted/35 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <Bot className="size-4 text-primary" />
                      <span className="text-sm font-semibold">Bot 防护</span>
                    </div>
                    <Field
                      orientation="horizontal"
                      className="rounded-md border bg-card px-4 py-3"
                    >
                      <FieldContent>
                        <FieldLabel>启用 Bot 防护</FieldLabel>
                        <FieldDescription>
                          按站点覆盖 Bot 检测开关；继承时使用全局配置
                        </FieldDescription>
                      </FieldContent>
                      <InheritToggle
                        value={botProtectionEnabled}
                        onChange={(value) => {
                          setBotProtectionEnabled(value)
                          if (value === null) {
                            setBotProtectionLevel("")
                          } else if (!botProtectionLevel) {
                            setBotProtectionLevel(DEFAULT_SITE_BOT_LEVEL)
                          }
                        }}
                      />
                    </Field>
                    {botProtectionEnabled !== null && (
                      <div className="mt-3 max-w-sm">
                        <FieldGroup label="防护等级">
                          <Select
                            value={botProtectionLevel}
                            onValueChange={setBotProtectionLevel}
                          >
                            <SelectTrigger className="rounded-md bg-background">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                <SelectItem value="low">
                                  低 - 仅拦截高置信度 Bot
                                </SelectItem>
                                <SelectItem value="medium">
                                  中 - 均衡策略
                                </SelectItem>
                                <SelectItem value="high">
                                  高 - 严格检测
                                </SelectItem>
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                        </FieldGroup>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="rounded-md border p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold">资源缓存规则</h3>
                    <p className="text-xs text-muted-foreground">
                      仅缓存 GET 200、无 Set-Cookie、响应体非空的安全响应。
                    </p>
                  </div>
                  <Switch
                    checked={cacheEnabled}
                    onCheckedChange={setCacheEnabled}
                    aria-label="启用资源缓存规则"
                  />
                </div>
                {cacheEnabled && (
                  <div className="mt-4 flex flex-col gap-3">
                    <div className="max-w-xs">
                      <FieldGroup label="默认 TTL（秒）">
                        <Input
                          type="number"
                          min={0}
                          value={cacheDefaultTTL}
                          onChange={(e) =>
                            setCacheDefaultTTL(Number(e.target.value))
                          }
                          className="rounded-md"
                        />
                      </FieldGroup>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      后缀、前缀、精确、子串规则可用英文逗号写多个模式；后缀可直接写扩展名（如{" "}
                      <span className="font-mono">js,css,html</span>，会自动按{" "}
                      <span className="font-mono">.js</span> 匹配）。
                      「正则」类型<strong>不</strong>
                      按逗号拆分（逗号是正则语法的一部分）；匹配默认针对路径+原始查询串，需要时用「忽略查询串」。
                      可选「忽略查询串」「忽略大小写」控制匹配与缓存键。
                    </p>
                    {cacheRules.some(
                      (r) =>
                        r.type === "prefix" &&
                        r.value.trim().startsWith(".") &&
                        r.value.trim().length > 0
                    ) && (
                      <Alert>
                        <AlertDescription>
                          提示：以「.」开头的是<strong>扩展名</strong>
                          ，应选「后缀」才能匹配如{" "}
                          <code className="rounded bg-muted px-1 font-mono">
                            /app/main.js
                          </code>
                          ；「前缀」表示路径从首字符起匹配（例如{" "}
                          <code className="rounded bg-muted px-1 font-mono">
                            /_next/static
                          </code>
                          ）。
                        </AlertDescription>
                      </Alert>
                    )}
                    {cacheRules.map((rule, idx) => (
                      <div
                        key={idx}
                        className="flex flex-col gap-2 rounded-md border bg-muted/35 p-3"
                      >
                        <div className="grid gap-2 md:grid-cols-[140px_1fr_120px_40px]">
                          <Select
                            value={rule.type}
                            onValueChange={(v) =>
                              setCacheRules(
                                cacheRules.map((item, i) =>
                                  i === idx ? { ...item, type: v } : item
                                )
                              )
                            }
                          >
                            <SelectTrigger className="rounded-md bg-background">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                <SelectItem value="suffix">后缀</SelectItem>
                                <SelectItem value="prefix">前缀</SelectItem>
                                <SelectItem value="exact">精确</SelectItem>
                                <SelectItem value="contains">子串</SelectItem>
                                <SelectItem value="regex">正则</SelectItem>
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                          <Input
                            value={rule.value}
                            onChange={(e) =>
                              setCacheRules(
                                cacheRules.map((item, i) =>
                                  i === idx
                                    ? { ...item, value: e.target.value }
                                    : item
                                )
                              )
                            }
                            placeholder={
                              rule.type === "suffix"
                                ? "js,css,html 或 .mjs,__PAGE__.txt"
                                : rule.type === "prefix"
                                  ? "/static 或 /a,/b"
                                  : rule.type === "exact"
                                    ? "/path 或 /a,/b"
                                    : rule.type === "contains"
                                      ? "/_next/static 或 v=hash"
                                      : String.raw`\.(js|css)$`
                            }
                            className="rounded-md bg-background font-mono text-xs"
                          />
                          <Input
                            type="number"
                            min={1}
                            value={rule.ttl}
                            onChange={(e) =>
                              setCacheRules(
                                cacheRules.map((item, i) =>
                                  i === idx
                                    ? { ...item, ttl: Number(e.target.value) }
                                    : item
                                )
                              )
                            }
                            className="rounded-md bg-background"
                          />
                          <Button
                            variant="destructive"
                            size="icon"
                            aria-label="删除缓存规则"
                            onClick={() =>
                              setCacheRules(
                                cacheRules.filter((_, i) => i !== idx)
                              )
                            }
                          >
                            <Trash2 data-icon="inline-start" />
                          </Button>
                        </div>
                        <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs text-muted-foreground md:pl-1">
                          <Field
                            orientation="horizontal"
                            className="w-auto items-center gap-2"
                          >
                            <Checkbox
                              id={`cache-rule-ignore-query-${idx}`}
                              checked={rule.ignore_query}
                              onCheckedChange={(checked) =>
                                setCacheRules(
                                  cacheRules.map((item, i) =>
                                    i === idx
                                      ? {
                                          ...item,
                                          ignore_query: checked === true,
                                        }
                                      : item
                                  )
                                )
                              }
                            />
                            <FieldLabel
                              htmlFor={`cache-rule-ignore-query-${idx}`}
                              className="cursor-pointer text-xs font-normal text-muted-foreground"
                            >
                              忽略查询串（匹配与缓存键不含 ? 后参数）
                            </FieldLabel>
                          </Field>
                          <Field
                            orientation="horizontal"
                            className="w-auto items-center gap-2"
                          >
                            <Checkbox
                              id={`cache-rule-case-insensitive-${idx}`}
                              checked={rule.case_insensitive}
                              onCheckedChange={(checked) =>
                                setCacheRules(
                                  cacheRules.map((item, i) =>
                                    i === idx
                                      ? {
                                          ...item,
                                          case_insensitive: checked === true,
                                        }
                                      : item
                                  )
                                )
                              }
                            />
                            <FieldLabel
                              htmlFor={`cache-rule-case-insensitive-${idx}`}
                              className="cursor-pointer text-xs font-normal text-muted-foreground"
                            >
                              忽略大小写（路径与缓存键路径用小写）
                            </FieldLabel>
                          </Field>
                        </div>
                      </div>
                    ))}
                    <Button
                      variant="outline"
                      size="sm"
                      className="rounded-md"
                      onClick={() =>
                        setCacheRules([
                          ...cacheRules,
                          {
                            type: "suffix",
                            value: "js,css",
                            ttl: 3600,
                            case_insensitive: false,
                            ignore_query: false,
                          },
                        ])
                      }
                    >
                      添加缓存规则
                    </Button>
                  </div>
                )}
              </div>

              {/* Maintenance */}
              <div className="rounded-md border p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold">维护模式</h3>
                    <p className="text-xs text-muted-foreground">
                      开启后将返回维护页面，所有流量不转发
                    </p>
                  </div>
                  <Switch
                    checked={maintenanceEnabled}
                    onCheckedChange={setMaintenanceEnabled}
                    aria-label="启用维护模式"
                  />
                </div>
                {maintenanceEnabled && (
                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <FieldGroup label="维护状态码">
                      <Input
                        type="number"
                        value={maintenanceStatus}
                        onChange={(e) =>
                          setMaintenanceStatus(Number(e.target.value))
                        }
                        className="rounded-md"
                      />
                    </FieldGroup>
                    <FieldGroup label="维护页面 HTML">
                      <Textarea
                        value={maintenanceHtml}
                        onChange={(e) => setMaintenanceHtml(e.target.value)}
                        rows={3}
                        placeholder="<h1>维护中</h1>"
                        className="rounded-md"
                      />
                    </FieldGroup>
                  </div>
                )}
              </div>

              {/* Block settings */}
              <div className="rounded-md border p-5">
                <h3 className="text-sm font-semibold">自定义拦截页面</h3>
                <p className="mb-4 text-xs text-muted-foreground">
                  当请求被 WAF 拦截时展示的页面内容
                </p>
                <div className="grid gap-4 md:grid-cols-2">
                  <FieldGroup label="拦截状态码">
                    <Input
                      type="number"
                      value={blockStatus}
                      onChange={(e) => setBlockStatus(Number(e.target.value))}
                      className="rounded-md"
                    />
                  </FieldGroup>
                  <FieldGroup label="拦截页面 HTML">
                    <Textarea
                      value={blockHtml}
                      onChange={(e) => setBlockHtml(e.target.value)}
                      rows={3}
                      placeholder="<h1>Access Denied</h1>"
                      className="rounded-md"
                    />
                  </FieldGroup>
                </div>
              </div>

              {/* Max body */}
              <div className="rounded-md border p-5">
                <h3 className="text-sm font-semibold">请求体限制</h3>
                <p className="mb-4 text-xs text-muted-foreground">
                  限制最大请求体大小（字节），0 表示不限制
                </p>
                <div className="max-w-xs">
                  <Input
                    type="number"
                    value={maxBodyBytes}
                    onChange={(e) => setMaxBodyBytes(Number(e.target.value))}
                    className="rounded-md"
                    placeholder="0"
                  />
                </div>
              </div>

              {/* Anti replay */}
              <div className="rounded-md border p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold">防重放保护</h3>
                    <p className="text-xs text-muted-foreground">
                      基于 Nonce 校验拦截重复提交请求
                    </p>
                  </div>
                  <Switch
                    checked={antiReplayEnabled}
                    onCheckedChange={setAntiReplayEnabled}
                    aria-label="启用防重放保护"
                  />
                </div>
                {antiReplayEnabled && (
                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <FieldGroup label="Nonce TTL（秒）">
                      <Input
                        type="number"
                        min={10}
                        max={86400}
                        value={antiReplayTTL}
                        onChange={(e) =>
                          setAntiReplayTTL(Number(e.target.value))
                        }
                        className="rounded-md"
                      />
                    </FieldGroup>
                    <FieldGroup label="命中动作">
                      <Select
                        value={antiReplayAction}
                        onValueChange={setAntiReplayAction}
                      >
                        <SelectTrigger className="rounded-md">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {antiReplayWAFActionOptions.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </FieldGroup>
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === "inventory" && (
            <div className="flex flex-col gap-8">
              <Alert>
                <AlertDescription className="text-xs leading-5">
                  <strong className="font-medium text-foreground">
                    说明：
                  </strong>
                  匹配规则在「保存」后立即写入数据库并触发快照重载；命中规则后，数据面会将资源摘要写入下方列表。下方“已记录资源”是按应用路由规则聚合的资源摘要，不是完整访问日志；完整请求请到访问日志按
                  Host、路径或 Request ID 检索。Header 类目标为「请求
                  Header（单项）」时须填写 Header 名称。
                </AlertDescription>
              </Alert>

              <div className="rounded-md border p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Route className="text-muted-foreground" />
                    <h3 className="text-sm font-semibold">匹配规则</h3>
                    {invLoading && (
                      <Loader2 className="animate-spin text-muted-foreground" />
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="rounded-md"
                      onClick={() => void refreshInventory()}
                    >
                      刷新
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="rounded-md"
                      disabled={exportingAppRules || appRuleTotal === 0}
                      onClick={() => void handleExportAppRules()}
                    >
                      {exportingAppRules ? (
                        <Loader2
                          data-icon="inline-start"
                          className="animate-spin"
                        />
                      ) : (
                        <Download data-icon="inline-start" />
                      )}
                      {exportingAppRules ? "导出中..." : "导出全部 JSON"}
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      className="rounded-md"
                      onClick={() => void handleAddAppRule()}
                    >
                      <Plus data-icon="inline-start" />
                      添加规则
                    </Button>
                  </div>
                </div>

                {appRuleTotal === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    暂无规则，点击「添加规则」创建一条默认规则后再按需修改。
                  </p>
                ) : (
                  <div className="flex flex-col gap-4">
                    {appRules.map((rule) => {
                      const rid = rule.id ?? 0
                      const showHeaderKey =
                        (rule.target || "") === "request_header"
                      return (
                        <div
                          key={rid || rule.name}
                          className="flex flex-col gap-3 rounded-md border bg-muted/35 p-4"
                        >
                          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                            <FieldGroup label="名称">
                              <Input
                                value={rule.name ?? ""}
                                onChange={(e) =>
                                  patchAppRule(rid, { name: e.target.value })
                                }
                                className="rounded-md bg-background"
                              />
                            </FieldGroup>
                            <FieldGroup label="优先级（越大越先）">
                              <Input
                                type="number"
                                value={rule.priority ?? 0}
                                onChange={(e) =>
                                  patchAppRule(rid, {
                                    priority: Number(e.target.value),
                                  })
                                }
                                className="rounded-md bg-background"
                              />
                            </FieldGroup>
                            <FieldGroup label="启用">
                              <div className="flex h-9 items-center">
                                <Switch
                                  checked={isAppRouteRuleEnabled(rule)}
                                  onCheckedChange={(v) =>
                                    patchAppRule(rid, { enabled: v })
                                  }
                                  aria-label="启用应用路由规则"
                                />
                              </div>
                            </FieldGroup>
                            <div className="flex items-end justify-end gap-2">
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                className="rounded-md"
                                disabled={!rid}
                                onClick={() =>
                                  void handleSaveAppRule({ ...rule, id: rid })
                                }
                              >
                                保存
                              </Button>
                              <Button
                                type="button"
                                size="sm"
                                variant="destructive"
                                className="rounded-md"
                                disabled={!rid}
                                aria-label="删除应用路由规则"
                                onClick={() => setDeleteAppRuleId(rid)}
                              >
                                <Trash2 data-icon="inline-start" />
                              </Button>
                            </div>
                          </div>
                          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                            <FieldGroup label="匹配目标">
                              <Select
                                value={rule.target || "request_method"}
                                onValueChange={(v) =>
                                  patchAppRule(rid, { target: v })
                                }
                              >
                                <SelectTrigger className="rounded-md bg-background">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectGroup>
                                    {APP_ROUTE_TARGETS.map((t) => (
                                      <SelectItem key={t.value} value={t.value}>
                                        {t.label}
                                      </SelectItem>
                                    ))}
                                  </SelectGroup>
                                </SelectContent>
                              </Select>
                            </FieldGroup>
                            <FieldGroup label="匹配方式">
                              <Select
                                value={rule.op || "eq"}
                                onValueChange={(v) =>
                                  patchAppRule(rid, { op: v })
                                }
                              >
                                <SelectTrigger className="rounded-md bg-background">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectGroup>
                                    {APP_ROUTE_OPS.map((o) => (
                                      <SelectItem key={o.value} value={o.value}>
                                        {o.label}
                                      </SelectItem>
                                    ))}
                                  </SelectGroup>
                                </SelectContent>
                              </Select>
                            </FieldGroup>
                            <FieldGroup label="匹配值 / 模式">
                              <Input
                                value={rule.pattern ?? ""}
                                onChange={(e) =>
                                  patchAppRule(rid, { pattern: e.target.value })
                                }
                                className="rounded-md bg-background font-mono text-xs"
                                placeholder="如 GET 或正则"
                              />
                            </FieldGroup>
                          </div>
                          {showHeaderKey && (
                            <FieldGroup label="Header 名称（仅 request_header）">
                              <Input
                                value={rule.header_key ?? ""}
                                onChange={(e) =>
                                  patchAppRule(rid, {
                                    header_key: e.target.value,
                                  })
                                }
                                className="max-w-md rounded-md bg-background font-mono text-xs"
                                placeholder="User-Agent"
                              />
                            </FieldGroup>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
                {appRuleTotal > APP_ROUTE_RULE_PAGE_SIZE ? (
                  <div className="mt-4 flex flex-col gap-2 text-xs text-muted-foreground">
                    <span>
                      共 {appRuleTotal} 条 · 第 {appRulePage} /{" "}
                      {appRuleTotalPages} 页
                    </span>
                    <Pagination
                      page={appRulePage}
                      totalPages={appRuleTotalPages}
                      total={appRuleTotal}
                      pageSize={APP_ROUTE_RULE_PAGE_SIZE}
                      onPageChange={setAppRulePage}
                    />
                  </div>
                ) : null}
              </div>

              <div className="rounded-md border p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold">已记录资源摘要</h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      当前站点内由应用路由规则命中的聚合记录，不等同于完整访问日志。
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="rounded-md"
                      onClick={() => void refreshInventory()}
                    >
                      刷新列表
                    </Button>
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      className="rounded-md"
                      onClick={() => setClearRecordedOpen(true)}
                    >
                      清空当前站点记录
                    </Button>
                  </div>
                </div>
                <div className="rounded-md border">
                  <Table className="min-w-[960px] text-xs">
                    <TableHeader className="bg-muted/35 text-muted-foreground">
                      <TableRow>
                        <TableHead className="px-2 py-2">方法</TableHead>
                        <TableHead className="px-2 py-2">Host</TableHead>
                        <TableHead className="px-2 py-2">路径</TableHead>
                        <TableHead className="px-2 py-2">状态</TableHead>
                        <TableHead className="px-2 py-2">类型</TableHead>
                        <TableHead className="px-2 py-2">客户端</TableHead>
                        <TableHead className="px-2 py-2">
                          历史命中规则 ID
                        </TableHead>
                        <TableHead className="px-2 py-2">命中</TableHead>
                        <TableHead className="px-2 py-2">首次</TableHead>
                        <TableHead className="px-2 py-2">最近</TableHead>
                        <TableHead className="px-2 py-2 text-right">
                          操作
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {recItems.length === 0 ? (
                        <TableRow>
                          <TableCell
                            colSpan={11}
                            className="px-3 py-8 text-center text-muted-foreground"
                          >
                            暂无记录；配置规则并产生匹配流量后将在此聚合展示。
                          </TableCell>
                        </TableRow>
                      ) : (
                        recItems.map((row) => {
                          const displayPath = redactSensitiveText(row.path)

                          return (
                            <TableRow key={row.id}>
                              <TableCell className="px-2 py-2 font-mono">
                                <Badge
                                  variant="secondary"
                                  className="font-mono"
                                >
                                  {row.method}
                                </Badge>
                              </TableCell>
                              <TableCell
                                className="max-w-[140px] truncate px-2 py-2 font-mono"
                                title={row.host}
                              >
                                {row.host}
                              </TableCell>
                              <TableCell
                                className="max-w-[220px] truncate px-2 py-2 font-mono"
                                title={displayPath}
                              >
                                {displayPath}
                              </TableCell>
                              <TableCell className="px-2 py-2">
                                <Badge variant="outline" className="font-mono">
                                  {row.status_code}
                                </Badge>
                              </TableCell>
                              <TableCell
                                className="max-w-[160px] truncate px-2 py-2"
                                title={row.content_type || ""}
                              >
                                {row.content_type || "—"}
                              </TableCell>
                              <TableCell
                                className="max-w-[120px] truncate px-2 py-2 font-mono"
                                title={row.client_ip || ""}
                              >
                                {row.client_ip || "—"}
                              </TableCell>
                              <TableCell
                                className="max-w-[100px] truncate px-2 py-2 font-mono"
                                title={row.matched_rule_ids || ""}
                              >
                                {row.matched_rule_ids ||
                                  (row.primary_rule_id != null
                                    ? String(row.primary_rule_id)
                                    : "—")}
                              </TableCell>
                              <TableCell className="px-2 py-2 font-mono">
                                {row.hit_count}
                              </TableCell>
                              <TableCell className="px-2 py-2 whitespace-nowrap text-muted-foreground">
                                {formatDate(row.first_seen)}
                              </TableCell>
                              <TableCell className="px-2 py-2 whitespace-nowrap text-muted-foreground">
                                {formatDate(row.last_seen)}
                              </TableCell>
                              <TableCell className="px-2 py-2 text-right">
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  className="h-8 rounded-md"
                                  onClick={() => setRecordedDetail(row)}
                                >
                                  详情
                                </Button>
                              </TableCell>
                            </TableRow>
                          )
                        })
                      )}
                    </TableBody>
                  </Table>
                </div>
                <div className="mt-3 flex flex-col gap-2 text-xs text-muted-foreground">
                  <span>
                    共 {recTotal} 条 · 第 {recPage} / {recTotalPages} 页 · 规则
                    ID 为记录产生时的历史命中值
                  </span>
                  <Pagination
                    page={recPage}
                    totalPages={recTotalPages}
                    total={recTotal}
                    pageSize={recPageSize}
                    onPageChange={setRecPage}
                  />
                </div>
              </div>
            </div>
          )}

          {tab === "observability" && (
            <SiteObservabilityPanel
              key={site.id}
              siteId={site.id}
              siteHost={site.host}
              accessStats={accessStats}
            />
          )}

          {tab === "error-pages" && (
            <SiteErrorPagesPanel siteId={site.id} siteHost={site.host} />
          )}
        </div>

        {tab !== "inventory" &&
          tab !== "observability" &&
          tab !== "error-pages" && (
          <>
            <Separator />
            <div className="flex justify-end px-6 py-4">
            <Button
              onClick={handleSave}
              disabled={saving}
              className="rounded-md"
            >
              {saving ? (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              ) : (
                <Save data-icon="inline-start" />
              )}
              {saving ? "保存中..." : "保存配置"}
            </Button>
          </div>
          </>
        )}
      </Tabs>
      <AlertDialog
        open={deleteAppRuleId != null}
        onOpenChange={(open) => {
          if (!open && !deletingAppRule) setDeleteAppRuleId(null)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除应用路由规则</AlertDialogTitle>
            <AlertDialogDescription>
              确定删除应用路由规则「
              {deleteAppRule?.name || deleteAppRuleId || "-"}
              」？删除后本站点将停止按该规则记录资源。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletingAppRule}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deletingAppRule}
              onClick={(event) => {
                event.preventDefault()
                void handleDeleteAppRule()
              }}
            >
              {deletingAppRule ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog
        open={clearRecordedOpen}
        onOpenChange={(open) => {
          if (!open && !clearingRecorded) setClearRecordedOpen(false)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认清空当前站点记录</AlertDialogTitle>
            <AlertDialogDescription>
              确定清空站点「{site.host || site.id}
              」的已记录资源数据？此操作只影响当前站点的资源聚合记录，不会删除访问日志或规则，且不可恢复。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={clearingRecorded}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={clearingRecorded}
              onClick={(event) => {
                event.preventDefault()
                void handleClearRecorded()
              }}
            >
              {clearingRecorded ? "清空中..." : "清空"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <Dialog
        open={!!recordedDetail}
        onOpenChange={(open) => {
          if (!open) setRecordedDetail(null)
        }}
      >
        <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto rounded-lg">
          <DialogHeader>
            <DialogTitle>已记录资源详情</DialogTitle>
            <DialogDescription>
              查看当前聚合记录的基础信息、命中规则和已截断审计字段。
            </DialogDescription>
          </DialogHeader>
          {recordedDetail && (
            <div className="flex flex-col gap-4">
              <div className="grid gap-3 md:grid-cols-2">
                <DetailField label="方法" value={recordedDetail.method} mono />
                <DetailField
                  label="状态码"
                  value={recordedDetail.status_code}
                  mono
                />
                <DetailField
                  label="Host"
                  value={redactSensitiveText(recordedDetail.host)}
                  mono
                  copyText={redactSensitiveText(recordedDetail.host)}
                />
                <DetailField
                  label="路径"
                  value={redactSensitiveText(recordedDetail.path)}
                  mono
                  copyText={redactSensitiveText(recordedDetail.path)}
                />
                <DetailField
                  label="客户端 IP"
                  value={recordedDetail.client_ip || "-"}
                  mono
                />
                <DetailField
                  label="内容类型"
                  value={recordedDetail.content_type || "-"}
                />
                <DetailField
                  label="JA3"
                  value={recordedDetail.ja3_hash || "-"}
                  mono
                />
                <DetailField
                  label="命中次数"
                  value={recordedDetail.hit_count}
                  mono
                />
                <DetailField
                  label="首次出现"
                  value={formatDate(recordedDetail.first_seen)}
                />
                <DetailField
                  label="最近出现"
                  value={formatDate(recordedDetail.last_seen)}
                />
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <DetailField
                  label="主要规则 ID"
                  value={
                    recordedDetail.primary_rule_id != null
                      ? recordedDetail.primary_rule_id
                      : "-"
                  }
                  mono
                />
                <DetailField
                  label="历史命中规则 ID"
                  value={recordedDetail.matched_rule_ids || "-"}
                  mono
                  copyText={recordedDetail.matched_rule_ids || "-"}
                />
              </div>
              <Alert>
                <AlertTitle>相关日志</AlertTitle>
                <AlertDescription>
                  按当前记录的站点、客户端 IP、Host 和路径检索访问日志；按客户端
                  IP、Host 和路径检索安全事件。
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button asChild variant="outline" size="sm">
                      <Link href={recordedAccessLogHref(recordedDetail)}>
                        <ExternalLink data-icon="inline-start" />
                        访问日志
                      </Link>
                    </Button>
                    <Button asChild variant="outline" size="sm">
                      <Link href={recordedSecurityEventHref(recordedDetail)}>
                        <ExternalLink data-icon="inline-start" />
                        安全事件
                      </Link>
                    </Button>
                  </div>
                </AlertDescription>
              </Alert>
              <CopyableBlock
                label="User-Agent"
                value={recordedDetail.user_agent}
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="请求头 JSON"
                value={recordedDetail.request_headers_json}
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="响应头 JSON"
                value={recordedDetail.response_headers_json}
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="请求体摘要"
                value={recordedDetail.request_body_snippet}
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="响应体摘要"
                value={recordedDetail.response_body_snippet}
                redact
                defaultOpen={false}
              />
            </div>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setRecordedDetail(null)}
            >
              关闭
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function MetricCard({
  label,
  value,
  tone = "slate",
}: {
  label: string
  value: number
  tone?: "slate" | "rose" | "amber"
}) {
  const toneClass = {
    slate: "bg-muted text-muted-foreground",
    rose: "bg-destructive/10 text-destructive",
    amber: "bg-secondary text-secondary-foreground",
  }[tone]
  return (
    <div className="rounded-lg border bg-card p-4 shadow-sm">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div
        className={`mt-2 inline-flex rounded-md px-2 py-1 text-lg font-semibold ${toneClass}`}
      >
        {value.toLocaleString()}
      </div>
    </div>
  )
}

function FieldGroup({
  label,
  children,
  className,
}: {
  label: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <Field className={cn("gap-1.5", className)}>
      <FieldLabel>{label}</FieldLabel>
      {children}
    </Field>
  )
}

function getQuickLinkToneClass(tone: string) {
  const toneClass: Record<string, string> = {
    primary: "bg-primary/10 text-primary",
    danger: "bg-destructive/10 text-destructive",
    muted: "bg-muted text-muted-foreground",
    warning: "bg-secondary text-secondary-foreground",
  }

  return toneClass[tone] ?? toneClass.muted
}

function InheritToggle({
  value,
  onChange,
}: {
  value: boolean | null
  onChange: (value: boolean | null) => void
}) {
  const items: Array<{ value: "inherit" | "on" | "off"; label: string }> = [
    { value: "inherit", label: "继承全局" },
    { value: "on", label: "覆盖启用" },
    { value: "off", label: "覆盖关闭" },
  ]
  const current = value === null ? "inherit" : value ? "on" : "off"

  return (
    <ToggleGroup
      type="single"
      value={current}
      onValueChange={(nextValue) => {
        if (!nextValue) return
        onChange(
          nextValue === "inherit" ? null : nextValue === "on" ? true : false
        )
      }}
      variant="outline"
      size="sm"
      spacing={0}
    >
      {items.map((item) => (
        <ToggleGroupItem key={item.value} value={item.value}>
          {item.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  )
}
