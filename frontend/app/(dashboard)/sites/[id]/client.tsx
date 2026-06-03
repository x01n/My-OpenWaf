"use client"

import Link from "next/link"
import { useCallback, useEffect, useMemo, useState } from "react"
import { useParams, usePathname, useSearchParams } from "next/navigation"
import {
  ArrowLeft,
  Bot,
  FileText,
  Loader2,
  Plus,
  Route,
  Save,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Zap,
} from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
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
import { SiteListenersPanel } from "@/components/site-listeners-panel"
import {
  clearRecordedResources,
  createApplicationRouteRule,
  deleteApplicationRouteRule,
  getCertificates,
  getSite,
  getSiteAccessLogStats,
  listApplicationRouteRules,
  listRecordedResources,
  startSite,
  stopSite,
  updateApplicationRouteRule,
  updateSite,
  type ApplicationRouteRule,
  type Certificate,
  type RecordedResource,
  type Site,
  type SiteAccessLogStats,
} from "@/lib/api"
import { EmptyState, PageIntro } from "@/components/console-shell"
import { terminalWAFActionOptions } from "@/lib/console"
import {
  findInvalidSiteUpstream,
  parseSiteUpstreams,
  serializeSiteUpstreams,
} from "@/lib/site-upstreams"
import { MultiHostInput } from "@/components/multi-host-input"
import { formatDate } from "@/lib/utils"
import { toast } from "sonner"

const sensitivityLevels = [
  { value: "off", label: "禁用" },
  { value: "low", label: "低" },
  { value: "mid", label: "中" },
  { value: "high", label: "高" },
  { value: "very_high", label: "极高" },
  { value: "strict", label: "严格" },
]

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

function extractSiteId(candidate: string | undefined) {
  if (!candidate) return ""
  const last = candidate.split("/").filter(Boolean).at(-1) ?? ""
  return /^\d+$/.test(last) ? last : ""
}

type TabKey = "basic" | "listeners" | "upstream" | "advanced" | "inventory"

export default function SiteDetailClient() {
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
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [tab, setTab] = useState<TabKey>("basic")
  const [accessStats, setAccessStats] = useState<SiteAccessLogStats | null>(
    null
  )

  // Editable form state
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
  const [owaspAction, setOwaspAction] = useState("intercept")
  const [cveAction, setCveAction] = useState("intercept")
  const [rateLimitAction, setRateLimitAction] = useState("rate_limit")

  // Advanced
  const [blockHtml, setBlockHtml] = useState("")
  const [blockStatus, setBlockStatus] = useState(403)
  const [maintenanceEnabled, setMaintenanceEnabled] = useState(false)
  const [maintenanceHtml, setMaintenanceHtml] = useState("")
  const [maintenanceStatus, setMaintenanceStatus] = useState(503)
  const [maxBodyBytes, setMaxBodyBytes] = useState(0)
  const [antiReplayEnabled, setAntiReplayEnabled] = useState(false)
  const [antiReplayTTL, setAntiReplayTTL] = useState(300)
  const [antiReplayAction, setAntiReplayAction] = useState("shield_challenge")

  // Per-site protection overrides
  const [owaspEnabled, setOwaspEnabled] = useState<boolean | null>(null)
  const [owaspSensitivity, setOwaspSensitivity] = useState("")
  const [cveEnabled, setCveEnabled] = useState<boolean | null>(null)
  const [rateLimitEnabled, setRateLimitEnabled] = useState<boolean | null>(null)
  const [rateLimitWindow, setRateLimitWindow] = useState(0)
  const [rateLimitMax, setRateLimitMax] = useState(0)
  const [botProtectionEnabled, setBotProtectionEnabled] = useState<
    boolean | null
  >(null)
  const [botProtectionLevel, setBotProtectionLevel] = useState("medium")

  const [appRules, setAppRules] = useState<ApplicationRouteRule[]>([])
  const [recItems, setRecItems] = useState<RecordedResource[]>([])
  const [recTotal, setRecTotal] = useState(0)
  const [recPage, setRecPage] = useState(1)
  const [invLoading, setInvLoading] = useState(false)
  const recPageSize = 20

  const load = useCallback(async () => {
    if (siteId === "_") {
      setSite(null)
      setLoading(false)
      return
    }
    setLoading(true)
    try {
      const [s, stats] = await Promise.all([
        getSite(siteId),
        getSiteAccessLogStats(siteId).catch((error) => {
          toast.error(
            error instanceof Error ? error.message : "加载站点统计失败"
          )
          return null
        }),
      ])
      setSite(s)
      setAccessStats(stats)
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
      setOwaspAction(s.owasp_action || "intercept")
      setCveAction(s.cve_action || "intercept")
      setRateLimitAction(s.rate_limit_action || "rate_limit")
      setOwaspEnabled(s.owasp_enabled ?? null)
      setOwaspSensitivity(s.owasp_sensitivity || "")
      setCveEnabled(s.cve_enabled ?? null)
      setRateLimitEnabled(s.rate_limit_enabled ?? null)
      setRateLimitWindow(s.rate_limit_window || 0)
      setRateLimitMax(s.rate_limit_max || 0)
      setBotProtectionEnabled(s.bot_protection_enabled ?? null)
      setBotProtectionLevel(s.bot_protection_level || "medium")
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
      toast.error(String(err))
      setSite(null)
    } finally {
      setLoading(false)
    }
  }, [siteId])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    getCertificates()
      .then((data) => setCertificates(data.items || []))
      .catch((error) => {
        toast.error(error instanceof Error ? error.message : "加载证书列表失败")
        setCertificates([])
      })
  }, [])

  const refreshInventory = useCallback(
    async (recordedPageOverride?: number) => {
      if (siteId === "_" || siteId === "") return
      const sid = Number(siteId)
      if (Number.isNaN(sid)) return
      const page = recordedPageOverride ?? recPage
      setInvLoading(true)
      try {
        const [rRules, rRec] = await Promise.all([
          listApplicationRouteRules(sid, { page: 1, page_size: 200 }),
          listRecordedResources(sid, { page, page_size: recPageSize }),
        ])
        setAppRules(rRules.items || [])
        setRecItems(rRec.items || [])
        setRecTotal(Number(rRec.total) || 0)
      } catch (e) {
        toast.error(String(e))
      } finally {
        setInvLoading(false)
      }
    },
    [siteId, recPage, recPageSize]
  )

  useEffect(() => {
    if (tab !== "inventory" || siteId === "_") return
    void refreshInventory()
  }, [tab, siteId, recPage, recPageSize, refreshInventory])

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
          min_tls_version: tlsEnabled ? minTlsVersion : undefined,
          max_tls_version: tlsEnabled ? maxTlsVersion : undefined,
          cipher_suites: tlsEnabled ? cipherSuites : undefined,
          alpn: tlsEnabled ? alpn : undefined,
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
          bot_protection_level: botProtectionLevel || undefined,
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

    setSaving(true)
    try {
      await updateSite(site.id, payload)
      toast.success("站点配置已保存")
      load()
    } catch (err) {
      toast.error(String(err))
    } finally {
      setSaving(false)
    }
  }

  async function handleToggle() {
    if (!site) return
    try {
      if (site.enabled) {
        await stopSite(site.id)
      } else {
        await startSite(site.id)
      }
      toast.success(site.enabled ? "站点已停用" : "站点已启用")
      load()
    } catch (err) {
      toast.error(String(err))
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
    try {
      await createApplicationRouteRule(site.id, {
        name: `资源规则 ${appRules.length + 1}`,
        enabled: true,
        priority: 0,
        target: "request_method",
        op: "eq",
        pattern: "GET",
        header_key: "",
      })
      toast.success("已创建规则")
      await refreshInventory()
    } catch (err) {
      toast.error(String(err))
    }
  }

  async function handleSaveAppRule(rule: ApplicationRouteRule) {
    if (!site || rule.id == null) return
    try {
      await updateApplicationRouteRule(site.id, rule.id, {
        name: rule.name ?? "",
        enabled: isAppRouteRuleEnabled(rule),
        priority: rule.priority ?? 0,
        target: rule.target,
        op: rule.op,
        pattern: rule.pattern,
        header_key: rule.header_key ?? "",
      })
      toast.success("规则已保存")
      await refreshInventory()
    } catch (err) {
      toast.error(String(err))
    }
  }

  async function handleDeleteAppRule(ruleId: number) {
    if (!site) return
    const rule = appRules.find((item) => item.id === ruleId)
    if (
      !window.confirm(
        `确定删除应用路由规则「${rule?.name || ruleId}」？删除后本站点将停止按该规则记录资源。`
      )
    )
      return
    try {
      await deleteApplicationRouteRule(site.id, ruleId)
      toast.success("已删除")
      await refreshInventory()
    } catch (err) {
      toast.error(String(err))
    }
  }

  async function handleClearRecorded() {
    if (!site) return
    if (
      !window.confirm(
        `确定清空站点「${site.host || site.id}」的已记录资源数据？此操作只影响当前站点的资源聚合记录，不会删除访问日志或规则，且不可恢复。`
      )
    )
      return
    try {
      await clearRecordedResources(site.id)
      toast.success("已清空")
      setRecPage(1)
      await refreshInventory(1)
    } catch (err) {
      toast.error(String(err))
    }
  }

  if (loading) {
    return (
      <EmptyState
        title="正在加载站点配置"
        description="正在读取站点基础信息、监听器、证书和最近 24 小时访问统计。"
        action={<Loader2 className="h-5 w-5 animate-spin text-slate-400" />}
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
  ]

  const recTotalPages = Math.max(1, Math.ceil(recTotal / recPageSize))

  const quickLinks = [
    {
      label: "CC 防护",
      desc: "管理 CC 防护规则与等待室",
      icon: Zap,
      href: "/cc-protection/",
      color: "bg-amber-50 text-amber-600",
    },
    {
      label: "Bot 防护",
      desc: "调整 Bot 阈值与评分策略",
      icon: Bot,
      href: "/bot-protection/",
      color: "bg-purple-50 text-purple-600",
    },
    {
      label: "攻击防护",
      desc: "配置 OWASP 与限流策略",
      icon: ShieldAlert,
      href: "/protection/",
      color: "bg-red-50 text-red-600",
    },
    {
      label: "安全策略",
      desc: "验证码、5秒盾与防重放",
      icon: ShieldCheck,
      href: "/security/",
      color: "bg-slate-100 text-slate-600",
    },
    {
      label: "请求日志",
      desc: "按首个 Host 检索请求明细",
      icon: FileText,
      href: `/access-logs/?host=${encodeURIComponent(site.host.split(",")[0]?.trim() || site.host)}`,
      color: "bg-cyan-50 text-cyan-600",
    },
    {
      label: "拦截日志",
      desc: "按首个 Host 查看拦截事件",
      icon: ShieldAlert,
      href: `/security-events/?host=${encodeURIComponent(site.host.split(",")[0]?.trim() || site.host)}`,
      color: "bg-rose-50 text-rose-600",
    },
  ]

  return (
    <div className="space-y-6">
      <Button
        asChild
        variant="ghost"
        className="rounded-md text-slate-500 hover:text-slate-900"
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
        description={`${site.tls_enabled ? "HTTPS" : "HTTP"} · 监听 ${site.bind} · 网络 ${site.network} · 创建于 ${formatDate(site.created_at)}`}
        actions={
          <>
            <span
              className={`inline-flex h-8 items-center rounded-lg border px-2.5 text-xs font-medium ${
                site.enabled
                  ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                  : "border-slate-200 bg-slate-50 text-slate-500"
              }`}
            >
              {site.enabled ? "运行中" : "已停止"}
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
            className="group console-panel flex min-w-0 items-start gap-3 p-4 text-left transition-all hover:border-slate-300 hover:shadow-md"
          >
            <div
              className={`flex size-10 shrink-0 items-center justify-center rounded-lg ${q.color}`}
            >
              <q.icon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <h3 className="truncate text-sm font-semibold text-slate-900 group-hover:text-slate-600">
                {q.label}
              </h3>
              <p className="mt-1 line-clamp-2 text-xs text-slate-500">
                {q.desc}
              </p>
            </div>
          </Link>
        ))}
      </div>

      <Tabs
        value={tab}
        onValueChange={(value) => setTab(value as TabKey)}
        className="rounded-lg border border-slate-200 bg-white shadow-sm"
      >
        <div className="overflow-x-auto overscroll-x-contain border-b border-slate-200 p-1">
          <TabsList variant="line" className="min-w-max bg-transparent">
            {tabs.map((t) => (
              <TabsTrigger key={t.key} value={t.key} className="px-5 py-2">
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <div className="p-6">
          {/* Basic Config Tab */}
          {tab === "basic" && (
            <div className="space-y-5">
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
                  />
                </FieldGroup>
                <FieldGroup label="网络协议">
                  <select
                    value={network}
                    onChange={(e) => setNetwork(e.target.value)}
                    className="h-10 w-full rounded-md border border-slate-200 bg-white px-3 text-sm"
                  >
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                  </select>
                </FieldGroup>
                <FieldGroup label="接入协议">
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setTlsEnabled(false)
                        setCertId(null)
                        setBind(":80")
                      }}
                      className={`flex-1 rounded-md border px-4 py-2 text-sm font-medium ${
                        !tlsEnabled
                          ? "border-slate-950 bg-slate-100 text-slate-950"
                          : "border-slate-200 text-slate-600"
                      }`}
                    >
                      HTTP
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setTlsEnabled(true)
                        setBind(":443")
                      }}
                      className={`flex-1 rounded-md border px-4 py-2 text-sm font-medium ${
                        tlsEnabled
                          ? "border-slate-950 bg-slate-100 text-slate-950"
                          : "border-slate-200 text-slate-600"
                      }`}
                    >
                      HTTPS
                    </button>
                  </div>
                </FieldGroup>
                {tlsEnabled && (
                  <>
                    <FieldGroup label="TLS 证书">
                      <Select
                        value={certId ? String(certId) : "none"}
                        onValueChange={(value) =>
                          setCertId(value === "none" ? null : Number(value))
                        }
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
                        </SelectContent>
                      </Select>
                    </FieldGroup>
                    <FieldGroup label="最低 TLS 版本">
                      <Select
                        value={minTlsVersion}
                        onValueChange={setMinTlsVersion}
                      >
                        <SelectTrigger className="rounded-md">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="TLS10">
                            TLS 1.0（不推荐）
                          </SelectItem>
                          <SelectItem value="TLS11">
                            TLS 1.1（不推荐）
                          </SelectItem>
                          <SelectItem value="TLS12">TLS 1.2（推荐）</SelectItem>
                          <SelectItem value="TLS13">TLS 1.3</SelectItem>
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
                          <SelectItem value="TLS10">TLS 1.0</SelectItem>
                          <SelectItem value="TLS11">TLS 1.1</SelectItem>
                          <SelectItem value="TLS12">TLS 1.2</SelectItem>
                          <SelectItem value="TLS13">TLS 1.3（推荐）</SelectItem>
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
                      <p className="mt-1 text-[11px] text-slate-500">
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
                        <p className="mt-1 text-[11px] text-slate-500">
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
                      <SelectItem value="strip_all_and_set_remote">
                        忽略 X-Forwarded-For，使用直连 IP
                      </SelectItem>
                      <SelectItem value="trust_outer_waf_cidr_then_take_leftmost">
                        信任外层 WAF CIDR 后取最左 IP
                      </SelectItem>
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
                <label className="flex items-center justify-between rounded-md border border-slate-200 bg-slate-50 px-4 py-3 md:col-span-2">
                  <div>
                    <div className="text-sm font-medium text-slate-900">
                      保留原始 Host
                    </div>
                    <div className="mt-0.5 text-xs text-slate-500">
                      转发到上游时使用客户端请求 Host，并写入 X-Forwarded-Host。
                    </div>
                  </div>
                  <Switch
                    checked={preserveOriginalHost}
                    onCheckedChange={setPreserveOriginalHost}
                    aria-label="保留原始 Host"
                  />
                </label>
              </div>
            </div>
          )}

          {/* Listeners Tab */}
          {tab === "listeners" && (
            <SiteListenersPanel siteId={site.id} onChanged={load} />
          )}

          {/* Upstream Tab */}
          {tab === "upstream" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">
                    上游地址列表
                  </h3>
                  <p className="text-xs text-slate-500">
                    请求将被转发到以下上游服务器
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="rounded-md"
                  onClick={() =>
                    setUpstreams([...upstreams, "http://127.0.0.1:8080"])
                  }
                >
                  <Plus className="mr-1.5 h-3.5 w-3.5" />
                  添加上游
                </Button>
              </div>
              <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                多上游按轮询转发；安全请求在连接失败时会尝试下一个
                upstream，避免重复提交非幂等请求。
              </div>
              <div className="grid gap-4 rounded-md border border-slate-200 bg-slate-50 p-4 md:grid-cols-2">
                <label className="flex items-center justify-between rounded-md border border-slate-200 bg-white px-4 py-3">
                  <div>
                    <div className="text-sm font-medium text-slate-900">
                      跳过上游 TLS 校验
                    </div>
                    <div className="mt-0.5 text-xs text-slate-500">
                      仅用于自签名或测试上游。
                    </div>
                  </div>
                  <Switch
                    checked={upstreamTLSSkipVerify}
                    onCheckedChange={setUpstreamTLSSkipVerify}
                    aria-label="跳过上游 TLS 校验"
                  />
                </label>
                <FieldGroup label="上游 TLS Server Name">
                  <Input
                    value={upstreamTLSServerName}
                    onChange={(e) => setUpstreamTLSServerName(e.target.value)}
                    placeholder="origin.example.com"
                    className="rounded-md font-mono"
                  />
                </FieldGroup>
              </div>
              <div className="space-y-3">
                {upstreams.length === 0 ? (
                  <div className="rounded-md border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-sm text-slate-400">
                    暂无上游地址，请点击上方按钮添加
                  </div>
                ) : (
                  upstreams.map((u, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 p-2"
                    >
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
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 shrink-0 rounded-md text-red-500 hover:bg-red-50 hover:text-red-600"
                          onClick={() =>
                            setUpstreams(
                              upstreams.filter((_, idx) => idx !== i)
                            )
                          }
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Advanced Tab */}
          {tab === "advanced" && (
            <div className="space-y-6">
              {/* Per-site Protection Configuration */}
              <div className="rounded-md border border-slate-200 p-5">
                <h3 className="mb-1 text-sm font-semibold text-slate-900">
                  站点防护配置
                </h3>
                <p className="mb-3 text-xs text-slate-500">
                  为本站点单独配置防护策略，或跟随全局配置。规则级 action
                  优先级更高。
                </p>
                <div className="mb-5 rounded-xl border border-cyan-100 bg-cyan-50/80 px-3 py-2 text-xs leading-5 text-cyan-800">
                  只有 OWASP、CVE、频率限制、Bot 使用“继承全局 / 覆盖启用 /
                  覆盖关闭”三态；缓存、防重放、维护模式是站点本地开关。
                </div>

                <div className="space-y-5">
                  {/* OWASP Section */}
                  <div className="rounded-md border border-slate-100 bg-slate-50/60 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-red-500" />
                      <span className="text-sm font-semibold text-slate-900">
                        攻击防护 (OWASP)
                      </span>
                    </div>
                    <InheritToggle
                      value={owaspEnabled}
                      onChange={(value) => {
                        setOwaspEnabled(value)
                        if (value === null) {
                          setOwaspSensitivity("")
                        }
                      }}
                    />
                    {owaspEnabled !== null && (
                      <div className="mt-4 space-y-3">
                        <label className="flex items-center justify-between rounded-md border border-slate-200 bg-white px-4 py-3">
                          <div>
                            <div className="text-sm font-medium text-slate-900">
                              启用 OWASP 检测
                            </div>
                            <div className="mt-0.5 text-xs text-slate-500">
                              关闭后将跳过 OWASP 攻击检测
                            </div>
                          </div>
                          <Switch
                            checked={owaspEnabled === true}
                            onCheckedChange={(v) => setOwaspEnabled(v)}
                            aria-label="启用 OWASP 检测"
                          />
                        </label>
                        <div className="grid gap-4 md:grid-cols-2">
                          <FieldGroup label="检测灵敏度">
                            <Select
                              value={owaspSensitivity || "mid"}
                              onValueChange={setOwaspSensitivity}
                            >
                              <SelectTrigger className="rounded-md bg-white">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {sensitivityLevels.map((item) => (
                                  <SelectItem
                                    key={item.value}
                                    value={item.value}
                                  >
                                    {item.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                          <FieldGroup label="命中动作">
                            <Select
                              value={owaspAction}
                              onValueChange={setOwaspAction}
                            >
                              <SelectTrigger className="rounded-md bg-white">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {terminalWAFActionOptions.map((item) => (
                                  <SelectItem
                                    key={item.value}
                                    value={item.value}
                                  >
                                    {item.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* CVE Section */}
                  <div className="rounded-md border border-slate-100 bg-slate-50/60 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-orange-500" />
                      <span className="text-sm font-semibold text-slate-900">
                        CVE 检测
                      </span>
                    </div>
                    <InheritToggle
                      value={cveEnabled}
                      onChange={setCveEnabled}
                    />
                    {cveEnabled !== null && (
                      <div className="mt-4 space-y-3">
                        <label className="flex items-center justify-between rounded-md border border-slate-200 bg-white px-4 py-3">
                          <div>
                            <div className="text-sm font-medium text-slate-900">
                              启用 CVE 检测
                            </div>
                            <div className="mt-0.5 text-xs text-slate-500">
                              关闭后将跳过 CVE 漏洞检测
                            </div>
                          </div>
                          <Switch
                            checked={cveEnabled === true}
                            onCheckedChange={(v) => setCveEnabled(v)}
                            aria-label="启用 CVE 检测"
                          />
                        </label>
                        <div className="max-w-sm">
                          <FieldGroup label="命中动作">
                            <Select
                              value={cveAction}
                              onValueChange={setCveAction}
                            >
                              <SelectTrigger className="rounded-md bg-white">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {terminalWAFActionOptions.map((item) => (
                                  <SelectItem
                                    key={item.value}
                                    value={item.value}
                                  >
                                    {item.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Rate Limit Section */}
                  <div className="rounded-md border border-slate-100 bg-slate-50/60 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <Zap className="h-4 w-4 text-amber-500" />
                      <span className="text-sm font-semibold text-slate-900">
                        频率限制
                      </span>
                    </div>
                    <InheritToggle
                      value={rateLimitEnabled}
                      onChange={(value) => {
                        setRateLimitEnabled(value)
                        if (value === null) {
                          setRateLimitWindow(0)
                          setRateLimitMax(0)
                        }
                      }}
                    />
                    {rateLimitEnabled !== null && (
                      <div className="mt-4 space-y-3">
                        <label className="flex items-center justify-between rounded-md border border-slate-200 bg-white px-4 py-3">
                          <div>
                            <div className="text-sm font-medium text-slate-900">
                              启用频率限制
                            </div>
                            <div className="mt-0.5 text-xs text-slate-500">
                              关闭后将跳过请求频率限制检查
                            </div>
                          </div>
                          <Switch
                            checked={rateLimitEnabled === true}
                            onCheckedChange={(v) => setRateLimitEnabled(v)}
                            aria-label="启用频率限制"
                          />
                        </label>
                        <div className="grid gap-4 md:grid-cols-3">
                          <FieldGroup label="时间窗口（秒）">
                            <Input
                              type="number"
                              min={1}
                              value={rateLimitWindow}
                              onChange={(e) =>
                                setRateLimitWindow(Number(e.target.value))
                              }
                              className="rounded-md bg-white"
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
                              className="rounded-md bg-white"
                              placeholder="100"
                            />
                          </FieldGroup>
                          <FieldGroup label="命中动作">
                            <Select
                              value={rateLimitAction}
                              onValueChange={setRateLimitAction}
                            >
                              <SelectTrigger className="rounded-md bg-white">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {terminalWAFActionOptions.map((item) => (
                                  <SelectItem
                                    key={item.value}
                                    value={item.value}
                                  >
                                    {item.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </FieldGroup>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Bot Protection Section */}
                  <div className="rounded-md border border-slate-100 bg-slate-50/60 p-4">
                    <div className="mb-3 flex items-center gap-2">
                      <Bot className="h-4 w-4 text-purple-500" />
                      <span className="text-sm font-semibold text-slate-900">
                        Bot 防护
                      </span>
                    </div>
                    <label className="flex items-center justify-between rounded-md border border-slate-200 bg-white px-4 py-3">
                      <div>
                        <div className="text-sm font-medium text-slate-900">
                          启用 Bot 防护
                        </div>
                        <div className="mt-0.5 text-xs text-slate-500">
                          按站点覆盖 Bot 检测开关；继承时使用全局配置
                        </div>
                      </div>
                      <InheritToggle
                        value={botProtectionEnabled}
                        onChange={setBotProtectionEnabled}
                      />
                    </label>
                    {botProtectionEnabled !== null && (
                      <div className="mt-3 max-w-sm">
                        <FieldGroup label="防护等级">
                          <Select
                            value={botProtectionLevel}
                            onValueChange={setBotProtectionLevel}
                          >
                            <SelectTrigger className="rounded-md bg-white">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="low">
                                低 - 仅拦截高置信度 Bot
                              </SelectItem>
                              <SelectItem value="medium">
                                中 - 均衡策略
                              </SelectItem>
                              <SelectItem value="high">
                                高 - 严格检测
                              </SelectItem>
                            </SelectContent>
                          </Select>
                        </FieldGroup>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="rounded-md border border-slate-200 p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">
                      资源缓存规则
                    </h3>
                    <p className="text-xs text-slate-500">
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
                  <div className="mt-4 space-y-3">
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
                    <p className="text-xs text-slate-500">
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
                      <p className="text-xs text-amber-800">
                        提示：以「.」开头的是<strong>扩展名</strong>
                        ，应选「后缀」才能匹配如{" "}
                        <code className="rounded bg-amber-100 px-1 font-mono">
                          /app/main.js
                        </code>
                        ；「前缀」表示路径从首字符起匹配（例如{" "}
                        <code className="rounded bg-amber-100 px-1 font-mono">
                          /_next/static
                        </code>
                        ）。
                      </p>
                    )}
                    {cacheRules.map((rule, idx) => (
                      <div
                        key={idx}
                        className="space-y-2 rounded-md border border-slate-200 bg-slate-50 p-3"
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
                            <SelectTrigger className="rounded-md bg-white">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="suffix">后缀</SelectItem>
                              <SelectItem value="prefix">前缀</SelectItem>
                              <SelectItem value="exact">精确</SelectItem>
                              <SelectItem value="contains">子串</SelectItem>
                              <SelectItem value="regex">正则</SelectItem>
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
                            className="rounded-md bg-white font-mono text-xs"
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
                            className="rounded-md bg-white"
                          />
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-9 w-9 text-rose-500"
                            onClick={() =>
                              setCacheRules(
                                cacheRules.filter((_, i) => i !== idx)
                              )
                            }
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                        <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs text-slate-700 md:pl-1">
                          <label className="flex cursor-pointer items-center gap-2">
                            <input
                              type="checkbox"
                              className="rounded border-slate-300"
                              checked={rule.ignore_query}
                              onChange={(e) =>
                                setCacheRules(
                                  cacheRules.map((item, i) =>
                                    i === idx
                                      ? {
                                          ...item,
                                          ignore_query: e.target.checked,
                                        }
                                      : item
                                  )
                                )
                              }
                            />
                            忽略查询串（匹配与缓存键不含 ? 后参数）
                          </label>
                          <label className="flex cursor-pointer items-center gap-2">
                            <input
                              type="checkbox"
                              className="rounded border-slate-300"
                              checked={rule.case_insensitive}
                              onChange={(e) =>
                                setCacheRules(
                                  cacheRules.map((item, i) =>
                                    i === idx
                                      ? {
                                          ...item,
                                          case_insensitive: e.target.checked,
                                        }
                                      : item
                                  )
                                )
                              }
                            />
                            忽略大小写（路径与缓存键路径用小写）
                          </label>
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
              <div className="rounded-md border border-slate-200 p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">
                      维护模式
                    </h3>
                    <p className="text-xs text-slate-500">
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
                      <textarea
                        value={maintenanceHtml}
                        onChange={(e) => setMaintenanceHtml(e.target.value)}
                        rows={3}
                        placeholder="<h1>维护中</h1>"
                        className="w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-sm"
                      />
                    </FieldGroup>
                  </div>
                )}
              </div>

              {/* Block settings */}
              <div className="rounded-md border border-slate-200 p-5">
                <h3 className="text-sm font-semibold text-slate-900">
                  自定义拦截页面
                </h3>
                <p className="mb-4 text-xs text-slate-500">
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
                    <textarea
                      value={blockHtml}
                      onChange={(e) => setBlockHtml(e.target.value)}
                      rows={3}
                      placeholder="<h1>Access Denied</h1>"
                      className="w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-sm"
                    />
                  </FieldGroup>
                </div>
              </div>

              {/* Max body */}
              <div className="rounded-md border border-slate-200 p-5">
                <h3 className="text-sm font-semibold text-slate-900">
                  请求体限制
                </h3>
                <p className="mb-4 text-xs text-slate-500">
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
              <div className="rounded-md border border-slate-200 p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">
                      防重放保护
                    </h3>
                    <p className="text-xs text-slate-500">
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
                          {terminalWAFActionOptions.map((item) => (
                            <SelectItem key={item.value} value={item.value}>
                              {item.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </FieldGroup>
                  </div>
                )}
              </div>
            </div>
          )}

          {tab === "inventory" && (
            <div className="space-y-8">
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

              <div className="rounded-md border border-slate-200 p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Route className="h-4 w-4 text-slate-500" />
                    <h3 className="text-sm font-semibold text-slate-900">
                      匹配规则
                    </h3>
                    {invLoading && (
                      <Loader2 className="h-4 w-4 animate-spin text-slate-400" />
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
                      size="sm"
                      className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
                      onClick={() => void handleAddAppRule()}
                    >
                      <Plus data-icon="inline-start" />
                      添加规则
                    </Button>
                  </div>
                </div>

                {appRules.length === 0 ? (
                  <p className="text-sm text-slate-500">
                    暂无规则，点击「添加规则」创建一条默认规则后再按需修改。
                  </p>
                ) : (
                  <div className="space-y-4">
                    {appRules.map((rule) => {
                      const rid = rule.id ?? 0
                      const showHeaderKey =
                        (rule.target || "") === "request_header"
                      return (
                        <div
                          key={rid || rule.name}
                          className="space-y-3 rounded-md border border-slate-200 bg-slate-50/50 p-4"
                        >
                          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                            <FieldGroup label="名称">
                              <Input
                                value={rule.name ?? ""}
                                onChange={(e) =>
                                  patchAppRule(rid, { name: e.target.value })
                                }
                                className="rounded-md bg-white"
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
                                className="rounded-md bg-white"
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
                                variant="ghost"
                                className="rounded-md text-red-600 hover:bg-red-50"
                                disabled={!rid}
                                onClick={() => void handleDeleteAppRule(rid)}
                              >
                                <Trash2 />
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
                                <SelectTrigger className="rounded-md bg-white">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  {APP_ROUTE_TARGETS.map((t) => (
                                    <SelectItem key={t.value} value={t.value}>
                                      {t.label}
                                    </SelectItem>
                                  ))}
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
                                <SelectTrigger className="rounded-md bg-white">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  {APP_ROUTE_OPS.map((o) => (
                                    <SelectItem key={o.value} value={o.value}>
                                      {o.label}
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                            </FieldGroup>
                            <FieldGroup label="匹配值 / 模式">
                              <Input
                                value={rule.pattern ?? ""}
                                onChange={(e) =>
                                  patchAppRule(rid, { pattern: e.target.value })
                                }
                                className="rounded-md bg-white font-mono text-xs"
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
                                className="max-w-md rounded-md bg-white font-mono text-xs"
                                placeholder="User-Agent"
                              />
                            </FieldGroup>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>

              <div className="rounded-md border border-slate-200 p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">
                      已记录资源摘要
                    </h3>
                    <p className="mt-1 text-xs text-slate-500">
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
                      variant="outline"
                      size="sm"
                      className="rounded-md text-red-600 hover:bg-red-50"
                      onClick={() => void handleClearRecorded()}
                    >
                      清空当前站点记录
                    </Button>
                  </div>
                </div>
                <div className="rounded-md border border-slate-100">
                  <Table className="min-w-[960px] text-xs">
                    <TableHeader className="bg-slate-50 text-slate-600">
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
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {recItems.length === 0 ? (
                        <TableRow>
                          <TableCell
                            colSpan={10}
                            className="px-3 py-8 text-center text-slate-500"
                          >
                            暂无记录；配置规则并产生匹配流量后将在此聚合展示。
                          </TableCell>
                        </TableRow>
                      ) : (
                        recItems.map((row) => (
                          <TableRow key={row.id}>
                            <TableCell className="px-2 py-2 font-mono">
                              <Badge variant="secondary" className="font-mono">
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
                              title={row.path}
                            >
                              {row.path}
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
                            <TableCell className="px-2 py-2 whitespace-nowrap text-slate-500">
                              {formatDate(row.first_seen)}
                            </TableCell>
                            <TableCell className="px-2 py-2 whitespace-nowrap text-slate-500">
                              {formatDate(row.last_seen)}
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600">
                  <span>
                    共 {recTotal} 条 · 第 {recPage} / {recTotalPages} 页 · 规则
                    ID 为记录产生时的历史命中值
                  </span>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-8 rounded-md"
                      disabled={recPage <= 1}
                      onClick={() => setRecPage((p) => Math.max(1, p - 1))}
                    >
                      上一页
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-8 rounded-md"
                      disabled={recPage >= recTotalPages}
                      onClick={() => setRecPage((p) => p + 1)}
                    >
                      下一页
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {tab !== "inventory" && (
          <div className="flex justify-end border-t border-slate-200 px-6 py-4">
            <Button
              onClick={handleSave}
              disabled={saving}
              className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
            >
              {saving ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Save className="mr-2 h-4 w-4" />
              )}
              {saving ? "保存中..." : "保存配置"}
            </Button>
          </div>
        )}
      </Tabs>
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
    slate: "bg-slate-50 text-slate-700",
    rose: "bg-rose-50 text-rose-700",
    amber: "bg-amber-50 text-amber-700",
  }[tone]
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="text-xs font-medium text-slate-500">{label}</div>
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
    <div className={`space-y-1.5 ${className ?? ""}`}>
      <label className="text-sm font-medium text-slate-700">{label}</label>
      {children}
    </div>
  )
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
    <div className="inline-flex overflow-hidden rounded-md border border-slate-200">
      {items.map((item) => (
        <button
          key={item.value}
          type="button"
          onClick={() =>
            onChange(
              item.value === "inherit"
                ? null
                : item.value === "on"
                  ? true
                  : false
            )
          }
          className={`px-3.5 py-1.5 text-xs font-medium transition-colors ${
            current === item.value
              ? "bg-teal-600 text-white"
              : "bg-white text-slate-500 hover:bg-slate-50"
          }`}
        >
          {item.label}
        </button>
      ))}
    </div>
  )
}
