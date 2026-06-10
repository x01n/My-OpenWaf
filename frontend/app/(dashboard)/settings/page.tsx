"use client"

import Link from "next/link"
import { useCallback, useEffect, useId, useMemo, useState } from "react"
import {
  ArrowRight,
  AlertTriangle,
  Clock,
  Copy,
  Database,
  Download,
  Eye,
  Globe,
  KeyRound,
  Lock,
  Network,
  Plus,
  RefreshCcw,
  Save,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Trash2,
  Zap,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { downloadCSV, toCSV } from "@/lib/download"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
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
import { Badge } from "@/components/ui/badge"
import {
  ConsoleTableShell,
  InlineMeta,
  PageIntro,
  Surface,
} from "@/components/console-shell"
import {
  CopyableBlock,
  DetailField,
  redactSensitiveText,
  WAFActionBadge,
} from "@/components/log-presentation"
import { Pagination } from "@/components/pagination"
import { RequestTracePanel } from "@/components/request-trace-panel"
import {
  createAPIKey,
  createSystemSetting,
  deleteSystemSetting,
  forceLogoutSession,
  getAPIKeys,
  getAccessLog,
  getAccessToken,
  getAuthMe,
  getAccessLogs,
  getDashboardSummary,
  getLogConfig,
  getNetworkConfig,
  getProtectionSettings,
  getRedisConfig,
  getRuntimeConfig,
  getRequestTrace,
  getSecurityEvent,
  getSecurityEvents,
  getSystemSettings,
  getTLSCipherSuites,
  getTLSDefaultConfig,
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
  listAuthSessions,
  reloadRuntimeSnapshot,
  removeAPIKey,
  updateRedisConfig,
  updateLogConfig,
  updateNetworkConfig,
  updateProtectionSettings,
  updateSystemSetting,
  updateTLSDefaultConfig,
  type APIKey,
  type AccessLog,
  type AuthSession,
  type AuthUser,
  type DashboardSummary,
  type LogConfig,
  type ProtectionSettings,
  type RequestTrace,
  type RuntimeConfig,
  type RedisConfig,
  type SecurityEvent,
  type SystemSetting,
} from "@/lib/api"
import { CAPTCHA_TYPE_OPTIONS } from "@/lib/security-api"
import { categoryLabels, getWAFActionMeta, phaseLabels } from "@/lib/console"
import { cn, formatBytes, formatDate, formatLatency } from "@/lib/utils"

type TLSCipherSuiteOption = {
  id: number
  name: string
}

type TLSCurveOption = {
  id: number
  name: string
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function getSettingValue(
  settings: SystemSetting[],
  key: string,
  fallback = ""
): string {
  return settings.find((s) => s.key === key)?.value ?? fallback
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days} 天 ${hours} 小时 ${mins} 分`
  if (hours > 0) return `${hours} 小时 ${mins} 分`
  return `${mins} 分钟`
}

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

function settingOperationDetails(
  key: string,
  value: string,
  response: SystemSetting
) {
  return {
    operation: "save_setting",
    payload: {
      key,
      value: redactSensitiveText(value),
    },
    response: {
      key: response.key,
      value: redactSensitiveText(response.value),
    },
  }
}

function readCurrentAccessJTI(): string {
  const token = getAccessToken()
  if (!token) return ""

  try {
    const parts = token.split(".")
    if (parts.length !== 3) return ""
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/")
    const paddedPayload = payload.padEnd(
      payload.length + ((4 - (payload.length % 4)) % 4),
      "="
    )
    const parsed = JSON.parse(atob(paddedPayload)) as { jti?: unknown }
    return typeof parsed.jti === "string" ? parsed.jti : ""
  } catch {
    return ""
  }
}

function optionCardClass(selected: boolean, className?: string) {
  return cn(
    "flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors",
    selected
      ? "border-primary/30 bg-primary/10"
      : "border-border bg-card hover:border-primary/30",
    className
  )
}

function optionPillClass(selected: boolean) {
  return cn(
    "flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors",
    selected
      ? "border-primary/30 bg-primary/10 text-primary"
      : "border-border bg-card text-muted-foreground hover:border-primary/30"
  )
}

function actionBadgeVariant(action?: string) {
  if (action === "intercept" || action === "block") return "destructive"
  if (action === "drop") return "secondary"
  if (action === "observe") return "outline"
  return "secondary"
}

function statusBadgeVariant(statusCode: number) {
  if (statusCode >= 500) return "destructive"
  if (statusCode >= 400) return "secondary"
  if (statusCode >= 200 && statusCode < 300) return "outline"
  return "secondary"
}

const RETENTION_OPTIONS = [
  { value: "0", label: "不清理" },
  { value: "1", label: "1 天" },
  { value: "3", label: "3 天" },
  { value: "7", label: "7 天" },
  { value: "15", label: "15 天" },
  { value: "30", label: "30 天" },
] as const

const OPTIMIZE_INTERVAL_OPTIONS = [
  { value: "1", label: "1 小时" },
  { value: "6", label: "6 小时" },
  { value: "12", label: "12 小时" },
  { value: "24", label: "24 小时" },
  { value: "48", label: "48 小时" },
  { value: "72", label: "72 小时" },
] as const

const CUSTOM_HTML_CODES = [
  {
    code: "403",
    label: "403 Forbidden",
  },
  {
    code: "429",
    label: "429 Too Many Requests",
  },
  {
    code: "404",
    label: "404 Not Found",
  },
  {
    code: "502",
    label: "502 Bad Gateway",
  },
  {
    code: "504",
    label: "504 Gateway Timeout",
  },
] as const

const LOG_PAGE_SIZE = 15

/* ------------------------------------------------------------------ */
/*  Main Component                                                     */
/* ------------------------------------------------------------------ */

export default function SettingsPage() {
  const tlsMinVersionId = useId()
  const tlsMaxVersionId = useId()
  const tlsCipherSuitesId = useId()
  const tlsCurvePreferencesId = useId()
  const tlsPreferServerCipherSuitesId = useId()
  const apiKeyNameId = useId()
  const minPasswordLenId = useId()
  const maxAttemptsId = useId()
  const lockoutMinutesId = useId()
  const sessionTimeoutId = useId()
  const accessIpWhitelistId = useId()
  const adminCertSelfSignedId = useId()
  const adminCertCustomId = useId()
  const adminCertNoneId = useId()
  const blockPageTypeId = useId()
  const blockPageTextId = useId()
  const customHtmlId = useId()
  const engineSingleId = useId()
  const engineMultiId = useId()
  const xffModeId = useId()
  const trustedCidrId = useId()
  const ipv6EnabledId = useId()
  const http2EnabledId = useId()
  const http3EnabledId = useId()
  const hstsEnabledId = useId()
  const brotliEnabledId = useId()
  const redisEnabledId = useId()
  const redisAddrId = useId()
  const redisPasswordId = useId()
  const redisDbId = useId()
  const logLevelId = useId()
  const logFilePathId = useId()
  const logAlsoStdoutId = useId()
  const [activeTab, setActiveTab] = useState("protection")

  /* Shared data */
  const [settings, setSettings] = useState<SystemSetting[]>([])
  const [protection, setProtection] = useState<ProtectionSettings | null>(null)
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [loading, setLoading] = useState(true)

  /* ---- Protection Config tab state ---- */
  const [savingProtection, setSavingProtection] = useState(false)

  // Data cleanup retention
  const [secEventRetention, setSecEventRetention] = useState("30")
  const [accessLogRetention, setAccessLogRetention] = useState("30")
  const [statsRetention, setStatsRetention] = useState("0")
  const [dbOptimizeInterval, setDbOptimizeInterval] = useState("24")

  // Block page customization
  const [blockPageType, setBlockPageType] = useState("default")
  const [blockPageText, setBlockPageText] = useState("")
  const [activeCustomCode, setActiveCustomCode] = useState("403")
  const [customHtmlMap, setCustomHtmlMap] = useState<Record<string, string>>({})

  // Detection engine mode
  const [engineMode, setEngineMode] = useState("multi")

  // Network config
  const [xffMode, setXffMode] = useState("X-Forwarded-For")
  const [trustedCidr, setTrustedCidr] = useState("")

  // Protocol state
  const [ipv6Enabled, setIpv6Enabled] = useState(false)
  const [http2Enabled, setHttp2Enabled] = useState(false)
  const [http3Enabled, setHttp3Enabled] = useState(false)
  const [hstsEnabled, setHstsEnabled] = useState(false)
  const [brotliEnabled, setBrotliEnabled] = useState(false)

  // TLS 配置
  const [tlsMinVersion, setTlsMinVersion] = useState("TLS12")
  const [tlsMaxVersion, setTlsMaxVersion] = useState("TLS13")
  const [cipherSuites, setCipherSuites] = useState("")
  const [curvePreferences, setCurvePreferences] = useState(
    "X25519,CurveP256,CurveP384"
  )
  const [preferServerCipherSuites, setPreferServerCipherSuites] = useState(true)
  const [secureCipherSuiteOptions, setSecureCipherSuiteOptions] = useState<
    TLSCipherSuiteOption[]
  >([])
  const [insecureCipherSuiteOptions, setInsecureCipherSuiteOptions] = useState<
    TLSCipherSuiteOption[]
  >([])
  const [curveOptions, setCurveOptions] = useState<TLSCurveOption[]>([])

  // 验证码策略
  const [captchaType, setCaptchaType] = useState("math")

  /* ---- Console Management tab state ---- */
  const [savingConsole, setSavingConsole] = useState(false)

  // Login security (from protection settings)
  const [maxAttempts, setMaxAttempts] = useState(5)
  const [lockoutMinutes, setLockoutMinutes] = useState(15)
  const [minPasswordLen, setMinPasswordLen] = useState(8)
  const [sessionTimeout, setSessionTimeout] = useState(60)
  const [accessIpWhitelist, setAccessIpWhitelist] = useState("")

  // API keys
  const [apiKeys, setApiKeys] = useState<APIKey[]>([])
  const [apiKeysLoading, setApiKeysLoading] = useState(false)
  const [apiKeyDialogOpen, setApiKeyDialogOpen] = useState(false)
  const [newKeyName, setNewKeyName] = useState("")
  const [createdToken, setCreatedToken] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<APIKey | null>(null)
  const [deleting, setDeleting] = useState(false)

  // Auth sessions
  const [authUser, setAuthUser] = useState<AuthUser | null>(null)
  const [sessions, setSessions] = useState<AuthSession[]>([])
  const [sessionsLoading, setSessionsLoading] = useState(false)
  const [sessionTarget, setSessionTarget] = useState<AuthSession | null>(null)
  const [sessionDeleting, setSessionDeleting] = useState(false)

  // Admin console certificate
  const [adminCertMode, setAdminCertMode] = useState("self_signed")

  /* ---- Runtime Config tab state ---- */
  const [runtimeConfig, setRuntimeConfig] = useState<RuntimeConfig | null>(null)
  const [redisConfig, setRedisConfig] = useState<RedisConfig | null>(null)
  const [redisEnabled, setRedisEnabled] = useState(false)
  const [redisAddr, setRedisAddr] = useState("")
  const [redisPassword, setRedisPassword] = useState("")
  const [redisDB, setRedisDB] = useState(0)
  const [savingRedis, setSavingRedis] = useState(false)
  const [reloadingRuntime, setReloadingRuntime] = useState(false)
  const [runtimeReloadDetails, setRuntimeReloadDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [systemSettingDeleteTarget, setSystemSettingDeleteTarget] =
    useState<SystemSetting | null>(null)
  const [systemSettingDeleting, setSystemSettingDeleting] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)

  /* ---- System Logs tab state ---- */
  const [logConfig, setLogConfig] = useState<LogConfig | null>(null)
  const [logLevel, setLogLevel] = useState("INFO")
  const [logFilePath, setLogFilePath] = useState("")
  const [logAlsoStdout, setLogAlsoStdout] = useState(false)
  const [savingLogConfig, setSavingLogConfig] = useState(false)
  const [logType, setLogType] = useState<"security" | "access">("security")
  const [secEvents, setSecEvents] = useState<SecurityEvent[]>([])
  const [accessLogs, setAccessLogs] = useState<AccessLog[]>([])
  const [logPage, setLogPage] = useState(1)
  const [logTotal, setLogTotal] = useState(0)
  const [logLoading, setLogLoading] = useState(false)
  const [logSearch, setLogSearch] = useState("")
  const [selectedAccessLog, setSelectedAccessLog] = useState<AccessLog | null>(
    null
  )
  const [selectedSecurityEvent, setSelectedSecurityEvent] =
    useState<SecurityEvent | null>(null)
  const [loadingAccessLogId, setLoadingAccessLogId] = useState<number | null>(
    null
  )
  const [loadingSecurityEventId, setLoadingSecurityEventId] = useState<
    number | null
  >(null)
  const [requestTrace, setRequestTrace] = useState<RequestTrace | null>(null)
  const [traceLoading, setTraceLoading] = useState(false)

  const selectedCipherSuiteNames = useMemo(
    () =>
      cipherSuites
        .split(",")
        .map((name) => name.trim())
        .filter(Boolean),
    [cipherSuites]
  )
  const selectedCurveNames = useMemo(
    () =>
      curvePreferences
        .split(",")
        .map((name) => name.trim())
        .filter(Boolean),
    [curvePreferences]
  )
  const sortedSystemSettings = useMemo(
    () =>
      [...settings].sort((left, right) => left.key.localeCompare(right.key)),
    [settings]
  )
  const currentSessionJTI = readCurrentAccessJTI()

  /* ---------------------------------------------------------------- */
  /*  Data loading                                                     */
  /* ---------------------------------------------------------------- */

  async function loadSettings() {
    setLoading(true)
    try {
      const [
        systemSettings,
        protectionSettings,
        dash,
        networkConfig,
        tlsConfig,
        cipherSuiteConfig,
        runtime,
        redis,
        log,
      ] = await Promise.all([
        getSystemSettings(),
        getProtectionSettings(),
        getDashboardSummary().catch((e) => {
          toast.error(e instanceof Error ? e.message : "加载运行摘要失败")
          return null
        }),
        getNetworkConfig().catch((e) => {
          toast.error(e instanceof Error ? e.message : "加载网络配置失败")
          return null
        }),
        getTLSDefaultConfig().catch((e) => {
          toast.error(e instanceof Error ? e.message : "加载 TLS 默认配置失败")
          return null
        }),
        getTLSCipherSuites().catch((e) => {
          toast.error(e instanceof Error ? e.message : "加载 TLS 可选套件失败")
          return { secure: [], insecure: [], curves: [] }
        }),
        getRuntimeConfig().catch((e) => {
          toast.error(e instanceof Error ? e.message : "加载运行配置失败")
          return null
        }),
        getRedisConfig().catch((e) => {
          toast.error(e instanceof Error ? e.message : "加载 Redis 配置失败")
          return null
        }),
        getLogConfig().catch((e) => {
          toast.error(e instanceof Error ? e.message : "加载日志配置失败")
          return null
        }),
      ])
      setSettings(systemSettings)
      setProtection(protectionSettings)
      setSummary(dash)
      setRuntimeConfig(runtime)
      setRedisConfig(redis)
      setLogConfig(log)
      setSecureCipherSuiteOptions(cipherSuiteConfig.secure ?? [])
      setInsecureCipherSuiteOptions(cipherSuiteConfig.insecure ?? [])
      setCurveOptions(cipherSuiteConfig.curves ?? [])

      // Populate protection config
      setSecEventRetention(
        getSettingValue(systemSettings, "security_event_retention_days", "30")
      )
      setAccessLogRetention(
        getSettingValue(systemSettings, "access_log_retention_days", "30")
      )
      setStatsRetention(
        getSettingValue(systemSettings, "stats_retention_days", "0")
      )
      setDbOptimizeInterval(
        getSettingValue(systemSettings, "db_optimize_interval_hours", "24")
      )
      setBlockPageType(
        getSettingValue(systemSettings, "block_page_type", "default")
      )
      setBlockPageText(getSettingValue(systemSettings, "block_page_text", ""))
      setEngineMode(getSettingValue(systemSettings, "engine_mode", "multi"))

      // Load custom HTML per code
      const htmlMap: Record<string, string> = {}
      for (const item of CUSTOM_HTML_CODES) {
        htmlMap[item.code] = getSettingValue(
          systemSettings,
          `custom_html_${item.code}`,
          ""
        )
      }
      setCustomHtmlMap(htmlMap)

      // Network config
      setXffMode(getSettingValue(systemSettings, "xff_mode", "X-Forwarded-For"))
      setTrustedCidr(getSettingValue(systemSettings, "trusted_cidr", ""))

      // Protocol
      setIpv6Enabled(networkConfig?.ipv6_enabled ?? false)
      setHttp2Enabled(networkConfig?.http2_enabled ?? true)
      setHttp3Enabled(networkConfig?.http3_enabled ?? true)
      setTlsMinVersion(tlsConfig?.min_version ?? "TLS12")
      setTlsMaxVersion(tlsConfig?.max_version ?? "TLS13")
      setCipherSuites(tlsConfig?.cipher_suites ?? "")
      setCurvePreferences(
        tlsConfig?.curve_preferences ?? "X25519,CurveP256,CurveP384"
      )
      setPreferServerCipherSuites(
        tlsConfig?.prefer_server_cipher_suites ?? true
      )
      setCaptchaType(
        protectionSettings?.captcha_type ??
          getSettingValue(systemSettings, "captcha_type", "math")
      )
      setHstsEnabled(getSettingValue(systemSettings, "hsts_enabled") === "true")
      setBrotliEnabled(
        getSettingValue(systemSettings, "brotli_enabled") === "true"
      )
      setRedisEnabled(redis?.enabled ?? false)
      setRedisAddr(redis?.addr ?? "")
      setRedisDB(redis?.db ?? 0)
      setRedisPassword("")
      setLogLevel(log?.level ?? "INFO")
      setLogFilePath(log?.file_path ?? "")
      setLogAlsoStdout(log?.also_stdout ?? false)

      // Login security
      setMaxAttempts(protectionSettings.login_max_attempts ?? 5)
      setLockoutMinutes(protectionSettings.login_lockout_minutes ?? 15)
      setMinPasswordLen(protectionSettings.login_min_password_length ?? 8)
      setSessionTimeout(
        Number(getSettingValue(systemSettings, "session_timeout_minutes", "60"))
      )
      setAccessIpWhitelist(
        getSettingValue(systemSettings, "access_ip_whitelist", "")
      )

      // Admin cert
      setAdminCertMode(
        getSettingValue(systemSettings, "admin_cert_mode", "self_signed")
      )
    } finally {
      setLoading(false)
    }
  }

  async function loadApiKeys() {
    setApiKeysLoading(true)
    try {
      const data = await getAPIKeys()
      setApiKeys(data.items || [])
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载 API 密钥失败")
    } finally {
      setApiKeysLoading(false)
    }
  }

  async function loadSessions() {
    setSessionsLoading(true)
    try {
      const me = await getAuthMe()
      setAuthUser(me)
      const data = await listAuthSessions(me.role === "admin")
      setSessions(data.sessions ?? [])
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载会话失败")
      setAuthUser(null)
      setSessions([])
    } finally {
      setSessionsLoading(false)
    }
  }

  const loadConsoleData = useCallback(async () => {
    await Promise.all([loadApiKeys(), loadSessions()])
  }, [])

  const loadLogs = useCallback(async () => {
    setLogLoading(true)
    try {
      if (logType === "security") {
        const res = await getSecurityEvents({
          page: logPage,
          page_size: LOG_PAGE_SIZE,
          client_ip: logSearch || undefined,
        })
        setSecEvents(res.items ?? [])
        setLogTotal(res.total ?? 0)
      } else {
        const res = await getAccessLogs({
          page: logPage,
          page_size: LOG_PAGE_SIZE,
          client_ip: logSearch || undefined,
        })
        setAccessLogs(res.items ?? [])
        setLogTotal(res.total ?? 0)
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载日志失败")
      if (logType === "security") {
        setSecEvents([])
      } else {
        setAccessLogs([])
      }
      setLogTotal(0)
    } finally {
      setLogLoading(false)
    }
  }, [logType, logPage, logSearch])

  useEffect(() => {
    return deferEffect(loadSettings)
  }, [])

  useEffect(() => {
    if (activeTab !== "console") return
    return deferEffect(loadConsoleData)
  }, [activeTab, loadConsoleData])

  useEffect(() => {
    if (activeTab !== "logs") return
    return deferEffect(loadLogs)
  }, [activeTab, loadLogs])

  /* ---------------------------------------------------------------- */
  /*  Save handlers                                                    */
  /* ---------------------------------------------------------------- */

  async function saveSetting(key: string, value: string) {
    const exists = settings.find((s) => s.key === key)
    if (exists) {
      return updateSystemSetting(key, value)
    } else {
      return createSystemSetting({ key, value })
    }
  }

  function collectAppliedReloadFailure(message: string, error: unknown) {
    if (!isConfigAppliedReloadFailureError(error)) {
      throw error
    }
    const details =
      getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
    if (!message && details) {
      setReloadFailureDetails(details)
    }
    return message || error.message
  }

  async function handleSaveProtection() {
    setSavingProtection(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      let reloadFailureMessage = ""
      const operationResponses: Record<string, unknown>[] = []
      // System settings
      const pairs: [string, string][] = [
        ["security_event_retention_days", secEventRetention],
        ["access_log_retention_days", accessLogRetention],
        ["stats_retention_days", statsRetention],
        ["db_optimize_interval_hours", dbOptimizeInterval],
        ["block_page_type", blockPageType],
        ["block_page_text", blockPageText],
        ["engine_mode", engineMode],
        ["xff_mode", xffMode],
        ["trusted_cidr", trustedCidr],
        ["hsts_enabled", String(hstsEnabled)],
        ["brotli_enabled", String(brotliEnabled)],
      ]

      const [latestNetworkConfig, latestTLSConfig] = await Promise.all([
        getNetworkConfig(),
        getTLSDefaultConfig(),
      ])
      const defaultALPN = [
        http3Enabled ? "h3" : null,
        http2Enabled ? "h2" : null,
        "http/1.1",
      ]
        .filter(Boolean)
        .join(",")

      const networkPayload = {
        ipv6_enabled: ipv6Enabled,
        http2_enabled: http2Enabled,
        http3_enabled: http3Enabled,
        http3_bind: latestNetworkConfig.http3_bind,
        default_alpn: defaultALPN,
        default_network: ipv6Enabled ? "tcp6" : "tcp",
      }
      const tlsPayload = {
        min_version: tlsMinVersion,
        max_version: tlsMaxVersion,
        cipher_suites: cipherSuites,
        default_alpn: defaultALPN,
        curve_preferences: curvePreferences,
        prefer_server_cipher_suites: preferServerCipherSuites,
        self_signed_on_ip: latestTLSConfig.self_signed_on_ip,
      }

      await Promise.all([
        updateNetworkConfig(networkPayload)
          .then((response) => {
            operationResponses.push({
              operation: "update_network_config",
              payload: networkPayload,
              response,
            })
          })
          .catch((error) => {
            reloadFailureMessage = collectAppliedReloadFailure(
              reloadFailureMessage,
              error
            )
          }),
        updateTLSDefaultConfig(tlsPayload)
          .then((response) => {
            operationResponses.push({
              operation: "update_tls_default_config",
              payload: tlsPayload,
              response,
            })
          })
          .catch((error) => {
            reloadFailureMessage = collectAppliedReloadFailure(
              reloadFailureMessage,
              error
            )
          }),
      ])

      for (const item of CUSTOM_HTML_CODES) {
        pairs.push([`custom_html_${item.code}`, customHtmlMap[item.code] ?? ""])
      }

      for (const [key, value] of pairs) {
        try {
          const response = await saveSetting(key, value)
          operationResponses.push(settingOperationDetails(key, value, response))
        } catch (error) {
          reloadFailureMessage = collectAppliedReloadFailure(
            reloadFailureMessage,
            error
          )
        }
      }

      if (!reloadFailureMessage) {
        setOperationDetails({
          operation: "save_protection_settings",
          payload: operationResponses.map((item) => item.payload ?? null),
          response: operationResponses.map((item) => item.response ?? null),
          responses: operationResponses,
        })
      }
      if (reloadFailureMessage) {
        toast.error(reloadFailureMessage)
      } else {
        toast.success("防护配置已保存")
      }
      await loadSettings()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存防护配置失败")
    } finally {
      setSavingProtection(false)
    }
  }

  function toggleCipherSuite(name: string) {
    const next = selectedCipherSuiteNames.includes(name)
      ? selectedCipherSuiteNames.filter((item) => item !== name)
      : [...selectedCipherSuiteNames, name]
    setCipherSuites(next.join(","))
  }

  function toggleCurvePreference(name: string) {
    const next = selectedCurveNames.includes(name)
      ? selectedCurveNames.filter((item) => item !== name)
      : [...selectedCurveNames, name]
    setCurvePreferences(next.join(","))
  }

  async function handleSaveConsole() {
    setSavingConsole(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      let reloadFailureMessage = ""
      const operationResponses: Record<string, unknown>[] = []
      const protectionPayload = {
        login_max_attempts: maxAttempts,
        login_lockout_minutes: lockoutMinutes,
        login_min_password_length: minPasswordLen,
      }
      try {
        const response = await updateProtectionSettings(protectionPayload)
        operationResponses.push({
          operation: "update_login_protection",
          payload: protectionPayload,
          response,
        })
      } catch (error) {
        reloadFailureMessage = collectAppliedReloadFailure(
          reloadFailureMessage,
          error
        )
      }

      // Save other console settings
      const pairs: [string, string][] = [
        ["session_timeout_minutes", String(sessionTimeout)],
        ["access_ip_whitelist", accessIpWhitelist],
        ["admin_cert_mode", adminCertMode],
      ]

      for (const [key, value] of pairs) {
        try {
          const response = await saveSetting(key, value)
          operationResponses.push(settingOperationDetails(key, value, response))
        } catch (error) {
          reloadFailureMessage = collectAppliedReloadFailure(
            reloadFailureMessage,
            error
          )
        }
      }

      if (!reloadFailureMessage) {
        setOperationDetails({
          operation: "save_console_settings",
          payload: operationResponses.map((item) => item.payload ?? null),
          response: operationResponses.map((item) => item.response ?? null),
          responses: operationResponses,
        })
      }
      if (reloadFailureMessage) {
        toast.error(reloadFailureMessage)
      } else {
        toast.success("控制台设置已保存")
      }
      await loadSettings()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存控制台设置失败")
    } finally {
      setSavingConsole(false)
    }
  }

  /* ---------------------------------------------------------------- */
  /*  API Key handlers                                                 */
  /* ---------------------------------------------------------------- */

  async function handleCreateKey() {
    if (!newKeyName.trim()) {
      toast.error("请输入密钥名称")
      return
    }
    setCreating(true)
    setOperationDetails(null)
    try {
      const response = await createAPIKey(newKeyName)
      setCreatedToken(response.token || null)
      setOperationDetails({
        operation: "create_api_key",
        payload: {
          name: newKeyName,
        },
        response: apiKeyResponseSummary(response),
      })
      setNewKeyName("")
      toast.success("密钥已创建，请立即复制明文 Token。")
      loadApiKeys()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "创建 API 密钥失败")
    } finally {
      setCreating(false)
    }
  }

  async function handleDeleteKey() {
    if (!deleteTarget) return
    setDeleting(true)
    setOperationDetails(null)
    try {
      const target = deleteTarget
      await removeAPIKey(target.id)
      setOperationDetails({
        operation: "delete_api_key",
        payload: {
          id: target.id,
          name: target.name,
        },
        status_code: 204,
        response: null,
      })
      toast.success("API 密钥已删除")
      setDeleteTarget(null)
      loadApiKeys()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除 API 密钥失败")
    } finally {
      setDeleting(false)
    }
  }

  async function handleForceLogoutSession() {
    if (!sessionTarget) return
    setSessionDeleting(true)
    setOperationDetails(null)
    try {
      const target = sessionTarget
      await forceLogoutSession(target.jti)
      setOperationDetails({
        operation: "force_logout_session",
        payload: {
          jti_masked: maskToken(target.jti),
          username: target.username,
          ip: target.ip,
        },
        status_code: 204,
        response: null,
      })
      toast.success("会话已强制退出")
      setSessionTarget(null)
      await loadSessions()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "强制退出失败")
    } finally {
      setSessionDeleting(false)
    }
  }

  async function handleReloadRuntime() {
    setReloadingRuntime(true)
    setRuntimeReloadDetails(null)
    setOperationDetails(null)
    const payload = null
    try {
      const response = await reloadRuntimeSnapshot()
      setRuntimeReloadDetails(response as unknown as Record<string, unknown>)
      setOperationDetails({
        operation: "reload_runtime_snapshot",
        payload,
        response,
      })
      const runtime = await getRuntimeConfig()
      setRuntimeConfig(runtime)
      toast.success("运行快照已重新加载")
    } catch (e) {
      const response = {
        error: e instanceof Error ? e.message : "运行快照重载失败",
      }
      setRuntimeReloadDetails(response)
      setOperationDetails({
        operation: "reload_runtime_snapshot",
        payload,
        response,
      })
      toast.error(e instanceof Error ? e.message : "运行快照重载失败")
    } finally {
      setReloadingRuntime(false)
    }
  }

  async function handleDeleteSystemSetting() {
    if (!systemSettingDeleteTarget) return
    const target = systemSettingDeleteTarget
    const payload = {
      key: target.key,
    }
    setSystemSettingDeleting(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      await deleteSystemSetting(target.key)
      setOperationDetails({
        operation: "delete_system_setting",
        payload,
        status_code: 204,
        response: null,
      })
      toast.success("系统设置已删除")
      setSystemSettingDeleteTarget(null)
      await loadSettings()
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(e)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "delete_system_setting",
            payload,
            response: details,
          })
        }
        toast.error(e.message)
        setSystemSettingDeleteTarget(null)
        await loadSettings()
      } else {
        toast.error(e instanceof Error ? e.message : "删除系统设置失败")
      }
    } finally {
      setSystemSettingDeleting(false)
    }
  }

  async function handleSaveLogConfig() {
    setSavingLogConfig(true)
    setOperationDetails(null)
    try {
      const payload = {
        level: logLevel,
        file_path: logFilePath,
        also_stdout: logAlsoStdout,
      }
      const next = await updateLogConfig(payload)
      setLogConfig(next)
      setLogLevel(next.level)
      setLogFilePath(next.file_path)
      setLogAlsoStdout(next.also_stdout)
      setOperationDetails({
        operation: "update_log_config",
        payload,
        response: next,
      })
      toast.success("日志配置已保存并立即生效")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "保存日志配置失败")
    } finally {
      setSavingLogConfig(false)
    }
  }

  async function openAccessLogDetail(item: AccessLog) {
    setSelectedAccessLog(item)
    setRequestTrace(null)
    setLoadingAccessLogId(item.id)
    setTraceLoading(true)
    try {
      const detail = await getAccessLog(item.id)
      setSelectedAccessLog(detail)
      if (detail.request_id) {
        try {
          const trace = await getRequestTrace(detail.request_id)
          setRequestTrace(trace)
        } catch {
          setRequestTrace(null)
        }
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载访问日志详情失败")
    } finally {
      setLoadingAccessLogId(null)
      setTraceLoading(false)
    }
  }

  async function openSecurityEventDetail(item: SecurityEvent) {
    setSelectedSecurityEvent(item)
    setRequestTrace(null)
    setLoadingSecurityEventId(item.id)
    setTraceLoading(true)
    try {
      const detail = await getSecurityEvent(item.id)
      setSelectedSecurityEvent(detail)
      if (detail.request_id) {
        try {
          const trace = await getRequestTrace(detail.request_id)
          setRequestTrace(trace)
        } catch {
          setRequestTrace(null)
        }
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载安全事件详情失败")
    } finally {
      setLoadingSecurityEventId(null)
      setTraceLoading(false)
    }
  }

  async function loadRequestTrace(requestId?: string) {
    if (!requestId) return
    setTraceLoading(true)
    try {
      const trace = await getRequestTrace(requestId)
      setRequestTrace(trace)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载请求追踪失败")
    } finally {
      setTraceLoading(false)
    }
  }

  async function handleSaveRedis() {
    setSavingRedis(true)
    setOperationDetails(null)
    try {
      const payload: {
        enabled: boolean
        addr: string
        db: number
        password?: string
      } = {
        enabled: redisEnabled,
        addr: redisAddr,
        db: redisDB,
      }
      if (redisPassword !== "") {
        payload.password = redisPassword
      }
      const [redis, runtime] = await Promise.all([
        updateRedisConfig(payload),
        getRuntimeConfig(),
      ])
      setRedisConfig(redis)
      setRuntimeConfig(runtime)
      setRedisEnabled(redis.enabled)
      setRedisAddr(redis.addr)
      setRedisDB(redis.db)
      setRedisPassword("")
      setOperationDetails({
        operation: "update_redis_config",
        payload: {
          enabled: payload.enabled,
          addr: payload.addr,
          db: payload.db,
          password_provided: Boolean(payload.password),
        },
        response: redis,
        runtime,
      })
      toast.success("Redis 配置已保存，重启后重建 Redis 客户端")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "保存 Redis 配置失败")
    } finally {
      setSavingRedis(false)
    }
  }

  /* ---------------------------------------------------------------- */
  /*  Log export                                                       */
  /* ---------------------------------------------------------------- */

  function exportLogCSV() {
    if (logType === "security") {
      const headers = [
        "ID",
        "时间",
        "源 IP",
        "Host",
        "方法",
        "路径",
        "动作",
        "类别",
        "匹配说明",
      ]
      const rows = secEvents.map((e) => [
        e.id,
        formatDate(e.created_at),
        e.client_ip,
        e.host,
        e.method,
        redactSensitiveText(e.path),
        getWAFActionMeta(e.action).label,
        e.category,
        redactSensitiveText(e.match_desc),
      ])
      downloadCSV(toCSV(headers, rows), "security-events")
    } else {
      const headers = [
        "ID",
        "时间",
        "源 IP",
        "方法",
        "路径",
        "状态码",
        "当时 WAF 动作",
        "HTTP协议",
        "TLS版本",
        "TLS SNI",
        "TLS ALPN",
        "JA3",
        "JA3 Hash",
        "JA4",
        "Header Order",
        "上游",
      ]
      const rows = accessLogs.map((i) => [
        i.id,
        formatDate(i.created_at),
        i.client_ip,
        i.method,
        redactSensitiveText(i.path),
        i.status_code,
        i.waf_action ? getWAFActionMeta(i.waf_action).label : "-",
        i.http_protocol,
        i.tls_version,
        i.tls_sni,
        i.tls_alpn,
        i.tls_ja3,
        i.tls_ja3_hash,
        i.tls_ja4,
        i.header_order,
        i.upstream,
      ])
      downloadCSV(toCSV(headers, rows), "access-logs")
    }
  }

  /* ---------------------------------------------------------------- */
  /*  Loading state                                                    */
  /* ---------------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <PageIntro
          eyebrow="Platform Settings"
          title="系统设置"
          description="加载中..."
        />
        <Surface className="min-h-[400px]">
          <Skeleton className="h-[340px] rounded-lg" />
        </Surface>
      </div>
    )
  }

  const logTotalPages = Math.max(1, Math.ceil(logTotal / LOG_PAGE_SIZE))

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Platform Settings"
        title="通用设置"
        description="按使用场景拆成防护运行时、控制台安全、日志运维三组；验证码跳过凭据现在绑定 IP、User-Agent、站点与监听器，并使用短期有效期。"
      />
      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回保存后的响应体；请核对其中的 key、config、item、policy 或
            settings 字段。
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
          <ShieldCheck />
          <AlertTitle>最近设置操作响应</AlertTitle>
          <AlertDescription>
            后端已返回设置操作响应体；请核对 operation、responses、response
            或 status_code 字段。
          </AlertDescription>
          <CopyableBlock
            label="设置操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}
      <div className="console-data-grid">
        {[
          {
            title: "防护运行时",
            desc: "网络、TLS、拦截页、数据清理",
            icon: Shield,
          },
          {
            title: "控制台安全",
            desc: "登录限制、会话、API Key",
            icon: Lock,
          },
          {
            title: "日志运维",
            desc: "安全事件与访问日志检索",
            icon: Database,
          },
          {
            title: "运行配置",
            desc: "Redis、数据库、监听与启动参数",
            icon: Network,
          },
        ].map((item) => (
          <div key={item.title} className="console-panel p-4">
            <item.icon className="size-5 text-primary" />
            <div className="mt-3 text-sm font-semibold">{item.title}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              {item.desc}
            </div>
          </div>
        ))}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="overflow-x-auto overscroll-x-contain rounded-2xl border bg-card p-1 shadow-sm">
          <TabsList
            variant="line"
            className="mb-0 min-w-max border-b-0 bg-transparent pb-0"
          >
            <TabsTrigger
              value="protection"
              className="gap-1.5 px-4 py-2 text-sm"
            >
              <Shield className="size-4" />
              防护配置
            </TabsTrigger>
            <TabsTrigger value="console" className="gap-1.5 px-4 py-2 text-sm">
              <Server className="size-4" />
              控制台管理
            </TabsTrigger>
            <TabsTrigger value="logs" className="gap-1.5 px-4 py-2 text-sm">
              <Database className="size-4" />
              系统日志
            </TabsTrigger>
            <TabsTrigger value="runtime" className="gap-1.5 px-4 py-2 text-sm">
              <Network className="size-4" />
              运行配置
            </TabsTrigger>
          </TabsList>
        </div>

        {}
        {}
        {}
        <TabsContent value="protection">
          <div className="flex flex-col gap-6">
            {/* Data Cleanup */}
            <Surface
              title="数据清理"
              description="配置安全事件、访问日志和统计数据的自动清理周期，超过保留天数的数据将被自动删除。"
            >
              <div className="grid gap-6 lg:grid-cols-3">
                {/* Security events retention */}
                <FieldSet>
                  <FieldLegend className="flex items-center gap-2">
                    <ShieldCheck className="size-4 text-primary" />
                    安全事件保留
                  </FieldLegend>
                  <RadioGroup
                    value={secEventRetention}
                    onValueChange={setSecEventRetention}
                    className="flex flex-wrap gap-2"
                  >
                    {RETENTION_OPTIONS.map((opt) => (
                      <FieldLabel
                        key={opt.value}
                        htmlFor={`sec-event-retention-${opt.value}`}
                        className={optionPillClass(
                          secEventRetention === opt.value
                        )}
                      >
                        <RadioGroupItem
                          id={`sec-event-retention-${opt.value}`}
                          value={opt.value}
                          className="sr-only"
                        />
                        {opt.label}
                      </FieldLabel>
                    ))}
                  </RadioGroup>
                </FieldSet>

                {/* Access log retention */}
                <FieldSet>
                  <FieldLegend className="flex items-center gap-2">
                    <Clock className="size-4 text-primary" />
                    访问日志保留
                  </FieldLegend>
                  <RadioGroup
                    value={accessLogRetention}
                    onValueChange={setAccessLogRetention}
                    className="flex flex-wrap gap-2"
                  >
                    {RETENTION_OPTIONS.map((opt) => (
                      <FieldLabel
                        key={opt.value}
                        htmlFor={`access-log-retention-${opt.value}`}
                        className={optionPillClass(
                          accessLogRetention === opt.value
                        )}
                      >
                        <RadioGroupItem
                          id={`access-log-retention-${opt.value}`}
                          value={opt.value}
                          className="sr-only"
                        />
                        {opt.label}
                      </FieldLabel>
                    ))}
                  </RadioGroup>
                </FieldSet>

                {/* Stats retention */}
                <FieldSet>
                  <FieldLegend className="flex items-center gap-2">
                    <Database className="size-4 text-primary" />
                    统计报表保留
                  </FieldLegend>
                  <RadioGroup
                    value={statsRetention}
                    onValueChange={setStatsRetention}
                    className="flex flex-wrap gap-2"
                  >
                    {RETENTION_OPTIONS.map((opt) => (
                      <FieldLabel
                        key={opt.value}
                        htmlFor={`stats-retention-${opt.value}`}
                        className={optionPillClass(
                          statsRetention === opt.value
                        )}
                      >
                        <RadioGroupItem
                          id={`stats-retention-${opt.value}`}
                          value={opt.value}
                          className="sr-only"
                        />
                        {opt.label}
                      </FieldLabel>
                    ))}
                  </RadioGroup>
                </FieldSet>
              </div>
            </Surface>

            {/* Database Optimization */}
            <Surface
              title="数据库优化"
              description="配置自动数据库优化的执行间隔。清理过期数据后系统将自动执行数据库优化操作（VACUUM/OPTIMIZE）以回收空间并提升查询性能。"
            >
              <FieldSet>
                <FieldLegend className="flex items-center gap-2">
                  <RefreshCcw className="size-4 text-primary" />
                  优化执行间隔
                </FieldLegend>
                <RadioGroup
                  value={dbOptimizeInterval}
                  onValueChange={setDbOptimizeInterval}
                  className="flex flex-wrap gap-2"
                >
                  {OPTIMIZE_INTERVAL_OPTIONS.map((opt) => (
                    <FieldLabel
                      key={opt.value}
                      htmlFor={`db-optimize-interval-${opt.value}`}
                      className={optionPillClass(
                        dbOptimizeInterval === opt.value
                      )}
                    >
                      <RadioGroupItem
                        id={`db-optimize-interval-${opt.value}`}
                        value={opt.value}
                        className="sr-only"
                      />
                      {opt.label}
                    </FieldLabel>
                  ))}
                </RadioGroup>
                <FieldDescription>
                  设置较短的间隔可保持数据库紧凑，但会增加 I/O
                  开销。建议日志量大时设为 12-24 小时。
                </FieldDescription>
              </FieldSet>
            </Surface>

            {/* Block Page Customization */}
            <Surface
              title="拦截页面"
              description="配置 WAF 拦截时向客户端返回的页面内容和样式。"
            >
              <div className="flex flex-col gap-4">
                <Field>
                  <FieldLabel htmlFor={blockPageTypeId}>页面类型</FieldLabel>
                  <Select
                    value={blockPageType}
                    onValueChange={setBlockPageType}
                  >
                    <SelectTrigger
                      id={blockPageTypeId}
                      className="w-[260px] rounded-md"
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="default">默认拦截页面</SelectItem>
                        <SelectItem value="text">纯文本</SelectItem>
                        <SelectItem value="custom">自定义 HTML</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>

                {blockPageType === "text" && (
                  <Field>
                    <FieldLabel htmlFor={blockPageTextId}>
                      拦截文本内容
                    </FieldLabel>
                    <Textarea
                      id={blockPageTextId}
                      value={blockPageText}
                      onChange={(e) => setBlockPageText(e.target.value)}
                      rows={4}
                      className="rounded-md"
                      placeholder="例如：Access Denied - Your request has been blocked."
                    />
                  </Field>
                )}

                {blockPageType === "custom" && (
                  <Field>
                    <FieldLabel htmlFor={customHtmlId}>
                      自定义 HTML（按状态码配置）
                    </FieldLabel>
                    <ToggleGroup
                      type="single"
                      value={activeCustomCode}
                      onValueChange={(value) => {
                        if (value) setActiveCustomCode(value)
                      }}
                      variant="outline"
                      size="sm"
                      className="flex-wrap justify-start"
                    >
                      {CUSTOM_HTML_CODES.map((item) => (
                        <ToggleGroupItem
                          key={item.code}
                          value={item.code}
                          className="rounded-lg"
                        >
                          {item.label}
                        </ToggleGroupItem>
                      ))}
                    </ToggleGroup>
                    <Textarea
                      id={customHtmlId}
                      value={customHtmlMap[activeCustomCode] ?? ""}
                      onChange={(e) =>
                        setCustomHtmlMap((prev) => ({
                          ...prev,
                          [activeCustomCode]: e.target.value,
                        }))
                      }
                      rows={10}
                      className="rounded-md font-mono text-xs"
                      placeholder={`输入 ${activeCustomCode} 状态码的自定义 HTML...`}
                    />
                    <Alert>
                      <AlertTriangle />
                      <AlertDescription>
                        支持 Go template 变量：{"{{.StatusCode}}"}
                        {"  "}
                        {"{{.Message}}"}
                        {"  "}
                        {"{{.ClientIP}}"}
                        {"  "}
                        {"{{.RequestID}}"}
                      </AlertDescription>
                    </Alert>
                  </Field>
                )}
              </div>
            </Surface>

            {/* Detection Engine Mode */}
            <Surface
              title="检测引擎性能配置"
              description="配置 WAF 检测引擎的运行模式，影响检测吞吐量和资源占用。"
            >
              <div className="flex flex-col gap-3">
                <RadioGroup
                  value={engineMode}
                  onValueChange={setEngineMode}
                  className="grid gap-3 sm:grid-cols-2"
                >
                  <FieldLabel
                    htmlFor={engineSingleId}
                    className={optionCardClass(engineMode === "single")}
                  >
                    <RadioGroupItem
                      id={engineSingleId}
                      value="single"
                      className="mt-0.5"
                    />
                    <FieldContent>
                      <span className="text-sm font-medium">单线程模式</span>
                      <FieldDescription>
                        适合低配置环境，资源消耗低，检测按顺序执行。
                      </FieldDescription>
                    </FieldContent>
                  </FieldLabel>
                  <FieldLabel
                    htmlFor={engineMultiId}
                    className={optionCardClass(engineMode === "multi")}
                  >
                    <RadioGroupItem
                      id={engineMultiId}
                      value="multi"
                      className="mt-0.5"
                    />
                    <FieldContent>
                      <span className="text-sm font-medium">多线程模式</span>
                      <FieldDescription>
                        推荐。OWASP 与 CVE 检测并行执行，吞吐量更高。
                      </FieldDescription>
                    </FieldContent>
                  </FieldLabel>
                </RadioGroup>
              </div>
            </Surface>

            {/* Network & Protocol */}
            <div className="grid gap-6 xl:grid-cols-2">
              <Surface
                title="网络配置"
                description="客户端 IP 获取方式和信任代理设置。"
              >
                <FieldGroup className="grid gap-5">
                  <Field>
                    <FieldLabel htmlFor={xffModeId}>
                      <Globe className="size-4 text-muted-foreground" />
                      客户端 IP 获取方式
                    </FieldLabel>
                    <Select value={xffMode} onValueChange={setXffMode}>
                      <SelectTrigger id={xffModeId} className="rounded-md">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="X-Forwarded-For">
                            X-Forwarded-For
                          </SelectItem>
                          <SelectItem value="X-Real-IP">X-Real-IP</SelectItem>
                          <SelectItem value="RemoteAddr">
                            RemoteAddr (直连)
                          </SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                    <FieldDescription>
                      反向代理架构下应选择 X-Forwarded-For 或 X-Real-IP
                    </FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor={trustedCidrId}>
                      <Network className="size-4 text-muted-foreground" />
                      信任代理 CIDR 列表
                    </FieldLabel>
                    <Input
                      id={trustedCidrId}
                      value={trustedCidr}
                      onChange={(e) => setTrustedCidr(e.target.value)}
                      className="rounded-md"
                      placeholder="例如：10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
                    />
                    <FieldDescription>
                      多个 CIDR 用逗号分隔，仅从受信代理的请求中提取客户端 IP
                    </FieldDescription>
                  </Field>
                </FieldGroup>
              </Surface>

              <Surface
                title="协议支持"
                description="控制服务端支持的网络协议和压缩特性。"
              >
                <FieldGroup className="grid gap-4">
                  {[
                    {
                      id: ipv6EnabledId,
                      label: "IPv6 支持",
                      desc: "允许通过 IPv6 地址访问",
                      icon: Zap,
                      checked: ipv6Enabled,
                      onChange: setIpv6Enabled,
                    },
                    {
                      id: http2EnabledId,
                      label: "HTTP/2",
                      desc: "启用 HTTP/2 协议以提升传输效率",
                      icon: Zap,
                      checked: http2Enabled,
                      onChange: setHttp2Enabled,
                    },
                    {
                      id: http3EnabledId,
                      label: "HTTP/3 (QUIC)",
                      desc: "启用基于 QUIC 协议的 HTTP/3 支持",
                      icon: Zap,
                      checked: http3Enabled,
                      onChange: setHttp3Enabled,
                    },
                    {
                      id: hstsEnabledId,
                      label: "HTTPS HSTS",
                      desc: "启用严格传输安全（Strict-Transport-Security）",
                      icon: Lock,
                      checked: hstsEnabled,
                      onChange: setHstsEnabled,
                    },
                    {
                      id: brotliEnabledId,
                      label: "Brotli 压缩",
                      desc: "启用 Brotli 压缩以减小传输体积",
                      icon: Zap,
                      checked: brotliEnabled,
                      onChange: setBrotliEnabled,
                    },
                  ].map((item) => (
                    <Field
                      key={item.label}
                      orientation="horizontal"
                      className="rounded-lg border bg-muted/35 px-4 py-3"
                    >
                      <FieldContent>
                        <FieldLabel htmlFor={item.id}>
                          <item.icon className="size-4 text-muted-foreground" />{" "}
                          {item.label}
                        </FieldLabel>
                        <FieldDescription>{item.desc}</FieldDescription>
                      </FieldContent>
                      <Switch
                        id={item.id}
                        checked={item.checked}
                        onCheckedChange={item.onChange}
                      />
                    </Field>
                  ))}
                </FieldGroup>
              </Surface>
            </div>

            {/* TLS & Captcha Configuration */}
            <div className="grid gap-6 xl:grid-cols-2">
              <Surface
                title="TLS 安全配置"
                description="配置 TLS 版本范围和密码套件。"
              >
                <FieldGroup className="flex flex-col gap-4">
                  <div className="grid grid-cols-2 gap-4">
                    <Field>
                      <FieldLabel htmlFor={tlsMinVersionId}>
                        最低 TLS 版本
                      </FieldLabel>
                      <Select
                        value={tlsMinVersion}
                        onValueChange={setTlsMinVersion}
                      >
                        <SelectTrigger id={tlsMinVersionId}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="TLS10">TLS 1.0</SelectItem>
                            <SelectItem value="TLS11">TLS 1.1</SelectItem>
                            <SelectItem value="TLS12">TLS 1.2</SelectItem>
                            <SelectItem value="TLS13">TLS 1.3</SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field>
                      <FieldLabel htmlFor={tlsMaxVersionId}>
                        最高 TLS 版本
                      </FieldLabel>
                      <Select
                        value={tlsMaxVersion}
                        onValueChange={setTlsMaxVersion}
                      >
                        <SelectTrigger id={tlsMaxVersionId}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="TLS10">TLS 1.0</SelectItem>
                            <SelectItem value="TLS11">TLS 1.1</SelectItem>
                            <SelectItem value="TLS12">TLS 1.2</SelectItem>
                            <SelectItem value="TLS13">TLS 1.3</SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </Field>
                  </div>
                  <Field>
                    <FieldLabel htmlFor={tlsCipherSuitesId}>
                      密码套件（逗号分隔，留空使用默认值）
                    </FieldLabel>
                    <Textarea
                      id={tlsCipherSuitesId}
                      value={cipherSuites}
                      onChange={(e) => setCipherSuites(e.target.value)}
                      placeholder="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                      rows={3}
                    />
                    <FieldDescription>
                      Go 仅允许配置 TLS 1.0-1.2 密码套件；TLS 1.3
                      套件由运行时固定启用。
                    </FieldDescription>
                    {(secureCipherSuiteOptions.length > 0 ||
                      insecureCipherSuiteOptions.length > 0) && (
                      <div className="mt-3 flex flex-col gap-3">
                        <div>
                          <div className="mb-2 text-xs font-medium text-muted-foreground">
                            推荐套件
                          </div>
                          <ToggleGroup
                            type="multiple"
                            value={selectedCipherSuiteNames}
                            variant="outline"
                            size="sm"
                            className="flex-wrap justify-start"
                          >
                            {secureCipherSuiteOptions.map((suite) => {
                              return (
                                <ToggleGroupItem
                                  key={suite.id}
                                  value={suite.name}
                                  onClick={() => toggleCipherSuite(suite.name)}
                                  className="rounded-full"
                                >
                                  {suite.name}
                                </ToggleGroupItem>
                              )
                            })}
                          </ToggleGroup>
                        </div>
                        {insecureCipherSuiteOptions.length > 0 && (
                          <div>
                            <div className="mb-2 text-xs font-medium text-muted-foreground">
                              不推荐套件
                            </div>
                            <ToggleGroup
                              type="multiple"
                              value={selectedCipherSuiteNames}
                              variant="outline"
                              size="sm"
                              className="flex-wrap justify-start"
                            >
                              {insecureCipherSuiteOptions.map((suite) => {
                                return (
                                  <ToggleGroupItem
                                    key={suite.id}
                                    value={suite.name}
                                    onClick={() =>
                                      toggleCipherSuite(suite.name)
                                    }
                                    className="rounded-full"
                                  >
                                    {suite.name}
                                  </ToggleGroupItem>
                                )
                              })}
                            </ToggleGroup>
                          </div>
                        )}
                      </div>
                    )}
                  </Field>
                  <Field>
                    <FieldLabel htmlFor={tlsCurvePreferencesId}>
                      椭圆曲线优先级（逗号分隔）
                    </FieldLabel>
                    <Textarea
                      id={tlsCurvePreferencesId}
                      value={curvePreferences}
                      onChange={(e) => setCurvePreferences(e.target.value)}
                      placeholder="X25519,CurveP256,CurveP384"
                      rows={2}
                    />
                    {curveOptions.length > 0 && (
                      <ToggleGroup
                        type="multiple"
                        value={selectedCurveNames}
                        variant="outline"
                        size="sm"
                        className="mt-3 flex-wrap justify-start"
                      >
                        {curveOptions.map((curve) => {
                          return (
                            <ToggleGroupItem
                              key={curve.id}
                              value={curve.name}
                              onClick={() => toggleCurvePreference(curve.name)}
                              className="rounded-full"
                            >
                              {curve.name}
                            </ToggleGroupItem>
                          )
                        })}
                      </ToggleGroup>
                    )}
                  </Field>
                  <Field
                    orientation="horizontal"
                    className="rounded-lg border bg-muted/35 px-4 py-3"
                  >
                    <FieldContent>
                      <FieldLabel htmlFor={tlsPreferServerCipherSuitesId}>
                        服务端密码套件优先
                      </FieldLabel>
                      <FieldDescription>
                        TLS 1.2 及以下连接按服务端配置顺序选择密码套件。
                      </FieldDescription>
                    </FieldContent>
                    <Switch
                      id={tlsPreferServerCipherSuitesId}
                      checked={preferServerCipherSuites}
                      onCheckedChange={setPreferServerCipherSuites}
                    />
                  </Field>
                </FieldGroup>
              </Surface>

              <Surface
                title="验证码跳过凭据"
                description="通过验证码后只发放短期 pass cookie；后端会绑定 Host、客户端 IP、User-Agent、站点 ID 与监听器，迁移 IP 或换浏览器都需要重新验证。"
              >
                <div className="flex flex-col gap-4">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-lg border bg-muted/35 px-4 py-3">
                      <div className="text-sm font-medium">当前验证码类型</div>
                      <div className="mt-1 text-sm text-muted-foreground">
                        {CAPTCHA_TYPE_OPTIONS.find(
                          (option) => option.value === captchaType
                        )?.label ?? captchaType}
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {CAPTCHA_TYPE_OPTIONS.find(
                          (option) => option.value === captchaType
                        )?.description ?? "请前往安全策略页面调整。"}
                      </div>
                    </div>
                    <div className="rounded-lg border bg-primary/10 px-4 py-3 text-primary">
                      <div className="text-sm font-medium">跳过有效期</div>
                      <div className="mt-1 text-sm">
                        {protection?.captcha_pass_ttl ??
                          protection?.captcha_timeout ??
                          120}{" "}
                        秒
                      </div>
                      <div className="mt-1 text-xs text-primary/80">
                        不再默认保留 1 小时，避免长时间绕过。
                      </div>
                    </div>
                  </div>
                  <div className="rounded-lg border bg-card px-4 py-3 text-xs leading-6 text-muted-foreground">
                    已绑定：Host、IP、User-Agent、SiteID、Bind；旧版未绑定
                    UA/Site 的 pass cookie 不再接受。
                  </div>
                  <div className="flex items-center justify-between rounded-lg border bg-card px-4 py-3">
                    <div>
                      <div className="text-sm font-medium">统一管理入口</div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        验证码启用、类型切换、5
                        秒盾与连锁策略都在安全策略页维护，避免与系统设置重复保存。
                      </div>
                    </div>
                    <Button
                      asChild
                      variant="outline"
                      className="gap-2 rounded-md"
                    >
                      <Link href="/security/">
                        前往安全策略
                        <ArrowRight data-icon="inline-end" />
                      </Link>
                    </Button>
                  </div>
                </div>
              </Surface>
            </div>

            {/* System info (readonly) */}
            <Surface title="系统信息" description="当前运行实例的只读信息。">
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                <InlineMeta
                  label="版本号"
                  value={
                    <span className="flex items-center gap-2">
                      <Server className="size-3.5 text-muted-foreground" />
                      {getSettingValue(settings, "version", "未知")}
                    </span>
                  }
                />
                <InlineMeta
                  label="运行时间"
                  value={summary ? formatUptime(summary.uptime_sec) : "未知"}
                />
                <InlineMeta
                  label="系统设置数"
                  value={String(settings.length)}
                />
                <InlineMeta
                  label="数据面版本"
                  value={
                    <span className="font-mono text-xs">
                      {String(summary?.revision ?? "N/A")}
                    </span>
                  }
                />
              </div>
            </Surface>

            {/* Save button */}
            <div className="flex justify-end">
              <Button
                onClick={handleSaveProtection}
                disabled={savingProtection}
                className="rounded-md"
              >
                <Save data-icon="inline-start" />
                {savingProtection ? "保存中..." : "保存防护配置"}
              </Button>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="console">
          <div className="flex flex-col gap-6">
            {/* Login Security */}
            <Surface
              title="登录安全设置"
              description="配置管理控制台的密码策略、登录锁定、会话超时和访问白名单。"
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <FieldGroup className="flex flex-col gap-5">
                  <Field>
                    <FieldLabel htmlFor={minPasswordLenId}>
                      <Shield className="size-4 text-primary" />
                      最小密码长度
                    </FieldLabel>
                    <Input
                      id={minPasswordLenId}
                      type="number"
                      value={minPasswordLen}
                      onChange={(e) =>
                        setMinPasswordLen(Number(e.target.value))
                      }
                      className="rounded-md"
                      min={6}
                      max={128}
                    />
                    <FieldDescription>
                      管理员密码的最小字符数要求
                    </FieldDescription>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={maxAttemptsId}>
                      <Shield className="size-4 text-primary" />
                      最大登录失败次数
                    </FieldLabel>
                    <Input
                      id={maxAttemptsId}
                      type="number"
                      value={maxAttempts}
                      onChange={(e) => setMaxAttempts(Number(e.target.value))}
                      className="rounded-md"
                      min={1}
                      max={100}
                    />
                    <FieldDescription>
                      超过此次数后账户将被临时锁定
                    </FieldDescription>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={lockoutMinutesId}>
                      <Lock className="size-4 text-primary" />
                      锁定时长（分钟）
                    </FieldLabel>
                    <Input
                      id={lockoutMinutesId}
                      type="number"
                      value={lockoutMinutes}
                      onChange={(e) =>
                        setLockoutMinutes(Number(e.target.value))
                      }
                      className="rounded-md"
                      min={1}
                      max={1440}
                    />
                    <FieldDescription>
                      账户被锁定后的自动解锁等待时间
                    </FieldDescription>
                  </Field>
                </FieldGroup>

                <FieldGroup className="flex flex-col gap-5">
                  <Field>
                    <FieldLabel htmlFor={sessionTimeoutId}>
                      <Clock className="size-4 text-primary" />
                      会话超时时间（分钟）
                    </FieldLabel>
                    <Input
                      id={sessionTimeoutId}
                      type="number"
                      value={sessionTimeout}
                      onChange={(e) =>
                        setSessionTimeout(Number(e.target.value))
                      }
                      className="rounded-md"
                      min={5}
                      max={10080}
                    />
                    <FieldDescription>
                      登录会话无操作后自动失效的时间
                    </FieldDescription>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={accessIpWhitelistId}>
                      <Network className="size-4 text-primary" />
                      控制台访问 IP 白名单
                    </FieldLabel>
                    <Textarea
                      id={accessIpWhitelistId}
                      value={accessIpWhitelist}
                      onChange={(e) => setAccessIpWhitelist(e.target.value)}
                      rows={3}
                      className="rounded-md"
                      placeholder="每行一个 IP 或 CIDR，留空表示不限制"
                    />
                    <FieldDescription>
                      限制仅允许特定 IP 访问管理控制台，留空则不限制
                    </FieldDescription>
                  </Field>
                </FieldGroup>
              </div>
            </Surface>

            {/* Auth Sessions */}
            <ConsoleTableShell
              title="活跃会话"
              description="查看当前账号登录会话；管理员可查看全部会话并强制退出非当前会话。"
              toolbar={
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                    <Badge variant="outline" className="rounded-md">
                      {authUser?.username ?? "未读取用户"}
                    </Badge>
                    <Badge variant="secondary" className="rounded-md">
                      {authUser?.role === "admin" ? "全部会话" : "当前用户"}
                    </Badge>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={loadSessions}
                    disabled={sessionsLoading}
                  >
                    <RefreshCcw data-icon="inline-start" />
                    刷新
                  </Button>
                </div>
              }
              state={
                sessionsLoading ? (
                  <div className="flex flex-col gap-3 p-6">
                    <Skeleton className="h-10 rounded-lg" />
                    <Skeleton className="h-10 rounded-lg" />
                    <Skeleton className="h-10 rounded-lg" />
                  </div>
                ) : sessions.length === 0 ? (
                  <div className="p-16 text-center text-sm text-muted-foreground">
                    暂无活跃会话
                  </div>
                ) : undefined
              }
            >
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground">
                    <TableHead className="px-4 py-3">用户</TableHead>
                    <TableHead className="px-4 py-3">IP</TableHead>
                    <TableHead className="min-w-[220px] px-4 py-3">
                      User-Agent
                    </TableHead>
                    <TableHead className="px-4 py-3">设备</TableHead>
                    <TableHead className="px-4 py-3">登录时间</TableHead>
                    <TableHead className="px-4 py-3">最近活跃</TableHead>
                    <TableHead className="px-4 py-3">过期时间</TableHead>
                    <TableHead className="w-24 px-4 py-3 text-right">
                      操作
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sessions.map((session) => {
                    const isCurrent =
                      currentSessionJTI !== "" &&
                      session.jti === currentSessionJTI
                    return (
                      <TableRow
                        key={session.jti}
                        className="hover:bg-muted/35"
                      >
                        <TableCell className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">
                              {session.username}
                            </span>
                            {isCurrent ? (
                              <Badge
                                variant="secondary"
                                className="rounded-md"
                              >
                                当前
                              </Badge>
                            ) : null}
                          </div>
                        </TableCell>
                        <TableCell className="px-4 py-3 font-mono text-xs text-muted-foreground">
                          {session.ip || "-"}
                        </TableCell>
                        <TableCell className="max-w-[320px] px-4 py-3 text-xs text-muted-foreground">
                          <span
                            className="block truncate"
                            title={redactSensitiveText(session.user_agent)}
                          >
                            {redactSensitiveText(session.user_agent)}
                          </span>
                        </TableCell>
                        <TableCell className="px-4 py-3 text-xs text-muted-foreground">
                          {session.device_info || "-"}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                          {formatDate(session.login_at)}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                          {formatDate(session.last_active_at)}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                          {formatDate(session.expires_at)}
                        </TableCell>
                        <TableCell className="px-4 py-3">
                          <div className="flex items-center justify-end">
                            <Button
                              type="button"
                              variant="destructive"
                              size="sm"
                              onClick={() => setSessionTarget(session)}
                              disabled={isCurrent}
                            >
                              退出
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </ConsoleTableShell>

            {/* API Keys */}
            <ConsoleTableShell
              title="API 令牌"
              description="为自动化任务、CI/CD 或运维脚本生成 Bearer Token。创建后仅返回一次明文 Token。"
              toolbar={
                <div className="flex justify-end">
                  <Button
                    className="rounded-md"
                    onClick={() => {
                      setApiKeyDialogOpen(true)
                      setCreatedToken(null)
                      setNewKeyName("")
                    }}
                  >
                    <Plus data-icon="inline-start" />
                    创建密钥
                  </Button>
                </div>
              }
              state={
                apiKeysLoading ? (
                  <div className="p-16 text-center text-sm text-muted-foreground">
                    加载中...
                  </div>
                ) : apiKeys.length === 0 ? (
                  <div className="p-16 text-center text-sm text-muted-foreground">
                    还没有 API 密钥。创建后可用于自动化访问管理 API。
                  </div>
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
                    <TableHead className="w-20 px-4 py-3 text-right">
                      操作
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {apiKeys.map((item) => (
                    <TableRow key={item.id} className="hover:bg-muted/35">
                      <TableCell className="px-4 py-3 font-mono text-xs text-muted-foreground">
                        {item.id}
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <KeyRound className="size-4 text-muted-foreground" />
                          <span className="font-medium">{item.name}</span>
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
                        <div className="flex items-center justify-end">
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

            {/* Admin Certificate Mode */}
            <Surface
              title="控制台证书"
              description="控制管理控制台 HTTPS 的证书来源。如需管理具体证书，请前往「证书管理」页面。"
            >
              <RadioGroup
                value={adminCertMode}
                onValueChange={setAdminCertMode}
                className="grid gap-3 sm:grid-cols-3"
              >
                <FieldLabel
                  htmlFor={adminCertSelfSignedId}
                  className={optionCardClass(adminCertMode === "self_signed")}
                >
                  <RadioGroupItem
                    id={adminCertSelfSignedId}
                    value="self_signed"
                    className="mt-0.5"
                  />
                  <FieldContent>
                    <span className="text-sm font-medium">自签名证书</span>
                    <FieldDescription>
                      系统自动生成，适合内网使用
                    </FieldDescription>
                  </FieldContent>
                </FieldLabel>
                <FieldLabel
                  htmlFor={adminCertCustomId}
                  className={optionCardClass(adminCertMode === "custom")}
                >
                  <RadioGroupItem
                    id={adminCertCustomId}
                    value="custom"
                    className="mt-0.5"
                  />
                  <FieldContent>
                    <span className="text-sm font-medium">自定义证书</span>
                    <FieldDescription>
                      使用「证书管理」中上传的证书
                    </FieldDescription>
                  </FieldContent>
                </FieldLabel>
                <FieldLabel
                  htmlFor={adminCertNoneId}
                  className={optionCardClass(adminCertMode === "none")}
                >
                  <RadioGroupItem
                    id={adminCertNoneId}
                    value="none"
                    className="mt-0.5"
                  />
                  <FieldContent>
                    <span className="text-sm font-medium">不启用 HTTPS</span>
                    <FieldDescription>
                      仅 HTTP 访问控制台（不推荐）
                    </FieldDescription>
                  </FieldContent>
                </FieldLabel>
              </RadioGroup>
              <Alert className="mt-4">
                <Lock />
                <AlertDescription>
                  管理和上传 TLS 证书请前往{" "}
                  <Link
                    href="/certificates/"
                    className="font-medium text-primary underline underline-offset-2"
                  >
                    证书管理
                  </Link>{" "}
                  页面。
                </AlertDescription>
              </Alert>
            </Surface>

            {/* Save button */}
            <div className="flex justify-end">
              <Button
                onClick={handleSaveConsole}
                disabled={savingConsole}
                className="rounded-md"
              >
                <Save data-icon="inline-start" />
                {savingConsole ? "保存中..." : "保存控制台设置"}
              </Button>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="logs">
          <div className="flex flex-col gap-6">
            <Surface
              title="日志输出配置"
              description="调整后端运行日志级别和输出位置；保存后由后端 logger 立即应用，省略字段会保留原配置。"
              action={
                <Button
                  type="button"
                  size="sm"
                  onClick={handleSaveLogConfig}
                  disabled={savingLogConfig}
                >
                  <Save data-icon="inline-start" />
                  {savingLogConfig ? "保存中..." : "保存日志配置"}
                </Button>
              }
            >
              <FieldGroup>
                <div className="grid gap-4 md:grid-cols-[180px_1fr]">
                  <Field>
                    <FieldLabel htmlFor={logLevelId}>日志级别</FieldLabel>
                    <Select value={logLevel} onValueChange={setLogLevel}>
                      <SelectTrigger id={logLevelId} className="rounded-md">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="DEBUG">DEBUG</SelectItem>
                          <SelectItem value="INFO">INFO</SelectItem>
                          <SelectItem value="WARN">WARN</SelectItem>
                          <SelectItem value="ERROR">ERROR</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                    <FieldDescription>
                      后端支持 DEBUG、INFO、WARN、ERROR。
                    </FieldDescription>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={logFilePathId}>日志文件路径</FieldLabel>
                    <Input
                      id={logFilePathId}
                      value={logFilePath}
                      onChange={(e) => setLogFilePath(e.target.value)}
                      placeholder="留空则不写入文件"
                      className="rounded-md"
                    />
                    <FieldDescription>
                      路径由后端进程所在环境解析；留空表示不配置文件输出。
                    </FieldDescription>
                  </Field>
                </div>

                <Field
                  orientation="horizontal"
                  className="items-center justify-between rounded-lg border bg-muted/35 px-4 py-3"
                >
                  <FieldContent>
                    <FieldLabel htmlFor={logAlsoStdoutId}>
                      同时输出到控制台
                    </FieldLabel>
                    <FieldDescription>
                      启用后运行日志会同时写入标准输出，便于容器或服务管理器采集。
                    </FieldDescription>
                  </FieldContent>
                  <Switch
                    id={logAlsoStdoutId}
                    checked={logAlsoStdout}
                    onCheckedChange={setLogAlsoStdout}
                  />
                </Field>

                <div className="grid gap-3 md:grid-cols-3">
                  <InlineMeta label="当前级别" value={logConfig?.level || "-"} />
                  <InlineMeta
                    label="文件输出"
                    value={
                      <span className="font-mono break-all">
                        {logConfig?.file_path || "未配置"}
                      </span>
                    }
                  />
                  <InlineMeta
                    label="控制台输出"
                    value={logConfig?.also_stdout ? "启用" : "关闭"}
                  />
                </div>
              </FieldGroup>
            </Surface>

            <ConsoleTableShell
              title={logType === "security" ? "安全事件日志" : "访问日志"}
              description={`当前筛选命中 ${logTotal} 条，导出仅包含当前页已加载数据。`}
              toolbar={
                <div className="flex flex-wrap items-center gap-3">
                  <Select
                    value={logType}
                    onValueChange={(v) => {
                      setLogType(v as "security" | "access")
                      setLogPage(1)
                    }}
                  >
                    <SelectTrigger className="w-[160px] rounded-lg">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="security">安全事件</SelectItem>
                        <SelectItem value="access">访问日志</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <div className="relative">
                    <Search className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      value={logSearch}
                      onChange={(e) => {
                        setLogSearch(e.target.value)
                        setLogPage(1)
                      }}
                      placeholder="搜索 IP"
                      className="w-[180px] rounded-lg pl-8"
                    />
                  </div>
                  <div className="ml-auto flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={loadLogs}>
                      <RefreshCcw data-icon="inline-start" /> 刷新
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={exportLogCSV}
                      disabled={
                        (logType === "security" && secEvents.length === 0) ||
                        (logType === "access" && accessLogs.length === 0)
                      }
                    >
                      <Download data-icon="inline-start" /> 导出当前页 CSV
                    </Button>
                  </div>
                </div>
              }
              state={
                logLoading ? (
                  <div className="p-16 text-center text-sm text-muted-foreground">
                    加载中...
                  </div>
                ) : logType === "security" && secEvents.length === 0 ? (
                  <div className="p-16 text-center text-sm text-muted-foreground">
                    暂无安全事件日志
                  </div>
                ) : logType === "access" && accessLogs.length === 0 ? (
                  <div className="p-16 text-center text-sm text-muted-foreground">
                    暂无访问日志
                  </div>
                ) : undefined
              }
              footer={
                !logLoading &&
                ((logType === "security" && secEvents.length > 0) ||
                  (logType === "access" && accessLogs.length > 0)) ? (
                  <Pagination
                    page={logPage}
                    totalPages={logTotalPages}
                    total={logTotal}
                    pageSize={LOG_PAGE_SIZE}
                    onPageChange={setLogPage}
                  />
                ) : null
              }
            >
              {logType === "security" ? (
                <Table>
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground">
                    <TableHead className="px-4 py-3">时间</TableHead>
                    <TableHead className="px-4 py-3">动作</TableHead>
                    <TableHead className="px-4 py-3">类别</TableHead>
                    <TableHead className="px-4 py-3">源 IP</TableHead>
                    <TableHead className="px-4 py-3">Host</TableHead>
                    <TableHead className="px-4 py-3">路径</TableHead>
                    <TableHead className="px-4 py-3">匹配描述</TableHead>
                    <TableHead className="w-20 px-4 py-3 text-right">
                      详情
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {secEvents.map((evt) => (
                    <TableRow
                      key={evt.id}
                      className="transition-colors hover:bg-muted/35"
                    >
                      <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(evt.created_at)}
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <Badge
                          variant={actionBadgeVariant(evt.action)}
                          className="rounded-md text-xs"
                        >
                          {getWAFActionMeta(evt.action).shortLabel}
                        </Badge>
                      </TableCell>
                      <TableCell className="px-4 py-3 text-xs">
                        {evt.category}
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-xs">
                        {evt.client_ip}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-xs text-muted-foreground">
                        {evt.host || "-"}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-muted-foreground">
                        {redactSensitiveText(evt.path)}
                      </TableCell>
                      <TableCell className="max-w-[180px] truncate px-4 py-3 text-xs text-muted-foreground">
                        {redactSensitiveText(evt.match_desc)}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-right">
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={loadingSecurityEventId === evt.id}
                          onClick={() => void openSecurityEventDetail(evt)}
                        >
                          <Eye data-icon="inline-start" />
                          详情
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground">
                    <TableHead className="px-4 py-3">时间</TableHead>
                    <TableHead className="px-4 py-3">方法</TableHead>
                    <TableHead className="px-4 py-3">路径</TableHead>
                    <TableHead className="px-4 py-3">状态码</TableHead>
                    <TableHead className="px-4 py-3">源 IP</TableHead>
                    <TableHead className="px-4 py-3">当时 WAF</TableHead>
                    <TableHead className="px-4 py-3">指纹</TableHead>
                    <TableHead className="px-4 py-3">上游</TableHead>
                    <TableHead className="w-20 px-4 py-3 text-right">
                      详情
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {accessLogs.map((item) => (
                    <TableRow
                      key={item.id}
                      className="transition-colors hover:bg-muted/35"
                    >
                      <TableCell className="px-4 py-3 text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(item.created_at)}
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <Badge
                          variant="outline"
                          className="rounded-md font-mono text-[11px]"
                        >
                          {item.method}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[240px] truncate px-4 py-3 font-mono text-xs text-muted-foreground">
                        {redactSensitiveText(item.path)}
                      </TableCell>
                      <TableCell className="px-4 py-3">
                        <Badge
                          variant={statusBadgeVariant(item.status_code)}
                          className="rounded-md font-mono text-xs"
                        >
                          {item.status_code}
                        </Badge>
                      </TableCell>
                      <TableCell className="px-4 py-3 font-mono text-xs">
                        {item.client_ip}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-xs text-muted-foreground">
                        {item.waf_action
                          ? getWAFActionMeta(item.waf_action).shortLabel
                          : "-"}
                      </TableCell>
                      <TableCell
                        className="max-w-[180px] truncate px-4 py-3 font-mono text-[11px] text-muted-foreground"
                        title={[
                          item.http_protocol,
                          item.tls_version,
                          item.tls_ja3_hash,
                          item.tls_ja4,
                        ]
                          .filter(Boolean)
                          .join(" / ")}
                      >
                        {[
                          item.http_protocol,
                          item.tls_version,
                          item.tls_ja3_hash || item.tls_ja4,
                        ]
                          .filter(Boolean)
                          .join(" / ") || "-"}
                      </TableCell>
                      <TableCell className="max-w-[160px] truncate px-4 py-3 font-mono text-xs text-muted-foreground">
                        {item.upstream || "-"}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-right">
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={loadingAccessLogId === item.id}
                          onClick={() => void openAccessLogDetail(item)}
                        >
                          <Eye data-icon="inline-start" />
                          详情
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </ConsoleTableShell>
          </div>
        </TabsContent>
        <TabsContent value="runtime">
          <div className="flex flex-col gap-6">
            <Surface
              title="启动与存储配置"
              description="展示当前进程启动时读取的 MY_OPENWAF_* 配置；数据库、Redis、监听地址等变更需要修改部署环境并重启后生效。"
              action={
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleReloadRuntime}
                  disabled={reloadingRuntime}
                >
                  <RefreshCcw data-icon="inline-start" />
                  {reloadingRuntime ? "重载中..." : "重载运行快照"}
                </Button>
              }
            >
              {runtimeReloadDetails ? (
                <Alert className="mb-4 gap-3">
                  <RefreshCcw />
                  <AlertTitle>运行快照重载响应</AlertTitle>
                  <AlertDescription>
                    后端已返回 `/api/v1/reload` 响应体；请核对 status 或
                    error 字段。
                  </AlertDescription>
                  <CopyableBlock
                    label="reload 响应体"
                    value={JSON.stringify(runtimeReloadDetails, null, 2)}
                    redact
                    defaultOpen={false}
                  />
                </Alert>
              ) : null}

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {[
                  ["配置来源", runtimeConfig?.source || "environment"],
                  ["可在线编辑", runtimeConfig?.editable ? "是" : "否"],
                  ["需要重启", runtimeConfig?.restart_required ? "是" : "否"],
                  ["数据库驱动", runtimeConfig?.db_driver || "-"],
                  ["数据目录", runtimeConfig?.data_dir || "-"],
                  ["Admin 监听", runtimeConfig?.admin_bind || "-"],
                  [
                    "Redis 状态",
                    runtimeConfig?.redis_enabled ? "已启用" : "未启用",
                  ],
                  ["Redis DB", String(runtimeConfig?.redis_db ?? 0)],
                  [
                    "CVE Feed",
                    runtimeConfig?.cve_feed_enabled ? "启用" : "关闭",
                  ],
                  ["Drop 策略", runtimeConfig?.drop_enabled ? "启用" : "关闭"],
                ].map(([label, value]) => (
                  <div
                    key={label}
                    className="rounded-lg border bg-muted/35 p-3"
                  >
                    <div className="text-xs text-muted-foreground">{label}</div>
                    <div className="mt-1 font-mono text-sm break-all">
                      {value}
                    </div>
                  </div>
                ))}
              </div>
            </Surface>

            <Surface
              title="Redis 配置"
              description="Redis 客户端在进程启动时创建；保存后配置写入专用端点，重启进程后生效。密码不会从后端回显。"
              action={
                <Button
                  type="button"
                  size="sm"
                  onClick={handleSaveRedis}
                  disabled={savingRedis}
                >
                  <Save data-icon="inline-start" />
                  {savingRedis ? "保存中..." : "保存 Redis"}
                </Button>
              }
            >
              <FieldGroup>
                <Field
                  orientation="horizontal"
                  className="items-center justify-between rounded-lg border bg-muted/35 px-4 py-3"
                >
                  <FieldContent>
                    <FieldLabel htmlFor={redisEnabledId}>启用 Redis</FieldLabel>
                    <FieldDescription>
                      启用后必须填写带端口的 Redis 地址。
                    </FieldDescription>
                  </FieldContent>
                  <Switch
                    id={redisEnabledId}
                    checked={redisEnabled}
                    onCheckedChange={setRedisEnabled}
                  />
                </Field>

                <div className="grid gap-4 md:grid-cols-2">
                  <Field data-invalid={redisEnabled && redisAddr.trim() === ""}>
                    <FieldLabel htmlFor={redisAddrId}>Redis 地址</FieldLabel>
                    <Input
                      id={redisAddrId}
                      value={redisAddr}
                      onChange={(e) => setRedisAddr(e.target.value)}
                      placeholder="127.0.0.1:6379"
                      aria-invalid={redisEnabled && redisAddr.trim() === ""}
                      className="rounded-md"
                    />
                    <FieldDescription>
                      后端要求格式可被解析为 host:port。
                    </FieldDescription>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={redisDbId}>Redis DB</FieldLabel>
                    <Input
                      id={redisDbId}
                      type="number"
                      min={0}
                      value={redisDB}
                      onChange={(e) => setRedisDB(Number(e.target.value))}
                      className="rounded-md"
                    />
                    <FieldDescription>
                      后端要求 Redis DB 大于或等于 0。
                    </FieldDescription>
                  </Field>
                </div>

                <Field>
                  <FieldLabel htmlFor={redisPasswordId}>Redis 密码</FieldLabel>
                  <Input
                    id={redisPasswordId}
                    type="password"
                    value={redisPassword}
                    onChange={(e) => setRedisPassword(e.target.value)}
                    placeholder={
                      redisConfig?.password_set
                        ? "已设置；留空保持不变"
                        : "未设置；留空不写入密码"
                    }
                    className="rounded-md"
                  />
                  <FieldDescription>
                    后端不会回显密码；只有输入非空值时才更新密码。
                  </FieldDescription>
                </Field>

                <div className="grid gap-3 md:grid-cols-3">
                  <InlineMeta
                    label="当前来源"
                    value={redisConfig?.source || "database"}
                  />
                  <InlineMeta
                    label="密码状态"
                    value={redisConfig?.password_set ? "已设置" : "未设置"}
                  />
                  <InlineMeta
                    label="生效方式"
                    value={
                      redisConfig?.restart_required
                        ? "需要重启进程"
                        : "无需重启"
                    }
                  />
                </div>
              </FieldGroup>
            </Surface>

            <ConsoleTableShell
              title="系统设置明细"
              description="列出 /api/v1/settings 返回的当前系统设置；删除会调用后端设置删除接口，受专用端点管理的键由后端拒绝。"
              state={
                sortedSystemSettings.length === 0 ? (
                  <div className="p-16 text-center text-sm text-muted-foreground">
                    暂无系统设置
                  </div>
                ) : undefined
              }
            >
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs font-medium text-muted-foreground">
                    <TableHead className="w-20 px-4 py-3">ID</TableHead>
                    <TableHead className="min-w-[220px] px-4 py-3">
                      键名
                    </TableHead>
                    <TableHead className="min-w-[320px] px-4 py-3">
                      当前值
                    </TableHead>
                    <TableHead className="w-20 px-4 py-3 text-right">
                      操作
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedSystemSettings.map((item) => {
                    const displayValue = redactSensitiveText(item.value)
                    return (
                      <TableRow key={item.key} className="hover:bg-muted/35">
                        <TableCell className="px-4 py-3 font-mono text-xs text-muted-foreground">
                          {item.id}
                        </TableCell>
                        <TableCell className="px-4 py-3">
                          <code className="rounded-md bg-muted px-2 py-1 font-mono text-xs text-foreground">
                            {item.key}
                          </code>
                        </TableCell>
                        <TableCell className="max-w-[520px] px-4 py-3">
                          <code
                            className="block truncate rounded-md bg-muted px-2 py-1 font-mono text-xs text-muted-foreground"
                            title={displayValue}
                          >
                            {displayValue}
                          </code>
                        </TableCell>
                        <TableCell className="px-4 py-3">
                          <div className="flex items-center justify-end">
                            <Button
                              type="button"
                              variant="destructive"
                              size="icon-sm"
                              disabled={systemSettingDeleting}
                              onClick={() => setSystemSettingDeleteTarget(item)}
                              aria-label="删除系统设置"
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
            </ConsoleTableShell>

            <Surface
              title="连接字符串与路径"
              description="DSN 会由后端脱敏后展示；Redis 密码等密钥不从接口返回。生产环境建议通过环境变量、systemd、Docker Compose 或 Kubernetes Secret 管理。"
            >
              <div className="flex flex-col gap-3">
                <InlineMeta
                  label="MY_OPENWAF_DSN / MY_OPENWAF_DB"
                  value={
                    <span className="font-mono break-all">
                      {runtimeConfig?.db_dsn || "-"}
                    </span>
                  }
                />
                <InlineMeta
                  label="MY_OPENWAF_LOG_DSN / MY_OPENWAF_LOG_DB"
                  value={
                    <span className="font-mono break-all">
                      {runtimeConfig?.log_db_dsn || "-"}
                    </span>
                  }
                />
                <InlineMeta
                  label="MY_OPENWAF_REDIS_ADDR"
                  value={
                    <span className="font-mono break-all">
                      {runtimeConfig?.redis_addr || "未配置"}
                    </span>
                  }
                />
                <InlineMeta
                  label="MY_OPENWAF_ADMIN_STATIC_DIR"
                  value={
                    <span className="font-mono break-all">
                      {runtimeConfig?.admin_static_dir || "embedded"}
                    </span>
                  }
                />
                <InlineMeta
                  label="MY_OPENWAF_GEOIP_DB"
                  value={
                    <span className="font-mono break-all">
                      {runtimeConfig?.geoip_db_path || "未配置"}
                    </span>
                  }
                />
                <InlineMeta
                  label="MY_OPENWAF_CVE_FEED_INTERVAL"
                  value={
                    <span className="font-mono break-all">
                      {runtimeConfig?.cve_feed_interval || "-"}
                    </span>
                  }
                />
              </div>
              <Alert className="mt-4">
                <AlertDescription>
                  这些是进程级配置，不适合直接写入业务数据库后热更新。后续如果要支持配置文件写回，应单独引入受控的
                  YAML 配置、权限校验、重启提示和回滚机制。
                </AlertDescription>
              </Alert>
            </Surface>
          </div>
        </TabsContent>
      </Tabs>

      <Dialog
        open={!!selectedSecurityEvent}
        onOpenChange={(open) => {
          if (!open) {
            setSelectedSecurityEvent(null)
            setRequestTrace(null)
          }
        }}
      >
        <DialogContent className="max-h-[86vh] max-w-3xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>安全事件详情</DialogTitle>
            <DialogDescription>
              系统日志页打开的安全事件详情；请求字段按脱敏策略展示。
            </DialogDescription>
          </DialogHeader>
          {selectedSecurityEvent && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                [
                  "Request ID",
                  selectedSecurityEvent.request_id || "-",
                  true,
                  true,
                ],
                [
                  "时间",
                  formatDate(selectedSecurityEvent.created_at),
                  false,
                  false,
                ],
                [
                  "客户端 IP",
                  selectedSecurityEvent.client_ip || "-",
                  true,
                  true,
                ],
                ["Host", selectedSecurityEvent.host || "-", true, true],
                ["方法", selectedSecurityEvent.method || "-", true, true],
                [
                  "阶段",
                  phaseLabels[selectedSecurityEvent.phase] ??
                    selectedSecurityEvent.phase ??
                    "-",
                  false,
                  false,
                ],
                [
                  "类别",
                  categoryLabels[selectedSecurityEvent.category] ??
                    selectedSecurityEvent.category ??
                    "-",
                  false,
                  false,
                ],
                [
                  "历史规则",
                  selectedSecurityEvent.rule_id_str ||
                    String(selectedSecurityEvent.rule_id || "-"),
                  true,
                  true,
                ],
                [
                  "状态码",
                  selectedSecurityEvent.status_code
                    ? String(selectedSecurityEvent.status_code)
                    : "-",
                  true,
                  true,
                ],
                [
                  "TLS 版本",
                  selectedSecurityEvent.tls_version || "-",
                  true,
                  true,
                ],
                [
                  "TLS SNI",
                  selectedSecurityEvent.tls_sni || "-",
                  true,
                  true,
                ],
                [
                  "TLS ALPN",
                  selectedSecurityEvent.tls_alpn || "-",
                  true,
                  true,
                ],
                [
                  "JA3 Hash",
                  selectedSecurityEvent.tls_ja3_hash || "-",
                  true,
                  true,
                ],
                ["JA4", selectedSecurityEvent.tls_ja4 || "-", true, true],
                [
                  "Header Order",
                  selectedSecurityEvent.header_order || "-",
                  true,
                  true,
                ],
                [
                  "请求大小",
                  formatBytes(selectedSecurityEvent.request_size ?? 0),
                  true,
                  false,
                ],
                [
                  "国家",
                  selectedSecurityEvent.geo_country || "-",
                  false,
                  false,
                ],
                [
                  "城市",
                  selectedSecurityEvent.geo_city || "-",
                  false,
                  false,
                ],
              ].map(([label, value, mono, copyable]) => (
                <DetailField
                  key={String(label)}
                  label={String(label)}
                  value={String(value)}
                  mono={Boolean(mono)}
                  copyText={copyable ? String(value) : undefined}
                />
              ))}
              <DetailField
                label="动作"
                value={<WAFActionBadge action={selectedSecurityEvent.action} />}
              />
              <RequestTracePanel
                requestId={selectedSecurityEvent.request_id}
                trace={requestTrace}
                loading={traceLoading}
                onLoad={() =>
                  loadRequestTrace(selectedSecurityEvent.request_id)
                }
              />
              <CopyableBlock
                label="路径"
                value={selectedSecurityEvent.path || "-"}
                as="code"
                className="sm:col-span-2"
                redact
              />
              <CopyableBlock
                label="匹配描述"
                value={selectedSecurityEvent.match_desc || "-"}
                className="sm:col-span-2"
                redact
              />
              <CopyableBlock
                label="查询参数"
                value={selectedSecurityEvent.query_string || "-"}
                as="code"
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="JA3"
                value={selectedSecurityEvent.tls_ja3 || "-"}
                as="code"
                className="sm:col-span-2"
                defaultOpen={false}
              />
              <CopyableBlock
                label="User-Agent"
                value={selectedSecurityEvent.user_agent || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="请求头"
                value={selectedSecurityEvent.request_headers || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label={
                  selectedSecurityEvent.request_body_truncated
                    ? "请求体预览（已截断）"
                    : "请求体预览"
                }
                value={selectedSecurityEvent.request_body_preview || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog
        open={!!selectedAccessLog}
        onOpenChange={(open) => {
          if (!open) {
            setSelectedAccessLog(null)
            setRequestTrace(null)
          }
        }}
      >
        <DialogContent className="max-h-[86vh] max-w-3xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>访问日志详情</DialogTitle>
            <DialogDescription>
              系统日志页打开的访问日志详情；请求头、响应头和请求体预览按脱敏策略展示。
            </DialogDescription>
          </DialogHeader>
          {selectedAccessLog && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["Request ID", selectedAccessLog.request_id || "-", true, true],
                ["时间", formatDate(selectedAccessLog.created_at), false, false],
                ["客户端 IP", selectedAccessLog.client_ip || "-", true, true],
                ["Host", selectedAccessLog.host || "-", true, true],
                ["方法", selectedAccessLog.method || "-", true, true],
                ["状态码", String(selectedAccessLog.status_code), true, true],
                ["缓存状态", selectedAccessLog.cache_state || "-", true, true],
                ["上游服务器", selectedAccessLog.upstream || "-", true, true],
                [
                  "上游耗时",
                  formatLatency(selectedAccessLog.upstream_latency_ms),
                  true,
                  false,
                ],
                [
                  "响应大小",
                  formatBytes(selectedAccessLog.response_size),
                  true,
                  false,
                ],
                [
                  "请求大小",
                  formatBytes(selectedAccessLog.request_size ?? 0),
                  true,
                  false,
                ],
                [
                  "HTTP 协议",
                  selectedAccessLog.http_protocol || "-",
                  true,
                  true,
                ],
                ["TLS 版本", selectedAccessLog.tls_version || "-", true, true],
                ["TLS SNI", selectedAccessLog.tls_sni || "-", true, true],
                ["TLS ALPN", selectedAccessLog.tls_alpn || "-", true, true],
                [
                  "JA3 Hash",
                  selectedAccessLog.tls_ja3_hash || "-",
                  true,
                  true,
                ],
                ["JA4", selectedAccessLog.tls_ja4 || "-", true, true],
                ["站点 ID", String(selectedAccessLog.site_id), true, true],
              ].map(([label, value, mono, copyable]) => (
                <DetailField
                  key={String(label)}
                  label={String(label)}
                  value={String(value)}
                  mono={Boolean(mono)}
                  copyText={copyable ? String(value) : undefined}
                />
              ))}
              <DetailField
                label="当时 WAF 动作"
                value={<WAFActionBadge action={selectedAccessLog.waf_action} />}
              />
              <RequestTracePanel
                requestId={selectedAccessLog.request_id}
                trace={requestTrace}
                loading={traceLoading}
                onLoad={() => loadRequestTrace(selectedAccessLog.request_id)}
              />
              <CopyableBlock
                label="路径"
                value={selectedAccessLog.path || "-"}
                as="code"
                className="sm:col-span-2"
                redact
              />
              <CopyableBlock
                label="查询参数"
                value={selectedAccessLog.query_string || "-"}
                as="code"
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="JA3"
                value={selectedAccessLog.tls_ja3 || "-"}
                as="code"
                className="sm:col-span-2"
                defaultOpen={false}
              />
              <CopyableBlock
                label="Header Order"
                value={selectedAccessLog.header_order || "-"}
                as="code"
                className="sm:col-span-2"
                defaultOpen={false}
              />
              <CopyableBlock
                label="User-Agent"
                value={selectedAccessLog.user_agent || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="请求头"
                value={selectedAccessLog.request_headers || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label={
                  selectedAccessLog.request_body_truncated
                    ? "请求体预览（已截断）"
                    : "请求体预览"
                }
                value={selectedAccessLog.request_body_preview || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <CopyableBlock
                label="响应头"
                value={selectedAccessLog.response_headers || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Create API Key Dialog */}
      <Dialog open={apiKeyDialogOpen} onOpenChange={setApiKeyDialogOpen}>
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
              <div className="flex gap-2 rounded-lg border bg-muted/35 p-3">
                <code className="flex-1 text-xs break-all text-muted-foreground">
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
                  aria-label="复制 API Token"
                >
                  <Copy data-icon="inline-start" />
                </Button>
              </div>
            </div>
          ) : (
            <Field>
              <FieldLabel htmlFor={apiKeyNameId}>密钥名称</FieldLabel>
              <Input
                id={apiKeyNameId}
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="例如：CI Deploy / Terraform / Alert Sync"
                className="rounded-lg"
                onKeyDown={(e) => e.key === "Enter" && handleCreateKey()}
              />
            </Field>
          )}
          <DialogFooter>
            {createdToken ? (
              <Button onClick={() => setApiKeyDialogOpen(false)}>完成</Button>
            ) : (
              <>
                <Button
                  variant="outline"
                  onClick={() => setApiKeyDialogOpen(false)}
                >
                  取消
                </Button>
                <Button onClick={handleCreateKey} disabled={creating}>
                  {creating ? "创建中..." : "创建"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete API Key Dialog */}
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
                handleDeleteKey()
              }}
            >
              {deleting ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!sessionTarget}
        onOpenChange={(open) => !open && setSessionTarget(null)}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认强制退出会话</AlertDialogTitle>
            <AlertDialogDescription>
              该会话会立即从管理控制台失效，对应用户需要重新登录。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Alert variant="destructive">
            <AlertDescription>
              目标用户：{sessionTarget?.username || "-"}；IP：
              {sessionTarget?.ip || "-"}
            </AlertDescription>
          </Alert>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={sessionDeleting}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={sessionDeleting}
              onClick={handleForceLogoutSession}
            >
              {sessionDeleting ? "退出中..." : "强制退出"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!systemSettingDeleteTarget}
        onOpenChange={(open) => {
          if (!open && !systemSettingDeleting) {
            setSystemSettingDeleteTarget(null)
          }
        }}
      >
        <AlertDialogContent className="max-w-md rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除系统设置</AlertDialogTitle>
            <AlertDialogDescription>
              删除后该键会从通用系统设置中移除，并触发后端重新加载运行快照。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Alert variant="destructive">
            <AlertDescription>
              目标键：{systemSettingDeleteTarget?.key || "-"}
            </AlertDescription>
          </Alert>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={systemSettingDeleting}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={systemSettingDeleting}
              onClick={(event) => {
                event.preventDefault()
                handleDeleteSystemSetting()
              }}
            >
              {systemSettingDeleting ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
