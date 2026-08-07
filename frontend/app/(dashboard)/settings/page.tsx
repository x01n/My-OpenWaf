"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import { toast } from "sonner"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  IconFileText,
  IconNetwork,
  IconShieldLock,
  IconDatabase,
} from "@tabler/icons-react"
import {
  useLogConfig,
  useLogConfigUpdate,
  useNetworkConfig,
  useNetworkConfigUpdate,
  useRedisConfig,
  useRedisConfigUpdate,
  useTLSConfig,
  useTLSConfigUpdate,
} from "@/hooks/use-api"
import type {
  LogConfigUpdate,
  NetworkConfig,
  NetworkConfigUpdate,
  RedisConfigUpdate,
  TLSConfigUpdate,
} from "@/lib/types"

const networkFields = [
  "ipv6_enabled",
  "http2_enabled",
  "http3_enabled",
  "http3_bind",
  "default_alpn",
  "default_network",
] as const
const tlsFields = [
  "min_version",
  "max_version",
  "cipher_suites",
  "default_alpn",
  "curve_preferences",
  "prefer_server_cipher_suites",
  "session_tickets_enabled",
  "self_signed_on_ip",
] as const
const logFields = ["level", "file_path", "also_stdout"] as const

function pickChangedFields<T extends object>(
  fields: readonly (keyof T)[],
  draft: Partial<T>
): Partial<T> {
  return fields.reduce<Partial<T>>((payload, field) => {
    if (draft[field] !== undefined) payload[field] = draft[field]
    return payload
  }, {})
}

export default function SettingsPage() {
  const { t } = useTranslation()
  const {
    data: networkConfig,
    isLoading: networkLoading,
    error: networkError,
  } = useNetworkConfig()
  const {
    data: tlsConfig,
    isLoading: tlsLoading,
    error: tlsError,
  } = useTLSConfig()
  const {
    data: logConfig,
    isLoading: logLoading,
    error: logError,
  } = useLogConfig()
  const networkUpdate = useNetworkConfigUpdate()
  const tlsUpdate = useTLSConfigUpdate()
  const logUpdate = useLogConfigUpdate()
  const [localNetwork, setLocalNetwork] = useState<NetworkConfigUpdate>({})
  const [localTLS, setLocalTLS] = useState<TLSConfigUpdate>({})
  const [localLog, setLocalLog] = useState<LogConfigUpdate>({})

  const networkValue = <K extends keyof NetworkConfig>(key: K) =>
    localNetwork[key] ?? networkConfig?.[key]
  const tlsValue = (key: keyof TLSConfigUpdate) =>
    localTLS[key] ?? tlsConfig?.[key]
  const logValue = (key: keyof LogConfigUpdate) =>
    localLog[key] ?? logConfig?.[key]
  const toggleNetwork = (
    key: "ipv6_enabled" | "http2_enabled" | "http3_enabled"
  ) => setLocalNetwork((prev) => ({ ...prev, [key]: !networkValue(key) }))
  const toggleTLS = (
    key:
      | "prefer_server_cipher_suites"
      | "session_tickets_enabled"
      | "self_signed_on_ip"
  ) => setLocalTLS((prev) => ({ ...prev, [key]: !tlsValue(key) }))

  const saveNetwork = async () => {
    const payload = pickChangedFields<NetworkConfig>(networkFields, localNetwork)
    if (!Object.keys(payload).length) return
    try {
      await networkUpdate.execute(payload)
      setLocalNetwork({})
      toast.success(t("settings.networkSaveSuccess"))
    } catch {
      toast.error(t("settings.networkSaveFailed"))
    }
  }
  const saveTLS = async () => {
    const payload = pickChangedFields<TLSConfigUpdate>(tlsFields, localTLS)
    if (!Object.keys(payload).length) return
    try {
      await tlsUpdate.execute(payload)
      setLocalTLS({})
      toast.success(t("settings.tlsSaveSuccess"))
    } catch {
      toast.error(t("settings.tlsSaveFailed"))
    }
  }
  const saveLog = async () => {
    const payload = pickChangedFields<LogConfigUpdate>(logFields, localLog)
    if (!Object.keys(payload).length) return
    try {
      await logUpdate.execute(payload)
      setLocalLog({})
      toast.success(t("settings.logSaveSuccess"))
    } catch {
      toast.error(t("settings.logSaveFailed"))
    }
  }

  const loading = networkLoading || tlsLoading || logLoading
  const error = networkError || tlsError || logError
  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        {[1, 2, 3, 4].map((item) => (
          <Skeleton key={item} className="h-64 w-full" />
        ))}
      </div>
    )
  }
  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title={t("settings.title")}
          description={t("settings.description")}
        />
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {(error as Error).message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("settings.title")}
        description={t("settings.description")}
      />
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconNetwork className="h-5 w-5 text-primary" />
            {t("settings.network")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            {(
              [
                [
                  "ipv6_enabled",
                  "settings.listenIpv6",
                  "settings.listenIpv6Desc",
                ],
                [
                  "http2_enabled",
                  "settings.enableHttp2",
                  "settings.enableHttp2Desc",
                ],
                [
                  "http3_enabled",
                  "settings.http3.enableLabel",
                  "settings.http3.description",
                ],
              ] as const
            ).map(([key, label, desc]) => (
              <div
                key={key}
                className="flex items-start gap-3 rounded-lg border p-3"
              >
                <Switch
                  id={key}
                  checked={Boolean(networkValue(key))}
                  onCheckedChange={() => toggleNetwork(key)}
                />
                <div className="space-y-0.5">
                  <Label htmlFor={key} className="cursor-pointer text-sm">
                    {t(label)}
                  </Label>
                  <p className="text-xs text-muted-foreground">{t(desc)}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-2">
              <Label>{t("settings.defaultNetwork")}</Label>
              <Select
                value={networkValue("default_network") ?? "tcp"}
                onValueChange={(value: NetworkConfig["default_network"]) =>
                  setLocalNetwork((prev) => ({
                    ...prev,
                    default_network: value,
                  }))
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">tcp</SelectItem>
                  <SelectItem value="tcp4">tcp4</SelectItem>
                  <SelectItem value="tcp6">tcp6</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("settings.defaultAlpn")}</Label>
              <Input
                value={networkValue("default_alpn") ?? ""}
                onChange={(event) =>
                  setLocalNetwork((prev) => ({
                    ...prev,
                    default_alpn: event.target.value,
                  }))
                }
                placeholder="h3,h2,http/1.1"
              />
            </div>
            <div className="space-y-2">
              <Label>{t("settings.http3.bindLabel")}</Label>
              <Input
                value={networkValue("http3_bind") ?? ""}
                onChange={(event) =>
                  setLocalNetwork((prev) => ({
                    ...prev,
                    http3_bind: event.target.value,
                  }))
                }
                placeholder={t("settings.http3.bindPlaceholder")}
                disabled={!networkValue("http3_enabled")}
              />
            </div>
          </div>
          <div className="flex justify-end">
            <Button onClick={saveNetwork} disabled={networkUpdate.loading}>
              {networkUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconShieldLock className="h-5 w-5 text-primary" />
            {t("settings.sslCompliance")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            {(["min_version", "max_version"] as const).map((key) => (
              <div key={key} className="space-y-2">
                <Label>
                  {t(
                    key === "min_version"
                      ? "settings.tlsMinVersion"
                      : "settings.tlsMaxVersion"
                  )}
                </Label>
                <Select
                  value={String(tlsValue(key) ?? "TLS13")}
                  onValueChange={(value) =>
                    setLocalTLS((prev) => ({ ...prev, [key]: value }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["TLS10", "TLS11", "TLS12", "TLS13"].map((version) => (
                      <SelectItem key={version} value={version}>
                        {version}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t("settings.cipherSuites")}</Label>
              <Input
                value={String(tlsValue("cipher_suites") ?? "")}
                onChange={(event) =>
                  setLocalTLS((prev) => ({
                    ...prev,
                    cipher_suites: event.target.value,
                  }))
                }
                placeholder={t("settings.tlsCipherPlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("settings.tlsDefaultAlpn")}</Label>
              <Input
                value={String(tlsValue("default_alpn") ?? "")}
                onChange={(event) =>
                  setLocalTLS((prev) => ({
                    ...prev,
                    default_alpn: event.target.value,
                  }))
                }
                placeholder="h2,h3,http/1.1"
              />
            </div>
            <div className="space-y-2">
              <Label>{t("settings.curvePreferences")}</Label>
              <Input
                value={String(tlsValue("curve_preferences") ?? "")}
                onChange={(event) =>
                  setLocalTLS((prev) => ({
                    ...prev,
                    curve_preferences: event.target.value,
                  }))
                }
                placeholder="X25519,CurveP256,CurveP384"
              />
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {(
              [
                [
                  "prefer_server_cipher_suites",
                  "settings.preferServerCipherSuites",
                ],
                ["session_tickets_enabled", "settings.sessionTickets"],
                ["self_signed_on_ip", "settings.selfSignedOnIp"],
              ] as const
            ).map(([key, label]) => (
              <div
                key={key}
                className="flex items-center gap-3 rounded-lg border p-3"
              >
                <Switch
                  id={key}
                  checked={Boolean(tlsValue(key))}
                  onCheckedChange={() => toggleTLS(key)}
                />
                <Label htmlFor={key} className="cursor-pointer text-sm">
                  {t(label)}
                </Label>
              </div>
            ))}
          </div>
          <div className="flex justify-end">
            <Button onClick={saveTLS} disabled={tlsUpdate.loading}>
              {tlsUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconFileText className="h-5 w-5 text-primary" />
            {t("settings.logging")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t("settings.logLevel")}</Label>
              <Select
                value={String(logValue("level") ?? "INFO")}
                onValueChange={(value) =>
                  setLocalLog((prev) => ({ ...prev, level: value }))
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {["DEBUG", "INFO", "WARN", "ERROR"].map((level) => (
                    <SelectItem key={level} value={level}>
                      {level}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("settings.logFilePath")}</Label>
              <Input
                value={String(logValue("file_path") ?? "")}
                onChange={(event) =>
                  setLocalLog((prev) => ({
                    ...prev,
                    file_path: event.target.value,
                  }))
                }
              />
            </div>
          </div>
          <div className="flex items-center gap-3 rounded-lg border p-3">
            <Switch
              id="also_stdout"
              checked={Boolean(logValue("also_stdout"))}
              onCheckedChange={() =>
                setLocalLog((prev) => ({
                  ...prev,
                  also_stdout: !logValue("also_stdout"),
                }))
              }
            />
            <Label htmlFor="also_stdout" className="cursor-pointer text-sm">
              {t("settings.logAlsoStdout")}
            </Label>
          </div>
          <div className="flex justify-end">
            <Button onClick={saveLog} disabled={logUpdate.loading}>
              {logUpdate.loading ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </CardContent>
      </Card>
      <RedisConfigCard />
    </div>
  )
}

function RedisConfigCard() {
  const { t } = useTranslation()
  const { data: redisConfig, isLoading, error } = useRedisConfig()
  const redisUpdate = useRedisConfigUpdate()
  const [draft, setDraft] = useState<Partial<RedisConfigUpdate>>({})
  const [passwordTouched, setPasswordTouched] = useState(false)

  const enabled = draft.enabled ?? redisConfig?.enabled ?? false
  const addr = draft.redis_addr ?? redisConfig?.redis_addr ?? ""
  const password = passwordTouched ? (draft.redis_password ?? "") : ""
  const db = String(draft.redis_db ?? redisConfig?.redis_db ?? 0)

  const handleSave = async () => {
    const payload: RedisConfigUpdate = {}
    if (draft.enabled !== undefined) {
      payload.enabled = draft.enabled
    }
    if (draft.redis_addr !== undefined) {
      payload.redis_addr = draft.redis_addr
    }
    if (draft.redis_db !== undefined) {
      payload.redis_db = draft.redis_db
    }
    if (passwordTouched) {
      payload.redis_password = password
    }
    if (Object.keys(payload).length === 0) {
      return
    }
    try {
      await redisUpdate.execute(payload)
      setDraft({})
      setPasswordTouched(false)
      toast.success(t("settings.redisSaveSuccess"))
    } catch {
      toast.error(t("settings.redisSaveFailed"))
    }
  }

  if (isLoading) {
    return <Skeleton className="h-48 w-full" />
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
        <AlertDescription>
          {(error as Error)?.message || t("error.unexpectedError")}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <IconDatabase className="h-5 w-5 text-primary" />
          {t("settings.redis")}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3 rounded-lg border p-3">
          <Switch
            id="redis_enabled"
            checked={enabled}
            onCheckedChange={(checked) =>
              setDraft((prev) => ({ ...prev, enabled: checked }))
            }
          />
          <div className="space-y-0.5">
            <Label htmlFor="redis_enabled" className="cursor-pointer text-sm">
              {t("settings.redisEnabled")}
            </Label>
            <p className="text-xs text-muted-foreground">
              {t("settings.redisEnabledDesc")}
            </p>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>{t("settings.redisAddr")}</Label>
            <Input
              value={addr}
              onChange={(e) =>
                setDraft((prev) => ({ ...prev, redis_addr: e.target.value }))
              }
              placeholder="127.0.0.1:6379"
            />
            <p className="text-xs text-muted-foreground">
              {t("settings.redisAddrDesc")}
            </p>
          </div>
          <div className="space-y-2">
            <Label>{t("settings.redisPassword")}</Label>
            <Input
              type="password"
              value={password}
              onChange={(e) => {
                setPasswordTouched(true)
                setDraft((prev) => ({
                  ...prev,
                  redis_password: e.target.value,
                }))
              }}
              placeholder={t("settings.redisPasswordPlaceholder")}
            />
            {redisConfig?.password_set && !passwordTouched && (
              <p className="text-xs text-muted-foreground">
                {t("settings.redisPasswordSet")}
              </p>
            )}
          </div>
        </div>
        <div className="space-y-2">
          <Label>{t("settings.redisDb")}</Label>
          <Input
            type="number"
            min={0}
            max={15}
            value={db}
            onChange={(e) =>
              setDraft((prev) => ({
                ...prev,
                redis_db: parseInt(e.target.value, 10) || 0,
              }))
            }
            className="w-32"
          />
          <p className="text-xs text-muted-foreground">
            {t("settings.redisDbDesc")}
          </p>
        </div>
        <div className="flex justify-end">
          <Button onClick={handleSave} disabled={redisUpdate.loading}>
            {redisUpdate.loading ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
