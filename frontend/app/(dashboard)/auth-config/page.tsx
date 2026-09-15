"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { toast } from "sonner"
import {
  IconUser,
  IconRefresh,
  IconShield,
  IconLogout,
} from "@tabler/icons-react"
import {
  useProtectionSettings,
  useProtectionSettingsUpdate,
  useAdminSessions,
  useForceLogout,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import type { ProtectionSettings } from "@/lib/types"

type BasicAuthSettings = Pick<
  ProtectionSettings,
  "basic_auth_enabled" | "basic_auth_username" | "basic_auth_password"
>

export default function AuthConfigPage() {
  const { t } = useTranslation()
  const { user, loading: authLoading } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const canForceLogout = user?.role === "admin"
  const { data: settings, isLoading, error } = useProtectionSettings()
  const updateSettings = useProtectionSettingsUpdate()

  const [localSettings, setLocalSettings] = useState<
    Partial<Pick<BasicAuthSettings, "basic_auth_enabled">>
  >({})
  const [username, setUsername] = useState<string | null>(null)
  const [password, setPassword] = useState("")
  const currentUsername = username ?? settings?.basic_auth_username ?? ""

  const handleToggle = () => {
    if (!canManage) return
    setLocalSettings((prev) => ({
      ...prev,
      basic_auth_enabled: !(
        prev.basic_auth_enabled ??
        settings?.basic_auth_enabled ??
        false
      ),
    }))
  }

  const handleSave = async () => {
    if (!canManage) return
    try {
      const payload: Partial<BasicAuthSettings> = { ...localSettings }
      if (username !== null) payload.basic_auth_username = username
      if (password) payload.basic_auth_password = password
      await updateSettings.execute(payload)
      toast.success(t("authConfig.saveSuccess"))
      setPassword("")
      setLocalSettings({})
    } catch {
      toast.error(t("authConfig.saveFailed"))
    }
  }

  if (isLoading) {
    return (
      <div className="min-w-0 space-y-4">
        <div>
          <Skeleton className="h-8 w-48" />
          <Skeleton className="mt-1 h-4 w-64" />
        </div>
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  if (error || !settings) {
    return (
      <div className="space-y-4">
        <PageHeader
          title={t("authConfig.title")}
          description={t("authConfig.description")}
        />
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {(error as Error)?.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  return (
    <div className="min-w-0 space-y-4">
      <PageHeader
        title={t("authConfig.title")}
        description={t("authConfig.description")}
        actions={
          <Button
            onClick={handleSave}
            disabled={!canManage || updateSettings.loading}
          >
            <IconRefresh className="mr-1 h-4 w-4" />
            {t("authConfig.saveConfig")}
          </Button>
        }
      />

      {!authLoading && !canManage && (
        <Alert>
          <AlertDescription>{t("common.readOnlyHint")}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconShield className="h-5 w-5 text-primary" />
            {t("authConfig.basicAuth")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Switch
              checked={
                localSettings.basic_auth_enabled ??
                settings?.basic_auth_enabled ??
                false
              }
              onCheckedChange={handleToggle}
              disabled={!canManage}
              id="basic_auth"
            />
            <div>
              <Label htmlFor="basic_auth" className="cursor-pointer">
                {t("authConfig.enableBasicAuth")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("authConfig.basicAuthDesc")}
              </p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t("common.username")}</Label>
              <Input
                value={currentUsername}
                onChange={(e) => setUsername(e.target.value)}
                disabled={!canManage}
                placeholder={t("authConfig.usernamePlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("common.password")}</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={!canManage}
                placeholder={t("authConfig.passwordPlaceholder")}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconUser className="h-5 w-5 text-primary" />
            {t("authConfig.sessionManagement")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border bg-muted/30 p-4">
            <p className="text-sm font-medium">
              {t("authConfig.sessionTimeout")}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {t("authConfig.sessionTimeoutFixed")}
            </p>
          </div>
        </CardContent>
      </Card>

      <ActiveSessionsCard canForceLogout={canForceLogout} />
    </div>
  )
}

function ActiveSessionsCard({ canForceLogout }: { canForceLogout: boolean }) {
  const { t } = useTranslation()
  const { data, isLoading, error } = useAdminSessions()
  const forceLogout = useForceLogout()

  const handleForceLogout = async (jti: string) => {
    if (!canForceLogout) return
    try {
      await forceLogout.execute(jti)
      toast.success(t("authConfig.forceLogoutSuccess"))
    } catch {
      toast.error(t("authConfig.forceLogoutFailed"))
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

  const sessions = data?.sessions ?? []

  return (
    <Card className="min-w-0 overflow-hidden">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <IconUser className="h-5 w-5 text-primary" />
          {t("authConfig.activeSessions")}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {sessions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t("authConfig.noActiveSessions")}
          </p>
        ) : (
          <div className="min-w-0 space-y-3">
            {sessions.map((session) => (
              <div
                key={session.jti}
                className="flex min-w-0 flex-wrap items-start justify-between gap-3 rounded-lg border p-3"
              >
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="min-w-0 truncate text-sm font-medium">
                      {session.username}
                    </span>
                    <span className="min-w-0 truncate text-xs text-muted-foreground">
                      {session.ip}
                    </span>
                  </div>
                  <p
                    className="max-w-md truncate text-xs text-muted-foreground"
                    title={session.user_agent}
                  >
                    {session.user_agent}
                  </p>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span className="break-words">
                      {t("authConfig.loginAt")}:{" "}
                      {new Date(session.login_at).toLocaleString()}
                    </span>
                    <span className="break-words">
                      {t("authConfig.lastActive")}:{" "}
                      {new Date(session.last_active_at).toLocaleString()}
                    </span>
                  </div>
                </div>
                <Button
                  variant="destructive"
                  size="sm"
                  className="shrink-0"
                  onClick={() => handleForceLogout(session.jti)}
                  disabled={!canForceLogout || forceLogout.loading}
                  title={
                    canForceLogout
                      ? t("authConfig.forceLogout")
                      : t("authConfig.forceLogoutAdminOnly")
                  }
                >
                  <IconLogout className="mr-1 h-4 w-4" />
                  {t("authConfig.forceLogout")}
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
