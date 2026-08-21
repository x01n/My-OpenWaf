"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { toast } from "sonner"
import {
  IconDeviceFloppy,
  IconKey,
  IconLock,
  IconPencil,
  IconPlus,
  IconRoute,
  IconTrash,
  IconUsers,
} from "@tabler/icons-react"
import {
  useAccessConfig,
  useAccessPathRules,
  useAccessProviders,
  useAccessUsers,
} from "@/hooks/use-api"
import { useAuth } from "@/hooks/use-auth"
import { AccessPathRuleDialog } from "@/app/(dashboard)/sites/components/access-path-rule-dialog"
import { AccessProviderDialog } from "@/app/(dashboard)/sites/components/access-provider-dialog"
import { AccessUserDialog } from "@/app/(dashboard)/sites/components/access-user-dialog"
import { accessApi, ApiError } from "@/lib/api"
import type {
  AccessPathRule,
  AccessProvider,
  AccessUser,
  Site,
} from "@/lib/types"

interface AccessControlTabProps {
  site: Site
}

type AccessDeleteTarget =
  | { kind: "provider"; item: AccessProvider }
  | { kind: "user"; item: AccessUser }
  | { kind: "path-rule"; item: AccessPathRule }

function getApiErrorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError && error.message ? error.message : fallback
}

export function AccessControlTab({ site }: AccessControlTabProps) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const canManage = user?.role === "admin" || user?.role === "operator"
  const { data: accessConfig, mutate: refreshConfig } = useAccessConfig(site.id)
  const { data: providers, mutate: refreshProviders } = useAccessProviders(
    site.id
  )
  const { data: users, mutate: refreshUsers } = useAccessUsers(site.id)
  const { data: pathRules, mutate: refreshPathRules } = useAccessPathRules(
    site.id
  )

  const [pendingAccessEnabled, setPendingAccessEnabled] = useState<
    boolean | null
  >(null)
  const accessEnabled = pendingAccessEnabled ?? accessConfig?.enabled ?? false
  const [sharedPassword, setSharedPassword] = useState("")
  const [showPasswordInput, setShowPasswordInput] = useState(false)
  const [saving, setSaving] = useState(false)
  const [providerDialogOpen, setProviderDialogOpen] = useState(false)
  const [userDialogOpen, setUserDialogOpen] = useState(false)
  const [pathRuleDialogOpen, setPathRuleDialogOpen] = useState(false)
  const [editingProvider, setEditingProvider] = useState<AccessProvider | null>(
    null
  )
  const [editingUser, setEditingUser] = useState<AccessUser | null>(null)
  const [editingPathRule, setEditingPathRule] = useState<AccessPathRule | null>(
    null
  )
  const [deleteTarget, setDeleteTarget] = useState<AccessDeleteTarget | null>(
    null
  )
  const [deleting, setDeleting] = useState(false)

  const saveConfig = async (data: {
    enabled?: boolean
    session_ttl?: number
    shared_password?: string
    clear_shared_password?: boolean
  }) => {
    if (!accessConfig) {
      throw new Error(t("common.operationFailed"))
    }
    await accessApi.saveConfig(site.id, {
      enabled: data.enabled ?? accessConfig.enabled,
      session_ttl: data.session_ttl ?? accessConfig.session_ttl,
      shared_password: data.shared_password,
      clear_shared_password: data.clear_shared_password,
    })
    await refreshConfig()
  }

  const handleToggleAccess = async (enabled: boolean) => {
    if (!accessConfig || !canManage) return
    setPendingAccessEnabled(enabled)
    try {
      await saveConfig({ enabled })
      setPendingAccessEnabled(null)
      toast.success(t("common.saveSuccess"))
    } catch (error) {
      setPendingAccessEnabled(null)
      await refreshConfig().catch(() => undefined)
      toast.error(getApiErrorMessage(error, t("common.operationFailed")))
    }
  }

  const handleSavePassword = async () => {
    if (!sharedPassword.trim() || !canManage) return
    setSaving(true)
    try {
      await saveConfig({ shared_password: sharedPassword })
      toast.success(t("common.saveSuccess"))
      setSharedPassword("")
      setShowPasswordInput(false)
    } catch (error) {
      await refreshConfig().catch(() => undefined)
      toast.error(getApiErrorMessage(error, t("common.operationFailed")))
    } finally {
      setSaving(false)
    }
  }

  const refreshDeletedTarget = async (target: AccessDeleteTarget) => {
    switch (target.kind) {
      case "provider":
        await refreshProviders()
        break
      case "user":
        await refreshUsers()
        break
      case "path-rule":
        await refreshPathRules()
        break
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget || !canManage) return
    setDeleting(true)
    try {
      switch (deleteTarget.kind) {
        case "provider":
          await accessApi.deleteProvider(site.id, deleteTarget.item.id)
          break
        case "user":
          await accessApi.deleteUser(site.id, deleteTarget.item.id)
          break
        case "path-rule":
          await accessApi.deletePathRule(site.id, deleteTarget.item.id)
          break
      }
      toast.success(t("common.deleteSuccess"))
      setDeleteTarget(null)
    } catch (error) {
      toast.error(getApiErrorMessage(error, t("common.deleteFailed")))
    } finally {
      await refreshDeletedTarget(deleteTarget).catch(() => undefined)
      setDeleting(false)
    }
  }

  const providerTypeLabel = (type: AccessProvider["type"]) => {
    switch (type) {
      case "oauth2":
        return t("sites.detail.typeOauth2")
      case "oidc":
        return t("sites.detail.typeOidc")
      case "password":
        return t("sites.detail.typePassword")
    }
  }

  const pathActionLabel = (action: AccessPathRule["action"]) => {
    switch (action) {
      case "allow":
        return t("sites.detail.actionAllow")
      case "deny":
        return t("sites.detail.actionDeny")
      case "require_auth":
        return t("sites.detail.actionRequireAuth")
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconLock className="h-4 w-4" />
            {t("sites.detail.accessControl")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">
                {t("sites.detail.enableAccessControl")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.accessControlDesc")}
              </p>
            </div>
            <Switch
              checked={accessEnabled}
              disabled={!accessConfig || !canManage}
              onCheckedChange={handleToggleAccess}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconKey className="h-4 w-4" />
            {t("sites.detail.sharedPassword")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-3">
            <Badge variant="outline" className="text-xs">
              {accessConfig?.shared_password_set
                ? t("sites.detail.passwordSet")
                : t("sites.detail.passwordNotSet")}
            </Badge>
            {canManage && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                disabled={!accessConfig}
                onClick={() => setShowPasswordInput((open) => !open)}
              >
                {t("sites.detail.setPassword")}
              </Button>
            )}
          </div>

          {showPasswordInput && canManage && (
            <div className="flex items-center gap-2">
              <Input
                type="password"
                value={sharedPassword}
                onChange={(e) => setSharedPassword(e.target.value)}
                placeholder={t("sites.detail.enterPassword")}
                className="flex-1"
              />
              <Button
                size="sm"
                onClick={handleSavePassword}
                disabled={saving || !accessConfig || !sharedPassword.trim()}
              >
                <IconDeviceFloppy className="mr-1 h-3.5 w-3.5" />
                {t("common.save")}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <IconUsers className="h-4 w-4" />
              {t("sites.detail.authProviders")}
            </CardTitle>
            {canManage && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                onClick={() => {
                  setEditingProvider(null)
                  setProviderDialogOpen(true)
                }}
              >
                <IconPlus className="mr-1 h-3.5 w-3.5" />
                {t("common.add")}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto rounded-lg border">
            <div className="min-w-[480px] divide-y">
              <div className="grid grid-cols-[minmax(10rem,1fr)_6rem_5rem_auto] items-center gap-3 bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
                <span>{t("common.name")}</span>
                <span>{t("common.type")}</span>
                <span>{t("rules.priority")}</span>
                {canManage && (
                  <span className="text-right">{t("common.actions")}</span>
                )}
              </div>
              {providers?.length ? (
                providers.map((provider) => (
                  <div
                    key={provider.id}
                    className="grid grid-cols-[minmax(10rem,1fr)_6rem_5rem_auto] items-center gap-3 px-4 py-3 text-sm"
                  >
                    <span className="min-w-0 truncate">{provider.name}</span>
                    <Badge variant="outline" className="w-fit text-[10px]">
                      {providerTypeLabel(provider.type)}
                    </Badge>
                    <span className="font-mono text-xs">
                      {provider.priority}
                    </span>
                    {canManage && (
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={t("common.edit")}
                          onClick={() => {
                            setEditingProvider(provider)
                            setProviderDialogOpen(true)
                          }}
                        >
                          <IconPencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="text-destructive"
                          aria-label={t("common.delete")}
                          onClick={() =>
                            setDeleteTarget({
                              kind: "provider",
                              item: provider,
                            })
                          }
                        >
                          <IconTrash className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
                  {t("sites.detail.noAuthProviders")}
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <IconUsers className="h-4 w-4" />
              {t("sites.detail.localUsers")}
            </CardTitle>
            {canManage && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                onClick={() => {
                  setEditingUser(null)
                  setUserDialogOpen(true)
                }}
              >
                <IconPlus className="mr-1 h-3.5 w-3.5" />
                {t("common.add")}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto rounded-lg border">
            <div className="min-w-[360px] divide-y">
              <div className="grid grid-cols-[minmax(10rem,1fr)_6rem_auto] items-center gap-3 bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
                <span>{t("sites.detail.username")}</span>
                <span>{t("common.status")}</span>
                {canManage && (
                  <span className="text-right">{t("common.actions")}</span>
                )}
              </div>
              {users?.length ? (
                users.map((accessUser) => (
                  <div
                    key={accessUser.id}
                    className="grid grid-cols-[minmax(10rem,1fr)_6rem_auto] items-center gap-3 px-4 py-3 text-sm"
                  >
                    <span className="min-w-0 truncate">
                      {accessUser.username}
                    </span>
                    <Badge
                      variant={accessUser.enabled ? "default" : "secondary"}
                      className="w-fit text-[10px]"
                    >
                      {accessUser.enabled
                        ? t("common.enabled")
                        : t("common.disabled")}
                    </Badge>
                    {canManage && (
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={t("common.edit")}
                          onClick={() => {
                            setEditingUser(accessUser)
                            setUserDialogOpen(true)
                          }}
                        >
                          <IconPencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="text-destructive"
                          aria-label={t("common.delete")}
                          onClick={() =>
                            setDeleteTarget({ kind: "user", item: accessUser })
                          }
                        >
                          <IconTrash className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
                  {t("sites.detail.noLocalUsers")}
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <IconRoute className="h-4 w-4" />
              {t("sites.detail.pathRules")}
            </CardTitle>
            {canManage && (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                onClick={() => {
                  setEditingPathRule(null)
                  setPathRuleDialogOpen(true)
                }}
              >
                <IconPlus className="mr-1 h-3.5 w-3.5" />
                {t("common.add")}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto rounded-lg border">
            <div className="min-w-[480px] divide-y">
              <div className="grid grid-cols-[minmax(10rem,1fr)_7rem_5rem_auto] items-center gap-3 bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
                <span>{t("sites.detail.path")}</span>
                <span>{t("common.action")}</span>
                <span>{t("rules.priority")}</span>
                {canManage && (
                  <span className="text-right">{t("common.actions")}</span>
                )}
              </div>
              {pathRules?.length ? (
                pathRules.map((pathRule) => (
                  <div
                    key={pathRule.id}
                    className="grid grid-cols-[minmax(10rem,1fr)_7rem_5rem_auto] items-center gap-3 px-4 py-3 text-sm"
                  >
                    <span className="min-w-0 truncate font-mono text-xs">
                      {pathRule.path}
                    </span>
                    <Badge variant="outline" className="w-fit text-[10px]">
                      {pathActionLabel(pathRule.action)}
                    </Badge>
                    <span className="font-mono text-xs">
                      {pathRule.priority}
                    </span>
                    {canManage && (
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={t("common.edit")}
                          onClick={() => {
                            setEditingPathRule(pathRule)
                            setPathRuleDialogOpen(true)
                          }}
                        >
                          <IconPencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="text-destructive"
                          aria-label={t("common.delete")}
                          onClick={() =>
                            setDeleteTarget({
                              kind: "path-rule",
                              item: pathRule,
                            })
                          }
                        >
                          <IconTrash className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
                  {t("sites.detail.noPathRules")}
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {providerDialogOpen && (
        <AccessProviderDialog
          key={editingProvider?.id ?? "new"}
          open={providerDialogOpen}
          onOpenChange={(open) => {
            setProviderDialogOpen(open)
            if (!open) setEditingProvider(null)
          }}
          siteId={site.id}
          provider={editingProvider}
        />
      )}
      {userDialogOpen && (
        <AccessUserDialog
          key={editingUser?.id ?? "new"}
          open={userDialogOpen}
          onOpenChange={(open) => {
            setUserDialogOpen(open)
            if (!open) setEditingUser(null)
          }}
          siteId={site.id}
          user={editingUser}
        />
      )}
      {pathRuleDialogOpen && (
        <AccessPathRuleDialog
          key={editingPathRule?.id ?? "new"}
          open={pathRuleDialogOpen}
          onOpenChange={(open) => {
            setPathRuleDialogOpen(open)
            if (!open) setEditingPathRule(null)
          }}
          siteId={site.id}
          rule={editingPathRule}
        />
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null)
        }}
        title={t("common.confirmDeleteTitle")}
        description={t("sites.detail.deleteAccessItemDescription")}
        loading={deleting}
        onConfirm={handleDelete}
      />
    </div>
  )
}
