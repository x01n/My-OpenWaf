"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import {
  IconArrowDown,
  IconArrowUp,
  IconDeviceFloppy,
} from "@tabler/icons-react"
import { useSiteMutation } from "@/hooks/use-api"
import { SiteXFFMode, type Site } from "@/lib/types"
import { cn } from "@/lib/utils"

interface AdvancedTabProps {
  site: Site
  canManage: boolean
}

/**
 * 三态取值：
 * - "inherit" 继承全局（提交 null）
 * - "on"      站点强制开启（提交 true）
 * - "off"     站点强制关闭（提交 false）
 */
type TriState = "inherit" | "on" | "off"

/** 反重放校验失败动作白名单，见 internal/admin/shared/helpers.go 的 ValidateAntiReplayAction。 */
const ANTI_REPLAY_ACTIONS = [
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
  "intercept",
] as const

/** 站点级默认质询动作白名单，null=继承全局。 */
const CHALLENGE_ACTIONS = [
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
] as const

/** 站点级 CAPTCHA 类型白名单，见 internal/waf/challenge/captcha.go 的 IsValidCaptchaType。 */
const CAPTCHA_TYPES = ["math", "click", "slide", "rotate"] as const

function normalizeClientIPHeaderOrder(
  value: string | string[] | undefined
): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string")
  }
  if (!value) return ["x_forwarded_for"]
  try {
    const parsed: unknown = JSON.parse(value)
    if (Array.isArray(parsed)) {
      const headers = parsed.filter(
        (item): item is string => typeof item === "string"
      )
      if (headers.length > 0) return headers
    }
  } catch {
    // 历史配置损坏时回退到安全的默认来源头。
  }
  return ["x_forwarded_for"]
}

/**
 * 将站点级 *bool 覆盖字段归一化为三态取值。
 *
 * @param value 站点字段原始值
 * @returns 三态取值
 */
function toTriState(value: boolean | null | undefined): TriState {
  if (value === true) return "on"
  if (value === false) return "off"
  return "inherit"
}

/**
 * 将三态取值转换回站点级 *bool 覆盖字段的提交值。
 *
 * @param value 三态取值
 * @returns null（继承）/ true / false
 */
function fromTriState(value: TriState): boolean | null {
  if (value === "on") return true
  if (value === "off") return false
  return null
}

/**
 * 三态覆盖选择器：继承全局 / 强制开启 / 强制关闭。
 */
function TriStateToggle({
  value,
  onChange,
  idPrefix,
}: {
  value: TriState
  onChange: (value: TriState) => void
  idPrefix: string
}) {
  const { t } = useTranslation()
  const options: { value: TriState; labelKey: string }[] = [
    { value: "inherit", labelKey: "sites.detail.dynOverride.inherit" },
    { value: "on", labelKey: "sites.detail.dynOverride.on" },
    { value: "off", labelKey: "sites.detail.dynOverride.off" },
  ]
  return (
    <div className="inline-flex items-center gap-1 rounded-md border p-0.5">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          id={`${idPrefix}-${option.value}`}
          onClick={() => onChange(option.value)}
          className={cn(
            "rounded px-2.5 py-1 text-xs transition-colors",
            value === option.value
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:bg-muted"
          )}
        >
          {t(option.labelKey)}
        </button>
      ))}
    </div>
  )
}

export function AdvancedTab({ site, canManage }: AdvancedTabProps) {
  const { t } = useTranslation()
  const updateSite = useSiteMutation()

  const [antiReplayState, setAntiReplayState] = useState<TriState>(() =>
    toTriState(site.anti_replay_enabled)
  )
  const [antiReplayTtl, setAntiReplayTtl] = useState(site.anti_replay_ttl)
  const [antiReplayAction, setAntiReplayAction] = useState(
    site.anti_replay_action || "shield_challenge"
  )
  const [challengeAction, setChallengeAction] = useState(
    site.challenge_action ?? ""
  )
  const [captchaType, setCaptchaType] = useState(site.captcha_type ?? "")
  const [maintenanceEnabled, setMaintenanceEnabled] = useState(
    site.maintenance_enabled
  )
  const [maintenanceStatus, setMaintenanceStatus] = useState(
    site.maintenance_status
  )
  const [xffMode, setXffMode] = useState(site.xff_mode)
  const [trustedCidr, setTrustedCidr] = useState(site.trusted_cidr)
  const [clientIPHeaderOrder, setClientIPHeaderOrder] = useState<string[]>(() =>
    normalizeClientIPHeaderOrder(site.client_ip_header_order)
  )
  const [preserveHost, setPreserveHost] = useState(site.preserve_original_host)
  const [saving, setSaving] = useState(false)

  const moveClientIPHeader = (index: number, direction: -1 | 1) => {
    const target = index + direction
    if (target < 0 || target >= clientIPHeaderOrder.length) return
    setClientIPHeaderOrder((current) => {
      const next = [...current]
      ;[next[index], next[target]] = [next[target], next[index]]
      return next
    })
  }

  const toggleClientIPHeader = (header: string, enabled: boolean) => {
    setClientIPHeaderOrder((current) => {
      if (enabled) return [...current, header]
      return current.filter((item) => item !== header)
    })
  }

  /**
   * 反重放三态切换即时保存单字段。
   *
   * @param value 三态取值
   */
  const handleAntiReplayStateChange = async (value: TriState) => {
    if (!canManage) return
    setAntiReplayState(value)
    try {
      await updateSite.execute({
        id: site.id,
        data: { anti_replay_enabled: fromTriState(value) },
      })
      toast.success(t("common.saveSuccess"))
    } catch {
      toast.error(t("common.operationFailed"))
      setAntiReplayState(toTriState(site.anti_replay_enabled))
    }
  }

  const handleToggleMaintenance = async (enabled: boolean) => {
    if (!canManage) return
    setMaintenanceEnabled(enabled)
    try {
      await updateSite.execute({
        id: site.id,
        data: { maintenance_enabled: enabled },
      })
      toast.success(t("common.saveSuccess"))
    } catch {
      toast.error(t("common.operationFailed"))
      setMaintenanceEnabled(!enabled)
    }
  }

  const handleSave = async () => {
    if (!canManage) return
    setSaving(true)
    try {
      await updateSite.execute({
        id: site.id,
        data: {
          anti_replay_enabled: fromTriState(antiReplayState),
          anti_replay_ttl: antiReplayTtl,
          anti_replay_action: antiReplayAction,
          challenge_action: challengeAction === "" ? null : challengeAction,
          captcha_type: captchaType === "" ? null : captchaType,
          maintenance_enabled: maintenanceEnabled,
          maintenance_status: maintenanceStatus,
          xff_mode: xffMode,
          trusted_cidr: trustedCidr,
          client_ip_header_order: clientIPHeaderOrder,
          preserve_original_host: preserveHost,
        },
      })
      toast.success(t("common.saveSuccess"))
    } catch {
      toast.error(t("common.operationFailed"))
    } finally {
      setSaving(false)
    }
  }

  return (
    <fieldset
      disabled={!canManage}
      className="m-0 min-w-0 space-y-4 border-0 p-0"
    >
      {/* TLS 配置 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">TLS</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">
                {t("sites.detail.tls")}
              </span>
              <p className="font-medium">
                <Badge
                  variant={site.tls_enabled ? "default" : "outline"}
                  className="h-5 text-[10px]"
                >
                  {site.tls_enabled ? "HTTPS" : "HTTP"}
                </Badge>
              </p>
            </div>
            {site.tls_enabled && (
              <>
                <div>
                  <span className="text-muted-foreground">
                    {t("sites.detail.minTlsVersion")}
                  </span>
                  <p className="font-medium">
                    {site.min_tls_version || "TLS 1.2"}
                  </p>
                </div>
                <div>
                  <span className="text-muted-foreground">
                    {t("sites.detail.maxTlsVersion")}
                  </span>
                  <p className="font-medium">
                    {site.max_tls_version || "TLS 1.3"}
                  </p>
                </div>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 站点级质询策略 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {t("sites.detail.challengeStrategy.title")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-muted-foreground">
            {t("sites.detail.challengeStrategy.desc")}
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>
                {t("sites.detail.challengeStrategy.challengeAction")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.challengeStrategy.challengeActionHint")}
              </p>
              <select
                value={challengeAction}
                onChange={(e) => setChallengeAction(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">
                  {t("sites.detail.challengeStrategy.actionInherit")}
                </option>
                {CHALLENGE_ACTIONS.map((action) => (
                  <option key={action} value={action}>
                    {t(`sites.detail.challengeStrategy.actions.${action}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <Label>{t("sites.detail.challengeStrategy.captchaType")}</Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.challengeStrategy.captchaTypeHint")}
              </p>
              <select
                value={captchaType}
                onChange={(e) => setCaptchaType(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">
                  {t("sites.detail.challengeStrategy.actionInherit")}
                </option>
                {CAPTCHA_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {t(`sites.detail.challengeStrategy.captchaTypes.${type}`)}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Anti-Replay */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Anti-Replay</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label>{t("sites.detail.enableAntiReplay")}</Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.antiReplayDesc")}
              </p>
            </div>
            <TriStateToggle
              value={antiReplayState}
              onChange={handleAntiReplayStateChange}
              idPrefix="adv-antireplay"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t("sites.detail.antiReplayTtl")}</Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.antiReplayTtlHint")}
              </p>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={1}
                  className="w-32"
                  value={antiReplayTtl}
                  onChange={(e) =>
                    setAntiReplayTtl(Math.max(1, Number(e.target.value) || 60))
                  }
                />
                <span className="text-sm text-muted-foreground">
                  {t("common.seconds")}
                </span>
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t("sites.detail.antiReplayAction")}</Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.antiReplayActionHint")}
              </p>
              <select
                value={antiReplayAction}
                onChange={(e) => setAntiReplayAction(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
              >
                {ANTI_REPLAY_ACTIONS.map((action) => (
                  <option key={action} value={action}>
                    {t(`sites.detail.antiReplayActions.${action}`)}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 维护模式 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {t("sites.detail.maintenanceMode")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label>{t("sites.detail.enableMaintenance")}</Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.maintenanceDesc")}
              </p>
            </div>
            <Switch
              checked={maintenanceEnabled}
              onCheckedChange={handleToggleMaintenance}
            />
          </div>

          {maintenanceEnabled && (
            <div className="space-y-2">
              <Label>{t("sites.detail.maintenanceStatus")}</Label>
              <Input
                type="number"
                min={100}
                max={599}
                className="w-32"
                value={maintenanceStatus}
                onChange={(e) =>
                  setMaintenanceStatus(Number(e.target.value) || 503)
                }
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* 网络配置 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            {t("sites.detail.networkConfig")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>{t("sites.detail.xffMode")}</Label>
            <select
              value={xffMode}
              onChange={(e) => {
                const value = e.target.value
                if (
                  value === SiteXFFMode.Strip ||
                  value === SiteXFFMode.TrustOuter
                ) {
                  setXffMode(value)
                }
              }}
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
            >
              <option value={SiteXFFMode.Strip}>Use direct peer IP</option>
              <option value={SiteXFFMode.TrustOuter}>
                Trust outer WAF CIDR and use leftmost configured header
              </option>
            </select>
          </div>

          <div className="space-y-2">
            <Label>{t("sites.detail.trustedCidr")}</Label>
            <Input
              value={trustedCidr}
              onChange={(e) => setTrustedCidr(e.target.value)}
              placeholder="10.0.0.0/8, 172.16.0.0/12"
            />
          </div>

          <div className="space-y-2">
            <Label>{t("sites.detail.clientIPHeaderOrder")}</Label>
            <p className="text-xs text-muted-foreground">
              {t("sites.detail.clientIPHeaderOrderDesc")}
            </p>
            <div className="space-y-2 rounded-lg border p-3">
              {[
                ["x_forwarded_for", "X-Forwarded-For"],
                ["x_real_ip", "X-Real-IP"],
                ["forwarded", "Forwarded"],
              ].map(([value, label]) => {
                const index = clientIPHeaderOrder.indexOf(value)
                const enabled = index >= 0
                return (
                  <div key={value} className="flex items-center gap-2">
                    <Switch
                      checked={enabled}
                      onCheckedChange={(checked) =>
                        toggleClientIPHeader(value, checked)
                      }
                    />
                    <span className="min-w-0 flex-1 text-sm">{label}</span>
                    {enabled && (
                      <>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          aria-label={t("sites.detail.moveHeaderUp")}
                          disabled={index === 0}
                          onClick={() => moveClientIPHeader(index, -1)}
                        >
                          <IconArrowUp className="h-4 w-4" />
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          aria-label={t("sites.detail.moveHeaderDown")}
                          disabled={index === clientIPHeaderOrder.length - 1}
                          onClick={() => moveClientIPHeader(index, 1)}
                        >
                          <IconArrowDown className="h-4 w-4" />
                        </Button>
                      </>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label>{t("sites.detail.preserveHost")}</Label>
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.preserveHostDesc")}
              </p>
            </div>
            <Switch checked={preserveHost} onCheckedChange={setPreserveHost} />
          </div>
        </CardContent>
      </Card>

      {/* 保存按钮 */}
      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saving}>
          <IconDeviceFloppy className="mr-1 h-4 w-4" />
          {saving ? t("common.saving") : t("common.save")}
        </Button>
      </div>
    </fieldset>
  )
}