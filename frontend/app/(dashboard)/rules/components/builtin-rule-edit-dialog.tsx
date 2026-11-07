"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { IconAlertTriangle } from "@tabler/icons-react"
import { ActionBadge } from "@/components/action-badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import type { CaptchaType, CiscoASAMode } from "@/lib/types"

const ACTIONS = [
  "intercept",
  "observe",
  "drop",
  "challenge",
  "rate_limit",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
  "redirect",
]
const SENSITIVITIES = ["low", "medium", "high", "very_high", "strict", "off"]
const CAPTCHA_TYPES: CaptchaType[] = ["math", "click", "slide", "rotate"]
const CISCO_ASA_MODES: CiscoASAMode[] = ["legacy", "strict", "scoped"]
/**
 * 只有该规则消费 cisco_asa_mode：internal/core/rules/phases.go 的 owaspPhase
 * 从 owasp:path:006 的规则覆盖里读取档位，其余规则的该字段没有消费点。
 */
const CISCO_ASA_RULE_ID = "owasp:path:006"

export interface BuiltinRuleEditInitialValue {
  enabled: boolean
  action: string
  sensitivity?: string
  statusCode?: number
  redirectTo?: string
  captchaType?: CaptchaType | ""
  ciscoASAMode?: CiscoASAMode | ""
  whitelist?: string[]
  note?: string
}

export interface BuiltinRuleEditPatch {
  enabled: boolean
  action: string
  sensitivity: string
  status_code: number
  redirect_to: string
  captcha_type: CaptchaType | ""
  cisco_asa_mode?: CiscoASAMode
  whitelist?: string[]
  note?: string
}

interface BuiltinRuleEditDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  ruleID: string
  name: string
  description?: string
  initial: BuiltinRuleEditInitialValue
  allowWhitelist?: boolean
  allowNote?: boolean
  onSubmit: (patch: BuiltinRuleEditPatch) => Promise<void>
}

/**
 * 内置 CVE/OWASP 规则的完整覆盖编辑器。
 * 内置检测定义不可物理删除；删除自定义配置由页面的“重置覆盖”操作完成。
 */
export function BuiltinRuleEditDialog({
  open,
  onOpenChange,
  ruleID,
  name,
  description,
  initial,
  allowWhitelist = false,
  allowNote = false,
  onSubmit,
}: BuiltinRuleEditDialogProps) {
  const { t } = useTranslation()
  const [enabled, setEnabled] = useState(initial.enabled)
  const [action, setAction] = useState(initial.action || "intercept")
  const [sensitivity, setSensitivity] = useState(
    initial.sensitivity || "inherit"
  )
  const [statusCode, setStatusCode] = useState(
    initial.statusCode ? String(initial.statusCode) : ""
  )
  const [redirectTo, setRedirectTo] = useState(initial.redirectTo || "")
  const [captchaType, setCaptchaType] = useState<CaptchaType | "">(
    initial.captchaType || ""
  )
  // 未覆盖时显示 scoped：数据面未配置时按 scoped 运行，显式 legacy 仍可恢复历史行为。
  const [ciscoASAMode, setCiscoASAMode] = useState<CiscoASAMode>(
    initial.ciscoASAMode || "scoped"
  )
  const [whitelist, setWhitelist] = useState(
    (initial.whitelist || []).join("\n")
  )
  const [note, setNote] = useState(initial.note || "")
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setSaving(true)
    setError(null)
    try {
      const parsedStatus = statusCode.trim() === "" ? 0 : Number(statusCode)
      if (
        !Number.isInteger(parsedStatus) ||
        (parsedStatus !== 0 && (parsedStatus < 100 || parsedStatus > 599))
      ) {
        throw new Error(
          t("rules.statusCodeInvalid", "状态码必须为 0 或 100 到 599")
        )
      }
      const paths = whitelist
        .split("\n")
        .map((item) => item.trim())
        .filter(Boolean)
      if (allowWhitelist) {
        if (paths.length > 64) {
          throw new Error(t("rules.pathWhitelistTooMany"))
        }
        if (paths.some((path) => new TextEncoder().encode(path).length > 512)) {
          throw new Error(t("rules.pathWhitelistEntryTooLong"))
        }
      }
      if (allowNote && new TextEncoder().encode(note.trim()).length > 4096) {
        throw new Error(t("rules.policyNoteTooLong"))
      }
      await onSubmit({
        enabled,
        action,
        sensitivity: sensitivity === "inherit" ? "" : sensitivity,
        status_code: parsedStatus,
        redirect_to: redirectTo.trim(),
        captcha_type: action === "captcha_challenge" ? captchaType : "",
        ...(ruleID === CISCO_ASA_RULE_ID ? { cisco_asa_mode: ciscoASAMode } : {}),
        ...(allowWhitelist ? { whitelist: Array.from(new Set(paths)) } : {}),
        ...(allowNote ? { note: note.trim() } : {}),
      })
      onOpenChange(false)
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : t("common.operationFailed")
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[calc(100dvh-2rem)] max-w-3xl flex-col overflow-hidden p-0">
        <DialogHeader className="shrink-0 border-b px-6 py-5">
          <DialogTitle>
            {t("rules.editBuiltinOverride", "编辑规则覆盖")}
          </DialogTitle>
          <DialogDescription className="space-y-1">
            <span className="block font-mono text-xs">{ruleID}</span>
            <span className="block font-medium text-foreground">{name}</span>
            {description && (
              <span className="line-clamp-2 block">{description}</span>
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-6 py-5">
          <Alert>
            <IconAlertTriangle className="h-4 w-4" />
            <AlertDescription>
              {t(
                "rules.builtinImmutableHint",
                "内置检测定义不可新增或物理删除；可编辑当前作用域覆盖，或在页面中重置以删除覆盖。自定义检测规则请使用自定义规则入口。"
              )}
            </AlertDescription>
          </Alert>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div>
              <Label>{t("common.enabled")}</Label>
              <p className="text-xs text-muted-foreground">
                {t(
                  "rules.enabledOverrideHint",
                  "控制当前策略或作用域是否执行此规则"
                )}
              </p>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>{t("rules.action")}</Label>
              <Select value={action} onValueChange={setAction}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ACTIONS.map((value) => (
                    <SelectItem key={value} value={value}>
                      <ActionBadge action={value} />
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("attacks.sensitivity")}</Label>
              <Select value={sensitivity} onValueChange={setSensitivity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="inherit">
                    {t("rules.captchaTypeInherit", "继承")}
                  </SelectItem>
                  {SENSITIVITIES.map((value) => (
                    <SelectItem key={value} value={value}>
                      {t(`attacks.sensitivityValues.${value}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="builtin-rule-status">
                {t("rules.statusCode", "响应状态码")}
              </Label>
              <Input
                id="builtin-rule-status"
                type="number"
                min={0}
                max={599}
                value={statusCode}
                onChange={(event) => setStatusCode(event.target.value)}
                placeholder={t("rules.statusCodeInherit", "0 / 空值表示默认")}
              />
            </div>
            {action === "captcha_challenge" && (
              <div className="space-y-2">
                <Label>{t("rules.captchaTypeLabel", "验证码类型")}</Label>
                <Select
                  value={captchaType || "inherit"}
                  onValueChange={(value) =>
                    setCaptchaType(
                      value === "inherit" ? "" : (value as CaptchaType)
                    )
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="inherit">
                      {t("rules.captchaTypeInherit", "继承全局")}
                    </SelectItem>
                    {CAPTCHA_TYPES.map((value) => (
                      <SelectItem key={value} value={value}>
                        {t(`rules.captchaType.${value}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          {ruleID === CISCO_ASA_RULE_ID && (
            <div className="space-y-2">
              <Label>{t("rules.ciscoASAModeLabel")}</Label>
              <Select
                value={ciscoASAMode}
                onValueChange={(value) =>
                  setCiscoASAMode(value as CiscoASAMode)
                }
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="max-w-[28rem]">
                  {CISCO_ASA_MODES.map((mode) => (
                    <SelectItem key={mode} value={mode}>
                      <span className="flex flex-col items-start gap-0.5 text-left whitespace-normal">
                        <span>{t(`rules.ciscoASAMode.${mode}.label`)}</span>
                        <span className="text-xs font-normal text-muted-foreground">
                          {t(`rules.ciscoASAMode.${mode}.hint`)}
                        </span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t(`rules.ciscoASAMode.${ciscoASAMode}.hint`)}
              </p>
              <p className="text-xs text-muted-foreground">
                {t("rules.ciscoASAModeScopeHint")}
              </p>
            </div>
          )}

          {action === "redirect" && (
            <div className="space-y-2">
              <Label htmlFor="builtin-rule-redirect">
                {t("rules.redirectTo", "跳转地址")}
              </Label>
              <Input
                id="builtin-rule-redirect"
                type="url"
                value={redirectTo}
                onChange={(event) => setRedirectTo(event.target.value)}
                placeholder="https://example.com/blocked"
              />
            </div>
          )}

          {allowWhitelist && (
            <div className="space-y-2">
              <Label htmlFor="builtin-rule-whitelist">
                {t("rules.pathWhitelist", "路径白名单")}
              </Label>
              <Textarea
                id="builtin-rule-whitelist"
                value={whitelist}
                onChange={(event) => setWhitelist(event.target.value)}
                rows={5}
                className="font-mono text-xs"
                placeholder={"/healthz\n/static/*"}
              />
              <p className="text-xs text-muted-foreground">
                {t(
                  "rules.pathWhitelistHint",
                  "每行一个精确路径或以 * 结尾的目录前缀；* 表示全部路径。"
                )}
              </p>
            </div>
          )}

          {allowNote && (
            <div className="space-y-2">
              <Label htmlFor="builtin-rule-note">
                {t("rules.policyNote", "策略备注")}
              </Label>
              <Textarea
                id="builtin-rule-note"
                value={note}
                onChange={(event) => setNote(event.target.value)}
                rows={4}
                maxLength={4096}
                placeholder={t(
                  "rules.policyNotePlaceholder",
                  "记录启用原因、业务例外或变更工单"
                )}
              />
            </div>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>

        <DialogFooter className="shrink-0 border-t px-6 py-4">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={saving}
          >
            {t("common.cancel")}
          </Button>
          <Button onClick={submit} disabled={saving}>
            {saving ? t("common.saving") : t("common.save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
