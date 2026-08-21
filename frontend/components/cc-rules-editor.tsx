"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { IconPencil, IconPlus, IconTrash } from "@tabler/icons-react"
import { cn } from "@/lib/utils"
import type { CaptchaType } from "@/lib/types"

/**
 * CC 规则单条匹配条件。
 */
export interface CCRuleCondition {
  target: string
  operator: string
  value: string
}

/**
 * CC 规则数据结构，与全局 CC 防护及站点级 CC 防护共用同一契约。
 */
export interface CCRule {
  enabled?: boolean
  name?: string
  action: string
  /** 空值继承全局验证码类型，仅对 captcha/captcha_challenge 生效。 */
  captcha_type?: CaptchaType | ""
  conditions: CCRuleCondition[]
  window: number
  threshold: number
  duration: number
  duration_unit?: "seconds" | "minutes"
}

/**
 * CC 规则可选触发动作，取值需与后端一致。
 */
export const CC_ACTION_OPTIONS = [
  "intercept",
  "rate_limit",
  "captcha",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
  "drop",
  "observe",
] as const

/**
 * CC 规则条件匹配目标。
 */
export const CC_CONDITION_TARGETS = ["url_path", "method", "header"] as const

/**
 * 各匹配目标可用的操作符集合。
 */
export const CC_CONDITION_OPERATORS: Record<string, string[]> = {
  url_path: ["equals", "prefix", "contains"],
  method: ["equals"],
  header: ["equals", "contains", "prefix"],
}

/**
 * 运行时校验 CC 规则条件结构。
 */
export function isCCRuleCondition(value: unknown): value is CCRuleCondition {
  if (!value || typeof value !== "object") return false
  const cond = value as Partial<CCRuleCondition>
  return (
    typeof cond.target === "string" &&
    typeof cond.operator === "string" &&
    typeof cond.value === "string"
  )
}

/**
 * 运行时校验 CC 规则结构。
 */
export function isCCRule(value: unknown): value is CCRule {
  if (!value || typeof value !== "object") return false
  const rule = value as Partial<CCRule>
  return (
    typeof rule.action === "string" &&
    rule.action.trim().length > 0 &&
    Array.isArray(rule.conditions) &&
    rule.conditions.every(isCCRuleCondition) &&
    typeof rule.window === "number" &&
    Number.isFinite(rule.window) &&
    typeof rule.threshold === "number" &&
    Number.isFinite(rule.threshold) &&
    typeof rule.duration === "number" &&
    Number.isFinite(rule.duration) &&
    (rule.enabled === undefined || typeof rule.enabled === "boolean") &&
    (rule.name === undefined || typeof rule.name === "string") &&
    (rule.captcha_type === undefined ||
      rule.captcha_type === "" ||
      rule.captcha_type === "math" ||
      rule.captcha_type === "click" ||
      rule.captcha_type === "slide" ||
      rule.captcha_type === "rotate") &&
    (rule.duration_unit === undefined ||
      rule.duration_unit === "seconds" ||
      rule.duration_unit === "minutes")
  )
}

/**
 * 将未知数据安全转换为 CCRule[]，过滤非法条目。
 */
export function toCCRules(value: unknown): CCRule[] {
  return Array.isArray(value) ? value.filter(isCCRule) : []
}

/**
 * 构造一条默认 CC 规则。
 *
 * @returns 带默认值的空规则
 */
export function emptyCCRule(): CCRule {
  return {
    enabled: true,
    name: "",
    action: "intercept",
    captcha_type: "",
    conditions: [{ target: "url_path", operator: "prefix", value: "" }],
    window: 60,
    threshold: 100,
    duration: 300,
    duration_unit: "seconds",
  }
}

interface CCRulesEditorProps {
  rules: CCRule[]
  onChange: (rules: CCRule[]) => void
}

/**
 * CC 规则列表编辑器：支持启停、编辑、删除、新增规则及每条规则的条件配置。
 *
 * 组件自身仅管理编辑面板的临时状态，规则数组通过受控 props（rules/onChange）向上同步。
 * 全局 CC 防护页与站点级 CC 防护 Tab 共用本组件以保证行为一致。
 */
export function CCRulesEditor({ rules, onChange }: CCRulesEditorProps) {
  const { t } = useTranslation()
  const [editingRuleIndex, setEditingRuleIndex] = useState<number | null>(null)
  const [editingRule, setEditingRule] = useState<CCRule | null>(null)

  const toggleRule = (index: number) => {
    if (editingRuleIndex !== null) return
    onChange(
      rules.map((rule, i) =>
        i === index ? { ...rule, enabled: !(rule.enabled ?? true) } : rule
      )
    )
  }

  const deleteRule = (index: number) => {
    if (editingRuleIndex !== null) return
    onChange(rules.filter((_, i) => i !== index))
  }

  const startAddRule = () => {
    setEditingRuleIndex(-1)
    setEditingRule(emptyCCRule())
  }

  const startEditRule = (index: number) => {
    if (editingRuleIndex !== null) return
    setEditingRuleIndex(index)
    setEditingRule({ ...rules[index] })
  }

  const cancelEditRule = () => {
    setEditingRuleIndex(null)
    setEditingRule(null)
  }

  const saveEditRule = () => {
    if (!editingRule) return
    if (editingRuleIndex === -1) {
      onChange([...rules, editingRule])
    } else if (editingRuleIndex !== null) {
      onChange(
        rules.map((rule, i) => (i === editingRuleIndex ? editingRule : rule))
      )
    }
    setEditingRuleIndex(null)
    setEditingRule(null)
  }

  const updateEditingCondition = (
    condIndex: number,
    field: keyof CCRuleCondition,
    value: string
  ) => {
    if (!editingRule) return
    const newConditions = editingRule.conditions.map((cond, i) =>
      i === condIndex ? { ...cond, [field]: value } : cond
    )
    if (field === "target") {
      const ops = CC_CONDITION_OPERATORS[value] ?? ["equals"]
      if (!ops.includes(newConditions[condIndex].operator)) {
        newConditions[condIndex].operator = ops[0]
      }
    }
    setEditingRule({ ...editingRule, conditions: newConditions })
  }

  const addEditingCondition = () => {
    if (!editingRule) return
    setEditingRule({
      ...editingRule,
      conditions: [
        ...editingRule.conditions,
        { target: "url_path", operator: "prefix", value: "" },
      ],
    })
  }

  const removeEditingCondition = (condIndex: number) => {
    if (!editingRule || editingRule.conditions.length <= 1) return
    setEditingRule({
      ...editingRule,
      conditions: editingRule.conditions.filter((_, i) => i !== condIndex),
    })
  }

  return (
    <div className="space-y-4">
      {rules.length === 0 && editingRuleIndex === null && (
        <p className="text-sm text-muted-foreground">
          {t("ccProtection.noCustomRules")}
        </p>
      )}

      <div className="space-y-2">
        {rules.map((rule, index) => (
          <div
            key={index}
            className={cn(
              "flex items-center gap-4 rounded-lg border p-3 transition-colors",
              (rule.enabled ?? true)
                ? "bg-teal-50/50 dark:bg-teal-950/20"
                : "bg-muted/30"
            )}
          >
            <Switch
              checked={rule.enabled ?? true}
              disabled={editingRuleIndex !== null}
              onCheckedChange={() => toggleRule(index)}
            />
            <div className="flex-1 space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">
                  {rule.name || `${t("ccProtection.rule")} #${index + 1}`}
                </span>
                <Badge
                  variant={(rule.enabled ?? true) ? "default" : "secondary"}
                  className="h-4 px-1.5 text-[10px]"
                >
                  {(rule.enabled ?? true)
                    ? t("common.enable")
                    : t("common.disable")}
                </Badge>
                <Badge variant="outline" className="h-4 px-1.5 text-[10px]">
                  {rule.action}
                </Badge>
                {(rule.action === "captcha" ||
                  rule.action === "captcha_challenge") &&
                  rule.captcha_type && (
                    <Badge variant="outline" className="h-4 px-1.5 text-[10px]">
                      {rule.captcha_type}
                    </Badge>
                  )}
              </div>
              <p className="text-xs text-muted-foreground">
                {rule.conditions
                  .map(
                    (c) =>
                      `${t(`ccProtection.target_${c.target}`, { defaultValue: c.target })} ${t(`ccProtection.operator_${c.operator}`, { defaultValue: c.operator })} "${c.value}"`
                  )
                  .join(` ${t("ccRulesEditor.andConnector")} `)}
                {rule.window > 0 &&
                  rule.threshold > 0 &&
                  ` | ${rule.threshold}/${rule.window}s`}
              </p>
            </div>
            <div className="flex gap-1">
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 shrink-0"
                onClick={() => startEditRule(index)}
                disabled={editingRuleIndex !== null}
              >
                <IconPencil className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 shrink-0 text-destructive hover:text-destructive"
                onClick={() => deleteRule(index)}
                disabled={editingRuleIndex !== null}
              >
                <IconTrash className="h-4 w-4" />
              </Button>
            </div>
          </div>
        ))}
      </div>

      {/* 编辑/新增规则面板 */}
      {editingRule !== null && (
        <div className="space-y-4 rounded-lg border-2 border-primary/30 bg-muted/20 p-4">
          <h4 className="text-sm font-medium">
            {editingRuleIndex === -1
              ? t("ccProtection.addRule")
              : t("ccProtection.editRule")}
          </h4>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>{t("ccProtection.ruleName")}</Label>
              <Input
                value={editingRule.name ?? ""}
                onChange={(e) =>
                  setEditingRule({ ...editingRule, name: e.target.value })
                }
                placeholder={t("ccProtection.ruleNamePlaceholder")}
              />
            </div>
            <div className="space-y-1.5">
              <Label>{t("ccProtection.action")}</Label>
              <Select
                value={editingRule.action}
                onValueChange={(v) =>
                  setEditingRule({
                    ...editingRule,
                    action: v,
                    captcha_type:
                      v === "captcha" || v === "captcha_challenge"
                        ? editingRule.captcha_type
                        : "",
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CC_ACTION_OPTIONS.map((action) => (
                    <SelectItem key={action} value={action}>
                      {t(`ccProtection.action_${action}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {(editingRule.action === "captcha" ||
              editingRule.action === "captcha_challenge") && (
              <div className="space-y-1.5">
                <Label>{t("rules.captchaTypeLabel", "验证码类型")}</Label>
                <Select
                  value={editingRule.captcha_type || "inherit"}
                  onValueChange={(value) =>
                    setEditingRule({
                      ...editingRule,
                      captcha_type:
                        value === "inherit" ? "" : (value as CaptchaType),
                    })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="inherit">
                      {t("rules.captchaTypeInherit", "继承全局")}
                    </SelectItem>
                    <SelectItem value="math">
                      {t("rules.captchaType.math", "数学")}
                    </SelectItem>
                    <SelectItem value="click">
                      {t("rules.captchaType.click", "点选")}
                    </SelectItem>
                    <SelectItem value="slide">
                      {t("rules.captchaType.slide", "滑块")}
                    </SelectItem>
                    <SelectItem value="rotate">
                      {t("rules.captchaType.rotate", "旋转")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="flex items-center justify-between">
              <Label>{t("ccProtection.conditions")}</Label>
              <span className="text-[11px] text-muted-foreground">
                {t("ccRulesEditor.atLeastOneCondition")}
              </span>
            </div>

            <div className="space-y-0">
              {editingRule.conditions.map((cond, condIndex) => (
                <div key={condIndex}>
                  {condIndex > 0 && (
                    <div className="relative flex h-6 items-center justify-center">
                      <div className="absolute top-0 left-1/2 h-full w-px -translate-x-1/2 bg-teal-300/60 dark:bg-teal-700/50" />
                      <Badge
                        variant="outline"
                        className="relative z-10 h-5 border-teal-400/60 bg-teal-50 px-2 text-[10px] font-semibold tracking-wider text-teal-700 dark:border-teal-600/60 dark:bg-teal-950/40 dark:text-teal-300"
                      >
                        {t("ccRulesEditor.andConnector")}
                      </Badge>
                    </div>
                  )}
                  <div className="rounded-md border bg-background/60 p-3 shadow-sm dark:bg-background/40">
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-[9rem_9rem_1fr_auto] sm:items-end">
                      <div className="space-y-1">
                        <Label className="text-[11px] text-muted-foreground">
                          {t("ccRulesEditor.matchTarget")}
                        </Label>
                        <Select
                          value={cond.target}
                          onValueChange={(v) =>
                            updateEditingCondition(condIndex, "target", v)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {CC_CONDITION_TARGETS.map((target) => (
                              <SelectItem key={target} value={target}>
                                {t(`ccProtection.target_${target}`)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-[11px] text-muted-foreground">
                          {t("ccRulesEditor.matchOperator")}
                        </Label>
                        <Select
                          value={cond.operator}
                          onValueChange={(v) =>
                            updateEditingCondition(condIndex, "operator", v)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {(
                              CC_CONDITION_OPERATORS[cond.target] ?? ["equals"]
                            ).map((op) => (
                              <SelectItem key={op} value={op}>
                                {t(`ccProtection.operator_${op}`)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-[11px] text-muted-foreground">
                          {t("ccRulesEditor.matchValue")}
                        </Label>
                        <Input
                          value={cond.value}
                          onChange={(e) =>
                            updateEditingCondition(
                              condIndex,
                              "value",
                              e.target.value
                            )
                          }
                          placeholder={
                            cond.target === "header"
                              ? "Header-Name:value"
                              : cond.target === "method"
                                ? "GET"
                                : "/path"
                          }
                        />
                      </div>
                      <div className="flex items-end justify-end sm:pb-0.5">
                        {editingRule.conditions.length > 1 ? (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 shrink-0 text-destructive hover:text-destructive"
                            onClick={() => removeEditingCondition(condIndex)}
                            aria-label={t("ccRulesEditor.deleteCondition")}
                          >
                            <IconTrash className="h-4 w-4" />
                          </Button>
                        ) : (
                          <div className="h-8 w-8" />
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <Button
              variant="outline"
              size="sm"
              className="h-8 w-full gap-1 border-dashed border-teal-400/60 text-xs text-teal-700 hover:bg-teal-50 hover:text-teal-800 dark:border-teal-600/60 dark:text-teal-300 dark:hover:bg-teal-950/30"
              onClick={addEditingCondition}
            >
              <IconPlus className="h-3.5 w-3.5" />
              {t("ccRulesEditor.addAndCondition")}
            </Button>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label>{t("ccProtection.ruleWindow")}</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={0}
                  value={editingRule.window}
                  onChange={(e) =>
                    setEditingRule({
                      ...editingRule,
                      window: Number(e.target.value),
                    })
                  }
                />
                <span className="text-sm text-muted-foreground">
                  {t("ccProtection.seconds")}
                </span>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>{t("ccProtection.ruleThreshold")}</Label>
              <Input
                type="number"
                min={0}
                value={editingRule.threshold}
                onChange={(e) =>
                  setEditingRule({
                    ...editingRule,
                    threshold: Number(e.target.value),
                  })
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label>{t("ccProtection.ruleDuration")}</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={0}
                  value={editingRule.duration}
                  onChange={(e) =>
                    setEditingRule({
                      ...editingRule,
                      duration: Number(e.target.value),
                    })
                  }
                />
                <Select
                  value={editingRule.duration_unit ?? "minutes"}
                  onValueChange={(v) =>
                    setEditingRule({
                      ...editingRule,
                      duration_unit: v as "seconds" | "minutes",
                    })
                  }
                >
                  <SelectTrigger className="w-28 shrink-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="seconds">
                      {t("ccProtection.seconds")}
                    </SelectItem>
                    <SelectItem value="minutes">
                      {t("ccProtection.minutes")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <div className="flex justify-end gap-2">
            <Button variant="outline" size="sm" onClick={cancelEditRule}>
              {t("common.cancel")}
            </Button>
            <Button size="sm" onClick={saveEditRule}>
              {t("common.confirm")}
            </Button>
          </div>
        </div>
      )}

      {editingRuleIndex === null && (
        <Button
          variant="outline"
          size="sm"
          className="gap-1"
          onClick={startAddRule}
        >
          <IconPlus className="h-3.5 w-3.5" />
          {t("ccProtection.addRule")}
        </Button>
      )}
    </div>
  )
}
