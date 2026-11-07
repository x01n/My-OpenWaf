"use client"

import { useTranslation } from "react-i18next"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { cn } from "@/lib/utils"
import {
  ENV_OVERRIDE_KEY_MAP,
  envOverrideDelegatedTargetKey,
  hasEnvOverrideEnvName,
  isEnvOverrideFromDefault,
  isEnvOverrideFromEnv,
  isEnvOverrideReadOnly,
  isEnvOverrideSensitive,
  type EnvOverrideValueType,
} from "@/lib/env-override"
import type { EnvOverrideItem } from "@/lib/types"

/** 单键控件的属性。 */
export interface EnvOverrideFieldProps {
  /** 后端返回的键状态（含生效值、来源、只读与敏感标记）。 */
  item: EnvOverrideItem
  /** 本地草稿；undefined 表示未改动，控件回落到生效值。 */
  draft: string | boolean | undefined
  /** 用户是否改过该键（决定是否显示「未保存」标识）。 */
  dirty: boolean
  /** 当前角色是否可写；false 时控件只读。 */
  canManage: boolean
  /** 草稿变更回调。 */
  onChange: (key: string, value: string | boolean) => void
}

/**
 * 判断条目当前处于逐键三态的哪一态，并附上本地未保存标识。
 *
 * 三枚来源徽章互斥且穷尽：`已覆盖`（覆盖表里有该键，DB 胜）、`ENV`（跟随
 * 环境变量）、`默认`（既没覆盖也没有可用的环境变量，跟随内置默认值）。
 * `未保存` 与来源徽章正交：它只表示本页改过、尚未提交。
 *
 * @param item 后端返回的键条目
 * @param dirty 本地是否改过
 * @returns 状态标识集合
 */
function statusBadges(
  item: EnvOverrideItem,
  dirty: boolean
): Array<"unsaved" | "overridden" | "env" | "default"> {
  const badges: Array<"unsaved" | "overridden" | "env" | "default"> = []
  if (dirty) badges.push("unsaved")
  if (item.overridden) badges.push("overridden")
  else if (isEnvOverrideFromEnv(item)) badges.push("env")
  else if (isEnvOverrideFromDefault(item)) badges.push("default")
  return badges
}

/**
 * 解析条目最终参与渲染的类型。
 *
 * 优先用前端注册表（契约镜像），注册表未登记时回落到后端 item.type，
 * 保证「后端新增键但前端注册表未同步」这种半成品状态也不会渲染成空白。
 *
 * @param item 后端返回的键条目
 * @returns 用于分支的类型
 */
function resolveValueType(item: EnvOverrideItem): EnvOverrideValueType {
  return ENV_OVERRIDE_KEY_MAP[item.key]?.type ?? item.type
}

/**
 * 按类型渲染输入控件。
 *
 * 四种 type 各有独立分支：bool 渲染 Switch，int 渲染带 min/max 的数字
 * 输入，duration 渲染带时长占位的文本输入，其余（string）渲染文本输入；
 * 敏感键在 string 分支内切换到 password 且留空表示不修改。
 *
 * @param type 值类型
 * @param props 渲染所需的上下文
 * @returns 对应类型的控件
 */
function renderControl(
  type: EnvOverrideValueType,
  props: {
    id: string
    readOnly: boolean
    sensitive: boolean
    boolChecked: boolean
    textValue: string
    min: number | null
    max: number | null
    onChange: (value: string | boolean) => void
    labels: {
      durationPlaceholder: string
      sensitivePlaceholder: string
      valuePlaceholder: string
      enabled: string
      disabled: string
    }
  }
) {
  switch (type) {
    case "bool":
      return (
        <div className="flex items-center gap-3">
          <Switch
            id={props.id}
            checked={props.boolChecked}
            disabled={props.readOnly}
            onCheckedChange={(checked) => props.onChange(checked)}
          />
          <span className="text-xs text-muted-foreground">
            {props.boolChecked ? props.labels.enabled : props.labels.disabled}
          </span>
        </div>
      )
    case "int":
      return (
        <Input
          id={props.id}
          type="number"
          value={props.textValue}
          min={props.min ?? undefined}
          max={props.max ?? undefined}
          disabled={props.readOnly}
          onChange={(event) => props.onChange(event.target.value)}
        />
      )
    case "duration":
      return (
        <Input
          id={props.id}
          value={props.textValue}
          disabled={props.readOnly}
          placeholder={props.labels.durationPlaceholder}
          onChange={(event) => props.onChange(event.target.value)}
        />
      )
    case "string":
    default:
      return (
        <Input
          id={props.id}
          type={props.sensitive ? "password" : "text"}
          value={props.textValue}
          disabled={props.readOnly}
          autoComplete="off"
          placeholder={
            props.sensitive
              ? props.labels.sensitivePlaceholder
              : props.labels.valuePlaceholder
          }
          onChange={(event) => props.onChange(event.target.value)}
        />
      )
  }
}

/**
 * 单个环境变量覆盖键的控件。
 *
 * 三类状态标识（未保存 / 已覆盖 / 由 env 提供）与只读、敏感分支都在这里
 * 收口，页面只负责摆放与保存。
 *
 * @param props 见 EnvOverrideFieldProps
 */
export function EnvOverrideField({
  item,
  draft,
  dirty,
  canManage,
  onChange,
}: EnvOverrideFieldProps) {
  const { t } = useTranslation()
  const readOnly = isEnvOverrideReadOnly(item) || !canManage
  const sensitive = isEnvOverrideSensitive(item.key) || item.sensitive
  const badges = statusBadges(item, dirty)
  const label = t(item.label_key)
  const description = t(item.description_key)
  const valueType = resolveValueType(item)
  // 只读键并不都是「只能靠环境变量」：delegated 键的写入口在本页的专用卡片里。
  const delegatedTargetKey = envOverrideDelegatedTargetKey(item)

  /** 只读行：直接回显生效值，不渲染输入控件。 */
  if (isEnvOverrideReadOnly(item)) {
    return (
      <div className="space-y-1 rounded-lg border bg-muted/30 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{label}</span>
          <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
            {t("envOverrides.readOnly")}
          </Badge>
          {badges.map((badge) => (
            <Badge
              key={badge}
              variant={badge === "env" ? "secondary" : "outline"}
              className="h-5 px-1.5 text-[10px]"
            >
              {t(`envOverrides.badge.${badge}`)}
            </Badge>
          ))}
        </div>
        <code className="block text-xs break-all text-muted-foreground">
          {sensitive
            ? t("envOverrides.maskedValue")
            : String(item.effective_value ?? t("envOverrides.emptyValue"))}
        </code>
        <p className="text-xs text-muted-foreground">{description}</p>
        {/* delegated 键的写入口不在本卡片：指名本页的哪张卡，不暴露端点路径。 */}
        {delegatedTargetKey && (
          <p className="text-xs text-primary">
            {t("envOverrides.delegatedHint", { target: t(delegatedTargetKey) })}
          </p>
        )}
        {/* 无环境变量载体的键（env 为空串）不展示空的环境变量名。 */}
        {hasEnvOverrideEnvName(item) && (
          <code className="block text-[11px] text-muted-foreground">
            {item.env}
          </code>
        )}
      </div>
    )
  }

  const boolChecked =
    typeof draft === "boolean"
      ? draft
      : Boolean(item.effective_value ?? item.value ?? item.default_value)
  // 敏感键留空即不修改：输入框初始为空，用户输入新值才进入草稿。
  const textValue =
    typeof draft === "string"
      ? draft
      : sensitive
        ? ""
        : String(item.effective_value ?? "")

  return (
    <div
      className={cn(
        "space-y-2 rounded-lg border p-3",
        dirty && "border-primary/40 bg-primary/5"
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor={`env-override-${item.key}`} className="text-sm">
          {label}
        </Label>
        {badges.map((badge) => (
          <Badge
            key={badge}
            variant={badge === "env" ? "secondary" : "outline"}
            className="h-5 px-1.5 text-[10px]"
          >
            {t(`envOverrides.badge.${badge}`)}
          </Badge>
        ))}
        {/* 启动固化类键改完不重启不生效，与「已覆盖」徽章并列打标。 */}
        {item.restart_required && (
          <Badge
            variant="outline"
            className="h-5 border-amber-500/50 px-1.5 text-[10px] text-amber-700 dark:text-amber-300"
          >
            {t("envOverrides.badge.restart")}
          </Badge>
        )}
        {/* 布尔键的开关只有两个状态，无法表达「回到 unset」，
            因此单独给出清除动作（写入空字符串草稿）。 */}
        {(item.overridden || dirty) && !readOnly && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-[11px]"
            onClick={() => onChange(item.key, "")}
          >
            {t("envOverrides.clearOverride")}
          </Button>
        )}
      </div>

      {renderControl(valueType, {
        id: `env-override-${item.key}`,
        readOnly,
        sensitive,
        boolChecked,
        textValue,
        min: item.min,
        max: item.max,
        onChange: (value) => onChange(item.key, value),
        labels: {
          durationPlaceholder: t("envOverrides.durationPlaceholder"),
          sensitivePlaceholder: t("envOverrides.sensitivePlaceholder"),
          valuePlaceholder: t("envOverrides.valuePlaceholder"),
          enabled: t("common.enabled"),
          disabled: t("common.disabled"),
        },
      })}

      {sensitive && (
        <p className="text-xs text-muted-foreground">
          {item.overridden
            ? t("envOverrides.sensitiveSet")
            : t("envOverrides.sensitiveUnset")}
        </p>
      )}
      <p className="text-xs text-muted-foreground">{description}</p>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
        {hasEnvOverrideEnvName(item) && <code>{item.env}</code>}
        <span>
          {t("envOverrides.effectiveValue")}:{" "}
          {sensitive
            ? t("envOverrides.maskedValue")
            : String(item.effective_value ?? t("envOverrides.emptyValue"))}
        </span>
        {item.min !== null || item.max !== null ? (
          <span>
            {t("envOverrides.range", {
              min: item.min ?? "-",
              max: item.max ?? "-",
            })}
          </span>
        ) : null}
      </div>
      {isEnvOverrideFromEnv(item) && (
        <p className="text-[11px] text-amber-700 dark:text-amber-300">
          {t("envOverrides.envHint")}
        </p>
      )}
      {/* 启动固化类键：保存进覆盖表后要等进程重启才会被读入。 */}
      {item.restart_required && (
        <p className="text-[11px] text-amber-700 dark:text-amber-300">
          {t("envOverrides.restartHint")}
        </p>
      )}
    </div>
  )
}