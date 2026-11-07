"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { IconAdjustmentsHorizontal } from "@tabler/icons-react"
import { EnvOverrideField } from "@/components/env-override-field"
import {
  buildEnvOverridePayload,
  ENV_OVERRIDE_KEY_MAP,
  envOverrideDelegatedTargetKey,
  isEnvOverrideReadOnly,
  type EnvOverrideKeySpec,
} from "@/lib/env-override"
import {
  envOverrideItemsOfGroup,
  envOverrideItemsOfKeys,
  useEnvOverrides,
} from "@/hooks/use-env-overrides"
import type { EnvOverrideGroupKey, EnvOverrideItem } from "@/lib/types"

/** 需要渲染的域标识；顺序由调用方给定。 */
export interface EnvOverrideCardProps {
  /** 域标识（按域渲染时使用）。 */
  group: EnvOverrideGroupKey
  /** 该域的中文/英文标题 key，取自后端 groups[]。 */
  labelKey: string
  /** 可选的卡片描述 key；省略时按只读与否取默认文案。 */
  descriptionKey?: string
  /** 仅渲染这些键；为空或省略时渲染整域。 */
  keys?: readonly string[]
  /** 全量条目（组件自行按域或键清单筛选）。 */
  items: readonly EnvOverrideItem[]
  /** 当前角色是否可写。 */
  canManage: boolean
  /** 保存中标记。 */
  saving: boolean
  /** 提交覆盖与清除。 */
  onSave: (payload: {
    overrides: Record<string, string | number | boolean>
    clear: string[]
  }) => Promise<unknown>
}

/**
 * 单个域（或域内若干键）的环境变量覆盖卡片。
 *
 * 草稿与 dirty 集合都收敛在卡内：每张卡独立保存，避免一个域的改动
 * 被另一个域的失败回滚牵连。只读域（bootstrap / internal，或整域都是
 * delegated 键的 http3）不渲染保存按钮，整卡只展示生效值；领域页可用
 * keys 只取本域相关的几个键。
 */
export function EnvOverrideCard({
  group,
  labelKey,
  descriptionKey,
  keys,
  items,
  canManage,
  saving,
  onSave,
}: EnvOverrideCardProps) {
  const { t } = useTranslation()
  const [drafts, setDrafts] = useState<Record<string, string | boolean>>({})
  const [dirty, setDirty] = useState<ReadonlySet<string>>(new Set())

  const groupItems = useMemo(
    () =>
      keys && keys.length > 0
        ? envOverrideItemsOfKeys(items, keys)
        : envOverrideItemsOfGroup(items, group),
    [items, group, keys]
  )
  const editable = useMemo(
    () => groupItems.filter((item) => !isEnvOverrideReadOnly(item)),
    [groupItems]
  )
  const readonly = groupItems.length > 0 && editable.length === 0
  /**
   * 只读域里是否每个键都有「本页旁边的专用入口」。
   *
   * 只读域分两种：`bootstrap` / `test_only` 只能靠环境变量，原文案准确；
   * `delegated` 能改，只是写入口在专用端点。整域都是 delegated 时用
   * `delegatedGroupDesc`，否则保留 `readOnlyGroupDesc`——混合域下原文案
   * 对 bootstrap 键仍然成立，而指引由逐行的 delegated 行自带。
   */
  const allDelegated =
    readonly &&
    groupItems.every((item) => envOverrideDelegatedTargetKey(item) !== null)

  const handleChange = (key: string, value: string | boolean) => {
    setDrafts((prev) => ({ ...prev, [key]: value }))
    setDirty((prev) => {
      const next = new Set(prev)
      next.add(key)
      return next
    })
  }

  const handleSave = async () => {
    if (!canManage || dirty.size === 0) return
    const specs: EnvOverrideKeySpec[] = [...dirty]
      .map((key) => ENV_OVERRIDE_KEY_MAP[key])
      .filter((spec): spec is EnvOverrideKeySpec => Boolean(spec))
    const payload = buildEnvOverridePayload(specs, drafts, dirty)
    if (
      Object.keys(payload.overrides).length === 0 &&
      payload.clear.length === 0
    ) {
      return
    }
    try {
      await onSave(payload)
      setDrafts({})
      setDirty(new Set())
      toast.success(t("envOverrides.saveSuccess"))
    } catch {
      toast.error(t("envOverrides.saveFailed"))
    }
  }

  if (groupItems.length === 0) return null

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t(labelKey)}</CardTitle>
        <CardDescription>
          {t(
            descriptionKey ??
              (allDelegated
                ? "envOverrides.delegatedGroupDesc"
                : readonly
                  ? "envOverrides.readOnlyGroupDesc"
                  : "envOverrides.groupDesc")
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 lg:grid-cols-2">
          {groupItems.map((item) => (
            <EnvOverrideField
              key={item.key}
              item={item}
              draft={drafts[item.key]}
              dirty={dirty.has(item.key)}
              canManage={canManage}
              onChange={handleChange}
            />
          ))}
        </div>
        {!readonly && (
          <div className="flex justify-end">
            <Button
              onClick={handleSave}
              disabled={!canManage || saving || dirty.size === 0}
            >
              {saving ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/** 环境变量覆盖整组卡片：一次性渲染给定域，共用一个数据源。 */
export interface EnvOverrideSectionProps {
  groups: readonly EnvOverrideGroupKey[]
  items: readonly EnvOverrideItem[]
  groupLabels: Record<string, string>
  isLoading: boolean
  error: Error | null
  canManage: boolean
  saving: boolean
  onSave: EnvOverrideCardProps["onSave"]
}

/**
 * 环境变量覆盖分区。
 *
 * 供 settings 页与其他领域页复用：调用方只给「要渲染哪些域」与数据源，
 * 其余（筛选、草稿、保存）由单卡负责。
 */
export function EnvOverrideSection({
  groups,
  items,
  groupLabels,
  isLoading,
  error,
  canManage,
  saving,
  onSave,
}: EnvOverrideSectionProps) {
  const { t } = useTranslation()

  if (isLoading) {
    return <Skeleton className="h-48 w-full" />
  }
  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
        <AlertDescription>
          {error.message || t("error.unexpectedError")}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <>
      {groups.map((group) => (
        <EnvOverrideCard
          key={group}
          group={group}
          labelKey={groupLabels[group] ?? `envOverrides.group.${group}`}
          items={items}
          canManage={canManage}
          saving={saving}
          onSave={onSave}
        />
      ))}
    </>
  )
}

/** 单个领域页内嵌卡片的属性：自取数据源，只渲染指定键。 */
export interface EnvOverrideDomainCardProps {
  /** 卡片标题的 i18n key。 */
  titleKey: string
  /** 卡片描述的 i18n key。 */
  descriptionKey: string
  /** 该页要渲染的域（决定域的默认标签）。 */
  group: EnvOverrideGroupKey
  /** 该页要渲染的键清单。 */
  keys: readonly string[]
  /**
   * 当前角色是否可写。
   *
   * 注意这与页面的 `canManage` 往往是两个口径：env 覆盖的写端点挂在
   * adminGroup（仅 admin），而领域页自身的表单可能允许 operator，
   * 因此调用方应传独立算出的「仅 admin」门控。
   */
  canManage: boolean
  /** 是否发起读取（未登录或整页只读时置 false）。 */
  enabled?: boolean
}

/**
 * 领域页内嵌的环境变量覆盖卡片。
 *
 * 与 settings 页的 EnvOverrideSection 共用同一数据源（SWR 缓存键
 * `env-overrides`），因此跨页不会重复请求；卡片只渲染本页相关的键。
 */
export function EnvOverrideDomainCard({
  titleKey,
  descriptionKey,
  group,
  keys,
  canManage,
  enabled = true,
}: EnvOverrideDomainCardProps) {
  const { t } = useTranslation()
  const { items, groups, isLoading, error, save, saving } =
    useEnvOverrides(enabled)
  const labelKey =
    groups.find((entry) => entry.key === group)?.label_key ??
    `envOverrides.group.${group}`

  return (
    <section className="space-y-3">
      <div className="flex items-center gap-2">
        <IconAdjustmentsHorizontal className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">{t(titleKey)}</h2>
      </div>
      <p className="text-sm text-muted-foreground">{t(descriptionKey)}</p>
      <EnvOverrideCard
        group={group}
        labelKey={labelKey}
        keys={keys}
        items={items}
        canManage={canManage}
        saving={saving}
        onSave={save}
      />
      {isLoading ? null : error ? (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {error.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      ) : null}
    </section>
  )
}