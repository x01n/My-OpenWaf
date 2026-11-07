"use client"

import { useCallback, useMemo, useState } from "react"
import useSWR, { mutate } from "swr"
import { runtimeApi } from "@/lib/api"
import { ENV_OVERRIDE_KEYS, ENV_OVERRIDE_KEY_MAP } from "@/lib/env-override"
import type {
  EnvOverrideGroupKey,
  EnvOverrideItem,
  EnvOverridesUpdate,
} from "@/lib/types"

/** 该视图的 SWR 缓存键前缀。 */
export const ENV_OVERRIDES_KEY = "env-overrides"

/**
 * 按域筛选键注册表。
 *
 * 注册表是前端侧的镜像，只用于决定「哪些键渲染在哪张卡上」；每个键的
 * 权威状态（生效值、来源、只读与否）一律取自后端 items。
 *
 * @param group 域标识
 * @returns 该域下的键注册表条目
 */
export function envOverrideKeysOfGroup(group: EnvOverrideGroupKey) {
  return ENV_OVERRIDE_KEYS.filter((spec) => spec.group === group)
}

/**
 * 从后端 items 中取出某域的全部条目，并按注册表顺序排列。
 *
 * 后端可能返回前端注册表里没有的键（版本不一致）；这里以注册表为准
 * 过滤，避免渲染出无标签的裸键。
 *
 * @param items 后端返回的全部条目
 * @param group 域标识
 * @returns 该域下的条目
 */
export function envOverrideItemsOfGroup(
  items: readonly EnvOverrideItem[],
  group: EnvOverrideGroupKey
): EnvOverrideItem[] {
  const byKey = new Map(items.map((item) => [item.key, item]))
  return envOverrideKeysOfGroup(group)
    .map((spec) => byKey.get(spec.key))
    .filter((item): item is EnvOverrideItem => Boolean(item))
}

/**
 * 从后端 items 中取出指定键的条目，并按注册表顺序排列。
 *
 * 领域页只关心本域的几个键（例如 CVE 页只渲染 CVE 相关键），因此提供
 * 按显式键清单筛选的入口。
 *
 * @param items 后端返回的全部条目
 * @param keys 需要渲染的键清单
 * @returns 命中的条目
 */
export function envOverrideItemsOfKeys(
  items: readonly EnvOverrideItem[],
  keys: readonly string[]
): EnvOverrideItem[] {
  const byKey = new Map(items.map((item) => [item.key, item]))
  return keys
    .map((key) => byKey.get(key))
    .filter((item): item is EnvOverrideItem => Boolean(item))
}

/**
 * 环境变量覆盖数据源。
 *
 * 读走 SWR（缓存键 `env-overrides`），写走 POST 并直接用响应刷新本地
 * 状态——后端返回的就是写后回读的完整快照，无需再发一次 GET。
 *
 * @param enabled 为 false 时不发请求（未登录或当前页无权限时）
 * @returns items / groups / 加载态 / 错误 / 保存函数 / 保存中标记
 */
export function useEnvOverrides(enabled = true) {
  const { data, isLoading, error, mutate: revalidate } = useSWR(
    enabled ? [ENV_OVERRIDES_KEY] : null,
    () => runtimeApi.getEnvOverrides(),
    { revalidateOnFocus: false }
  )
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<Error | null>(null)

  const items = useMemo(() => data?.items ?? [], [data])
  const groups = useMemo(() => data?.groups ?? [], [data])

  /**
   * 提交覆盖与清除；成功后把响应写入 SWR 缓存，失败时抛回给调用方。
   *
   * @param payload 覆盖表与清除键清单
   * @returns 写后回读的完整快照
   */
  const save = useCallback(
    async (payload: EnvOverridesUpdate) => {
      setSaving(true)
      setSaveError(null)
      try {
        const next = await runtimeApi.updateEnvOverrides(payload)
        await mutate([ENV_OVERRIDES_KEY], next, { revalidate: false })
        // 覆盖会影响其他只读视图展示的生效值，写后让它们重新取一次。
        await mutate((key) => Array.isArray(key) && key[0] === "runtime-config")
        return next
      } catch (err) {
        setSaveError(err as Error)
        throw err
      } finally {
        setSaving(false)
      }
    },
    []
  )

  return {
    items,
    groups,
    isLoading: enabled && isLoading,
    error: (error as Error | undefined) ?? null,
    saveError,
    revalidate,
    save,
    saving,
  }
}

/**
 * 按注册表键名取单个条目的类型信息，供控件渲染。
 *
 * @param key 稳定键名
 * @returns 注册表条目；未登记时返回 undefined
 */
export function envOverrideSpec(key: string) {
  return ENV_OVERRIDE_KEY_MAP[key]
}