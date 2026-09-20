"use client"

import { useTranslation } from "react-i18next"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card"
import { MetricStrip } from "@/components/metric-strip"
import { Skeleton } from "@/components/ui/skeleton"
import { cn, formatNumber } from "@/lib/utils"
import { IconAlertTriangle, IconInfoCircle } from "@tabler/icons-react"
import type { LuaPlugin, LuaPluginStat } from "@/lib/types"

/**
 * 判定「持续失败 / 持续超时」所需的最小样本量。
 *
 * 几十次执行里出现一次异常算不出有意义的占比，此时着色只会误导，
 * 所以样本不足时一律按中性呈现，只把原始计数摆出来。
 */
const MIN_RATE_SAMPLE = 100

/**
 * 超时率分级线。
 *
 * 默认超时是 50 ms 挂钟时间，而正常脚本只需一两百微秒，中间三个数量级的余量
 * 会被 GC 停顿、CPU 争抢这类运行时抖动吃掉——项目文档记录的实测结果是 4000 次
 * 连续调用里出现过一次孤立超时（约 0.025%），脚本本身并没有问题。
 * 因此告警线取到该基线的数十倍以上，偶发几次保持中性配色。
 */
const TIMEOUT_WARN_RATE = 0.01
const TIMEOUT_DANGER_RATE = 0.05

/**
 * 失败率分级线。
 *
 * 失败来自 handle 报错、panic、缺少入口函数这类确定性缺陷，不是运行时抖动，
 * 所以阈值比超时更严。
 */
const FAILURE_WARN_RATE = 0.005
const FAILURE_DANGER_RATE = 0.02

/** 占比的语义分级。muted 表示「不下健康结论」，不是「健康」。 */
type RateTone = "muted" | "warning" | "danger"

/** 分级 -> 徽章配色。与本页 STAGE_CLASS 同一套写法，保持浅/深色双向可读。 */
const TONE_CHIP: Record<RateTone, string> = {
  muted: "border-border/70 bg-muted/60 text-muted-foreground",
  warning:
    "border-amber-500/30 bg-amber-500/12 text-amber-700 dark:border-amber-400/30 dark:bg-amber-400/15 dark:text-amber-300",
  danger:
    "border-rose-500/30 bg-rose-500/12 text-rose-700 dark:border-rose-400/30 dark:bg-rose-400/15 dark:text-rose-300",
}

/** 统计索引的键。持久化插件 ID 在数据库内唯一。 */
function statsKey(id: number): string {
  return String(id)
}

/** 按持久化插件 ID 索引的统计表。 */
export type LuaStatsIndex = Map<string, LuaPluginStat>

/**
 * 建立统计索引。
 *
 * @param items 后端返回的统计条目，可为空。
 * @returns 按持久化插件 ID 索引的统计表。
 */
export function buildLuaStatsIndex(
  items: LuaPluginStat[] | undefined
): LuaStatsIndex {
  const index: LuaStatsIndex = new Map()
  for (const item of items || []) {
    index.set(statsKey(item.id), item)
  }
  return index
}

/**
 * 取某个脚本的统计条目。
 *
 * @param index 统计索引。
 * @param plugin 列表行。
 * @returns 命中的统计条目；脚本未载入引擎时为 undefined。
 */
export function lookupLuaStat(
  index: LuaStatsIndex,
  plugin: LuaPlugin
): LuaPluginStat | undefined {
  return index.get(statsKey(plugin.id))
}

/**
 * 占比计算。
 *
 * 总数为 0 或非有限值时返回 null，交由调用方决定如何呈现，
 * 从源头上排除 NaN% 与除零结果。
 */
function rateOf(part: number, total: number): number | null {
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) {
    return null
  }
  return part / total
}

/**
 * 占比格式化。
 *
 * 非零但极小的占比显示为 "<0.01%" 而不是四舍五入成 "0.00%"，
 * 否则会与「一次都没发生」混淆。
 */
function formatRate(rate: number | null): string {
  if (rate === null) return "-"
  if (rate <= 0) return "0%"
  if (rate < 0.0001) return "<0.01%"
  if (rate < 0.01) return `${(rate * 100).toFixed(2)}%`
  if (rate < 0.1) return `${(rate * 100).toFixed(1)}%`
  return `${Math.round(rate * 100)}%`
}

/** 平均耗时格式化。后端给的是浮点毫秒，正常脚本在 0.1~0.2 ms 量级，需要保留小数。 */
function formatAvgMs(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0 ms"
  if (ms < 0.01) return "<0.01 ms"
  if (ms < 1) return `${ms.toFixed(2)} ms`
  if (ms < 10) return `${ms.toFixed(1)} ms`
  return `${Math.round(ms)} ms`
}

/**
 * 占比分级。
 *
 * 样本不足时返回 muted：此时占比不可信，着色属于误导。
 */
function rateTone(
  rate: number | null,
  runs: number,
  warn: number,
  danger: number
): RateTone {
  if (rate === null || rate <= 0) return "muted"
  if (runs < MIN_RATE_SAMPLE) return "muted"
  if (rate >= danger) return "danger"
  if (rate >= warn) return "warning"
  return "muted"
}

/** 单个脚本的健康判定结果。 */
interface LuaHealth {
  failureRate: number | null
  timeoutRate: number | null
  failureTone: RateTone
  timeoutTone: RateTone
  /** 两项中较重的分级，用于汇总告警的严重度 */
  worst: RateTone
}

/**
 * 计算单个脚本的健康分级。
 *
 * @param stat 统计条目。
 * @returns 失败率、超时率及各自的分级。
 */
function evaluateHealth(stat: LuaPluginStat): LuaHealth {
  const failureRate = rateOf(stat.failures, stat.runs)
  const timeoutRate = rateOf(stat.timeouts, stat.runs)
  const failureTone = rateTone(
    failureRate,
    stat.runs,
    FAILURE_WARN_RATE,
    FAILURE_DANGER_RATE
  )
  const timeoutTone = rateTone(
    timeoutRate,
    stat.runs,
    TIMEOUT_WARN_RATE,
    TIMEOUT_DANGER_RATE
  )
  const worst: RateTone =
    failureTone === "danger" || timeoutTone === "danger"
      ? "danger"
      : failureTone === "warning" || timeoutTone === "warning"
        ? "warning"
        : "muted"
  return { failureRate, timeoutRate, failureTone, timeoutTone, worst }
}

/**
 * 运行时统计单元格。
 *
 * 展示的是占比而非单纯的原始计数：孤立的一两次超时保持中性配色，
 * 只有占比越过阈值才着色，避免把运行时抖动渲染成故障。
 *
 * @returns 单元格元素
 */
export function LuaRuntimeStatsCell({
  plugin,
  stat,
  loading,
  unavailable,
}: {
  plugin: LuaPlugin
  /** 该脚本的统计条目；未载入引擎时为 undefined */
  stat?: LuaPluginStat
  /** 统计请求进行中 */
  loading?: boolean
  /** 统计请求失败，无法判断脚本状态 */
  unavailable?: boolean
}) {
  const { t } = useTranslation()

  if (loading) {
    return <Skeleton className="h-4 w-24" />
  }

  if (unavailable) {
    return (
      <span
        className="text-sm text-muted-foreground"
        title={t("luaPlugins.stats.unavailableHint")}
      >
        -
      </span>
    )
  }

  // 停用的脚本不会被编译进引擎，本就没有统计条目；先判 enabled 才不会把
  // 「已停用」误报成「未载入」。反过来若停用后尚未重载、条目仍在，则照实显示计数。
  if (!stat) {
    return plugin.enabled ? (
      <span
        className="text-sm text-muted-foreground"
        title={t("luaPlugins.stats.notLoadedHint")}
      >
        {t("luaPlugins.stats.notLoaded")}
      </span>
    ) : (
      <span
        className="text-sm text-muted-foreground/70"
        title={t("luaPlugins.stats.disabledHint")}
      >
        {t("luaPlugins.stats.disabled")}
      </span>
    )
  }

  if (stat.runs <= 0) {
    return (
      <span
        className="text-sm text-muted-foreground"
        title={t("luaPlugins.stats.neverRunHint")}
      >
        {t("luaPlugins.stats.neverRun")}
      </span>
    )
  }

  const health = evaluateHealth(stat)
  const successes = Math.max(0, stat.runs - stat.failures - stat.timeouts)

  return (
    <HoverCard openDelay={150} closeDelay={80}>
      <HoverCardTrigger asChild>
        <div className="flex w-fit cursor-help flex-wrap items-center gap-1.5">
          <span className="font-mono text-sm tabular-nums">
            {/* 不用 count 作插值名：i18next 会把它当复数计数并去找 _one/_other 变体 */}
            {t("luaPlugins.stats.runsShort", {
              value: formatNumber(stat.runs),
            })}
          </span>
          <span className="font-mono text-xs text-muted-foreground tabular-nums">
            {formatAvgMs(stat.avg_ms)}
          </span>
          {stat.failures > 0 && (
            <Badge
              variant="outline"
              className={cn("font-mono", TONE_CHIP[health.failureTone])}
            >
              {t("luaPlugins.stats.failChip", {
                rate: formatRate(health.failureRate),
              })}
            </Badge>
          )}
          {stat.timeouts > 0 && (
            <Badge
              variant="outline"
              className={cn("font-mono", TONE_CHIP[health.timeoutTone])}
            >
              {t("luaPlugins.stats.timeoutChip", {
                rate: formatRate(health.timeoutRate),
              })}
            </Badge>
          )}
        </div>
      </HoverCardTrigger>
      <HoverCardContent align="end" className="w-80">
        <div className="text-sm font-medium">{stat.name}</div>
        <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
          <dt className="text-muted-foreground">
            {t("luaPlugins.stats.runs")}
          </dt>
          <dd className="text-end font-mono tabular-nums">{stat.runs}</dd>

          <dt className="text-muted-foreground">
            {t("luaPlugins.stats.successes")}
          </dt>
          <dd className="text-end font-mono tabular-nums">
            {successes}
            <span className="ms-1.5 text-muted-foreground">
              {formatRate(rateOf(successes, stat.runs))}
            </span>
          </dd>

          <dt className="text-muted-foreground">
            {t("luaPlugins.stats.failures")}
          </dt>
          <dd className="text-end font-mono tabular-nums">
            {stat.failures}
            <span className="ms-1.5 text-muted-foreground">
              {formatRate(health.failureRate)}
            </span>
          </dd>

          <dt className="text-muted-foreground">
            {t("luaPlugins.stats.timeouts")}
          </dt>
          <dd className="text-end font-mono tabular-nums">
            {stat.timeouts}
            <span className="ms-1.5 text-muted-foreground">
              {formatRate(health.timeoutRate)}
            </span>
          </dd>

          <dt className="text-muted-foreground">{t("luaPlugins.stats.avg")}</dt>
          <dd className="text-end font-mono tabular-nums">
            {formatAvgMs(stat.avg_ms)}
          </dd>
        </dl>
        <p className="mt-2.5 border-t pt-2 text-[11px] leading-snug text-muted-foreground">
          {t("luaPlugins.stats.avgSkewHint")}
        </p>
        {stat.runs < MIN_RATE_SAMPLE && (
          <p className="mt-1.5 text-[11px] leading-snug text-muted-foreground">
            {t("luaPlugins.stats.lowSampleHint", { min: MIN_RATE_SAMPLE })}
          </p>
        )}
      </HoverCardContent>
    </HoverCard>
  )
}

/**
 * 运行时统计汇总条。
 *
 * 数值是后端统计条目的全量求和（该接口不分页），不是当前页局部统计；
 * 统计口径与归零时机由 caption 明确声明，避免被当成历史总量。
 *
 * @returns 汇总条元素
 */
export function LuaRuntimeStatsSummary({
  items,
  loading,
  error,
}: {
  items: LuaPluginStat[] | undefined
  loading?: boolean
  error?: unknown
}) {
  const { t } = useTranslation()

  if (loading) {
    return (
      <Card className="py-0">
        <CardContent className="px-4 py-3">
          <Skeleton className="h-3.5 w-40" />
          <Skeleton className="mt-1.5 h-3 w-72" />
          <div className="mt-3 grid grid-cols-3 gap-x-4 gap-y-3 border-t border-border/60 pt-3 sm:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8">
            {Array.from({ length: 7 }).map((_, i) => (
              <div key={i}>
                <Skeleton className="h-3 w-14" />
                <Skeleton className="mt-1.5 h-4 w-10" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  // 统计只是辅助信息，取不到不代表页面坏了：用低干扰的虚线提示，
  // 不用 destructive Alert，以免看起来像脚本本身出了问题。
  if (error) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-dashed px-4 py-3 text-xs text-muted-foreground">
        <IconInfoCircle className="mt-px h-4 w-4 shrink-0" />
        <span>
          {t("luaPlugins.stats.loadFailed")}
          {(error as Error)?.message ? `（${(error as Error).message}）` : ""}
        </span>
      </div>
    )
  }

  const list = items || []
  const totalRuns = list.reduce((sum, s) => sum + s.runs, 0)
  const totalFailures = list.reduce((sum, s) => sum + s.failures, 0)
  const totalTimeouts = list.reduce((sum, s) => sum + s.timeouts, 0)
  // avg_ms 各自的分母是自己的 runs，汇总必须按次数加权
  const weightedAvgMs =
    totalRuns > 0
      ? list.reduce((sum, s) => sum + s.avg_ms * s.runs, 0) / totalRuns
      : 0

  return (
    <MetricStrip
      title={t("luaPlugins.stats.title")}
      caption={t("luaPlugins.stats.caption")}
      action={
        <Badge variant="outline" className="shrink-0">
          {t("luaPlugins.stats.scopeBadge")}
        </Badge>
      }
      items={[
        {
          label: t("luaPlugins.stats.loadedScripts"),
          value: String(list.length),
          rawValue: list.length,
          hint: t("luaPlugins.stats.loadedScriptsHint"),
        },
        {
          label: t("luaPlugins.stats.runs"),
          value: formatNumber(totalRuns),
          rawValue: totalRuns,
          hint: t("luaPlugins.stats.runsHint"),
        },
        {
          label: t("luaPlugins.stats.failures"),
          value: formatNumber(totalFailures),
          rawValue: totalFailures,
          hint: t("luaPlugins.stats.failuresHint"),
        },
        {
          label: t("luaPlugins.stats.failureRate"),
          value: formatRate(rateOf(totalFailures, totalRuns)),
          rawValue: totalFailures,
          hint: t("luaPlugins.stats.failureRateHint"),
        },
        {
          label: t("luaPlugins.stats.timeouts"),
          value: formatNumber(totalTimeouts),
          rawValue: totalTimeouts,
          hint: t("luaPlugins.stats.timeoutsHint"),
        },
        {
          label: t("luaPlugins.stats.timeoutRate"),
          value: formatRate(rateOf(totalTimeouts, totalRuns)),
          rawValue: totalTimeouts,
          hint: t("luaPlugins.stats.timeoutRateHint"),
        },
        {
          label: t("luaPlugins.stats.avg"),
          value: formatAvgMs(weightedAvgMs),
          rawValue: totalRuns > 0 ? weightedAvgMs : 0,
          hint: t("luaPlugins.stats.avgHint"),
        },
      ]}
    />
  )
}

/**
 * 持续异常告警。
 *
 * 只在占比越过阈值、且样本量足够时才出现，并直接点名脚本——这是「哪个脚本有问题」
 * 的主入口。孤立的偶发超时不会触发，不制造噪声。
 *
 * @returns 告警元素；没有越线脚本时返回 null
 */
export function LuaRuntimeStatsAlert({
  items,
}: {
  items: LuaPluginStat[] | undefined
}) {
  const { t } = useTranslation()

  const flagged = (items || [])
    .map((stat) => ({ stat, health: evaluateHealth(stat) }))
    .filter(({ health }) => health.worst !== "muted")

  if (flagged.length === 0) return null

  const hasDanger = flagged.some(({ health }) => health.worst === "danger")

  return (
    <Alert
      variant={hasDanger ? "destructive" : "default"}
      className={cn(
        !hasDanger &&
          "border-amber-500/40 text-amber-700 dark:border-amber-400/40 dark:text-amber-300"
      )}
    >
      <IconAlertTriangle className="h-4 w-4" />
      <AlertTitle>
        {t("luaPlugins.stats.alertTitle", { total: flagged.length })}
      </AlertTitle>
      <AlertDescription className="space-y-1">
        <span>{t("luaPlugins.stats.alertHint")}</span>
        <ul className="space-y-0.5">
          {flagged.map(({ stat, health }) => (
            <li
              key={statsKey(stat.id)}
              className="font-mono text-xs"
            >
              {stat.name}
              <span className="ms-1.5 text-muted-foreground">
                {t("luaPlugins.stats.alertItem", {
                  runs: stat.runs,
                  failureRate: formatRate(health.failureRate),
                  timeoutRate: formatRate(health.timeoutRate),
                })}
              </span>
            </li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  )
}
