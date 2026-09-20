"use client"

import { useMemo } from "react"
import { useTranslation } from "react-i18next"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Skeleton } from "@/components/ui/skeleton"
import { StatCard } from "@/components/stat-card"
import { useBotScores, useBotStats, useDropStats } from "@/hooks/use-api"
import { formatRelative } from "@/lib/time-format"
import {
  IconAlertTriangle,
  IconChartBar,
  IconRobot,
  IconShieldX,
} from "@tabler/icons-react"
import type {
  BotScoreListResponse,
  BotScoreLog,
} from "@/lib/types"

/** 表格行：以请求维度精简，镜像后端 BotScoreLog JSON 字段名。 */
interface BotScoreTableRow {
  row_id: number
  client_ip: string
  host_path: string
  total_score: number
  score_bits: string
  action: string
  is_high_risk: boolean
  created_at: string
}

/** 数值小数值舍入展示；NaN/缺省时降级为占位符。 */
function roundStat(value: number | undefined | null): string {
  if (value == null || !Number.isFinite(value)) return "-"
  return Math.round(value).toString()
}

/** 简化 bot 评分记录为表格行，缺失字段回退为占位符。 */
function toTableRows(
  data: BotScoreListResponse | undefined
): BotScoreTableRow[] {
  return (data?.items ?? []).map((row: BotScoreLog) => ({
    row_id: row.id,
    client_ip: row.client_ip || "-",
    host_path: `${row.host || "-"}${row.path || "/"}`,
    total_score: row.total_score,
    score_bits: [
      roundStat(row.geoip_score),
      roundStat(row.fingerprint_score),
      roundStat(row.behavior_score),
      roundStat(row.ip_rep_score),
    ].join(" · "),
    action: row.action || "-",
    is_high_risk: Boolean(row.is_high_risk),
    created_at: row.created_at || "-",
  }))
}

/** 动作徽章色调：分值越高越趋向危险色，避免未命中动作标签时误读状态。 */
function scoreBadgeClass(score: number): string {
  if (score >= 80)
    return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
  if (score >= 50)
    return "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
  return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
}

/** toast 错误提示使用的动作名按 action-style 的映射集中翻译。 */
function actionLabelKey(action: string): string {
  return `securityEvents.action.${action.toLowerCase()}`
}

/**
 * Bot 观测卡片：24 小时聚合统计 + 最近高风险客户端 + TCP Drop 归因。
 *
 * 后端契约：
 * - GET /api/v1/bot-stats（internal/admin/router.go:181，
 *   repository.BotScoreStats 聚合 24 小时 total/blocked/high_risk/avg）。
 * - GET /api/v1/bot-scores?high_risk=true&page_size=10（router.go:182，
 *   bot_score.go List 按 id DESC 返回最近记录）。
 * - GET /api/v1/drop-stats（router.go:207，DropStatsSummary 按 source 分桶）。
 *
 * 统计卡使用后端真实聚合值；列表无本地占位数据。
 */
export function BotObservationCard() {
  const { t } = useTranslation()
  const {
    data: stats,
    error: statsError,
    isLoading: statsLoading,
  } = useBotStats()
  const {
    data: scores,
    error: scoresError,
    isLoading: scoresLoading,
  } = useBotScores({ high_risk: true, page_size: 10 })
  const {
    data: dropStats,
    error: dropError,
    isLoading: dropLoading,
  } = useDropStats()

  const rows = useMemo(() => toTableRows(scores), [scores])
  const hasAnyError = Boolean(statsError || scoresError || dropError)

  const total24h = stats?.total_24h ?? 0
  const blocked24h = stats?.blocked_24h ?? 0
  const highRisk24h = stats?.high_risk_24h ?? 0
  const blockRate =
    total24h > 0
      ? t("captcha.observation.blockRate", {
          percent: Math.round((blocked24h / total24h) * 100),
        })
      : t("captcha.observation.noBlockRate")

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <IconChartBar className="h-5 w-5 text-primary" aria-hidden="true" />
          <CardTitle className="text-base">
            {t("captcha.observation.title")}
          </CardTitle>
        </div>
        <CardDescription>
          {t("captcha.observation.description")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {hasAnyError && (
          <Alert variant="destructive">
            <AlertTitle>{t("captcha.observation.loadFailed")}</AlertTitle>
            <AlertDescription>
              {(statsError as Error | undefined)?.message ||
                (scoresError as Error | undefined)?.message ||
                (dropError as Error | undefined)?.message ||
                t("error.unexpectedError")}
            </AlertDescription>
          </Alert>
        )}

        {statsLoading ? (
          <Skeleton className="h-24 w-full rounded-2xl" />
        ) : (
          <div
            className="grid grid-cols-2 gap-3 xl:grid-cols-4"
            aria-live="polite"
          >
            <StatCard
              compact
              title={t("captcha.observation.total24h")}
              value={total24h}
              icon={<IconRobot className="h-4 w-4" aria-hidden="true" />}
            />
            <StatCard
              compact
              title={t("captcha.observation.blocked24h")}
              value={blocked24h}
              trend="down"
              description={blockRate}
              icon={<IconShieldX className="h-4 w-4" aria-hidden="true" />}
            />
            <StatCard
              compact
              title={t("captcha.observation.highRisk24h")}
              value={highRisk24h}
              trend={highRisk24h > 0 ? "down" : "neutral"}
              icon={
                <IconAlertTriangle className="h-4 w-4" aria-hidden="true" />
              }
            />
            <StatCard
              compact
              title={t("captcha.observation.avgScore24h")}
              value={roundStat(stats?.avg_score_24h)}
              icon={<IconChartBar className="h-4 w-4" aria-hidden="true" />}
            />
          </div>
        )}

        {scoresLoading ? (
          <Skeleton className="h-40 w-full rounded-2xl" />
        ) : (
          <div className="space-y-2">
            <p className="text-[11px] text-muted-foreground">
              {t("captcha.observation.recentHighRisk")}
            </p>

            <div className="overflow-x-auto rounded-xl border">
              <table className="w-full min-w-[760px] text-left text-xs">
                <thead className="bg-muted/50 text-[11px] text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.time")}
                    </th>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.client")}
                    </th>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.request")}
                    </th>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.totalScore")}
                    </th>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.scoreBits")}
                    </th>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.action")}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {rows.map((row) => (
                    <tr key={row.row_id}>
                      <td className="px-3 py-2 font-mono whitespace-nowrap">
                        {formatRelative(row.created_at)}
                      </td>
                      <td className="px-3 py-2">
                        <code className="font-mono">{row.client_ip}</code>
                      </td>
                      <td className="px-3 py-2">
                        <code className="block max-w-64 truncate font-mono text-muted-foreground">
                          {row.host_path}
                        </code>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold tabular-nums">
                            {row.total_score}
                          </span>
                          {row.is_high_risk && (
                            <Badge
                              variant="destructive"
                              className="h-5 px-1.5 text-[10px]"
                            >
                              {t("requestTrace.highRisk")}
                            </Badge>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">
                        {row.score_bits}
                      </td>
                      <td className="px-3 py-2">
                        <Badge
                          variant="outline"
                          className={scoreBadgeClass(row.total_score)}
                        >
                          {t(actionLabelKey(row.action), {
                            defaultValue: row.action,
                          })}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {rows.length === 0 && (
                <p className="border-t px-3 py-6 text-center text-xs text-muted-foreground">
                  {t("captcha.observation.noHighRisk")}
                </p>
              )}
            </div>
          </div>
        )}

        {dropLoading ? (
          <Skeleton className="h-24 w-full rounded-2xl" />
        ) : (
          <div className="space-y-2">
            <p className="text-[11px] text-muted-foreground">
              {t("captcha.observation.dropTitle")}
            </p>
            <div className="overflow-x-auto rounded-xl border">
              <table className="w-full min-w-[560px] text-left text-xs">
                <thead className="bg-muted/50 text-[11px] text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.dropSource")}
                    </th>
                    <th className="px-3 py-2 font-medium">
                      {t("captcha.observation.dropCount")}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  <tr>
                    <td className="px-3 py-2">
                      {t("captcha.observation.dropByBot")}
                    </td>
                    <td className="px-3 py-2 font-mono tabular-nums">
                      {dropStats?.by_bot ?? 0}
                    </td>
                  </tr>
                  <tr>
                    <td className="px-3 py-2">
                      {t("captcha.observation.dropByCve")}
                    </td>
                    <td className="px-3 py-2 font-mono tabular-nums">
                      {dropStats?.by_cve ?? 0}
                    </td>
                  </tr>
                  <tr>
                    <td className="px-3 py-2">
                      {t("captcha.observation.dropByRule")}
                    </td>
                    <td className="px-3 py-2 font-mono tabular-nums">
                      {dropStats?.by_rule ?? 0}
                    </td>
                  </tr>
                  <tr>
                    <td className="px-3 py-2">
                      {t("captcha.observation.dropByIpRep")}
                    </td>
                    <td className="px-3 py-2 font-mono tabular-nums">
                      {dropStats?.by_ip_reputation ?? 0}
                    </td>
                  </tr>
                  <tr className="bg-muted/40">
                    <td className="px-3 py-2 font-medium">
                      {t("captcha.observation.dropTotal24h")}
                    </td>
                    <td className="px-3 py-2 font-mono font-medium tabular-nums">
                      {dropStats?.total_24h ?? 0}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
