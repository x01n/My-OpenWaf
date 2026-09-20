"use client"

import { useTranslation } from "react-i18next"
import { Badge } from "@/components/ui/badge"
import type { AccessLog } from "@/lib/types"
import { cn } from "@/lib/utils"

type AccessLogOriginFields = Pick<
  AccessLog,
  "status_code" | "waf_action" | "upstream"
>

type AccessLog429Origin = "waf_rate_limit" | "upstream_429"

/**
 * 仅识别已有运行证据能够严格区分的两种 HTTP 429 来源。
 * 其他字段组合不生成来源标签，避免把状态码来源推断为 WAF 动作。
 */
export function getAccessLog429Origin(
  log: AccessLogOriginFields
): AccessLog429Origin | null {
  if (log.status_code !== 429) return null
  if (log.waf_action === "rate_limit") return "waf_rate_limit"
  if (log.waf_action === "none" && Boolean(log.upstream)) {
    return "upstream_429"
  }
  return null
}

/** 为可明确归因的 429 响应展示来源徽章。 */
export function AccessLogOriginBadge({
  log,
  className,
}: {
  log: AccessLogOriginFields
  className?: string
}) {
  const { t } = useTranslation()
  const origin = getAccessLog429Origin(log)

  if (!origin) return null

  return (
    <Badge
      variant="outline"
      className={cn(
        "h-5 px-1.5 text-[10px]",
        origin === "waf_rate_limit"
          ? "border-amber-500/30 bg-amber-500/12 text-amber-700 dark:border-amber-400/30 dark:bg-amber-400/15 dark:text-amber-300"
          : "border-violet-500/30 bg-violet-500/12 text-violet-700 dark:border-violet-400/30 dark:bg-violet-400/15 dark:text-violet-300",
        className
      )}
    >
      {origin === "waf_rate_limit"
        ? t("accessLogs.sourceWafRateLimit")
        : t("accessLogs.sourceUpstream429")}
    </Badge>
  )
}
