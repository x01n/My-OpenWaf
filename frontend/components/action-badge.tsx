"use client"

import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import { actionBadgeClass, hasActionLabel } from "@/lib/action-style"
import { useTranslation } from "react-i18next"

/**
 * @typedef {object} ActionBadgeProps
 * @property {string | null | undefined} action 后端返回的 WAF 动作名（drop/intercept/challenge/observe/...）
 * @property {string} [fallback] action 为空时展示的占位文本，默认 "-"
 * @property {string} [className] 附加类名
 */
export interface ActionBadgeProps {
  action?: string | null
  fallback?: string
  className?: string
}

/**
 * WAF 动作徽章：颜色按后端终端优先级语义分级，文案走 i18n。
 * 未知动作保持中性色并原样回显，避免误导为“已拦截”。
 */
export function ActionBadge({
  action,
  fallback = "-",
  className,
}: ActionBadgeProps) {
  const { t } = useTranslation()

  if (!action) {
    return <span className="text-muted-foreground">{fallback}</span>
  }

  const label = hasActionLabel(action)
    ? t(`securityEvents.action.${action.toLowerCase()}`)
    : action

  return (
    <Badge
      variant="outline"
      className={cn("font-medium", actionBadgeClass(action), className)}
    >
      {label}
    </Badge>
  )
}
