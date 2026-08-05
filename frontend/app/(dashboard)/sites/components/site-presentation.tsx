"use client"

import * as React from "react"
import Link from "next/link"
import { useTranslation } from "react-i18next"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { cn } from "@/lib/utils"
import type { Site } from "@/lib/types"
import {
  parseSiteListeners,
  parseUpstreamUrls,
  resolveSiteCapabilities,
  resolveSiteMode,
  type SiteCapabilityKey,
  type SiteMode,
} from "@/lib/site-display"
import {
  IconActivity,
  IconArrowRight,
  IconBolt,
  IconDotsVertical,
  IconEdit,
  IconEye,
  IconGauge,
  IconLock,
  IconPlayerPause,
  IconPlayerPlay,
  IconRobot,
  IconShield,
  IconShieldCheck,
  IconTrash,
} from "@tabler/icons-react"

/**
 * 站点行/卡片共用的操作回调。
 */
export interface SiteActionHandlers {
  onEdit: (site: Site) => void
  onToggle: (site: Site) => void
  onDelete: (site: Site) => void
}

/** 防护姿态 -> 徽章样式与图标 */
const MODE_STYLE: Record<
  SiteMode,
  { className: string; icon: typeof IconShield }
> = {
  protection: {
    className:
      "border-emerald-500/30 bg-emerald-500/12 text-emerald-700 dark:border-emerald-400/30 dark:bg-emerald-400/15 dark:text-emerald-300",
    icon: IconShieldCheck,
  },
  observe: {
    className:
      "border-amber-500/30 bg-amber-500/12 text-amber-700 dark:border-amber-400/30 dark:bg-amber-400/15 dark:text-amber-300",
    icon: IconEye,
  },
  maintenance: {
    className:
      "border-slate-500/30 bg-slate-500/12 text-slate-700 dark:border-slate-400/30 dark:bg-slate-400/15 dark:text-slate-300",
    icon: IconPlayerPause,
  },
}

/** 防护姿态 -> i18n key */
const MODE_LABEL: Record<SiteMode, string> = {
  protection: "sites.protectionMode",
  observe: "sites.observeMode",
  maintenance: "sites.maintenanceMode",
}

/**
 * 防护姿态徽章。
 * @param {{ site: Site; className?: string }} props 组件属性
 */
export function SiteModeBadge({
  site,
  className,
}: {
  site: Site
  className?: string
}) {
  const { t } = useTranslation()
  const mode = resolveSiteMode(site)
  const { className: toneClass, icon: Icon } = MODE_STYLE[mode]

  return (
    <Badge
      variant="outline"
      className={cn(
        "h-5 gap-1 px-1.5 text-[11px] font-medium",
        toneClass,
        className
      )}
    >
      <Icon className="size-3" />
      {t(MODE_LABEL[mode])}
    </Badge>
  )
}

/**
 * 运行状态圆点。启用时用脉动绿点，停用时为静态灰点。
 * @param {{ enabled: boolean }} props 组件属性
 */
export function SiteStatusDot({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className="relative flex size-2 shrink-0"
          aria-label={enabled ? t("common.running") : t("common.stopped")}
        >
          {enabled && (
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
          )}
          <span
            className={cn(
              "relative inline-flex size-2 rounded-full",
              enabled ? "bg-emerald-500" : "bg-muted-foreground/40"
            )}
          />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {enabled ? t("common.running") : t("common.stopped")}
      </TooltipContent>
    </Tooltip>
  )
}

/**
 * 监听端口徽章组。
 *
 * 多监听场景下后端列表接口只提供聚合的 TLS 摘要，不含逐条监听的 TLS 状态，
 * 因此此时只展示端口号并附「多监听」标记，不推测每个端口的协议。
 *
 * @param {{ site: Site; max?: number }} props 组件属性
 */
export function SiteListenerBadges({
  site,
  max = 4,
}: {
  site: Site
  max?: number
}) {
  const { t } = useTranslation()
  const listeners = React.useMemo(() => parseSiteListeners(site), [site])
  const isMulti = (site.managed_listener_count ?? 0) > 0

  if (listeners.length === 0) {
    return <span className="text-xs text-muted-foreground">-</span>
  }

  const shown = listeners.slice(0, max)
  const rest = listeners.length - shown.length

  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map((l, i) => (
        <Badge
          key={`${l.bind}-${i}`}
          variant="outline"
          className={cn(
            "h-5 gap-1 px-1.5 font-mono text-[11px] tabular-nums",
            l.scheme === "HTTPS" &&
              "border-emerald-500/30 text-emerald-700 dark:text-emerald-400",
            l.scheme === "HTTP" &&
              "border-sky-500/30 text-sky-700 dark:text-sky-400"
          )}
          title={l.bind}
        >
          {l.scheme && (
            <span className="font-sans text-[9px] font-semibold opacity-70">
              {l.scheme}
            </span>
          )}
          {l.port}
        </Badge>
      ))}
      {rest > 0 && (
        <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
          +{rest}
        </Badge>
      )}
      {isMulti && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge
              variant="ghost"
              className="h-5 px-1 text-[10px] text-muted-foreground"
            >
              {t("sites.multiListener")}
            </Badge>
          </TooltipTrigger>
          <TooltipContent className="max-w-64">
            {t("sites.multiListenerHint")}
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  )
}

/**
 * 上游地址展示：首个地址 + 剩余数量。
 * @param {{ site: Site; className?: string }} props 组件属性
 */
export function SiteUpstream({
  site,
  className,
}: {
  site: Site
  className?: string
}) {
  const { t } = useTranslation()
  const upstreams = React.useMemo(
    () => parseUpstreamUrls(site.upstream_urls),
    [site.upstream_urls]
  )

  if (upstreams.length === 0) {
    return <span className="text-xs text-muted-foreground">-</span>
  }

  return (
    <div className={cn("flex min-w-0 items-center gap-1.5", className)}>
      <IconArrowRight className="size-3.5 shrink-0 text-muted-foreground/60" />
      <span
        className="truncate font-mono text-xs text-foreground/80"
        title={upstreams.join("\n")}
      >
        {upstreams[0]}
      </span>
      {upstreams.length > 1 && (
        <Badge
          variant="secondary"
          className="h-4 shrink-0 px-1.5 text-[10px] tabular-nums"
        >
          {t("sites.upstreamMoreCount", { count: upstreams.length })}
        </Badge>
      )}
    </div>
  )
}

/** 能力标识 -> i18n key */
const CAPABILITY_LABEL: Record<SiteCapabilityKey, string> = {
  bot: "sites.capability.bot",
  cve: "sites.capability.cve",
  rateLimit: "sites.capability.rateLimit",
  cache: "sites.capability.cache",
  antiReplay: "sites.capability.antiReplay",
  dynamic: "sites.capability.dynamic",
  cc: "sites.capability.cc",
}

/**
 * 已显式开启的防护能力徽章组。
 *
 * 只渲染站点上明确开启的能力；`null`（继承全局）不渲染，避免把继承状态
 * 误读成站点自身配置。
 *
 * @param {{ site: Site; max?: number }} props 组件属性
 */
export function SiteCapabilityBadges({
  site,
  max = 4,
}: {
  site: Site
  max?: number
}) {
  const { t } = useTranslation()
  const caps = React.useMemo(() => resolveSiteCapabilities(site), [site])

  if (caps.length === 0) {
    return (
      <span className="text-[11px] text-muted-foreground/70">
        {t("sites.capability.none")}
      </span>
    )
  }

  const shown = caps.slice(0, max)
  const rest = caps.slice(max)

  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map((c) => (
        <Badge
          key={c}
          variant="secondary"
          className="h-5 px-1.5 text-[10px] font-normal text-muted-foreground"
        >
          {t(CAPABILITY_LABEL[c])}
        </Badge>
      ))}
      {rest.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge
              variant="secondary"
              className="h-5 px-1.5 text-[10px] font-normal text-muted-foreground"
            >
              +{rest.length}
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            {rest.map((c) => t(CAPABILITY_LABEL[c])).join(" · ")}
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  )
}

/**
 * 快捷入口定义。
 *
 * 每一项指向站点详情页的一个不同 Tab，取值均来自详情页的 `ALLOWED_TABS` 白名单
 * （`app/(dashboard)/sites/detail/page.tsx`）。
 */
export const QUICK_LINKS: Array<{
  key: string
  tab: string
  icon: typeof IconRobot
  labelKey: string
}> = [
  {
    key: "monitor",
    tab: "monitor",
    icon: IconActivity,
    labelKey: "sites.detail.monitor.tab",
  },
  {
    key: "protection",
    tab: "protection",
    icon: IconShield,
    labelKey: "sites.attackProtection",
  },
  { key: "bot", tab: "rules", icon: IconRobot, labelKey: "sites.detail.rules" },
  { key: "cc", tab: "cc", icon: IconGauge, labelKey: "sites.ccProtection" },
  {
    key: "dynamic",
    tab: "dynamic",
    icon: IconBolt,
    labelKey: "sites.dynamicProtection",
  },
  {
    key: "access",
    tab: "access",
    icon: IconLock,
    labelKey: "sites.accessControl",
  },
]

/**
 * 快捷入口图标条：纯图标 + Tooltip，深链到详情页对应 Tab。
 * @param {{ siteId: number; className?: string }} props 组件属性
 */
export function SiteQuickLinks({
  siteId,
  className,
}: {
  siteId: number
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <div className={cn("flex items-center gap-0.5", className)}>
      {QUICK_LINKS.map((item) => {
        const Icon = item.icon
        const label = t(item.labelKey)
        return (
          <Tooltip key={item.key}>
            <TooltipTrigger asChild>
              <Button
                asChild
                variant="ghost"
                size="icon-xs"
                className="text-muted-foreground hover:bg-primary/10 hover:text-primary"
              >
                <Link
                  href={`/sites/detail/?id=${siteId}&tab=${item.tab}`}
                  aria-label={label}
                >
                  <Icon />
                </Link>
              </Button>
            </TooltipTrigger>
            <TooltipContent>{label}</TooltipContent>
          </Tooltip>
        )
      })}
    </div>
  )
}

/**
 * 站点操作下拉菜单。
 * @param {{ site: Site } & SiteActionHandlers} props 组件属性
 */
export function SiteActionsMenu({
  site,
  onEdit,
  onToggle,
  onDelete,
}: { site: Site } & SiteActionHandlers) {
  const { t } = useTranslation()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon-xs"
          className="shrink-0 text-muted-foreground"
          aria-label={t("sites.moreActions")}
        >
          <IconDotsVertical />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        <DropdownMenuItem asChild>
          <Link href={`/sites/detail/?id=${site.id}`}>
            <IconEye className="mr-2 size-4" />
            {t("common.viewDetail")}
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onEdit(site)}>
          <IconEdit className="mr-2 size-4" />
          {t("common.edit")}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onToggle(site)}>
          {site.enabled ? (
            <>
              <IconPlayerPause className="mr-2 size-4" />
              {t("common.stop")}
            </>
          ) : (
            <>
              <IconPlayerPlay className="mr-2 size-4" />
              {t("common.start")}
            </>
          )}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onClick={() => onDelete(site)}>
          <IconTrash className="mr-2 size-4" />
          {t("common.delete")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
