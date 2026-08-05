"use client"

import Link from "next/link"
import { useTranslation } from "react-i18next"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { SiteHoverPreview } from "@/components/site-hover-preview"
import { parseSiteHosts } from "@/lib/site-display"
import type { Site } from "@/lib/types"
import {
  SiteActionsMenu,
  SiteCapabilityBadges,
  SiteListenerBadges,
  SiteModeBadge,
  SiteQuickLinks,
  SiteStatusDot,
  SiteUpstream,
  type SiteActionHandlers,
} from "./site-presentation"

/**
 * 站点列表（表格视图）。
 *
 * 站点数量较多时用它替代卡片网格：一行一站点，横向铺满可用宽度，
 * 单屏可见的站点数远高于网格，也避免少量站点时右侧留下大片空白。
 *
 * @param {{ sites: Site[] } & SiteActionHandlers} props 组件属性
 * @returns {React.ReactElement} 站点表格
 */
export function SiteTable({
  sites,
  onEdit,
  onToggle,
  onDelete,
}: { sites: Site[] } & SiteActionHandlers) {
  const { t } = useTranslation()

  return (
    <div className="overflow-x-auto rounded-xl border">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="h-9 w-[240px] ps-4 text-xs">
              {t("sites.host")}
            </TableHead>
            <TableHead className="h-9 w-[120px] text-xs">
              {t("sites.detail.protectionMode")}
            </TableHead>
            <TableHead className="h-9 w-[190px] text-xs">
              {t("sites.listeners")}
            </TableHead>
            <TableHead className="h-9 text-xs">{t("sites.upstream")}</TableHead>
            <TableHead className="hidden h-9 w-[200px] text-xs lg:table-cell">
              {t("sites.capability.label")}
            </TableHead>
            <TableHead className="hidden h-9 w-[170px] text-xs xl:table-cell">
              {t("sites.quickAccess")}
            </TableHead>
            <TableHead className="h-9 w-12 pe-4" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {sites.map((site) => {
            const hosts = parseSiteHosts(site.host)
            const primaryHost = hosts[0] || site.host

            return (
              <TableRow
                key={site.id}
                className={site.enabled ? undefined : "bg-muted/25"}
              >
                <TableCell className="ps-4">
                  <SiteHoverPreview site={site} className="min-w-0">
                    <Link
                      href={`/sites/detail/?id=${site.id}`}
                      className="group/link flex min-w-0 items-center gap-2"
                    >
                      <SiteStatusDot enabled={site.enabled} />
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span
                          className="truncate text-sm font-medium transition-colors group-hover/link:text-primary"
                          title={hosts.join("\n") || site.host}
                        >
                          {primaryHost}
                        </span>
                        {hosts.length > 1 && (
                          <span className="shrink-0 rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                            +{hosts.length - 1}
                          </span>
                        )}
                      </span>
                    </Link>
                  </SiteHoverPreview>
                </TableCell>
                <TableCell>
                  <SiteModeBadge site={site} />
                </TableCell>
                <TableCell>
                  <SiteListenerBadges site={site} max={3} />
                </TableCell>
                <TableCell className="max-w-0">
                  <SiteUpstream site={site} />
                </TableCell>
                <TableCell className="hidden lg:table-cell">
                  <SiteCapabilityBadges site={site} max={3} />
                </TableCell>
                <TableCell className="hidden xl:table-cell">
                  <SiteQuickLinks siteId={site.id} />
                </TableCell>
                <TableCell className="pe-4 text-end">
                  <SiteActionsMenu
                    site={site}
                    onEdit={onEdit}
                    onToggle={onToggle}
                    onDelete={onDelete}
                  />
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}
