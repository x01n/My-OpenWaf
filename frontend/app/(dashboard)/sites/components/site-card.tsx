"use client";

import Link from "next/link";
import { useTranslation } from "react-i18next";
import { Card } from "@/components/ui/card";
import { SiteHoverPreview } from "@/components/site-hover-preview";
import type { Site } from "@/lib/types";
import {
  SiteActionsMenu,
  SiteCapabilityBadges,
  SiteListenerBadges,
  SiteModeBadge,
  SiteQuickLinks,
  SiteStatusDot,
  SiteUpstream,
  type SiteActionHandlers,
} from "./site-presentation";

/**
 * 站点网格卡片。
 *
 * 信息按三层组织：第一层是域名与运行状态，第二层是监听/上游等接入信息，
 * 第三层是防护能力与快捷入口。层间用分隔线与字号差拉开，避免所有信息等权堆叠。
 *
 * @param {{ site: Site } & SiteActionHandlers} props 组件属性
 * @returns {React.ReactElement} 站点卡片
 */
export function SiteCard({
  site,
  onEdit,
  onToggle,
  onDelete,
}: { site: Site } & SiteActionHandlers) {
  const { t } = useTranslation();

  return (
    <Card
      className={`group relative gap-0 overflow-hidden py-0 transition-[border-color,box-shadow] duration-200 hover:border-primary/40 hover:shadow-md ${
        site.enabled ? "" : "bg-muted/25"
      }`}
    >
      {/* 左侧运行状态色条 */}
      <span
        aria-hidden="true"
        className={`pointer-events-none absolute inset-y-0 left-0 w-[3px] ${
          site.enabled ? "bg-emerald-500" : "bg-border"
        }`}
      />

      {/* 第一层：域名 + 状态 + 操作 */}
      <div className="flex items-start justify-between gap-2 px-4 pt-3.5 pb-3">
        <SiteHoverPreview site={site} className="min-w-0 flex-1">
          <Link
            href={`/sites/detail/?id=${site.id}`}
            className="group/link flex min-w-0 items-center gap-2"
          >
            <SiteStatusDot enabled={site.enabled} />
            <span
              className="truncate text-sm font-semibold tracking-tight transition-colors group-hover/link:text-primary"
              title={site.host}
            >
              {site.host}
            </span>
          </Link>
        </SiteHoverPreview>
        <div className="flex shrink-0 items-center gap-1">
          <SiteModeBadge site={site} />
          <SiteActionsMenu
            site={site}
            onEdit={onEdit}
            onToggle={onToggle}
            onDelete={onDelete}
          />
        </div>
      </div>

      {/* 第二层：接入信息 */}
      <dl className="space-y-2 border-t border-border/60 px-4 py-3 text-xs">
        <div className="flex items-start gap-2">
          <dt className="w-12 shrink-0 pt-0.5 text-[11px] text-muted-foreground">
            {t("sites.listeners")}
          </dt>
          <dd className="min-w-0 flex-1">
            <SiteListenerBadges site={site} max={3} />
          </dd>
        </div>
        <div className="flex items-start gap-2">
          <dt className="w-12 shrink-0 pt-0.5 text-[11px] text-muted-foreground">
            {t("sites.upstream")}
          </dt>
          <dd className="min-w-0 flex-1">
            <SiteUpstream site={site} />
          </dd>
        </div>
        <div className="flex items-start gap-2">
          <dt className="w-12 shrink-0 pt-0.5 text-[11px] text-muted-foreground">
            {t("sites.capability.label")}
          </dt>
          <dd className="min-w-0 flex-1">
            <SiteCapabilityBadges site={site} max={3} />
          </dd>
        </div>
      </dl>

      {/* 第三层：快捷入口 */}
      <div className="flex items-center justify-between gap-2 border-t border-border/60 bg-muted/25 px-3 py-1.5">
        <SiteQuickLinks siteId={site.id} />
        <Link
          href={`/sites/detail/?id=${site.id}`}
          className="shrink-0 pe-1 text-[11px] text-muted-foreground transition-colors hover:text-primary"
        >
          {t("common.viewDetail")}
        </Link>
      </div>
    </Card>
  );
}
