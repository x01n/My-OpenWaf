"use client";

/**
 * 站点详情抽屉：基本信息 + 监听器 / 访问控制 / 错误页 / 应用路由规则 / 录制资源 / 站点流量 / 安全事件 / 站点规则 / 高级配置九个 Tab。
 * 各 Tab 的数据与操作由对应面板组件自治（site-panels.tsx、site-traffic-panel.tsx、site-security-panel.tsx、site-rules-panel.tsx、advanced/site-advanced-panel.tsx）。
 */

import { useCallback } from "react";
import { Tabs, useOverlayState } from "@heroui/react";
import type { Certificate } from "@/lib/types/site";
import type { SiteListItem } from "@/lib/types/site-admin";
import { apiGet } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { formatDateTime } from "@/lib/utils/format";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { StatusChip } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";
import {
  ListenersPanel,
  AccessPanel,
  ErrorPagesPanel,
  RulesPanel,
  RecordedResourcesPanel,
} from "./site-panels";
import { SiteTrafficPanel } from "./site-traffic-panel";
import { SiteRulesPanel } from "./site-rules-panel";
import { SiteSecurityPanel } from "./site-security-panel";
import { SiteAdvancedPanel } from "./advanced/site-advanced-panel";

/** GET /sites/:id/status 响应（internal/admin/site GetSiteStatus）。 */
type SiteStatusResponse = {
  id: number;
  host: string;
  status: "running" | "stopped";
};

/** 站点运行状态行：真实状态源为站点 enabled 字段。 */
function SiteStatusRow({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const { data, loading, error } = useApi(
    useCallback(() => apiGet<SiteStatusResponse>(`/sites/${siteId}/status`), [siteId]),
  );

  let content: React.ReactNode;
  if (loading) {
    content = <span className="text-muted">{t("common.loading")}</span>;
  } else if (error || !data) {
    content = <span className="text-muted">{t("siteDetail.unknown")}</span>;
  } else {
    content = (
      <StatusChip tone={data.status === "running" ? "success" : "neutral"}>
        {data.status === "running" ? t("sites.status.running") : t("sites.status.stopped")}
      </StatusChip>
    );
  }

  return <DetailRow label={t("siteDetail.field.status")}>{content}</DetailRow>;
}

export function SiteDetailDrawer({
  state,
  site,
  certs,
  onChanged,
}: {
  state: ReturnType<typeof useOverlayState>;
  site: SiteListItem | null;
  certs: Certificate[];
  onChanged: () => void;
}) {
  const { t } = useI18n();

  return (
    <DetailDrawer
      state={state}
      title={site?.host ?? t("siteDetail.title")}
      description={
        site ? t("siteDetail.description", { id: site.id, tls: site.tls_summary ?? "" }) : undefined
      }
      width="w-[680px]"
    >
      {site ? (
        <div className="flex flex-col gap-3">
          <div className="bg-surface rounded-xl border border-separator px-4 py-2">
            <DetailRow label={t("siteDetail.field.id")}>
              <span className="tabular">{site.id}</span>
            </DetailRow>
            <DetailRow label={t("common.host")}>{site.host}</DetailRow>
            <DetailRow label={t("siteDetail.field.bind")}>{site.bind || "-"}</DetailRow>
            <DetailRow label={t("siteDetail.field.upstream")}>
              <span className="break-all">{site.upstream_urls || "-"}</span>
            </DetailRow>
            <DetailRow label="TLS">{site.tls_summary ?? "-"}</DetailRow>
            <DetailRow label={t("siteDetail.field.certId")}>
              <span className="tabular">{site.cert_id ?? "-"}</span>
            </DetailRow>
            <DetailRow label={t("siteDetail.field.createdAt")}>
              {formatDateTime(site.created_at)}
            </DetailRow>
            <DetailRow label={t("siteDetail.field.updatedAt")}>
              {formatDateTime(site.updated_at)}
            </DetailRow>
            <SiteStatusRow siteId={site.id} />
          </div>

          <Tabs aria-label={t("siteDetail.tabs.aria")}>
            <Tabs.List aria-label={t("siteDetail.tabs.navAria")}>
              <Tabs.Tab id="listeners">{t("siteDetail.tab.listeners")}</Tabs.Tab>
              <Tabs.Tab id="access">{t("siteDetail.tab.access")}</Tabs.Tab>
              <Tabs.Tab id="error-pages">{t("siteDetail.tab.errorPages")}</Tabs.Tab>
              <Tabs.Tab id="routes">{t("siteDetail.tab.routes")}</Tabs.Tab>
              <Tabs.Tab id="recorded">{t("siteDetail.tab.recorded")}</Tabs.Tab>
              <Tabs.Tab id="traffic">{t("siteDetail.tab.traffic")}</Tabs.Tab>
              <Tabs.Tab id="security">{t("siteDetail.tab.security")}</Tabs.Tab>
              <Tabs.Tab id="site-rules">{t("siteDetail.tab.siteRules")}</Tabs.Tab>
              <Tabs.Tab id="advanced">{t("siteDetail.tab.advanced")}</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel id="listeners">
              <ListenersPanel siteId={site.id} certs={certs} onChanged={onChanged} />
            </Tabs.Panel>
            <Tabs.Panel id="access">
              <AccessPanel siteId={site.id} />
            </Tabs.Panel>
            <Tabs.Panel id="error-pages">
              <ErrorPagesPanel siteId={site.id} />
            </Tabs.Panel>
            <Tabs.Panel id="routes">
              <RulesPanel siteId={site.id} onChanged={onChanged} />
            </Tabs.Panel>
            <Tabs.Panel id="recorded">
              <RecordedResourcesPanel siteId={site.id} />
            </Tabs.Panel>
            <Tabs.Panel id="traffic">
              <SiteTrafficPanel siteId={site.id} />
            </Tabs.Panel>
            <Tabs.Panel id="security">
              <SiteSecurityPanel siteId={site.id} />
            </Tabs.Panel>
            <Tabs.Panel id="site-rules">
              <SiteRulesPanel siteId={site.id} />
            </Tabs.Panel>
            <Tabs.Panel id="advanced">
              <SiteAdvancedPanel siteId={site.id} onChanged={onChanged} />
            </Tabs.Panel>
          </Tabs>
        </div>
      ) : null}
    </DetailDrawer>
  );
}
