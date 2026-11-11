"use client";

/**
 * 威胁情报页面入口：页头 + 订阅源 / 同步日志两个 Tab + 新建 / 编辑弹窗编排。
 *
 * 各列表与表单分别实现于同目录下的单一职责文件；
 * 保存、同步、删除后通过递增 `refreshKey` 让两个面板同时刷新，
 * 与后端写同步日志的时机保持一致。
 */

import { useCallback, useState } from "react";
import { useOverlayState, Button, Tabs } from "@heroui/react";
import { Plus } from "lucide-react";
import { apiGet, type ListResponse } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import type { Site } from "@/lib/types/site";
import type { ThreatIntelFeed } from "@/lib/types/ip";
import { PageHeader } from "@/components/ui/primitives";
import { FeedsPanel } from "./feeds-panel";
import { SyncLogsPanel } from "./sync-logs-panel";
import { FeedFormDialog } from "./feed-form-dialog";

export default function ThreatIntelClient() {
  const { t } = useI18n();
  const [formVisible, setFormVisible] = useState(false);
  const [editing, setEditing] = useState<ThreatIntelFeed | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const formState = useOverlayState();

  const sites = useApi<ListResponse<Site>>(
    useCallback(() => apiGet<ListResponse<Site>>("/sites"), []),
  );

  /** 打开新建（feed = null）或编辑弹窗 */
  const openForm = useCallback(
    (feed: ThreatIntelFeed | null) => {
      setEditing(feed);
      setFormVisible(true);
      formState.open();
    },
    [formState],
  );

  const handleMutated = useCallback(() => setRefreshKey((k) => k + 1), []);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("threatIntel.title")}
        description={t("threatIntel.description")}
        actions={
          <Button variant="primary" onPress={() => openForm(null)}>
            <Plus className="size-4" /> {t("threatIntel.create")}
          </Button>
        }
      />

      <Tabs aria-label={t("threatIntel.title")}>
        <Tabs.List aria-label={t("threatIntel.tabsAria")}>
          <Tabs.Tab id="feeds">{t("threatIntel.tab.feeds")}</Tabs.Tab>
          <Tabs.Tab id="logs">{t("threatIntel.tab.logs")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel id="feeds">
          <FeedsPanel
            refreshKey={refreshKey}
            onEdit={openForm}
            onMutated={handleMutated}
          />
        </Tabs.Panel>
        <Tabs.Panel id="logs">
          <SyncLogsPanel refreshKey={refreshKey} />
        </Tabs.Panel>
      </Tabs>

      {formVisible ? (
        <FeedFormDialog
          key={editing ? `ti-feed-${editing.id}` : "ti-feed-new"}
          state={formState}
          feed={editing}
          sites={sites.data?.items ?? []}
          onSaved={() => {
            setFormVisible(false);
            handleMutated();
          }}
        />
      ) : null}
    </div>
  );
}
