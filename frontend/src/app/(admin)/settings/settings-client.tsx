"use client";

/**
 * 系统设置页：按后端契约分组的十个配置 Tab。
 * 各 Tab 的数据获取与保存逻辑收敛到同目录的独立 panel 文件。
 */

import { Tabs } from "@heroui/react";
import { PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";
import { NetworkPanel } from "./network-panel";
import { TLSPanel } from "./tls-panel";
import { HTTP2Panel } from "./http2-panel";
import { RedisPanel } from "./redis-panel";
import { LogPanel } from "./log-panel";
import { ImagePanel } from "./image-panel";
import { RuntimePanel } from "./runtime-panel";
import { BackupPanel } from "./backup-panel";
import { KVPanel } from "./kv-panel";
import { UpstreamPanel } from "./upstream-panel";

function SettingsClient() {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("settings.title")}
        description={t("settings.description")}
      />
      <Tabs aria-label={t("settings.title")}>
        <Tabs.List aria-label={t("settings.tabsNav")}>
          <Tabs.Tab id="network">{t("settings.tab.network")}</Tabs.Tab>
          <Tabs.Tab id="tls">{t("settings.tab.tls")}</Tabs.Tab>
          <Tabs.Tab id="http2">HTTP/2</Tabs.Tab>
          <Tabs.Tab id="redis">{t("settings.tab.redis")}</Tabs.Tab>
          <Tabs.Tab id="log">{t("settings.tab.log")}</Tabs.Tab>
          <Tabs.Tab id="image">{t("settings.tab.image")}</Tabs.Tab>
          <Tabs.Tab id="runtime">{t("settings.tab.runtime")}</Tabs.Tab>
          <Tabs.Tab id="backup">{t("settings.tab.backup")}</Tabs.Tab>
          <Tabs.Tab id="kv">{t("settings.tab.kv")}</Tabs.Tab>
          <Tabs.Tab id="upstreams">{t("settings.tab.upstreams")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel id="network">
          <NetworkPanel />
        </Tabs.Panel>
        <Tabs.Panel id="tls">
          <TLSPanel />
        </Tabs.Panel>
        <Tabs.Panel id="http2">
          <HTTP2Panel />
        </Tabs.Panel>
        <Tabs.Panel id="redis">
          <RedisPanel />
        </Tabs.Panel>
        <Tabs.Panel id="log">
          <LogPanel />
        </Tabs.Panel>
        <Tabs.Panel id="image">
          <ImagePanel />
        </Tabs.Panel>
        <Tabs.Panel id="runtime">
          <RuntimePanel />
        </Tabs.Panel>
        <Tabs.Panel id="backup">
          <BackupPanel />
        </Tabs.Panel>
        <Tabs.Panel id="kv">
          <KVPanel />
        </Tabs.Panel>
        <Tabs.Panel id="upstreams">
          <UpstreamPanel />
        </Tabs.Panel>
      </Tabs>
    </div>
  );
}

export default SettingsClient;
