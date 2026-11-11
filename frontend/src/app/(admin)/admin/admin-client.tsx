"use client";

/**
 * 账户与密钥页：管理员账户、API 密钥、登录会话、修改自己密码四个 Tab。
 */

import { Tabs } from "@heroui/react";
import { PageHeader } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";
import { UsersPanel } from "./users-panel";
import { APIKeysPanel } from "./apikeys-panel";
import { SessionsPanel } from "./sessions-panel";
import { ChangePasswordPanel } from "./change-password-panel";

function AdminClient() {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t("admin.title")} description={t("admin.description")} />
      <Tabs aria-label={t("admin.tabsAria")}>
        <Tabs.List aria-label={t("admin.navAria")}>
          <Tabs.Tab id="users">{t("admin.tab.users")}</Tabs.Tab>
          <Tabs.Tab id="api-keys">{t("admin.tab.apiKeys")}</Tabs.Tab>
          <Tabs.Tab id="sessions">{t("admin.tab.sessions")}</Tabs.Tab>
          <Tabs.Tab id="password">{t("admin.tab.password")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel id="users">
          <UsersPanel />
        </Tabs.Panel>
        <Tabs.Panel id="api-keys">
          <APIKeysPanel />
        </Tabs.Panel>
        <Tabs.Panel id="sessions">
          <SessionsPanel />
        </Tabs.Panel>
        <Tabs.Panel id="password">
          <ChangePasswordPanel />
        </Tabs.Panel>
      </Tabs>
    </div>
  );
}

export default AdminClient;
