"use client";

/**
 * 防护设置入口：页头 + 9 个 Tab 编排。
 *
 * 各 Tab 表单分别实现于 `protection/` 下的单一职责文件，
 * 本文件仅负责页面骨架与导航，便于单独演进各面板。
 */

import { Tabs } from "@heroui/react";
import { useI18n } from "@/i18n";
import { PageHeader } from "@/components/ui/primitives";
import { GeneralPanel } from "./protection/general-panel";
import { BotPanel } from "./protection/bot-panel";
import { BotScoresPanel } from "./protection/bot-scores-panel";
import { CaptchaPanel } from "./protection/captcha-panel";
import { ChainPanel } from "./protection/chain-panel";
import { SensitivityPanel } from "./protection/sensitivity-panel";
import { EscalationPanel } from "./protection/escalation-panel";
import { DropPanel } from "./protection/drop-panel";
import { PageTemplatesPanel } from "./protection/page-templates-panel";

export default function ProtectionClient() {
  const { t } = useI18n();

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t("protection.title")} description={t("protection.description")} />
      <Tabs aria-label={t("protection.title")}>
        <Tabs.List aria-label={t("protection.tabsAria")}>
          <Tabs.Tab id="general">{t("protection.tab.general")}</Tabs.Tab>
          <Tabs.Tab id="bot">{t("protection.tab.bot")}</Tabs.Tab>
          <Tabs.Tab id="bot-scores">{t("protection.tab.botScores")}</Tabs.Tab>
          <Tabs.Tab id="captcha">{t("protection.tab.captcha")}</Tabs.Tab>
          <Tabs.Tab id="chain">{t("protection.tab.chain")}</Tabs.Tab>
          <Tabs.Tab id="sensitivity">{t("protection.tab.sensitivity")}</Tabs.Tab>
          <Tabs.Tab id="escalation">{t("protection.tab.escalation")}</Tabs.Tab>
          <Tabs.Tab id="drop">{t("protection.tab.drop")}</Tabs.Tab>
          <Tabs.Tab id="pages">{t("protection.tab.pages")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel id="general">
          <GeneralPanel />
        </Tabs.Panel>
        <Tabs.Panel id="bot">
          <BotPanel />
        </Tabs.Panel>
        <Tabs.Panel id="bot-scores">
          <BotScoresPanel />
        </Tabs.Panel>
        <Tabs.Panel id="captcha">
          <CaptchaPanel />
        </Tabs.Panel>
        <Tabs.Panel id="chain">
          <ChainPanel />
        </Tabs.Panel>
        <Tabs.Panel id="sensitivity">
          <SensitivityPanel />
        </Tabs.Panel>
        <Tabs.Panel id="escalation">
          <EscalationPanel />
        </Tabs.Panel>
        <Tabs.Panel id="drop">
          <DropPanel />
        </Tabs.Panel>
        <Tabs.Panel id="pages">
          <PageTemplatesPanel />
        </Tabs.Panel>
      </Tabs>
    </div>
  );
}
