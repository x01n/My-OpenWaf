"use client";

import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ActionBadge } from "@/components/action-badge";
import { LuaCodeEditor } from "@/components/lua-code-editor";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { IconWand, IconBraces, IconBolt } from "@tabler/icons-react";
import type { LuaPluginStage } from "@/lib/types";
import { CTX_FIELDS, KV_METHODS, LUA_ACTIONS, LUA_EXAMPLES } from "./examples";

/**
 * @typedef {object} LuaHelpPanelProps
 * @property {(source: string, stage: LuaPluginStage) => void} onApplyExample
 *   一键填入示例脚本；同时切换到示例适用的阶段，避免 post 示例落在 pre 上。
 */
export interface LuaHelpPanelProps {
  onApplyExample: (source: string, stage: LuaPluginStage) => void;
}

/**
 * 帮助面板：ctx 字段、kv 方法、合法动作与可一键填入的示例脚本。
 *
 * @param {LuaHelpPanelProps} props 组件属性
 * @returns {React.ReactElement} 帮助面板元素
 */
export function LuaHelpPanel({ onApplyExample }: LuaHelpPanelProps) {
  const { t } = useTranslation();

  return (
    <div className="space-y-4">
      <section className="space-y-2 rounded-lg border bg-muted/30 p-4">
        <h3 className="text-sm font-semibold">
          {t("luaPlugins.help.contractTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.contractIntro")}
        </p>
        <ul className="space-y-1 text-xs text-muted-foreground">
          <li className="flex gap-2">
            <code className="shrink-0 font-mono text-foreground">nil / false</code>
            <span>{t("luaPlugins.help.returnNil")}</span>
          </li>
          <li className="flex gap-2">
            <code className="shrink-0 font-mono text-foreground">string</code>
            <span>{t("luaPlugins.help.returnString")}</span>
          </li>
          <li className="flex gap-2">
            <code className="shrink-0 font-mono text-foreground">table</code>
            <span>{t("luaPlugins.help.returnTable")}</span>
          </li>
        </ul>
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.sandboxNote")}
        </p>
      </section>

      <section className="space-y-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <IconBolt className="h-4 w-4" />
          {t("luaPlugins.help.actionsTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.actionsHint")}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {LUA_ACTIONS.map((a) => (
            <ActionBadge key={a} action={a} />
          ))}
        </div>
      </section>

      <Separator />

      <section className="space-y-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <IconBraces className="h-4 w-4" />
          {t("luaPlugins.help.ctxTitle")}
        </h3>
        <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
          {CTX_FIELDS.map((f) => (
            <div
              key={f.name}
              className="flex items-baseline justify-between gap-2 border-b border-dashed py-1 text-xs last:border-0"
            >
              <code className="font-mono">{f.name}</code>
              <span className="shrink-0 text-muted-foreground">{f.type}</span>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.ctxNote")}
        </p>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold">
          {t("luaPlugins.help.kvTitle")}
        </h3>
        <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
          {KV_METHODS.map((m) => (
            <div
              key={m.name}
              className="flex items-baseline justify-between gap-2 border-b border-dashed py-1 text-xs last:border-0"
            >
              <code className="font-mono">{m.name}</code>
              <span className="shrink-0 text-muted-foreground">{m.type}</span>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.kvNote")}
        </p>
      </section>

      <Separator />

      <section className="space-y-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <IconWand className="h-4 w-4" />
          {t("luaPlugins.help.examplesTitle")}
        </h3>
        <Accordion type="single" collapsible className="w-full">
          {LUA_EXAMPLES.map((ex) => (
            <AccordionItem key={ex.id} value={ex.id}>
              <AccordionTrigger className="text-xs">
                <span className="flex items-center gap-2">
                  <Badge
                    variant={ex.stage === "pre" ? "secondary" : "outline"}
                    className="font-mono"
                  >
                    {ex.stage}
                  </Badge>
                  {t(`luaPlugins.help.examples.${ex.id}.title`)}
                </span>
              </AccordionTrigger>
              <AccordionContent className="space-y-2">
                <p className="text-xs text-muted-foreground">
                  {t(`luaPlugins.help.examples.${ex.id}.description`)}
                </p>
                <LuaCodeEditor
                  value={ex.source}
                  onChange={() => {}}
                  readOnly
                  rows={ex.source.split("\n").length}
                  ariaLabel={t(`luaPlugins.help.examples.${ex.id}.title`)}
                />
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onApplyExample(ex.source, ex.stage)}
                >
                  <IconWand className="h-4 w-4" />
                  {t("luaPlugins.help.applyExample")}
                </Button>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </section>
    </div>
  );
}
