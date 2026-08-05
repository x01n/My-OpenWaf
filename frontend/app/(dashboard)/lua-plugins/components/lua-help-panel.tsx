"use client"

import { useTranslation } from "react-i18next"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { ActionBadge } from "@/components/action-badge"
import { LuaCodeEditor } from "@/components/lua-code-editor"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { IconWand, IconBraces, IconBolt } from "@tabler/icons-react"
import type { LuaPluginStage } from "@/lib/types"
import {
  CTX_FIELDS,
  KV_METHODS,
  LUA_ACTIONS,
  LUA_BLOCKED_RESPONSE_HEADERS,
  LUA_DECISION_LIMITS,
  LUA_EXAMPLES,
} from "./examples"

/**
 * @typedef {object} LuaHelpPanelProps
 * @property {(source: string, stage: LuaPluginStage) => void} onApplyExample
 *   一键填入示例脚本；同时切换到示例适用的阶段，避免 post 示例落在 pre 上。
 */
export interface LuaHelpPanelProps {
  onApplyExample: (source: string, stage: LuaPluginStage) => void
}

/**
 * 帮助面板：ctx 字段、kv 方法、合法动作与可一键填入的示例脚本。
 *
 * @param {LuaHelpPanelProps} props 组件属性
 * @returns {React.ReactElement} 帮助面板元素
 */
export function LuaHelpPanel({ onApplyExample }: LuaHelpPanelProps) {
  const { t } = useTranslation()

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
            <code className="shrink-0 font-mono text-foreground">
              nil / false
            </code>
            <span>{t("luaPlugins.help.returnNil")}</span>
          </li>
          <li className="flex gap-2">
            <code className="shrink-0 font-mono text-foreground">true</code>
            <span>{t("luaPlugins.help.returnTrue")}</span>
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
        <ul className="space-y-1 text-xs text-muted-foreground">
          <li>
            <code className="font-mono text-foreground">site_id</code>{" "}
            {t("luaPlugins.help.siteScopeNote", {
              defaultValue:
                "全局脚本对所有站点执行；绑定站点的脚本只在 ctx.site_id 相等时执行。",
            })}
          </li>
          <li>
            <code className="font-mono text-foreground">ctx.kv</code>{" "}
            {t("luaPlugins.help.kvFailOpenNote", {
              defaultValue:
                "线上 KV 为 nil 或不可用时，该阶段脚本不会执行并请求 fail-open；dry-run 直接执行脚本，不代表线上路径。",
            })}
          </li>
        </ul>
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

      <section className="space-y-2 rounded-lg border bg-muted/30 p-4">
        <h3 className="text-sm font-semibold">
          {t("luaPlugins.help.outputTitle", {
            defaultValue: "Decision 输出与边界",
          })}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.outputHint", {
            defaultValue:
              "表返回值中的 headers、response_body、tags 会沿受控 action.Result 路径传递，不是任意写响应或写日志的能力。",
          })}
        </p>
        <ul className="space-y-1 text-xs text-muted-foreground">
          <li>
            <code className="font-mono text-foreground">response_body</code>{" "}
            {t("luaPlugins.help.responseBodyLimit", {
              defaultValue: `最多 ${LUA_DECISION_LIMITS.responseBodyBytes / 1024} KiB，按 UTF-8 字符边界安全截断；空值不覆盖响应。`,
            })}
          </li>
          <li>
            <code className="font-mono text-foreground">headers</code>{" "}
            {t("luaPlugins.help.headersLimit", {
              defaultValue: `最多 ${LUA_DECISION_LIMITS.headerEntries} 项；名称必须是合法 HTTP header 且最多 ${LUA_DECISION_LIMITS.stringBytes / 1024} KiB，值最多 ${LUA_DECISION_LIMITS.headerValueBytes / 1024} KiB，含 CR/LF 或敏感/逐跳/Content-Length/Location 头会被拒绝。`,
            })}
          </li>
          <li>
            <code className="font-mono text-foreground">tags</code>{" "}
            {t("luaPlugins.help.tagsLimit", {
              defaultValue: `仅读取数组索引 1..${LUA_DECISION_LIMITS.tagEntries}，每项最多 ${LUA_DECISION_LIMITS.stringBytes / 1024} KiB；当前进入 Result 供观测，但尚未持久化日志。`,
            })}
          </li>
          <li>
            <code className="font-mono text-foreground">status_code</code>{" "}
            {t("luaPlugins.help.statusRedirectLimit", {
              defaultValue: `仅接受 ${LUA_DECISION_LIMITS.statusMin}–${LUA_DECISION_LIMITS.statusMax}；redirect_to 仅允许 / 开头的相对路径或 http/https 绝对 URL。`,
            })}
          </li>
          <li>
            {t("luaPlugins.help.responseApplicability", {
              defaultValue:
                "response_body 只由普通 Lua 终止响应消费；challenge、redirect、drop 以及上游响应不会被它覆盖。",
            })}
          </li>
        </ul>
        <p className="text-[11px] text-muted-foreground">
          {t("luaPlugins.help.blockedHeaders", {
            defaultValue: `拒绝的 header 名称：${LUA_BLOCKED_RESPONSE_HEADERS.join(", ")}。`,
          })}
        </p>
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
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.ctxSiteNote", {
            defaultValue:
              "ctx.site_id 始终是当前请求匹配到的站点 ID；脚本自身的 site_id 作用域由 Engine 在执行前过滤。",
          })}
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
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.help.kvRuntimeNote", {
            defaultValue:
              "ctx.kv 的方法在脚本内仍以 nil/false 降级；但线上 Engine 在执行前后都会检查 KV，发现不可用就丢弃本阶段判定并放行。",
          })}
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
  )
}
