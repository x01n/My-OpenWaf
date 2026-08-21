"use client"

import { useTranslation } from "react-i18next"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import {
  IconAlertTriangle,
  IconBraces,
  IconInfoCircle,
} from "@tabler/icons-react"

/**
 * JavaScript request-stage 插件契约说明面板。
 *
 * response 阶段可能保留在历史数据中，但当前后端没有执行入口，不能当作可用能力展示。
 */
export function JSHelpPanel() {
  const { t } = useTranslation()

  return (
    <div className="space-y-4">
      <section className="space-y-2 rounded-lg border bg-muted/30 p-4">
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <IconBraces className="h-4 w-4" />
          {t("jsPlugins.help.contractTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("jsPlugins.help.contractDescription")}
        </p>
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="font-mono">
            export default
          </Badge>
          <Badge variant="outline" className="font-mono">
            fetch(request, env, ctx)
          </Badge>
          <Badge variant="secondary">256 KiB</Badge>
          <Badge variant="secondary">0–1000 ms</Badge>
        </div>
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-semibold">
          {t("jsPlugins.help.stagesTitle")}
        </h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-sky-500/30 p-3">
            <Badge className="mb-2" variant="outline">
              request
            </Badge>
            <p className="text-xs text-muted-foreground">
              {t("jsPlugins.help.requestStage")}
            </p>
          </div>
          <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-3">
            <Badge className="mb-2" variant="outline">
              response
            </Badge>
            <p className="text-xs text-muted-foreground">
              {t("jsPlugins.help.responseStage")}
            </p>
          </div>
        </div>
      </section>

      <Separator />

      <section className="space-y-2">
        <h3 className="text-sm font-semibold">
          {t("jsPlugins.help.snapshotTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("jsPlugins.help.snapshotDescription")}
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {[
            "request_id",
            "site_id",
            "method",
            "path",
            "raw_query",
            "host",
            "client_ip",
            "user_agent",
            "content_type",
            "body",
            "headers",
            "query_params",
          ].map((field) => (
            <code key={field} className="rounded bg-muted px-2 py-1 text-xs">
              {field}
            </code>
          ))}
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold">
          {t("jsPlugins.help.mutationTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("jsPlugins.help.mutationDescription")}
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {[
            "method",
            "path",
            "raw_query",
            "body",
            "set_headers",
            "delete_headers",
          ].map((field) => (
            <code key={field} className="rounded bg-muted px-2 py-1 text-xs">
              {field}
            </code>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          {t("jsPlugins.help.mutationSemantics")}
        </p>
        <pre className="overflow-auto rounded bg-muted p-3 text-xs">
          return &#123;&#125;
        </pre>
      </section>

      <section className="space-y-3 rounded-lg border bg-muted/30 p-4">
        <h3 className="text-sm font-semibold">
          {t("jsPlugins.help.limitsTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("jsPlugins.help.limitsDescription")}
        </p>
        <ul className="space-y-2 text-xs text-muted-foreground">
          <li>{t("jsPlugins.help.pathLimit")}</li>
          <li>{t("jsPlugins.help.rawQueryLimit")}</li>
          <li>{t("jsPlugins.help.methodBodyLimit")}</li>
          <li>{t("jsPlugins.help.headerLimit")}</li>
          <li>{t("jsPlugins.help.snapshotLimit")}</li>
        </ul>
      </section>

      <section className="space-y-2 rounded-lg border bg-muted/30 p-4">
        <h3 className="text-sm font-semibold">
          {t("jsPlugins.help.sampleTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("jsPlugins.help.sampleDescription")}
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {[
            "method",
            "path",
            "raw_query",
            "host",
            "client_ip",
            "user_agent",
            "content_type",
            "body",
            "headers",
            "query_params",
          ].map((field) => (
            <code key={field} className="rounded bg-muted px-2 py-1 text-xs">
              {field}
            </code>
          ))}
        </div>
      </section>

      <section className="space-y-2 rounded-lg border bg-muted/30 p-4">
        <h3 className="text-sm font-semibold">
          {t("jsPlugins.help.scopeTitle")}
        </h3>
        <p className="text-xs text-muted-foreground">
          {t("jsPlugins.help.scopeDescription")}
        </p>
        <p className="text-xs text-muted-foreground">
          <code className="font-mono text-foreground">site_id</code>:{" "}
          {t("jsPlugins.help.siteIdDescription")}
        </p>
      </section>

      <Alert>
        <IconInfoCircle className="h-4 w-4" />
        <AlertTitle>{t("jsPlugins.help.runtimeTitle")}</AlertTitle>
        <AlertDescription>
          {t("jsPlugins.help.runtimeDescription")}
        </AlertDescription>
      </Alert>

      <Alert variant="destructive">
        <IconAlertTriangle className="h-4 w-4" />
        <AlertTitle>{t("jsPlugins.help.failureTitle")}</AlertTitle>
        <AlertDescription>
          {t("jsPlugins.help.failureDescription")}
        </AlertDescription>
      </Alert>
    </div>
  )
}
