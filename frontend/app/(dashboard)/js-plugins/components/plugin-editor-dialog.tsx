"use client"

import { useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { LuaCodeEditor } from "@/components/lua-code-editor"
import {
  useJSPluginDryRun,
  useJSPluginMutation,
  useJSPluginValidate,
} from "@/hooks/use-api"
import { IconAlertTriangle, IconInfoCircle } from "@tabler/icons-react"
import type {
  JSPlugin,
  JSPluginCreateRequest,
  JSPluginFailureMode,
  JSPluginReloadFailureResponse,
  JSPluginSampleRequest,
  JSPluginStage,
  JSPluginDryRunResponse,
  JSPluginUpdateRequest,
} from "@/lib/types"
import { JSHelpPanel } from "./js-help-panel"

const GLOBAL_SCOPE = "global"
const MAX_TIMEOUT_MS = 1000

type PluginForm = {
  name: string
  source: string
  stage: JSPluginStage
  failure_mode: JSPluginFailureMode
  enabled: boolean
  priority: number
  timeout_ms: number
  site_id: string
  description: string
}

const EMPTY_FORM: PluginForm = {
  name: "",
  source:
    "export default {\n  fetch(request, env, ctx) {\n    return {}\n  },\n}\n",
  stage: "request",
  failure_mode: "fail_open",
  enabled: true,
  priority: 100,
  timeout_ms: 0,
  site_id: GLOBAL_SCOPE,
  description: "",
}

type DryRunSampleForm = {
  method: string
  path: string
  raw_query: string
  host: string
  client_ip: string
  user_agent: string
  content_type: string
  body: string
  headers_json: string
  query_params_json: string
}

const EMPTY_DRY_RUN_SAMPLE: DryRunSampleForm = {
  method: "GET",
  path: "/",
  raw_query: "",
  host: "",
  client_ip: "",
  user_agent: "",
  content_type: "",
  body: "",
  headers_json: "{}",
  query_params_json: "{}",
}

function parseStringRecord(value: string, errorMessage: string) {
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    throw new Error(errorMessage)
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.values(parsed).some((item) => typeof item !== "string")
  ) {
    throw new Error(errorMessage)
  }
  return parsed as Record<string, string>
}

function buildSampleRequest(
  form: DryRunSampleForm,
  invalidJSON: (field: string) => string
): JSPluginSampleRequest {
  const sample: JSPluginSampleRequest = {}
  const fields: Array<
    keyof Omit<DryRunSampleForm, "headers_json" | "query_params_json" | "body">
  > = [
    "method",
    "path",
    "raw_query",
    "host",
    "client_ip",
    "user_agent",
    "content_type",
  ]
  for (const field of fields) {
    if (form[field]) sample[field] = form[field]
  }
  if (form.body) sample.body = form.body
  sample.headers = parseStringRecord(form.headers_json, invalidJSON("headers"))
  sample.query_params = parseStringRecord(
    form.query_params_json,
    invalidJSON("query_params")
  )
  return sample
}

function formFromPlugin(plugin: JSPlugin | null): PluginForm {
  if (!plugin) return EMPTY_FORM
  return {
    name: plugin.name,
    source: plugin.source,
    stage: plugin.stage,
    failure_mode: plugin.failure_mode,
    enabled: plugin.enabled,
    priority: plugin.priority,
    timeout_ms: plugin.timeout_ms,
    site_id: plugin.site_id == null ? GLOBAL_SCOPE : String(plugin.site_id),
    description: plugin.description || "",
  }
}

function isRuntimeUnavailable(error: unknown) {
  return (error as { status?: number } | null)?.status === 503
}

export interface JSPluginEditorDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  editing: JSPlugin | null
  sites: Array<{ id: number; host: string }>
  onSaved: () => void
}

/**
 * JavaScript 插件编辑对话框，包含脚本编辑、说明、校验和运行时降级提示。
 */
export function JSPluginEditorDialog({
  open,
  onOpenChange,
  editing,
  sites,
  onSaved,
}: JSPluginEditorDialogProps) {
  const { t } = useTranslation()
  const [form, setForm] = useState<PluginForm>(() => formFromPlugin(editing))
  const [validation, setValidation] = useState<{
    valid: boolean
    error?: string
  } | null>(null)
  const [runtimeMessage, setRuntimeMessage] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [dryRunResponse, setDryRunResponse] =
    useState<JSPluginDryRunResponse | null>(null)
  const [dryRunError, setDryRunError] = useState<string | null>(null)
  const [sampleRequest, setSampleRequest] =
    useState<DryRunSampleForm>(EMPTY_DRY_RUN_SAMPLE)
  const [activeTab, setActiveTab] = useState("script")
  const { execute: save, loading: saving } = useJSPluginMutation()
  const { execute: validate, loading: validating } = useJSPluginValidate()
  const { execute: dryRun, loading: dryRunning } = useJSPluginDryRun()
  const responseStageLocked = form.stage === "response"

  const update = <K extends keyof PluginForm>(key: K, value: PluginForm[K]) => {
    setForm((current) => ({ ...current, [key]: value }))
    setSaveError(null)
    if (key === "source" || key === "stage") {
      setValidation(null)
      setRuntimeMessage(null)
      setDryRunResponse(null)
      setDryRunError(null)
    }
  }

  const updateSample = <K extends keyof DryRunSampleForm>(
    key: K,
    value: DryRunSampleForm[K]
  ) => {
    setSampleRequest((current) => ({ ...current, [key]: value }))
    setDryRunResponse(null)
    setDryRunError(null)
  }

  const handleValidate = async () => {
    setRuntimeMessage(null)
    const stage = form.stage
    if (stage !== "request") {
      setValidation({
        valid: false,
        error: t("jsPlugins.responseStageUnavailable"),
      })
      return
    }
    try {
      const result = await validate({
        stage,
        source: form.source,
        timeout_ms: form.timeout_ms || undefined,
      })
      setValidation(result)
    } catch (error) {
      if (isRuntimeUnavailable(error)) {
        setRuntimeMessage(t("jsPlugins.runtimeUnavailable"))
      } else {
        setValidation({
          valid: false,
          error: error instanceof Error ? error.message : String(error),
        })
      }
    }
  }

  const handleDryRun = async () => {
    setRuntimeMessage(null)
    setDryRunResponse(null)
    setDryRunError(null)
    const stage = form.stage
    if (stage !== "request") {
      setDryRunError(t("jsPlugins.responseStageUnavailable"))
      return
    }
    try {
      const sample = buildSampleRequest(sampleRequest, (field) =>
        t("jsPlugins.dryRunJsonInvalid", { field })
      )
      const response = await dryRun({
        source: form.source,
        stage,
        timeout_ms: form.timeout_ms || undefined,
        sample_request: sample,
      })
      setDryRunResponse(response)
      setDryRunError(response.error ?? null)
    } catch (error) {
      if (isRuntimeUnavailable(error)) {
        setRuntimeMessage(t("jsPlugins.runtimeUnavailable"))
      } else {
        setDryRunError(error instanceof Error ? error.message : String(error))
      }
    }
  }

  const handleSave = async () => {
    const stage = form.stage
    if (stage !== "request") {
      setSaveError(t("jsPlugins.responseStageUnavailable"))
      return
    }
    const base = {
      name: form.name.trim(),
      source: form.source,
      stage,
      failure_mode: form.failure_mode,
      enabled: form.enabled,
      priority: form.priority,
      timeout_ms: form.timeout_ms,
      description: form.description,
    }
    const data: JSPluginCreateRequest | JSPluginUpdateRequest = {
      ...base,
      site_id: form.site_id === GLOBAL_SCOPE ? null : Number(form.site_id),
    }
    setSaveError(null)
    try {
      await save({ id: editing?.id, data })
      toast.success(
        editing ? t("common.updateSuccess") : t("common.createSuccess")
      )
      onOpenChange(false)
      onSaved()
    } catch (error) {
      const data = (error as { data?: JSPluginReloadFailureResponse })?.data
      const compileError = data?.item?.compile_error
      const reloadError = data?.reload_error
      const message =
        typeof compileError === "string"
          ? compileError
          : typeof reloadError === "string"
            ? reloadError
            : error instanceof Error
              ? error.message
              : t("common.saveFailed")
      setSaveError(message)
      toast.error(message)
    }
  }

  const canSave =
    form.stage === "request" &&
    form.name.trim().length > 0 &&
    form.source.trim().length > 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-5xl">
        <DialogHeader>
          <DialogTitle>
            {editing ? t("jsPlugins.editTitle") : t("jsPlugins.addTitle")}
          </DialogTitle>
          <DialogDescription>
            {t("jsPlugins.dialogDescription")}
          </DialogDescription>
          {editing?.compile_error && (
            <Alert variant="destructive" className="mt-3">
              <IconAlertTriangle className="h-4 w-4" />
              <AlertTitle>{t("luaPlugins.compileError")}</AlertTitle>
              <AlertDescription className="break-all whitespace-pre-wrap">
                {editing.compile_error}
              </AlertDescription>
            </Alert>
          )}
          {responseStageLocked && (
            <Alert className="mt-3">
              <IconAlertTriangle className="h-4 w-4" />
              <AlertTitle>{t("jsPlugins.responseStageReadOnly")}</AlertTitle>
              <AlertDescription>
                {t("jsPlugins.responseStageMigrationHint")}
              </AlertDescription>
            </Alert>
          )}
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="script">
              {t("jsPlugins.tabs.script")}
            </TabsTrigger>
            <TabsTrigger value="help">{t("jsPlugins.tabs.help")}</TabsTrigger>
          </TabsList>
          <TabsContent value="script" className="space-y-4 pt-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>{t("jsPlugins.name")}</Label>
                <Input
                  value={form.name}
                  disabled={responseStageLocked}
                  onChange={(event) => update("name", event.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>{t("jsPlugins.stage")}</Label>
                <Select
                  value={form.stage}
                  onValueChange={(value) =>
                    update("stage", value as JSPluginStage)
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="request">
                      {t("jsPlugins.stageRequest")}
                    </SelectItem>
                    {editing?.stage === "response" && (
                      <SelectItem value="response" disabled>
                        {t("jsPlugins.stageResponse")}
                      </SelectItem>
                    )}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t("jsPlugins.failureMode")}</Label>
                <Select
                  value={form.failure_mode}
                  disabled={responseStageLocked}
                  onValueChange={(value) =>
                    update("failure_mode", value as JSPluginFailureMode)
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="fail_open">
                      {t("jsPlugins.failOpen")}
                    </SelectItem>
                    <SelectItem value="fail_closed">
                      {t("jsPlugins.failClosed")}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t("jsPlugins.priority")}</Label>
                <Input
                  type="number"
                  value={form.priority}
                  disabled={responseStageLocked}
                  onChange={(event) =>
                    update("priority", Number(event.target.value) || 0)
                  }
                />
              </div>
              <div className="space-y-2">
                <Label>{t("jsPlugins.timeout")}</Label>
                <Input
                  type="number"
                  min={0}
                  max={MAX_TIMEOUT_MS}
                  value={form.timeout_ms}
                  disabled={responseStageLocked}
                  onChange={(event) =>
                    update(
                      "timeout_ms",
                      Math.max(
                        0,
                        Math.min(
                          MAX_TIMEOUT_MS,
                          Number(event.target.value) || 0
                        )
                      )
                    )
                  }
                />
                <p className="text-xs text-muted-foreground">
                  {t("jsPlugins.timeoutHint", { max: MAX_TIMEOUT_MS })}
                </p>
              </div>
              <div className="space-y-2">
                <Label>{t("jsPlugins.scope")}</Label>
                <Select
                  value={form.site_id}
                  disabled={responseStageLocked}
                  onValueChange={(value) => update("site_id", value)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={GLOBAL_SCOPE}>
                      {t("jsPlugins.scopeGlobal")}
                    </SelectItem>
                    {sites.map((site) => (
                      <SelectItem key={site.id} value={String(site.id)}>
                        {site.host}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <Label>{t("jsPlugins.enabled")}</Label>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {t("jsPlugins.enabledHint")}
                </p>
              </div>
              <Switch
                checked={form.enabled}
                disabled={responseStageLocked}
                onCheckedChange={(value) => update("enabled", value)}
              />
            </div>

            <div className="space-y-2">
              <Label>{t("common.description")}</Label>
              <Textarea
                value={form.description}
                disabled={responseStageLocked}
                onChange={(event) => update("description", event.target.value)}
              />
            </div>

            <div className="space-y-3 rounded-lg border bg-muted/20 p-3">
              <div>
                <h3 className="text-sm font-semibold">
                  {t("jsPlugins.dryRunSampleTitle")}
                </h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  {t("jsPlugins.dryRunSampleDescription")}
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label>{t("jsPlugins.sampleMethod")}</Label>
                  <Input
                    value={sampleRequest.method}
                    onChange={(event) =>
                      updateSample("method", event.target.value)
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>{t("jsPlugins.samplePath")}</Label>
                  <Input
                    value={sampleRequest.path}
                    onChange={(event) =>
                      updateSample("path", event.target.value)
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>{t("jsPlugins.sampleRawQuery")}</Label>
                  <Input
                    value={sampleRequest.raw_query}
                    onChange={(event) =>
                      updateSample("raw_query", event.target.value)
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>{t("jsPlugins.sampleHost")}</Label>
                  <Input
                    value={sampleRequest.host}
                    onChange={(event) =>
                      updateSample("host", event.target.value)
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>{t("jsPlugins.sampleClientIP")}</Label>
                  <Input
                    value={sampleRequest.client_ip}
                    onChange={(event) =>
                      updateSample("client_ip", event.target.value)
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>{t("jsPlugins.sampleUserAgent")}</Label>
                  <Input
                    value={sampleRequest.user_agent}
                    onChange={(event) =>
                      updateSample("user_agent", event.target.value)
                    }
                  />
                </div>
                <div className="space-y-1 sm:col-span-2">
                  <Label>{t("jsPlugins.sampleContentType")}</Label>
                  <Input
                    value={sampleRequest.content_type}
                    onChange={(event) =>
                      updateSample("content_type", event.target.value)
                    }
                  />
                </div>
              </div>
              <div className="space-y-1">
                <Label>{t("jsPlugins.sampleBody")}</Label>
                <Textarea
                  value={sampleRequest.body}
                  onChange={(event) => updateSample("body", event.target.value)}
                  rows={3}
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label>{t("jsPlugins.sampleHeaders")}</Label>
                  <Textarea
                    value={sampleRequest.headers_json}
                    onChange={(event) =>
                      updateSample("headers_json", event.target.value)
                    }
                    rows={3}
                    className="font-mono text-xs"
                  />
                </div>
                <div className="space-y-1">
                  <Label>{t("jsPlugins.sampleQueryParams")}</Label>
                  <Textarea
                    value={sampleRequest.query_params_json}
                    onChange={(event) =>
                      updateSample("query_params_json", event.target.value)
                    }
                    rows={3}
                    className="font-mono text-xs"
                  />
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Label>{t("jsPlugins.source")}</Label>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleValidate}
                    disabled={
                      responseStageLocked || validating || !form.source.trim()
                    }
                  >
                    {validating
                      ? t("jsPlugins.validating")
                      : t("jsPlugins.validate")}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleDryRun}
                    disabled={responseStageLocked || dryRunning}
                  >
                    {dryRunning
                      ? t("jsPlugins.running")
                      : t("jsPlugins.dryRun")}
                  </Button>
                </div>
              </div>
              <LuaCodeEditor
                value={form.source}
                onChange={(value) => update("source", value)}
                readOnly={responseStageLocked}
                rows={16}
                ariaLabel={t("jsPlugins.source")}
              />
              <p className="text-xs text-muted-foreground">
                {t("jsPlugins.sourceHint")}
              </p>
              {validation?.valid && (
                <Badge
                  variant="outline"
                  className="border-emerald-500/30 text-emerald-700"
                >
                  {t("jsPlugins.validatePassed")}
                </Badge>
              )}
              {validation && !validation.valid && (
                <Alert variant="destructive">
                  <IconAlertTriangle className="h-4 w-4" />
                  <AlertTitle>{t("jsPlugins.validateFailed")}</AlertTitle>
                  <AlertDescription>{validation.error}</AlertDescription>
                </Alert>
              )}
              {dryRunError && (
                <Alert variant="destructive">
                  <IconAlertTriangle className="h-4 w-4" />
                  <AlertTitle>{t("jsPlugins.dryRunFailed")}</AlertTitle>
                  <AlertDescription className="space-y-2 break-all whitespace-pre-wrap">
                    <p>{dryRunError}</p>
                    {dryRunResponse !== null && dryRunResponse.result !== null && (
                      <div className="space-y-2">
                        <p>{t("jsPlugins.dryRunResult")}</p>
                        <pre className="max-h-56 overflow-auto rounded bg-muted p-2 text-xs break-all whitespace-pre-wrap">
                          {JSON.stringify(dryRunResponse.result, null, 2)}
                        </pre>
                        {dryRunResponse.execution_time_ms !== undefined && (
                          <p>
                            {t("jsPlugins.dryRunExecutionTime", {
                              value: dryRunResponse.execution_time_ms.toFixed(2),
                            })}
                          </p>
                        )}
                      </div>
                    )}
                  </AlertDescription>
                </Alert>
              )}
              {dryRunResponse && !dryRunError && (
                <Alert>
                  <IconInfoCircle className="h-4 w-4" />
                  <AlertTitle>{t("jsPlugins.dryRunPassed")}</AlertTitle>
                  <AlertDescription className="space-y-2">
                    <p>
                      {dryRunResponse.result &&
                      Object.keys(dryRunResponse.result).length === 0
                        ? t("jsPlugins.dryRunNoChanges")
                        : t("jsPlugins.dryRunResult")}
                    </p>
                    <pre className="max-h-56 overflow-auto rounded bg-muted p-2 text-xs break-all whitespace-pre-wrap">
                      {JSON.stringify(dryRunResponse.result, null, 2)}
                    </pre>
                    {dryRunResponse.execution_time_ms !== undefined && (
                      <p>
                        {t("jsPlugins.dryRunExecutionTime", {
                          value: dryRunResponse.execution_time_ms.toFixed(2),
                        })}
                      </p>
                    )}
                  </AlertDescription>
                </Alert>
              )}
              {runtimeMessage && (
                <Alert variant="destructive">
                  <IconAlertTriangle className="h-4 w-4" />
                  <AlertTitle>
                    {t("jsPlugins.runtimeUnavailableTitle")}
                  </AlertTitle>
                  <AlertDescription>{runtimeMessage}</AlertDescription>
                </Alert>
              )}
              {saveError && (
                <Alert variant="destructive">
                  <IconAlertTriangle className="h-4 w-4" />
                  <AlertTitle>{t("common.saveFailed")}</AlertTitle>
                  <AlertDescription className="break-all whitespace-pre-wrap">
                    {saveError}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          </TabsContent>
          <TabsContent value="help" className="pt-4">
            <JSHelpPanel />
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button onClick={handleSave} disabled={saving || !canSave}>
            {saving
              ? t("common.saving")
              : editing
                ? t("common.save")
                : t("common.create")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
