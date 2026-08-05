"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Separator } from "@/components/ui/separator"
import { ActionBadge } from "@/components/action-badge"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useLuaPluginDryRun } from "@/hooks/use-api"
import {
  IconPlayerPlay,
  IconAlertTriangle,
  IconClock,
  IconCircleCheck,
} from "@tabler/icons-react"
import type {
  LuaDryRunResult,
  LuaDryRunRequestView,
  LuaPluginStage,
} from "@/lib/types"
import { LUA_ACTIONS } from "./examples"

/** 试运行样例请求可选的方法，覆盖 WAF 实际会检测的动词。 */
const METHODS = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
] as const

/** 「模拟内置判定」下拉里代表「内置未拦截」的选项值（Select 不接受空字符串）。 */
const BUILTIN_NONE = "__none__"

/**
 * @typedef {object} SampleForm
 * @description 试运行样例请求的本地表单态。headers 以文本形式编辑，提交前解析。
 */
interface SampleForm {
  client_ip: string
  /** 传给 ctx.site_id 的样例站点 ID；仅用于构造试运行上下文。 */
  site_id: string
  method: string
  path: string
  query: string
  host: string
  user_agent: string
  content_type: string
  tls_version: string
  tls_ja3: string
  tls_ja4: string
  tls_sni: string
  body: string
  headersText: string
  /** 模拟前序管线命中的阶段，仅 post 阶段有意义 */
  phase: string
  /** 模拟前序管线的判定动作，仅 post 阶段有意义 */
  action: string
}

const emptySample: SampleForm = {
  client_ip: "203.0.113.7",
  site_id: "1",
  method: "GET",
  path: "/",
  query: "",
  host: "",
  user_agent: "Mozilla/5.0",
  content_type: "",
  tls_version: "",
  tls_ja3: "",
  tls_ja4: "",
  tls_sni: "",
  body: "",
  headersText: "",
  phase: "",
  action: BUILTIN_NONE,
}

/**
 * 把 "Name: value" 逐行文本解析为请求头表。
 *
 * 只按首个冒号切分：Cookie、Referer 之类的值本身常含冒号，按全部冒号切会截断值。
 * 键统一转小写——脚本侧 ctx.headers 是小写键表，这里不做则试运行与线上行为不一致。
 *
 * @param {string} text 逐行的请求头文本
 * @returns {Record<string, string>} 解析结果，空行与无冒号行被忽略
 */
function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":")
    if (idx <= 0) continue
    const name = line.slice(0, idx).trim().toLowerCase()
    const value = line.slice(idx + 1).trim()
    if (name) out[name] = value
  }
  return out
}

/**
 * 把毫秒数格式化为可读耗时。
 *
 * @param {number} ms 毫秒
 * @returns {string} 形如 "0.24ms" 或 "1.20s"
 */
function formatElapsed(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "-"
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${ms.toFixed(2)}ms`
}

/**
 * @typedef {object} DryRunPanelProps
 * @property {LuaPluginStage} stage 当前编辑的阶段，决定是否展示「模拟内置判定」
 * @property {string} source 待试运行的源码
 * @property {number} timeoutMs 超时（毫秒），0 表示用后端默认值
 */
export interface DryRunPanelProps {
  stage: LuaPluginStage
  source: string
  timeoutMs: number
}

/**
 * 试运行面板：填样例请求、执行脚本、展示判定与耗时。
 *
 * 不保存配置、不会改变线上脚本，但 ctx.kv.set/delete/incr 可能写入真实 Redis；后端每次使用独立的状态机池。
 *
 * @param {DryRunPanelProps} props 组件属性
 * @returns {React.ReactElement} 面板元素
 */
export function DryRunPanel({ stage, source, timeoutMs }: DryRunPanelProps) {
  const { t } = useTranslation()
  const [sample, setSample] = useState<SampleForm>(emptySample)
  const [iterations, setIterations] = useState(2)
  const [result, setResult] = useState<LuaDryRunResult | null>(null)
  const [requestError, setRequestError] = useState<string | null>(null)

  const { execute: dryRun, loading } = useLuaPluginDryRun()

  const set = <K extends keyof SampleForm>(key: K, value: SampleForm[K]) =>
    setSample((s) => ({ ...s, [key]: value }))

  const parsedHeaders = useMemo(
    () => parseHeaders(sample.headersText),
    [sample.headersText]
  )

  const handleRun = async () => {
    setRequestError(null)
    const siteID = Number.parseInt(sample.site_id, 10)
    const request: LuaDryRunRequestView = {
      client_ip: sample.client_ip,
      method: sample.method,
      path: sample.path,
      query: sample.query,
      host: sample.host,
      user_agent: sample.user_agent,
      content_type: sample.content_type,
      tls_version: sample.tls_version,
      tls_ja3: sample.tls_ja3,
      tls_ja4: sample.tls_ja4,
      tls_sni: sample.tls_sni,
      body: sample.body,
      headers: parsedHeaders,
    }
    if (Number.isInteger(siteID) && siteID > 0) {
      request.site_id = siteID
    }
    // phase/action 仅 post 阶段可读到，pre 阶段传了也只会误导用户。
    if (stage === "post") {
      request.phase = sample.phase
      request.action = sample.action === BUILTIN_NONE ? "" : sample.action
    }

    try {
      const res = await dryRun({
        stage,
        source,
        timeout_ms: timeoutMs,
        iterations,
        request,
      })
      setResult(res)
    } catch (err) {
      setResult(null)
      setRequestError((err as Error)?.message || t("error.unexpectedError"))
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">
        {t("luaPlugins.dryRun.hint")}
      </p>
      <p className="text-xs text-muted-foreground">
        {t("luaPlugins.dryRun.contractHint", {
          defaultValue:
            "试运行直接调用脚本：不会保存配置，但 ctx.kv.set/delete/incr 可能写入真实 Redis；KV 不可用时仍显示脚本结果，线上 Engine 会强制 fail-open。headers、response_body、tags 仍按后端边界校验。",
        })}
      </p>

      <div className="grid gap-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.method")}</Label>
          <Select value={sample.method} onValueChange={(v) => set("method", v)}>
            <SelectTrigger className="h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {METHODS.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.path")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.path}
            onChange={(e) => set("path", e.target.value)}
            placeholder="/api/login"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.query")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.query}
            onChange={(e) => set("query", e.target.value)}
            placeholder="id=1&debug=true"
          />
          <p className="text-xs text-muted-foreground">
            {t("luaPlugins.dryRun.queryParamsHint", {
              defaultValue:
                "后端将首个值写入 ctx.query_params，全部重复值按顺序写入 ctx.query_values。",
            })}
          </p>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.clientIp")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.client_ip}
            onChange={(e) => set("client_ip", e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">
            {t("luaPlugins.dryRun.siteId", { defaultValue: "站点 ID" })}
          </Label>
          <Input
            className="h-8 font-mono text-xs"
            type="number"
            min={1}
            step={1}
            value={sample.site_id}
            onChange={(e) => set("site_id", e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            {t("luaPlugins.dryRun.siteIdHint", {
              defaultValue:
                "仅设置 ctx.site_id；dry-run 不执行 Engine 的脚本站点作用域过滤。",
            })}
          </p>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.host")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.host}
            onChange={(e) => set("host", e.target.value)}
            placeholder="example.com"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">
            {t("luaPlugins.dryRun.contentType")}
          </Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.content_type}
            onChange={(e) => set("content_type", e.target.value)}
            placeholder="application/json"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.tlsVersion")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.tls_version}
            onChange={(e) => set("tls_version", e.target.value)}
            placeholder="TLS13"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.tlsJa3")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.tls_ja3}
            onChange={(e) => set("tls_ja3", e.target.value)}
            placeholder="JA3 hash"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.tlsJa4")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.tls_ja4}
            onChange={(e) => set("tls_ja4", e.target.value)}
            placeholder="t13d1516h2_..."
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">{t("luaPlugins.dryRun.tlsSni")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.tls_sni}
            onChange={(e) => set("tls_sni", e.target.value)}
            placeholder="example.com"
          />
        </div>
        <div className="space-y-1.5 sm:col-span-2">
          <Label className="text-xs">{t("luaPlugins.dryRun.userAgent")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            value={sample.user_agent}
            onChange={(e) => set("user_agent", e.target.value)}
          />
        </div>
        <div className="space-y-1.5 sm:col-span-2">
          <Label className="text-xs">{t("luaPlugins.dryRun.iterations")}</Label>
          <Input
            className="h-8 font-mono text-xs"
            type="number"
            min={1}
            max={100}
            value={iterations}
            onChange={(e) => {
              const value = Number(e.target.value)
              setIterations(
                Number.isFinite(value) ? Math.min(100, Math.max(1, value)) : 1
              )
            }}
          />
          <p className="text-xs text-muted-foreground">
            {t("luaPlugins.dryRun.iterationsHint")}
          </p>
        </div>
        <div className="space-y-1.5 sm:col-span-2">
          <Label className="text-xs">{t("luaPlugins.dryRun.headers")}</Label>
          <Textarea
            className="min-h-20 font-mono text-xs"
            value={sample.headersText}
            onChange={(e) => set("headersText", e.target.value)}
            placeholder={
              "X-Forwarded-For: 203.0.113.7\nReferer: https://example.com/"
            }
            spellCheck={false}
          />
          <p className="text-xs text-muted-foreground">
            {t("luaPlugins.dryRun.headersHint", {
              count: Object.keys(parsedHeaders).length,
            })}
          </p>
          <p className="text-xs text-muted-foreground">
            {t("luaPlugins.dryRun.headersLimitHint", {
              defaultValue:
                "Decision 输出 headers 最多 256 项，每值最多 4 KiB；非法、敏感、逐跳及 Content-Length/Location 等头会被后端拒绝。",
            })}
          </p>
        </div>
        <div className="space-y-1.5 sm:col-span-2">
          <Label className="text-xs">{t("luaPlugins.dryRun.body")}</Label>
          <Textarea
            className="min-h-20 font-mono text-xs"
            value={sample.body}
            onChange={(e) => set("body", e.target.value)}
            placeholder='{"username":"admin"}'
            spellCheck={false}
          />
        </div>

        {stage === "post" && (
          <>
            <div className="space-y-1.5 sm:col-span-2">
              <Separator />
              <p className="pt-1 text-xs text-muted-foreground">
                {t("luaPlugins.dryRun.builtinHint")}
              </p>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">
                {t("luaPlugins.dryRun.builtinAction")}
              </Label>
              <Select
                value={sample.action}
                onValueChange={(v) => set("action", v)}
              >
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={BUILTIN_NONE}>
                    {t("luaPlugins.dryRun.builtinNone")}
                  </SelectItem>
                  {LUA_ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">
                {t("luaPlugins.dryRun.builtinPhase")}
              </Label>
              <Input
                className="h-8 font-mono text-xs"
                value={sample.phase}
                onChange={(e) => set("phase", e.target.value)}
                placeholder="owasp"
              />
            </div>
          </>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Button
          onClick={handleRun}
          disabled={loading || !source.trim()}
          size="sm"
        >
          <IconPlayerPlay className="h-4 w-4" />
          {loading
            ? t("luaPlugins.dryRun.running")
            : t("luaPlugins.dryRun.run")}
        </Button>
        {!source.trim() && (
          <span className="text-xs text-muted-foreground">
            {t("luaPlugins.dryRun.needSource")}
          </span>
        )}
      </div>

      {requestError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3">
          <p className="flex items-center gap-1.5 text-xs font-medium text-destructive">
            <IconAlertTriangle className="h-4 w-4" />
            {t("luaPlugins.dryRun.requestFailed")}
          </p>
          <p className="mt-1 font-mono text-xs break-all text-destructive">
            {requestError}
          </p>
        </div>
      )}

      {result && <DryRunResultView result={result} />}
    </div>
  )
}

/**
 * 试运行结果展示。
 *
 * 编译错误优先于其它信息：编译未通过时 decision 与耗时都没有意义，
 * 一并铺开只会让用户误读。
 *
 * @param {{ result: LuaDryRunResult }} props 组件属性
 * @returns {React.ReactElement} 结果区元素
 */
function DryRunResultView({ result }: { result: LuaDryRunResult }) {
  const { t } = useTranslation()
  const { decision } = result

  if (result.compile_error) {
    return (
      <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3">
        <p className="flex items-center gap-1.5 text-xs font-medium text-destructive">
          <IconAlertTriangle className="h-4 w-4" />
          {t("luaPlugins.compileError")}
        </p>
        <pre className="mt-1.5 overflow-x-auto font-mono text-xs whitespace-pre-wrap text-destructive">
          {result.compile_error}
        </pre>
      </div>
    )
  }

  const headerEntries = Object.entries(decision.SetHeaders ?? {})
  const tags = decision.Tags ?? []

  return (
    <div className="space-y-3 rounded-lg border p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs font-medium text-muted-foreground">
          {t("luaPlugins.dryRun.decision")}
        </span>
        {decision.Action ? (
          <ActionBadge action={decision.Action} />
        ) : (
          <Badge variant="outline" className="gap-1">
            <IconCircleCheck className="h-3.5 w-3.5" />
            {t("luaPlugins.dryRun.noDecision")}
          </Badge>
        )}
        <Badge
          variant={result.kv_available ? "secondary" : "destructive"}
          className="gap-1"
        >
          {result.kv_available
            ? t("luaPlugins.dryRun.kvAvailable")
            : t("luaPlugins.dryRun.kvUnavailable")}
        </Badge>
        <span className="ms-auto flex items-center gap-1 font-mono text-xs text-muted-foreground">
          <IconClock className="h-3.5 w-3.5" />
          {formatElapsed(result.elapsed_ms)}
        </span>
      </div>

      {!result.kv_available && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3">
          <p className="flex items-center gap-1.5 text-xs font-medium text-destructive">
            <IconAlertTriangle className="h-4 w-4" />
            {t("luaPlugins.dryRun.kvUnavailableTitle")}
          </p>
          <p className="mt-1 text-xs text-destructive">
            {t("luaPlugins.dryRun.kvUnavailableHint")}
          </p>
        </div>
      )}

      {!decision.Action && (
        <p className="text-xs text-muted-foreground">
          {t("luaPlugins.dryRun.noDecisionHint")}
        </p>
      )}

      <p className="text-xs text-muted-foreground">
        {t("luaPlugins.dryRun.decisionSemantics")}
      </p>

      {result.runtime_error && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3">
          <p className="flex items-center gap-1.5 text-xs font-medium text-destructive">
            <IconAlertTriangle className="h-4 w-4" />
            {t("luaPlugins.runtimeError")}
          </p>
          <pre className="mt-1.5 overflow-x-auto font-mono text-xs whitespace-pre-wrap text-destructive">
            {result.runtime_error}
          </pre>
        </div>
      )}

      <dl className="grid gap-x-4 gap-y-2 text-xs sm:grid-cols-[8rem_1fr]">
        <ResultRow
          label={t("luaPlugins.dryRun.iteration")}
          value={`${result.iteration || 1} / ${result.iterations || 1}`}
        />
        <ResultRow
          label={t("luaPlugins.dryRun.message")}
          value={decision.Message}
        />
        <ResultRow
          label={t("luaPlugins.dryRun.statusCode")}
          value={decision.StatusCode ? String(decision.StatusCode) : ""}
        />
        <ResultRow
          label={t("luaPlugins.dryRun.redirectTo")}
          value={decision.RedirectTo}
        />
        <ResultRow
          label={t("luaPlugins.dryRun.setHeaders")}
          value={
            headerEntries.length > 0
              ? headerEntries.map(([k, v]) => `${k}: ${v}`).join("\n")
              : ""
          }
        />
        <ResultRow
          label={t("luaPlugins.dryRun.responseBody", {
            defaultValue: "response_body",
          })}
          value={decision.ResponseBody}
        />
        <ResultRow
          label={t("luaPlugins.dryRun.tags")}
          value={tags.length > 0 ? tags.join(", ") : ""}
        />
        <div className="text-[11px] text-muted-foreground sm:col-span-2">
          {t("luaPlugins.dryRun.outputApplicability", {
            defaultValue:
              "response_body 只覆盖普通 Lua 终止响应；challenge、redirect、drop 与上游响应不会使用它。tags 已进入 Result，但尚未持久化日志。",
          })}
        </div>
      </dl>

      {result.runs && result.runs.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">
            {t("luaPlugins.dryRun.runTrace")}
          </p>
          <div className="space-y-1.5">
            {result.runs.map((run) => (
              <div
                key={run.iteration}
                className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/30 px-3 py-2 text-xs"
              >
                <span className="font-mono text-muted-foreground">
                  #{run.iteration}
                </span>
                {run.decision.Action ? (
                  <ActionBadge action={run.decision.Action} />
                ) : (
                  <Badge variant="outline">
                    {t("luaPlugins.dryRun.noDecision")}
                  </Badge>
                )}
                {run.runtime_error && (
                  <Badge variant="destructive">
                    {t("luaPlugins.runtimeError")}
                  </Badge>
                )}
                {run.decision.Message && (
                  <span className="min-w-0 flex-1 truncate font-mono">
                    {run.decision.Message}
                  </span>
                )}
                <span className="ms-auto font-mono text-muted-foreground">
                  {formatElapsed(run.elapsed_ms)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * 结果里的一行「标签 - 值」。值为空时显示占位符而非整行隐藏，
 * 让用户能确认字段确实为空、而不是界面漏渲染。
 *
 * @param {{ label: string; value: string }} props 组件属性
 * @returns {React.ReactElement} 一行定义列表元素
 */
function ResultRow({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0">
        {value ? (
          <pre className="overflow-x-auto font-mono break-all whitespace-pre-wrap">
            {value}
          </pre>
        ) : (
          <span className="text-muted-foreground">-</span>
        )}
      </dd>
    </>
  )
}
