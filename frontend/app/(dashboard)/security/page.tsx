"use client"

import { useEffect, useId, useState } from "react"
import Link from "next/link"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import {
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
} from "@/lib/api"
import {
  AlertTriangle,
  Shield,
  ShieldCheck,
  Link2,
  RotateCcw,
  Search,
  TrendingUp,
  Plus,
  Trash2,
  ArrowUp,
  ArrowDown,
  Loader2,
  Play,
  ExternalLink,
} from "@/lib/icons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import {
  Alert,
  AlertAction,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  EmptyState,
  Notice,
  PageIntro,
  Surface,
} from "@/components/console-shell"
import { CopyableBlock } from "@/components/log-presentation"
import {
  getCaptchaConfig,
  updateCaptchaConfig,
  testCaptcha,
  getChainConfig,
  updateChainConfig,
  listChainSessions,
  deleteChainSession,
  getEscalationConfig,
  updateEscalationConfig,
  getEscalationIPStatus,
  resetEscalationIPStatus,
  CAPTCHA_TYPE_OPTIONS,
  defaultCaptchaConfig,
  type CaptchaConfig,
  type CaptchaTestResponse,
  type ChainConfig,
  type ChainSession,
  type ChainStep,
  type EscalationStep,
  type EscalationConfig,
  type EscalationIPStatus,
} from "@/lib/security-api"

function captchaTypeLabel(value: string) {
  return (
    CAPTCHA_TYPE_OPTIONS.find((option) => option.value === value)?.label ??
    value
  )
}

function readReloadFailureDetails(error: unknown) {
  return getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
}

function captchaPreviewOperationResponse(response: CaptchaTestResponse) {
  return {
    session_id: response.session_id,
    captcha_type: response.captcha_type,
    type: response.type,
    prompt: response.prompt,
    width: response.width,
    height: response.height,
    timeout: response.timeout,
    pass_ttl: response.pass_ttl,
    fallback: response.fallback ?? false,
    master_img_present: Boolean(response.master_img),
    master_img_length: response.master_img.length,
    thumb_img_present: Boolean(response.thumb_img),
    thumb_img_length: response.thumb_img?.length ?? 0,
  }
}

function ReloadFailureDetailsAlert({
  details,
  description,
}: {
  details: Record<string, unknown>
  description: string
}) {
  return (
    <Alert className="gap-3">
      <AlertTriangle />
      <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
      <AlertDescription>{description}</AlertDescription>
      <CopyableBlock
        label="reload 失败响应体"
        value={JSON.stringify(details, null, 2)}
        redact
        defaultOpen={false}
      />
    </Alert>
  )
}

function OperationDetailsAlert({
  details,
  title,
  description,
  label,
  icon: Icon,
}: {
  details: Record<string, unknown>
  title: string
  description: string
  label: string
  icon: typeof Shield
}) {
  return (
    <Alert className="gap-3">
      <Icon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{description}</AlertDescription>
      <CopyableBlock
        label={label}
        value={JSON.stringify(details, null, 2)}
        redact
        defaultOpen={false}
      />
    </Alert>
  )
}

/* ───────── 验证码 Tab ───────── */
function CaptchaTab() {
  const captchaEnabledId = useId()
  const captchaTimeoutId = useId()
  const captchaPassTtlId = useId()
  const captchaTypeId = useId()
  const [cfg, setCfg] = useState<CaptchaConfig>({ ...defaultCaptchaConfig })
  const [preview, setPreview] = useState<CaptchaTestResponse | null>(null)
  const [captchaAnswer, setCaptchaAnswer] = useState("")
  const [clickPoints, setClickPoints] = useState<
    Array<{ x: number; y: number }>
  >([])
  const [slideX, setSlideX] = useState(0)
  const [rotateAngle, setRotateAngle] = useState(0)
  const [captchaImageSize, setCaptchaImageSize] = useState({
    width: 0,
    height: 0,
  })
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  useEffect(() => {
    getCaptchaConfig()
      .then(setCfg)
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载验证码配置失败")
      )
  }, [])

  async function save() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    let submittedPayload: CaptchaConfig | null = null
    try {
      const latest = await getCaptchaConfig()
      const payload: CaptchaConfig = {
        ...latest,
        captcha_enabled: cfg.captcha_enabled,
        captcha_type: cfg.captcha_type,
        captcha_timeout: cfg.captcha_timeout,
        captcha_pass_ttl: cfg.captcha_pass_ttl,
      }
      submittedPayload = payload
      const saved = await updateCaptchaConfig(payload)
      setOperationDetails({
        operation: "update",
        payload,
        response: saved,
      })
      setCfg(saved)
      toast.success("验证码配置已保存")
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        const details = readReloadFailureDetails(e)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "update",
            payload: submittedPayload,
            response: details,
          })
        }
        const latest = await getCaptchaConfig()
        setCfg(latest)
      }
      toast.error(e instanceof Error ? e.message : "保存验证码配置失败")
    } finally {
      setSaving(false)
    }
  }

  async function doTest() {
    setOperationDetails(null)
    setTesting(true)
    try {
      const r = await testCaptcha()
      setPreview(r)
      setCaptchaAnswer("")
      setClickPoints([])
      setSlideX(0)
      setRotateAngle(0)
      setCaptchaImageSize({ width: 0, height: 0 })
      setOperationDetails({
        operation: "preview",
        payload: null,
        response: captchaPreviewOperationResponse(r),
      })
      if (r.fallback) {
        toast.warning("当前验证码类型已回退到内置算术验证码")
        return
      }
      toast.success("验证码预览已生成")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "生成验证码预览失败")
    } finally {
      setTesting(false)
    }
  }

  function handleCaptchaClick(event: React.MouseEvent<HTMLImageElement>) {
    if (!preview || preview.type !== "click") return
    const rect = event.currentTarget.getBoundingClientRect()
    const naturalWidth = event.currentTarget.naturalWidth || rect.width
    const naturalHeight = event.currentTarget.naturalHeight || rect.height
    const x = Math.round(
      ((event.clientX - rect.left) / rect.width) * naturalWidth
    )
    const y = Math.round(
      ((event.clientY - rect.top) / rect.height) * naturalHeight
    )
    const next = [...clickPoints, { x, y }]
    setClickPoints(next)
    setCaptchaAnswer(JSON.stringify(next))
  }

  function updateSlideAnswer(value: number) {
    setSlideX(value)
    setCaptchaAnswer(JSON.stringify({ x: value }))
  }

  function updateRotateAnswer(value: number) {
    setRotateAngle(value)
    setCaptchaAnswer(JSON.stringify({ angle: value }))
  }

  function currentAnswerHint() {
    if (!preview) return ""
    if (preview.type === "click") {
      return clickPoints.length
        ? JSON.stringify(clickPoints)
        : "请在主图中按顺序点击目标"
    }
    if (preview.type === "slide") return JSON.stringify({ x: slideX })
    if (preview.type === "rotate") return JSON.stringify({ angle: rotateAngle })
    return captchaAnswer || "请输入算术结果"
  }

  return (
    <Surface
      title="验证码类型配置"
      description="规则动作触发 captcha_challenge 时使用本配置；连锁验证的验证码步骤使用步骤内的 captcha_type。"
    >
      {reloadFailureDetails ? (
        <ReloadFailureDetailsAlert
          details={reloadFailureDetails}
          description="后端已返回验证码配置操作响应体；请核对 error 字段。"
        />
      ) : null}
      {operationDetails ? (
        <OperationDetailsAlert
          details={operationDetails}
          title="最近验证码操作响应"
          description="后端已返回验证码操作响应体；请核对 operation、payload 或 response 字段。"
          label="验证码操作响应体"
          icon={ShieldCheck}
        />
      ) : null}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,560px)_minmax(320px,1fr)]">
        <FieldGroup className="flex flex-col gap-5">
          <Field
            orientation="horizontal"
            className="rounded-xl border bg-muted/35 px-4 py-3"
          >
            <FieldContent>
              <FieldLabel htmlFor={captchaEnabledId}>
                启用 captcha_challenge
              </FieldLabel>
              <FieldDescription>
                关闭后命中验证码动作会退回通用挑战页，不会生成具体验证码。
              </FieldDescription>
            </FieldContent>
            <Switch
              id={captchaEnabledId}
              checked={cfg.captcha_enabled}
              onCheckedChange={(v) => setCfg({ ...cfg, captcha_enabled: v })}
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor={captchaTimeoutId}>
                验证超时时间（秒）
              </FieldLabel>
              <Input
                id={captchaTimeoutId}
                type="number"
                min={10}
                max={600}
                value={cfg.captcha_timeout}
                onChange={(e) =>
                  setCfg({ ...cfg, captcha_timeout: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor={captchaPassTtlId}>
                通过有效期（秒）
              </FieldLabel>
              <Input
                id={captchaPassTtlId}
                type="number"
                min={10}
                max={3600}
                value={cfg.captcha_pass_ttl}
                onChange={(e) =>
                  setCfg({ ...cfg, captcha_pass_ttl: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </Field>
          </div>
          <Field>
            <FieldLabel htmlFor={captchaTypeId}>验证码类型</FieldLabel>
            <Select
              value={cfg.captcha_type}
              onValueChange={(v: CaptchaConfig["captcha_type"]) =>
                setCfg({ ...cfg, captcha_type: v })
              }
            >
              <SelectTrigger id={captchaTypeId} className="rounded-md">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {CAPTCHA_TYPE_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <FieldDescription>
              {
                CAPTCHA_TYPE_OPTIONS.find(
                  (option) => option.value === cfg.captcha_type
                )?.description
              }
            </FieldDescription>
          </Field>
          <Alert>
            <AlertTitle>触发关系</AlertTitle>
            <AlertDescription>
              验证码类型不会由 HTTP 状态码决定，而是由 WAF 动作决定：规则动作为
              <code className="mx-1 rounded bg-muted px-1 py-0.5">
                captcha_challenge
              </code>
              时使用本配置；5 秒盾和连锁验证有独立流程。
            </AlertDescription>
          </Alert>
          <div className="flex gap-3 pt-2">
            <Button
              onClick={doTest}
              variant="outline"
              className="rounded-md"
              disabled={testing}
            >
              {testing ? (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              ) : (
                <Play data-icon="inline-start" />
              )}
              生成预览
            </Button>
            <Button onClick={save} disabled={saving}>
              {saving ? "保存中..." : "保存配置"}
            </Button>
          </div>
        </FieldGroup>
        <div className="console-panel p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-foreground">
                当前预览
              </div>
              <div className="text-xs text-muted-foreground">
                预览会创建一次性 session，不包含答案。
              </div>
            </div>
            {preview && (
              <Badge variant={preview.fallback ? "secondary" : "outline"}>
                {captchaTypeLabel(preview.type)}
              </Badge>
            )}
          </div>
          {preview ? (
            <div className="flex flex-col gap-3">
              <div className="overflow-hidden rounded-xl border bg-background p-3">
                <div className="relative mx-auto w-fit">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={preview.master_img}
                    alt="captcha preview"
                    className={
                      preview.type === "click"
                        ? "mx-auto max-h-64 max-w-full cursor-crosshair rounded-md object-contain"
                        : "mx-auto max-h-64 max-w-full rounded-md object-contain"
                    }
                    style={
                      preview.type === "rotate"
                        ? { transform: `rotate(${rotateAngle}deg)` }
                        : undefined
                    }
                    onClick={handleCaptchaClick}
                    onLoad={(event) =>
                      setCaptchaImageSize({
                        width:
                          event.currentTarget.naturalWidth ||
                          preview.width ||
                          1,
                        height:
                          event.currentTarget.naturalHeight ||
                          preview.height ||
                          1,
                      })
                    }
                  />
                  {preview.type === "click" &&
                    clickPoints.map((point, idx) => {
                      const naturalWidth =
                        captchaImageSize.width || preview.width || 1
                      const naturalHeight =
                        captchaImageSize.height || preview.height || 1
                      const left = `${(point.x / naturalWidth) * 100}%`
                      const top = `${(point.y / naturalHeight) * 100}%`
                      return (
                        <span
                          key={`${point.x}-${point.y}-${idx}`}
                          className="absolute -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary px-1.5 py-0.5 text-[10px] font-bold text-primary-foreground shadow"
                          style={{ left, top }}
                        >
                          {idx + 1}
                        </span>
                      )
                    })}
                </div>
                {preview.thumb_img && (
                  <>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={preview.thumb_img}
                      alt="captcha target preview"
                      className={
                        preview.type === "slide"
                          ? "mt-3 max-h-24 max-w-full rounded-md object-contain"
                          : "mx-auto mt-3 max-h-24 max-w-full rounded-md object-contain"
                      }
                      style={
                        preview.type === "slide"
                          ? { transform: `translateX(${slideX}px)` }
                          : undefined
                      }
                    />
                  </>
                )}
              </div>
              <div className="rounded-xl border bg-background p-3 text-xs leading-5 text-muted-foreground">
                <div className="font-medium text-foreground">
                  {preview.prompt}
                </div>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <div className="rounded-lg border bg-muted/35 px-3 py-2">
                    <div className="text-[11px] text-muted-foreground">
                      配置类型
                    </div>
                    <div className="mt-1 font-medium text-foreground">
                      {captchaTypeLabel(preview.captcha_type)}
                    </div>
                  </div>
                  <div className="rounded-lg border bg-muted/35 px-3 py-2">
                    <div className="text-[11px] text-muted-foreground">
                      实际生成
                    </div>
                    <div className="mt-1 font-medium text-foreground">
                      {captchaTypeLabel(preview.type)}
                    </div>
                  </div>
                </div>
                <div className="mt-3 flex flex-col gap-2">
                  {preview.type === "math" && (
                    <Input
                      value={captchaAnswer}
                      onChange={(event) => setCaptchaAnswer(event.target.value)}
                      placeholder="输入算术结果"
                      className="rounded-md"
                    />
                  )}
                  {preview.type === "click" && (
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="rounded-md"
                        onClick={() => {
                          setClickPoints([])
                          setCaptchaAnswer("")
                        }}
                      >
                        清空点击点
                      </Button>
                      <span>已选择 {clickPoints.length} 个点击点</span>
                    </div>
                  )}
                  {preview.type === "slide" && (
                    <Input
                      type="range"
                      min={0}
                      max={preview.width || 360}
                      value={slideX}
                      onChange={(event) =>
                        updateSlideAnswer(Number(event.target.value))
                      }
                    />
                  )}
                  {preview.type === "rotate" && (
                    <Input
                      type="range"
                      min={0}
                      max={360}
                      value={rotateAngle}
                      onChange={(event) =>
                        updateRotateAnswer(Number(event.target.value))
                      }
                    />
                  )}
                  <div className="rounded bg-muted px-2 py-1 font-mono text-[11px] break-all text-muted-foreground">
                    验证提交值预览：{currentAnswerHint()}
                  </div>
                </div>
                <div className="mt-1 break-all">
                  Session: {preview.session_id}
                </div>
                <div>
                  Timeout: {preview.timeout}s · Pass TTL:{" "}
                  {preview.pass_ttl ?? cfg.captcha_pass_ttl}s
                </div>
                {preview.fallback && (
                  <Alert className="mt-2">
                    <AlertDescription>
                      后端返回的配置类型为{" "}
                      <code className="rounded bg-muted px-1 py-0.5">
                        {preview.captcha_type}
                      </code>
                      ，实际生成类型为{" "}
                      <code className="rounded bg-muted px-1 py-0.5">
                        {preview.type}
                      </code>
                      。go-captcha 资源不可用或生成失败时会回退到内置
                      math，已保存的验证码类型不会被改写。
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </div>
          ) : (
            <EmptyState
              title="尚未生成验证码预览"
              description="点击“生成预览”查看后端真实验证码资源。"
            />
          )}
        </div>
      </div>
    </Surface>
  )
}

/* ───────── 5 秒盾 Tab ───────── */
function ShieldTab() {
  const shieldEnabledId = useId()
  const shieldDifficultyId = useId()
  const shieldTimeoutId = useId()
  const shieldDelayId = useId()
  const shieldRetriesId = useId()
  const shieldEnvStrictnessId = useId()
  const [cfg, setCfg] = useState<CaptchaConfig>({ ...defaultCaptchaConfig })
  const [saving, setSaving] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  useEffect(() => {
    getCaptchaConfig()
      .then(setCfg)
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载验证码配置失败")
      )
  }, [])

  async function save() {
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    let submittedPayload: CaptchaConfig | null = null
    try {
      const latest = await getCaptchaConfig()
      const payload: CaptchaConfig = {
        ...latest,
        shield_enabled: cfg.shield_enabled,
        shield_difficulty: cfg.shield_difficulty,
        shield_timeout_secs: cfg.shield_timeout_secs,
        shield_auto_start_delay: cfg.shield_auto_start_delay,
        shield_max_retries: cfg.shield_max_retries,
        shield_env_strictness: cfg.shield_env_strictness,
        shield_require_http2: cfg.shield_require_http2,
        shield_require_http3: cfg.shield_require_http3,
        shield_allow_http1: cfg.shield_allow_http1,
        shield_enable_wasm: cfg.shield_enable_wasm,
        shield_enable_js_challenge: cfg.shield_enable_js_challenge,
        shield_enable_env_check: cfg.shield_enable_env_check,
        shield_enable_devtools: cfg.shield_enable_devtools,
      }
      submittedPayload = payload
      const saved = await updateCaptchaConfig(payload)
      setOperationDetails({
        operation: "update",
        payload,
        response: saved,
      })
      setCfg(saved)
      toast.success("5 秒盾配置已保存")
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        const details = readReloadFailureDetails(e)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "update",
            payload: submittedPayload,
            response: details,
          })
        }
        const latest = await getCaptchaConfig()
        setCfg(latest)
      }
      toast.error(e instanceof Error ? e.message : "保存 5 秒盾配置失败")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <Surface
        title="5 秒盾基础配置"
        description="基于 PoW、JavaScript/WASM、环境指纹和协议约束的浏览器挑战。"
      >
        {reloadFailureDetails ? (
          <ReloadFailureDetailsAlert
            details={reloadFailureDetails}
            description="后端已返回 5 秒盾配置操作响应体；请核对 error 字段。"
          />
        ) : null}
        {operationDetails ? (
          <OperationDetailsAlert
            details={operationDetails}
            title="最近 5 秒盾配置操作响应"
            description="后端已返回 5 秒盾配置操作响应体；请核对 operation、payload 与 response 字段。"
            label="5 秒盾配置操作响应体"
            icon={Shield}
          />
        ) : null}
        <FieldGroup className="max-w-xl">
          <Field
            orientation="horizontal"
            className="rounded-lg border bg-muted/35 px-4 py-3"
          >
            <FieldLabel htmlFor={shieldEnabledId}>启用 5 秒盾</FieldLabel>
            <Switch
              id={shieldEnabledId}
              checked={cfg.shield_enabled}
              onCheckedChange={(v) => setCfg({ ...cfg, shield_enabled: v })}
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor={shieldDifficultyId}>
                PoW 难度（前导零位数）
              </FieldLabel>
              <Input
                id={shieldDifficultyId}
                type="number"
                min={1}
                max={32}
                value={cfg.shield_difficulty}
                onChange={(e) =>
                  setCfg({ ...cfg, shield_difficulty: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor={shieldTimeoutId}>验证超时（秒）</FieldLabel>
              <Input
                id={shieldTimeoutId}
                type="number"
                min={5}
                max={300}
                value={cfg.shield_timeout_secs ?? 30}
                onChange={(e) =>
                  setCfg({
                    ...cfg,
                    shield_timeout_secs: Number(e.target.value),
                  })
                }
                className="rounded-md"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor={shieldDelayId}>
                自动启动延迟（ms）
              </FieldLabel>
              <Input
                id={shieldDelayId}
                type="number"
                min={0}
                max={5000}
                value={cfg.shield_auto_start_delay ?? 800}
                onChange={(e) =>
                  setCfg({
                    ...cfg,
                    shield_auto_start_delay: Number(e.target.value),
                  })
                }
                className="rounded-md"
              />
            </Field>
            <Field>
              <FieldLabel htmlFor={shieldRetriesId}>最大重试次数</FieldLabel>
              <Input
                id={shieldRetriesId}
                type="number"
                min={1}
                max={10}
                value={cfg.shield_max_retries ?? 3}
                onChange={(e) =>
                  setCfg({ ...cfg, shield_max_retries: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </Field>
          </div>
          <Field>
            <FieldLabel htmlFor={shieldEnvStrictnessId}>
              环境检测严格度
            </FieldLabel>
            <Select
              value={String(cfg.shield_env_strictness ?? 1)}
              onValueChange={(v) =>
                setCfg({ ...cfg, shield_env_strictness: Number(v) })
              }
            >
              <SelectTrigger id={shieldEnvStrictnessId} className="rounded-md">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="0">宽松（仅基础检测）</SelectItem>
                  <SelectItem value="1">标准（推荐）</SelectItem>
                  <SelectItem value="2">严格（可能增加误报）</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
        </FieldGroup>
      </Surface>

      <Surface title="挑战策略" description="控制使用哪些验证手段组合。">
        <FieldGroup className="grid max-w-xl gap-3 sm:grid-cols-2">
          {[
            {
              key: "shield_enable_wasm" as const,
              label: "WASM PoW",
              desc: "使用 WebAssembly 执行工作量证明（性能更高）",
            },
            {
              key: "shield_enable_js_challenge" as const,
              label: "JS 挑战",
              desc: "JavaScript 环境验证和动态检测",
            },
            {
              key: "shield_enable_env_check" as const,
              label: "环境指纹",
              desc: "收集浏览器环境数据进行自动化检测",
            },
            {
              key: "shield_enable_devtools" as const,
              label: "DevTools 检测",
              desc: "检测是否打开了浏览器开发者工具",
            },
          ].map(({ key, label, desc }) => (
            <Field
              key={key}
              orientation="horizontal"
              className="flex items-center justify-between gap-3 rounded-lg border bg-muted/35 px-4 py-3"
            >
              <FieldContent>
                <FieldLabel>{label}</FieldLabel>
                <FieldDescription>{desc}</FieldDescription>
              </FieldContent>
              <Switch
                checked={cfg[key] !== false}
                onCheckedChange={(v) => setCfg({ ...cfg, [key]: v })}
              />
            </Field>
          ))}
        </FieldGroup>
      </Surface>

      <Surface
        title="HTTP 协议版本要求"
        description="限制客户端必须使用的 HTTP 协议版本，可用于过滤低质量流量。"
      >
        <div className="flex flex-col gap-3">
          <FieldGroup className="grid max-w-xl gap-3 sm:grid-cols-3">
            {[
              {
                key: "shield_allow_http1" as const,
                label: "允许 HTTP/1.1",
                desc: "允许 HTTP/1.0 和 HTTP/1.1 连接",
              },
              {
                key: "shield_require_http2" as const,
                label: "要求 HTTP/2",
                desc: "要求客户端支持 HTTP/2 协议",
              },
              {
                key: "shield_require_http3" as const,
                label: "要求 HTTP/3",
                desc: "要求客户端支持 HTTP/3 (QUIC)",
              },
            ].map(({ key, label, desc }) => (
              <Field
                key={key}
                className="flex flex-col gap-1 rounded-lg border bg-muted/35 px-4 py-3"
              >
                <div className="flex items-center justify-between gap-2">
                  <FieldLabel>{label}</FieldLabel>
                  <Switch
                    checked={cfg[key] === true}
                    onCheckedChange={(v) => setCfg({ ...cfg, [key]: v })}
                  />
                </div>
                <FieldDescription>{desc}</FieldDescription>
              </Field>
            ))}
          </FieldGroup>
          <Alert className="max-w-xl">
            <AlertTitle>协议兼容性</AlertTitle>
            <AlertDescription>
              同时要求 HTTP/2 和 HTTP/3 时，客户端需支持其中任一即可通过。禁用
              HTTP/1.1 可能会阻止部分旧版浏览器和 CLI 工具。
            </AlertDescription>
          </Alert>
        </div>
      </Surface>

      <div className="flex justify-end pb-4">
        <Button onClick={save} disabled={saving} className="rounded-md">
          {saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </div>
  )
}

/* ───────── 连锁策略 Tab ───────── */
function ChainTab() {
  const chainEnabledId = useId()
  const [enabled, setEnabled] = useState(false)
  const [steps, setSteps] = useState<ChainStep[]>([])
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  useEffect(() => {
    getChainConfig()
      .then((c) => {
        setEnabled(c.chain_enabled)
        setSteps(Array.isArray(c.chain_steps) ? c.chain_steps : [])
        setLoaded(true)
      })
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载连锁策略失败")
      )
  }, [])

  function addStep() {
    setSteps([...steps, { type: "env", condition: "all" }])
  }
  function removeStep(i: number) {
    setSteps(steps.filter((_, idx) => idx !== i))
  }
  function moveStep(i: number, dir: -1 | 1) {
    const j = i + dir
    if (j < 0 || j >= steps.length) return
    const arr = [...steps]
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
    setSteps(arr)
  }
  function updateStep(i: number, patch: Partial<ChainStep>) {
    setSteps(
      steps.map((s, idx) => {
        if (idx !== i) return s
        const next = { ...s, ...patch }
        if (patch.type && patch.type !== "captcha") {
          delete next.captcha_type
        }
        if (patch.type === "captcha" && !next.captcha_type) {
          next.captcha_type = "math"
        }
        return next
      })
    )
  }

  async function save() {
    if (!loaded) {
      toast.error("连锁策略加载完成后再保存")
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    let submittedPayload: Partial<ChainConfig> | null = null
    try {
      const payload: Partial<ChainConfig> = {
        chain_enabled: enabled,
        chain_steps: steps,
      }
      submittedPayload = payload
      const saved = await updateChainConfig(payload)
      setOperationDetails({
        operation: "update",
        payload,
        response: saved,
      })
      setEnabled(saved.chain_enabled)
      setSteps(Array.isArray(saved.chain_steps) ? saved.chain_steps : [])
      setLoaded(true)
      toast.success("连锁策略已保存")
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        const details = readReloadFailureDetails(e)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "update",
            payload: submittedPayload,
            response: details,
          })
        }
        const latest = await getChainConfig()
        setEnabled(latest.chain_enabled)
        setSteps(Array.isArray(latest.chain_steps) ? latest.chain_steps : [])
        setLoaded(true)
      }
      toast.error(e instanceof Error ? e.message : "保存连锁策略失败")
    } finally {
      setSaving(false)
    }
  }

  return (
    <Surface
      title="连锁策略"
      description="多步骤逐级验证链路，验证码步骤使用当前步骤保存的 captcha_type，不继承全局 captcha_challenge 类型。"
    >
      {reloadFailureDetails ? (
        <ReloadFailureDetailsAlert
          details={reloadFailureDetails}
          description="后端已返回连锁策略配置操作响应体；请核对 error 字段。"
        />
      ) : null}
      {operationDetails ? (
        <OperationDetailsAlert
          details={operationDetails}
          title="最近连锁策略操作响应"
          description="后端已返回连锁策略操作响应体；请核对 operation、payload 与 response 字段。"
          label="连锁策略操作响应体"
          icon={Link2}
        />
      ) : null}
      <div className="flex flex-col gap-5">
        <Field
          orientation="horizontal"
          className="max-w-xl rounded-xl border bg-muted/35 px-4 py-3"
        >
          <FieldLabel htmlFor={chainEnabledId}>启用连锁策略</FieldLabel>
          <Switch
            id={chainEnabledId}
            checked={enabled}
            onCheckedChange={setEnabled}
          />
        </Field>
        <div className="flex flex-col gap-3">
          {steps.map((step, i) => (
            <div
              key={i}
              className="flex items-center gap-3 rounded-xl border bg-background p-4"
            >
              <Badge variant="outline" className="font-mono">
                #{i + 1}
              </Badge>
              <Select
                value={step.type}
                onValueChange={(v: ChainStep["type"]) =>
                  updateStep(i, { type: v })
                }
              >
                <SelectTrigger className="w-[180px] rounded-md">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="env">环境检测</SelectItem>
                    <SelectItem value="pow">PoW 验证</SelectItem>
                    <SelectItem value="captcha">验证码</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
              <Select
                value={step.condition}
                onValueChange={(v) => updateStep(i, { condition: v })}
              >
                <SelectTrigger className="w-[180px] rounded-md">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="all">全部（all）</SelectItem>
                    <SelectItem value="env_score>30">
                      env_score &gt; 30
                    </SelectItem>
                    <SelectItem value="env_score<30">
                      env_score &lt; 30
                    </SelectItem>
                    <SelectItem value="score>50">score &gt; 50</SelectItem>
                    <SelectItem value="score>80">score &gt; 80</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
              {step.type === "captcha" && (
                <Select
                  value={step.captcha_type || "math"}
                  onValueChange={(v) =>
                    updateStep(i, {
                      captcha_type: v as ChainStep["captcha_type"],
                    })
                  }
                >
                  <SelectTrigger className="w-[190px] rounded-md">
                    <SelectValue placeholder="验证码类型" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {CAPTCHA_TYPE_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              )}
              <div className="ml-auto flex gap-1">
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={() => moveStep(i, -1)}
                  disabled={i === 0}
                  aria-label="上移连锁步骤"
                >
                  <ArrowUp data-icon="inline-start" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={() => moveStep(i, 1)}
                  disabled={i === steps.length - 1}
                  aria-label="下移连锁步骤"
                >
                  <ArrowDown data-icon="inline-start" />
                </Button>
                <Button
                  size="icon"
                  variant="destructive"
                  onClick={() => removeStep(i)}
                  aria-label="删除连锁步骤"
                >
                  <Trash2 data-icon="inline-start" />
                </Button>
              </div>
            </div>
          ))}
        </div>
        <Button variant="outline" onClick={addStep}>
          <Plus data-icon="inline-start" /> 添加步骤
        </Button>
        {steps.length > 0 && (
          <div className="rounded-xl border border-dashed bg-muted/35 px-4 py-3 text-sm text-muted-foreground">
            <span className="font-medium text-foreground">流程预览：</span>{" "}
            {steps.map((s, i) => (
              <span key={i}>
                {i > 0 && <span className="mx-1 text-muted-foreground">→</span>}
                <Badge variant="outline" className="font-mono">
                  {s.type === "captcha"
                    ? `captcha:${s.captcha_type || "math"}`
                    : s.type}
                </Badge>
              </span>
            ))}
            <span className="mx-1 text-muted-foreground">→</span>
            <Badge className="font-mono">pass</Badge>
          </div>
        )}
        <Button onClick={save} disabled={saving || !loaded}>
          {!loaded ? "加载中..." : saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </Surface>
  )
}

function ChainSessionsPanel() {
  const [sessions, setSessions] = useState<ChainSession[]>([])
  const [loading, setLoading] = useState(false)
  const [deleteSessionId, setDeleteSessionId] = useState<string | null>(null)
  const [deletingSession, setDeletingSession] = useState(false)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  async function load() {
    setLoading(true)
    try {
      const res = await listChainSessions()
      setSessions(res.items ?? [])
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载连锁验证会话失败")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    return deferEffect(load)
  }, [])

  async function remove() {
    if (!deleteSessionId) return
    const sessionId = deleteSessionId
    setDeletingSession(true)
    setOperationDetails(null)
    try {
      const response = await deleteChainSession(sessionId)
      setOperationDetails({
        operation: "delete_chain_session",
        session_id: sessionId,
        payload: { session_id: sessionId },
        response,
      })
      toast.success("连锁验证会话已清理")
      setSessions((current) =>
        current.filter((session) => session.id !== sessionId)
      )
      setDeleteSessionId(null)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "清理连锁验证会话失败")
    } finally {
      setDeletingSession(false)
    }
  }

  return (
    <Surface
      title="连锁验证会话"
      description="查看正在进行的 chain_challenge 会话，并清理异常卡住的验证状态。"
    >
      {operationDetails ? (
        <OperationDetailsAlert
          details={operationDetails}
          title="最近连锁验证会话操作响应"
          description="后端已返回连锁验证会话操作响应体；请核对 operation、session_id、payload 与 response 字段。"
          label="连锁验证会话操作响应体"
          icon={Link2}
        />
      ) : null}
      <div className="overflow-x-auto rounded-xl border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Session</TableHead>
              <TableHead>原始地址</TableHead>
              <TableHead>步骤</TableHead>
              <TableHead>开始时间</TableHead>
              <TableHead className="w-20 text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sessions.map((session) => (
              <TableRow key={session.id}>
                <TableCell className="max-w-[220px] truncate font-mono text-xs">
                  {session.id}
                </TableCell>
                <TableCell className="max-w-[260px] truncate text-xs text-muted-foreground">
                  {session.original_url || "—"}
                </TableCell>
                <TableCell>
                  {session.current_step}/{session.step_count}
                </TableCell>
                <TableCell className="text-xs whitespace-nowrap text-muted-foreground">
                  {session.started_at || "—"}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    size="icon"
                    variant="destructive"
                    onClick={() => setDeleteSessionId(session.id)}
                    aria-label="清理连锁验证会话"
                  >
                    <Trash2 data-icon="inline-start" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {!sessions.length && (
              <TableRow>
                <TableCell colSpan={5} className="py-8">
                  <EmptyState
                    title={
                      loading ? "正在加载连锁验证会话" : "暂无连锁验证会话"
                    }
                    description={
                      loading
                        ? "正在读取后端会话列表。"
                        : "当前没有正在进行的 chain_challenge 会话。"
                    }
                  />
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <Button variant="outline" className="mt-4 rounded-md" onClick={load}>
        刷新会话
      </Button>
      <AlertDialog
        open={!!deleteSessionId}
        onOpenChange={(open) => {
          if (!open && !deletingSession) setDeleteSessionId(null)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认清理连锁验证会话</AlertDialogTitle>
            <AlertDialogDescription>
              确认清理连锁验证会话 {deleteSessionId || "-"}
              ？正在验证的客户端需要重新开始 chain_challenge。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletingSession}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deletingSession}
              onClick={(event) => {
                event.preventDefault()
                void remove()
              }}
            >
              {deletingSession ? "清理中..." : "清理"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Surface>
  )
}

/* ───────── 防重放 Tab ───────── */
function AntiReplayTab() {
  return (
    <Surface
      title="防重放配置"
      description="Nonce、TTL 和挑战动作按站点保存，避免全局策略覆盖不同应用的请求语义。"
      action={
        <Button asChild variant="outline" size="sm">
          <Link href="/sites/">
            站点管理
            <ExternalLink data-icon="inline-end" />
          </Link>
        </Button>
      }
    >
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableBody>
              {[
                ["配置范围", "站点级覆盖"],
                [
                  "保存字段",
                  "anti_replay_enabled / anti_replay_ttl / anti_replay_action",
                ],
                ["默认动作", "shield_challenge"],
                ["继承关系", "不写入全局 protection 配置"],
              ].map(([label, value]) => (
                <TableRow key={label}>
                  <TableCell className="w-32 bg-muted/45 text-xs font-semibold text-muted-foreground">
                    {label}
                  </TableCell>
                  <TableCell className="font-mono text-sm text-foreground">
                    {value}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <Notice tone="sky" title="站点详情负责保存">
          防重放策略依赖站点
          Cookie、上游路径和放行动作，当前页只保留边界说明与入口，防止把站点级
          nullable 字段误写为全局布尔值。
        </Notice>
        <Alert className="lg:col-span-2">
          <AlertTitle>站点详情负责编辑</AlertTitle>
          <AlertDescription>
            修改站点防重放时，进入具体站点详情的高级保护区域。
          </AlertDescription>
          <AlertAction>
            <Button asChild size="sm">
              <Link href="/sites/">
                打开站点列表
                <ExternalLink data-icon="inline-end" />
              </Link>
            </Button>
          </AlertAction>
        </Alert>
      </div>
    </Surface>
  )
}

function getEscalationValidationMessage(cfg: EscalationConfig) {
  if (cfg.escalation_window_secs <= 0) {
    return "时间窗口必须大于 0"
  }
  for (let i = 0; i < cfg.escalation_steps.length; i++) {
    const step = cfg.escalation_steps[i]
    if (step.threshold <= 0) {
      return `第 ${i + 1} 个阶梯阈值必须大于 0`
    }
    if (i > 0 && step.threshold <= cfg.escalation_steps[i - 1].threshold) {
      return "阶梯阈值必须按顺序递增"
    }
    if (!step.action) {
      return `第 ${i + 1} 个阶梯动作不能为空`
    }
  }
  return ""
}

/* ───────── 阶梯升级 Tab ───────── */
function EscalationTab() {
  const escalationEnabledId = useId()
  const escalationWindowId = useId()
  const escalationStatusIpId = useId()
  const escalationStatusSiteId = useId()
  const [cfg, setCfg] = useState<EscalationConfig>({
    escalation_enabled: false,
    escalation_window_secs: 60,
    escalation_steps: [],
  })
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [statusIP, setStatusIP] = useState("")
  const [statusSiteID, setStatusSiteID] = useState("")
  const [status, setStatus] = useState<EscalationIPStatus | null>(null)
  const [statusScopeSiteID, setStatusScopeSiteID] = useState("")
  const [loadingStatus, setLoadingStatus] = useState(false)
  const [resetTarget, setResetTarget] = useState<{
    ip: string
    siteID: string
  } | null>(null)
  const [resettingStatus, setResettingStatus] = useState(false)
  const escalationValidationMessage = getEscalationValidationMessage(cfg)
  const escalationConfigInvalid = Boolean(escalationValidationMessage)

  useEffect(() => {
    getEscalationConfig("global")
      .then((config) => {
        setCfg(config)
        setLoaded(true)
      })
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载阶梯升级配置失败")
      )
  }, [])

  function addStep() {
    const steps = [...cfg.escalation_steps]
    const last = steps[steps.length - 1]
    steps.push({ threshold: (last?.threshold ?? 0) + 5, action: "challenge" })
    setCfg({ ...cfg, escalation_steps: steps })
  }
  function removeStep(i: number) {
    setCfg({
      ...cfg,
      escalation_steps: cfg.escalation_steps.filter((_, idx) => idx !== i),
    })
  }
  function updateStep(i: number, patch: Partial<EscalationStep>) {
    setCfg({
      ...cfg,
      escalation_steps: cfg.escalation_steps.map((s, idx) =>
        idx === i ? { ...s, ...patch } : s
      ),
    })
  }

  async function save() {
    if (!loaded) {
      toast.error("阶梯升级配置加载完成后再保存")
      return
    }
    if (escalationValidationMessage) {
      toast.error(escalationValidationMessage)
      return
    }
    setReloadFailureDetails(null)
    setOperationDetails(null)
    setSaving(true)
    const payload: EscalationConfig = cfg
    try {
      const saved = await updateEscalationConfig("global", payload)
      setOperationDetails({
        operation: "update",
        scope: "global",
        payload,
        response: saved,
      })
      setCfg(saved)
      setLoaded(true)
      toast.success("阶梯升级配置已保存")
    } catch (e) {
      if (isConfigAppliedReloadFailureError(e)) {
        const details = readReloadFailureDetails(e)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "update",
            scope: "global",
            payload,
            response: details,
          })
        }
        const latest = await getEscalationConfig("global")
        setCfg(latest)
        setLoaded(true)
      }
      toast.error(e instanceof Error ? e.message : "保存阶梯升级配置失败")
    } finally {
      setSaving(false)
    }
  }

  async function queryStatus() {
    const ip = statusIP.trim()
    const siteID = statusSiteID.trim()
    if (!ip) {
      toast.error("请输入客户端 IP")
      return
    }
    if (!siteID) {
      toast.error("请输入站点 ID")
      return
    }
    if (!/^[1-9]\d*$/.test(siteID)) {
      toast.error("站点 ID 必须是正整数")
      return
    }
    setLoadingStatus(true)
    setOperationDetails(null)
    try {
      const next = await getEscalationIPStatus(ip, siteID)
      setStatus(next)
      setStatusScopeSiteID(siteID)
      setOperationDetails({
        operation: "get_ip_status",
        scope: "site",
        payload: { ip, site_id: siteID },
        response: next,
      })
      toast.success("阶梯升级状态已加载")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载阶梯升级状态失败")
    } finally {
      setLoadingStatus(false)
    }
  }

  async function resetStatus() {
    if (!resetTarget) return
    const target = resetTarget
    setResettingStatus(true)
    setOperationDetails(null)
    try {
      const response = await resetEscalationIPStatus(target.ip, target.siteID)
      const next = await getEscalationIPStatus(
        target.ip,
        target.siteID
      )
      setStatus(next)
      setStatusScopeSiteID(target.siteID)
      setOperationDetails({
        operation: "reset_ip_status",
        scope: "site",
        payload: { ip: target.ip, site_id: target.siteID },
        response: {
          resetEscalationIPStatus: response,
          getEscalationIPStatus: next,
        },
      })
      setResetTarget(null)
      toast.success("阶梯升级状态已重置")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "重置阶梯升级状态失败")
    } finally {
      setResettingStatus(false)
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <Surface
        title="阶梯升级"
        description="在 WAF 命中后按客户端违规次数升级响应动作，不作为独立检测阶段。"
      >
        {reloadFailureDetails ? (
          <ReloadFailureDetailsAlert
            details={reloadFailureDetails}
            description="后端已返回阶梯升级配置操作响应体；请核对 error 字段。"
          />
        ) : null}
        {operationDetails ? (
          <OperationDetailsAlert
            details={operationDetails}
            title="最近阶梯升级操作响应"
            description="后端已返回阶梯升级操作响应体；请核对 operation、scope、payload 或 response 字段。"
            label="阶梯升级操作响应体"
            icon={TrendingUp}
          />
        ) : null}
        <div className="flex flex-col gap-5">
          <Field
            orientation="horizontal"
            className="max-w-xl rounded-lg border bg-muted/35 px-4 py-3"
          >
            <FieldLabel htmlFor={escalationEnabledId}>启用阶梯升级</FieldLabel>
            <Switch
              id={escalationEnabledId}
              checked={cfg.escalation_enabled}
              onCheckedChange={(v) =>
                setCfg({ ...cfg, escalation_enabled: v })
              }
            />
          </Field>
          <Field className="max-w-xl">
            <FieldLabel htmlFor={escalationWindowId}>时间窗口（秒）</FieldLabel>
            <Input
              id={escalationWindowId}
              type="number"
              min={1}
              aria-invalid={cfg.escalation_window_secs <= 0}
              value={cfg.escalation_window_secs}
              onChange={(e) =>
                setCfg({
                  ...cfg,
                  escalation_window_secs: Number(e.target.value),
                })
              }
              className="rounded-md"
            />
          </Field>
          {cfg.escalation_steps.length > 0 && (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">阈值</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead className="w-20 text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {cfg.escalation_steps.map((step, i) => (
                    <TableRow key={i}>
                      <TableCell>
                        <Input
                          type="number"
                          min={1}
                          aria-invalid={
                            step.threshold <= 0 ||
                            (i > 0 &&
                              step.threshold <=
                                cfg.escalation_steps[i - 1].threshold)
                          }
                          value={step.threshold}
                          className="w-24 rounded-md"
                          onChange={(e) =>
                            updateStep(i, { threshold: Number(e.target.value) })
                          }
                        />
                      </TableCell>
                      <TableCell>
                        <Select
                          value={step.action}
                          onValueChange={(v) => updateStep(i, { action: v })}
                        >
                          <SelectTrigger className="w-[160px] rounded-md">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              <SelectItem value="challenge">
                                Challenge（挑战）
                              </SelectItem>
                              <SelectItem value="intercept">
                                Intercept（拦截）
                              </SelectItem>
                              <SelectItem value="block">
                                Block（阻断）
                              </SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="icon"
                          variant="destructive"
                          aria-label="删除阶梯升级步骤"
                          onClick={() => removeStep(i)}
                        >
                          <Trash2 data-icon="inline-start" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {escalationValidationMessage ? (
            <Alert>
              <AlertTitle>阶梯升级配置未通过校验</AlertTitle>
              <AlertDescription>{escalationValidationMessage}</AlertDescription>
            </Alert>
          ) : null}
          <Button variant="outline" className="rounded-md" onClick={addStep}>
            <Plus data-icon="inline-start" />
            添加步骤
          </Button>
          <div>
            <Button
              onClick={save}
              disabled={saving || !loaded || escalationConfigInvalid}
              className="rounded-md"
            >
              {!loaded ? "加载中..." : saving ? "保存中..." : "保存配置"}
            </Button>
          </div>
        </div>
      </Surface>

      <Surface
        title="IP 升级状态"
        description="按站点 ID 和客户端 IP 查询当前窗口内违规命中次数、阶梯序号和已升级动作。"
      >
        <div className="flex flex-col gap-5">
          <FieldGroup className="grid gap-3 lg:grid-cols-[minmax(0,320px)_180px_auto]">
            <Field>
              <FieldLabel htmlFor={escalationStatusIpId}>
                客户端 IP
              </FieldLabel>
              <Input
                id={escalationStatusIpId}
                value={statusIP}
                onChange={(e) => setStatusIP(e.target.value)}
                placeholder="例如 203.0.113.10"
                className="rounded-md font-mono"
              />
              <FieldDescription>
                查询接口使用路径参数，不修改阶梯升级配置。
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor={escalationStatusSiteId}>
                站点 ID
              </FieldLabel>
              <Input
                id={escalationStatusSiteId}
                type="number"
                min={1}
                value={statusSiteID}
                onChange={(e) => setStatusSiteID(e.target.value)}
                className="rounded-md font-mono"
              />
              <FieldDescription>
                运行态计数按站点隔离，与数据面记录的 site_id 对齐。
              </FieldDescription>
            </Field>
            <Field className="justify-end">
              <Button
                onClick={queryStatus}
                disabled={loadingStatus}
                className="rounded-md md:mb-[26px]"
              >
                {loadingStatus ? (
                  <Loader2 data-icon="inline-start" className="animate-spin" />
                ) : (
                  <Search data-icon="inline-start" />
                )}
                {loadingStatus ? "查询中..." : "查询状态"}
              </Button>
            </Field>
          </FieldGroup>

          {status ? (
            <div className="overflow-hidden rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead className="w-28">站点 ID</TableHead>
                    <TableHead className="w-28">命中次数</TableHead>
                    <TableHead className="w-28">当前阶梯</TableHead>
                    <TableHead className="w-36">动作</TableHead>
                    <TableHead className="w-24 text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell className="font-mono">{status.ip}</TableCell>
                    <TableCell className="font-mono">
                      {statusScopeSiteID}
                    </TableCell>
                    <TableCell>{status.hit_count}</TableCell>
                    <TableCell>
                      {status.current_step >= 0 ? status.current_step : "未命中"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={status.action ? "outline" : "secondary"}>
                        {status.action || "无"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="destructive"
                        disabled={resettingStatus}
                        onClick={() =>
                          setResetTarget({
                            ip: status.ip,
                            siteID: statusScopeSiteID,
                          })
                        }
                      >
                        <RotateCcw data-icon="inline-start" />
                        重置
                      </Button>
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </div>
          ) : (
            <EmptyState
              title="尚未查询 IP 状态"
              description="输入站点 ID 和客户端 IP 后查询当前运行态中的阶梯升级计数。"
            />
          )}

          {status?.message ? (
            <Notice tone="amber" title="运行状态说明" size="sm">
              {status.message}
            </Notice>
          ) : null}
        </div>
      </Surface>

      <AlertDialog
        open={Boolean(resetTarget)}
        onOpenChange={(open) => {
          if (!open && !resettingStatus) setResetTarget(null)
        }}
      >
        <AlertDialogContent className="rounded-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>确认重置阶梯升级状态</AlertDialogTitle>
            <AlertDialogDescription>
              将清除 IP{" "}
              <span className="font-mono text-foreground">
                {resetTarget?.ip ?? ""}
              </span>{" "}
              在站点{" "}
              <span className="font-mono text-foreground">
                {resetTarget?.siteID ?? ""}
              </span>{" "}
              下的当前升级计数，后续命中会重新累计。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={resettingStatus}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={resettingStatus}
              onClick={(event) => {
                event.preventDefault()
                void resetStatus()
              }}
            >
              {resettingStatus ? "重置中..." : "确认重置"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

/* ───────── 主页面 ───────── */
export default function SecurityPolicyPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Security Policy"
        title="安全策略"
        description="验证码、5 秒盾、连锁策略、防重放与阶梯升级，构建多层次安全防护体系。"
      />
      <Tabs defaultValue="captcha" className="flex flex-col gap-4">
        <div className="overflow-x-auto overscroll-x-contain rounded-2xl border bg-card p-1 shadow-sm">
          <TabsList className="min-w-max">
            <TabsTrigger value="captcha">
              <ShieldCheck data-icon="inline-start" /> 验证码
            </TabsTrigger>
            <TabsTrigger value="shield">
              <Shield data-icon="inline-start" /> 5 秒盾
            </TabsTrigger>
            <TabsTrigger value="chain">
              <Link2 data-icon="inline-start" /> 连锁策略
            </TabsTrigger>
            <TabsTrigger value="sessions">
              <ShieldCheck data-icon="inline-start" /> 会话管理
            </TabsTrigger>
            <TabsTrigger value="antireplay">
              <RotateCcw data-icon="inline-start" /> 防重放
            </TabsTrigger>
            <TabsTrigger value="escalation">
              <TrendingUp data-icon="inline-start" /> 阶梯升级
            </TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="captcha">
          <CaptchaTab />
        </TabsContent>
        <TabsContent value="shield">
          <ShieldTab />
        </TabsContent>
        <TabsContent value="chain">
          <ChainTab />
        </TabsContent>
        <TabsContent value="sessions">
          <ChainSessionsPanel />
        </TabsContent>
        <TabsContent value="antireplay">
          <AntiReplayTab />
        </TabsContent>
        <TabsContent value="escalation">
          <EscalationTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}
