"use client"

import { useEffect, useRef, useState } from "react"
import Link from "next/link"
import { toast } from "sonner"
import {
  Shield,
  ShieldCheck,
  Link2,
  RotateCcw,
  TrendingUp,
  Plus,
  Trash2,
  ArrowUp,
  ArrowDown,
  Loader2,
  Play,
  ExternalLink,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
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
  CAPTCHA_TYPE_OPTIONS,
  defaultCaptchaConfig,
  type CaptchaConfig,
  type CaptchaTestResponse,
  type ChainSession,
  type ChainStep,
  type EscalationStep,
  type EscalationConfig,
} from "@/lib/security-api"

/* ───────── 验证码 Tab ───────── */
function CaptchaTab() {
  const [cfg, setCfg] = useState<CaptchaConfig>({ ...defaultCaptchaConfig })
  const [preview, setPreview] = useState<CaptchaTestResponse | null>(null)
  const [captchaAnswer, setCaptchaAnswer] = useState("")
  const [clickPoints, setClickPoints] = useState<
    Array<{ x: number; y: number }>
  >([])
  const [slideX, setSlideX] = useState(0)
  const [rotateAngle, setRotateAngle] = useState(0)
  const captchaImgRef = useRef<HTMLImageElement | null>(null)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    getCaptchaConfig()
      .then(setCfg)
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载验证码配置失败")
      )
  }, [])

  async function save() {
    setSaving(true)
    try {
      const latest = await getCaptchaConfig()
      const saved = await updateCaptchaConfig({
        ...latest,
        captcha_enabled: cfg.captcha_enabled,
        captcha_type: cfg.captcha_type,
        captcha_timeout: cfg.captcha_timeout,
        captcha_pass_ttl: cfg.captcha_pass_ttl,
      })
      setCfg(saved)
      toast.success("验证码配置已保存")
    } catch (e) {
      toast.error(String(e))
    } finally {
      setSaving(false)
    }
  }

  async function doTest() {
    setTesting(true)
    try {
      const r = await testCaptcha()
      setPreview(r)
      setCaptchaAnswer("")
      setClickPoints([])
      setSlideX(0)
      setRotateAngle(0)
      if (r.fallback) {
        toast.warning("当前验证码类型已回退到内置算术验证码")
        return
      }
      toast.success("验证码预览已生成")
    } catch (e) {
      toast.error(String(e))
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
      description="仅在规则动作触发 captcha_challenge，或连锁验证执行 captcha 步骤时生效。"
    >
      <div className="grid gap-5 xl:grid-cols-[minmax(0,560px)_minmax(320px,1fr)]">
        <div className="space-y-5">
          <div className="flex items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-3">
            <div>
              <Label className="font-medium">启用 captcha_challenge</Label>
              <p className="mt-1 text-xs text-slate-500">
                关闭后命中验证码动作会退回通用挑战页，不会生成具体验证码。
              </p>
            </div>
            <Switch
              checked={cfg.captcha_enabled}
              onCheckedChange={(v) => setCfg({ ...cfg, captcha_enabled: v })}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>验证超时时间（秒）</Label>
              <Input
                type="number"
                min={10}
                max={600}
                value={cfg.captcha_timeout}
                onChange={(e) =>
                  setCfg({ ...cfg, captcha_timeout: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </div>
            <div className="space-y-2">
              <Label>通过有效期（秒）</Label>
              <Input
                type="number"
                min={10}
                max={3600}
                value={cfg.captcha_pass_ttl}
                onChange={(e) =>
                  setCfg({ ...cfg, captcha_pass_ttl: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>验证码类型</Label>
            <Select
              value={cfg.captcha_type}
              onValueChange={(v: CaptchaConfig["captcha_type"]) =>
                setCfg({ ...cfg, captcha_type: v })
              }
            >
              <SelectTrigger className="rounded-md">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CAPTCHA_TYPE_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="text-xs text-slate-500">
              {
                CAPTCHA_TYPE_OPTIONS.find(
                  (option) => option.value === cfg.captcha_type
                )?.description
              }
            </div>
          </div>
          <div className="rounded-xl border border-slate-200/80 bg-white/95 px-4 py-3 text-sm leading-6 text-slate-600">
            <div className="font-medium text-slate-900">触发关系</div>
            <p className="mt-1">
              验证码类型不会由 HTTP 状态码决定，而是由 WAF 动作决定：规则动作为
              <code className="mx-1 rounded bg-slate-100 px-1 py-0.5">
                captcha_challenge
              </code>
              时使用本配置；5 秒盾和连锁验证有独立流程。
            </p>
          </div>
          <div className="flex gap-3 pt-2">
            <Button
              onClick={doTest}
              variant="outline"
              className="rounded-md"
              disabled={testing}
            >
              {testing ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Play className="mr-2 h-4 w-4" />
              )}
              生成预览
            </Button>
            <Button
              onClick={save}
              disabled={saving}
              className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
            >
              {saving ? "保存中..." : "保存配置"}
            </Button>
          </div>
        </div>
        <div className="console-panel p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-slate-900">
                当前预览
              </div>
              <div className="text-xs text-slate-500">
                预览会创建一次性 session，不包含答案。
              </div>
            </div>
            {preview && (
              <span className="rounded-full border border-slate-200 bg-white px-2 py-1 text-xs text-slate-500">
                {preview.type}
              </span>
            )}
          </div>
          {preview ? (
            <div className="space-y-3">
              <div className="overflow-hidden rounded-xl border border-slate-200/80 bg-white/95 p-3">
                <div className="relative mx-auto w-fit">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    ref={captchaImgRef}
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
                  />
                  {preview.type === "click" &&
                    clickPoints.map((point, idx) => {
                      const img = captchaImgRef.current
                      const naturalWidth =
                        img?.naturalWidth || preview.width || 1
                      const naturalHeight =
                        img?.naturalHeight || preview.height || 1
                      const left = `${(point.x / naturalWidth) * 100}%`
                      const top = `${(point.y / naturalHeight) * 100}%`
                      return (
                        <span
                          key={`${point.x}-${point.y}-${idx}`}
                          className="absolute -translate-x-1/2 -translate-y-1/2 rounded-full bg-teal-500 px-1.5 py-0.5 text-[10px] font-bold text-white shadow"
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
              <div className="rounded-xl border border-slate-200/80 bg-white/95 p-3 text-xs leading-5 text-slate-600">
                <div className="font-medium text-slate-900">
                  {preview.prompt}
                </div>
                <div className="mt-3 space-y-2">
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
                  <div className="rounded bg-slate-50 px-2 py-1 font-mono text-[11px] break-all text-slate-500">
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
                  <div className="mt-2 rounded border border-amber-200 bg-amber-50 px-2 py-1 text-amber-700">
                    go-captcha 资源不可用，已回退到内置 math。
                  </div>
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

/* ───────── 5秒盾 Tab ───────── */
function ShieldTab() {
  const [cfg, setCfg] = useState<CaptchaConfig>({ ...defaultCaptchaConfig })
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getCaptchaConfig()
      .then(setCfg)
      .catch((e) =>
        toast.error(e instanceof Error ? e.message : "加载验证码配置失败")
      )
  }, [])

  async function save() {
    setSaving(true)
    try {
      const latest = await getCaptchaConfig()
      const saved = await updateCaptchaConfig({
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
      })
      setCfg(saved)
      toast.success("5秒盾配置已保存")
    } catch (e) {
      toast.error(String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <Surface
        title="5秒盾基础配置"
        description="基于 PoW、JavaScript/WASM、环境指纹和协议约束的浏览器挑战。"
      >
        <div className="max-w-xl space-y-5">
          <div className="flex items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-3">
            <Label className="font-medium">启用5秒盾</Label>
            <Switch
              checked={cfg.shield_enabled}
              onCheckedChange={(v) => setCfg({ ...cfg, shield_enabled: v })}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>PoW 难度（前导零位数）</Label>
              <Input
                type="number"
                min={1}
                max={32}
                value={cfg.shield_difficulty}
                onChange={(e) =>
                  setCfg({ ...cfg, shield_difficulty: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </div>
            <div className="space-y-2">
              <Label>验证超时（秒）</Label>
              <Input
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
            </div>
            <div className="space-y-2">
              <Label>自动启动延迟（ms）</Label>
              <Input
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
            </div>
            <div className="space-y-2">
              <Label>最大重试次数</Label>
              <Input
                type="number"
                min={1}
                max={10}
                value={cfg.shield_max_retries ?? 3}
                onChange={(e) =>
                  setCfg({ ...cfg, shield_max_retries: Number(e.target.value) })
                }
                className="rounded-md"
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>环境检测严格度</Label>
            <Select
              value={String(cfg.shield_env_strictness ?? 1)}
              onValueChange={(v) =>
                setCfg({ ...cfg, shield_env_strictness: Number(v) })
              }
            >
              <SelectTrigger className="rounded-md">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="0">宽松（仅基础检测）</SelectItem>
                <SelectItem value="1">标准（推荐）</SelectItem>
                <SelectItem value="2">严格（可能增加误报）</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </Surface>

      <Surface title="挑战策略" description="控制使用哪些验证手段组合。">
        <div className="grid max-w-xl gap-3 sm:grid-cols-2">
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
            <div
              key={key}
              className="flex items-center justify-between gap-3 rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-3"
            >
              <div>
                <div className="text-sm font-semibold text-slate-900">
                  {label}
                </div>
                <div className="text-[11px] text-slate-500">{desc}</div>
              </div>
              <Switch
                checked={cfg[key] !== false}
                onCheckedChange={(v) => setCfg({ ...cfg, [key]: v })}
              />
            </div>
          ))}
        </div>
      </Surface>

      <Surface
        title="HTTP 协议版本要求"
        description="限制客户端必须使用的 HTTP 协议版本，可用于过滤低质量流量。"
      >
        <div className="grid max-w-xl gap-3 sm:grid-cols-3">
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
            <div
              key={key}
              className="rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-3"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="text-sm font-semibold text-slate-900">
                  {label}
                </div>
                <Switch
                  checked={cfg[key] === true}
                  onCheckedChange={(v) => setCfg({ ...cfg, [key]: v })}
                />
              </div>
              <div className="mt-1 text-[11px] text-slate-500">{desc}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 max-w-xl rounded-xl border border-amber-200 bg-amber-50/90 px-4 py-3 text-sm text-amber-800">
          注意：同时要求 HTTP/2 和 HTTP/3 时，客户端需支持其中任一即可通过。禁用
          HTTP/1.1 可能会阻止部分旧版浏览器和 CLI 工具。
        </div>
      </Surface>

      <div className="flex justify-end pb-4">
        <Button
          onClick={save}
          disabled={saving}
          className="rounded-md bg-teal-500 px-8 text-white hover:bg-teal-600"
        >
          {saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </div>
  )
}

/* ───────── 连锁策略 Tab ───────── */
function ChainTab() {
  const [enabled, setEnabled] = useState(false)
  const [steps, setSteps] = useState<ChainStep[]>([])
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)

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
    setSaving(true)
    try {
      await updateChainConfig({ chain_enabled: enabled, chain_steps: steps })
      toast.success("连锁策略已保存")
    } catch (e) {
      toast.error(String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Surface
      title="连锁策略"
      description="多步骤逐级验证链路，按顺序执行每个挑战步骤。"
    >
      <div className="space-y-5">
        <div className="flex max-w-xl items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-3">
          <Label className="font-medium">启用连锁策略</Label>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <div className="space-y-3">
          {steps.map((step, i) => (
            <div
              key={i}
              className="flex items-center gap-3 rounded-xl border border-slate-200/80 bg-white/95 p-4"
            >
              <span className="w-8 text-xs font-bold text-slate-400">
                #{i + 1}
              </span>
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
                  <SelectItem value="env">环境检测</SelectItem>
                  <SelectItem value="pow">PoW 验证</SelectItem>
                  <SelectItem value="captcha">验证码</SelectItem>
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
                  <SelectItem value="all">全部（all）</SelectItem>
                  <SelectItem value="env_score>30">
                    env_score &gt; 30
                  </SelectItem>
                  <SelectItem value="env_score<30">
                    env_score &lt; 30
                  </SelectItem>
                  <SelectItem value="score>50">score &gt; 50</SelectItem>
                  <SelectItem value="score>80">score &gt; 80</SelectItem>
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
                    {CAPTCHA_TYPE_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
              <div className="ml-auto flex gap-1">
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-8 w-8"
                  onClick={() => moveStep(i, -1)}
                  disabled={i === 0}
                >
                  <ArrowUp className="h-4 w-4" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-8 w-8"
                  onClick={() => moveStep(i, 1)}
                  disabled={i === steps.length - 1}
                >
                  <ArrowDown className="h-4 w-4" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-8 w-8 text-rose-500 hover:text-rose-700"
                  onClick={() => removeStep(i)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ))}
        </div>
        <Button variant="outline" className="rounded-md" onClick={addStep}>
          <Plus className="mr-2 h-4 w-4" /> 添加步骤
        </Button>
        {steps.length > 0 && (
          <div className="rounded-xl border border-dashed border-slate-300/90 bg-slate-50/80 px-4 py-3 text-sm text-slate-600">
            <span className="font-medium text-slate-500">流程预览：</span>{" "}
            {steps.map((s, i) => (
              <span key={i}>
                {i > 0 && <span className="mx-1 text-slate-600">→</span>}
                <span className="rounded border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-xs">
                  {s.type === "captcha"
                    ? `captcha:${s.captcha_type || "math"}`
                    : s.type}
                </span>
              </span>
            ))}
            <span className="mx-1 text-slate-600">→</span>
            <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 font-mono text-xs text-emerald-700">
              pass
            </span>
          </div>
        )}
        <Button
          onClick={save}
          disabled={saving || !loaded}
          className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
        >
          {!loaded ? "加载中..." : saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </Surface>
  )
}

function ChainSessionsPanel() {
  const [sessions, setSessions] = useState<ChainSession[]>([])
  const [loading, setLoading] = useState(false)

  async function load() {
    setLoading(true)
    try {
      const res = await listChainSessions()
      setSessions(res.items ?? [])
    } catch (e) {
      toast.error(String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  async function remove(id: string) {
    const confirmed = window.confirm(
      `确认清理连锁验证会话 ${id}？正在验证的客户端需要重新开始 chain_challenge。`
    )
    if (!confirmed) return
    try {
      await deleteChainSession(id)
      toast.success("连锁验证会话已清理")
      setSessions(sessions.filter((session) => session.id !== id))
    } catch (e) {
      toast.error(String(e))
    }
  }

  return (
    <Surface
      title="连锁验证会话"
      description="查看正在进行的 chain_challenge 会话，并清理异常卡住的验证状态。"
    >
      <div className="overflow-x-auto rounded-xl border border-slate-200/80">
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
                <TableCell className="max-w-[260px] truncate text-xs text-slate-600">
                  {session.original_url || "—"}
                </TableCell>
                <TableCell>
                  {session.current_step}/{session.step_count}
                </TableCell>
                <TableCell className="text-xs whitespace-nowrap text-slate-500">
                  {session.started_at || "—"}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-8 w-8 text-rose-500 hover:text-rose-700"
                    onClick={() => remove(session.id)}
                  >
                    <Trash2 className="h-4 w-4" />
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
        <div className="overflow-hidden rounded-lg border border-slate-200/80">
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
                  <TableCell className="w-32 bg-slate-50/80 text-xs font-semibold text-slate-500">
                    {label}
                  </TableCell>
                  <TableCell className="font-mono text-sm text-slate-900">
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
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-teal-200 bg-teal-50/80 px-4 py-3 lg:col-span-2">
          <div className="text-sm font-medium text-teal-950">
            修改站点防重放时，进入具体站点详情的高级保护区域。
          </div>
          <Button asChild size="sm">
            <Link href="/sites/">
              打开站点列表
              <ExternalLink data-icon="inline-end" />
            </Link>
          </Button>
        </div>
      </div>
    </Surface>
  )
}

/* ───────── 阶梯升级 Tab ───────── */
function EscalationTab() {
  const [cfg, setCfg] = useState<EscalationConfig>({
    escalation_enabled: false,
    escalation_window_secs: 60,
    escalation_steps: [],
  })
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)

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
    setSaving(true)
    try {
      await updateEscalationConfig("global", cfg)
      toast.success("阶梯升级配置已保存")
    } catch (e) {
      toast.error(String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Surface
      title="阶梯升级"
      description="在 WAF 命中后按客户端违规次数升级响应动作，不作为独立检测阶段。"
    >
      <div className="space-y-5">
        <div className="flex max-w-xl items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-3">
          <Label className="font-medium">启用阶梯升级</Label>
          <Switch
            checked={cfg.escalation_enabled}
            onCheckedChange={(v) => setCfg({ ...cfg, escalation_enabled: v })}
          />
        </div>
        <div className="max-w-xl space-y-2">
          <Label>时间窗口（秒）</Label>
          <Input
            type="number"
            min={1}
            value={cfg.escalation_window_secs}
            onChange={(e) =>
              setCfg({ ...cfg, escalation_window_secs: Number(e.target.value) })
            }
            className="rounded-md"
          />
        </div>
        {cfg.escalation_steps.length > 0 && (
          <div className="overflow-x-auto rounded-xl border border-slate-200/80">
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
                          <SelectItem value="challenge">
                            Challenge（挑战）
                          </SelectItem>
                          <SelectItem value="intercept">
                            Intercept（拦截）
                          </SelectItem>
                          <SelectItem value="block">Block（阻断）</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-rose-500 hover:text-rose-700"
                        onClick={() => removeStep(i)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <Button variant="outline" className="rounded-md" onClick={addStep}>
          <Plus className="mr-2 h-4 w-4" /> 添加步骤
        </Button>
        <div>
          <Button
            onClick={save}
            disabled={saving || !loaded}
            className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
          >
            {!loaded ? "加载中..." : saving ? "保存中..." : "保存配置"}
          </Button>
        </div>
      </div>
    </Surface>
  )
}

/* ───────── 主页面 ───────── */
export default function SecurityPolicyPage() {
  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Security Policy"
        title="安全策略"
        description="验证码、5秒盾、连锁策略、防重放与阶梯升级，构建多层次安全防护体系。"
      />
      <Tabs defaultValue="captcha" className="space-y-4">
        <div className="overflow-x-auto overscroll-x-contain rounded-2xl border border-slate-200/80 bg-white/90 p-1 shadow-sm backdrop-blur">
          <TabsList className="min-w-max bg-transparent">
            <TabsTrigger value="captcha" className="gap-1.5">
              <ShieldCheck className="h-4 w-4" /> 验证码
            </TabsTrigger>
            <TabsTrigger value="shield" className="gap-1.5">
              <Shield className="h-4 w-4" /> 5秒盾
            </TabsTrigger>
            <TabsTrigger value="chain" className="gap-1.5">
              <Link2 className="h-4 w-4" /> 连锁策略
            </TabsTrigger>
            <TabsTrigger value="sessions" className="gap-1.5">
              <ShieldCheck className="h-4 w-4" /> 会话管理
            </TabsTrigger>
            <TabsTrigger value="antireplay" className="gap-1.5">
              <RotateCcw className="h-4 w-4" /> 防重放
            </TabsTrigger>
            <TabsTrigger value="escalation" className="gap-1.5">
              <TrendingUp className="h-4 w-4" /> 阶梯升级
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
