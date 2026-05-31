"use client"

import { useEffect, useState } from "react"
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
import { PageIntro, Surface } from "@/components/console-shell"
import {
  getCaptchaConfig,
  updateCaptchaConfig,
  testCaptcha,
  getChainConfig,
  updateChainConfig,
  getEscalationConfig,
  updateEscalationConfig,
  CAPTCHA_TYPE_OPTIONS,
  type CaptchaConfig,
  type ChainStep,
  type EscalationStep,
  type EscalationConfig,
} from "@/lib/security-api"

/* ───────── 验证码 Tab ───────── */
function CaptchaTab() {
  const [cfg, setCfg] = useState<CaptchaConfig>({
    captcha_enabled: false,
    captcha_type: "math",
    captcha_timeout: 120,
    shield_enabled: false,
    shield_difficulty: 4,
  })
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    getCaptchaConfig()
      .then(setCfg)
      .catch(() => {})
  }, [])

  async function save() {
    setSaving(true)
    try {
      await updateCaptchaConfig(cfg)
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
      if (r.implemented === false || r.supported === false) {
        toast.warning(r.message || "验证码测试预览暂未接入真实后端能力")
        return
      }
      toast.success(r.message || "测试成功")
    } catch (e) {
      toast.error(String(e))
    } finally {
      setTesting(false)
    }
  }

  return (
    <Surface title="验证码配置" description="配置人机验证码类型和难度。">
      <div className="max-w-xl space-y-5">
        <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
          <Label className="font-medium">启用验证码</Label>
          <Switch
            checked={cfg.captcha_enabled}
            onCheckedChange={(v) => setCfg({ ...cfg, captcha_enabled: v })}
          />
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
        <div className="space-y-2">
          <Label>超时时间（秒）</Label>
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
            测试预览
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
    </Surface>
  )
}

/* ───────── 5秒盾 Tab ───────── */
function ShieldTab() {
  const [cfg, setCfg] = useState<CaptchaConfig>({
    captcha_enabled: false,
    captcha_type: "math",
    captcha_timeout: 120,
    shield_enabled: false,
    shield_difficulty: 4,
    shield_timeout_secs: 30,
    shield_auto_start_delay: 800,
    shield_max_retries: 3,
    shield_env_strictness: 1,
    shield_require_http2: false,
    shield_require_http3: false,
    shield_allow_http1: true,
    shield_enable_wasm: true,
    shield_enable_js_challenge: true,
    shield_enable_env_check: true,
    shield_enable_devtools: true,
  })
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getCaptchaConfig()
      .then(setCfg)
      .catch(() => {})
  }, [])

  async function save() {
    setSaving(true)
    try {
      await updateCaptchaConfig(cfg)
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
        description="基于 PoW + 验证码的浏览器环境挑战，类似 Cloudflare 5s Shield。"
      >
        <div className="max-w-xl space-y-5">
          <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
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
              className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50/60 px-4 py-3"
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
              className="rounded-lg border border-slate-200 bg-slate-50/60 px-4 py-3"
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
        <div className="mt-3 max-w-xl rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
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
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getChainConfig()
      .then((c) => {
        setEnabled(c.chain_enabled)
        setSteps(Array.isArray(c.chain_steps) ? c.chain_steps : [])
      })
      .catch(() => {})
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
    setSteps(steps.map((s, idx) => (idx === i ? { ...s, ...patch } : s)))
  }

  async function save() {
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
        <div className="flex max-w-xl items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
          <Label className="font-medium">启用连锁策略</Label>
          <Switch checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <div className="space-y-3">
          {steps.map((step, i) => (
            <div
              key={i}
              className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white p-4"
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
                  <SelectItem value="captcha">算术验证码</SelectItem>
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
                  <SelectItem value="score>50">score &gt; 50</SelectItem>
                  <SelectItem value="score>80">score &gt; 80</SelectItem>
                  <SelectItem value="env_score<30">
                    env_score &lt; 30
                  </SelectItem>
                </SelectContent>
              </Select>
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
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            <span className="font-medium text-slate-500">流程预览：</span>{" "}
            {steps.map((s, i) => (
              <span key={i}>
                {i > 0 && <span className="mx-1 text-slate-600">→</span>}
                <span className="rounded border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-xs">
                  {s.type}
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
          disabled={saving}
          className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
        >
          {saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </Surface>
  )
}

/* ───────── 防重放 Tab ───────── */
function AntiReplayTab() {
  return (
    <Surface
      title="防重放配置"
      description="基于 Nonce 的请求重放防护，当前按站点独立配置。"
    >
      <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-5 text-sm leading-6 text-amber-900">
          <div className="font-semibold text-amber-950">
            此处不再展示不可保存的假表单
          </div>
          <p className="mt-2">
            防重放依赖站点级 Cookie、Nonce
            TTL、动作策略和上游行为，必须在具体站点上下文中启用。全局安全策略页仅作为能力说明，避免误以为这里可以保存全局配置。
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-5">
          <div className="text-sm font-semibold text-slate-950">下一步</div>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            进入站点详情，在“高级保护/安全覆盖”中配置站点级防重放。
          </p>
          <Button
            asChild
            className="mt-4 w-full rounded-md bg-slate-950 text-white hover:bg-slate-800"
          >
            <Link href="/sites/">
              前往站点管理
              <ExternalLink className="ml-2 h-3.5 w-3.5" />
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
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getEscalationConfig(1)
      .then(setCfg)
      .catch(() => {})
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
    setSaving(true)
    try {
      await updateEscalationConfig(1, cfg)
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
        <div className="flex max-w-xl items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
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
          <div className="overflow-x-auto rounded-lg border border-slate-200">
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
            disabled={saving}
            className="rounded-md bg-teal-500 text-white hover:bg-teal-600"
          >
            {saving ? "保存中..." : "保存配置"}
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
        <div className="overflow-x-auto overscroll-x-contain pb-1">
          <TabsList className="min-w-max">
            <TabsTrigger value="captcha" className="gap-1.5">
              <ShieldCheck className="h-4 w-4" /> 验证码
            </TabsTrigger>
            <TabsTrigger value="shield" className="gap-1.5">
              <Shield className="h-4 w-4" /> 5秒盾
            </TabsTrigger>
            <TabsTrigger value="chain" className="gap-1.5">
              <Link2 className="h-4 w-4" /> 连锁策略
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
