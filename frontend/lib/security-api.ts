import { api, buildQuery } from "./api"

/* ── Captcha / Shield Config ── */

export const CAPTCHA_TYPES = ["math", "click", "slide", "rotate"] as const
export type CaptchaType = (typeof CAPTCHA_TYPES)[number]

export const CAPTCHA_TYPE_OPTIONS: Array<{
  value: CaptchaType
  label: string
  description: string
}> = [
  {
    value: "math",
    label: "Math（算术验证码）",
    description: "简单数学运算，无需外部资源",
  },
  {
    value: "click",
    label: "Click（点击验证码）",
    description: "按顺序点击图中文字（go-captcha）",
  },
  {
    value: "slide",
    label: "Slide（滑动验证码）",
    description: "拖动滑块到指定位置（go-captcha）",
  },
  {
    value: "rotate",
    label: "Rotate（旋转验证码）",
    description: "旋转图片至正确角度（go-captcha）",
  },
]

export interface CaptchaConfig {
  captcha_enabled: boolean
  captcha_type: CaptchaType
  captcha_timeout: number
  captcha_pass_ttl: number
  shield_enabled: boolean
  shield_difficulty: number
  shield_timeout_secs: number
  shield_auto_start_delay: number
  shield_max_retries: number
  shield_env_strictness: number
  shield_require_http2: boolean
  shield_require_http3: boolean
  shield_allow_http1: boolean
  shield_enable_wasm: boolean
  shield_enable_js_challenge: boolean
  shield_enable_env_check: boolean
  shield_enable_devtools: boolean
}

export const defaultCaptchaConfig: CaptchaConfig = {
  captcha_enabled: false,
  captcha_type: "math",
  captcha_timeout: 120,
  captcha_pass_ttl: 120,
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
}

export function normalizeCaptchaConfig(
  input?: Partial<CaptchaConfig> | null
): CaptchaConfig {
  return {
    captcha_enabled:
      input?.captcha_enabled ?? defaultCaptchaConfig.captcha_enabled,
    captcha_type: input?.captcha_type ?? defaultCaptchaConfig.captcha_type,
    captcha_timeout:
      input?.captcha_timeout ?? defaultCaptchaConfig.captcha_timeout,
    captcha_pass_ttl:
      input?.captcha_pass_ttl ?? defaultCaptchaConfig.captcha_pass_ttl,
    shield_enabled:
      input?.shield_enabled ?? defaultCaptchaConfig.shield_enabled,
    shield_difficulty:
      input?.shield_difficulty ?? defaultCaptchaConfig.shield_difficulty,
    shield_timeout_secs:
      input?.shield_timeout_secs ?? defaultCaptchaConfig.shield_timeout_secs,
    shield_auto_start_delay:
      input?.shield_auto_start_delay ??
      defaultCaptchaConfig.shield_auto_start_delay,
    shield_max_retries:
      input?.shield_max_retries ?? defaultCaptchaConfig.shield_max_retries,
    shield_env_strictness:
      input?.shield_env_strictness ??
      defaultCaptchaConfig.shield_env_strictness,
    shield_require_http2:
      input?.shield_require_http2 ?? defaultCaptchaConfig.shield_require_http2,
    shield_require_http3:
      input?.shield_require_http3 ?? defaultCaptchaConfig.shield_require_http3,
    shield_allow_http1:
      input?.shield_allow_http1 ?? defaultCaptchaConfig.shield_allow_http1,
    shield_enable_wasm:
      input?.shield_enable_wasm ?? defaultCaptchaConfig.shield_enable_wasm,
    shield_enable_js_challenge:
      input?.shield_enable_js_challenge ??
      defaultCaptchaConfig.shield_enable_js_challenge,
    shield_enable_env_check:
      input?.shield_enable_env_check ??
      defaultCaptchaConfig.shield_enable_env_check,
    shield_enable_devtools:
      input?.shield_enable_devtools ??
      defaultCaptchaConfig.shield_enable_devtools,
  }
}

export async function getCaptchaConfig(): Promise<CaptchaConfig> {
  return normalizeCaptchaConfig(
    await api<Partial<CaptchaConfig>>("/api/v1/captcha/config")
  )
}

export async function updateCaptchaConfig(
  cfg: CaptchaConfig
): Promise<CaptchaConfig> {
  return normalizeCaptchaConfig(
    await api<Partial<CaptchaConfig>>("/api/v1/captcha/config", {
      method: "POST",
      body: JSON.stringify(normalizeCaptchaConfig(cfg)),
    })
  )
}

export interface CaptchaTestResponse {
  session_id: string
  captcha_type: CaptchaType
  type: CaptchaType
  master_img: string
  thumb_img?: string
  prompt: string
  width?: number
  height?: number
  timeout: number
  pass_ttl?: number
  fallback?: boolean
}

export async function testCaptcha(): Promise<CaptchaTestResponse> {
  return api<CaptchaTestResponse>("/api/v1/captcha/test", { method: "POST" })
}

/* ── Chain Challenge Config ── */

export type ChainStepType = "env" | "pow" | "captcha"

export interface ChainStep {
  type: ChainStepType
  condition: string
  match?: string
  captcha_type?: CaptchaType
}

export interface ChainConfig {
  chain_enabled: boolean
  chain_steps: ChainStep[]
}

export async function getChainConfig(): Promise<ChainConfig> {
  return api<ChainConfig>("/api/v1/chain/config")
}

export async function updateChainConfig(
  cfg: Partial<ChainConfig>
): Promise<ChainConfig> {
  return api<ChainConfig>("/api/v1/chain/config", {
    method: "POST",
    body: JSON.stringify(cfg),
  })
}

export interface ChainSession {
  id: string
  current_step: number
  step_count: number
  original_url: string
  started_at: string
}

export interface ChainSessionListResponse {
  items: ChainSession[]
  total: number
}

export interface ChainSessionDeleteResponse {
  message: string
}

export async function listChainSessions(): Promise<ChainSessionListResponse> {
  return api<ChainSessionListResponse>("/api/v1/chain/sessions")
}

export async function deleteChainSession(
  id: string
): Promise<ChainSessionDeleteResponse> {
  return api<ChainSessionDeleteResponse>(
    `/api/v1/chain/sessions/${encodeURIComponent(id)}/delete`,
    { method: "POST" }
  )
}

export interface EscalationStep {
  threshold: number
  action: string
}

export interface EscalationConfig {
  escalation_enabled: boolean
  escalation_window_secs: number
  escalation_steps: EscalationStep[]
}

export interface EscalationIPStatus {
  ip: string
  hit_count: number
  current_step: number
  action?: string
  message?: string
}

export interface EscalationResetResponse {
  message: string
}

export async function getEscalationConfig(
  protectionId: number | string = "global"
): Promise<EscalationConfig> {
  return api<EscalationConfig>(`/api/v1/protection/${protectionId}/escalation`)
}

export async function updateEscalationConfig(
  protectionId: number | string,
  cfg: Partial<EscalationConfig>
): Promise<EscalationConfig> {
  return api<EscalationConfig>(
    `/api/v1/protection/${protectionId}/escalation`,
    {
      method: "POST",
      body: JSON.stringify(cfg),
    }
  )
}

export async function getEscalationIPStatus(
  ip: string,
  siteId?: number | string
): Promise<EscalationIPStatus> {
  return api<EscalationIPStatus>(
    `/api/v1/escalation/status/${encodeURIComponent(ip)}${buildQuery({
      site_id: siteId,
    })}`
  )
}

export async function resetEscalationIPStatus(
  ip: string,
  siteId?: number | string
): Promise<EscalationResetResponse> {
  return api<EscalationResetResponse>(
    `/api/v1/escalation/status/${encodeURIComponent(ip)}/reset${buildQuery({
      site_id: siteId,
    })}`,
    { method: "POST" }
  )
}
