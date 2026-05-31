import { api } from "./api"

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
  shield_timeout_secs?: number
  shield_auto_start_delay?: number
  shield_max_retries?: number
  shield_env_strictness?: number
  shield_require_http2?: boolean
  shield_require_http3?: boolean
  shield_allow_http1?: boolean
  shield_enable_wasm?: boolean
  shield_enable_js_challenge?: boolean
  shield_enable_env_check?: boolean
  shield_enable_devtools?: boolean
}

export async function getCaptchaConfig(): Promise<CaptchaConfig> {
  return api<CaptchaConfig>("/api/v1/captcha/config")
}

export async function updateCaptchaConfig(
  cfg: CaptchaConfig
): Promise<CaptchaConfig> {
  return api<CaptchaConfig>("/api/v1/captcha/config", {
    method: "POST",
    body: JSON.stringify(cfg),
  })
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
  captcha_type?: CaptchaType | "inherit"
}

export interface ChainConfig {
  chain_enabled: boolean
  chain_steps: ChainStep[]
}

export async function getChainConfig(): Promise<ChainConfig> {
  return api<ChainConfig>("/api/v1/chain/config")
}

export async function updateChainConfig(
  cfg: ChainConfig
): Promise<ChainConfig> {
  return api<ChainConfig>("/api/v1/chain/config", {
    method: "POST",
    body: JSON.stringify(cfg),
  })
}

export interface ChainSession {
  id: string
  client_ip: string
  current_step: number
  started_at: string
}

export interface ChainSessionListResponse {
  items: ChainSession[]
  total: number
}

export async function listChainSessions(): Promise<ChainSessionListResponse> {
  return api<ChainSessionListResponse>("/api/v1/chain/sessions")
}

export async function deleteChainSession(id: string): Promise<{ message?: string }> {
  return api<{ message?: string }>(
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

export async function getEscalationConfig(
  protectionId: number | string = "global"
): Promise<EscalationConfig> {
  return api<EscalationConfig>(`/api/v1/protection/${protectionId}/escalation`)
}

export async function updateEscalationConfig(
  protectionId: number | string,
  cfg: EscalationConfig
): Promise<EscalationConfig> {
  return api<EscalationConfig>(
    `/api/v1/protection/${protectionId}/escalation`,
    {
      method: "POST",
      body: JSON.stringify(cfg),
    }
  )
}
